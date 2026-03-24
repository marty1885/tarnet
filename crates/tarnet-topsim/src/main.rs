mod inproc;
mod topology;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use inproc::InProcNetwork;
use tarnet::link::PeerLink;
use tarnet::identity::Keypair;
use tarnet::node::{Node, NodeEvent};
use tarnet::transport::Discovery;

use topology::{NodeKind, ProbePair, ProbeRender, SvgSummary, TopologyPlan};

#[derive(Parser, Debug)]
#[command(
    name = "tarnet-topsim",
    about = "Spawn a geographically-shaped test topology using real tarnet transport and DV routing"
)]
struct Cli {
    /// Total nodes to create.
    #[arg(short, long, default_value_t = 256)]
    nodes: usize,

    /// RNG seed for reproducible topology and probe selection.
    #[arg(long, default_value_t = 1)]
    seed: u64,

    /// Number of route probes to run after the network settles.
    #[arg(short, long, default_value_t = 48)]
    probes: usize,

    /// How many seconds to wait before probing.
    #[arg(long, default_value_t = 15)]
    settle_secs: u64,

    /// Maximum concurrent probes. 0 means unlimited.
    #[arg(long = "parallel-tests", visible_alias = "parallel-probes", default_value_t = 0)]
    parallel_tests: usize,

    /// Delay between node starts. Small non-zero values reduce burstiness.
    #[arg(long, default_value_t = 0)]
    spawn_delay_ms: u64,

    /// Emit a Graphviz DOT topology file.
    #[arg(long)]
    dot: Option<PathBuf>,

    /// Emit an SVG topology file with live link and probe status overlays.
    #[arg(long)]
    svg: Option<PathBuf>,

    /// Emit per-node connectivity summary after settling.
    #[arg(long)]
    list_links: bool,

    /// Increase logging to info.
    #[arg(short, long)]
    verbose: bool,
}

struct SimNode {
    node: Arc<Node>,
    peer_id: tarnet::types::PeerId,
    kind: NodeKind,
}

struct ProbeOutcome {
    pair: ProbePair,
    cost: Option<u16>,
    elapsed: Duration,
}

const PHASE_COUNT: usize = 3;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if cli.verbose { "info" } else { "error" }),
    )
        .filter_level(if cli.verbose {
            log::LevelFilter::Info
        } else {
            log::LevelFilter::Error
        })
        .format_timestamp_millis()
        .init();
    let plan = topology::generate(cli.nodes, cli.seed);
    print_topology_summary(&plan, &cli);

    let network = InProcNetwork::new();
    let mut discoveries: Vec<Option<Box<dyn Discovery>>> = Vec::with_capacity(plan.nodes.len());
    let mut addrs = Vec::with_capacity(plan.nodes.len());
    for idx in 0..plan.nodes.len() {
        let addr = format!("inproc://{}", idx);
        let discovery = network.bind(addr.clone()).await?;
        addrs.push(discovery.local_addr().to_string());
        discoveries.push(Some(Box::new(discovery)));
    }

    let start = Instant::now();
    let mut sim_nodes: Vec<Option<SimNode>> = (0..plan.nodes.len()).map(|_| None).collect();
    let phase_pause = phase_pause(cli.settle_secs);

    for phase in 0..PHASE_COUNT {
        let phase_nodes: Vec<usize> = plan
            .spawn_order()
            .into_iter()
            .filter(|&idx| phase_for_kind(plan.nodes[idx].kind) == phase)
            .collect();
        if phase_nodes.is_empty() {
            continue;
        }

        println!(
            "phase {}: {}",
            phase + 1,
            phase_description(phase, phase_nodes.len())
        );
        for idx in phase_nodes {
            let bootstrap = essential_bootstrap(&plan, idx)
                .into_iter()
                .map(|peer| addrs[peer].clone())
                .collect::<Vec<_>>();

            let node = Arc::new(Node::new(Keypair::generate_ed25519()));
            let peer_id = node.peer_id();
            let runner = node.clone();
            let discovery = discoveries[idx].take().expect("discovery already taken");
            tokio::spawn(async move {
                let _ = runner.run(discovery, bootstrap, Vec::new()).await;
            });

            sim_nodes[idx] = Some(SimNode {
                node,
                peer_id,
                kind: plan.nodes[idx].kind,
            });

            if cli.spawn_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(cli.spawn_delay_ms)).await;
            }
        }

        if phase + 1 < PHASE_COUNT {
            println!(
                "phase {} complete, pausing {}s for upstream links and routing to settle...",
                phase + 1,
                phase_pause.as_secs()
            );
            tokio::time::sleep(phase_pause).await;
        }
    }

    let sim_nodes: Vec<SimNode> = sim_nodes.into_iter().map(|node| node.unwrap()).collect();
    println!(
        "spawned {} nodes in {:.2}s",
        sim_nodes.len(),
        start.elapsed().as_secs_f64()
    );

    println!("phase 4: attaching deferred/optional links (secondary uplinks, shortcuts, repeater extras)...");
    attach_deferred_links(&network, &plan, &sim_nodes, &addrs, cli.parallel_tests.max(8)).await;

    println!("final settle: waiting {}s for full-network convergence...", cli.settle_secs);
    tokio::time::sleep(Duration::from_secs(cli.settle_secs)).await;

    let link_snapshot = collect_link_snapshot(&sim_nodes).await;
    let actual_links = link_snapshot.edges.len();
    let isolated = link_snapshot
        .per_node_counts
        .iter()
        .filter(|count| **count == 0)
        .count();
    let avg_degree = link_snapshot.per_node_counts.iter().sum::<usize>() as f64
        / link_snapshot.per_node_counts.len() as f64;
    println!(
        "links: expected={}, actual={}, isolated={}, avg_degree={:.2}",
        plan.expected_links, actual_links, isolated, avg_degree
    );

    if cli.list_links {
        for (idx, count) in link_snapshot.per_node_counts.iter().enumerate() {
            println!("  node {:4} {:10} peers={}", idx, sim_nodes[idx].kind, count);
        }
    }

    let pairs = topology::sample_probe_pairs(&plan, cli.probes, cli.seed);
    println!(
        "probing {} pairs (parallel_tests={})...",
        pairs.len(),
        if cli.parallel_tests == 0 {
            "unlimited".to_string()
        } else {
            cli.parallel_tests.to_string()
        }
    );
    let outcomes = run_probes(&sim_nodes, pairs, cli.parallel_tests).await;
    print_probe_summary(&outcomes);

    if let Some(dot_path) = cli.dot.as_deref() {
        topology::write_dot(dot_path, &plan, &outcomes.iter().map(|o| o.pair.clone()).collect::<Vec<_>>())?;
        println!("wrote {}", dot_path.display());
    }

    if let Some(svg_path) = cli.svg.as_deref() {
        let (
            probe_successes,
            probe_failures,
            probe_success_rate,
            median_probe_ms,
            median_probe_cost,
        ) =
            probe_summary_numbers(&outcomes);
        let probe_render: Vec<ProbeRender> = outcomes
            .iter()
            .map(|outcome| ProbeRender {
                src: outcome.pair.src,
                dst: outcome.pair.dst,
                ok: outcome.cost.is_some(),
                label: format!(
                    "{} {}",
                    outcome.pair.label,
                    outcome
                        .cost
                        .map(|cost| format!("cost={cost}"))
                        .unwrap_or_else(|| "failed".to_string())
                ),
            })
            .collect();
        let summary = SvgSummary {
            nodes: cli.nodes,
            seed: cli.seed,
            settle_secs: cli.settle_secs,
            probes: cli.probes,
            parallel_tests: cli.parallel_tests,
            expected_links: plan.expected_links,
            actual_links,
            isolated_nodes: isolated,
            avg_degree,
            probe_successes,
            probe_failures,
            probe_success_rate,
            median_probe_ms,
            median_probe_cost,
        };
        topology::write_svg(svg_path, &plan, &link_snapshot.edges, &probe_render, &summary)?;
        println!("wrote {}", svg_path.display());
    }

    Ok(())
}

struct LinkSnapshot {
    per_node_counts: Vec<usize>,
    edges: BTreeSet<(usize, usize)>,
}

async fn collect_link_snapshot(sim_nodes: &[SimNode]) -> LinkSnapshot {
    let peer_map: Arc<HashMap<tarnet::types::PeerId, usize>> = Arc::new(
        sim_nodes
            .iter()
            .enumerate()
            .map(|(idx, sim)| (sim.peer_id, idx))
            .collect(),
    );
    let mut handles = Vec::with_capacity(sim_nodes.len());
    for sim in sim_nodes {
        let node = sim.node.clone();
        let peer_map = peer_map.clone();
        handles.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), node.connected_peers())
                .await
                .map(|peers| {
                    peers.into_iter()
                        .filter_map(|peer| peer_map.get(&peer).copied())
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default()
        }));
    }

    let mut per_node = Vec::with_capacity(handles.len());
    let mut edges = BTreeSet::new();
    for (idx, handle) in handles.into_iter().enumerate() {
        let peers = handle.await.expect("connectivity task panicked");
        per_node.push(peers.len());
        for peer in peers {
            let edge = if idx < peer { (idx, peer) } else { (peer, idx) };
            edges.insert(edge);
        }
    }
    LinkSnapshot {
        per_node_counts: per_node,
        edges,
    }
}

async fn run_probes(
    sim_nodes: &[SimNode],
    pairs: Vec<ProbePair>,
    parallelism: usize,
) -> Vec<ProbeOutcome> {
    let semaphore = if parallelism == 0 {
        None
    } else {
        Some(Arc::new(tokio::sync::Semaphore::new(parallelism)))
    };
    let completed = Arc::new(AtomicUsize::new(0));
    let total = pairs.len();
    let mut tasks = Vec::with_capacity(pairs.len());

    for pair in pairs {
        let permit = if let Some(semaphore) = &semaphore {
            Some(
                semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("semaphore closed"),
            )
        } else {
            None
        };
        let src = sim_nodes[pair.src].node.clone();
        let target = sim_nodes[pair.dst].node.peer_id();
        let completed = completed.clone();
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            let cost = tokio::time::timeout(Duration::from_secs(12), src.route_probe(target))
                .await
                .ok()
                .flatten();
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            println!(
                "  probe {done}/{total}: {} -> {} {} in {:.0}ms",
                pair.src,
                pair.dst,
                cost.map(|c| format!("ok cost={c}"))
                    .unwrap_or_else(|| "failed".to_string()),
                started.elapsed().as_secs_f64() * 1_000.0
            );
            drop(permit);
            ProbeOutcome {
                pair,
                cost,
                elapsed: started.elapsed(),
            }
        }));
    }

    let mut outcomes = Vec::with_capacity(tasks.len());
    for task in tasks {
        outcomes.push(task.await.expect("probe task panicked"));
    }
    outcomes
}

fn print_topology_summary(plan: &TopologyPlan, cli: &Cli) {
    println!(
        "tarnet-topsim nodes={} seed={} settle={}s probes={}",
        cli.nodes, cli.seed, cli.settle_secs, cli.probes
    );
    for (kind, count) in plan.member_counts_by_kind() {
        println!("  {:10} {}", kind, count);
    }
    println!(
        "  households={} local_peer_links={} residential_shortcuts={} repeater_chains={} repeater_spurs={}",
        plan.stats.households,
        plan.stats.local_peer_links,
        plan.stats.residential_shortcuts,
        plan.stats.repeater_chains,
        plan.stats.repeater_spurs
    );
}

fn print_probe_summary(outcomes: &[ProbeOutcome]) {
    let (successes, failures, success_rate, median_latency_ms, median_cost) =
        probe_summary_numbers(outcomes);

    println!(
        "probe results: success={}/{} ({:.1}%) failure={} median_cost={:.2} median_probe_ms={:.1}",
        successes,
        outcomes.len(),
        success_rate,
        failures,
        median_cost,
        median_latency_ms
    );

    let mut per_label = std::collections::BTreeMap::<&'static str, (usize, usize)>::new();
    for outcome in outcomes {
        let entry = per_label.entry(outcome.pair.label).or_insert((0, 0));
        entry.0 += 1;
        if outcome.cost.is_some() {
            entry.1 += 1;
        }
    }
    for (label, (total, ok)) in per_label {
        let pct = if total == 0 {
            0.0
        } else {
            ok as f64 * 100.0 / total as f64
        };
        println!("  {:18} {}/{} ({:.1}%)", label, ok, total, pct);
    }

    for outcome in outcomes.iter().filter(|outcome| outcome.cost.is_none()).take(10) {
        println!(
            "  unreachable {} -> {} ({})",
            outcome.pair.src, outcome.pair.dst, outcome.pair.label
        );
    }
}

fn probe_summary_numbers(outcomes: &[ProbeOutcome]) -> (usize, usize, f64, f64, f64) {
    let successes: Vec<&ProbeOutcome> = outcomes
        .iter()
        .filter(|outcome| outcome.cost.is_some())
        .collect();
    let success_count = successes.len();
    let failures = outcomes.len().saturating_sub(success_count);
    let success_rate = if outcomes.is_empty() {
        0.0
    } else {
        success_count as f64 * 100.0 / outcomes.len() as f64
    };
    let median_latency_ms = median(
        outcomes
            .iter()
            .map(|outcome| outcome.elapsed.as_secs_f64() * 1_000.0)
            .collect(),
    );
    let median_cost = median(
        successes
            .iter()
            .map(|outcome| outcome.cost.unwrap() as f64)
            .collect(),
    );
    (success_count, failures, success_rate, median_latency_ms, median_cost)
}

fn median(mut values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2.0
    }
}

fn phase_for_kind(kind: NodeKind) -> usize {
    match kind {
        NodeKind::InternetExchange
        | NodeKind::CityDistributor
        | NodeKind::RegionalDistributor
        | NodeKind::LocalDistributor => 0,
        NodeKind::Gateway => 1,
        NodeKind::Device | NodeKind::Repeater => 2,
    }
}

fn essential_bootstrap(plan: &TopologyPlan, idx: usize) -> Vec<usize> {
    let node = &plan.nodes[idx];
    match node.kind {
        NodeKind::InternetExchange | NodeKind::Repeater => node.bootstrap.clone(),
        _ => node.bootstrap.iter().copied().take(1).collect(),
    }
}

fn deferred_bootstrap(plan: &TopologyPlan, idx: usize) -> Vec<usize> {
    let node = &plan.nodes[idx];
    match node.kind {
        NodeKind::InternetExchange | NodeKind::Repeater => Vec::new(),
        _ => node.bootstrap.iter().copied().skip(1).collect(),
    }
}

fn phase_pause(settle_secs: u64) -> Duration {
    let secs = (settle_secs / 3).max(1);
    Duration::from_secs(secs)
}

fn phase_description(phase: usize, count: usize) -> String {
    match phase {
        0 => format!(
            "spawning {} core nodes (IX, city, regional, local distributors)",
            count
        ),
        1 => format!("spawning {} gateway nodes (homes coming online)", count),
        2 => format!(
            "spawning {} edge/repeater nodes (devices and long-haul relays)",
            count
        ),
        _ => format!("spawning {} nodes", count),
    }
}

async fn attach_deferred_links(
    network: &InProcNetwork,
    plan: &TopologyPlan,
    sim_nodes: &[SimNode],
    addrs: &[String],
    parallelism: usize,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(parallelism.max(1)));
    let mut tasks = Vec::new();

    for idx in 0..plan.nodes.len() {
        for peer in deferred_bootstrap(plan, idx) {
            let permit = semaphore.clone().acquire_owned().await.expect("semaphore closed");
            let network = network.clone();
            let addr = addrs[peer].clone();
            let expected_peer = sim_nodes[peer].peer_id;
            let node = sim_nodes[idx].node.clone();
            let identity = node.identity_clone();
            let event_tx = node.event_sender();
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let Ok(transport) = network.connect(&addr).await else {
                    return;
                };
                let Ok(link) = PeerLink::initiator(transport, &identity, Some(expected_peer)).await else {
                    return;
                };
                let _ = event_tx
                    .send(NodeEvent::LinkUp(link.remote_peer(), Arc::new(link)))
                    .await;
            }));
        }
    }

    for task in tasks {
        let _ = task.await;
    }
}
