mod cluster;
mod inproc;
mod sim;
mod topology;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use cluster::{
    compute_country_positions, merge_worker_plans, phase_name, ArmMsg, CoordinatorToWorker,
    FinalInventoryMsg, InternationalLinkAssignment, Phase, PhaseStatusMsg, PreparedMsg, ProbeResultMsg,
    RegisterMsg, RunConfig, RunProbesMsg, WorkerManifest, WorkerPlacement, WorkerToCoordinator,
};
use serde::de::DeserializeOwned;
use sim::{LocalRuntime, ProbeOutcome};
use tarnet::types::PeerId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use topology::{ProbePair, ProbeRender, SvgSummary, TopologyPlan};

#[derive(Parser, Debug)]
#[command(
    name = "tarnet-topsim",
    about = "Spawn a geographically-shaped test topology using real tarnet transport and DV routing"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    local: LocalCli,
}

#[derive(Subcommand, Debug)]
enum Command {
    Coordinator(CoordinatorCli),
    Worker(WorkerCli),
}

#[derive(Args, Debug, Clone)]
struct LocalCli {
    #[arg(short, long, default_value_t = 256)]
    nodes: usize,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    #[arg(short, long, default_value_t = 48)]
    probes: usize,
    #[arg(long, default_value_t = 15)]
    settle_secs: u64,
    #[arg(long = "parallel-tests", visible_alias = "parallel-probes", default_value_t = 0)]
    parallel_tests: usize,
    #[arg(long, default_value_t = 0)]
    spawn_delay_ms: u64,
    #[arg(long)]
    dot: Option<PathBuf>,
    #[arg(long)]
    svg: Option<PathBuf>,
    #[arg(long)]
    list_links: bool,
    #[arg(short, long)]
    verbose: bool,
    /// SVG layers to render (comma-separated).
    /// Layers: links, missing-links, extra-links, probes, failed-probes.
    /// Shorthands: all (default), errors (missing-links + failed-probes).
    /// Example: --svg-layers errors,links
    #[arg(long, default_value = "all")]
    svg_layers: String,
}

#[derive(Args, Debug)]
struct CoordinatorCli {
    #[arg(long)]
    run: PathBuf,
    #[arg(short, long)]
    verbose: bool,
    /// SVG layers to render (comma-separated).
    /// Layers: links, missing-links, extra-links, probes, failed-probes.
    /// Shorthands: all (default), errors (missing-links + failed-probes).
    #[arg(long, default_value = "all")]
    svg_layers: String,
}

#[derive(Args, Debug)]
struct WorkerCli {
    #[arg(long)]
    worker_id: String,
    #[arg(long)]
    coordinator: String,
    #[arg(long, default_value = "0.0.0.0:0")]
    tcp_bind: String,
    #[arg(short, long)]
    verbose: bool,
}

struct WorkerConn {
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    manifest: WorkerManifest,
    prepared: Option<PreparedMsg>,
    armed: bool,
    final_inventory: Option<FinalInventoryMsg>,
    probe_results: Vec<ProbeResultMsg>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let verbose = match &cli.command {
        Some(Command::Coordinator(cmd)) => cmd.verbose,
        Some(Command::Worker(cmd)) => cmd.verbose,
        None => cli.local.verbose,
    };
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if verbose { "info" } else { "error" }),
    )
    .filter_level(if verbose {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Error
    })
    .format_timestamp_millis()
    .init();

    match cli.command {
        Some(Command::Coordinator(cmd)) => run_coordinator(cmd).await,
        Some(Command::Worker(cmd)) => run_worker(cmd).await,
        None => run_local(cli.local).await,
    }
}

async fn run_local(cli: LocalCli) -> Result<(), Box<dyn std::error::Error>> {
    let plan = topology::generate(cli.nodes, cli.seed);
    let svg_layers = topology::SvgLayers::parse(&cli.svg_layers)
        .map_err(|e| format!("--svg-layers: {}", e))?;
    sim::print_topology_summary(&plan, cli.nodes, cli.seed, cli.settle_secs, cli.probes);

    let mut runtime =
        LocalRuntime::prepare("local", plan.clone(), "127.0.0.1:0", false, None).await?;
    let phase_pause = phase_pause(cli.settle_secs);

    println!(
        "phase 1: {}",
        phase_description(Phase::DomesticCore, &plan, &runtime)
    );
    runtime.start_phase(Phase::DomesticCore, cli.spawn_delay_ms).await?;
    println!(
        "phase 1 complete, pausing {}s for upstream links and routing to settle...",
        phase_pause.as_secs()
    );
    tokio::time::sleep(phase_pause).await;

    println!("phase 2: {}", phase_description(Phase::Gateways, &runtime.plan, &runtime));
    runtime.start_phase(Phase::Gateways, cli.spawn_delay_ms).await?;
    println!(
        "phase 2 complete, pausing {}s for upstream links and routing to settle...",
        phase_pause.as_secs()
    );
    tokio::time::sleep(phase_pause).await;

    println!("phase 3: {}", phase_description(Phase::Edge, &runtime.plan, &runtime));
    runtime.start_phase(Phase::Edge, cli.spawn_delay_ms).await?;

    println!("phase 4: attaching deferred/optional links...");
    runtime.attach_deferred_links(cli.parallel_tests.max(8)).await;

    println!(
        "final settle: waiting {}s for full-network convergence...",
        cli.settle_secs
    );
    tokio::time::sleep(Duration::from_secs(cli.settle_secs)).await;

    let inventories = runtime.collect_inventory().await;
    let peer_map = inventories
        .iter()
        .enumerate()
        .map(|(idx, inv)| (inv.peer_id, idx))
        .collect::<HashMap<_, _>>();
    let (per_node_counts, actual_links) =
        sim::collect_link_snapshot_from_inventory(&inventories, &peer_map);
    print_link_summary(&runtime.plan, &per_node_counts, &actual_links, cli.list_links);

    let pairs = topology::sample_probe_pairs(&runtime.plan, cli.probes, cli.seed);
    println!(
        "probing {} pairs (parallel_tests={})...",
        pairs.len(),
        if cli.parallel_tests == 0 {
            "unlimited".to_string()
        } else {
            cli.parallel_tests.to_string()
        }
    );
    let outcomes = run_local_probes(&runtime, pairs, cli.parallel_tests).await;
    sim::print_probe_summary(&outcomes);

    write_outputs(
        &runtime.plan,
        &actual_links,
        &outcomes,
        cli.nodes,
        cli.seed,
        cli.settle_secs,
        cli.probes,
        cli.parallel_tests,
        cli.dot.as_deref(),
        cli.svg.as_deref(),
        &svg_layers,
    )?;
    Ok(())
}

async fn run_worker(cli: WorkerCli) -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(&cli.coordinator).await?;
    let (read_half, write_half) = stream.into_split();
    let writer = Arc::new(Mutex::new(write_half));
    let mut reader = BufReader::new(read_half);

    let register = WorkerToCoordinator::Register(RegisterMsg {
        worker_id: cli.worker_id.clone(),
    });
    send_message(&writer, &register).await?;

    let ack = read_message::<CoordinatorToWorker>(&mut reader).await?;
    let (run_id, manifest) = match ack {
        CoordinatorToWorker::RegisterAck { run_id, manifest } => (run_id, manifest),
        other => return Err(format!("expected register_ack, got {other:?}").into()),
    };

    let plan = topology::generate(manifest.nodes, manifest.seed);
    sim::print_topology_summary(&plan, manifest.nodes, manifest.seed, 0, 0);
    let mut runtime =
        LocalRuntime::prepare(
            &cli.worker_id,
            plan.clone(),
            &cli.tcp_bind,
            true,
            Some(&manifest.advertise_host),
        )
        .await?;
    send_message(
        &writer,
        &WorkerToCoordinator::Prepared(PreparedMsg {
            worker_id: cli.worker_id.clone(),
            country: manifest.country.clone(),
            plan,
            exported_nodes: runtime.exported_nodes.clone(),
        }),
    )
    .await?;

    let mut assignments = Vec::new();
    loop {
        match read_message::<CoordinatorToWorker>(&mut reader).await? {
            CoordinatorToWorker::Arm(ArmMsg { assignments: links, .. }) => {
                assignments = links;
                send_message(
                    &writer,
                    &WorkerToCoordinator::Armed {
                        worker_id: cli.worker_id.clone(),
                    },
                )
                .await?;
            }
            CoordinatorToWorker::StartPhase { phase, settle_secs } => {
                let status = handle_worker_phase(
                    &cli.worker_id,
                    &mut runtime,
                    phase,
                    0,
                    settle_secs,
                    &assignments,
                )
                .await?;
                send_message(&writer, &WorkerToCoordinator::PhaseStatus(status)).await?;
                if phase == Phase::FinalSettle {
                    send_message(
                        &writer,
                        &WorkerToCoordinator::FinalInventory(FinalInventoryMsg {
                            worker_id: cli.worker_id.clone(),
                            inventories: runtime.collect_inventory().await,
                        }),
                    )
                    .await?;
                }
            }
            CoordinatorToWorker::RunProbes(msg) => {
                let tasks = msg
                    .probes
                    .into_iter()
                    .map(|probe| {
                        (
                            probe.src_local_idx,
                            probe.src_global_idx,
                            probe.dst_global_idx,
                            probe.label,
                            PeerId(probe.dst_peer_id),
                        )
                    })
                    .collect();
                let results = runtime.run_probe_tasks(tasks, msg.parallel_tests).await;
                let results = results
                    .into_iter()
                    .map(
                        |(src_global_idx, dst_global_idx, label, cost, elapsed_ms)| ProbeResultMsg {
                            worker_id: cli.worker_id.clone(),
                            src_global_idx,
                            dst_global_idx,
                            label,
                            cost,
                            elapsed_ms,
                        },
                    )
                    .collect();
                send_message(
                    &writer,
                    &WorkerToCoordinator::ProbeResults {
                        worker_id: cli.worker_id.clone(),
                        results,
                    },
                )
                .await?;
            }
            CoordinatorToWorker::Complete => break,
            CoordinatorToWorker::Abort { reason } => {
                return Err(format!("coordinator aborted run: {reason}").into());
            }
            CoordinatorToWorker::RegisterAck { .. } => {
                return Err("duplicate register_ack".into());
            }
        }
    }

    println!("worker {} completed run {}", cli.worker_id, run_id);
    Ok(())
}

async fn run_coordinator(cli: CoordinatorCli) -> Result<(), Box<dyn std::error::Error>> {
    let run: RunConfig = load_toml(&cli.run)?;
    // CLI --svg-layers overrides config; if CLI is default "all", use config value.
    let layers_spec = if cli.svg_layers == "all" { &run.svg_layers } else { &cli.svg_layers };
    let svg_layers = topology::SvgLayers::parse(layers_spec)
        .map_err(|e| format!("svg_layers: {}", e))?;
    let run_id = run
        .run_id
        .clone()
        .unwrap_or_else(|| format!("topsim-{}", chrono_like_now()));
    let listener = TcpListener::bind(&run.bind_addr).await?;
    println!(
        "coordinator listening on {} for {} workers",
        listener.local_addr()?,
        run.workers.len()
    );

    let expected = run
        .workers
        .iter()
        .map(|worker| worker.worker_id.clone())
        .collect::<BTreeSet<_>>();
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<(String, WorkerToCoordinator)>();
    let mut workers = HashMap::<String, WorkerConn>::new();

    let join_deadline = Instant::now() + Duration::from_secs(run.join_timeout_secs);
    while workers.len() < expected.len() {
        let timeout = join_deadline.saturating_duration_since(Instant::now());
        let accepted = tokio::time::timeout(timeout, listener.accept()).await??;
        let (stream, addr) = accepted;
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));
        let mut reader = BufReader::new(read_half);
        let register = match read_message::<WorkerToCoordinator>(&mut reader).await? {
            WorkerToCoordinator::Register(register) => register,
            other => return Err(format!("expected register message, got {other:?}").into()),
        };
        if !expected.contains(&register.worker_id) {
            return Err(format!("unexpected worker {}", register.worker_id).into());
        }
        let worker_cfg = run
            .workers
            .iter()
            .find(|worker| worker.worker_id == register.worker_id)
            .ok_or_else(|| format!("unexpected worker {}", register.worker_id))?;
        let advertise_host = worker_cfg
            .advertise_host
            .clone()
            .unwrap_or_else(|| addr.ip().to_string());
        let manifest = WorkerManifest {
            nodes: worker_cfg.nodes,
            seed: worker_cfg.seed,
            country: worker_cfg.country.clone(),
            advertise_host,
        };
        println!(
            "worker {} connected from {} ({}/{})",
            register.worker_id,
            addr,
            workers.len() + 1,
            expected.len()
        );
        send_message(
            &writer,
            &CoordinatorToWorker::RegisterAck {
                run_id: run_id.clone(),
                manifest: manifest.clone(),
            },
        )
        .await?;
        let worker_id = register.worker_id.clone();
        let tx = msg_tx.clone();
        tokio::spawn(async move {
            loop {
                match read_message::<WorkerToCoordinator>(&mut reader).await {
                    Ok(msg) => {
                        let _ = tx.send((worker_id.clone(), msg));
                    }
                    Err(_) => {
                        let _ = tx.send((
                            worker_id.clone(),
                            WorkerToCoordinator::Failed {
                                worker_id: worker_id.clone(),
                                reason: "control channel closed".to_string(),
                            },
                        ));
                        break;
                    }
                }
            }
        });
        workers.insert(
            register.worker_id.clone(),
            WorkerConn {
                writer,
                manifest,
                prepared: None,
                armed: false,
                final_inventory: None,
                probe_results: Vec::new(),
            },
        );
    }

    println!("all workers registered; waiting for prepared state...");
    wait_for_prepared(&mut workers, &mut msg_rx, run.prepare_timeout_secs).await?;
    let (placements, international_edges, assignments_by_worker) = build_global_plan(&run, &workers)?;
    for (worker_id, conn) in &workers {
        send_message(
            &conn.writer,
            &CoordinatorToWorker::Arm(ArmMsg {
                run_id: run_id.clone(),
                assignments: assignments_by_worker
                    .get(worker_id)
                    .cloned()
                    .unwrap_or_default(),
            }),
        )
        .await?;
    }
    wait_for_armed(&mut workers, &mut msg_rx, run.prepare_timeout_secs).await?;

    for phase in [
        Phase::DomesticCore,
        Phase::InternationalCore,
        Phase::Gateways,
        Phase::Edge,
        Phase::OptionalLinks,
        Phase::FinalSettle,
    ] {
        println!("starting phase: {}", phase_name(phase));
        for conn in workers.values() {
            send_message(
                &conn.writer,
                &CoordinatorToWorker::StartPhase {
                    phase,
                    settle_secs: run.settle_secs,
                },
            )
            .await?;
        }
        wait_for_phase(&workers, &mut msg_rx, phase).await?;
        if phase != Phase::FinalSettle {
            let pause = phase_pause(run.settle_secs);
            println!(
                "phase {} complete, pausing {}s for routing convergence...",
                phase_name(phase),
                pause.as_secs()
            );
            tokio::time::sleep(pause).await;
        }
    }

    wait_for_inventory(&mut workers, &mut msg_rx).await?;
    let merged = merge_worker_plans(&placements, &international_edges);
    let (per_node_counts, actual_links, global_peer_map) = merge_inventories(&placements, &workers, &merged.plan)?;

    let pairs = topology::sample_probe_pairs(&merged.plan, run.probes, 0xfeed_5eed);
    let probe_tasks = assign_global_probes(&placements, &workers, &merged, &pairs, &global_peer_map)?;
    println!(
        "probing {} pairs (parallel_tests={})...",
        pairs.len(),
        if run.parallel_tests == 0 {
            "unlimited".to_string()
        } else {
            run.parallel_tests.to_string()
        }
    );
    for (worker_id, conn) in &workers {
        send_message(
            &conn.writer,
            &CoordinatorToWorker::RunProbes(RunProbesMsg {
                parallel_tests: run.parallel_tests,
                probes: probe_tasks.get(worker_id).cloned().unwrap_or_default(),
            }),
        )
        .await?;
    }
    let expected_probe_results = workers.len();
    wait_for_probe_results(&mut workers, &mut msg_rx, expected_probe_results).await?;

    let all_results = workers
        .values()
        .flat_map(|conn| conn.probe_results.clone())
        .collect::<Vec<_>>();
    print_global_probe_summary(&all_results);
    print_merged_link_summary(&merged.plan, &per_node_counts, &actual_links);
    write_global_outputs(&run, &merged.plan, &actual_links, &all_results, &svg_layers)?;
    for conn in workers.values() {
        send_message(&conn.writer, &CoordinatorToWorker::Complete).await?;
    }
    println!("run {} complete", run_id);
    Ok(())
}

async fn handle_worker_phase(
    worker_id: &str,
    runtime: &mut LocalRuntime,
    phase: Phase,
    spawn_delay_ms: u64,
    settle_secs: u64,
    assignments: &[InternationalLinkAssignment],
) -> Result<PhaseStatusMsg, Box<dyn std::error::Error>> {
    match phase {
        Phase::DomesticCore | Phase::Gateways | Phase::Edge => {
            let started = runtime.start_phase(phase, spawn_delay_ms).await?;
            Ok(PhaseStatusMsg {
                worker_id: worker_id.to_string(),
                phase,
                detail: format!("started {started} nodes for {}", phase_name(phase)),
                started_nodes: runtime.started_nodes(),
                planned_international_links: assignments.len(),
                established_international_links: 0,
            })
        }
        Phase::InternationalCore => {
            let outbound = assignments.iter().filter(|assignment| assignment.dial).count();
            let up = runtime
                .attach_international_links(assignments, assignments.len().max(1))
                .await;
            Ok(PhaseStatusMsg {
                worker_id: worker_id.to_string(),
                phase,
                detail: format!(
                    "dialed {up}/{outbound} outbound direct tcp ix links ({} total assigned)",
                    assignments.len()
                ),
                started_nodes: runtime.started_nodes(),
                planned_international_links: assignments.len(),
                established_international_links: up,
            })
        }
        Phase::OptionalLinks => {
            runtime.attach_deferred_links(16).await;
            Ok(PhaseStatusMsg {
                worker_id: worker_id.to_string(),
                phase,
                detail: "attached deferred domestic links".to_string(),
                started_nodes: runtime.started_nodes(),
                planned_international_links: assignments.len(),
                established_international_links: 0,
            })
        }
        Phase::FinalSettle => {
            tokio::time::sleep(Duration::from_secs(settle_secs)).await;
            Ok(PhaseStatusMsg {
                worker_id: worker_id.to_string(),
                phase,
                detail: format!("settled for {}s", settle_secs),
                started_nodes: runtime.started_nodes(),
                planned_international_links: assignments.len(),
                established_international_links: 0,
            })
        }
    }
}

async fn wait_for_prepared(
    workers: &mut HashMap<String, WorkerConn>,
    msg_rx: &mut mpsc::UnboundedReceiver<(String, WorkerToCoordinator)>,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while workers.values().any(|conn| conn.prepared.is_none()) {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let Some((worker_id, msg)) = tokio::time::timeout(timeout, msg_rx.recv()).await? else {
            return Err("worker message channel closed before all workers prepared".into());
        };
        match msg {
            WorkerToCoordinator::Prepared(prepared) => {
                println!(
                    "prepared {}: country={} nodes={} exported_nodes={}",
                    worker_id,
                    workers
                        .get(&worker_id)
                        .map(|conn| conn.manifest.country.as_str())
                        .unwrap_or("?"),
                    workers
                        .get(&worker_id)
                        .map(|conn| conn.manifest.nodes)
                        .unwrap_or(prepared.plan.nodes.len()),
                    prepared.exported_nodes.len()
                );
                workers
                    .get_mut(&worker_id)
                    .expect("prepared from unknown worker")
                    .prepared = Some(prepared);
            }
            WorkerToCoordinator::Failed { reason, .. } => return Err(reason.into()),
            _ => {}
        }
    }
    Ok(())
}

async fn wait_for_armed(
    workers: &mut HashMap<String, WorkerConn>,
    msg_rx: &mut mpsc::UnboundedReceiver<(String, WorkerToCoordinator)>,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while workers.values().any(|conn| !conn.armed) {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let Some((worker_id, msg)) = tokio::time::timeout(timeout, msg_rx.recv()).await? else {
            return Err("worker message channel closed before all workers armed".into());
        };
        match msg {
            WorkerToCoordinator::Armed { .. } => {
                println!("armed {}", worker_id);
                workers.get_mut(&worker_id).expect("armed from unknown worker").armed = true;
            }
            WorkerToCoordinator::Failed { reason, .. } => return Err(reason.into()),
            _ => {}
        }
    }
    Ok(())
}

async fn wait_for_phase(
    workers: &HashMap<String, WorkerConn>,
    msg_rx: &mut mpsc::UnboundedReceiver<(String, WorkerToCoordinator)>,
    phase: Phase,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen = BTreeSet::new();
    while seen.len() < workers.len() {
        let Some((worker_id, msg)) = msg_rx.recv().await else {
            return Err("worker message channel closed during phase".into());
        };
        match msg {
            WorkerToCoordinator::PhaseStatus(status) if status.phase == phase => {
                println!("  {}: {}", worker_id, status.detail);
                seen.insert(worker_id);
            }
            WorkerToCoordinator::Failed { reason, .. } => return Err(reason.into()),
            _ => {}
        }
    }
    Ok(())
}

async fn wait_for_inventory(
    workers: &mut HashMap<String, WorkerConn>,
    msg_rx: &mut mpsc::UnboundedReceiver<(String, WorkerToCoordinator)>,
) -> Result<(), Box<dyn std::error::Error>> {
    while workers.values().any(|conn| conn.final_inventory.is_none()) {
        let Some((worker_id, msg)) = msg_rx.recv().await else {
            return Err("worker message channel closed while waiting for inventory".into());
        };
        match msg {
            WorkerToCoordinator::FinalInventory(inventory) => {
                workers
                    .get_mut(&worker_id)
                    .expect("inventory from unknown worker")
                    .final_inventory = Some(inventory);
            }
            WorkerToCoordinator::Failed { reason, .. } => return Err(reason.into()),
            _ => {}
        }
    }
    Ok(())
}

async fn wait_for_probe_results(
    workers: &mut HashMap<String, WorkerConn>,
    msg_rx: &mut mpsc::UnboundedReceiver<(String, WorkerToCoordinator)>,
    expected_workers: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen = BTreeSet::new();
    while seen.len() < expected_workers {
        let Some((worker_id, msg)) = msg_rx.recv().await else {
            return Err("worker message channel closed while waiting for probes".into());
        };
        match msg {
            WorkerToCoordinator::ProbeResults { results, .. } => {
                workers
                    .get_mut(&worker_id)
                    .expect("probe results from unknown worker")
                    .probe_results = results;
                seen.insert(worker_id);
            }
            WorkerToCoordinator::Failed { reason, .. } => return Err(reason.into()),
            _ => {}
        }
    }
    Ok(())
}

fn build_global_plan(
    run: &RunConfig,
    workers: &HashMap<String, WorkerConn>,
) -> Result<
    (
        Vec<WorkerPlacement>,
        Vec<(usize, usize)>,
        HashMap<String, Vec<InternationalLinkAssignment>>,
    ),
    Box<dyn std::error::Error>,
> {
    let positions = compute_country_positions(&run.workers);
    let mut placements = Vec::new();
    let mut node_offset = 0;
    let mut city_offset = 0;
    let mut local_offset = 0;
    let mut household_offset = 0;

    for (idx, worker_cfg) in run.workers.iter().enumerate() {
        let conn = workers
            .get(&worker_cfg.worker_id)
            .ok_or_else(|| format!("missing worker {}", worker_cfg.worker_id))?;
        let prepared = conn
            .prepared
            .clone()
            .ok_or_else(|| format!("worker {} missing prepared state", worker_cfg.worker_id))?;
        let city_count = prepared
            .plan
            .nodes
            .iter()
            .filter_map(|node| node.city)
            .max()
            .map(|v| v + 1)
            .unwrap_or(0);
        let local_count = prepared
            .plan
            .nodes
            .iter()
            .filter_map(|node| node.local)
            .max()
            .map(|v| v + 1)
            .unwrap_or(0);
        let household_count = prepared
            .plan
            .nodes
            .iter()
            .filter_map(|node| node.household)
            .max()
            .map(|v| v + 1)
            .unwrap_or(0);
        placements.push(WorkerPlacement {
            worker_id: worker_cfg.worker_id.clone(),
            pos: positions[idx],
            plan: prepared.plan.clone(),
            exported_nodes: prepared.exported_nodes.clone(),
            node_offset,
            city_offset,
            local_offset,
            household_offset,
        });
        node_offset += prepared.plan.nodes.len();
        city_offset += city_count;
        local_offset += local_count;
        household_offset += household_count;
    }

    let mut international_edges = Vec::new();
    let mut assignments = HashMap::<String, Vec<InternationalLinkAssignment>>::new();
    if placements.len() >= 2 {
        for idx in 0..placements.len() {
            let next = (idx + 1) % placements.len();
            if idx > next {
                continue;
            }
            let a = &placements[idx];
            let b = &placements[next];
            let a_ix = exported_by_kind(a, topology::NodeKind::InternetExchange);
            let b_ix = exported_by_kind(b, topology::NodeKind::InternetExchange);
            let ix_link_count = a_ix.len().min(b_ix.len()).clamp(1, 3);
            for link_slot in 0..ix_link_count {
                add_international_assignment(
                    &mut international_edges,
                    &mut assignments,
                    a,
                    b,
                    a_ix[link_slot % a_ix.len()],
                    b_ix[(link_slot + idx) % b_ix.len()],
                );
            }

            let a_cities = border_city_exports(a, b);
            let b_cities = border_city_exports(b, a);
            let city_link_count = a_cities.len().min(b_cities.len()).clamp(0, 2);
            for link_slot in 0..city_link_count {
                add_international_assignment(
                    &mut international_edges,
                    &mut assignments,
                    a,
                    b,
                    a_cities[link_slot],
                    b_cities[link_slot],
                );
            }
        }
    }

    Ok((placements, international_edges, assignments))
}

fn merge_inventories(
    placements: &[WorkerPlacement],
    workers: &HashMap<String, WorkerConn>,
    merged_plan: &TopologyPlan,
) -> Result<(Vec<usize>, BTreeSet<(usize, usize)>, HashMap<[u8; 32], usize>), Box<dyn std::error::Error>>
{
    let mut global_peer_map = HashMap::new();
    let mut all_inventories = Vec::new();
    for placement in placements {
        let inventory = workers
            .get(&placement.worker_id)
            .and_then(|conn| conn.final_inventory.clone())
            .ok_or_else(|| format!("worker {} missing inventory", placement.worker_id))?;
        for node in inventory.inventories {
            let global_idx = placement.node_offset + node.local_idx;
            global_peer_map.insert(node.peer_id, global_idx);
            all_inventories.push((global_idx, node.connected));
        }
    }

    let mut per_node_counts = vec![0; merged_plan.nodes.len()];
    let mut actual_links = BTreeSet::new();
    for (src, peers) in all_inventories {
        let mut unique = BTreeSet::new();
        for peer in peers {
            if let Some(dst) = global_peer_map.get(&peer).copied() {
                if unique.insert(dst) {
                    per_node_counts[src] += 1;
                    let edge = if src < dst { (src, dst) } else { (dst, src) };
                    actual_links.insert(edge);
                }
            }
        }
    }
    Ok((per_node_counts, actual_links, global_peer_map))
}

fn exported_by_kind<'a>(
    placement: &'a WorkerPlacement,
    kind: topology::NodeKind,
) -> Vec<&'a cluster::ExportedNode> {
    placement
        .exported_nodes
        .iter()
        .filter(|node| node.kind == kind)
        .collect()
}

fn border_city_exports<'a>(
    source: &'a WorkerPlacement,
    target: &'a WorkerPlacement,
) -> Vec<&'a cluster::ExportedNode> {
    let dx = target.pos.0 - source.pos.0;
    let dy = target.pos.1 - source.pos.1;
    let len = (dx * dx + dy * dy).sqrt().max(1.0);
    let ux = dx / len;
    let uy = dy / len;
    let mut cities = source
        .exported_nodes
        .iter()
        .filter(|node| node.kind == topology::NodeKind::CityDistributor)
        .map(|node| {
            let pos = source.plan.nodes[node.local_idx].pos;
            let score = pos.0 * ux + pos.1 * uy;
            (score, node)
        })
        .collect::<Vec<_>>();
    cities.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    cities.into_iter().map(|(_, node)| node).take(2).collect()
}

fn add_international_assignment(
    international_edges: &mut Vec<(usize, usize)>,
    assignments: &mut HashMap<String, Vec<InternationalLinkAssignment>>,
    a: &WorkerPlacement,
    b: &WorkerPlacement,
    a_export: &cluster::ExportedNode,
    b_export: &cluster::ExportedNode,
) {
    let edge_id = international_edges.len();
    international_edges.push((
        a.node_offset + a_export.local_idx,
        b.node_offset + b_export.local_idx,
    ));
    assignments
        .entry(a.worker_id.clone())
        .or_default()
        .push(InternationalLinkAssignment {
            edge_id,
            local_idx: a_export.local_idx,
            remote_worker_id: b.worker_id.clone(),
            remote_idx: b_export.local_idx,
            remote_addr: b_export.addrs[0].clone(),
            dial: a.worker_id < b.worker_id,
        });
    assignments
        .entry(b.worker_id.clone())
        .or_default()
        .push(InternationalLinkAssignment {
            edge_id,
            local_idx: b_export.local_idx,
            remote_worker_id: a.worker_id.clone(),
            remote_idx: a_export.local_idx,
            remote_addr: a_export.addrs[0].clone(),
            dial: b.worker_id < a.worker_id,
        });
}

fn assign_global_probes(
    placements: &[WorkerPlacement],
    workers: &HashMap<String, WorkerConn>,
    merged: &cluster::MergedPlan,
    pairs: &[ProbePair],
    peer_map: &HashMap<[u8; 32], usize>,
) -> Result<HashMap<String, Vec<cluster::ProbeTask>>, Box<dyn std::error::Error>> {
    let mut owner_by_global = HashMap::new();
    for (worker_id, range) in &merged.worker_ranges {
        for idx in range.clone() {
            owner_by_global.insert(idx, worker_id.clone());
        }
    }

    let mut local_peer_ids = HashMap::<usize, [u8; 32]>::new();
    for placement in placements {
        let inventory = workers
            .get(&placement.worker_id)
            .and_then(|conn| conn.final_inventory.clone())
            .ok_or_else(|| format!("worker {} missing inventory", placement.worker_id))?;
        for node in inventory.inventories {
            local_peer_ids.insert(placement.node_offset + node.local_idx, node.peer_id);
        }
    }

    let mut tasks = HashMap::<String, Vec<cluster::ProbeTask>>::new();
    for pair in pairs {
        let owner = owner_by_global
            .get(&pair.src)
            .ok_or_else(|| format!("no owner for global node {}", pair.src))?
            .clone();
        let placement = placements
            .iter()
            .find(|placement| placement.worker_id == owner)
            .ok_or_else(|| format!("missing placement for worker {owner}"))?;
        let dst_peer = *local_peer_ids
            .get(&pair.dst)
            .or_else(|| peer_map.iter().find_map(|(peer, idx)| (*idx == pair.dst).then_some(peer)))
            .ok_or_else(|| format!("missing destination peer id for node {}", pair.dst))?;
        tasks.entry(owner.clone()).or_default().push(cluster::ProbeTask {
            src_local_idx: pair.src - placement.node_offset,
            src_global_idx: pair.src,
            dst_global_idx: pair.dst,
            dst_peer_id: dst_peer,
            label: pair.label.to_string(),
        });
    }
    Ok(tasks)
}

fn write_outputs(
    plan: &TopologyPlan,
    actual_links: &BTreeSet<(usize, usize)>,
    outcomes: &[ProbeOutcome],
    nodes: usize,
    seed: u64,
    settle_secs: u64,
    probes: usize,
    parallel_tests: usize,
    dot: Option<&Path>,
    svg: Option<&Path>,
    svg_layers: &topology::SvgLayers,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(dot_path) = dot {
        topology::write_dot(
            dot_path,
            plan,
            &outcomes.iter().map(|outcome| outcome.pair.clone()).collect::<Vec<_>>(),
        )?;
        println!("wrote {}", dot_path.display());
    }

    if let Some(svg_path) = svg {
        let (probe_successes, probe_failures, probe_success_rate, median_probe_ms, median_probe_cost) =
            sim::probe_summary_numbers(outcomes);
        let probe_render = outcomes
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
            .collect::<Vec<_>>();
        let isolated = actual_links
            .iter()
            .flat_map(|(a, b)| [a, b])
            .collect::<BTreeSet<_>>()
            .len();
        let avg_degree = if plan.nodes.is_empty() {
            0.0
        } else {
            actual_links.len() as f64 * 2.0 / plan.nodes.len() as f64
        };
        let summary = SvgSummary {
            nodes,
            seed,
            settle_secs,
            probes,
            parallel_tests,
            expected_links: plan.expected_links,
            actual_links: actual_links.len(),
            isolated_nodes: plan.nodes.len().saturating_sub(isolated),
            avg_degree,
            probe_successes,
            probe_failures,
            probe_success_rate,
            median_probe_ms,
            median_probe_cost,
        };
        topology::write_svg(svg_path, plan, actual_links, &probe_render, &summary, svg_layers)?;
        println!("wrote {}", svg_path.display());
    }
    Ok(())
}

fn write_global_outputs(
    run: &RunConfig,
    plan: &TopologyPlan,
    actual_links: &BTreeSet<(usize, usize)>,
    results: &[ProbeResultMsg],
    svg_layers: &topology::SvgLayers,
) -> Result<(), Box<dyn std::error::Error>> {
    let probes = results
        .iter()
        .map(|result| ProbeRender {
            src: result.src_global_idx,
            dst: result.dst_global_idx,
            ok: result.cost.is_some(),
            label: format!(
                "{} {}",
                result.label,
                result
                    .cost
                    .map(|cost| format!("cost={cost}"))
                    .unwrap_or_else(|| "failed".to_string())
            ),
        })
        .collect::<Vec<_>>();
    if let Some(dot) = run.dot.as_deref() {
        topology::write_dot(
            Path::new(dot),
            plan,
            &results
                .iter()
                .map(|result| ProbePair {
                    src: result.src_global_idx,
                    dst: result.dst_global_idx,
                    label: Box::leak(result.label.clone().into_boxed_str()),
                })
                .collect::<Vec<_>>(),
        )?;
    }
    if let Some(svg) = run.svg.as_deref() {
        let (successes, failures, success_rate, median_probe_ms, median_cost) =
            summarize_probe_results(results);
        let avg_degree = if plan.nodes.is_empty() {
            0.0
        } else {
            actual_links.len() as f64 * 2.0 / plan.nodes.len() as f64
        };
        let connected_nodes = actual_links
            .iter()
            .flat_map(|(a, b)| [a, b])
            .collect::<BTreeSet<_>>()
            .len();
        let summary = SvgSummary {
            nodes: plan.nodes.len(),
            seed: 0,
            settle_secs: run.settle_secs,
            probes: run.probes,
            parallel_tests: run.parallel_tests,
            expected_links: plan.expected_links,
            actual_links: actual_links.len(),
            isolated_nodes: plan.nodes.len().saturating_sub(connected_nodes),
            avg_degree,
            probe_successes: successes,
            probe_failures: failures,
            probe_success_rate: success_rate,
            median_probe_ms,
            median_probe_cost: median_cost,
        };
        topology::write_svg(Path::new(svg), plan, actual_links, &probes, &summary, svg_layers)?;
        println!("wrote {}", svg);
    }
    Ok(())
}

fn summarize_probe_results(results: &[ProbeResultMsg]) -> (usize, usize, f64, f64, f64) {
    let successes = results.iter().filter(|result| result.cost.is_some()).count();
    let failures = results.len().saturating_sub(successes);
    let success_rate = if results.is_empty() {
        0.0
    } else {
        successes as f64 * 100.0 / results.len() as f64
    };
    let median_probe_ms = sim::median(results.iter().map(|result| result.elapsed_ms).collect());
    let median_cost = sim::median(
        results
            .iter()
            .filter_map(|result| result.cost.map(|cost| cost as f64))
            .collect(),
    );
    (successes, failures, success_rate, median_probe_ms, median_cost)
}

fn print_global_probe_summary(results: &[ProbeResultMsg]) {
    let (successes, failures, success_rate, median_probe_ms, median_cost) =
        summarize_probe_results(results);
    println!(
        "probe results: success={}/{} ({:.1}%) failure={} median_cost={:.2} median_probe_ms={:.1}",
        successes,
        results.len(),
        success_rate,
        failures,
        median_cost,
        median_probe_ms
    );
    let mut per_label = BTreeMap::<String, (usize, usize)>::new();
    for result in results {
        let entry = per_label.entry(result.label.clone()).or_insert((0, 0));
        entry.0 += 1;
        if result.cost.is_some() {
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
}

fn print_link_summary(
    plan: &TopologyPlan,
    per_node_counts: &[usize],
    actual_links: &BTreeSet<(usize, usize)>,
    list_links: bool,
) {
    let isolated = per_node_counts.iter().filter(|count| **count == 0).count();
    let avg_degree = if per_node_counts.is_empty() {
        0.0
    } else {
        per_node_counts.iter().sum::<usize>() as f64 / per_node_counts.len() as f64
    };
    println!(
        "links: expected={}, actual={}, isolated={}, avg_degree={:.2}",
        plan.expected_links,
        actual_links.len(),
        isolated,
        avg_degree
    );
    if list_links {
        for (idx, count) in per_node_counts.iter().enumerate() {
            println!("  node {:4} peers={}", idx, count);
        }
    }
}

fn print_merged_link_summary(
    plan: &TopologyPlan,
    per_node_counts: &[usize],
    actual_links: &BTreeSet<(usize, usize)>,
) {
    print_link_summary(plan, per_node_counts, actual_links, false);
}

async fn run_local_probes(
    runtime: &LocalRuntime,
    pairs: Vec<ProbePair>,
    parallel_tests: usize,
) -> Vec<ProbeOutcome> {
    let tasks = pairs
        .iter()
        .map(|pair| {
            (
                pair.src,
                pair.src,
                pair.dst,
                pair.label.to_string(),
                runtime.peer_ids()[pair.dst],
            )
        })
        .collect::<Vec<_>>();
    let results = runtime.run_probe_tasks(tasks, parallel_tests).await;
    results
        .into_iter()
        .map(|(src, dst, label, cost, elapsed_ms)| ProbeOutcome {
            pair: ProbePair {
                src,
                dst,
                label: Box::leak(label.into_boxed_str()),
            },
            cost,
            elapsed: Duration::from_secs_f64(elapsed_ms / 1_000.0),
        })
        .collect()
}

async fn send_message<T: serde::Serialize>(
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    message: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = writer.lock().await;
    let line = serde_json::to_vec(message)?;
    writer.write_all(&line).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

async fn read_message<T: DeserializeOwned>(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut line = String::new();
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        return Err("control stream closed".into());
    }
    Ok(serde_json::from_str(line.trim_end())?)
}

fn load_toml<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&text)?)
}

fn phase_pause(settle_secs: u64) -> Duration {
    Duration::from_secs((settle_secs / 3).max(1))
}

fn phase_description(phase: Phase, plan: &TopologyPlan, _runtime: &LocalRuntime) -> String {
    let count = plan
        .nodes
        .iter()
        .filter(|node| match phase {
            Phase::DomesticCore => matches!(
                node.kind,
                topology::NodeKind::InternetExchange
                    | topology::NodeKind::CityDistributor
                    | topology::NodeKind::RegionalDistributor
                    | topology::NodeKind::LocalDistributor
            ),
            Phase::Gateways => matches!(node.kind, topology::NodeKind::Gateway),
            Phase::Edge => matches!(node.kind, topology::NodeKind::Device | topology::NodeKind::Repeater),
            _ => false,
        })
        .count();
    match phase {
        Phase::DomesticCore => format!(
            "spawning {} core nodes (IX, city, regional, local distributors)",
            count
        ),
        Phase::Gateways => format!("spawning {} gateway nodes (homes coming online)", count),
        Phase::Edge => format!("spawning {} edge/repeater nodes (devices and long-haul relays)", count),
        _ => format!("starting {}", phase_name(phase)),
    }
}

fn chrono_like_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
