use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tarnet::identity::Keypair;
use tarnet::link::PeerLink;
use tarnet::node::{Node, NodeEvent};
use tarnet::transport::tcp::{TcpDiscovery, TcpTransport};
use tarnet::transport::{Discovery, MultiDiscovery};
use tarnet::types::PeerId;
use tokio::net::TcpStream;

use crate::cluster::{ExportedNode, InternationalLinkAssignment, NodePeerInventory, Phase};
use crate::inproc::InProcNetwork;
use crate::topology::{NodeKind, ProbePair, TopologyPlan};

pub struct SimNode {
    pub node: Arc<Node>,
    pub peer_id: PeerId,
}

pub struct LocalRuntime {
    pub plan: TopologyPlan,
    network: InProcNetwork,
    discoveries: Vec<Option<Box<dyn Discovery>>>,
    addrs: Vec<String>,
    pub exported_nodes: Vec<ExportedNode>,
    sim_nodes: Vec<Option<SimNode>>,
    started_nodes: usize,
    /// Force every routing table down to this many destinations, so
    /// landmarks and the address directory run at simulation scale.
    pub route_budget: Option<usize>,
    /// Probe by building a circuit and opening a stream, not by waiting for
    /// a route (scoped tables have no route to most destinations).
    pub circuit_probes: bool,
}

/// Port every node listens on for circuit probes.
const PROBE_PORT: &str = "topsim-probe";
const PROBE_MODE: tarnet_api::service::PortMode = tarnet_api::service::PortMode::ReliableOrdered;

pub struct ProbeOutcome {
    pub pair: ProbePair,
    pub cost: Option<u16>,
    pub elapsed: Duration,
}

impl LocalRuntime {
    pub async fn prepare(
        worker_id: &str,
        plan: TopologyPlan,
        tcp_bind: &str,
        export_ix_tcp: bool,
        tcp_advertise_host: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let network = InProcNetwork::new();
        let mut discoveries: Vec<Option<Box<dyn Discovery>>> = Vec::with_capacity(plan.nodes.len());
        let mut addrs = Vec::with_capacity(plan.nodes.len());
        let mut exported_nodes = Vec::new();
        let export_indices: HashSet<usize> = plan
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| {
                matches!(
                    node.kind,
                    NodeKind::InternetExchange | NodeKind::CityDistributor
                )
            })
            .map(|(idx, _)| idx)
            .collect();

        for idx in 0..plan.nodes.len() {
            let addr = format!("inproc://{worker_id}/{idx}");
            let inproc = network.bind(addr.clone()).await?;
            addrs.push(inproc.local_addr().to_string());

            if export_ix_tcp && export_indices.contains(&idx) {
                let tcp = TcpDiscovery::bind(&[tcp_bind.to_string()]).await?;
                let tcp_addrs = tcp
                    .local_addrs()
                    .iter()
                    .map(|addr| advertise_addr(*addr, tcp_advertise_host))
                    .collect::<Vec<_>>();
                discoveries.push(Some(Box::new(MultiDiscovery::new(vec![
                    Box::new(inproc),
                    Box::new(tcp),
                ]))));
                exported_nodes.push(ExportedNode {
                    local_idx: idx,
                    kind: plan.nodes[idx].kind,
                    addrs: tcp_addrs,
                });
            } else {
                discoveries.push(Some(Box::new(inproc)));
            }
        }

        let sim_nodes = (0..plan.nodes.len()).map(|_| None).collect();
        Ok(Self {
            plan,
            network,
            discoveries,
            addrs,
            exported_nodes,
            sim_nodes,
            started_nodes: 0,
            route_budget: None,
            circuit_probes: false,
        })
    }

    pub async fn start_phase(
        &mut self,
        phase: Phase,
        spawn_delay_ms: u64,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let target_phase = match phase {
            Phase::DomesticCore => Some(0),
            Phase::Gateways => Some(1),
            Phase::Edge => Some(2),
            _ => None,
        };
        let Some(target_phase) = target_phase else {
            return Ok(0);
        };

        let phase_nodes: Vec<usize> = self
            .plan
            .spawn_order()
            .into_iter()
            .filter(|&idx| phase_for_kind(self.plan.nodes[idx].kind) == target_phase)
            .collect();

        for idx in &phase_nodes {
            let bootstrap = essential_bootstrap(&self.plan, *idx)
                .into_iter()
                .map(|peer| self.addrs[peer].clone())
                .collect::<Vec<_>>();

            let node = Arc::new(Node::new(Keypair::generate()));
            if let Some(budget) = self.route_budget {
                node.set_route_budget(budget).await;
                node.set_landmark_config(tarnet::node::LandmarkConfig {
                    promote_delay_max: Duration::from_secs(10),
                    publish_gap: Duration::from_secs(5),
                    ..Default::default()
                })
                .await;
            }
            if self.circuit_probes {
                let listener = node
                    .circuit_listen(
                        tarnet_api::types::ServiceId::ALL,
                        PROBE_MODE,
                        PROBE_PORT,
                        tarnet_api::service::ListenerOptions::default(),
                    )
                    .await?;
                let acceptor = node.clone();
                tokio::spawn(async move {
                    while let Ok(conn) = acceptor.circuit_accept(listener.id).await {
                        tokio::spawn(async move {
                            while let Ok(data) = conn.recv().await {
                                if conn.send(&data).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                });
            }
            let peer_id = node.peer_id();
            let runner = node.clone();
            let discovery = self.discoveries[*idx]
                .take()
                .expect("discovery already taken for node");
            tokio::spawn(async move {
                let _ = runner.run(discovery, bootstrap, Vec::new()).await;
            });
            self.sim_nodes[*idx] = Some(SimNode {
                node,
                peer_id,
            });
            self.started_nodes += 1;
            if spawn_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(spawn_delay_ms)).await;
            }
        }

        Ok(phase_nodes.len())
    }

    pub async fn attach_deferred_links(&self, parallelism: usize) {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(parallelism.max(1)));
        let mut tasks = Vec::new();

        for idx in 0..self.plan.nodes.len() {
            for peer in deferred_bootstrap(&self.plan, idx) {
                let permit = semaphore.clone().acquire_owned().await.expect("semaphore closed");
                let network = self.network.clone();
                let addr = self.addrs[peer].clone();
                let expected_peer = self.sim_nodes[peer].as_ref().expect("peer not started").peer_id;
                let node = self.sim_nodes[idx]
                    .as_ref()
                    .expect("node not started")
                    .node
                    .clone();
                let identity = node.identity_clone();
                let event_tx = node.event_sender();
                tasks.push(tokio::spawn(async move {
                    let _permit = permit;
                    tokio::time::timeout(LINK_ATTACH_TIMEOUT, async move {
                        let Ok(transport) = network.connect(&addr).await else {
                            return false;
                        };
                        let Ok(link) =
                            PeerLink::initiator(transport, &identity, Some(expected_peer)).await
                        else {
                            return false;
                        };
                        event_tx
                            .send(NodeEvent::LinkUp(link.remote_peer(), Arc::new(link)))
                            .await
                            .is_ok()
                    })
                    .await
                    .unwrap_or(false)
                }));
            }
        }

        for task in tasks {
            let _ = task.await;
        }
    }

    pub async fn attach_international_links(
        &self,
        assignments: &[InternationalLinkAssignment],
        parallelism: usize,
    ) -> usize {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(parallelism.max(1)));
        let mut tasks = Vec::new();

        for assignment in assignments.iter().filter(|assignment| assignment.dial) {
            let permit = semaphore.clone().acquire_owned().await.expect("semaphore closed");
            let node = self.sim_nodes[assignment.local_idx]
                .as_ref()
                .expect("international node not started")
                .node
                .clone();
            let identity = node.identity_clone();
            let event_tx = node.event_sender();
            let remote_addr = assignment.remote_addr.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                tokio::time::timeout(LINK_ATTACH_TIMEOUT, async move {
                    let stream = TcpStream::connect(&remote_addr).await.ok()?;
                    stream.set_nodelay(true).ok()?;
                    let transport = Box::new(TcpTransport::new(stream));
                    let link = PeerLink::initiator(transport, &identity, None).await.ok()?;
                    event_tx
                        .send(NodeEvent::LinkUp(link.remote_peer(), Arc::new(link)))
                        .await
                        .ok()?;
                    Some(())
                })
                .await
                .ok()
                .flatten()
            }));
        }

        let mut successes = 0;
        for task in tasks {
            if task.await.ok().flatten().is_some() {
                successes += 1;
            }
        }
        successes
    }

    pub async fn collect_inventory(&self) -> Vec<NodePeerInventory> {
        let mut tasks = Vec::with_capacity(self.sim_nodes.len());
        for (idx, sim) in self.sim_nodes.iter().enumerate() {
            let sim = sim.as_ref().expect("node not started");
            let node = sim.node.clone();
            let peer_id = sim.peer_id;
            tasks.push(tokio::spawn(async move {
                let peers = tokio::time::timeout(Duration::from_secs(2), node.connected_peers())
                    .await
                    .unwrap_or_default();
                NodePeerInventory {
                    local_idx: idx,
                    peer_id: peer_id.0,
                    connected: peers.into_iter().map(|peer| peer.0).collect(),
                }
            }));
        }

        let mut inventories = Vec::with_capacity(tasks.len());
        for task in tasks {
            inventories.push(task.await.expect("inventory task panicked"));
        }
        inventories
    }

    pub async fn run_probe_tasks(
        &self,
        tasks: Vec<(usize, usize, usize, String, PeerId)>,
        parallelism: usize,
    ) -> Vec<(usize, usize, String, Option<u16>, f64)> {
        let semaphore = if parallelism == 0 {
            None
        } else {
            Some(Arc::new(tokio::sync::Semaphore::new(parallelism)))
        };
        let completed = Arc::new(AtomicUsize::new(0));
        let total = tasks.len();
        let mut handles = Vec::with_capacity(tasks.len());

        let mut services = HashMap::new();
        if self.circuit_probes {
            for sim in self.sim_nodes.iter().flatten() {
                services.insert(sim.peer_id, sim.node.default_service_id().await);
            }
        }
        let circuit_probes = self.circuit_probes;
        for (src_local_idx, src_global_idx, dst_global_idx, label, dst_peer) in tasks {
            let dst_service = services.get(&dst_peer).copied();
            let permit = if let Some(semaphore) = &semaphore {
                Some(
                    semaphore
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("probe semaphore closed"),
                )
            } else {
                None
            };
            let src = self.sim_nodes[src_local_idx]
                .as_ref()
                .expect("probe source not started")
                .node
                .clone();
            let completed = completed.clone();
            handles.push(tokio::spawn(async move {
                let started = Instant::now();
                let cost = if circuit_probes {
                    // Build a circuit and echo one message over it.
                    let probe = async {
                        let service = dst_service?;
                        let conn = src
                            .circuit_connect(service, PROBE_MODE, PROBE_PORT, Some(dst_peer), None)
                            .await
                            .ok()?;
                        conn.send(b"probe").await.ok()?;
                        let back = conn.recv().await.ok()?;
                        (back == b"probe").then_some(())
                    };
                    match tokio::time::timeout(Duration::from_secs(90), probe).await {
                        Ok(Some(())) => Some(
                            src.route_cost(&dst_peer)
                                .await
                                .map_or(0, |c| c.min(u16::MAX as u32) as u16),
                        ),
                        _ => None,
                    }
                } else {
                // Wait for distance-vector routing to learn the destination.
                tokio::time::timeout(Duration::from_secs(12), async {
                    loop {
                        if let Some(c) = src.route_cost(&dst_peer).await {
                            break c.min(u16::MAX as u32) as u16;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                })
                .await
                .ok()
                };
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                println!(
                    "  probe {done}/{total}: {src_global_idx} -> {dst_global_idx} {} in {:.0}ms",
                    cost.map(|c| format!("ok cost={c}"))
                        .unwrap_or_else(|| "failed".to_string()),
                    started.elapsed().as_secs_f64() * 1_000.0
                );
                drop(permit);
                (
                    src_global_idx,
                    dst_global_idx,
                    label,
                    cost,
                    started.elapsed().as_secs_f64() * 1_000.0,
                )
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.expect("probe task panicked"));
        }
        results
    }

    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.sim_nodes
            .iter()
            .map(|sim| sim.as_ref().expect("node not started").peer_id)
            .collect()
    }

    pub fn started_nodes(&self) -> usize {
        self.started_nodes
    }
}

fn advertise_addr(addr: SocketAddr, override_host: Option<&str>) -> String {
    if let Some(host) = override_host {
        return format!("{host}:{}", addr.port());
    }
    if addr.ip().is_unspecified() {
        match addr {
            SocketAddr::V4(_) => format!("127.0.0.1:{}", addr.port()),
            SocketAddr::V6(_) => format!("[::1]:{}", addr.port()),
        }
    } else {
        addr.to_string()
    }
}

pub fn collect_link_snapshot_from_inventory(
    inventories: &[NodePeerInventory],
    peer_map: &HashMap<[u8; 32], usize>,
) -> (Vec<usize>, BTreeSet<(usize, usize)>) {
    let mut per_node_counts = vec![0; inventories.len()];
    let mut edges = BTreeSet::new();
    for inventory in inventories {
        let src = inventory.local_idx;
        let mut unique = HashSet::new();
        for peer in &inventory.connected {
            if let Some(dst) = peer_map.get(peer).copied() {
                if unique.insert(dst) {
                    per_node_counts[src] += 1;
                    let edge = if src < dst { (src, dst) } else { (dst, src) };
                    edges.insert(edge);
                }
            }
        }
    }
    (per_node_counts, edges)
}

pub fn print_topology_summary(plan: &TopologyPlan, nodes: usize, seed: u64, settle_secs: u64, probes: usize) {
    println!("tarnet-topsim nodes={nodes} seed={seed} settle={}s probes={probes}", settle_secs);
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

pub fn print_probe_summary(outcomes: &[ProbeOutcome]) {
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
    let mut per_label = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    for outcome in outcomes {
        let entry = per_label.entry(&outcome.pair.label).or_insert((0, 0));
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
}

pub fn probe_summary_numbers(outcomes: &[ProbeOutcome]) -> (usize, usize, f64, f64, f64) {
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

pub fn median(mut values: Vec<f64>) -> f64 {
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

pub fn phase_for_kind(kind: NodeKind) -> usize {
    match kind {
        NodeKind::InternetExchange
        | NodeKind::CityDistributor
        | NodeKind::RegionalDistributor
        | NodeKind::LocalDistributor => 0,
        NodeKind::Gateway => 1,
        NodeKind::Device | NodeKind::Repeater => 2,
    }
}

pub fn essential_bootstrap(plan: &TopologyPlan, idx: usize) -> Vec<usize> {
    let node = &plan.nodes[idx];
    match node.kind {
        NodeKind::InternetExchange | NodeKind::Repeater => node.bootstrap.clone(),
        _ => node.bootstrap.iter().copied().take(1).collect(),
    }
}

pub fn deferred_bootstrap(plan: &TopologyPlan, idx: usize) -> Vec<usize> {
    let node = &plan.nodes[idx];
    match node.kind {
        NodeKind::InternetExchange | NodeKind::Repeater => Vec::new(),
        _ => node.bootstrap.iter().copied().skip(1).collect(),
    }
}
const LINK_ATTACH_TIMEOUT: Duration = Duration::from_secs(8);
