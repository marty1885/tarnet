use serde::{Deserialize, Serialize};

use crate::topology::{NodeKind, TopologyPlan, TopologyStats};

#[derive(Debug, Clone, Deserialize)]
pub struct RunConfig {
    pub bind_addr: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default = "default_probes")]
    pub probes: usize,
    #[serde(default = "default_settle_secs")]
    pub settle_secs: u64,
    #[serde(default)]
    pub parallel_tests: usize,
    #[serde(default = "default_join_timeout_secs")]
    pub join_timeout_secs: u64,
    #[serde(default = "default_prepare_timeout_secs")]
    pub prepare_timeout_secs: u64,
    #[serde(default)]
    pub svg: Option<String>,
    #[serde(default)]
    pub dot: Option<String>,
    /// SVG layers: comma-separated (links, missing-links, extra-links, probes, failed-probes, all, errors).
    #[serde(default = "default_svg_layers")]
    pub svg_layers: String,
    pub workers: Vec<RunWorkerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunWorkerConfig {
    pub worker_id: String,
    pub country: String,
    pub nodes: usize,
    #[serde(default = "default_seed")]
    pub seed: u64,
    #[serde(default)]
    pub advertise_host: Option<String>,
    #[serde(default)]
    pub pos: Option<[f64; 2]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerManifest {
    pub nodes: usize,
    pub seed: u64,
    pub country: String,
    pub advertise_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMsg {
    pub worker_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedNode {
    pub local_idx: usize,
    pub kind: NodeKind,
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedMsg {
    pub worker_id: String,
    pub country: String,
    pub plan: TopologyPlan,
    pub exported_nodes: Vec<ExportedNode>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    DomesticCore,
    InternationalCore,
    Gateways,
    Edge,
    OptionalLinks,
    FinalSettle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseStatusMsg {
    pub worker_id: String,
    pub phase: Phase,
    pub detail: String,
    pub started_nodes: usize,
    pub planned_international_links: usize,
    pub established_international_links: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternationalLinkAssignment {
    pub edge_id: usize,
    pub local_idx: usize,
    pub remote_worker_id: String,
    pub remote_idx: usize,
    pub remote_addr: String,
    pub dial: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmMsg {
    pub run_id: String,
    pub assignments: Vec<InternationalLinkAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePeerInventory {
    pub local_idx: usize,
    pub peer_id: [u8; 32],
    pub connected: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalInventoryMsg {
    pub worker_id: String,
    pub inventories: Vec<NodePeerInventory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTask {
    pub src_local_idx: usize,
    pub src_global_idx: usize,
    pub dst_global_idx: usize,
    pub dst_peer_id: [u8; 32],
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunProbesMsg {
    pub parallel_tests: usize,
    pub probes: Vec<ProbeTask>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResultMsg {
    pub worker_id: String,
    pub src_global_idx: usize,
    pub dst_global_idx: usize,
    pub label: String,
    pub cost: Option<u16>,
    pub elapsed_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordinatorToWorker {
    RegisterAck { run_id: String, manifest: WorkerManifest },
    Arm(ArmMsg),
    StartPhase { phase: Phase, settle_secs: u64 },
    RunProbes(RunProbesMsg),
    Complete,
    Abort { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerToCoordinator {
    Register(RegisterMsg),
    Prepared(PreparedMsg),
    Armed { worker_id: String },
    PhaseStatus(PhaseStatusMsg),
    FinalInventory(FinalInventoryMsg),
    ProbeResults {
        worker_id: String,
        results: Vec<ProbeResultMsg>,
    },
    Failed {
        worker_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct WorkerPlacement {
    pub worker_id: String,
    pub pos: (f64, f64),
    pub plan: TopologyPlan,
    pub exported_nodes: Vec<ExportedNode>,
    pub node_offset: usize,
    pub city_offset: usize,
    pub local_offset: usize,
    pub household_offset: usize,
}

#[derive(Debug, Clone)]
pub struct MergedPlan {
    pub plan: TopologyPlan,
    pub worker_ranges: Vec<(String, std::ops::Range<usize>)>,
}

pub fn default_probes() -> usize {
    48
}

pub fn default_settle_secs() -> u64 {
    15
}

pub fn default_join_timeout_secs() -> u64 {
    60
}

pub fn default_prepare_timeout_secs() -> u64 {
    60
}

pub fn default_seed() -> u64 {
    1
}

fn default_svg_layers() -> String {
    "all".to_string()
}

pub fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::DomesticCore => "domestic core",
        Phase::InternationalCore => "international ix tcp links",
        Phase::Gateways => "gateways",
        Phase::Edge => "edge and repeaters",
        Phase::OptionalLinks => "optional domestic links",
        Phase::FinalSettle => "final settle",
    }
}

pub fn merge_worker_plans(
    placements: &[WorkerPlacement],
    international_edges: &[(usize, usize)],
) -> MergedPlan {
    let mut nodes = Vec::new();
    let mut stats = TopologyStats::default();
    let mut worker_ranges = Vec::new();

    for placement in placements {
        let start = nodes.len();
        for node in &placement.plan.nodes {
            let mut merged = node.clone();
            merged.id = placement.node_offset + node.id;
            merged.pos = (node.pos.0 + placement.pos.0, node.pos.1 + placement.pos.1);
            merged.bootstrap = node
                .bootstrap
                .iter()
                .map(|peer| placement.node_offset + *peer)
                .collect();
            merged.city = node.city.map(|city| placement.city_offset + city);
            merged.local = node.local.map(|local| placement.local_offset + local);
            merged.household = node.household.map(|hh| placement.household_offset + hh);
            nodes.push(merged);
        }
        worker_ranges.push((
            placement.worker_id.clone(),
            start..(start + placement.plan.nodes.len()),
        ));
        stats.households += placement.plan.stats.households;
        stats.residential_shortcuts += placement.plan.stats.residential_shortcuts;
        stats.local_peer_links += placement.plan.stats.local_peer_links;
        stats.repeater_chains += placement.plan.stats.repeater_chains;
        stats.repeater_spurs += placement.plan.stats.repeater_spurs;
    }

    for &(a, b) in international_edges {
        nodes[a].bootstrap.push(b);
    }

    let expected_links = nodes.iter().map(|node| node.bootstrap.len()).sum();
    MergedPlan {
        plan: TopologyPlan {
            nodes,
            expected_links,
            stats,
        },
        worker_ranges,
    }
}

pub fn compute_country_positions(workers: &[RunWorkerConfig]) -> Vec<(f64, f64)> {
    let radius = 1_600_000.0 + workers.len() as f64 * 220_000.0;
    workers
        .iter()
        .enumerate()
        .map(|(idx, worker)| {
            if let Some([x, y]) = worker.pos {
                (x, y)
            } else {
                let angle = std::f64::consts::TAU * idx as f64 / workers.len().max(1) as f64;
                (radius * angle.cos(), radius * angle.sin())
            }
        })
        .collect()
}
