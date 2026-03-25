use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::io::Write;
use std::path::Path;

use rand::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    InternetExchange,
    CityDistributor,
    RegionalDistributor,
    LocalDistributor,
    Gateway,
    Device,
    Repeater,
}

impl NodeKind {
    pub fn priority(self) -> u8 {
        match self {
            NodeKind::InternetExchange => 0,
            NodeKind::CityDistributor => 1,
            NodeKind::RegionalDistributor => 2,
            NodeKind::LocalDistributor => 3,
            NodeKind::Gateway => 4,
            NodeKind::Device => 5,
            NodeKind::Repeater => 6,
        }
    }

    pub fn color(self) -> &'static str {
        match self {
            NodeKind::InternetExchange => "#d7263d",
            NodeKind::CityDistributor => "#f46036",
            NodeKind::RegionalDistributor => "#2e86ab",
            NodeKind::LocalDistributor => "#1b998b",
            NodeKind::Gateway => "#7b2cbf",
            NodeKind::Device => "#5c677d",
            NodeKind::Repeater => "#c77dff",
        }
    }

    pub fn is_edge(self) -> bool {
        matches!(self, NodeKind::Gateway | NodeKind::Device)
    }
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeKind::InternetExchange => write!(f, "ix"),
            NodeKind::CityDistributor => write!(f, "city"),
            NodeKind::RegionalDistributor => write!(f, "regional"),
            NodeKind::LocalDistributor => write!(f, "local"),
            NodeKind::Gateway => write!(f, "gateway"),
            NodeKind::Device => write!(f, "device"),
            NodeKind::Repeater => write!(f, "repeater"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePlan {
    pub id: usize,
    pub kind: NodeKind,
    pub pos: (f64, f64),
    pub bootstrap: Vec<usize>,
    pub city: Option<usize>,
    pub local: Option<usize>,
    pub household: Option<usize>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TopologyStats {
    pub households: usize,
    pub residential_shortcuts: usize,
    pub local_peer_links: usize,
    pub repeater_chains: usize,
    pub repeater_spurs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyPlan {
    pub nodes: Vec<NodePlan>,
    pub expected_links: usize,
    pub stats: TopologyStats,
}

impl TopologyPlan {
    pub fn member_counts_by_kind(&self) -> BTreeMap<NodeKind, usize> {
        let mut counts = BTreeMap::new();
        for node in &self.nodes {
            *counts.entry(node.kind).or_default() += 1;
        }
        counts
    }

    pub fn spawn_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.nodes.len()).collect();
        order.sort_by_key(|&idx| (self.nodes[idx].kind.priority(), idx));
        order
    }

    pub fn edge_nodes(&self) -> Vec<usize> {
        self.nodes
            .iter()
            .filter(|n| n.kind.is_edge())
            .map(|n| n.id)
            .collect()
    }

    pub fn households(&self) -> BTreeMap<usize, Vec<usize>> {
        let mut groups = BTreeMap::<usize, Vec<usize>>::new();
        for node in &self.nodes {
            if let Some(household) = node.household {
                groups.entry(household).or_default().push(node.id);
            }
        }
        groups
    }

    pub fn locals(&self) -> BTreeMap<usize, Vec<usize>> {
        let mut groups = BTreeMap::<usize, Vec<usize>>::new();
        for node in &self.nodes {
            if let Some(local) = node.local {
                groups.entry(local).or_default().push(node.id);
            }
        }
        groups
    }

    pub fn cities(&self) -> BTreeMap<usize, Vec<usize>> {
        let mut groups = BTreeMap::<usize, Vec<usize>>::new();
        for node in &self.nodes {
            if let Some(city) = node.city {
                groups.entry(city).or_default().push(node.id);
            }
        }
        groups
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbePair {
    pub src: usize,
    pub dst: usize,
    pub label: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRender {
    pub src: usize,
    pub dst: usize,
    pub ok: bool,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvgSummary {
    pub nodes: usize,
    pub seed: u64,
    pub settle_secs: u64,
    pub probes: usize,
    pub parallel_tests: usize,
    pub expected_links: usize,
    pub actual_links: usize,
    pub isolated_nodes: usize,
    pub avg_degree: f64,
    pub probe_successes: usize,
    pub probe_failures: usize,
    pub probe_success_rate: f64,
    pub median_probe_ms: f64,
    pub median_probe_cost: f64,
}

pub fn generate(target_nodes: usize, seed: u64) -> TopologyPlan {
    assert!(target_nodes >= 24, "topology needs at least 24 nodes");

    let mut rng = StdRng::seed_from_u64(seed);
    let mut stats = TopologyStats::default();
    let mut nodes = Vec::with_capacity(target_nodes);

    let add_node = |kind: NodeKind,
                    pos: (f64, f64),
                    bootstrap: Vec<usize>,
                    city: Option<usize>,
                    local: Option<usize>,
                    household: Option<usize>,
                    nodes: &mut Vec<NodePlan>| {
        let id = nodes.len();
        nodes.push(NodePlan {
            id,
            kind,
            pos,
            bootstrap,
            city,
            local,
            household,
        });
        id
    };

    let ix_count = (target_nodes / 1200 + 2).clamp(2, 5);
    let mut city_count = (target_nodes / 90).clamp(3, 14);
    let mut regionals_per_city = ((target_nodes / city_count.max(1)) / 80).clamp(1, 4);
    let mut locals_per_regional = ((target_nodes / (city_count.max(1) * regionals_per_city.max(1))) / 22)
        .clamp(2, 5);

    loop {
        let regional_count = city_count * regionals_per_city;
        let local_count = regional_count * locals_per_regional;
        let infra = ix_count + city_count + regional_count + local_count;
        if infra + local_count * 2 <= target_nodes {
            break;
        }
        if locals_per_regional > 2 {
            locals_per_regional -= 1;
        } else if regionals_per_city > 1 {
            regional_count_sanity(regional_count);
            regionals_per_city -= 1;
        } else if city_count > 2 {
            city_count -= 1;
        } else {
            break;
        }
    }

    let regional_count = city_count * regionals_per_city;
    let local_count = regional_count * locals_per_regional;
    let infra_nodes = ix_count + city_count + regional_count + local_count;
    let min_edge_budget = local_count * 2;
    let max_repeater_budget = target_nodes.saturating_sub(infra_nodes + min_edge_budget);
    let repeater_budget = if city_count > 1 {
        (target_nodes / 12).clamp(2, max_repeater_budget.min(city_count * 12))
    } else {
        0
    };

    let world_radius = 420_000.0 + city_count as f64 * 82_000.0;
    let ix_radius = world_radius * 0.18;
    let city_radius = world_radius * 0.74;

    let mut ix_ids = Vec::with_capacity(ix_count);
    for i in 0..ix_count {
        let angle = std::f64::consts::TAU * (i as f64) / ix_count as f64;
        let pos = (
            ix_radius * angle.cos() + rng.gen_range(-5_000.0..5_000.0),
            ix_radius * angle.sin() + rng.gen_range(-5_000.0..5_000.0),
        );
        let id = add_node(NodeKind::InternetExchange, pos, Vec::new(), None, None, None, &mut nodes);
        ix_ids.push(id);
    }

    for i in 0..ix_ids.len() {
        for j in 0..i {
            nodes[ix_ids[i]].bootstrap.push(ix_ids[j]);
        }
    }

    let mut city_ids = Vec::with_capacity(city_count);
    let mut regional_ids_by_city = Vec::with_capacity(city_count);
    let mut local_ids_by_city = Vec::with_capacity(city_count);

    for city_idx in 0..city_count {
        let angle = std::f64::consts::TAU * (city_idx as f64) / city_count as f64;
        let pos = (
            city_radius * angle.cos() + rng.gen_range(-95_000.0..95_000.0),
            city_radius * angle.sin() + rng.gen_range(-95_000.0..95_000.0),
        );
        let primary_ix = ix_ids[city_idx % ix_ids.len()];
        let mut bootstrap = vec![primary_ix];
        let secondary_ix = ix_ids[(city_idx + 1) % ix_ids.len()];
        if secondary_ix != primary_ix && rng.gen_bool(0.55) {
            bootstrap.push(secondary_ix);
        }
        let city_id = add_node(
            NodeKind::CityDistributor,
            pos,
            bootstrap,
            Some(city_idx),
            None,
            None,
            &mut nodes,
        );
        city_ids.push(city_id);
        regional_ids_by_city.push(Vec::new());
        local_ids_by_city.push(Vec::new());
    }

    for city_idx in 0..city_count {
        for regional_slot in 0..regionals_per_city {
            let city_node = city_ids[city_idx];
            let pos = jitter(nodes[city_node].pos, 42_000.0, &mut rng);
            let regional_id = add_node(
                NodeKind::RegionalDistributor,
                pos,
                vec![city_node],
                Some(city_idx),
                None,
                None,
                &mut nodes,
            );
            regional_ids_by_city[city_idx].push(regional_id);

            for local_slot in 0..locals_per_regional {
                let local_pos = jitter(pos, 18_000.0, &mut rng);
                let mut bootstrap = vec![regional_id];
                if regional_ids_by_city[city_idx].len() > 1 && rng.gen_bool(0.25) {
                    let alt = regional_ids_by_city[city_idx]
                        [(regional_slot + local_slot + 1) % regional_ids_by_city[city_idx].len()];
                    if alt != regional_id {
                        bootstrap.push(alt);
                    }
                }
                let local_id = add_node(
                    NodeKind::LocalDistributor,
                    local_pos,
                    bootstrap,
                    Some(city_idx),
                    None,
                    None,
                    &mut nodes,
                );
                local_ids_by_city[city_idx].push(local_id);
            }
        }
    }

    let mut edge_budget = target_nodes.saturating_sub(nodes.len() + repeater_budget);
    let all_local_ids: Vec<usize> = local_ids_by_city.iter().flat_map(|ids| ids.iter().copied()).collect();
    let mut gateways_by_household = Vec::new();

    for (local_idx, &local_id) in all_local_ids.iter().enumerate() {
        if edge_budget == 0 {
            break;
        }
        let household = stats.households;
        let city = nodes[local_id].city;
        let gateway_id = add_node(
            NodeKind::Gateway,
            jitter(nodes[local_id].pos, 2_100.0, &mut rng),
            vec![local_id],
            city,
            Some(local_id),
            Some(household),
            &mut nodes,
        );
        gateways_by_household.push((household, gateway_id));
        stats.households += 1;
        edge_budget -= 1;

        if edge_budget == 0 {
            break;
        }

        let extra_devices = draw_household_size(&mut rng).saturating_sub(1).min(edge_budget);
        for _ in 0..extra_devices {
            add_node(
                NodeKind::Device,
                jitter(nodes[gateway_id].pos, 260.0, &mut rng),
                vec![gateway_id],
                city,
                Some(local_id),
                Some(household),
                &mut nodes,
            );
            edge_budget -= 1;
            if edge_budget == 0 {
                break;
            }
        }

        if edge_budget == 0 || local_idx + 1 == all_local_ids.len() {
            break;
        }
    }

    while edge_budget > 0 && !all_local_ids.is_empty() {
        let local_id = all_local_ids[rng.gen_range(0..all_local_ids.len())];
        let household = stats.households;
        let city = nodes[local_id].city;
        let gateway_id = add_node(
            NodeKind::Gateway,
            jitter(nodes[local_id].pos, 2_100.0, &mut rng),
            vec![local_id],
            city,
            Some(local_id),
            Some(household),
            &mut nodes,
        );
        gateways_by_household.push((household, gateway_id));
        stats.households += 1;
        edge_budget -= 1;

        let extra_devices = draw_household_size(&mut rng).saturating_sub(1).min(edge_budget);
        for _ in 0..extra_devices {
            add_node(
                NodeKind::Device,
                jitter(nodes[gateway_id].pos, 260.0, &mut rng),
                vec![gateway_id],
                city,
                Some(local_id),
                Some(household),
                &mut nodes,
            );
            edge_budget -= 1;
            if edge_budget == 0 {
                break;
            }
        }
    }

    let gateways_only: Vec<usize> = gateways_by_household.iter().map(|(_, gateway)| *gateway).collect();
    let gateway_households: BTreeMap<usize, usize> = gateways_by_household.into_iter().collect();

    let local_peering_targets = (all_local_ids.len() / 5).max(1);
    let mut used_local_pairs = HashSet::new();
    for _ in 0..local_peering_targets {
        if let Some((a, b)) = choose_near_local_pair(&nodes, &all_local_ids, &mut used_local_pairs, &mut rng) {
            let (src, dst) = if a > b { (a, b) } else { (b, a) };
            nodes[src].bootstrap.push(dst);
            stats.local_peer_links += 1;
        }
    }

    let residential_targets = (gateways_only.len() / 10).max(1);
    let mut used_gateway_pairs = HashSet::new();
    for _ in 0..residential_targets {
        if let Some((a, b)) =
            choose_near_gateway_pair(&nodes, &gateways_only, &gateway_households, &mut used_gateway_pairs, &mut rng)
        {
            let (src, dst) = if a > b { (a, b) } else { (b, a) };
            nodes[src].bootstrap.push(dst);
            stats.residential_shortcuts += 1;
        }
    }

    let repeater_candidates = if gateways_only.len() >= 4 {
        gateways_only.clone()
    } else {
        all_local_ids.clone()
    };
    let mut remaining_repeater_budget = repeater_budget.min(target_nodes.saturating_sub(nodes.len()));
    if remaining_repeater_budget > 0 {
        let mut candidate_pairs = Vec::new();
        for i in 0..repeater_candidates.len() {
            for j in (i + 1)..repeater_candidates.len() {
                let a = repeater_candidates[i];
                let b = repeater_candidates[j];
                if nodes[a].city == nodes[b].city {
                    continue;
                }
                let distance = dist(nodes[a].pos, nodes[b].pos);
                if distance < 120_000.0 {
                    continue;
                }
                candidate_pairs.push((a, b, distance));
            }
        }
        candidate_pairs.sort_by(|lhs, rhs| rhs.2.partial_cmp(&lhs.2).unwrap());

        let target_repeater_chains = ((city_count * 2).min(remaining_repeater_budget / 2))
            .max(1)
            .min(candidate_pairs.len().max(1));
        let mut built_chains = 0usize;
        let mut used_city_pairs = HashSet::new();
        let mut anchor_usage: HashMap<usize, usize> = HashMap::new();

        for (src_anchor, dst_anchor, distance) in candidate_pairs {
            if remaining_repeater_budget < 2 {
                break;
            }
            if built_chains >= target_repeater_chains {
                break;
            }

            let city_pair = match (nodes[src_anchor].city, nodes[dst_anchor].city) {
                (Some(a), Some(b)) => {
                    if a < b { (a, b) } else { (b, a) }
                }
                _ => continue,
            };
            if used_city_pairs.contains(&city_pair) {
                continue;
            }
            if anchor_usage.get(&src_anchor).copied().unwrap_or(0) >= 2
                || anchor_usage.get(&dst_anchor).copied().unwrap_or(0) >= 2
            {
                continue;
            }

            let chains_left = target_repeater_chains.saturating_sub(built_chains).max(1);
            let reserved_for_future = chains_left.saturating_sub(1) * 2;
            let available_now = remaining_repeater_budget.saturating_sub(reserved_for_future).max(2);
            let mut repeaters_needed = (distance / 75_000.0).round() as usize;
            let per_chain_cap = (remaining_repeater_budget / chains_left).max(2) + 1;
            repeaters_needed = repeaters_needed
                .max(2)
                .min(available_now)
                .min(per_chain_cap);
            if repeaters_needed < 2 {
                continue;
            }

            let pos_a = nodes[src_anchor].pos;
            let pos_b = nodes[dst_anchor].pos;
            let dx = pos_b.0 - pos_a.0;
            let dy = pos_b.1 - pos_a.1;
            let distance = (dx * dx + dy * dy).sqrt().max(1.0);
            let perp = (-dy / distance, dx / distance);
            let wave_amplitude = (distance * 0.08).min(30_000.0);
            let mut previous = src_anchor;
            let mut previous_previous = None;
            let mut chain_ids = Vec::with_capacity(repeaters_needed);
            for hop in 0..repeaters_needed {
                let t = (hop as f64 + 1.0) / (repeaters_needed as f64 + 1.0);
                let wave = (t * std::f64::consts::PI * 1.4).sin();
                let side = if hop % 2 == 0 { -1.0 } else { 1.0 };
                let lateral = side * wave * wave_amplitude;
                let pos = (
                    pos_a.0 + dx * t + perp.0 * lateral + rng.gen_range(-2_000.0..2_000.0),
                    pos_a.1 + dy * t + perp.1 * lateral + rng.gen_range(-2_000.0..2_000.0),
                );
                let mut bootstrap = vec![previous];
                if let Some(prev_prev) = previous_previous {
                    if rng.gen_bool(0.45) {
                        bootstrap.push(prev_prev);
                    }
                }
                if hop + 1 == repeaters_needed {
                    bootstrap.push(dst_anchor);
                }
                let rep_id = add_node(
                    NodeKind::Repeater,
                    pos,
                    bootstrap,
                    None,
                    None,
                    None,
                    &mut nodes,
                );
                chain_ids.push(rep_id);
                previous_previous = Some(previous);
                previous = rep_id;
                remaining_repeater_budget -= 1;
                if remaining_repeater_budget == 0 {
                    break;
                }
            }

            if !chain_ids.is_empty() {
                *anchor_usage.entry(src_anchor).or_default() += 1;
                *anchor_usage.entry(dst_anchor).or_default() += 1;
                used_city_pairs.insert(city_pair);
                stats.repeater_chains += 1;
                built_chains += 1;

                if remaining_repeater_budget > 0 && rng.gen_bool(0.45) {
                    let anchor = chain_ids[rng.gen_range(0..chain_ids.len())];
                    let spur_len = remaining_repeater_budget.min(rng.gen_range(1..=2));
                    let mut parent = anchor;
                    for _ in 0..spur_len {
                        let spur_pos = jitter(nodes[parent].pos, 3_000.0, &mut rng);
                        let mut bootstrap = vec![parent];
                        if rng.gen_bool(0.35) {
                            let branch_target = if rng.gen_bool(0.5) { src_anchor } else { dst_anchor };
                            bootstrap.push(branch_target);
                        }
                        let spur = add_node(
                            NodeKind::Repeater,
                            spur_pos,
                            bootstrap,
                            None,
                            None,
                            None,
                            &mut nodes,
                        );
                        parent = spur;
                        remaining_repeater_budget -= 1;
                        stats.repeater_spurs += 1;
                        if remaining_repeater_budget == 0 {
                            break;
                        }
                    }
                }
            }
        }
    }

    while nodes.len() < target_nodes && !gateways_only.is_empty() {
        let gateway = gateways_only[rng.gen_range(0..gateways_only.len())];
        add_node(
            NodeKind::Device,
            jitter(nodes[gateway].pos, 90.0, &mut rng),
            vec![gateway],
            nodes[gateway].city,
            nodes[gateway].local,
            nodes[gateway].household,
            &mut nodes,
        );
    }

    relax_layout(&mut nodes, 80);

    let expected_links = nodes.iter().map(|node| node.bootstrap.len()).sum();
    TopologyPlan {
        nodes,
        expected_links,
        stats,
    }
}

pub fn sample_probe_pairs(plan: &TopologyPlan, count: usize, seed: u64) -> Vec<ProbePair> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5eed_5eed_d15c_a11);
    let households = plan.households();
    let locals = plan.locals();
    let cities = plan.cities();
    let edge_nodes = plan.edge_nodes();
    let mut seen = BTreeSet::new();
    let mut pairs = Vec::new();

    let local_groups: Vec<Vec<usize>> = households
        .values()
        .filter(|members| members.len() >= 2)
        .cloned()
        .collect();
    let neighborhood_groups: Vec<Vec<usize>> = locals
        .values()
        .map(|members| {
            members
                .iter()
                .copied()
                .filter(|&id| plan.nodes[id].kind.is_edge())
                .collect::<Vec<_>>()
        })
        .filter(|members| members.len() >= 2)
        .collect();
    let metro_groups: Vec<Vec<usize>> = cities
        .values()
        .map(|members| {
            members
                .iter()
                .copied()
                .filter(|&id| plan.nodes[id].kind.is_edge())
                .collect::<Vec<_>>()
        })
        .filter(|members| members.len() >= 2)
        .collect();

    // Build per-city edge node groups for cross-city sampling.
    // In federated runs, each worker has distinct city IDs after offset, so
    // pairs drawn from different cities naturally cross worker boundaries.
    let city_edge_groups: Vec<(usize, Vec<usize>)> = cities
        .iter()
        .map(|(&city_id, members)| {
            let edges: Vec<usize> = members
                .iter()
                .copied()
                .filter(|&id| plan.nodes[id].kind.is_edge())
                .collect();
            (city_id, edges)
        })
        .filter(|(_, edges)| !edges.is_empty())
        .collect();
    let has_multiple_cities = city_edge_groups.len() >= 2;

    // Allocate budget: if multiple cities exist (federated), reserve a tier
    // for cross-city probes; otherwise give all to the existing tiers.
    let cross_city_target = if has_multiple_cities { count / 5 } else { 0 };
    let remaining = count - cross_city_target;
    let local_target = remaining / 4;
    let neighborhood_target = remaining / 4;
    let metro_target = remaining / 4;

    sample_group_pairs(
        &mut rng,
        &local_groups,
        local_target,
        "same-household",
        &mut seen,
        &mut pairs,
    );
    sample_group_pairs(
        &mut rng,
        &neighborhood_groups,
        neighborhood_target,
        "same-neighborhood",
        &mut seen,
        &mut pairs,
    );
    sample_group_pairs(
        &mut rng,
        &metro_groups,
        metro_target,
        "same-city",
        &mut seen,
        &mut pairs,
    );

    // Cross-city probes: pick src and dst from different cities to ensure
    // inter-worker routing is covered in federated topologies.
    if has_multiple_cities {
        let mut cross_attempts = 0;
        while pairs.len() < local_target + neighborhood_target + metro_target + cross_city_target
            && cross_attempts < cross_city_target * 10
        {
            cross_attempts += 1;
            let i = rng.gen_range(0..city_edge_groups.len());
            let j = (i + rng.gen_range(1..city_edge_groups.len())) % city_edge_groups.len();
            let src = city_edge_groups[i].1[rng.gen_range(0..city_edge_groups[i].1.len())];
            let dst = city_edge_groups[j].1[rng.gen_range(0..city_edge_groups[j].1.len())];
            push_unique_pair(src, dst, "cross-city", &mut seen, &mut pairs);
        }
    }

    while pairs.len() < count && edge_nodes.len() >= 2 {
        let src = edge_nodes[rng.gen_range(0..edge_nodes.len())];
        let mut dst = edge_nodes[rng.gen_range(0..edge_nodes.len())];
        if src == dst {
            dst = edge_nodes[(rng.gen_range(0..edge_nodes.len() - 1) + 1) % edge_nodes.len()];
        }
        let label = match (plan.nodes[src].city, plan.nodes[dst].city) {
            (Some(a), Some(b)) if a == b => "same-city",
            _ => "inter-city",
        };
        let _ = push_unique_pair(src, dst, label, &mut seen, &mut pairs);
        if seen.len() == edge_nodes.len() * edge_nodes.len().saturating_sub(1) / 2 {
            break;
        }
    }

    pairs.truncate(count);
    pairs
}

pub fn write_dot(
    path: &Path,
    plan: &TopologyPlan,
    sampled_pairs: &[ProbePair],
) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    writeln!(file, "graph tarnet_topology {{")?;
    writeln!(file, "  graph [overlap=false, splines=true, outputorder=edgesfirst];")?;
    writeln!(file, "  node [shape=circle, style=filled, fontname=\"monospace\"];")?;

    for node in &plan.nodes {
        writeln!(
            file,
            "  n{} [label=\"{}:{}\", fillcolor=\"{}\", pos=\"{:.2},{:.2}!\"];",
            node.id,
            node.kind,
            node.id,
            node.kind.color(),
            node.pos.0 / 1_000.0,
            node.pos.1 / 1_000.0,
        )?;
    }

    let mut emitted = HashSet::new();
    for node in &plan.nodes {
        for &peer in &node.bootstrap {
            let key = if node.id < peer { (node.id, peer) } else { (peer, node.id) };
            if emitted.insert(key) {
                writeln!(file, "  n{} -- n{};", key.0, key.1)?;
            }
        }
    }

    for pair in sampled_pairs {
        writeln!(
            file,
            "  n{} -- n{} [color=\"#ef476f\", penwidth=2.4, style=dashed, constraint=false, label=\"{}\"];",
            pair.src,
            pair.dst,
            pair.label,
        )?;
    }

    writeln!(file, "}}")?;
    Ok(())
}

/// Which layers to include in the SVG output.
#[derive(Debug, Clone)]
pub struct SvgLayers {
    pub links: bool,
    pub missing_links: bool,
    pub extra_links: bool,
    pub probes: bool,
    pub failed_probes: bool,
}

impl SvgLayers {
    pub fn all() -> Self {
        Self { links: true, missing_links: true, extra_links: true, probes: true, failed_probes: true }
    }

    /// Parse a comma-separated layer spec.
    /// Individual layers: links, missing-links, extra-links, probes, failed-probes
    /// Shorthands: all (everything), errors (missing-links + failed-probes)
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut layers = Self { links: false, missing_links: false, extra_links: false, probes: false, failed_probes: false };
        for token in spec.split(',').map(str::trim) {
            match token {
                "all" => return Ok(Self::all()),
                "errors" => { layers.missing_links = true; layers.failed_probes = true; }
                "links" => layers.links = true,
                "missing-links" => layers.missing_links = true,
                "extra-links" => layers.extra_links = true,
                "probes" => layers.probes = true,
                "failed-probes" => layers.failed_probes = true,
                other => return Err(format!("unknown svg layer '{}'; expected: all, errors, links, missing-links, extra-links, probes, failed-probes", other)),
            }
        }
        Ok(layers)
    }
}

pub fn write_svg(
    path: &Path,
    plan: &TopologyPlan,
    actual_links: &BTreeSet<(usize, usize)>,
    probes: &[ProbeRender],
    summary: &SvgSummary,
    layers: &SvgLayers,
) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    let (min_x, min_y, max_x, max_y) = bounding_box(plan);
    let width = (max_x - min_x).max(1.0);
    let height = (max_y - min_y).max(1.0);
    let pad = 110.0;
    let canvas_w = 3000.0;
    let scale = (canvas_w - pad * 2.0) / width.max(height);
    let canvas_h = height * scale + pad * 2.0;

    let tx = |x: f64| (x - min_x) * scale + pad;
    let ty = |y: f64| (y - min_y) * scale + pad;

    writeln!(
        file,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{canvas_w:.0}\" height=\"{canvas_h:.0}\" viewBox=\"0 0 {canvas_w:.0} {canvas_h:.0}\">"
    )?;
    writeln!(
        file,
        "<rect width=\"100%\" height=\"100%\" fill=\"#091018\"/><rect x=\"18\" y=\"18\" width=\"{}\" height=\"{}\" rx=\"18\" fill=\"#101a26\" stroke=\"#243447\"/>",
        canvas_w - 36.0,
        canvas_h - 36.0
    )?;

    let planned_edges = planned_edges(plan);
    for &(a, b) in &planned_edges {
        let established = actual_links.contains(&(a, b));
        if established && !layers.links {
            continue;
        }
        if !established && !layers.missing_links {
            continue;
        }
        let pa = plan.nodes[a].pos;
        let pb = plan.nodes[b].pos;
        let (stroke, dash, width) = if established {
            ("#3ddc97", "", 2.2)
        } else {
            ("#ff5d73", " stroke-dasharray=\"8 7\"", 2.4)
        };
        writeln!(
            file,
            "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"{}\" stroke-width=\"{:.1}\"{} opacity=\"0.85\"/>",
            tx(pa.0),
            ty(pa.1),
            tx(pb.0),
            ty(pb.1),
            stroke,
            width,
            dash
        )?;
    }

    // Unexpected direct links (not in plan but established)
    if layers.extra_links {
        for &(a, b) in actual_links {
            if planned_edges.contains(&(a, b)) {
                continue;
            }
            let pa = plan.nodes[a].pos;
            let pb = plan.nodes[b].pos;
            writeln!(
                file,
                "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"#8aa1b5\" stroke-width=\"1.5\" stroke-dasharray=\"3 6\" opacity=\"0.45\"/>",
                tx(pa.0),
                ty(pa.1),
                tx(pb.0),
                ty(pb.1),
            )?;
        }
    }

    for probe in probes {
        if probe.ok && !layers.probes {
            continue;
        }
        if !probe.ok && !layers.failed_probes {
            continue;
        }
        let pa = plan.nodes[probe.src].pos;
        let pb = plan.nodes[probe.dst].pos;
        let stroke = if probe.ok { "#59a5ff" } else { "#ff335f" };
        let width = if probe.ok { 3.2 } else { 2.8 };
        let dash = if probe.ok { "10 7" } else { "5 7" };
        writeln!(
            file,
            "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"{}\" stroke-width=\"{:.1}\" stroke-dasharray=\"{}\" opacity=\"0.75\"><title>{}</title></line>",
            tx(pa.0),
            ty(pa.1),
            tx(pb.0),
            ty(pb.1),
            stroke,
            width,
            dash,
            probe.label
        )?;
    }

    for node in &plan.nodes {
        let radius = match node.kind {
            NodeKind::InternetExchange => 8.0,
            NodeKind::CityDistributor => 7.0,
            NodeKind::RegionalDistributor => 6.0,
            NodeKind::LocalDistributor => 5.0,
            NodeKind::Gateway => 4.5,
            NodeKind::Device => 3.0,
            NodeKind::Repeater => 4.0,
        };
        let stroke = if matches!(node.kind, NodeKind::Repeater) {
            "#ffe082"
        } else {
            "#f8fafc"
        };
        writeln!(
            file,
            "<circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"{:.1}\" fill=\"{}\" stroke=\"{}\" stroke-width=\"1.1\"/>",
            tx(node.pos.0),
            ty(node.pos.1),
            radius,
            node.kind.color(),
            stroke
        )?;
    }

    writeln!(
        file,
        "<text x=\"36\" y=\"42\" font-family=\"monospace\" font-size=\"20\" fill=\"#e6edf3\">tarnet-topsim topology</text>"
    )?;
    writeln!(
        file,
        "<text x=\"36\" y=\"66\" font-family=\"monospace\" font-size=\"12\" fill=\"#9fb3c8\">green=planned link works  red=planned link missing  gray=unexpected direct link  blue=probe success  red=probe failure</text>"
    )?;
    writeln!(
        file,
        "<text x=\"36\" y=\"88\" font-family=\"monospace\" font-size=\"12\" fill=\"#9fb3c8\">nodes={} seed={} settle={}s probes={} parallel_tests={}</text>",
        summary.nodes,
        summary.seed,
        summary.settle_secs,
        summary.probes,
        if summary.parallel_tests == 0 {
            "unlimited".to_string()
        } else {
            summary.parallel_tests.to_string()
        }
    )?;
    writeln!(
        file,
        "<text x=\"36\" y=\"106\" font-family=\"monospace\" font-size=\"12\" fill=\"#9fb3c8\">links actual/expected={}/{} isolated={} avg_degree={:.2} probe_success={}/{} ({:.1}%) median_probe_ms={:.1} median_cost={:.2}</text>",
        summary.actual_links,
        summary.expected_links,
        summary.isolated_nodes,
        summary.avg_degree,
        summary.probe_successes,
        summary.probe_successes + summary.probe_failures,
        summary.probe_success_rate,
        summary.median_probe_ms,
        summary.median_probe_cost
    )?;

    let mut legend_y = 138.0;
    for kind in [
        NodeKind::InternetExchange,
        NodeKind::CityDistributor,
        NodeKind::RegionalDistributor,
        NodeKind::LocalDistributor,
        NodeKind::Gateway,
        NodeKind::Device,
        NodeKind::Repeater,
    ] {
        writeln!(
            file,
            "<circle cx=\"42\" cy=\"{legend_y:.1}\" r=\"5\" fill=\"{}\" stroke=\"#f8fafc\" stroke-width=\"1\"/><text x=\"56\" y=\"{:.1}\" font-family=\"monospace\" font-size=\"12\" fill=\"#d6e2ee\">{}</text>",
            kind.color(),
            legend_y - 1.0,
            kind
        )?;
        legend_y += 18.0;
    }

    writeln!(file, "</svg>")?;
    Ok(())
}

fn draw_household_size(rng: &mut StdRng) -> usize {
    match rng.gen_range(0..100) {
        0..=10 => 1,
        11..=34 => 2,
        35..=62 => 3,
        63..=82 => 4,
        83..=94 => 5,
        _ => 6,
    }
}

fn sample_group_pairs(
    rng: &mut StdRng,
    groups: &[Vec<usize>],
    target: usize,
    label: &'static str,
    seen: &mut BTreeSet<(usize, usize)>,
    pairs: &mut Vec<ProbePair>,
) {
    if groups.is_empty() || target == 0 {
        return;
    }

    let mut attempts = 0usize;
    while pairs.len() < target && attempts < target * 32 {
        attempts += 1;
        let group = &groups[rng.gen_range(0..groups.len())];
        if group.len() < 2 {
            continue;
        }
        let src_idx = rng.gen_range(0..group.len());
        let mut dst_idx = rng.gen_range(0..group.len() - 1);
        if dst_idx >= src_idx {
            dst_idx += 1;
        }
        let _ = push_unique_pair(group[src_idx], group[dst_idx], label, seen, pairs);
    }
}

fn push_unique_pair(
    src: usize,
    dst: usize,
    label: &'static str,
    seen: &mut BTreeSet<(usize, usize)>,
    pairs: &mut Vec<ProbePair>,
) -> bool {
    let key = if src < dst { (src, dst) } else { (dst, src) };
    if seen.insert(key) {
        pairs.push(ProbePair { src, dst, label });
        true
    } else {
        false
    }
}

fn choose_near_local_pair(
    nodes: &[NodePlan],
    local_ids: &[usize],
    used_pairs: &mut HashSet<(usize, usize)>,
    rng: &mut StdRng,
) -> Option<(usize, usize)> {
    choose_near_pair(nodes, local_ids, used_pairs, rng, |a, b| nodes[a].city == nodes[b].city)
}

fn choose_near_gateway_pair(
    nodes: &[NodePlan],
    gateway_ids: &[usize],
    households: &BTreeMap<usize, usize>,
    used_pairs: &mut HashSet<(usize, usize)>,
    rng: &mut StdRng,
) -> Option<(usize, usize)> {
    choose_near_pair(nodes, gateway_ids, used_pairs, rng, |a, b| {
        nodes[a].city == nodes[b].city
            && households
                .iter()
                .find_map(|(household, &gateway)| if gateway == a { Some(*household) } else { None })
                != households
                    .iter()
                    .find_map(|(household, &gateway)| if gateway == b { Some(*household) } else { None })
    })
}

fn choose_near_pair<F>(
    nodes: &[NodePlan],
    candidates: &[usize],
    used_pairs: &mut HashSet<(usize, usize)>,
    rng: &mut StdRng,
    allow: F,
) -> Option<(usize, usize)>
where
    F: Fn(usize, usize) -> bool,
{
    if candidates.len() < 2 {
        return None;
    }

    for _ in 0..64 {
        let a = candidates[rng.gen_range(0..candidates.len())];
        let mut nearest = None;
        for &b in candidates {
            if a == b || !allow(a, b) {
                continue;
            }
            let key = if a < b { (a, b) } else { (b, a) };
            if used_pairs.contains(&key) {
                continue;
            }
            let distance = dist(nodes[a].pos, nodes[b].pos);
            match nearest {
                None => nearest = Some((b, distance)),
                Some((_, best)) if distance < best => nearest = Some((b, distance)),
                _ => {}
            }
        }
        if let Some((b, _)) = nearest {
            let key = if a < b { (a, b) } else { (b, a) };
            used_pairs.insert(key);
            return Some((a, b));
        }
    }

    None
}

fn regional_count_sanity(_: usize) {}

fn jitter(origin: (f64, f64), radius: f64, rng: &mut StdRng) -> (f64, f64) {
    let angle = rng.gen_range(0.0..std::f64::consts::TAU);
    let length = rng.gen_range(0.0..radius);
    (origin.0 + length * angle.cos(), origin.1 + length * angle.sin())
}

fn dist(a: (f64, f64), b: (f64, f64)) -> f64 {
    let dx = a.0 - b.0;
    let dy = a.1 - b.1;
    (dx * dx + dy * dy).sqrt()
}

fn relax_layout(nodes: &mut [NodePlan], iterations: usize) {
    if nodes.len() < 2 {
        return;
    }

    let edges = planned_edges_from_nodes(nodes);
    let mobility = |kind: NodeKind| match kind {
        NodeKind::InternetExchange => 0.05,
        NodeKind::CityDistributor => 0.12,
        NodeKind::RegionalDistributor => 0.28,
        NodeKind::LocalDistributor => 0.45,
        NodeKind::Gateway => 0.9,
        NodeKind::Device => 1.0,
        NodeKind::Repeater => 0.35,
    };

    let (min_x, min_y, max_x, max_y) = bounding_box_from_nodes(nodes);
    let world = (max_x - min_x).max(max_y - min_y).max(1.0);
    let repel_radius = world * 0.13;
    let repel_sq = repel_radius * repel_radius;
    let spring_rest = world * 0.038;
    let spring_k = 0.012;
    let repel_k = world * 0.075;

    for step in 0..iterations {
        let cooling = 1.0 - (step as f64 / iterations as f64) * 0.82;
        let max_step = world * 0.0075 * cooling;
        let mut forces = vec![(0.0f64, 0.0f64); nodes.len()];
        let cell_size = repel_radius.max(1.0);
        let mut grid: HashMap<(i32, i32), Vec<usize>> = HashMap::new();
        for (idx, node) in nodes.iter().enumerate() {
            let cell = (
                (node.pos.0 / cell_size).floor() as i32,
                (node.pos.1 / cell_size).floor() as i32,
            );
            grid.entry(cell).or_default().push(idx);
        }

        for (&(cx, cy), members) in &grid {
            for &i in members {
                for nx in (cx - 1)..=(cx + 1) {
                    for ny in (cy - 1)..=(cy + 1) {
                        let Some(neighbors) = grid.get(&(nx, ny)) else {
                            continue;
                        };
                        for &j in neighbors {
                            if j <= i {
                                continue;
                            }
                            let dx = nodes[j].pos.0 - nodes[i].pos.0;
                            let dy = nodes[j].pos.1 - nodes[i].pos.1;
                            let d_sq = dx * dx + dy * dy;
                            if d_sq < 1.0e-6 || d_sq > repel_sq {
                                continue;
                            }
                            let d = d_sq.sqrt();
                            let force = repel_k / d_sq.max(10.0);
                            let fx = dx / d * force;
                            let fy = dy / d * force;
                            forces[i].0 -= fx;
                            forces[i].1 -= fy;
                            forces[j].0 += fx;
                            forces[j].1 += fy;
                        }
                    }
                }
            }
        }

        for &(a, b) in &edges {
            let dx = nodes[b].pos.0 - nodes[a].pos.0;
            let dy = nodes[b].pos.1 - nodes[a].pos.1;
            let d = (dx * dx + dy * dy).sqrt().max(1.0);
            let stretch = d - spring_rest;
            let force = spring_k * stretch;
            let fx = dx / d * force;
            let fy = dy / d * force;
            forces[a].0 += fx;
            forces[a].1 += fy;
            forces[b].0 -= fx;
            forces[b].1 -= fy;
        }

        for (idx, node) in nodes.iter_mut().enumerate() {
            let m = mobility(node.kind);
            let mut fx = forces[idx].0 * m;
            let mut fy = forces[idx].1 * m;
            let mag = (fx * fx + fy * fy).sqrt();
            if mag > max_step {
                let s = max_step / mag;
                fx *= s;
                fy *= s;
            }
            node.pos.0 += fx;
            node.pos.1 += fy;
        }
    }
}

fn planned_edges(plan: &TopologyPlan) -> BTreeSet<(usize, usize)> {
    planned_edges_from_nodes(&plan.nodes)
}

fn planned_edges_from_nodes(nodes: &[NodePlan]) -> BTreeSet<(usize, usize)> {
    let mut edges = BTreeSet::new();
    for node in nodes {
        for &peer in &node.bootstrap {
            let edge = if node.id < peer {
                (node.id, peer)
            } else {
                (peer, node.id)
            };
            edges.insert(edge);
        }
    }
    edges
}

fn bounding_box(plan: &TopologyPlan) -> (f64, f64, f64, f64) {
    bounding_box_from_nodes(&plan.nodes)
}

fn bounding_box_from_nodes(nodes: &[NodePlan]) -> (f64, f64, f64, f64) {
    let mut min_x = f64::MAX;
    let mut min_y = f64::MAX;
    let mut max_x = f64::MIN;
    let mut max_y = f64::MIN;
    for node in nodes {
        min_x = min_x.min(node.pos.0);
        min_y = min_y.min(node.pos.1);
        max_x = max_x.max(node.pos.0);
        max_y = max_y.max(node.pos.1);
    }
    (min_x, min_y, max_x, max_y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_exact_node_count() {
        let plan = generate(256, 7);
        assert_eq!(plan.nodes.len(), 256);
    }

    #[test]
    fn samples_probe_pairs_without_self_edges() {
        let plan = generate(128, 9);
        let pairs = sample_probe_pairs(&plan, 32, 11);
        assert!(!pairs.is_empty());
        assert!(pairs.iter().all(|pair| pair.src != pair.dst));
    }
}
