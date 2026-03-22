pub mod dv;

use std::collections::HashMap;
use std::time::Instant;

use crate::types::PeerId;

const MAX_ROUTES_PER_DEST: usize = 3;

/// Default maximum number of destinations in the routing table.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Minimum per-peer fair share. When every peer is at or below this count
/// and the table is full, new advertisements are dropped.
const DEFAULT_MIN_FAIR_SHARE: usize = 200;

/// Whether a route update comes from a DV advertisement or a local request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    /// Passively learned from a neighbor's route advertisement.
    Advertisement,
    /// Actively requested by this node (e.g. discovery, direct connection).
    Local,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub next_hop: PeerId,
    pub cost: u32,
    pub last_updated: Instant,
}

/// Routing table: maps destination PeerId to top-k routes.
///
/// Bounded to `max_entries` destinations. When full, fair-share eviction
/// ensures no single next-hop peer can monopolise the table:
///
/// - **Advertisement**: find the peer with the most entries. If that peer
///   is above `min_fair_share`, evict their oldest route. Otherwise drop
///   the advertisement (everyone is at or below fair share).
/// - **Local request**: always evict the oldest route from the peer with
///   the most entries, regardless of fair share.
pub struct RoutingTable {
    routes: HashMap<PeerId, Vec<Route>>,
    local_peer: PeerId,
    max_entries: usize,
    min_fair_share: usize,
}

impl RoutingTable {
    pub fn new(local_peer: PeerId) -> Self {
        Self {
            routes: HashMap::new(),
            local_peer,
            max_entries: DEFAULT_MAX_ENTRIES,
            min_fair_share: DEFAULT_MIN_FAIR_SHARE,
        }
    }

    /// Create a routing table with custom capacity limits.
    #[allow(dead_code)]
    pub fn with_capacity(local_peer: PeerId, max_entries: usize, min_fair_share: usize) -> Self {
        Self {
            routes: HashMap::new(),
            local_peer,
            max_entries,
            min_fair_share,
        }
    }

    /// Number of distinct destinations in the table.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Look up the best next hop for a destination.
    pub fn lookup(&self, dest: &PeerId) -> Option<&Route> {
        self.routes.get(dest).and_then(|routes| routes.first())
    }

    /// Get all routes for a destination (up to k).
    pub fn lookup_all(&self, dest: &PeerId) -> Option<&[Route]> {
        self.routes.get(dest).map(|v| v.as_slice())
    }

    /// Insert or update a route. Returns true if the table changed.
    pub fn update(&mut self, dest: PeerId, next_hop: PeerId, cost: u32) -> bool {
        self.update_with_source(dest, next_hop, cost, RouteSource::Local)
    }

    /// Insert or update a route with an explicit source.
    pub fn update_with_source(
        &mut self,
        dest: PeerId,
        next_hop: PeerId,
        cost: u32,
        source: RouteSource,
    ) -> bool {
        if dest == self.local_peer {
            return false; // don't route to self
        }

        // Fast path: destination already in table (update-in-place, no eviction needed).
        if let Some(routes) = self.routes.get_mut(&dest) {
            return Self::update_routes_vec(routes, next_hop, cost);
        }

        // New destination — may need eviction if table is full.
        if self.routes.len() >= self.max_entries {
            if !self.evict_one(source) {
                return false; // table full, eviction refused
            }
        }

        // Insert new destination.
        let routes = self.routes.entry(dest).or_default();
        Self::update_routes_vec(routes, next_hop, cost);
        true
    }

    /// Update the route vec for an existing or freshly-inserted destination.
    /// Returns true if anything changed.
    fn update_routes_vec(routes: &mut Vec<Route>, next_hop: PeerId, cost: u32) -> bool {
        if let Some(existing) = routes.iter_mut().find(|r| r.next_hop == next_hop) {
            if existing.cost == cost {
                existing.last_updated = Instant::now();
                return false;
            }
            existing.cost = cost;
            existing.last_updated = Instant::now();
        } else if routes.len() < MAX_ROUTES_PER_DEST {
            routes.push(Route {
                next_hop,
                cost,
                last_updated: Instant::now(),
            });
        } else {
            // Replace worst route if new one is better
            if let Some((worst_idx, worst)) =
                routes.iter().enumerate().max_by_key(|(_, r)| r.cost)
            {
                if cost < worst.cost {
                    routes[worst_idx] = Route {
                        next_hop,
                        cost,
                        last_updated: Instant::now(),
                    };
                } else {
                    return false;
                }
            }
        }
        routes.sort_by_key(|r| r.cost);
        true
    }

    /// Try to evict one destination to make room. Returns true if eviction
    /// succeeded (a slot is now free).
    fn evict_one(&mut self, source: RouteSource) -> bool {
        // Count entries per next_hop (using the *primary* / best route for each dest).
        let mut counts: HashMap<PeerId, usize> = HashMap::new();
        for routes in self.routes.values() {
            if let Some(best) = routes.first() {
                *counts.entry(best.next_hop).or_default() += 1;
            }
        }

        // Find the peer with the most entries.
        let biggest = counts.iter().max_by_key(|(_, &c)| c);
        let (biggest_peer, biggest_count) = match biggest {
            Some((&p, &c)) => (p, c),
            None => return false, // empty table, shouldn't happen
        };

        match source {
            RouteSource::Advertisement => {
                if biggest_count <= self.min_fair_share {
                    // Everyone at or below fair share — drop the ad.
                    return false;
                }
            }
            RouteSource::Local => {
                // Local requests always evict.
            }
        }

        // Evict the LRU destination whose primary route goes through biggest_peer.
        let victim = self
            .routes
            .iter()
            .filter(|(_, routes)| {
                routes
                    .first()
                    .map(|r| r.next_hop == biggest_peer)
                    .unwrap_or(false)
            })
            .min_by_key(|(_, routes)| {
                routes
                    .first()
                    .map(|r| r.last_updated)
                    .unwrap_or_else(Instant::now)
            })
            .map(|(dest, _)| *dest);

        if let Some(dest) = victim {
            self.routes.remove(&dest);
            true
        } else {
            false
        }
    }

    /// Remove all routes through a given next hop (link went down).
    pub fn remove_next_hop(&mut self, next_hop: &PeerId) {
        self.routes.retain(|_, routes| {
            routes.retain(|r| r.next_hop != *next_hop);
            !routes.is_empty()
        });
    }

    /// Add a direct neighbor with default cost 1.
    pub fn add_neighbor(&mut self, peer: PeerId) {
        // Neighbors are local — always make room for them.
        self.update(peer, peer, 1);
    }

    /// Add a direct neighbor with a specific cost (based on RTT).
    pub fn add_neighbor_with_cost(&mut self, peer: PeerId, cost: u32) {
        self.update(peer, peer, cost.max(1));
    }

    /// Return up to `n` distinct next-hops for a destination.
    pub fn lookup_multi(&self, dest: &PeerId, n: usize) -> Vec<PeerId> {
        match self.routes.get(dest) {
            Some(routes) => routes.iter().map(|r| r.next_hop).take(n).collect(),
            None => Vec::new(),
        }
    }

    /// All known destinations and their best routes.
    pub fn all_destinations(&self) -> impl Iterator<Item = (&PeerId, &Route)> {
        self.routes
            .iter()
            .filter_map(|(dest, routes)| routes.first().map(|r| (dest, r)))
    }

    /// All known destinations with ALL their routes (not just the best).
    pub fn all_routes(&self) -> impl Iterator<Item = (&PeerId, &Route)> {
        self.routes
            .iter()
            .flat_map(|(dest, routes)| routes.iter().map(move |r| (dest, r)))
    }

    /// All known destinations with best cost (for advertisements).
    pub fn entries_for_advertisement(&self) -> Vec<(PeerId, u32)> {
        self.routes
            .iter()
            .filter_map(|(dest, routes)| routes.first().map(|r| (*dest, r.cost)))
            .collect()
    }

    /// Expire routes older than the given duration.
    pub fn expire(&mut self, max_age: std::time::Duration) {
        let cutoff = Instant::now() - max_age;
        self.routes.retain(|_, routes| {
            routes.retain(|r| r.last_updated > cutoff);
            !routes.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn basic_lookup() {
        let mut rt = RoutingTable::new(pid(0));
        rt.add_neighbor(pid(1));
        assert!(rt.lookup(&pid(1)).is_some());
        assert_eq!(rt.lookup(&pid(1)).unwrap().cost, 1);
    }

    #[test]
    fn top_k_routes() {
        let mut rt = RoutingTable::new(pid(0));
        rt.update(pid(10), pid(1), 2);
        rt.update(pid(10), pid(2), 3);
        rt.update(pid(10), pid(3), 4);
        // Fourth route (worse) should not be added
        rt.update(pid(10), pid(4), 5);
        let routes = rt.lookup_all(&pid(10)).unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].cost, 2); // sorted by cost
    }

    #[test]
    fn replace_worst() {
        let mut rt = RoutingTable::new(pid(0));
        rt.update(pid(10), pid(1), 5);
        rt.update(pid(10), pid(2), 3);
        rt.update(pid(10), pid(3), 4);
        // Better route should replace worst
        assert!(rt.update(pid(10), pid(4), 1));
        let routes = rt.lookup_all(&pid(10)).unwrap();
        assert!(routes.iter().any(|r| r.next_hop == pid(4) && r.cost == 1));
        assert!(!routes.iter().any(|r| r.next_hop == pid(1))); // worst removed
    }

    #[test]
    fn remove_next_hop_clears_routes() {
        let mut rt = RoutingTable::new(pid(0));
        rt.add_neighbor(pid(1));
        rt.update(pid(2), pid(1), 2); // reachable through 1
        rt.remove_next_hop(&pid(1));
        assert!(rt.lookup(&pid(1)).is_none());
        assert!(rt.lookup(&pid(2)).is_none());
    }

    #[test]
    fn no_self_route() {
        let mut rt = RoutingTable::new(pid(0));
        assert!(!rt.update(pid(0), pid(1), 1));
    }

    // --- Bounded table / fair-share eviction tests ---

    #[test]
    fn eviction_ad_drops_when_all_at_fair_share() {
        // Table of 4 entries, min_fair_share=2. Two peers each with 2 entries.
        let mut rt = RoutingTable::with_capacity(pid(0), 4, 2);
        // Peer 1 advertises destinations 10, 11
        rt.update_with_source(pid(10), pid(1), 2, RouteSource::Advertisement);
        rt.update_with_source(pid(11), pid(1), 3, RouteSource::Advertisement);
        // Peer 2 advertises destinations 20, 21
        rt.update_with_source(pid(20), pid(2), 2, RouteSource::Advertisement);
        rt.update_with_source(pid(21), pid(2), 3, RouteSource::Advertisement);
        assert_eq!(rt.len(), 4);

        // New ad should be dropped — both peers at fair share (2).
        let added = rt.update_with_source(pid(30), pid(3), 1, RouteSource::Advertisement);
        assert!(!added);
        assert_eq!(rt.len(), 4);
    }

    #[test]
    fn eviction_ad_evicts_over_fair_share_peer() {
        // Table of 4, min_fair_share=2. Peer 1 has 3, peer 2 has 1.
        let mut rt = RoutingTable::with_capacity(pid(0), 4, 2);
        rt.update_with_source(pid(10), pid(1), 5, RouteSource::Advertisement);
        rt.update_with_source(pid(11), pid(1), 3, RouteSource::Advertisement);
        rt.update_with_source(pid(12), pid(1), 2, RouteSource::Advertisement);
        rt.update_with_source(pid(20), pid(2), 2, RouteSource::Advertisement);
        assert_eq!(rt.len(), 4);

        // New ad from peer 3: peer 1 is over fair share (3 > 2), should evict peer 1's LRU.
        let added = rt.update_with_source(pid(30), pid(3), 1, RouteSource::Advertisement);
        assert!(added);
        assert_eq!(rt.len(), 4);
        // Peer 1's oldest entry (pid(10), added first) should be evicted
        assert!(rt.lookup(&pid(30)).is_some());
    }

    #[test]
    fn eviction_local_always_evicts() {
        // Table of 4, min_fair_share=2. All peers at fair share.
        let mut rt = RoutingTable::with_capacity(pid(0), 4, 2);
        rt.update_with_source(pid(10), pid(1), 2, RouteSource::Advertisement);
        rt.update_with_source(pid(11), pid(1), 3, RouteSource::Advertisement);
        rt.update_with_source(pid(20), pid(2), 2, RouteSource::Advertisement);
        rt.update_with_source(pid(21), pid(2), 3, RouteSource::Advertisement);
        assert_eq!(rt.len(), 4);

        // Local request always succeeds — evicts LRU from biggest (or either, they're equal).
        let added = rt.update_with_source(pid(30), pid(3), 1, RouteSource::Local);
        assert!(added);
        assert_eq!(rt.len(), 4);
        assert!(rt.lookup(&pid(30)).is_some());
    }

    #[test]
    fn update_existing_dest_no_eviction_needed() {
        // Updating a destination already in the table shouldn't trigger eviction.
        let mut rt = RoutingTable::with_capacity(pid(0), 2, 1);
        rt.update_with_source(pid(10), pid(1), 5, RouteSource::Advertisement);
        rt.update_with_source(pid(20), pid(2), 5, RouteSource::Advertisement);
        assert_eq!(rt.len(), 2);

        // Update existing dest with better cost — should succeed without eviction.
        let changed = rt.update_with_source(pid(10), pid(1), 2, RouteSource::Advertisement);
        assert!(changed); // cost changed
        assert_eq!(rt.len(), 2); // but no new destination added
    }

    #[test]
    fn small_table_never_fills_on_line() {
        // Simulate a 50-node line: 50 destinations through 2 peers, table cap 100.
        let mut rt = RoutingTable::with_capacity(pid(0), 100, 200);
        // Peer 1: nodes to the left (25 of them)
        for i in 1..=25u8 {
            rt.update_with_source(PeerId([i; 32]), pid(1), i as u32, RouteSource::Advertisement);
        }
        // Peer 2: nodes to the right (25 of them)
        for i in 26..=50u8 {
            rt.update_with_source(
                PeerId([i; 32]),
                pid(2),
                (i - 25) as u32,
                RouteSource::Advertisement,
            );
        }
        assert_eq!(rt.len(), 50); // all fit, no eviction
    }
}
