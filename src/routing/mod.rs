pub mod dv;

use std::collections::HashMap;
use std::time::Instant;

use crate::types::PeerId;

const MAX_ROUTES_PER_DEST: usize = 3;

#[derive(Debug, Clone)]
pub struct Route {
    pub next_hop: PeerId,
    pub cost: u32,
    pub last_updated: Instant,
}

/// Routing table: maps destination PeerId to top-k routes.
pub struct RoutingTable {
    routes: HashMap<PeerId, Vec<Route>>,
    local_peer: PeerId,
}

impl RoutingTable {
    pub fn new(local_peer: PeerId) -> Self {
        Self {
            routes: HashMap::new(),
            local_peer,
        }
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
        if dest == self.local_peer {
            return false; // don't route to self
        }

        let routes = self.routes.entry(dest).or_default();

        // Check if we already have a route through this next_hop
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
            if let Some((worst_idx, worst)) = routes.iter().enumerate().max_by_key(|(_, r)| r.cost) {
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

        // Keep sorted by cost
        routes.sort_by_key(|r| r.cost);
        true
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
        self.update(peer, peer, 1);
    }

    /// Add a direct neighbor with a specific cost (based on RTT).
    pub fn add_neighbor_with_cost(&mut self, peer: PeerId, cost: u32) {
        self.update(peer, peer, cost.max(1));
    }

    /// Return up to `n` distinct next-hops for a destination.
    pub fn lookup_multi(&self, dest: &PeerId, n: usize) -> Vec<PeerId> {
        match self.routes.get(dest) {
            Some(routes) => routes
                .iter()
                .map(|r| r.next_hop)
                .take(n)
                .collect(),
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
}
