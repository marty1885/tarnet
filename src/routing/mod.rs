//! Babel-style distance-vector routing (RFC 8966), see `docs/spec/routing.md`.
//!
//! Pure state machine: callers feed it link events and received messages and
//! send what it hands back. It does no I/O.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use crate::types::PeerId;
use crate::wire::{RouteDigestMsg, RouteEntry, RouteUpdateMsg, ROUTE_INFINITY};

/// Routes kept per destination for failover.
const MAX_ROUTES_PER_DEST: usize = 3;

/// Minimum number of destinations every node keeps (network-wide assumption).
pub const B_MIN: usize = 1024;

/// Entries accepted from one neighbour beyond our own budget. A neighbour
/// keeps at most its own budget, which is never far from ours.
const RIB_SLACK: usize = 2;

/// Hop count of a seqno request we originate.
const SEQNO_REQUEST_HOPS: u8 = 64;

/// A feasibility distance is forgotten this long after its destination was
/// last advertised.
const FD_GC: Duration = Duration::from_secs(180);

/// Duplicate seqno requests are dropped for this long.
const REQUEST_DEDUP: Duration = Duration::from_secs(10);

/// Link cost of a fast link.
pub const COST_FAST: u16 = 1;
/// Link cost of a slow link.
pub const COST_SLOW: u16 = 16;

/// `a` is newer than `b`, modulo 2^16.
pub fn seqno_newer(a: u16, b: u16) -> bool {
    a != b && b.wrapping_sub(a) >= 0x8000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub next_hop: PeerId,
    pub cost: u32,
    pub seqno: u16,
}

struct Neighbour {
    cost: u16,
    degree: u8,
    /// Everything this neighbour advertised to us and has not retracted.
    rib: BTreeMap<PeerId, RouteEntry>,
    /// A full dump in progress, replacing `rib` when it ends.
    staging: Option<BTreeMap<PeerId, RouteEntry>>,
    /// Changes to our advertised set not yet sent to this neighbour.
    pending: BTreeMap<PeerId, RouteEntry>,
}

/// A seqno request to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqnoRequest {
    pub to: PeerId,
    pub dest: PeerId,
    pub seqno: u16,
    pub hops: u8,
}

pub struct RoutingTable {
    local: PeerId,
    seqno: u16,
    budget: usize,
    neighbours: HashMap<PeerId, Neighbour>,
    /// Selected routes, best first, for the destinations we keep.
    selected: HashMap<PeerId, Vec<Route>>,
    /// What we advertise, including ourselves.
    advertised: BTreeMap<PeerId, RouteEntry>,
    /// Feasibility distance `(seqno, metric)` and when it was last used.
    fd: HashMap<PeerId, (u16, u16, Instant)>,
    recent_requests: HashMap<(PeerId, u16), Instant>,
}

impl RoutingTable {
    pub fn new(local: PeerId) -> Self {
        Self::with_budget(local, B_MIN)
    }

    pub fn with_budget(local: PeerId, budget: usize) -> Self {
        let mut t = Self {
            local,
            seqno: rand::random(),
            budget,
            neighbours: HashMap::new(),
            selected: HashMap::new(),
            advertised: BTreeMap::new(),
            fd: HashMap::new(),
            recent_requests: HashMap::new(),
        };
        t.advertise_self();
        t
    }

    // ── Lookups ──

    /// Number of destinations we have a route to.
    pub fn len(&self) -> usize {
        self.selected.len()
    }

    /// Best route to `dest`. A direct neighbour is always reachable.
    pub fn lookup(&self, dest: &PeerId) -> Option<Route> {
        self.selected
            .get(dest)
            .and_then(|r| r.first().copied())
            .or_else(|| {
                self.neighbours.get(dest).map(|n| Route {
                    next_hop: *dest,
                    cost: n.cost as u32,
                    seqno: 0,
                })
            })
    }

    /// Up to `n` distinct next hops toward `dest`, best first.
    pub fn lookup_multi(&self, dest: &PeerId, n: usize) -> Vec<PeerId> {
        match self.selected.get(dest) {
            Some(routes) => routes.iter().map(|r| r.next_hop).take(n).collect(),
            None => self
                .lookup(dest)
                .map(|r| vec![r.next_hop])
                .unwrap_or_default(),
        }
    }

    /// Every destination with its best route.
    pub fn all_destinations(&self) -> impl Iterator<Item = (&PeerId, &Route)> {
        self.selected
            .iter()
            .filter_map(|(dest, routes)| routes.first().map(|r| (dest, r)))
    }

    /// Our number of links, saturating at 255.
    pub fn degree(&self) -> u8 {
        self.neighbours.len().min(255) as u8
    }

    /// A neighbour's advertised number of links.
    pub fn neighbour_degree(&self, n: &PeerId) -> Option<u8> {
        self.neighbours.get(n).map(|n| n.degree)
    }

    // ── Link events ──

    /// A neighbour came up. Returns the full dump to send it.
    pub fn neighbour_up(&mut self, n: PeerId, cost: u16) -> Vec<RouteUpdateMsg> {
        let cost = cost.max(1);
        match self.neighbours.get_mut(&n) {
            Some(nb) if nb.cost == cost => {}
            Some(nb) => {
                nb.cost = cost;
                self.decide();
            }
            None => {
                self.neighbours.insert(
                    n,
                    Neighbour {
                        cost,
                        degree: 0,
                        rib: BTreeMap::new(),
                        staging: None,
                        pending: BTreeMap::new(),
                    },
                );
            }
        }
        self.full_dump(&n)
    }

    /// A neighbour went down: its routes are gone. Returns seqno requests for
    /// destinations left with only infeasible routes.
    pub fn neighbour_down(&mut self, n: &PeerId) -> Vec<SeqnoRequest> {
        if self.neighbours.remove(n).is_none() {
            return Vec::new();
        }
        self.decide()
    }

    pub fn is_neighbour(&self, n: &PeerId) -> bool {
        self.neighbours.contains_key(n)
    }

    // ── Received messages ──

    /// Apply a `RouteUpdate` from neighbour `from`.
    pub fn apply_update(&mut self, from: &PeerId, msg: &RouteUpdateMsg) -> Vec<SeqnoRequest> {
        let cap = self.budget.saturating_mul(RIB_SLACK) + 1;
        let Some(nb) = self.neighbours.get_mut(from) else {
            return Vec::new();
        };
        nb.degree = msg.degree;
        if msg.flags & crate::wire::ROUTE_FULL_START != 0 {
            nb.staging = Some(BTreeMap::new());
        }
        let full = msg.flags & crate::wire::ROUTE_FULL != 0;
        // Entries for ourselves are kept too: the digest covers them. They
        // are never selected.
        for e in &msg.entries {
            let mut targets = vec![&mut nb.rib];
            if let (true, Some(staging)) = (full, nb.staging.as_mut()) {
                targets.push(staging);
            }
            for rib in targets {
                if e.metric == ROUTE_INFINITY {
                    rib.remove(&e.dest);
                } else if rib.len() < cap || rib.contains_key(&e.dest) {
                    rib.insert(e.dest, *e);
                }
            }
        }
        if msg.flags & crate::wire::ROUTE_FULL_END != 0 {
            if let Some(staging) = nb.staging.take() {
                nb.rib = staging;
            }
        }
        self.decide()
    }

    /// Whether `from`'s digest matches what we hold from it. A mismatch means
    /// an update was lost; ask for a full dump.
    pub fn digest_matches(&self, from: &PeerId, digest: &RouteDigestMsg) -> bool {
        self.neighbours
            .get(from)
            .map_or(true, |nb| RouteDigestMsg::of(nb.rib.values()) == *digest)
    }

    /// Handle a seqno request from `from`. Returns a request to forward, if
    /// any; answers are queued as updates.
    pub fn seqno_request(
        &mut self,
        from: &PeerId,
        dest: PeerId,
        seqno: u16,
        hops: u8,
    ) -> Option<SeqnoRequest> {
        if dest == self.local {
            if seqno_newer(seqno, self.seqno) {
                self.seqno = seqno;
                self.advertise_self();
            } else {
                self.resend(&dest, from);
            }
            return None;
        }
        let now = Instant::now();
        if self
            .recent_requests
            .get(&(dest, seqno))
            .is_some_and(|t| now.duration_since(*t) < REQUEST_DEDUP)
        {
            return None;
        }
        self.recent_requests.insert((dest, seqno), now);
        if let Some(best) = self.selected.get(&dest).and_then(|r| r.first()) {
            if !seqno_newer(seqno, best.seqno) {
                self.resend(&dest, from);
                return None;
            }
        }
        if hops <= 1 {
            return None;
        }
        let next = self
            .selected
            .get(&dest)
            .and_then(|r| r.first())
            .map(|r| r.next_hop)
            .filter(|n| n != from)
            .or_else(|| {
                self.neighbours
                    .iter()
                    .find(|(n, nb)| *n != from && nb.rib.contains_key(&dest))
                    .map(|(n, _)| *n)
            })?;
        Some(SeqnoRequest {
            to: next,
            dest,
            seqno,
            hops: hops - 1,
        })
    }

    // ── Outgoing ──

    /// Changes not yet sent to `n`, split into messages.
    pub fn take_pending(&mut self, n: &PeerId) -> Vec<RouteUpdateMsg> {
        let degree = self.degree();
        let Some(nb) = self.neighbours.get_mut(n) else {
            return Vec::new();
        };
        let entries: Vec<RouteEntry> = std::mem::take(&mut nb.pending).into_values().collect();
        entries
            .chunks(RouteUpdateMsg::MAX_ENTRIES)
            .map(|c| RouteUpdateMsg {
                flags: 0,
                degree,
                entries: c.to_vec(),
            })
            .collect()
    }

    pub fn has_pending(&self, n: &PeerId) -> bool {
        self.neighbours
            .get(n)
            .is_some_and(|nb| !nb.pending.is_empty())
    }

    /// Everything we advertise, as a full dump for `n`. Clears its pending
    /// changes, which the dump includes.
    pub fn full_dump(&mut self, n: &PeerId) -> Vec<RouteUpdateMsg> {
        if let Some(nb) = self.neighbours.get_mut(n) {
            nb.pending.clear();
        }
        let degree = self.degree();
        let entries: Vec<RouteEntry> = self.advertised.values().copied().collect();
        let chunks: Vec<&[RouteEntry]> = entries.chunks(RouteUpdateMsg::MAX_ENTRIES).collect();
        let last = chunks.len().saturating_sub(1);
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, c)| {
                let mut flags = crate::wire::ROUTE_FULL;
                if i == 0 {
                    flags |= crate::wire::ROUTE_FULL_START;
                }
                if i == last {
                    flags |= crate::wire::ROUTE_FULL_END;
                }
                RouteUpdateMsg {
                    flags,
                    degree,
                    entries: c.to_vec(),
                }
            })
            .collect()
    }

    /// Digest of what `n` should hold from us, or `None` while changes to it
    /// are still pending.
    pub fn digest_for(&self, n: &PeerId) -> Option<RouteDigestMsg> {
        if self.has_pending(n) {
            return None;
        }
        Some(RouteDigestMsg::of(self.advertised.values()))
    }

    /// Forget old feasibility distances and request records.
    pub fn gc(&mut self) {
        let now = Instant::now();
        let selected = &self.selected;
        self.fd
            .retain(|d, (_, _, t)| selected.contains_key(d) || now.duration_since(*t) < FD_GC);
        self.recent_requests
            .retain(|_, t| now.duration_since(*t) < REQUEST_DEDUP);
    }

    // ── Internals ──

    fn feasible(&self, dest: &PeerId, e: &RouteEntry) -> bool {
        match self.fd.get(dest) {
            None => true,
            Some(&(s, m, _)) => seqno_newer(e.seqno, s) || (e.seqno == s && e.metric < m),
        }
    }

    fn advertise_self(&mut self) {
        let e = RouteEntry {
            dest: self.local,
            seqno: self.seqno,
            metric: 0,
            eflags: 0,
        };
        self.set_advertised(e);
    }

    fn set_advertised(&mut self, e: RouteEntry) {
        if e.metric == ROUTE_INFINITY {
            if self.advertised.remove(&e.dest).is_none() {
                return;
            }
        } else {
            if self.advertised.get(&e.dest) == Some(&e) {
                return;
            }
            self.advertised.insert(e.dest, e);
            if e.dest != self.local {
                let now = Instant::now();
                let fd = self.fd.entry(e.dest).or_insert((e.seqno, e.metric, now));
                if seqno_newer(e.seqno, fd.0) || (e.seqno == fd.0 && e.metric < fd.1) {
                    *fd = (e.seqno, e.metric, now);
                }
                fd.2 = now;
            }
        }
        for nb in self.neighbours.values_mut() {
            nb.pending.insert(e.dest, e);
        }
    }

    /// Queue our current entry for `dest` (or a retraction) to `to` only.
    fn resend(&mut self, dest: &PeerId, to: &PeerId) {
        let e = self.advertised.get(dest).copied().unwrap_or(RouteEntry {
            dest: *dest,
            seqno: 0,
            metric: ROUTE_INFINITY,
            eflags: 0,
        });
        if let Some(nb) = self.neighbours.get_mut(to) {
            nb.pending.insert(*dest, e);
        }
    }

    /// Reselect every route, keep the `budget` best destinations, and queue
    /// the differences to what we advertised.
    fn decide(&mut self) -> Vec<SeqnoRequest> {
        let mut candidates: HashMap<PeerId, Vec<Route>> = HashMap::new();
        let mut infeasible: HashMap<PeerId, Vec<PeerId>> = HashMap::new();
        for (n, nb) in &self.neighbours {
            for (dest, e) in &nb.rib {
                if *dest == self.local {
                    continue;
                }
                let cost = e.metric as u32 + nb.cost as u32;
                if cost >= ROUTE_INFINITY as u32 {
                    continue;
                }
                if !self.feasible(dest, e) {
                    infeasible.entry(*dest).or_default().push(*n);
                    continue;
                }
                candidates.entry(*dest).or_default().push(Route {
                    next_hop: *n,
                    cost,
                    seqno: e.seqno,
                });
            }
        }

        let mut ranked: Vec<(u32, PeerId, Vec<Route>)> = candidates
            .into_iter()
            .map(|(dest, mut routes)| {
                let current = self
                    .selected
                    .get(&dest)
                    .and_then(|r| r.first())
                    .map(|r| r.next_hop);
                // Ties keep the current next hop, so routes don't flap.
                routes.sort_by_key(|r| (r.cost, Some(r.next_hop) != current, r.next_hop.0));
                routes.truncate(MAX_ROUTES_PER_DEST);
                (routes[0].cost, dest, routes)
            })
            .collect();
        ranked.sort_by_key(|(cost, dest, _)| (*cost, dest.0));
        ranked.truncate(self.budget);

        let old = std::mem::take(&mut self.selected);
        let mut changes = Vec::with_capacity(ranked.len());
        for (cost, dest, routes) in ranked {
            changes.push(RouteEntry {
                dest,
                seqno: routes[0].seqno,
                metric: cost as u16,
                eflags: 0,
            });
            self.selected.insert(dest, routes);
        }
        for e in changes {
            self.set_advertised(e);
        }

        let mut requests = Vec::new();
        for dest in old.keys() {
            if self.selected.contains_key(dest) {
                continue;
            }
            self.set_advertised(RouteEntry {
                dest: *dest,
                seqno: 0,
                metric: ROUTE_INFINITY,
                eflags: 0,
            });
            // Starvation: routes exist but none is feasible. Ask the
            // destination for a newer seqno.
            if let (Some(via), Some(&(s, _, _))) = (infeasible.get(dest), self.fd.get(dest)) {
                for n in via {
                    requests.push(SeqnoRequest {
                        to: *n,
                        dest: *dest,
                        seqno: s.wrapping_add(1),
                        hops: SEQNO_REQUEST_HOPS,
                    });
                }
            }
        }
        requests
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ROUTE_FULL, ROUTE_FULL_END, ROUTE_FULL_START};

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    fn entry(dest: u8, seqno: u16, metric: u16) -> RouteEntry {
        RouteEntry {
            dest: pid(dest),
            seqno,
            metric,
            eflags: 0,
        }
    }

    fn update(entries: Vec<RouteEntry>) -> RouteUpdateMsg {
        RouteUpdateMsg {
            flags: 0,
            degree: 1,
            entries,
        }
    }

    /// Deliver everything pending between two tables, both ways, until quiet.
    fn exchange(tables: &mut [&mut RoutingTable]) {
        for _ in 0..32 {
            let mut moved = false;
            for i in 0..tables.len() {
                for j in 0..tables.len() {
                    if i == j {
                        continue;
                    }
                    let to = tables[j].local;
                    if !tables[i].is_neighbour(&to) {
                        continue;
                    }
                    let from = tables[i].local;
                    for m in tables[i].take_pending(&to) {
                        moved = true;
                        tables[j].apply_update(&from, &m);
                    }
                }
            }
            if !moved {
                return;
            }
        }
        panic!("routing did not converge");
    }

    fn link(a: &mut RoutingTable, b: &mut RoutingTable) {
        let (pa, pb) = (a.local, b.local);
        let (to_b, to_a) = (a.neighbour_up(pb, COST_FAST), b.neighbour_up(pa, COST_FAST));
        for m in to_b {
            b.apply_update(&pa, &m);
        }
        for m in to_a {
            a.apply_update(&pb, &m);
        }
    }

    #[test]
    fn seqno_comparison_wraps() {
        assert!(seqno_newer(1, 0));
        assert!(seqno_newer(0, 0xFFFF));
        assert!(!seqno_newer(0, 1));
        assert!(!seqno_newer(5, 5));
    }

    #[test]
    fn learns_routes_along_a_chain() {
        let (mut a, mut b, mut c) = (
            RoutingTable::new(pid(1)),
            RoutingTable::new(pid(2)),
            RoutingTable::new(pid(3)),
        );
        link(&mut a, &mut b);
        link(&mut b, &mut c);
        exchange(&mut [&mut a, &mut b, &mut c]);
        let r = a.lookup(&pid(3)).unwrap();
        assert_eq!((r.next_hop, r.cost), (pid(2), 2));
        assert_eq!(c.lookup(&pid(1)).unwrap().next_hop, pid(2));
    }

    #[test]
    fn link_death_retracts_downstream() {
        let (mut a, mut b, mut c) = (
            RoutingTable::new(pid(1)),
            RoutingTable::new(pid(2)),
            RoutingTable::new(pid(3)),
        );
        link(&mut a, &mut b);
        link(&mut b, &mut c);
        exchange(&mut [&mut a, &mut b, &mut c]);
        b.neighbour_down(&pid(3));
        c.neighbour_down(&pid(2));
        exchange(&mut [&mut a, &mut b, &mut c]);
        assert!(a.lookup(&pid(3)).is_none());
        assert!(b.lookup(&pid(3)).is_none());
    }

    #[test]
    fn infeasible_update_is_not_selected() {
        let mut a = RoutingTable::new(pid(1));
        a.neighbour_up(pid(2), COST_FAST);
        a.neighbour_up(pid(3), COST_FAST);
        a.apply_update(&pid(2), &update(vec![entry(9, 10, 1)]));
        assert_eq!(a.lookup(&pid(9)).unwrap().cost, 2);
        // Same seqno, metric not below our FD (2): could be a loop through us.
        a.apply_update(&pid(3), &update(vec![entry(9, 10, 2)]));
        a.apply_update(&pid(2), &update(vec![entry(9, 10, ROUTE_INFINITY)]));
        assert!(a.lookup(&pid(9)).is_none());
    }

    #[test]
    fn starvation_requests_newer_seqno() {
        let mut a = RoutingTable::new(pid(1));
        a.neighbour_up(pid(2), COST_FAST);
        a.neighbour_up(pid(3), COST_FAST);
        a.apply_update(&pid(2), &update(vec![entry(9, 10, 1)]));
        a.apply_update(&pid(3), &update(vec![entry(9, 10, 5)]));
        let reqs = a.apply_update(&pid(2), &update(vec![entry(9, 10, ROUTE_INFINITY)]));
        assert_eq!(
            reqs,
            vec![SeqnoRequest {
                to: pid(3),
                dest: pid(9),
                seqno: 11,
                hops: SEQNO_REQUEST_HOPS
            }]
        );
        // The destination answers with a newer seqno: feasible again.
        a.apply_update(&pid(3), &update(vec![entry(9, 11, 5)]));
        assert_eq!(a.lookup(&pid(9)).unwrap().next_hop, pid(3));
    }

    #[test]
    fn destination_bumps_seqno_on_request() {
        let mut d = RoutingTable::new(pid(9));
        d.neighbour_up(pid(3), COST_FAST);
        d.take_pending(&pid(3));
        let want = d.seqno.wrapping_add(1);
        assert!(d.seqno_request(&pid(3), pid(9), want, 64).is_none());
        let sent = d.take_pending(&pid(3));
        assert_eq!(sent[0].entries, vec![entry(9, want, 0)]);
    }

    #[test]
    fn seqno_request_is_forwarded_toward_destination() {
        let mut b = RoutingTable::new(pid(2));
        b.neighbour_up(pid(1), COST_FAST);
        b.neighbour_up(pid(3), COST_FAST);
        b.apply_update(&pid(3), &update(vec![entry(9, 10, 1)]));
        let fwd = b.seqno_request(&pid(1), pid(9), 11, 64).unwrap();
        assert_eq!((fwd.to, fwd.hops), (pid(3), 63));
        // Duplicates are dropped.
        assert!(b.seqno_request(&pid(1), pid(9), 11, 64).is_none());
    }

    #[test]
    fn budget_keeps_nearest_and_retracts_the_rest() {
        let mut a = RoutingTable::with_budget(pid(1), 2);
        a.neighbour_up(pid(2), COST_FAST);
        a.apply_update(
            &pid(2),
            &update(vec![entry(2, 1, 0), entry(8, 1, 3), entry(9, 1, 1)]),
        );
        assert!(a.lookup(&pid(9)).is_some());
        assert!(a.lookup(&pid(8)).is_none());
        assert_eq!(a.len(), 2);
        let adv: Vec<PeerId> = a.advertised.keys().copied().collect();
        assert!(!adv.contains(&pid(8)));
    }

    #[test]
    fn digest_mismatch_and_full_dump_repair() {
        let (mut a, mut b, mut c) = (
            RoutingTable::new(pid(1)),
            RoutingTable::new(pid(2)),
            RoutingTable::new(pid(3)),
        );
        link(&mut a, &mut b);
        link(&mut b, &mut c);
        exchange(&mut [&mut a, &mut b, &mut c]);
        assert!(a.digest_matches(&pid(2), &b.digest_for(&pid(1)).unwrap()));

        // B loses C, and its retraction to A is lost.
        b.neighbour_down(&pid(3));
        b.take_pending(&pid(1));
        let digest = b.digest_for(&pid(1)).unwrap();
        assert!(!a.digest_matches(&pid(2), &digest));
        for m in b.full_dump(&pid(1)) {
            a.apply_update(&pid(2), &m);
        }
        assert!(a.digest_matches(&pid(2), &digest));
        assert!(a.lookup(&pid(3)).is_none());
    }

    #[test]
    fn full_dump_flags_bracket_the_dump() {
        let mut a = RoutingTable::new(pid(1));
        a.neighbour_up(pid(2), COST_FAST);
        let dump = a.full_dump(&pid(2));
        assert_eq!(dump.len(), 1);
        assert_eq!(
            dump[0].flags,
            ROUTE_FULL | ROUTE_FULL_START | ROUTE_FULL_END
        );
    }

    #[test]
    fn loop_free_after_link_failure_in_a_ring() {
        // Square a-b-c-d-a; cut b-c and c-d so c is unreachable. No node may
        // keep a route to c that loops.
        let mut t: Vec<RoutingTable> = (1..=4).map(|i| RoutingTable::new(pid(i))).collect();
        let edges = [(0, 1), (1, 2), (2, 3), (3, 0)];
        for &(i, j) in &edges {
            let (lo, hi) = t.split_at_mut(j.max(i));
            let (x, y) = if i < j {
                (&mut lo[i], &mut hi[0])
            } else {
                (&mut hi[0], &mut lo[j])
            };
            link(x, y);
        }
        {
            let mut refs: Vec<&mut RoutingTable> = t.iter_mut().collect();
            exchange(&mut refs);
        }
        t[1].neighbour_down(&pid(3));
        t[2].neighbour_down(&pid(2));
        t[2].neighbour_down(&pid(4));
        t[3].neighbour_down(&pid(3));
        let mut refs: Vec<&mut RoutingTable> = t.iter_mut().collect();
        exchange(&mut refs);
        for (i, table) in t.iter().enumerate() {
            if i != 2 {
                assert!(
                    table.lookup(&pid(3)).is_none(),
                    "node {} kept a route",
                    i + 1
                );
            }
        }
    }
}
