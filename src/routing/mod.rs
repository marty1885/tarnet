//! Babel-style distance-vector routing (RFC 8966), see `docs/spec/routing.md`.
//!
//! Pure state machine: callers feed it link events and received messages and
//! send what it hands back. It does no I/O.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::types::PeerId;
use crate::wire::{RouteDigestMsg, RouteEntry, RouteUpdateMsg, ROUTE_INFINITY, ROUTE_LANDMARK};

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

/// Landmark acceptance limits and flag rate limit (sybil defence).
#[derive(Debug, Clone, Copy)]
pub struct LandmarkLimits {
    /// Landmarks always accepted via one next hop (`LM_SHARE_MIN`).
    pub share_min: usize,
    /// Fair share factor: `ceil(share_factor · L / d)` per next hop.
    pub share_factor: usize,
    /// Most landmarks accepted in total (`LM_MAX`).
    pub max: usize,
    /// A destination whose flag changes twice within this is ignored as a
    /// landmark for this long.
    pub flag_min_gap: Duration,
}

impl Default for LandmarkLimits {
    fn default() -> Self {
        Self {
            share_min: 32,
            share_factor: 2,
            max: 8192,
            flag_min_gap: Duration::from_secs(600),
        }
    }
}

/// What we know about a destination's `LANDMARK` flag.
struct FlagState {
    flag: bool,
    /// When the flag last changed.
    changed: Option<Instant>,
    /// When we first saw the flag set, this time round.
    since: Option<Instant>,
    /// Ignored as a landmark until then: it toggled too fast.
    ignored_until: Option<Instant>,
}

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
    /// The advertised entry carried the `LANDMARK` flag.
    pub landmark: bool,
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
    /// The last reselection had at least as many destinations as it keeps.
    evicting: bool,
    /// We are a landmark: our own route carries the flag.
    landmark: bool,
    limits: LandmarkLimits,
    flags: HashMap<PeerId, FlagState>,
    /// Accepted landmarks.
    landmarks: HashSet<PeerId>,
    /// Cost of the farthest destination in the local area, while evicting.
    radius: Option<u32>,
    /// Next hops whose landmark flags toggled too fast, for strikes.
    flag_strikes: Vec<PeerId>,
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
            evicting: false,
            landmark: false,
            limits: LandmarkLimits::default(),
            flags: HashMap::new(),
            landmarks: HashSet::new(),
            radius: None,
            flag_strikes: Vec::new(),
        };
        t.advertise_self();
        t
    }

    // ── Lookups ──

    /// Whether the table holds every destination it hears of. Once it is
    /// at its budget it holds only the local area, which is no fair sample
    /// of the network.
    pub fn is_complete(&self) -> bool {
        !self.evicting
    }

    /// Change the budget (testing). Returns the seqno requests to send.
    #[doc(hidden)]
    pub fn set_budget(&mut self, budget: usize) -> Vec<SeqnoRequest> {
        self.budget = budget.max(1);
        self.decide()
    }

    /// Change the landmark acceptance limits. Returns the seqno requests to
    /// send.
    pub fn set_landmark_limits(&mut self, limits: LandmarkLimits) -> Vec<SeqnoRequest> {
        self.limits = limits;
        self.decide()
    }

    /// Our table budget `B_MIN` (before landmarks raise it).
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// Whether we are a landmark.
    pub fn is_landmark(&self) -> bool {
        self.landmark
    }

    /// Take or give up the landmark role: our own route carries the flag.
    pub fn set_landmark(&mut self, on: bool) {
        if self.landmark != on {
            self.landmark = on;
            self.advertise_self();
        }
    }

    /// Accepted landmarks other than us, with their best route.
    pub fn landmarks(&self) -> Vec<(PeerId, Route)> {
        let mut out: Vec<(PeerId, Route)> = self
            .landmarks
            .iter()
            .filter_map(|l| self.selected.get(l).and_then(|r| r.first()).map(|r| (*l, *r)))
            .collect();
        out.sort_by_key(|(l, r)| (r.cost, l.0));
        out
    }

    /// When we first saw `dest` carry the landmark flag (incumbency).
    pub fn landmark_since(&self, dest: &PeerId) -> Option<Instant> {
        self.flags.get(dest).and_then(|f| f.since)
    }

    /// Cost of the farthest destination in our local area, while the table
    /// is evicting; `None` while it holds everything.
    pub fn local_radius(&self) -> Option<u32> {
        self.radius
    }

    /// Some accepted landmark (or we) lies within our local area.
    pub fn is_covered(&self) -> bool {
        if self.landmark {
            return true;
        }
        let radius = self.radius.unwrap_or(u32::MAX);
        self.landmarks()
            .iter()
            .any(|(_, r)| r.cost <= radius)
    }

    /// Next hops that advertised a landmark flag toggling too fast since the
    /// last call.
    pub fn take_flag_strikes(&mut self) -> Vec<PeerId> {
        std::mem::take(&mut self.flag_strikes)
    }

    /// Network size estimate: the table plus us while it is a complete view,
    /// else landmarks times budget.
    pub fn network_size_estimate(&self) -> usize {
        let complete = self.selected.len() + 1;
        if self.is_complete() {
            return complete;
        }
        let l = self.landmarks.len() + self.landmark as usize;
        (l.max(1) * self.budget.max(l)).max(complete)
    }

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
                    landmark: false,
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

    /// The forwarding rule: `dest` itself if linked, else the next hop of
    /// our route to it, else toward the last hint we can reach (the one
    /// nearest `dest`). `usable` says which neighbours we may send to (linked,
    /// and not where the packet came from).
    pub fn next_hop_hinted(
        &self,
        dest: &PeerId,
        hints: &[PeerId],
        usable: impl Fn(&PeerId) -> bool,
    ) -> Option<PeerId> {
        if usable(dest) {
            return Some(*dest);
        }
        let via = |t: &PeerId| {
            self.lookup_multi(t, MAX_ROUTES_PER_DEST)
                .into_iter()
                .find(|n| usable(n))
        };
        via(dest).or_else(|| {
            hints
                .iter()
                .rev()
                .find_map(|h| if usable(h) { Some(*h) } else { via(h) })
        })
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
        // A neighbour keeps its local area plus its accepted landmarks.
        let cap = self
            .budget
            .saturating_mul(RIB_SLACK)
            .saturating_add(self.limits.max)
            + 1;
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
            eflags: if self.landmark { ROUTE_LANDMARK } else { 0 },
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

    /// Track each destination's landmark flag (as carried by its best
    /// route) and mark the ones that toggle too fast.
    fn observe_flags(&mut self, ranked: &[(u32, PeerId, Vec<Route>)]) {
        let now = Instant::now();
        let gap = self.limits.flag_min_gap;
        for (_, dest, routes) in ranked {
            let flag = routes[0].landmark;
            let st = self.flags.entry(*dest).or_insert(FlagState {
                flag,
                changed: None,
                since: flag.then_some(now),
                ignored_until: None,
            });
            if st.flag == flag {
                continue;
            }
            if st.changed.is_some_and(|t| now.duration_since(t) < gap) {
                st.ignored_until = Some(now + gap);
                self.flag_strikes.push(routes[0].next_hop);
            }
            st.flag = flag;
            st.changed = Some(now);
            st.since = flag.then_some(now);
        }
        let present: HashSet<PeerId> = ranked.iter().map(|(_, d, _)| *d).collect();
        // Forget destinations gone for longer than the rate limit.
        self.flags.retain(|d, st| {
            present.contains(d) || st.changed.map_or(false, |t| now.duration_since(t) < gap)
        });
    }

    /// Landmarks to accept from the ranked candidates: flagged, not toggling,
    /// at most a fair share per next hop and `max` in total.
    fn accept_landmarks(&self, ranked: &[(u32, PeerId, Vec<Route>)]) -> HashSet<PeerId> {
        let now = Instant::now();
        let candidates: Vec<&(u32, PeerId, Vec<Route>)> = ranked
            .iter()
            .filter(|(_, d, routes)| {
                routes[0].landmark
                    && !self
                        .flags
                        .get(d)
                        .and_then(|f| f.ignored_until)
                        .is_some_and(|t| t > now)
            })
            .collect();
        let d = self.neighbours.len().max(1);
        let share = self
            .limits
            .share_min
            .max((self.limits.share_factor * candidates.len()).div_ceil(d));
        let mut per_hop: HashMap<PeerId, usize> = HashMap::new();
        let mut accepted = HashSet::new();
        for (_, dest, routes) in candidates {
            if accepted.len() >= self.limits.max {
                break;
            }
            let n = per_hop.entry(routes[0].next_hop).or_default();
            if *n >= share {
                continue;
            }
            *n += 1;
            accepted.insert(*dest);
        }
        accepted
    }

    /// Reselect every route, keep the local area (the `max(budget, L)`
    /// nearest destinations) plus every accepted landmark, and queue the
    /// differences to what we advertised.
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
                    landmark: e.eflags & ROUTE_LANDMARK != 0,
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
        self.observe_flags(&ranked);
        self.landmarks = self.accept_landmarks(&ranked);
        let area = self.budget.max(self.landmarks.len() + self.landmark as usize);
        // At exactly the budget we can't tell whether more lie beyond: only
        // fewer destinations than we could keep proves a complete view.
        self.evicting = ranked.len() >= area;
        self.radius = if self.evicting {
            Some(ranked[area - 1].0)
        } else {
            None
        };
        let landmarks = &self.landmarks;
        let ranked: Vec<(u32, PeerId, Vec<Route>)> = ranked
            .into_iter()
            .enumerate()
            .filter(|(i, (_, dest, _))| *i < area || landmarks.contains(dest))
            .map(|(_, r)| r)
            .collect();

        let old = std::mem::take(&mut self.selected);
        let mut changes = Vec::with_capacity(ranked.len());
        for (cost, dest, routes) in ranked {
            changes.push(RouteEntry {
                dest,
                seqno: routes[0].seqno,
                metric: cost as u16,
                // Relays pass on the flag of the route they selected.
                eflags: if routes[0].landmark { ROUTE_LANDMARK } else { 0 },
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
        assert!(!a.is_complete());
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

    fn landmark_entry(dest: u8, seqno: u16, metric: u16) -> RouteEntry {
        RouteEntry {
            eflags: ROUTE_LANDMARK,
            ..entry(dest, seqno, metric)
        }
    }

    #[test]
    fn landmarks_are_kept_beyond_the_budget_and_flagged_on() {
        let mut a = RoutingTable::with_budget(pid(1), 2);
        a.neighbour_up(pid(2), COST_FAST);
        a.apply_update(
            &pid(2),
            &update(vec![
                entry(2, 1, 0),
                entry(7, 1, 1),
                entry(8, 1, 2),
                landmark_entry(9, 1, 6),
            ]),
        );
        // Local area: 2 and 7. 9 is far but a landmark.
        assert!(a.lookup(&pid(8)).is_none());
        let r = a.lookup(&pid(9)).unwrap();
        assert!(r.landmark);
        assert_eq!(a.landmarks().iter().map(|(l, _)| *l).collect::<Vec<_>>(), vec![pid(9)]);
        assert_eq!(a.local_radius(), Some(2));
        assert!(!a.is_covered(), "landmark at 7 is outside radius 2");
        // We pass the flag on.
        let adv = a.advertised.get(&pid(9)).unwrap();
        assert_eq!(adv.eflags, ROUTE_LANDMARK);

        // Our own flag rides on our own route.
        a.set_landmark(true);
        assert_eq!(a.advertised.get(&pid(1)).unwrap().eflags, ROUTE_LANDMARK);
        assert!(a.is_covered());
        a.set_landmark(false);
        assert_eq!(a.advertised.get(&pid(1)).unwrap().eflags, 0);
    }

    #[test]
    fn a_near_landmark_covers_us() {
        let mut a = RoutingTable::with_budget(pid(1), 2);
        a.neighbour_up(pid(2), COST_FAST);
        a.apply_update(
            &pid(2),
            &update(vec![entry(2, 1, 0), landmark_entry(7, 1, 1), entry(8, 1, 2)]),
        );
        assert!(a.is_covered());
    }

    #[test]
    fn landmark_budget_grows_with_landmarks() {
        // Budget 1, three landmarks: B = max(1, 3) keeps three nearest plus
        // the landmarks.
        let mut a = RoutingTable::with_budget(pid(1), 1);
        a.neighbour_up(pid(2), COST_FAST);
        a.apply_update(
            &pid(2),
            &update(vec![
                entry(2, 1, 0),
                entry(3, 1, 1),
                entry(4, 1, 2),
                entry(5, 1, 3),
                landmark_entry(10, 1, 9),
                landmark_entry(11, 1, 9),
                landmark_entry(12, 1, 9),
            ]),
        );
        for d in [2, 3, 4, 10, 11, 12] {
            assert!(a.lookup(&pid(d)).is_some(), "lost {}", d);
        }
        assert!(a.lookup(&pid(5)).is_none());
        assert_eq!(a.network_size_estimate(), 9);
    }

    #[test]
    fn landmarks_per_next_hop_are_capped() {
        let mut a = RoutingTable::with_budget(pid(1), 1);
        a.limits = LandmarkLimits {
            share_min: 2,
            share_factor: 1,
            max: 100,
            ..LandmarkLimits::default()
        };
        a.neighbour_up(pid(2), COST_FAST);
        a.neighbour_up(pid(3), COST_FAST);
        // A sybil behind 2 claims eight landmarks; 3 has one.
        let sybils: Vec<RouteEntry> = (10..18).map(|d| landmark_entry(d, 1, 1)).collect();
        a.apply_update(&pid(2), &update(sybils));
        a.apply_update(&pid(3), &update(vec![landmark_entry(30, 1, 1)]));
        let ls: Vec<PeerId> = a.landmarks().into_iter().map(|(l, _)| l).collect();
        // Share: max(2, ceil(1 * 9 / 2)) = 5 via one next hop.
        assert_eq!(ls.iter().filter(|l| l.0[0] < 20).count(), 5);
        assert!(ls.contains(&pid(30)));

        a.limits.max = 3;
        a.decide();
        assert_eq!(a.landmarks().len(), 3);
    }

    #[test]
    fn a_toggling_landmark_flag_is_ignored_and_struck() {
        let mut a = RoutingTable::with_budget(pid(1), 1);
        a.neighbour_up(pid(2), COST_FAST);
        a.apply_update(&pid(2), &update(vec![landmark_entry(9, 1, 1)]));
        assert_eq!(a.landmarks().len(), 1);
        // One change is fine.
        a.apply_update(&pid(2), &update(vec![entry(9, 1, 1)]));
        assert!(a.landmarks().is_empty());
        assert!(a.take_flag_strikes().is_empty());
        // A second within the rate limit is not.
        a.apply_update(&pid(2), &update(vec![landmark_entry(9, 1, 1)]));
        assert!(a.landmarks().is_empty(), "toggling landmark accepted");
        assert_eq!(a.take_flag_strikes(), vec![pid(2)]);
    }

    #[test]
    fn landmark_flag_propagates_along_a_chain() {
        let (mut a, mut b, mut c) = (
            RoutingTable::new(pid(1)),
            RoutingTable::new(pid(2)),
            RoutingTable::new(pid(3)),
        );
        link(&mut a, &mut b);
        link(&mut b, &mut c);
        exchange(&mut [&mut a, &mut b, &mut c]);
        c.set_landmark(true);
        exchange(&mut [&mut a, &mut b, &mut c]);
        assert!(a.lookup(&pid(3)).unwrap().landmark);
        assert!(a.landmark_since(&pid(3)).is_some());
        c.set_landmark(false);
        exchange(&mut [&mut a, &mut b, &mut c]);
        assert!(!a.lookup(&pid(3)).unwrap().landmark);
        assert!(a.landmark_since(&pid(3)).is_none());
    }

    #[test]
    fn forwarding_rule_prefers_dest_then_route_then_last_reachable_hint() {
        let mut a = RoutingTable::new(pid(1));
        a.neighbour_up(pid(2), COST_FAST);
        a.neighbour_up(pid(3), COST_FAST);
        a.apply_update(&pid(2), &update(vec![entry(20, 1, 1)]));
        a.apply_update(&pid(3), &update(vec![entry(30, 1, 1)]));
        let linked = |p: &PeerId| *p == pid(2) || *p == pid(3);
        // 1. Linked destination.
        assert_eq!(a.next_hop_hinted(&pid(3), &[], linked), Some(pid(3)));
        // 2. Routed destination, hints ignored.
        assert_eq!(a.next_hop_hinted(&pid(20), &[pid(30)], linked), Some(pid(2)));
        // 3. Unknown: the last hint we reach, not the first.
        assert_eq!(
            a.next_hop_hinted(&pid(99), &[pid(20), pid(30), pid(98)], linked),
            Some(pid(3))
        );
        assert_eq!(
            a.next_hop_hinted(&pid(99), &[pid(30), pid(20)], linked),
            Some(pid(2))
        );
        // A linked hint is used directly.
        assert_eq!(a.next_hop_hinted(&pid(99), &[pid(2)], linked), Some(pid(2)));
        // 4. Nothing reachable.
        assert_eq!(a.next_hop_hinted(&pid(99), &[pid(98)], linked), None);
        // Never back where it came from: the alternative route is used.
        let not_2 = |p: &PeerId| *p == pid(3);
        assert_eq!(a.next_hop_hinted(&pid(20), &[pid(30)], not_2), Some(pid(3)));
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
