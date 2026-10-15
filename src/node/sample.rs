//! Relay sampling: Metropolis–Hastings walks for uniformly random relays,
//! and the pool of sampled relays that circuit waypoints, intro points and
//! rendezvous points are picked from once the routing table holds only the
//! local area.

use super::*;
use crate::wire::{Sample, SampleResultMsg, SampleWalkMsg, SAMPLE_PATH_MAX};

/// Sampled relays kept ready.
const POOL_SIZE: usize = 32;
/// A sample is replaced after about this long (jittered per sample).
const SAMPLE_LIFETIME: Duration = Duration::from_secs(600);
/// How often the pool is topped up.
const POOL_REFRESH: Duration = Duration::from_secs(20);
/// Walks started at once when topping up.
const POOL_WALKS_AT_ONCE: usize = 8;
/// How long the walker waits for a result, and relays remember a walk.
const WALK_TIMEOUT: Duration = Duration::from_secs(20);
/// Walks a relay remembers at once.
const MAX_FORWARDED_WALKS: usize = 4096;
/// Rounds of walks a request for relays may wait for.
const ON_DEMAND_ROUNDS: usize = 3;
/// Most steps a walk may ask for.
const MAX_STEPS: u8 = 64;

/// A relay found by a walk, with hints that reach it.
#[derive(Clone)]
pub(super) struct SampledRelay {
    pub peer: PeerId,
    /// Forwarding hints toward `peer`, nearest it last.
    pub hints: Vec<PeerId>,
    expires: Instant,
}

/// A walk we passed on.
struct Forwarded {
    /// Who sent it to us, and the token they used.
    prev: PeerId,
    prev_token: [u8; 32],
    /// Who we sent it to: only they may answer.
    next: PeerId,
}

/// Our own walk in flight.
struct Waiter {
    first_hop: PeerId,
    tx: oneshot::Sender<Option<Sample>>,
}

pub(super) struct SampleState {
    forwarded: Mutex<crate::bounded::BoundedMap<[u8; 32], Forwarded>>,
    waiters: Mutex<HashMap<[u8; 32], Waiter>>,
    pool: Mutex<Vec<SampledRelay>>,
}

impl SampleState {
    pub(super) fn new() -> Self {
        Self {
            forwarded: Mutex::new(crate::bounded::BoundedMap::new(MAX_FORWARDED_WALKS, WALK_TIMEOUT)),
            waiters: Mutex::new(HashMap::new()),
            pool: Mutex::new(Vec::new()),
        }
    }
}

/// Steps for a network of about `n` nodes: `min(64, 2·ceil(log2 n) + 4)`.
fn walk_steps(n: usize) -> u8 {
    let log2 = usize::BITS - n.max(2).saturating_sub(1).leading_zeros();
    (2 * log2 as usize + 4).min(MAX_STEPS as usize) as u8
}

impl Node {
    /// Run Metropolis–Hastings steps here: pick a neighbour uniformly and
    /// move with probability `min(1, d_i / d_j)`, else stay; either way one
    /// step is used. Returns where the walk goes next and the steps left,
    /// or `None` if it ends here.
    async fn walk_from_here(&self, mut steps: u8) -> Option<(PeerId, u8)> {
        use rand::seq::SliceRandom;
        use rand::Rng;
        let linked: Vec<PeerId> = self.links.lock().await.keys().copied().collect();
        let rt = self.routing_table.lock().await;
        let neighbours: Vec<(PeerId, usize)> = linked
            .into_iter()
            .filter_map(|p| rt.neighbour_degree(&p).map(|d| (p, d as usize)))
            .collect();
        drop(rt);
        let d_i = neighbours.len();
        let mut rng = rand::thread_rng();
        while steps > 0 && d_i > 0 {
            steps -= 1;
            let &(j, d_j) = neighbours.choose(&mut rng).expect("non-empty");
            // A neighbour that hasn't told us its degree counts as ours.
            let d_j = if d_j == 0 { d_i } else { d_j };
            if d_i >= d_j || rng.gen_bool(d_i as f64 / d_j as f64) {
                return Some((j, steps));
            }
        }
        None
    }

    pub(super) async fn handle_sample_walk(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = SampleWalkMsg::from_bytes(payload)?;
        let Some((next, steps)) = self.walk_from_here(msg.steps.min(MAX_STEPS)).await else {
            // The walk ends here. A client-only node is no relay.
            let sample = if self.is_client_only() {
                None
            } else {
                Some(Sample {
                    peer: self.peer_id(),
                    path: Vec::new(),
                    address: self.own_address().await,
                })
            };
            let result = SampleResultMsg {
                token: msg.token,
                sample,
            };
            return self
                .send_to_peer_deferred(&from, &result.to_wire().encode())
                .await;
        };
        // A fresh token per hop, so nodes on the walk can't match theirs.
        let token: [u8; 32] = rand::random();
        let forwarded = Forwarded {
            prev: from,
            prev_token: msg.token,
            next,
        };
        if self.sampling.forwarded.lock().await.try_insert(token, forwarded).is_err() {
            return Ok(());
        }
        let walk = SampleWalkMsg { token, steps };
        self.send_to_peer_deferred(&next, &walk.to_wire().encode())
            .await
    }

    pub(super) async fn handle_sample_result(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = SampleResultMsg::from_bytes(payload)?;
        {
            let mut waiters = self.sampling.waiters.lock().await;
            if waiters.get(&msg.token).is_some_and(|w| w.first_hop == from) {
                let w = waiters.remove(&msg.token).expect("checked");
                let _ = w.tx.send(msg.sample);
                return Ok(());
            }
        }
        let fwd = {
            let mut forwarded = self.sampling.forwarded.lock().await;
            match forwarded.get(&msg.token) {
                Some(f) if f.next == from => match forwarded.remove(&msg.token) {
                    Some(f) => f,
                    None => return Ok(()),
                },
                _ => return Ok(()),
            }
        };
        let me = self.peer_id();
        let sample = msg.sample.map(|mut s| {
            // Erase loops as the result goes back, and keep only the nodes
            // nearest the sample: those say nothing about where the walk began.
            if s.peer == me {
                s.path.clear();
            } else if let Some(i) = s.path.iter().position(|p| *p == me) {
                s.path.truncate(i + 1);
            } else if s.path.len() < SAMPLE_PATH_MAX {
                s.path.push(me);
            }
            s
        });
        let result = SampleResultMsg {
            token: fwd.prev_token,
            sample,
        };
        self.send_to_peer_deferred(&fwd.prev, &result.to_wire().encode())
            .await
    }

    /// Walk for one random relay. `None` if the walk ended at us, found
    /// nothing, or timed out.
    pub(super) async fn sample_relay(&self) -> Option<SampledRelay> {
        let n_est = self.routing_table.lock().await.network_size_estimate();
        let (first_hop, steps) = self.walk_from_here(walk_steps(n_est)).await?;
        let token: [u8; 32] = rand::random();
        let (tx, rx) = oneshot::channel();
        self.sampling
            .waiters
            .lock()
            .await
            .insert(token, Waiter { first_hop, tx });
        let walk = SampleWalkMsg { token, steps };
        if self
            .send_to_peer_deferred(&first_hop, &walk.to_wire().encode())
            .await
            .is_err()
        {
            self.sampling.waiters.lock().await.remove(&token);
            return None;
        }
        let result = tokio::time::timeout(WALK_TIMEOUT, rx).await;
        self.sampling.waiters.lock().await.remove(&token);
        let Sample {
            peer,
            mut path,
            address,
        } = result.ok()?.ok()??;
        let me = self.peer_id();
        if peer == me {
            return None;
        }
        // Its address reaches it from anywhere; the walk's path only
        // from near where the walk ended.
        if let Some(rec) = address.and_then(|r| crate::directory::VerifiedAddress::verify_for(r, &peer)) {
            self.cache_address(rec).await;
        }
        // Drop our own neighbourhood from the hints: they are sent to
        // waypoints and services, which must not learn where we are.
        let linked: HashSet<PeerId> = self.links.lock().await.keys().copied().collect();
        if let Some(i) = path.iter().position(|p| *p == me || linked.contains(p)) {
            path.truncate(i);
        }
        path.reverse();
        Some(SampledRelay {
            peer,
            hints: path,
            expires: Instant::now() + crate::types::jittered(SAMPLE_LIFETIME),
        })
    }

    /// Run up to `n` walks at once and add what they find to the pool.
    async fn fill_pool(&self, n: usize) {
        let walks = (0..n).map(|_| self.sample_relay());
        let found = futures_util::future::join_all(walks).await;
        let mut pool = self.sampling.pool.lock().await;
        for s in found.into_iter().flatten() {
            if let Some(p) = pool.iter_mut().find(|p| p.peer == s.peer) {
                *p = s;
            } else if pool.len() < POOL_SIZE {
                pool.push(s);
            }
        }
    }

    /// Keep the relay pool full while the routing table is not a complete
    /// view of the network.
    pub(super) fn spawn_sampling_task(&self, node: Arc<Node>) {
        tokio::spawn(async move {
            let mut interval = jittered_interval(POOL_REFRESH);
            loop {
                interval.tick().await;
                if node.routing_table.lock().await.is_complete() {
                    continue;
                }
                let missing = {
                    let mut pool = node.sampling.pool.lock().await;
                    let now = Instant::now();
                    pool.retain(|s| s.expires > now);
                    POOL_SIZE.saturating_sub(pool.len())
                };
                if missing > 0 {
                    node.fill_pool(missing.min(POOL_WALKS_AT_ONCE)).await;
                }
            }
        });
    }

    /// Up to `n` distinct relays picked at random, never us or anything in
    /// `exclude`. While the routing table holds every destination it hears
    /// of, they come from the table; otherwise from sampled relays, since
    /// the table would only offer the local area.
    pub(super) async fn pick_relays(&self, n: usize, exclude: &[PeerId]) -> Vec<PeerId> {
        use rand::seq::SliceRandom;
        let me = self.peer_id();
        let complete = self.routing_table.lock().await.is_complete();
        if complete {
            let mut candidates: Vec<PeerId> = self
                .routing_table
                .lock()
                .await
                .all_destinations()
                .map(|(p, _)| *p)
                .chain(self.connected_peers().await)
                .filter(|p| *p != me && !exclude.contains(p))
                .collect();
            candidates.sort_unstable();
            candidates.dedup();
            candidates.shuffle(&mut rand::thread_rng());
            candidates.truncate(n);
            return candidates;
        }
        let pooled = || async {
            let now = Instant::now();
            let mut picks: Vec<PeerId> = self
                .sampling
                .pool
                .lock()
                .await
                .iter()
                .filter(|s| s.expires > now && s.peer != me && !exclude.contains(&s.peer))
                .map(|s| s.peer)
                .collect();
            picks.shuffle(&mut rand::thread_rng());
            picks.truncate(n);
            picks
        };
        // Not enough yet (just started, or many excluded): walk now. A walk
        // may end at us or at an excluded node, so allow a few rounds.
        let mut picks = pooled().await;
        for _ in 0..ON_DEMAND_ROUNDS {
            if picks.len() >= n {
                break;
            }
            self.fill_pool((n - picks.len() + 2).min(POOL_WALKS_AT_ONCE))
                .await;
            picks = pooled().await;
        }
        picks
    }

    /// Hints toward a relay we may not have a route to: from its address
    /// if we hold one we can use, else the walk that sampled it, else its
    /// address looked up in the directory.
    pub(super) async fn relay_hints(&self, peer: &PeerId) -> Vec<PeerId> {
        if *peer == self.peer_id()
            || self.links.lock().await.contains_key(peer)
            || self.routing_table.lock().await.lookup(peer).is_some()
        {
            return Vec::new();
        }
        let hints = self.cached_hints(peer).await;
        if !hints.is_empty() {
            return hints;
        }
        let walked = self
            .sampling
            .pool
            .lock()
            .await
            .iter()
            .find(|s| s.peer == *peer)
            .map(|s| s.hints.clone())
            .unwrap_or_default();
        if !walked.is_empty() {
            return walked;
        }
        self.address_hints(peer).await
    }

    /// Sample one relay now, bypassing the pool (testing).
    #[doc(hidden)]
    pub async fn sample_relay_for_test(&self) -> Option<(PeerId, Vec<PeerId>)> {
        self.sample_relay().await.map(|s| (s.peer, s.hints))
    }

    /// Shrink the routing table's budget, so it stops being a complete view
    /// (testing).
    #[doc(hidden)]
    pub async fn set_route_budget(&self, budget: usize) {
        let _ = self.routing_table.lock().await.set_budget(budget);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_steps_grow_with_log_n() {
        assert_eq!(walk_steps(1), 6);
        assert_eq!(walk_steps(2), 6);
        assert_eq!(walk_steps(3), 8);
        assert_eq!(walk_steps(1024), 24);
        assert_eq!(walk_steps(1025), 26);
        assert_eq!(walk_steps(usize::MAX), MAX_STEPS);
    }
}
