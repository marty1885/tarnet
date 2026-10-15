//! Bounded route search: the fallback when the directory has no record for
//! a node, or every address it has fails. An expanding-ring flood, with no
//! originator, answered by any node with a route to the target. See
//! "Fallback: bounded route search" in `docs/spec/routing.md`.

use super::*;
use crate::wire::{RouteSearchFoundMsg, RouteSearchMsg, MAX_HINTS, ROUTE_SEARCH_MAX_TTL, ROUTE_SEARCH_PATH_MAX};

/// Ring sizes, tried in turn.
const RINGS: [u8; 3] = [4, 8, 16];
/// How long a ring of `ttl` hops is waited for.
fn ring_wait(ttl: u8) -> Duration {
    Duration::from_millis(500 * ttl as u64)
}
/// How long relays remember a search.
const NONCE_LIFETIME: Duration = Duration::from_secs(30);
/// Searches a relay remembers at once.
const MAX_SEEN: usize = 8192;
/// At most one search per target this often.
const SEARCH_PER_TARGET: Duration = Duration::from_secs(30);
/// How long a search's answer is used.
const FOUND_LIFETIME: Duration = Duration::from_secs(300);
/// Targets with searched hints, or searched recently, remembered at once.
const MAX_TARGETS: usize = 4096;

/// A search that passed us.
struct Seen {
    prev: PeerId,
    target: PeerId,
    /// An answer already went back through us.
    answered: bool,
}

pub(super) struct SearchState {
    seen: Mutex<crate::bounded::BoundedMap<[u8; 16], Seen>>,
    waiters: crate::bounded::Requests<[u8; 16], (oneshot::Sender<Vec<PeerId>>, PeerId)>,
    /// Hints a search found, by target.
    found: Mutex<crate::bounded::BoundedMap<PeerId, Vec<PeerId>>>,
    /// Targets searched for recently: one search each per `SEARCH_PER_TARGET`.
    last_search: Mutex<crate::bounded::BoundedMap<PeerId, ()>>,
}

impl SearchState {
    pub(super) fn new() -> Self {
        Self {
            seen: Mutex::new(crate::bounded::BoundedMap::new(MAX_SEEN, NONCE_LIFETIME)),
            waiters: crate::bounded::Requests::new(MAX_TARGETS, NONCE_LIFETIME),
            found: Mutex::new(crate::bounded::BoundedMap::new(MAX_TARGETS, FOUND_LIFETIME)),
            last_search: Mutex::new(crate::bounded::BoundedMap::new(MAX_TARGETS, SEARCH_PER_TARGET)),
        }
    }
}

/// Hints from an answer's hop list (answering node first, our neighbour
/// last): reversed to run toward the target, starting from the last node we
/// can reach ourselves. `None` if that is still longer than a message may
/// carry.
fn hints_from_hops(hops: &[PeerId], reach: impl Fn(&PeerId) -> bool) -> Option<Vec<PeerId>> {
    let toward: Vec<PeerId> = hops.iter().rev().copied().collect();
    let start = toward.iter().rposition(|p| reach(p)).unwrap_or(0);
    let hints = toward[start..].to_vec();
    (hints.len() <= MAX_HINTS).then_some(hints)
}

impl Node {
    /// Remember a search. False if we have seen it already.
    async fn remember_search(
        &self,
        nonce: [u8; 16],
        prev: PeerId,
        target: PeerId,
        answered: bool,
    ) -> bool {
        self.search
            .seen
            .lock()
            .await
            .try_insert(
                nonce,
                Seen {
                    prev,
                    target,
                    answered,
                },
            )
            .is_ok()
    }

    pub(super) async fn handle_route_search(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = RouteSearchMsg::from_bytes(payload)?;
        if !self
            .remember_search(msg.nonce, from, msg.target, false)
            .await
        {
            return Ok(());
        }
        let me = self.peer_id();
        let links: Vec<PeerId> = self.links.lock().await.keys().copied().collect();
        let knows = msg.target == me
            || links.contains(&msg.target)
            || self.routing_table.lock().await.lookup(&msg.target).is_some();
        if knows {
            if let Some(s) = self.search.seen.lock().await.get_mut(&msg.nonce) {
                s.answered = true;
            }
            let found = RouteSearchFoundMsg {
                nonce: msg.nonce,
                target: msg.target,
                hops: vec![me],
            };
            return self
                .send_to_peer_deferred(&from, &found.to_wire().encode())
                .await;
        }
        let ttl = msg.ttl.min(ROUTE_SEARCH_MAX_TTL);
        if ttl <= 1 {
            return Ok(());
        }
        let next = RouteSearchMsg { ttl: ttl - 1, ..msg }.to_wire().encode();
        for peer in links.iter().filter(|p| **p != from) {
            let _ = self.send_to_peer_deferred(peer, &next).await;
        }
        Ok(())
    }

    pub(super) async fn handle_route_search_found(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut msg = RouteSearchFoundMsg::from_bytes(payload)?;
        if msg.hops.last() != Some(&from) {
            return Ok(());
        }
        let me = self.peer_id();
        if msg.hops.contains(&me) || msg.hops.len() >= ROUTE_SEARCH_PATH_MAX {
            return Ok(());
        }
        if self.search.waiters.contains(&msg.nonce) {
            if let Some((tx, _)) = self
                .search
                .waiters
                .take_if(&msg.nonce, |(_, target)| *target == msg.target)
            {
                let _ = tx.send(msg.hops);
            }
            return Ok(());
        }
        let prev = {
            let mut seen = self.search.seen.lock().await;
            match seen.get_mut(&msg.nonce) {
                // The first answer goes back; the rest add nothing. We sent
                // the search to every neighbour but `prev`, so an answer
                // can't come from it.
                Some(s) if !s.answered && s.prev != from && s.target == msg.target => {
                    s.answered = true;
                    s.prev
                }
                _ => return Ok(()),
            }
        };
        msg.hops.push(me);
        self.send_to_peer_deferred(&prev, &msg.to_wire().encode())
            .await
    }

    /// Hints toward `target` from a recent search, if any.
    pub(super) async fn searched_hints(&self, target: &PeerId) -> Vec<PeerId> {
        self.search.found.lock().await.get(target).cloned().unwrap_or_default()
    }

    /// A build using the searched hints failed: search again next time.
    pub(super) async fn forget_search(&self, target: &PeerId) {
        self.search.found.lock().await.remove(target);
    }

    /// Search for a route to `target` in rings of 4, 8 and 16 hops. Returns
    /// hints toward it, or `None` if no ring found it (or a search for it
    /// ran less than `SEARCH_PER_TARGET` ago).
    pub async fn route_search(&self, target: &PeerId) -> Option<Vec<PeerId>> {
        // A search for this target ran recently (or too many are tracked).
        if self.search.last_search.lock().await.try_insert(*target, ()).is_err() {
            return None;
        }
        let me = self.peer_id();
        for ttl in RINGS {
            let links: Vec<PeerId> = self.links.lock().await.keys().copied().collect();
            if links.is_empty() {
                return None;
            }
            let nonce: [u8; 16] = rand::random();
            // Our own flood coming back is not forwarded again.
            self.remember_search(nonce, me, *target, true).await;
            let (tx, rx) = oneshot::channel();
            let _request = self.search.waiters.register(nonce, (tx, *target))?;
            let msg = RouteSearchMsg {
                nonce,
                target: *target,
                ttl,
            }
            .to_wire()
            .encode();
            for peer in &links {
                let _ = self.send_to_peer_deferred(peer, &msg).await;
            }
            let answer = tokio::time::timeout(ring_wait(ttl), rx).await;
            let Ok(Ok(hops)) = answer else { continue };
            let linked: HashSet<PeerId> = self.links.lock().await.keys().copied().collect();
            let hints = {
                let rt = self.routing_table.lock().await;
                hints_from_hops(&hops, |p| linked.contains(p) || rt.lookup(p).is_some())
            };
            match hints {
                Some(hints) => {
                    log::info!("Route search found {:?} within {} hops", target, ttl);
                    let _ = self.search.found.lock().await.upsert(*target, hints.clone());
                    return Some(hints);
                }
                None => {
                    log::debug!("Route search found {:?}, but too far for hints", target);
                    return None;
                }
            }
        }
        log::info!("Route search found no route to {:?}", target);
        None
    }

    pub(super) fn spawn_search_gc(&self, node: Arc<Node>) {
        tokio::spawn(async move {
            let mut interval = jittered_interval(NONCE_LIFETIME);
            loop {
                interval.tick().await;
                let now = Instant::now();
                node.search.seen.lock().await.expire(now);
                node.search.found.lock().await.expire(now);
                node.search.last_search.lock().await.expire(now);
            }
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
    fn hints_start_at_the_last_node_we_reach() {
        // Answer from 5, back through 4, 3, 2 to our neighbour 1.
        let hops = vec![pid(5), pid(4), pid(3), pid(2), pid(1)];
        // We reach 1 and 2 (our local area).
        let reach = |p: &PeerId| *p == pid(1) || *p == pid(2);
        assert_eq!(hints_from_hops(&hops, reach), Some(vec![pid(2), pid(3), pid(4), pid(5)]));
        // We reach the answering node itself.
        assert_eq!(hints_from_hops(&hops, |p| *p == pid(5)), Some(vec![pid(5)]));
        // Too long to carry.
        let long: Vec<PeerId> = (1..=12).rev().map(pid).collect();
        assert_eq!(hints_from_hops(&long, |p| *p == pid(1)), None);
        assert!(hints_from_hops(&long, |p| *p == pid(4)).is_some());
    }
}

#[cfg(test)]
mod response_regressions {
    use super::*;

    #[tokio::test]
    async fn invalid_first_answers_do_not_consume_local_or_relay_requests() {
        let node = Node::new(Keypair::generate_ed25519());
        let from = PeerId([1; 32]);
        let target = PeerId([2; 32]);
        let nonce = [3; 16];
        node.remember_search(nonce, PeerId([4; 32]), target, false)
            .await;
        let mut msg = RouteSearchFoundMsg {
            nonce,
            target,
            hops: vec![node.peer_id(), from],
        };
        node.handle_route_search_found(from, &msg.to_bytes())
            .await
            .unwrap();
        assert!(!node.search.seen.lock().await.get(&nonce).unwrap().answered);
        msg.hops = vec![from];
        msg.target = PeerId([5; 32]);
        node.handle_route_search_found(from, &msg.to_bytes())
            .await
            .unwrap();
        assert!(!node.search.seen.lock().await.get(&nonce).unwrap().answered);

        let (tx, rx) = oneshot::channel();
        let _request = node.search.waiters.register(nonce, (tx, target)).unwrap();
        node.handle_route_search_found(from, &msg.to_bytes())
            .await
            .unwrap();
        assert!(node.search.waiters.contains(&nonce));
        msg.target = target;
        node.handle_route_search_found(from, &msg.to_bytes())
            .await
            .unwrap();
        assert_eq!(rx.await.unwrap(), vec![from]);
    }
}
