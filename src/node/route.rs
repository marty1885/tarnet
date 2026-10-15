//! Node glue for the distance-vector routing table: link events, message
//! handlers, batched updates and digests.

use super::*;
use crate::routing::{SeqnoRequest, COST_FAST, COST_SLOW};
use crate::wire::{RouteDigestMsg, RouteRequestMsg, RouteUpdateMsg};
use super::sender::{Budget, Queue};

/// Changes are batched for this long before they are sent.
const UPDATE_BATCH: Duration = Duration::from_millis(250);
/// Minimum gap between updates on a slow link.
const SLOW_UPDATE_GAP: Duration = Duration::from_secs(2);
/// Digest interval on fast and slow links.
const DIGEST_INTERVAL_FAST: Duration = Duration::from_secs(30);
const DIGEST_INTERVAL_SLOW: Duration = Duration::from_secs(120);
/// A neighbour gets at most one requested full dump per this interval.
const FULL_DUMP_MIN_GAP: Duration = Duration::from_secs(10);

fn link_cost(link: &PeerLink) -> u16 {
    if link.is_slow() {
        COST_SLOW
    } else {
        COST_FAST
    }
}

impl Node {
    pub(super) async fn routing_link_up(&self, peer: &PeerId) {
        let Some(link) = self.links.lock().await.get(peer).cloned() else {
            return;
        };
        let (dump, requests) = self
            .routing_table
            .lock()
            .await
            .neighbour_up(*peer, link_cost(&link));
        for m in dump {
            let bytes = m.to_wire().encode();
            if let Err(e) = self.sender.to_peer(peer, &bytes, Queue::Deferred, Budget::Upkeep).await {
                log::warn!("Failed to send route dump to {:?}: {}", peer, e);
            }
        }
        self.send_seqno_requests(requests).await;
    }

    /// One of several links to `peer` went away: its cost is now that of
    /// whichever link is active.
    pub(super) async fn routing_link_changed(&self, peer: &PeerId) {
        let Some(link) = self.links.lock().await.get(peer).cloned() else {
            return;
        };
        let requests = self
            .routing_table
            .lock()
            .await
            .neighbour_cost(peer, link_cost(&link));
        self.send_seqno_requests(requests).await;
    }

    pub(super) async fn routing_link_down(&self, peer: &PeerId) {
        let requests = self.routing_table.lock().await.neighbour_down(peer);
        self.route_dumps_sent.lock().await.remove(peer);
        self.send_seqno_requests(requests).await;
    }

    pub(super) async fn handle_route_update(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = RouteUpdateMsg::from_bytes(payload)?;
        let requests = self.routing_table.lock().await.apply_update(&from, &msg);
        self.send_seqno_requests(requests).await;
        Ok(())
    }

    pub(super) async fn handle_route_digest(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let digest = RouteDigestMsg::from_bytes(payload)?;
        if self
            .routing_table
            .lock()
            .await
            .digest_matches(&from, &digest)
        {
            return Ok(());
        }
        log::debug!(
            "Route digest mismatch from {:?}, requesting full dump",
            from
        );
        let req = RouteRequestMsg {
            full_dump: true,
            seqno: None,
        };
        self.send_to_peer_deferred(&from, &req.to_wire().encode())
            .await
    }

    pub(super) async fn handle_route_request(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let req = RouteRequestMsg::from_bytes(payload)?;
        if req.full_dump {
            let due = {
                let mut sent = self.route_dumps_sent.lock().await;
                let now = Instant::now();
                let due = sent
                    .get(&from)
                    .map_or(true, |t| now.duration_since(*t) >= FULL_DUMP_MIN_GAP);
                if due {
                    sent.insert(from, now);
                }
                due
            };
            if due {
                let dump = self.routing_table.lock().await.full_dump(&from);
                for m in dump {
                    self.send_to_peer_deferred(&from, &m.to_wire().encode())
                        .await?;
                }
            }
        }
        if let Some((dest, seqno, hops)) = req.seqno {
            let forward = self
                .routing_table
                .lock()
                .await
                .seqno_request(&from, dest, seqno, hops);
            self.send_seqno_requests(forward.into_iter().collect())
                .await;
        }
        Ok(())
    }

    pub(super) async fn send_seqno_requests(&self, requests: Vec<SeqnoRequest>) {
        for r in requests {
            let msg = RouteRequestMsg {
                full_dump: false,
                seqno: Some((r.dest, r.seqno, r.hops)),
            };
            if let Err(e) = self.send_to_peer(&r.to, &msg.to_wire().encode()).await {
                log::debug!("Failed to send seqno request to {:?}: {}", r.to, e);
            }
        }
    }

    /// Send batched route changes and periodic digests to every neighbour.
    pub(super) fn spawn_routing_task(&self) {
        let links = self.links.clone();
        let sender = self.sender.clone();
        let routing = self.routing_table.clone();
        tokio::spawn(async move {
            // Per neighbour: last update sent, next digest due.
            let mut timers: HashMap<PeerId, (Instant, Instant)> = HashMap::new();
            let mut next_gc = Instant::now() + Duration::from_secs(30);
            let mut interval = jittered_interval(UPDATE_BATCH);
            loop {
                interval.tick().await;
                let now = Instant::now();
                let peers: Vec<(PeerId, Arc<PeerLink>)> = links
                    .lock()
                    .await
                    .iter()
                    .map(|(p, l)| (*p, l.clone()))
                    .collect();
                timers.retain(|p, _| peers.iter().any(|(q, _)| q == p));

                let mut to_send: Vec<(PeerId, Arc<PeerLink>, Vec<u8>)> = Vec::new();
                {
                    let mut rt = routing.lock().await;
                    let mut requests = Vec::new();
                    if now >= next_gc {
                        requests.extend(rt.gc());
                        next_gc = now + Duration::from_secs(30);
                    }
                    // The active link to a peer can change under us (failover,
                    // score-driven promotion): keep each neighbour's cost in
                    // step with the link actually carrying its traffic.
                    for (peer, link) in &peers {
                        requests.extend(rt.neighbour_cost(peer, link_cost(link)));
                    }
                    requests.extend(rt.retry_starving());
                    for r in requests {
                        if let Some((_, link)) = peers.iter().find(|(p, _)| *p == r.to) {
                            let msg = RouteRequestMsg {
                                full_dump: false,
                                seqno: Some((r.dest, r.seqno, r.hops)),
                            };
                            to_send.push((r.to, link.clone(), msg.to_wire().encode()));
                        }
                    }
                    for (peer, link) in &peers {
                        let slow = link.is_slow();
                        let digest_interval = if slow {
                            DIGEST_INTERVAL_SLOW
                        } else {
                            DIGEST_INTERVAL_FAST
                        };
                        let (last_update, next_digest) = timers.entry(*peer).or_insert_with(|| {
                            use rand::Rng;
                            let jitter =
                                rand::thread_rng().gen_range(0..digest_interval.as_millis() as u64);
                            (
                                now.checked_sub(SLOW_UPDATE_GAP).unwrap_or(now),
                                now + Duration::from_millis(jitter),
                            )
                        });
                        if rt.has_pending(peer)
                            && (!slow || now.duration_since(*last_update) >= SLOW_UPDATE_GAP)
                        {
                            *last_update = now;
                            for m in rt.take_pending(peer) {
                                to_send.push((*peer, link.clone(), m.to_wire().encode()));
                            }
                        }
                        if now >= *next_digest {
                            if let Some(d) = rt.digest_for(peer) {
                                *next_digest = now + digest_interval;
                                to_send.push((*peer, link.clone(), d.to_wire().encode()));
                            }
                        }
                    }
                }
                for (peer, _link, msg) in to_send {
                    if let Err(e) = sender.to_peer(&peer, &msg, Queue::Deferred, Budget::Upkeep).await {
                        log::warn!("Failed to send routing message to {:?}: {}", peer, e);
                    }
                }
            }
        });
    }
}
