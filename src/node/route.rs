//! Node glue for the distance-vector routing table: link events, message
//! handlers, batched updates and digests.

use super::*;
use crate::routing::{SeqnoRequest, COST_FAST, COST_SLOW};
use crate::wire::{RouteDigestMsg, RouteRequestMsg, RouteUpdateMsg};
use super::sender::Queue;

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

struct RouteTimers {
    last_update: Instant,
    next_digest: Instant,
    batch_at: Option<Instant>,
}

/// Routing shares the deferred queue so a neighbour receives updates in
/// order. The link scheduler classifies it as control within the I/O budget.
async fn send_route(sender: &super::sender::Sender, to: &PeerId, bytes: &[u8]) -> bool {
    if let Err(e) = sender.to_peer(to, bytes, Queue::Deferred).await {
        log::debug!("Failed to send routing message to {:?}: {}", to, e);
        false
    } else {
        true
    }
}

impl Node {
    /// A neighbour came up: it is owed a full dump, which the routing task
    /// sends with its other updates.
    pub(super) async fn routing_link_up(&self, peer: &PeerId) {
        let Some(link) = self.links.lock().await.get(peer).cloned() else {
            return;
        };
        let requests = self
            .routing_table
            .lock()
            .await
            .neighbour_up(*peer, link_cost(&link));
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
        send_route(&self.sender, &from, &req.to_wire().encode()).await;
        Ok(())
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
                self.routing_table.lock().await.request_full_dump(&from);
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
            send_route(&self.sender, &r.to, &msg.to_wire().encode()).await;
        }
    }

    /// Send batched route changes and periodic digests to every neighbour.
    pub(super) fn spawn_routing_task(&self) {
        let links = self.links.clone();
        let sender = self.sender.clone();
        let routing = self.routing_table.clone();
        #[cfg(test)]
        let passes = self.scheduler_passes.clone();
        tokio::spawn(async move {
            let changed = routing.lock().await.changed_notify();
            let links_changed = links.lock().await.routing_notify();
            let mut timers: HashMap<PeerId, RouteTimers> = HashMap::new();
            loop {
                #[cfg(test)]
                passes.routing.fetch_add(1, Ordering::Relaxed);
                let now = Instant::now();
                let mut wake_at: Option<Instant> = None;
                let peers: Vec<(PeerId, Arc<PeerLink>)> = links
                    .lock()
                    .await
                    .iter()
                    .map(|(p, l)| (*p, l.clone()))
                    .collect();
                timers.retain(|p, _| peers.iter().any(|(q, _)| q == p));

                let mut to_send: Vec<(PeerId, Vec<u8>)> = Vec::new();
                {
                    let mut rt = routing.lock().await;
                    let mut requests = rt.advance_time(now);
                    // The active link to a peer can change under us (failover,
                    // score-driven promotion): keep each neighbour's cost in
                    // step with the link actually carrying its traffic.
                    for (peer, link) in &peers {
                        requests.extend(rt.neighbour_cost(peer, link_cost(link)));
                    }
                    requests.extend(rt.retry_starving());
                    for r in requests {
                        if peers.iter().any(|(p, _)| *p == r.to) {
                            let msg = RouteRequestMsg {
                                full_dump: false,
                                seqno: Some((r.dest, r.seqno, r.hops)),
                            };
                            to_send.push((r.to, msg.to_wire().encode()));
                        }
                    }
                    for (peer, link) in &peers {
                        let slow = link.is_slow();
                        let digest_interval = if slow {
                            DIGEST_INTERVAL_SLOW
                        } else {
                            DIGEST_INTERVAL_FAST
                        };
                        let timer = timers.entry(*peer).or_insert_with(|| {
                            use rand::Rng;
                            let jitter =
                                rand::thread_rng().gen_range(0..digest_interval.as_millis() as u64);
                            RouteTimers {
                                last_update: now.checked_sub(SLOW_UPDATE_GAP).unwrap_or(now),
                                next_digest: now + Duration::from_millis(jitter),
                                batch_at: None,
                            }
                        });
                        if rt.has_pending(peer) {
                            let batch_at = *timer.batch_at.get_or_insert(now + UPDATE_BATCH);
                            let due = if slow { batch_at.max(timer.last_update + SLOW_UPDATE_GAP) } else { batch_at };
                            if now >= due {
                                timer.last_update = now;
                                timer.batch_at = None;
                                for m in rt.take_pending(peer) {
                                    to_send.push((*peer, m.to_wire().encode()));
                                }
                            } else {
                                wake_at = Some(wake_at.map_or(due, |old| old.min(due)));
                            }
                        } else {
                            timer.batch_at = None;
                        }
                        if now >= timer.next_digest {
                            if let Some(d) = rt.digest_for(peer) {
                                timer.next_digest = now + digest_interval;
                                to_send.push((*peer, d.to_wire().encode()));
                            }
                        }
                        // A digest waits for its pending batch instead of
                        // repeatedly waking on a past-due digest deadline.
                        if timer.next_digest > now {
                            wake_at = Some(wake_at.map_or(timer.next_digest, |old| old.min(timer.next_digest)));
                        }
                    }
                    if let Some(at) = rt.next_deadline() {
                        wake_at = Some(wake_at.map_or(at, |old| old.min(at)));
                    }
                }
                for (peer, msg) in to_send {
                    if !send_route(&sender, &peer, &msg).await {
                        // take_pending transfers the outbox to this task. Failed
                        // admission must put an authoritative replacement back.
                        routing.lock().await.request_full_dump(&peer);
                    }
                }
                tokio::select! {
                    _ = changed.notified() => {}
                    _ = links_changed.notified() => {}
                    _ = async {
                        match wake_at {
                            Some(at) => tokio::time::sleep_until(at.into()).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {}
                }
            }
        });
    }
}

#[cfg(test)]
mod stress_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tickless_routing_quiesces_after_notification_storm() {
        let node = Arc::new(Node::new(Keypair::generate()));
        node.spawn_routing_task();
        let mut writers = Vec::new();
        for writer in 0..32 {
            let node = node.clone();
            writers.push(tokio::spawn(async move {
                for change in 0..512 {
                    node.routing_table.lock().await.set_budget(64 + (writer + change) % 8);
                    if change % 16 == 0 { tokio::task::yield_now().await; }
                }
            }));
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            for writer in writers { writer.await.unwrap(); }
        }).await.expect("routing notification storm stalled");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before_final = node.scheduler_passes.routing.load(Ordering::Relaxed);
        node.routing_table.lock().await.set_budget(7777);
        tokio::time::timeout(Duration::from_secs(2), async {
            while node.scheduler_passes.routing.load(Ordering::Relaxed) == before_final {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.expect("routing lost a notification after the storm drained");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let passes = node.scheduler_passes.routing.load(Ordering::Relaxed);
        assert!(passes > 0);
        tokio::time::sleep(Duration::from_millis(650)).await;
        assert_eq!(node.scheduler_passes.routing.load(Ordering::Relaxed), passes,
            "routing polled after its notifications and deadlines drained");
        eprintln!("tickless routing: 16384 concurrent mutations + final idle wake, {passes} passes, 0 idle passes in 650 ms");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tickless_heartbeat_rearms_earlier_deadlines_under_churn() {
        use crate::transport::tcp::{TcpDiscovery, TcpTransport};
        let node = Arc::new(Node::new(Keypair::generate()));
        let discovery = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
        let address = discovery.local_addrs()[0].to_string();
        let running = node.clone();
        let task = tokio::spawn(async move { running.run(Box::new(discovery), vec![], vec![]).await.unwrap(); });
        let remote_id = Keypair::generate();
        let socket = tokio::net::TcpStream::connect(&address).await.unwrap();
        let remote = PeerLink::initiator(Box::new(TcpTransport::new(socket)), &remote_id, None).await.unwrap();
        let peer = remote_id.peer_id();
        let id = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(id) = node.links.lock().await.link_ids(&peer).first() { break *id; }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.unwrap();
        // A real frame confirms the responder link without waiting for its
        // normal heartbeat, which would otherwise be tens of seconds away.
        remote.send_message(&KeepaliveMsg { ping_id: None, probe_nonce: None, padding: vec![] }.to_wire().encode()).await.unwrap();
        for _ in 0..64 {
            node.links.lock().await.reschedule_heartbeat_for_test(&peer, id, Instant::now() + Duration::from_millis(2));
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let bytes = remote.recv_message().await.unwrap();
                    let message = WireMessage::decode(&bytes).unwrap();
                    if message.msg_type == MessageType::Keepalive {
                        let keepalive = KeepaliveMsg::from_bytes(&message.payload).unwrap();
                        if keepalive.ping_id.is_some() { break; }
                    }
                }
            }).await.expect("earlier heartbeat deadline was lost");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let passes = node.scheduler_passes.heartbeat.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1250)).await;
        assert_eq!(node.scheduler_passes.heartbeat.load(Ordering::Relaxed), passes,
            "completed heartbeats left a polling loop");
        eprintln!("tickless heartbeat: 64 earlier-deadline rearms, {passes} passes, 0 idle passes in 1250 ms");
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tickless_heartbeat_has_no_empty_table_polling() {
        use crate::transport::tcp::TcpDiscovery;
        let node = Arc::new(Node::new(Keypair::generate()));
        node.set_client_only(true);
        let discovery = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
        let running = node.clone();
        let task = tokio::spawn(async move { running.run(Box::new(discovery), vec![], vec![]).await.unwrap(); });
        tokio::time::timeout(Duration::from_secs(3), async {
            while node.scheduler_passes.heartbeat.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.unwrap();
        let passes = node.scheduler_passes.heartbeat.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1250)).await;
        assert_eq!(node.scheduler_passes.heartbeat.load(Ordering::Relaxed), passes,
            "heartbeat scheduler polled an empty link table");
        eprintln!("tickless heartbeat: 0 idle passes in 1250 ms");
        task.abort();
    }
}
