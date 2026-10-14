use super::*;

/// How long the initiator waits for CircuitCreated, resending CREATE every
/// `CREATE_RESEND_INTERVAL` meanwhile.
const CREATE_TIMEOUT: Duration = Duration::from_secs(8);
const CREATE_RESEND_INTERVAL: Duration = Duration::from_secs(1);
/// Floor for one EXTEND step's wait; see [`Node::extend_step_timeout`].
const EXTEND_STEP_FLOOR: Duration = Duration::from_millis(1500);
/// Per built hop allowance in an EXTEND step's wait, on top of airtime.
const EXTEND_PER_HOP: Duration = Duration::from_millis(500);
/// Tries at one EXTEND step before the circuit fails. Between tries the
/// circuit is truncated back to the hops already built.
const EXTEND_ATTEMPTS: usize = 3;
/// Tries at getting TRUNCATED back from the last built hop.
const TRUNCATE_ATTEMPTS: usize = 3;
/// How long a hop keeps its CircuitCreated reply for answering resent CREATEs.
const CREATED_REPLY_TTL: Duration = Duration::from_secs(30);
/// How long a CREATE's ephemeral key is remembered to catch loops.
const CREATE_KEY_TTL: Duration = Duration::from_secs(30);
/// Ephemeral keys remembered at once.
const MAX_CREATE_KEYS: usize = 16 * 1024;
/// CREATEs accepted per second per incoming link, and the burst allowed.
const CREATE_RATE: f64 = 50.0;
const CREATE_BURST: f64 = 200.0;
/// A routed CREATE not answered in this time is torn down.
pub(super) const ROUTED_CREATE_TIMEOUT: Duration = Duration::from_secs(30);
/// A relay or endpoint entry that carries no cell for this long is torn
/// down. Live circuits send keepalive padding far more often.
pub(super) const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// How long a connection keeps trying a destination it knows how to reach
/// (a route or an address) but can't build a circuit to yet. After a link
/// dies, routes reconverge and addresses are republished well inside this,
/// which is well inside a TCP connect timeout (~127 s).
const CONNECT_PERSIST: Duration = Duration::from_secs(60);
/// Pause between rounds of build attempts, doubling up to the max.
const CONNECT_ROUND_GAP: Duration = Duration::from_secs(1);
const CONNECT_ROUND_GAP_MAX: Duration = Duration::from_secs(8);

/// Failed or cancelled handshakes must not leave circuits and waiters behind.
pub(super) struct CircuitAttemptGuard {
    circuit_id: u32,
    circuits: CircuitState,
    endpoints: EndpointState,
    first_hop: Option<PeerId>,
    links: Arc<Mutex<crate::peer_transport::LinkTable>>,
    pub(super) armed: bool,
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use crate::circuit::{CongestionWindow, SENDME_STALL_TIMEOUT};

    fn circuit(peer: PeerId) -> OutboundCircuit {
        OutboundCircuit::new(
            peer,
            7,
            OnionLayers::new(vec![HopKey::derive(&[42; 32], &[0; 32])]),
            vec![peer],
            CircuitPhase::Ready,
        )
    }

    #[test]
    fn backward_cells_open_by_origin_and_replays_are_rejected() {
        let mut outbound = circuit(PeerId([1; 32]));
        let first = outbound.layers.hops[0].clone();
        let last = HopKey::derive(&[43; 32], &[0; 32]);
        outbound.layers.push(last.clone());
        let decode = |encoded: Vec<u8>| -> [u8; CELL_SIZE] {
            CircuitRelayMsg::from_bytes(&WireMessage::decode(&encoded).unwrap().payload)
                .unwrap()
                .data
                .try_into()
                .unwrap()
        };
        let seal = |keys: &LayerKeys, counter, text: &[u8]| {
            decode(seal_backward_cell(
                keys,
                counter,
                7,
                &write_cell_body(RelayCellCommand::Extended, 0, text),
            ))
        };
        let first_reply = seal(&first.backward, 0, b"first hop");
        let mut corrupted = first_reply;
        corrupted[3] ^= 1;
        assert!(outbound.recv_from_hop(&corrupted, 0).is_err());
        assert_eq!(outbound.recv_from_hop(&first_reply, 0).unwrap().data, b"first hop");

        // The last hop's cell gains the first hop's layer on the way.
        let mut last_reply = seal(&last.backward, 0, b"last hop");
        let mut relay = HopCrypto::new(first.backward.clone(), CryptoOp::Encrypt);
        assert!(relay.wrap(&mut last_reply));
        assert!(outbound.recv_from_hop(&last_reply, 0).is_err());
        let mut outbound2 = circuit(PeerId([1; 32]));
        outbound2.layers.push(last.clone());
        assert_eq!(outbound2.recv_relay_cell(&last_reply).unwrap().data, b"last hop");
        assert!(outbound2.recv_relay_cell(&last_reply).is_err());
        // Each origin keeps its own replay window.
        assert!(outbound.recv_from_hop(&first_reply, 0).is_err());
    }

    #[tokio::test]
    async fn inbound_id_collision_does_not_touch_another_peers_stream_or_waiter() {
        let node = Node::new(Keypair::generate());
        let local_peer = PeerId([1; 32]);
        let remote_peer = PeerId([2; 32]);
        node.circuits
            .outbound
            .lock()
            .await
            .insert(7, node.manage_circuit(7, circuit(local_peer)));
        let local_key = CircuitKey {
            circuit_id: 7,
            from_peer: local_peer,
        };
        let remote_key = CircuitKey {
            circuit_id: 7,
            from_peer: remote_peer,
        };
        node.circuits.table.lock().await.insert(
            remote_key,
            CircuitAction::Endpoint {
                assembler: Default::default(),
                crypto: None,
                origin_hop: remote_peer,
            },
        );
        let (local_tx, mut local_rx) = mpsc::channel(1);
        let (remote_tx, mut remote_rx) = mpsc::channel(1);
        node.endpoints
            .data_txs
            .lock()
            .await
            .extend([(local_key, local_tx), (remote_key, remote_tx)]);
        let (pending_tx, mut pending_rx) = oneshot::channel();
        node.circuits
            .pending_extends
            .lock()
            .await
            .insert(7, pending_tx);
        node.handle_circuit_destroy(
            remote_peer,
            &CircuitDestroyMsg { circuit_id: 7 }.to_wire().payload,
        )
        .await
        .unwrap();
        assert!(remote_rx.recv().await.is_none());
        assert!(!local_rx.is_closed());
        assert!(pending_rx.try_recv().is_err());
        assert!(node.circuits.pending_extends.lock().await.contains_key(&7));
        assert!(node.circuits.outbound.lock().await.contains_key(&7));
        node.cleanup_peer_circuits(remote_peer).await;
        assert!(!local_rx.is_closed());
        assert!(node.circuits.pending_extends.lock().await.contains_key(&7));
        node.handle_circuit_destroy(
            local_peer,
            &CircuitDestroyMsg { circuit_id: 7 }.to_wire().payload,
        )
        .await
        .unwrap();
        assert!(local_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn foreign_destroy_does_not_close_outbound_stream() {
        let node = Node::new(Keypair::generate());
        let peer = Keypair::generate().peer_id();
        let stranger = Keypair::generate().peer_id();
        node.circuits
            .outbound
            .lock()
            .await
            .insert(7, node.manage_circuit(7, circuit(peer)));
        let (tx, mut rx) = mpsc::channel(1);
        node.endpoints.data_txs.lock().await.insert(
            CircuitKey {
                circuit_id: 7,
                from_peer: peer,
            },
            tx,
        );
        let payload = CircuitDestroyMsg { circuit_id: 7 }.to_wire().payload;
        node.handle_circuit_destroy(stranger, &payload)
            .await
            .unwrap();
        assert!(node.circuits.outbound.lock().await.contains_key(&7));
        assert!(!rx.is_closed());
        node.handle_circuit_destroy(peer, &payload).await.unwrap();
        assert!(!node.circuits.outbound.lock().await.contains_key(&7));
        assert_eq!(rx.recv().await, None);
    }

    #[tokio::test]
    async fn destroy_removes_both_relay_directions() {
        let node = Node::new(Keypair::generate());
        let upstream = Keypair::generate().peer_id();
        let downstream = Keypair::generate().peer_id();
        let mut table = node.circuits.table.lock().await;
        table.insert(
            CircuitKey {
                circuit_id: 7,
                from_peer: upstream,
            },
            CircuitAction::Forward {
                next_hop: downstream,
                next_circuit_id: 8,
                crypto: None,
            },
        );
        table.insert(
            CircuitKey {
                circuit_id: 8,
                from_peer: downstream,
            },
            CircuitAction::Forward {
                next_hop: upstream,
                next_circuit_id: 7,
                crypto: None,
            },
        );
        drop(table);
        node.handle_circuit_destroy(
            upstream,
            &CircuitDestroyMsg { circuit_id: 7 }.to_wire().payload,
        )
        .await
        .unwrap();
        assert!(node.circuits.table.lock().await.is_empty());
    }

    #[tokio::test]
    async fn idle_relay_entries_expire_but_busy_ones_stay() {
        let node = Node::new(Keypair::generate());
        let up = Keypair::generate().peer_id();
        let down = Keypair::generate().peer_id();
        let pair = |a: u32, b: u32| {
            [
                (
                    CircuitKey { circuit_id: a, from_peer: up },
                    CircuitAction::Forward { next_hop: down, next_circuit_id: b, crypto: None },
                ),
                (
                    CircuitKey { circuit_id: b, from_peer: down },
                    CircuitAction::Forward { next_hop: up, next_circuit_id: a, crypto: None },
                ),
            ]
        };
        {
            let mut table = node.circuits.table.lock().await;
            for (k, v) in pair(1, 2).into_iter().chain(pair(3, 4)) {
                table.insert(k, v);
            }
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        // Circuit 3/4 carries a backward cell: both directions stay.
        node.circuits
            .table
            .lock()
            .await
            .lookup_mut(&CircuitKey { circuit_id: 4, from_peer: down });
        node.expire_idle_relay_entries(Duration::from_millis(50)).await;
        let table = node.circuits.table.lock().await;
        assert_eq!(table.len(), 2);
        assert!(table.lookup(&CircuitKey { circuit_id: 3, from_peer: up }).is_some());
    }

    #[tokio::test]
    async fn create_failure_cleans_up_pending_handshake() {
        let node = Node::new(Keypair::generate());
        let peer = Keypair::generate().peer_id();
        assert!(node.build_circuit(peer, vec![peer]).await.is_err());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if node.circuits.pending_extends.lock().await.is_empty()
                    && node.circuits.pending_create_peers.lock().await.is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed CREATE leaked its pending entries");
    }

    #[tokio::test]
    async fn foreign_created_does_not_consume_pending_handshake() {
        let node = Node::new(Keypair::generate());
        let peer = Keypair::generate().peer_id();
        let stranger = Keypair::generate().peer_id();
        let (tx, mut rx) = oneshot::channel();
        node.circuits.pending_extends.lock().await.insert(7, tx);
        node.circuits
            .pending_create_peers
            .lock()
            .await
            .insert(7, peer);
        let payload = CircuitCreatedMsg {
            circuit_id: 7,
            encrypted_reply: vec![1, 2, 3],
        }
        .to_wire()
        .payload;
        node.handle_circuit_created(stranger, &payload)
            .await
            .unwrap();
        assert!(rx.try_recv().is_err());
        assert!(node.circuits.pending_extends.lock().await.contains_key(&7));
        node.handle_circuit_created(peer, &payload).await.unwrap();
        assert_eq!(rx.await.unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn sender_exits_when_queued_data_loses_its_circuit() {
        let node = Node::new(Keypair::generate());
        let peer = Keypair::generate().peer_id();
        node.circuits
            .outbound
            .lock()
            .await
            .insert(7, node.manage_circuit(7, circuit(peer)));
        let conn = node
            .circuit_connection(
                node.default_service_id().await,
                tarnet_api::service::PortMode::ReliableOrdered,
                "80",
                7,
            )
            .await;
        node.circuits.outbound.lock().await.remove(&7);
        conn.send(b"queued data").await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), conn.recv())
            .await
            .expect("sender waited forever on a missing circuit")
            .is_err());
        assert!(node.endpoints.streams.lock().await.is_empty());
    }

    #[test]
    fn first_lost_sendme_starts_a_stall_timer() {
        let mut cw = CongestionWindow::new();
        for _ in 0..cw.cwnd {
            cw.on_send();
        }
        assert!(!cw.check_stall());
        assert!(cw.last_sendme_at.is_some());
        cw.last_sendme_at = Some(Instant::now() - SENDME_STALL_TIMEOUT);
        assert!(cw.check_stall());
        assert!(cw.can_send());
    }

    #[tokio::test]
    async fn lost_peer_closes_outbound_stream_immediately() {
        let node = Node::new(Keypair::generate());
        let peer = Keypair::generate().peer_id();
        node.circuits
            .outbound
            .lock()
            .await
            .insert(7, node.manage_circuit(7, circuit(peer)));
        let (tx, mut rx) = mpsc::channel(1);
        node.endpoints.data_txs.lock().await.insert(
            CircuitKey {
                circuit_id: 7,
                from_peer: peer,
            },
            tx,
        );
        node.cleanup_peer_circuits(peer).await;
        assert!(node.circuits.outbound.lock().await.is_empty());
        assert_eq!(rx.recv().await, None);
    }

    #[tokio::test]
    async fn stream_setup_failure_cleans_up_receive_channel() {
        let node = Node::new(Keypair::generate());
        let peer = Keypair::generate().peer_id();
        node.circuits
            .outbound
            .lock()
            .await
            .insert(7, node.manage_circuit(7, circuit(peer)));
        assert!(node
            .setup_circuit_connection(
                node.default_service_id().await,
                tarnet_api::service::PortMode::ReliableOrdered,
                "80",
                7
            )
            .await
            .is_err());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if node.endpoints.data_txs.lock().await.is_empty()
                    && node.endpoints.pending_connects.lock().await.is_empty()
                    && node.circuits.outbound.lock().await.is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed stream setup leaked state");
    }

    #[tokio::test]
    async fn rendezvous_without_introduction_points_returns_error() {
        let node = Node::new(Keypair::generate());
        assert!(node
            .connect_via_rendezvous(
                node.default_service_id().await,
                tarnet_api::service::PortMode::ReliableOrdered,
                "80",
                &[],
                1,
            )
            .await
            .is_err());
    }
}

impl Drop for CircuitAttemptGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let id = self.circuit_id;
        let circuits = self.circuits.clone();
        let endpoints = self.endpoints.clone();
        let first_hop = self.first_hop;
        let links = self.links.clone();
        tokio::spawn(async move {
            circuits.pending_extends.lock().await.remove(&id);
            circuits.pending_create_peers.lock().await.remove(&id);
            endpoints.pending_connects.lock().await.remove(&id);
            let peer = first_hop.or(circuits.outbound.lock().await.get(&id).map(|c| c.first_hop));
            if let Some(peer) = peer {
                endpoints
                    .close_stream(CircuitKey {
                        circuit_id: id,
                        from_peer: peer,
                    })
                    .await;
            }
            let removed = circuits.outbound.lock().await.remove(&id);
            if removed.is_none() {
                if let Some(peer) = first_hop {
                    let link = links.lock().await.get(&peer).cloned();
                    if let Some(link) = link {
                        let _ = link
                            .send_message_critical(
                                &CircuitDestroyMsg { circuit_id: id }.to_wire().encode(),
                            )
                            .await;
                    }
                }
            }
        });
    }
}

/// Seal a relay cell at this hop for the circuit initiator. Returns the
/// encoded wire message.
pub(super) fn seal_backward_cell(
    keys: &LayerKeys,
    counter: u64,
    circuit_id: u32,
    body: &[u8; CELL_BODY_SIZE],
) -> Vec<u8> {
    encode_circuit_relay_cell(circuit_id, &seal_outward(keys, counter, body))
}

impl Node {
    pub(super) fn circuit_attempt_guard(&self, circuit_id: u32) -> CircuitAttemptGuard {
        CircuitAttemptGuard {
            circuit_id,
            circuits: self.circuits.clone(),
            endpoints: self.endpoints.clone(),
            first_hop: None,
            links: self.links.clone(),
            armed: true,
        }
    }
    // ── Circuit message handlers ──

    /// Handle an incoming CircuitRelay cell: look up forwarding table, rewrite circuit_id, forward.
    /// `payload` is the raw wire payload: circuit_id(4 BE) || cell_data.
    /// We parse circuit_id and borrow cell_data directly to avoid allocating a Vec.
    pub(super) async fn handle_circuit_relay(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        if payload.len() < 4 {
            return Err(Error::Wire("CircuitRelay too short".into()));
        }
        let circuit_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        // Every cell is CELL_SIZE on every hop; anything else is dropped, so a
        // relay can't mark a circuit by changing cell sizes.
        let Ok(mut cell) = <[u8; CELL_SIZE]>::try_from(&payload[4..]) else {
            log::debug!("CircuitRelay of wrong size from {:?}, dropping", from);
            return Ok(());
        };

        let key = CircuitKey {
            circuit_id,
            from_peer: from,
        };

        let mut table = self.circuits.table.lock().await;
        match table.lookup_mut(&key) {
            Some(CircuitAction::Forward {
                next_hop,
                next_circuit_id,
                crypto,
            }) => {
                let next_hop = *next_hop;
                let next_id = *next_circuit_id;
                match crypto {
                    Some(hop) if hop.op == CryptoOp::Decrypt => match hop.peel(&mut cell) {
                        Peeled::Replayed => return Ok(()),
                        Peeled::Through => {
                            if let Some(wrap) = hop.splice.as_mut() {
                                if !wrap.wrap(&mut cell) {
                                    return Ok(());
                                }
                            }
                        }
                        // A forwarding hop still recognises TRUNCATE addressed
                        // to it: the initiator uses it to undo an EXTEND whose
                        // reply never came.
                        Peeled::Mine(body) => {
                            drop(table);
                            if RelayPiece::from_cell(&body)
                                .is_ok_and(|p| p.command == RelayCellCommand::Truncate)
                            {
                                return self.handle_truncate(from, circuit_id).await;
                            }
                            return Ok(());
                        }
                    },
                    Some(hop) => {
                        if !hop.wrap(&mut cell) {
                            return Ok(());
                        }
                    }
                    None => {}
                }
                drop(table);
                let encoded = encode_circuit_relay_cell(next_id, &cell);
                self.stats.record_relay(encoded.len() as u64);
                self.send_to_peer(&next_hop, &encoded).await
            }
            Some(CircuitAction::Endpoint {
                crypto: Some(hop), ..
            }) => {
                let Peeled::Mine(body) = hop.peel(&mut cell) else {
                    return Ok(());
                };
                drop(table);
                self.handle_endpoint_relay_cell(from, circuit_id, &body)
                    .await
            }
            Some(CircuitAction::Endpoint { crypto: None, .. }) => Ok(()),
            None => {
                drop(table);

                // Check if this is a backward cell for an outbound circuit we initiated.
                let mut circuits = self.circuits.outbound.lock().await;
                if let Some(circuit) = circuits.get_mut(&circuit_id) {
                    if from == circuit.first_hop {
                        let decoded = circuit.recv_relay_message(&cell);
                        if decoded.is_ok() {
                            circuit.last_activity = Instant::now();
                        }
                        drop(circuits);
                        let decoded = match decoded {
                            // Piece of a multi-cell message; more to come.
                            Ok(None) => return Ok(()),
                            Ok(Some(relay_cell)) => Ok(relay_cell),
                            Err(e) => Err(e),
                        };
                        if let Ok(relay_cell) = decoded {
                            if relay_cell.command == RelayCellCommand::Truncated {
                                let mut pending = self.circuits.pending_truncates.lock().await;
                                if let Some(tx) = pending.remove(&circuit_id) {
                                    let _ = tx.send(());
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::Extended {
                                // This is an EXTENDED reply during circuit construction.
                                let mut pending = self.circuits.pending_extends.lock().await;
                                if let Some(tx) = pending.remove(&circuit_id) {
                                    let _ = tx.send(relay_cell.data);
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::Data {
                                return self.handle_stream_data(key, &relay_cell.data).await;
                            }
                            if relay_cell.command == RelayCellCommand::StreamAck {
                                return self.handle_stream_ack(key, &relay_cell.data).await;
                            }
                            if relay_cell.command == RelayCellCommand::RendezvousReady {
                                let ready = self.endpoints.streams.lock().await.contains_key(&key);
                                if ready {
                                    self.send_circuit_data_cmd(
                                        circuit_id,
                                        RelayCellCommand::StreamConnected,
                                        &[],
                                    )
                                    .await?;
                                    if let Some(tx) = self
                                        .circuits
                                        .pending_extends
                                        .lock()
                                        .await
                                        .remove(&circuit_id)
                                    {
                                        let _ = tx.send(Vec::new());
                                    }
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::StreamConnected {
                                let mut pending = self.endpoints.pending_connects.lock().await;
                                if let Some(tx) = pending.remove(&circuit_id) {
                                    let _ = tx.send(true);
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::StreamRefused {
                                let mut pending = self.endpoints.pending_connects.lock().await;
                                if let Some(tx) = pending.remove(&circuit_id) {
                                    let _ = tx.send(false);
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::StreamEnd {
                                // The endpoint closed the stream (backend EOF, dial
                                // failed, or backend restart). Drop the data channel
                                // so the app's recv() errors and splice() resets the
                                // local client (e.g. Chromium) socket — without this,
                                // the client keeps reusing a dead pooled connection.
                                self.endpoints.close_stream(key).await;
                                return Ok(());
                            }
                            // Rendezvous protocol backward cells
                            if relay_cell.command == RelayCellCommand::IntroRegistered
                                || relay_cell.command == RelayCellCommand::IntroduceAck
                                || relay_cell.command == RelayCellCommand::RendezvousJoined
                            {
                                // Deliver via pending_circuit_extends (reusing the same mechanism)
                                let mut pending = self.circuits.pending_extends.lock().await;
                                if let Some(tx) = pending.remove(&circuit_id) {
                                    let _ = tx.send(relay_cell.data);
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::Introduce {
                                // INTRODUCE forwarded to us (the hidden service) through
                                // our intro point circuit. Answering takes a circuit build,
                                // so it runs off this circuit's queue, a few at a time.
                                let node = self.weak_self.get().and_then(|w| w.upgrade());
                                let permit = self.hidden.introduce_slots.clone().try_acquire_owned();
                                match (node, permit) {
                                    (Some(node), Ok(permit)) => {
                                        tokio::spawn(async move {
                                            node.handle_introduce_at_service(circuit_id, &relay_cell.data)
                                                .await;
                                            drop(permit);
                                        });
                                    }
                                    _ => log::debug!("INTRODUCE dropped: too many in progress"),
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::Padding {
                                // Circuit keepalive response — activity already updated above.
                                return Ok(());
                            }
                            log::debug!(
                                "Backward relay cell: circuit_id={}, cmd={:?}",
                                circuit_id,
                                relay_cell.command
                            );
                            return Ok(());
                        } else {
                            log::warn!(
                                "Backward relay cell parse failed circuit={}",
                                circuit_id,
                            );
                        }
                    } else {
                        drop(circuits);
                    }
                }

                log::debug!(
                    "Unknown circuit_id {} from {:?}, dropping",
                    circuit_id,
                    from
                );
                Ok(())
            }
        }
    }

    /// Handle a relay cell addressed to us as a circuit's endpoint.
    async fn handle_endpoint_relay_cell(
        &self,
        from: PeerId,
        circuit_id: u32,
        body: &[u8; CELL_BODY_SIZE],
    ) -> Result<()> {
        let key = CircuitKey {
            circuit_id,
            from_peer: from,
        };
        let piece = match RelayPiece::from_cell(body) {
            Ok(piece) => piece,
            Err(e) => {
                log::warn!(
                    "Relay cell parse failed at endpoint circuit_id={}: {}",
                    circuit_id,
                    e
                );
                return Ok(());
            }
        };
        // Pieces of a larger message are held on the circuit entry, so they
        // go away with the circuit.
        let relay_cell = {
            let mut table = self.circuits.table.lock().await;
            let Some(CircuitAction::Endpoint { assembler, .. }) = table.lookup_mut(&key) else {
                return Ok(());
            };
            match assembler.push(piece) {
                Some(relay_cell) => relay_cell,
                None => return Ok(()),
            }
        };

        match relay_cell.command {
            RelayCellCommand::Truncate => self.handle_truncate(from, circuit_id).await,
            RelayCellCommand::Extend => {
                self.handle_extend_at_relay(from, circuit_id, &relay_cell.data)
                    .await
            }
            RelayCellCommand::Data => self.handle_stream_data(key, &relay_cell.data).await,
            RelayCellCommand::StreamAck => self.handle_stream_ack(key, &relay_cell.data).await,
            RelayCellCommand::StreamBegin => {
                self.handle_stream_begin(from, circuit_id, &relay_cell.data)
                    .await
            }
            RelayCellCommand::StreamEnd => {
                self.endpoints.close_stream(key).await;
                Ok(())
            }
            RelayCellCommand::Introduce => {
                self.handle_introduce(from, circuit_id, &relay_cell.data)
                    .await
            }
            RelayCellCommand::IntroRegister => {
                self.handle_intro_register(from, circuit_id, &relay_cell.data)
                    .await
            }
            RelayCellCommand::RendezvousEstablish => {
                self.handle_rendezvous_establish(from, circuit_id, &relay_cell.data)
                    .await
            }
            RelayCellCommand::RendezvousJoin => {
                self.handle_rendezvous_join(from, circuit_id, &relay_cell.data)
                    .await
            }
            RelayCellCommand::Padding => {
                // Echo padding back to the initiator for circuit keepalive.
                self.send_endpoint_relay_cell(from, circuit_id, RelayCellCommand::Padding, &[])
                    .await
            }
            _ => {
                log::debug!(
                    "Unhandled relay cell command {:?} at endpoint",
                    relay_cell.command
                );
                Ok(())
            }
        }
    }

    /// Send a relay cell back from a circuit endpoint to the initiator.
    async fn send_endpoint_relay_cell(
        &self,
        from: PeerId,
        circuit_id: u32,
        command: RelayCellCommand,
        data: &[u8],
    ) -> Result<()> {
        let message = RelayCell {
            command,
            stream_id: 0,
            data: data.to_vec(),
        };
        for piece in message.pieces()? {
            let encoded = self
                .seal_backward(circuit_id, from, &piece.to_cell())
                .await
                .ok_or_else(|| Error::Protocol("no backward keys for circuit".into()))?;
            self.send_to_peer_critical(&from, &encoded).await?;
        }
        Ok(())
    }

    /// Handle TRUNCATE at the hop it is addressed to: undo whatever this hop
    /// started downstream (an EXTEND whose reply the initiator never got),
    /// become the circuit's endpoint again and answer TRUNCATED. Idempotent:
    /// a hop with nothing downstream just answers.
    async fn handle_truncate(&self, from: PeerId, circuit_id: u32) -> Result<()> {
        let key = CircuitKey {
            circuit_id,
            from_peer: from,
        };
        match self.circuits.table.lock().await.lookup(&key) {
            Some(CircuitAction::Forward { .. } | CircuitAction::Endpoint { .. }) => {}
            None => return Ok(()),
        }
        if let Some((next_hop, next_circuit_id)) = self.revert_extend(key).await {
            log::debug!(
                "TRUNCATE on circuit_id={} from {:?}: dropping leg to {:?}",
                circuit_id,
                from,
                next_hop
            );
            let destroy = CircuitDestroyMsg {
                circuit_id: next_circuit_id,
            };
            let _ = self.send_to_peer(&next_hop, &destroy.to_wire().encode()).await;
        }
        self.send_endpoint_relay_cell(from, circuit_id, RelayCellCommand::Truncated, &[])
            .await
    }

    /// Handle STREAM_BEGIN at the endpoint — the client wants to open a connection.
    /// Check if we're listening, create an incoming Connection, queue it for accept().
    ///
    /// Idempotent: if this circuit already has a stream (retransmitted StreamBegin),
    /// re-send StreamConnected without re-creating channels.
    async fn handle_stream_begin(
        &self,
        from: PeerId,
        circuit_id: u32,
        payload: &[u8],
    ) -> Result<()> {
        let key = CircuitKey {
            circuit_id,
            from_peer: from,
        };
        let (service_id, mode, port) = parse_stream_begin_payload(payload)?;

        // Idempotent: if we already set up a stream on this circuit,
        // just re-send StreamConnected (the first one may have been dropped).
        {
            let streams = self.endpoints.streams.lock().await;
            if streams.contains_key(&key) {
                drop(streams);
                log::debug!(
                    "STREAM_BEGIN retransmit on circuit {}, re-sending StreamConnected",
                    circuit_id,
                );
                self.send_endpoint_relay_cell(
                    from,
                    circuit_id,
                    RelayCellCommand::StreamConnected,
                    &[],
                )
                .await?;
                return Ok(());
            }
        }

        // A Hidden identity is reached only through its rendezvous circuits.
        // Refuse exactly as a node that doesn't host it would, so probing
        // candidate hosts with direct streams finds nothing.
        let hidden = self
            .identity_store
            .lock()
            .await
            .get_by_service_id(&service_id)
            .is_some_and(|id| matches!(id.privacy, tarnet_api::types::PrivacyLevel::Hidden { .. }));
        if hidden || !self.has_matching_listener(service_id, mode, &port).await {
            log::debug!(
                "STREAM_BEGIN rejected: not listening on {:?} mode {:?} port {}",
                service_id,
                mode,
                port,
            );
            // Send StreamRefused back to the initiator.
            self.send_endpoint_relay_cell(from, circuit_id, RelayCellCommand::StreamRefused, &[])
                .await?;
            return Ok(());
        }

        // Per-peer and global stream limits to prevent SYN flood.
        {
            let owners = self.endpoints.stream_owners.lock().await;
            // Global limit.
            if owners.len() >= super::MAX_STREAMS_GLOBAL {
                drop(owners);
                log::warn!("STREAM_BEGIN rejected: global stream limit reached");
                self.send_endpoint_relay_cell(
                    from,
                    circuit_id,
                    RelayCellCommand::StreamRefused,
                    &[],
                )
                .await?;
                return Ok(());
            }
            // Per-peer limit.
            let peer_count = owners.values().filter(|p| **p == from).count();
            if peer_count >= super::MAX_STREAMS_PER_PEER {
                drop(owners);
                log::warn!(
                    "STREAM_BEGIN rejected: peer {:?} at stream limit ({}/{})",
                    from,
                    peer_count,
                    super::MAX_STREAMS_PER_PEER,
                );
                self.send_endpoint_relay_cell(
                    from,
                    circuit_id,
                    RelayCellCommand::StreamRefused,
                    &[],
                )
                .await?;
                return Ok(());
            }
        }

        log::info!(
            "Incoming connection: {:?} mode {:?} port {} on circuit_id={}",
            service_id,
            mode,
            port,
            circuit_id
        );

        self.endpoints.stream_owners.lock().await.insert(key, from);
        let conn = self
            .stream_connection(service_id, mode, &port, key, false)
            .await;

        let port_name = conn.port.clone();
        let dispatch = self
            .dispatch_incoming_connection(service_id, mode, &port_name, conn)
            .await;
        if !matches!(dispatch, ListenerDispatch::Enqueued) {
            let reason = match dispatch {
                ListenerDispatch::NoListener => "listener disappeared before enqueue",
                ListenerDispatch::QueueFull => "listener queue full",
                ListenerDispatch::Enqueued => unreachable!(),
            };
            log::warn!(
                "STREAM_BEGIN rejected: {} on circuit {}",
                reason,
                circuit_id
            );
            self.endpoints.close_stream(key).await;
            self.send_endpoint_relay_cell(from, circuit_id, RelayCellCommand::StreamRefused, &[])
                .await?;
            return Ok(());
        }

        // Send StreamConnected back to the initiator.
        self.send_endpoint_relay_cell(from, circuit_id, RelayCellCommand::StreamConnected, &[])
            .await?;

        Ok(())
    }

    /// The neighbour to pass a routed CREATE to on its way to `dest`: `dest`
    /// itself if linked, else the next hop of our route to it, else toward
    /// the last hint we can reach. Never back to `from`.
    pub(super) async fn next_hop_toward(&self, dest: &PeerId, hints: &[PeerId], from: &PeerId) -> Option<PeerId> {
        let linked: HashSet<PeerId> = self.links.lock().await.keys().copied().collect();
        self.routing_table
            .lock()
            .await
            .next_hop_hinted(dest, hints, |p| linked.contains(p) && p != from)
    }

    /// Reserve a circuit id on our link to `next_hop`. Must be called with
    /// the reservation, outbound and table locks held, in that order.
    fn alloc_leg_id(
        table: &CircuitTable,
        reserved: &HashMap<u32, PeerId>,
        outbound: &HashMap<u32, ManagedCircuit>,
        we_initiated: bool,
    ) -> u32 {
        table.alloc_id(we_initiated, |id| {
            outbound.contains_key(&id) || reserved.contains_key(&id)
        })
    }

    async fn we_initiated_link(&self, peer: &PeerId) -> bool {
        self.links
            .lock()
            .await
            .get(peer)
            .map(|l| l.is_initiator())
            .unwrap_or(true)
    }

    /// Remember a CREATE's ephemeral key. Returns false if another circuit
    /// already used it: the CREATE looped, or was copied.
    async fn note_create_key(&self, eph_pk: &[u8], key: CircuitKey) -> bool {
        let id = *blake3::hash(eph_pk).as_bytes();
        let mut seen = self.circuits.create_keys.lock().await;
        let now = Instant::now();
        match seen.get(&id) {
            Some((k, at)) if now.duration_since(*at) < CREATE_KEY_TTL => *k == key,
            _ => {
                if seen.len() >= MAX_CREATE_KEYS {
                    seen.retain(|_, (_, at)| now.duration_since(*at) < CREATE_KEY_TTL);
                    if seen.len() >= MAX_CREATE_KEYS {
                        return false;
                    }
                }
                seen.insert(id, (key, now));
                true
            }
        }
    }

    /// Token bucket for CREATEs arriving on one link.
    async fn allow_create(&self, from: &PeerId) -> bool {
        let mut buckets = self.circuits.create_budget.lock().await;
        let now = Instant::now();
        let (tokens, at) = buckets.entry(*from).or_insert((CREATE_BURST, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * CREATE_RATE).min(CREATE_BURST);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    async fn refuse_create(&self, to: &PeerId, circuit_id: u32) {
        let destroy = CircuitDestroyMsg { circuit_id };
        let _ = self.send_to_peer(to, &destroy.to_wire().encode()).await;
    }

    /// Handle EXTEND at the circuit's last waypoint: send a routed CREATE
    /// toward the next waypoint. Our entry becomes a Forward with our layer;
    /// the nodes in between install keyless entries. The destination's
    /// CREATED comes back as EXTENDED; a failure as an empty EXTENDED.
    async fn handle_extend_at_relay(
        &self,
        from: PeerId,
        inbound_circuit_id: u32,
        extend_data: &[u8],
    ) -> Result<()> {
        let fail = || async {
            self.send_endpoint_relay_cell(from, inbound_circuit_id, RelayCellCommand::Extended, &[])
                .await
        };
        let Ok(req) = CreateRequest::from_bytes(extend_data) else {
            return fail().await;
        };
        if req.destination == self.peer_id() {
            return fail().await;
        }
        // A new segment may head back the way the circuit came: waypoints
        // are random, so the next one can lie behind us.
        let Some(next_hop) = self
            .next_hop_toward(&req.destination, &req.hints, &self.peer_id())
            .await
        else {
            log::debug!("EXTEND: no route to {:?}", req.destination);
            return fail().await;
        };
        let we_initiated_next = self.we_initiated_link(&next_hop).await;

        let reserved = self.circuits.pending_create_peers.lock().await;
        let outbound = self.circuits.outbound.lock().await;
        let mut table = self.circuits.table.lock().await;
        let inbound_key = CircuitKey {
            circuit_id: inbound_circuit_id,
            from_peer: from,
        };
        let existing_crypto = match table.lookup(&inbound_key) {
            Some(CircuitAction::Endpoint { crypto, .. }) => crypto.clone(),
            _ => {
                log::debug!("EXTEND on non-endpoint circuit_id={}", inbound_circuit_id);
                return Ok(());
            }
        };
        let outbound_id = Self::alloc_leg_id(&table, &reserved, &outbound, we_initiated_next);
        let out_key = CircuitKey {
            circuit_id: outbound_id,
            from_peer: next_hop,
        };
        // Cells from downstream gain our layer on their way to the initiator.
        let bwd_crypto = self
            .circuits
            .hop_backward_keys
            .lock()
            .await
            .get(&(inbound_circuit_id, from))
            .map(|hop| HopCrypto::new(hop.keys.clone(), CryptoOp::Encrypt));
        table.insert(
            inbound_key,
            CircuitAction::Forward {
                next_hop,
                next_circuit_id: outbound_id,
                crypto: existing_crypto,
            },
        );
        table.insert(
            out_key,
            CircuitAction::Forward {
                next_hop: from,
                next_circuit_id: inbound_circuit_id,
                crypto: bwd_crypto,
            },
        );
        drop(table);
        drop(outbound);
        drop(reserved);

        // A loop that brings this CREATE back to us must be recognised.
        self.note_create_key(&req.eph_pk, out_key).await;
        self.circuits
            .relay_extend_pending
            .lock()
            .await
            .insert(out_key, (from, inbound_circuit_id, Instant::now()));
        let create = CircuitCreateMsg {
            circuit_id: outbound_id,
            encrypted_payload: extend_data.to_vec(),
        };
        self.send_to_peer_critical(&next_hop, &create.to_wire().encode())
            .await
    }

    /// Undo an EXTEND at the waypoint that answered it: drop the leg it
    /// started and become the circuit's endpoint again. Returns the dropped
    /// leg.
    async fn revert_extend(&self, inbound: CircuitKey) -> Option<(PeerId, u32)> {
        let mut table = self.circuits.table.lock().await;
        let Some(CircuitAction::Forward {
            next_hop,
            next_circuit_id,
            crypto: Some(crypto),
        }) = table.lookup(&inbound).cloned()
        else {
            return None;
        };
        if crypto.op != CryptoOp::Decrypt || crypto.splice.is_some() {
            return None;
        }
        let leg = CircuitKey {
            circuit_id: next_circuit_id,
            from_peer: next_hop,
        };
        table.remove(&leg);
        table.insert(
            inbound,
            CircuitAction::Endpoint {
                assembler: Default::default(),
                origin_hop: inbound.from_peer,
                crypto: Some(crypto),
            },
        );
        drop(table);
        self.circuits.relay_extend_pending.lock().await.remove(&leg);
        Some((next_hop, next_circuit_id))
    }

    /// Handle CircuitCreate. A CREATE names its destination: the destination
    /// answers with a signed CREATED and becomes the circuit's endpoint; any
    /// other node passes it on along the route and installs keyless entries.
    pub(super) async fn handle_circuit_create(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = CircuitCreateMsg::from_bytes(payload)?;
        let key = CircuitKey {
            circuit_id: msg.circuit_id,
            from_peer: from,
        };

        // A resend of a CREATE already answered: the reply was lost. Answer
        // identically; fresh keys would not match.
        let create_hash = *blake3::hash(&msg.encrypted_payload).as_bytes();
        let cached = self
            .circuits
            .created_replies
            .lock()
            .await
            .get(&key)
            .filter(|(hash, _, _)| *hash == create_hash)
            .map(|(_, reply, _)| reply.clone());
        if let Some(reply) = cached {
            if self.circuits.table.lock().await.lookup(&key).is_some() {
                log::debug!("CircuitCreate {} resent by {:?}, replaying reply", msg.circuit_id, from);
                return self.send_to_peer_critical(&from, &reply).await;
            }
        }
        // A resend of a CREATE we passed on and still wait for: pass it on again.
        let passed_on = self
            .circuits
            .routed_pending
            .lock()
            .await
            .iter()
            .find(|(_, p)| p.upstream == key && p.hash == create_hash)
            .map(|(down, p)| (down.from_peer, p.create.clone()));
        if let Some((next_hop, create)) = passed_on {
            return self.send_to_peer_critical(&next_hop, &create).await;
        }

        if !self.allow_create(&from).await {
            log::debug!("CREATE rate limit for {:?}, refusing", from);
            self.refuse_create(&from, msg.circuit_id).await;
            return Ok(());
        }
        let req = match CreateRequest::from_bytes(&msg.encrypted_payload) {
            Ok(req) => req,
            Err(e) => {
                self.refuse_create(&from, msg.circuit_id).await;
                return Err(e);
            }
        };
        if !self.note_create_key(&req.eph_pk, key).await {
            log::debug!("CREATE from {:?} reuses a key in flight (loop), refusing", from);
            self.refuse_create(&from, msg.circuit_id).await;
            return Ok(());
        }

        if req.destination == self.peer_id() {
            return self.answer_create(key, &req, create_hash).await;
        }

        let Some(next_hop) = self.next_hop_toward(&req.destination, &req.hints, &from).await else {
            log::debug!("CREATE: no route to {:?}", req.destination);
            self.refuse_create(&from, msg.circuit_id).await;
            return Ok(());
        };
        let we_initiated_next = self.we_initiated_link(&next_hop).await;
        let reserved = self.circuits.pending_create_peers.lock().await;
        let outbound = self.circuits.outbound.lock().await;
        let mut table = self.circuits.table.lock().await;
        if table.lookup(&key).is_some()
            || outbound.get(&msg.circuit_id).is_some_and(|c| c.first_hop == from)
            || reserved.get(&msg.circuit_id) == Some(&from)
        {
            return Err(Error::Protocol("circuit ID already in use on this link".into()));
        }
        let outbound_id = Self::alloc_leg_id(&table, &reserved, &outbound, we_initiated_next);
        let down = CircuitKey {
            circuit_id: outbound_id,
            from_peer: next_hop,
        };
        table.insert(
            key,
            CircuitAction::Forward {
                next_hop,
                next_circuit_id: outbound_id,
                crypto: None,
            },
        );
        table.insert(
            down,
            CircuitAction::Forward {
                next_hop: from,
                next_circuit_id: msg.circuit_id,
                crypto: None,
            },
        );
        drop(table);
        drop(outbound);
        drop(reserved);

        let create = CircuitCreateMsg {
            circuit_id: outbound_id,
            encrypted_payload: msg.encrypted_payload,
        }
        .to_wire()
        .encode();
        self.circuits.routed_pending.lock().await.insert(
            down,
            RoutedCreate {
                upstream: key,
                hash: create_hash,
                create: create.clone(),
                at: Instant::now(),
            },
        );
        self.send_to_peer_critical(&next_hop, &create).await
    }

    /// We are a CREATE's destination: accept the key exchange, sign the
    /// handshake and become the circuit's endpoint.
    async fn answer_create(&self, key: CircuitKey, req: &CreateRequest, create_hash: [u8; 32]) -> Result<()> {
        let algo = tarnet_api::types::KemAlgo::from_u8(req.kem_algo)
            .map_err(|e| Error::Wire(format!("CircuitCreate unknown KEM algo: {}", e)))?;
        let (shared, kem_ct) = kex_accept(algo, &req.eph_pk)?;
        let transcript = req.transcript(&kem_ct);
        let hop_keys = HopKey::derive(&shared, &transcript);
        let reply = CreatedReply {
            sig: self.identity.sign(&created_signed_message(&transcript)),
            signing_pk: self.identity.identity.signing.signing_pubkey_bytes(),
            kem_ct,
        };

        let reserved = self.circuits.pending_create_peers.lock().await;
        let outbound = self.circuits.outbound.lock().await;
        let mut table = self.circuits.table.lock().await;
        if table.lookup(&key).is_some()
            || outbound
                .get(&key.circuit_id)
                .is_some_and(|c| c.first_hop == key.from_peer)
            || reserved.get(&key.circuit_id) == Some(&key.from_peer)
        {
            return Err(Error::Protocol("circuit ID already in use on this link".into()));
        }
        table.insert(
            key,
            CircuitAction::Endpoint {
                assembler: Default::default(),
                origin_hop: key.from_peer,
                crypto: Some(HopCrypto::new(hop_keys.forward.clone(), CryptoOp::Decrypt)),
            },
        );
        drop(table);
        drop(outbound);
        drop(reserved);
        self.store_hop_backward_crypto(key.circuit_id, key.from_peer, hop_keys.backward, transcript)
            .await;

        let reply = CircuitCreatedMsg {
            circuit_id: key.circuit_id,
            encrypted_reply: reply.to_bytes(),
        }
        .to_wire()
        .encode();
        self.cache_created_reply(key, create_hash, reply.clone()).await;
        self.send_to_peer_critical(&key.from_peer, &reply).await
    }

    /// Tear down routed CREATEs older than [`ROUTED_CREATE_TIMEOUT`]: drop
    /// both keyless entries and tell both neighbours.
    pub(super) async fn expire_routed_creates(&self) {
        let now = Instant::now();
        let stale: Vec<(CircuitKey, CircuitKey)> = {
            let mut pending = self.circuits.routed_pending.lock().await;
            let stale = pending
                .iter()
                .filter(|(_, p)| now.duration_since(p.at) >= ROUTED_CREATE_TIMEOUT)
                .map(|(down, p)| (*down, p.upstream))
                .collect::<Vec<_>>();
            for (down, _) in &stale {
                pending.remove(down);
            }
            stale
        };
        for (down, up) in stale {
            {
                let mut table = self.circuits.table.lock().await;
                table.remove(&down);
                table.remove(&up);
            }
            log::debug!("Routed CREATE toward {:?} unanswered, tearing down", down.from_peer);
            self.refuse_create(&down.from_peer, down.circuit_id).await;
            self.refuse_create(&up.from_peer, up.circuit_id).await;
        }
    }

    /// Tear down relay and endpoint entries idle for `max_idle`, with
    /// DESTROY both ways, so a circuit whose ends vanished without a DESTROY
    /// doesn't hold state forever.
    pub(super) async fn expire_idle_relay_entries(&self, max_idle: Duration) {
        let idle = self.circuits.table.lock().await.idle_entries(max_idle);
        for key in idle {
            // Tearing down one direction of a pair removes the other too.
            if self.circuits.table.lock().await.lookup(&key).is_none() {
                continue;
            }
            log::debug!(
                "Circuit entry {} from {:?} idle, tearing down",
                key.circuit_id,
                key.from_peer
            );
            let destroy = CircuitDestroyMsg {
                circuit_id: key.circuit_id,
            };
            // As if `from_peer` had sent DESTROY: clears our state and
            // passes it on downstream.
            let _ = self
                .handle_circuit_destroy(key.from_peer, &destroy.to_bytes())
                .await;
            self.refuse_create(&key.from_peer, key.circuit_id).await;
        }
    }

    async fn cache_created_reply(&self, key: CircuitKey, create_hash: [u8; 32], reply: Vec<u8>) {
        let mut cache = self.circuits.created_replies.lock().await;
        let now = Instant::now();
        cache.retain(|_, (_, _, at)| now.duration_since(*at) < CREATED_REPLY_TTL);
        cache.insert(key, (create_hash, reply, now));
    }

    /// Handle CircuitCreated: pass it back along a routed CREATE, turn it
    /// into EXTENDED at the waypoint that sent the CREATE, or hand it to the
    /// initiator.
    pub(super) async fn handle_circuit_created(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = CircuitCreatedMsg::from_bytes(payload)?;
        let key = CircuitKey {
            circuit_id: msg.circuit_id,
            from_peer: from,
        };
        let expected = self.circuits.table.lock().await.lookup(&key).is_some();

        if expected {
            let routed = self.circuits.routed_pending.lock().await.remove(&key);
            if let Some(p) = routed {
                let reply = CircuitCreatedMsg {
                    circuit_id: p.upstream.circuit_id,
                    encrypted_reply: msg.encrypted_reply,
                }
                .to_wire()
                .encode();
                self.cache_created_reply(p.upstream, p.hash, reply.clone()).await;
                return self.send_to_peer_critical(&p.upstream.from_peer, &reply).await;
            }
            let extend = self.circuits.relay_extend_pending.lock().await.remove(&key);
            if let Some((inbound_from, inbound_circuit_id, _)) = extend {
                return self
                    .send_endpoint_relay_cell(
                        inbound_from,
                        inbound_circuit_id,
                        RelayCellCommand::Extended,
                        &msg.encrypted_reply,
                    )
                    .await;
            }
        }

        // Otherwise, this is for the circuit initiator.
        let expected = self.circuits.pending_create_peers.lock().await;
        if expected.get(&msg.circuit_id) != Some(&from) {
            return Ok(());
        }
        drop(expected);
        // Hop 1 is already built (the partial circuit is stored before any
        // EXTEND waiter is registered under the same id): this is a duplicate
        // reply to a resent CREATE and must not reach an EXTEND waiter.
        if self.circuits.outbound.lock().await.contains_key(&msg.circuit_id) {
            log::trace!("Duplicate CircuitCreated for circuit {}", msg.circuit_id);
            return Ok(());
        }
        let mut pending = self.circuits.pending_extends.lock().await;
        if let Some(tx) = pending.remove(&msg.circuit_id) {
            let _ = tx.send(msg.encrypted_reply);
        } else {
            log::debug!(
                "No pending extend for CircuitCreated circuit_id={}",
                msg.circuit_id
            );
        }
        Ok(())
    }

    /// Handle CircuitDestroy — teardown a circuit hop.
    pub(super) async fn handle_circuit_destroy(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = CircuitDestroyMsg::from_bytes(payload)?;
        let key = CircuitKey {
            circuit_id: msg.circuit_id,
            from_peer: from,
        };

        let local_attempt = self
            .circuits
            .outbound
            .lock()
            .await
            .get(&msg.circuit_id)
            .is_some_and(|c| c.first_hop == from)
            || self
                .circuits
                .pending_create_peers
                .lock()
                .await
                .get(&msg.circuit_id)
                == Some(&from);

        let action = {
            let mut table = self.circuits.table.lock().await;
            let action = table.remove(&key);
            if let Some(CircuitAction::Forward {
                next_hop,
                next_circuit_id,
                ..
            }) = &action
            {
                let reverse = CircuitKey {
                    circuit_id: *next_circuit_id,
                    from_peer: *next_hop,
                };
                if matches!(table.lookup(&reverse), Some(CircuitAction::Forward {
                    next_hop, next_circuit_id, ..
                }) if *next_hop == from && *next_circuit_id == msg.circuit_id)
                {
                    table.remove(&reverse);
                    self.circuits
                        .hop_backward_keys
                        .lock()
                        .await
                        .remove(&(reverse.circuit_id, reverse.from_peer));
                    self.circuits
                        .relay_queues
                        .lock()
                        .await
                        .remove(&(reverse.circuit_id, reverse.from_peer));
                }
            }
            action
        };
        if let Some(action) = action {
            // Propagate destroy to the next hop
            if let CircuitAction::Forward {
                next_hop,
                next_circuit_id,
                ..
            } = action
            {
                let destroy = CircuitDestroyMsg {
                    circuit_id: next_circuit_id,
                };
                let _ = self
                    .send_to_peer_critical(&next_hop, &destroy.to_wire().encode())
                    .await;
            }
            log::debug!(
                "Circuit destroyed: circuit_id={} from {:?}",
                msg.circuit_id,
                from
            );
        } else {
            // IDs are scoped to a link. An unrelated peer must not tear down
            // an outbound circuit or its application's receive channel.
            let mut outbound = self.circuits.outbound.lock().await;
            let owns_outbound = outbound
                .get(&msg.circuit_id)
                .is_some_and(|c| c.first_hop == from);
            if owns_outbound {
                outbound.remove(&msg.circuit_id);
            }
            drop(outbound);
            let mut pending = self.circuits.pending_create_peers.lock().await;
            let owns_pending = pending.get(&msg.circuit_id) == Some(&from);
            if owns_pending {
                pending.remove(&msg.circuit_id);
            }
            if !owns_outbound && !owns_pending {
                return Ok(());
            }
        }

        self.endpoints.close_stream(key).await;
        if local_attempt {
            self.endpoints
                .pending_connects
                .lock()
                .await
                .remove(&msg.circuit_id);
            self.circuits
                .pending_extends
                .lock()
                .await
                .remove(&msg.circuit_id);
        }
        self.circuits
            .relay_extend_pending
            .lock()
            .await
            .retain(|id, (peer, cid, _)| {
                *id != key && !(*peer == from && *cid == msg.circuit_id)
            });
        self.circuits
            .routed_pending
            .lock()
            .await
            .retain(|down, p| *down != key && p.upstream != key);
        self.circuits
            .hop_backward_keys
            .lock()
            .await
            .remove(&(msg.circuit_id, from));
        // Remove the per-circuit relay queue (drops the sender, which
        // causes the processing task to exit on next recv()).
        self.circuits
            .relay_queues
            .lock()
            .await
            .remove(&(msg.circuit_id, from));
        // Clean up intro point registration if this circuit was an intro point.
        self.hidden.intro_registrations.lock().await.remove(&key);
        // Clean up rendezvous entries where this circuit was a participant.
        self.hidden.rendezvous.lock().await.retain(|_, entry| {
            !(entry.client_circuit_id == msg.circuit_id && entry.client_from == from)
                && !(entry.service_circuit_id == Some(msg.circuit_id)
                    && entry.service_from == Some(from))
        });

        Ok(())
    }

    // ── Rendezvous protocol handlers ──

    /// Handle INTRO_REGISTER: a hidden service registers with us as an intro point.
    async fn handle_intro_register(
        &self,
        from: PeerId,
        circuit_id: u32,
        payload: &[u8],
    ) -> Result<()> {
        // The registration must be signed by the service's key and bound to
        // our handshake with this circuit.
        let transcript = self
            .circuits
            .hop_backward_keys
            .lock()
            .await
            .get(&(circuit_id, from))
            .map(|hop| hop.transcript);
        let Some(transcript) = transcript else {
            return Ok(());
        };
        let service_id = match verify_intro_register(payload, &self.peer_id(), &transcript) {
            Ok(sid) => sid,
            Err(e) => {
                log::warn!("IntroRegister refused on circuit_id={}: {}", circuit_id, e);
                return Ok(());
            }
        };
        log::info!(
            "IntroRegister: service {:?} registered on circuit_id={}",
            service_id,
            circuit_id,
        );
        self.hidden.intro_registrations.lock().await.insert(
            CircuitKey {
                circuit_id,
                from_peer: from,
            },
            (service_id, from),
        );

        // Send IntroRegistered back (empty payload)
        self.send_endpoint_relay_cell(from, circuit_id, RelayCellCommand::IntroRegistered, &[])
            .await
    }

    /// Handle INTRODUCE at an intro point: forward the INTRODUCE data to the registered service.
    async fn handle_introduce(&self, from: PeerId, circuit_id: u32, payload: &[u8]) -> Result<()> {
        log::info!(
            "Introduce received at intro point on circuit_id={}",
            circuit_id,
        );

        // The client prefixes the target ServiceId so we forward to the circuit
        // of the service it actually wants. Without this we'd forward to an
        // arbitrary registered service, and any node hosting more than one
        // hidden service (which typically share intro points) would be
        // unreachable for all but one of them.
        let (target_sid, _ext, sealed) = match parse_introduce_cell(payload) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[B-INTRO] malformed INTRODUCE cell: {}", e);
                return Ok(());
            }
        };

        self.forward_introduce(&target_sid, sealed).await;

        // Send IntroduceAck back to the client
        self.send_endpoint_relay_cell(from, circuit_id, RelayCellCommand::IntroduceAck, &[])
            .await
    }

    /// As an intro point: pass a sealed INTRODUCE to the service registered
    /// for `target_sid`, on its circuit to us. Returns whether one was.
    pub(super) async fn forward_introduce(
        &self,
        target_sid: &tarnet_api::types::ServiceId,
        sealed: &[u8],
    ) -> bool {
        let service = self
            .hidden
            .intro_registrations
            .lock()
            .await
            .iter()
            .find(|(_, (sid, _))| sid == target_sid)
            .map(|(key, _)| *key);
        let Some(service) = service else {
            log::warn!("No service {:?} registered at this intro point", target_sid);
            return false;
        };
        self.send_endpoint_relay_cell(
            service.from_peer,
            service.circuit_id,
            RelayCellCommand::Introduce,
            sealed,
        )
        .await
        .is_ok()
    }

    /// Handle RENDEZVOUS_ESTABLISH: client registers a cookie at the rendezvous point.
    async fn handle_rendezvous_establish(
        &self,
        from: PeerId,
        circuit_id: u32,
        payload: &[u8],
    ) -> Result<()> {
        let cookie = parse_rendezvous_establish_payload(payload)?;
        log::info!(
            "RendezvousEstablish: cookie registered on circuit_id={} from {:?}",
            circuit_id,
            from,
        );
        let entry = RendezvousEntry {
            client_circuit_id: circuit_id,
            client_from: from,
            service_circuit_id: None,
            service_from: None,
            created_at: Instant::now(),
        };
        self.hidden.rendezvous.lock().await.insert(cookie, entry);
        Ok(())
    }

    /// Handle RENDEZVOUS_JOIN: service connects to rendezvous with a cookie.
    async fn handle_rendezvous_join(
        &self,
        from: PeerId,
        circuit_id: u32,
        payload: &[u8],
    ) -> Result<()> {
        let (cookie, join) = parse_rendezvous_join_payload(payload)?;
        log::info!(
            "RendezvousJoin: cookie lookup on circuit_id={} from {:?}",
            circuit_id,
            from,
        );

        let mut table = self.hidden.rendezvous.lock().await;
        let entry = match table.get_mut(&cookie) {
            Some(e) if e.service_circuit_id.is_none() => e,
            _ => {
                log::debug!("RendezvousJoin: unknown or used cookie");
                return Ok(());
            }
        };
        entry.service_circuit_id = Some(circuit_id);
        entry.service_from = Some(from);
        let client = CircuitKey {
            circuit_id: entry.client_circuit_id,
            from_peer: entry.client_from,
        };
        drop(table);
        let service = CircuitKey {
            circuit_id,
            from_peer: from,
        };

        // Splice the circuits. A cell from one side loses our layer of that
        // circuit and gains our layer of the other, so both ends keep all
        // their hop keys and the end-to-end layer rides inside.
        let backward = |key: CircuitKey| async move {
            self.circuits
                .hop_backward_keys
                .lock()
                .await
                .get(&(key.circuit_id, key.from_peer))
                .map(|hop| HopCrypto::new(hop.keys.clone(), CryptoOp::Encrypt))
        };
        let (Some(to_client), Some(to_service)) = (backward(client).await, backward(service).await)
        else {
            return Ok(());
        };
        {
            let mut ct = self.circuits.table.lock().await;
            let peel = |ct: &CircuitTable, key: &CircuitKey| match ct.lookup(key) {
                Some(CircuitAction::Endpoint {
                    crypto: Some(c), ..
                }) => Some(c.clone()),
                _ => None,
            };
            let (Some(from_client), Some(from_service)) = (peel(&ct, &client), peel(&ct, &service))
            else {
                return Ok(());
            };
            ct.insert(
                client,
                CircuitAction::Forward {
                    next_hop: service.from_peer,
                    next_circuit_id: service.circuit_id,
                    crypto: Some(from_client.spliced(to_service)),
                },
            );
            ct.insert(
                service,
                CircuitAction::Forward {
                    next_hop: client.from_peer,
                    next_circuit_id: client.circuit_id,
                    crypto: Some(from_service.spliced(to_client)),
                },
            );
        }

        // Pass the service's answer to the client.
        self.send_endpoint_relay_cell(
            client.from_peer,
            client.circuit_id,
            RelayCellCommand::RendezvousJoined,
            join,
        )
        .await
    }

    async fn store_hop_backward_crypto(
        &self,
        circuit_id: u32,
        from_peer: PeerId,
        keys: LayerKeys,
        transcript: [u8; 32],
    ) {
        self.circuits.hop_backward_keys.lock().await.insert(
            (circuit_id, from_peer),
            super::HopBackward {
                keys,
                counter: 0,
                transcript,
            },
        );
    }

    /// Seal a cell at our layer of a circuit for its initiator, taking the
    /// next backward counter. `None` once the circuit is gone.
    pub(super) async fn seal_backward(
        &self,
        circuit_id: u32,
        from_peer: PeerId,
        body: &[u8; CELL_BODY_SIZE],
    ) -> Option<Vec<u8>> {
        let mut map = self.circuits.hop_backward_keys.lock().await;
        let hop = map.get_mut(&(circuit_id, from_peer))?;
        let n = hop.counter;
        hop.counter = n.checked_add(1)?;
        Some(seal_backward_cell(&hop.keys, n, circuit_id, body))
    }

    /// How long to wait for one EXTEND step: a floor, plus per built hop an
    /// allowance and the airtime of the step's cells on our first link. The
    /// first link is the only one whose speed we know; on a slow chain it is
    /// usually the slow part.
    async fn extend_step_timeout(&self, first_hop: PeerId, hops_built: usize, bytes: usize) -> Duration {
        let airtime = self
            .links
            .lock()
            .await
            .get(&first_hop)
            .map(|l| l.tx_time(bytes as u64))
            .unwrap_or_default();
        EXTEND_STEP_FLOOR.max((EXTEND_PER_HOP + airtime * 4) * hops_built as u32)
    }

    /// Send a relay message to the circuit's current last hop.
    async fn send_to_last_hop(&self, circuit_id: u32, message: &RelayCell) -> Result<usize> {
        let mut circuits = self.circuits.outbound.lock().await;
        let circuit = circuits
            .get_mut(&circuit_id)
            .ok_or_else(|| Error::Protocol("circuit gone during extension".into()))?;
        let hops_built = circuit.layers.len();
        let (first_hop, cid, cells) = circuit.send_relay_message(message)?;
        drop(circuits);
        for cell in &cells {
            let encoded = encode_circuit_relay_cell(cid, cell);
            self.send_to_peer_critical(&first_hop, &encoded).await?;
        }
        Ok(hops_built)
    }

    /// One EXTEND step toward `waypoint`, returning the new layer once the
    /// waypoint has proven itself. If the reply doesn't come in time, truncate
    /// back to the hops already built and try again, so a lost cell costs one
    /// step rather than the whole circuit. A step the waypoint's route can't
    /// make (empty EXTENDED) is retried too: routes change.
    async fn extend_step(
        &self,
        circuit_id: u32,
        first_hop: PeerId,
        kem_algo: tarnet_api::types::KemAlgo,
        waypoint: &PeerId,
        hints: &[PeerId],
    ) -> Result<(HopKey, [u8; 32])> {
        // Links the routed CREATE may cross, as far as our table can tell.
        let segment = self
            .routing_table
            .lock()
            .await
            .lookup(waypoint)
            .map_or(2, |r| (r.cost as usize).clamp(1, 32));
        for attempt in 1..=EXTEND_ATTEMPTS {
            let kex = KexOffer::new(kem_algo);
            let request = CreateRequest {
                kem_algo: kex.algo_byte(),
                eph_pk: kex.pubkey_bytes(),
                destination: *waypoint,
                hints: hints.to_vec(),
            };
            let extend_cell = RelayCell {
                command: RelayCellCommand::Extend,
                stream_id: 0,
                data: request.to_bytes(),
            };

            // Register before sending: a fast EXTENDED reply must not be lost.
            let (tx, rx) = oneshot::channel();
            self.circuits
                .pending_extends
                .lock()
                .await
                .insert(circuit_id, tx);

            let hops_built = self.send_to_last_hop(circuit_id, &extend_cell).await?;
            // The signed reply is about twice the request.
            let timeout = self
                .extend_step_timeout(first_hop, hops_built + segment, extend_cell.data.len() * 3)
                .await;

            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(data)) if data.is_empty() => {
                    log::debug!(
                        "EXTEND toward {:?} on circuit {} failed (try {})",
                        waypoint,
                        circuit_id,
                        attempt
                    );
                }
                Ok(Ok(data)) => return Self::complete_hop(&kex, &request, &data),
                Ok(Err(_)) => {
                    self.circuits.pending_extends.lock().await.remove(&circuit_id);
                    return Err(Error::Protocol("circuit extend channel dropped".into()));
                }
                Err(_) => {
                    self.circuits.pending_extends.lock().await.remove(&circuit_id);
                    if attempt == EXTEND_ATTEMPTS {
                        break;
                    }
                    log::debug!(
                        "EXTEND toward {:?} on circuit {} timed out (try {}), truncating",
                        waypoint,
                        circuit_id,
                        attempt
                    );
                    self.truncate_circuit(circuit_id, timeout).await?;
                }
            }
        }
        Err(Error::Protocol(format!("could not extend to {:?}", waypoint)))
    }

    /// Check a CREATED (or EXTENDED) reply against our request and derive
    /// the new layer. Fails unless the destination itself answered.
    fn complete_hop(
        kex: &KexOffer,
        request: &CreateRequest,
        reply: &[u8],
    ) -> Result<(HopKey, [u8; 32])> {
        let reply = CreatedReply::from_bytes(reply)?;
        let transcript = reply.verify(request)?;
        let shared = kex.complete(&reply.kem_ct)?;
        Ok((HopKey::derive(&shared, &transcript), transcript))
    }

    /// Ask the circuit's last built hop to drop anything it started
    /// downstream, and wait for it to confirm.
    async fn truncate_circuit(&self, circuit_id: u32, timeout: Duration) -> Result<()> {
        let truncate = RelayCell {
            command: RelayCellCommand::Truncate,
            stream_id: 0,
            data: Vec::new(),
        };
        for _ in 0..TRUNCATE_ATTEMPTS {
            let (tx, rx) = oneshot::channel();
            self.circuits
                .pending_truncates
                .lock()
                .await
                .insert(circuit_id, tx);
            self.send_to_last_hop(circuit_id, &truncate).await?;
            if let Ok(Ok(())) = tokio::time::timeout(timeout, rx).await {
                return Ok(());
            }
        }
        self.circuits.pending_truncates.lock().await.remove(&circuit_id);
        Err(Error::Protocol("circuit truncate timed out".into()))
    }

    /// Number of onion layers on one of our circuits (testing).
    #[doc(hidden)]
    pub async fn circuit_layer_count(&self, circuit_id: u32) -> Option<usize> {
        self.circuits
            .outbound
            .lock()
            .await
            .get(&circuit_id)
            .map(|c| c.layers.len())
    }

    pub async fn build_circuit(&self, first_hop: PeerId, waypoints: Vec<PeerId>) -> Result<u32> {
        self.build_circuit_hinted(first_hop, waypoints, &[]).await
    }

    /// Hints for the CREATE to waypoint `i`: `target_hints` for the last one
    /// if given, else what relay sampling found.
    async fn waypoint_hints(&self, waypoints: &[PeerId], i: usize, target_hints: &[PeerId]) -> Vec<PeerId> {
        if i + 1 == waypoints.len() && !target_hints.is_empty() {
            return target_hints.to_vec();
        }
        self.relay_hints(&waypoints[i]).await
    }

    /// Build a circuit through `waypoints`, the last reached with
    /// `target_hints` (if any) rather than hints of our own.
    pub(super) async fn build_circuit_hinted(
        &self,
        first_hop: PeerId,
        waypoints: Vec<PeerId>,
        target_hints: &[PeerId],
    ) -> Result<u32> {
        if waypoints.is_empty() {
            return Err(Error::Protocol("circuit waypoints are empty".into()));
        }

        let we_initiated = {
            let links = self.links.lock().await;
            links
                .get(&first_hop)
                .map(|l| l.is_initiator())
                .unwrap_or(true)
        };
        let circuit_id = {
            let mut reserved = self.circuits.pending_create_peers.lock().await;
            let oc = self.circuits.outbound.lock().await;
            let id = self
                .circuits
                .table
                .lock()
                .await
                .alloc_id(we_initiated, |id| {
                    oc.contains_key(&id) || reserved.contains_key(&id)
                });
            reserved.insert(id, first_hop);
            id
        };
        let mut attempt = self.circuit_attempt_guard(circuit_id);
        attempt.first_hop = Some(first_hop);

        log::debug!(
            "Building circuit: circuit_id={}, first_hop={:?}, waypoints={:?}",
            circuit_id,
            first_hop,
            waypoints
        );

        let mut hop_keys = Vec::with_capacity(waypoints.len());

        // --- First waypoint: a CREATE routed from our first hop ---
        let kem_algo = self.identity.identity.kem_algo();
        let kex = KexOffer::new(kem_algo);
        let request = CreateRequest {
            kem_algo: kex.algo_byte(),
            eph_pk: kex.pubkey_bytes(),
            destination: waypoints[0],
            hints: self.waypoint_hints(&waypoints, 0, target_hints).await,
        };
        let create_payload = request.to_bytes();

        // Register pending extend before sending
        let (tx, rx) = oneshot::channel();
        self.circuits
            .pending_extends
            .lock()
            .await
            .insert(circuit_id, tx);

        let create = CircuitCreateMsg {
            circuit_id,
            encrypted_payload: create_payload,
        };
        let create = create.to_wire().encode();
        self.send_to_peer_critical(&first_hop, &create).await?;

        // Wait for CircuitCreated, resending the identical CREATE meanwhile:
        // either message may be lost, and the hop answers a repeat with the
        // same reply. On a slow link, wait for the CREATE and its reply to be
        // on the air before resending.
        let airtime = self
            .links
            .lock()
            .await
            .get(&first_hop)
            .map(|l| l.tx_time(2 * create.len() as u64))
            .unwrap_or_default();
        let resend_interval = CREATE_RESEND_INTERVAL.max(airtime * 2);
        let deadline = tokio::time::Instant::now() + CREATE_TIMEOUT.max(resend_interval * 8);
        let mut rx = rx;
        let reply = loop {
            let wait = crate::types::jittered(resend_interval)
                .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            match tokio::time::timeout(wait, &mut rx).await {
                Ok(r) => {
                    break r.map_err(|_| Error::Protocol("circuit create channel dropped".into()))?
                }
                Err(_) if tokio::time::Instant::now() >= deadline => {
                    self.circuits.pending_extends.lock().await.remove(&circuit_id);
                    return Err(Error::Protocol("circuit create timed out".into()));
                }
                Err(_) => {
                    log::debug!("CircuitCreate {} to {:?} resent", circuit_id, first_hop);
                    self.send_to_peer_critical(&first_hop, &create).await?;
                }
            }
        };

        let (first_layer, first_transcript) = Self::complete_hop(&kex, &request, &reply)?;
        hop_keys.push(first_layer);
        log::debug!("Circuit hop 1 ({:?}) established", waypoints[0]);

        // Store the partial circuit so backward relay cells can be decrypted
        // during construction of subsequent hops.
        {
            let mut circuit = OutboundCircuit::new(
                first_hop,
                circuit_id,
                OnionLayers::new(hop_keys.clone()),
                waypoints.clone(),
                CircuitPhase::Extending { hops_built: 1 },
            );
            circuit.transcripts.push(first_transcript);
            let managed = self.manage_circuit(circuit_id, circuit);
            self.circuits
                .outbound
                .lock()
                .await
                .insert(circuit_id, managed);
        }
        self.circuits
            .pending_create_peers
            .lock()
            .await
            .remove(&circuit_id);

        // --- Each further waypoint: one EXTEND step ---
        for (i, waypoint) in waypoints.iter().enumerate().skip(1) {
            let hints = self.waypoint_hints(&waypoints, i, target_hints).await;
            let (hop, transcript) = self
                .extend_step(circuit_id, first_hop, kem_algo, waypoint, &hints)
                .await?;
            let hops_built = {
                let mut circuits = self.circuits.outbound.lock().await;
                let circuit = circuits
                    .get_mut(&circuit_id)
                    .ok_or_else(|| Error::Protocol("circuit gone during extension".into()))?;
                circuit.layers.push(hop);
                circuit.transcripts.push(transcript);
                let hops = circuit.layers.len();
                circuit.state = CircuitPhase::Extending { hops_built: hops };
                hops
            };
            log::debug!("Circuit hop {} established (waypoint {:?})", hops_built, waypoint);
        }

        // Mark circuit as ready.
        let final_hops = {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits
                .get_mut(&circuit_id)
                .ok_or_else(|| Error::Protocol("circuit gone during construction".into()))?;
            circuit.state = CircuitPhase::Ready;
            circuit.layers.len()
        };

        log::info!(
            "Circuit built: circuit_id={}, {} hops, {} waypoints",
            circuit_id,
            final_hops,
            waypoints.len()
        );
        attempt.armed = false;
        Ok(circuit_id)
    }

    /// Submit application data to the circuit's Channel, never bypassing its
    /// delivery semantics. Bare circuits must establish a stream first.
    pub async fn send_circuit_data(&self, circuit_id: u32, data: &[u8]) -> Result<()> {
        let peer = self
            .circuits
            .outbound
            .lock()
            .await
            .get(&circuit_id)
            .map(|c| c.first_hop)
            .ok_or_else(|| Error::Protocol("no such outbound circuit".into()))?;
        let key = CircuitKey {
            circuit_id,
            from_peer: peer,
        };
        let tx = self
            .endpoints
            .streams
            .lock()
            .await
            .get(&key)
            .and_then(|stream| stream.app_tx.upgrade())
            .ok_or_else(|| Error::Protocol("circuit has no open stream".into()))?;
        tx.send(data.to_vec())
            .await
            .map_err(|_| Error::Protocol("stream closed".into()))
    }

    /// Send a circuit control command; application DATA goes through Channel.
    pub(super) async fn send_circuit_data_cmd(
        &self,
        circuit_id: u32,
        command: RelayCellCommand,
        data: &[u8],
    ) -> Result<()> {
        let mut circuits = self.circuits.outbound.lock().await;
        let circuit = circuits
            .get_mut(&circuit_id)
            .ok_or_else(|| Error::Protocol("no such outbound circuit".into()))?;

        let relay_cell = RelayCell {
            command,
            stream_id: 0,
            data: data.to_vec(),
        };

        let (first_hop, cid, cell) = circuit.send_relay_cell(&relay_cell);
        drop(circuits);

        let encoded = encode_circuit_relay_cell(cid, &cell);
        self.send_to_peer(&first_hop, &encoded).await
    }

    /// Destroy an outbound circuit.
    /// Destroy an outbound circuit. Removing it from the map triggers the
    /// [`CircuitDropGuard`] which sends CircuitDestroy, cleans up connections,
    /// and handles multipath failover automatically.
    pub async fn destroy_circuit(&self, circuit_id: u32) -> Result<()> {
        let removed = self.circuits.outbound.lock().await.remove(&circuit_id);
        if removed.is_some() {
            log::debug!("Destroyed outbound circuit {}", circuit_id);
        }
        Ok(())
    }

    /// Build a circuit with a multipath backup through a different first hop.
    /// Creates a CircuitGroup with primary + backup (if possible).
    /// Returns the primary circuit_id and registers the group.
    ///
    /// `node_arc` is needed to spawn the background backup-building task.
    pub async fn build_circuit_with_backup(
        node_arc: Arc<Node>,
        dest: &PeerId,
        first_hop: PeerId,
        waypoints: Vec<PeerId>,
        mode: crate::multipath::PathMode,
    ) -> Result<u32> {
        let primary_id = node_arc.build_circuit(first_hop, waypoints.clone()).await?;

        // Register the circuit group
        let group =
            crate::multipath::CircuitGroup::new(*dest, mode, primary_id, first_hop, waypoints);
        node_arc.circuits.groups.lock().await.insert(group);

        // Try to build a backup circuit through a different first hop
        let node = node_arc.clone();
        let dest_copy = *dest;
        tokio::spawn(async move {
            // Cooldown to avoid overwhelming the network during setup
            tokio::time::sleep(CIRCUIT_REBUILD_COOLDOWN).await;

            let used_hops = {
                let groups = node.circuits.groups.lock().await;
                match groups.get(&dest_copy) {
                    Some(g) => g.used_first_hops(),
                    None => return,
                }
            };

            // Find an alternative first hop via routing table
            let alt_hops: Vec<PeerId> = {
                let rt = node.routing_table.lock().await;
                rt.lookup_multi(&dest_copy, 3)
                    .into_iter()
                    .filter(|h| !used_hops.contains(h))
                    .collect()
            };

            if let Some(alt_first_hop) = alt_hops.first() {
                let backup_waypoints = vec![dest_copy];
                match node
                    .build_circuit(*alt_first_hop, backup_waypoints.clone())
                    .await
                {
                    Ok(backup_id) => {
                        let mut groups = node.circuits.groups.lock().await;
                        if let Some(group) = groups.get_mut(&dest_copy) {
                            let disjoint =
                                group.add_backup(backup_id, *alt_first_hop, backup_waypoints);
                            log::info!(
                                "Built backup circuit {} for {:?} (node-disjoint: {})",
                                backup_id,
                                dest_copy,
                                disjoint,
                            );
                        }
                    }
                    Err(e) => {
                        log::debug!("Failed to build backup circuit for {:?}: {}", dest_copy, e);
                    }
                }
            } else {
                log::debug!(
                    "No alternative first hop for backup circuit to {:?}",
                    dest_copy
                );
            }
        });

        Ok(primary_id)
    }

    /// Connect to a remote service via onion circuit.
    /// Builds a circuit, returns a Connection for bidirectional data exchange.
    ///
    /// Resolution order:
    /// 1. If `dest_peer` hint provided, route directly to that node.
    /// 2. Try every reachable peer — build circuit, send StreamBegin.
    ///    The remote node matches ServiceId against its listeners.
    /// 3. Fall back to rendezvous via TNS intro points (hidden services).
    pub async fn circuit_connect(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        dest_peer: Option<PeerId>,
        source_identity: Option<tarnet_api::types::ServiceId>,
    ) -> Result<tarnet_api::service::Connection> {
        // 0. Loopback: if we own this ServiceId AND are listening on it, short-circuit.
        //    A wildcard listener (ServiceId::ALL) alone is NOT enough — we must
        //    actually own the target service_id, otherwise we'd loopback when we
        //    should be connecting to a remote node.
        {
            let is_local_service = self.keypair_for_service(&service_id).await.is_some();
            let local =
                is_local_service && self.has_matching_listener(service_id, mode, port).await;
            if local {
                log::info!(
                    "circuit_connect: loopback to local listener {:?} mode {:?} port {}",
                    service_id,
                    mode,
                    port
                );
                let (client_tx, server_rx) = mpsc::channel::<Vec<u8>>(256);
                let (server_tx, client_rx) = mpsc::channel::<Vec<u8>>(256);
                let conn_id = {
                    let oc = self.circuits.outbound.lock().await;
                    self.circuits
                        .table
                        .lock()
                        .await
                        .alloc_id(true, |id| oc.contains_key(&id))
                };

                let server_conn = tarnet_api::service::Connection::new(
                    service_id,
                    mode,
                    port.to_string(),
                    conn_id,
                    server_tx,
                    server_rx,
                );
                match self
                    .dispatch_incoming_connection(service_id, mode, port, server_conn)
                    .await
                {
                    ListenerDispatch::Enqueued => {}
                    ListenerDispatch::NoListener => {
                        return Err(Error::Protocol("no listener for local service".into()));
                    }
                    ListenerDispatch::QueueFull => {
                        return Err(Error::Protocol("listener queue full".into()));
                    }
                }

                // Return client-side Connection
                return Ok(tarnet_api::service::Connection::new(
                    service_id,
                    mode,
                    port.to_string(),
                    conn_id,
                    client_tx,
                    client_rx,
                ));
            }
        }

        let connected = self.connected_peers().await;
        log::info!(
            "circuit_connect: service={:?} mode={:?} port={} connected_peers={}",
            service_id,
            mode,
            port,
            connected.len()
        );

        // Look up outbound_hops for the source identity.
        let min_hops = if let Some(src_sid) = &source_identity {
            let is = self.identity_store.lock().await;
            is.get_by_service_id(src_sid)
                .map(|id| id.outbound_hops as usize)
                .unwrap_or(1)
        } else {
            1
        };

        // 1. Explicit peer hint — build circuit via DV routing.
        if let Some(dest_peer) = dest_peer {
            log::info!("circuit_connect: trying explicit peer hint {:?}", dest_peer);
            if let Some(conn) = self
                .try_connect_to_peer(service_id, mode, port, &dest_peer, min_hops, &connected)
                .await
            {
                return Ok(conn);
            }
        }

        // 2. Resolve ServiceId via TNS peer record (public services).
        //    The peer record is signed by the service's signing key and verified
        //    against the expected ServiceId — forged records are rejected.
        let peer_resolution = crate::tns::resolve(self, service_id, "peer").await;
        if let crate::tns::TnsResolution::Records(records) = &peer_resolution {
            for record in records {
                if let Ok(peer) = crate::tns::verify_peer_record(record, &service_id) {
                    // Already tried, and waited for, as the explicit hint.
                    if Some(peer) == dest_peer {
                        continue;
                    }
                    let dest_peer = peer;
                    log::info!(
                        "circuit_connect: TNS peer record resolved {:?} → {:?}",
                        service_id,
                        dest_peer
                    );
                    if let Some(conn) = self
                        .try_connect_to_peer(
                            service_id, mode, port, &dest_peer, min_hops, &connected,
                        )
                        .await
                    {
                        return Ok(conn);
                    }
                } else {
                    log::warn!(
                        "circuit_connect: TNS peer record for {:?} failed verification, ignoring",
                        service_id
                    );
                }
            }
        }

        // 3. Rendezvous via TNS intro points (hidden services).
        let resolution = crate::tns::resolve(self, service_id, "intro").await;
        if let crate::tns::TnsResolution::Records(records) = resolution {
            let intro_points: Vec<_> = records
                .iter()
                .filter_map(|r| match r {
                    crate::tns::TnsRecord::IntroductionPoint {
                        relay_peer_id,
                        kem_algo,
                        kem_pubkey,
                    } => Some((*relay_peer_id, *kem_algo, kem_pubkey.clone())),
                    _ => None,
                })
                .collect();

            if !intro_points.is_empty() {
                return self
                    .connect_via_rendezvous(service_id, mode, port, &intro_points, min_hops)
                    .await;
            }
        }

        Err(Error::Protocol(
            "cannot reach service: no reachable peer hosts this ServiceId and no intro points found".into(),
        ))
    }

    /// Try to build a circuit to `dest_peer` and establish a stream connection.
    /// Returns `Some(Connection)` on success, `None` if all attempts failed.
    async fn try_connect_to_peer(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        dest_peer: &PeerId,
        min_hops: usize,
        connected: &[PeerId],
    ) -> Option<tarnet_api::service::Connection> {
        let deadline = tokio::time::Instant::now() + CONNECT_PERSIST;
        let mut gap = CONNECT_ROUND_GAP;
        // Waiting is worth it for a destination we knew how to reach when we
        // started (routes may be reconverging after a link died), and for
        // any destination while our table is not a complete view: its
        // address may not be resolvable yet, or a lookup may have been
        // lost. In a small network a destination we have no route to
        // doesn't exist.
        let known = connected.contains(dest_peer)
            || self.route_cost(dest_peer).await.is_some()
            || !self.routing_table.lock().await.is_complete()
            || !self.relay_hints(dest_peer).await.is_empty();
        loop {
            let (waypoints, first_hops) =
                self.plan_circuit_path(dest_peer, min_hops, connected).await;

            // No route: bounded route search (RouteSearch) is not implemented yet.
            if first_hops.is_empty() {
                log::info!("try_connect_to_peer: no route to {:?}", dest_peer);
                return None;
            }

            let built = match self
                .try_build_with_hops(service_id, mode, port, dest_peer, &waypoints, &first_hops)
                .await
            {
                Ok(conn) => return Some(conn),
                Err(built) => built,
            };
            // A stale address may be why: look it up afresh next time.
            self.forget_address(dest_peer).await;
            // A circuit was built but the stream failed: the service said
            // no, which waiting won't change.
            if built || !known || tokio::time::Instant::now() + gap >= deadline {
                return None;
            }
            log::info!(
                "try_connect_to_peer: no circuit to {:?} yet, trying again in {:?}",
                dest_peer,
                gap
            );
            tokio::time::sleep(crate::types::jittered(gap)).await;
            gap = (gap * 2).min(CONNECT_ROUND_GAP_MAX);
        }
    }

    /// Try each first_hop candidate to build a circuit and establish a connection.
    /// On failure, says whether any circuit was built (the stream failed,
    /// not the path).
    ///
    /// The whole sweep is retried with backoff: mid-path relays forward
    /// EXTEND/EXTENDED as opaque cells they may drop under congestion, so a
    /// build failure is often transient. Each retry starts a fresh circuit
    /// (new circuit_id, new KEM offers), which keeps the protocol free of
    /// duplicate-EXTEND idempotency concerns.
    async fn try_build_with_hops(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        dest_peer: &PeerId,
        waypoints: &[PeerId],
        first_hops: &[PeerId],
    ) -> std::result::Result<tarnet_api::service::Connection, bool> {
        const BUILD_ATTEMPTS: u32 = 3;
        let mut built = false;
        for attempt in 0..BUILD_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(200 << attempt)).await;
            }
            for first_hop in first_hops {
                match self.build_circuit(*first_hop, waypoints.to_vec()).await {
                    Ok(circuit_id) => {
                        built = true;
                        match self
                            .setup_circuit_connection(service_id, mode, port, circuit_id)
                            .await
                        {
                            Ok(conn) => return Ok(conn),
                            Err(e) => {
                                log::info!(
                                    "circuit_connect: StreamBegin to {:?} failed: {}",
                                    dest_peer,
                                    e
                                );
                                let _ = self.destroy_circuit(circuit_id).await;
                            }
                        }
                    }
                    Err(e) => {
                        log::info!(
                            "circuit_connect: build_circuit to {:?} failed (attempt {}): {}",
                            dest_peer,
                            attempt + 1,
                            e
                        );
                    }
                }
            }
        }
        Err(built)
    }

    /// Plan the full circuit path: choose waypoints and determine first hops,
    /// using a single routing table lock.
    ///
    /// `min_hops == 1`: waypoints = `[dest]` — DV routes directly.
    /// `min_hops > 1`: waypoints = `[random_peer, ..., dest]` — random intermediate
    /// waypoints add hops for privacy before reaching the destination.
    ///
    /// Returns `(waypoints, first_hops)` where first_hops are up to 3 candidate
    /// first hops for multipath diversity.
    async fn plan_circuit_path(
        &self,
        dest: &PeerId,
        min_hops: usize,
        connected: &[PeerId],
    ) -> (Vec<PeerId>, Vec<PeerId>) {
        // --- Choose waypoints ---
        let waypoints = if min_hops <= 1 {
            vec![*dest]
        } else {
            // Never fewer hops than asked for: a circuit that quietly
            // skips waypoints gives its user less privacy than they chose.
            let mut wps = self.pick_relays(min_hops - 1, &[*dest]).await;
            if wps.len() < min_hops - 1 {
                log::info!(
                    "plan_circuit_path: {} hops asked, only {} relays known",
                    min_hops,
                    wps.len()
                );
                return (vec![*dest], Vec::new());
            }
            wps.push(*dest);
            wps
        };
        // A sampled waypoint may lie beyond our table; its hints reach it.
        let hinted = self
            .next_hop_toward(
                &waypoints[0],
                &self.relay_hints(&waypoints[0]).await,
                &self.peer_id(),
            )
            .await;
        let rt = self.routing_table.lock().await;

        // --- Determine first hops ---
        let target = waypoints[0]; // first waypoint determines routing
        let first_hops = if connected.contains(&target) {
            // Target is a direct neighbor — use it as first hop
            vec![target]
        } else {
            let hops = rt.lookup_multi(&target, 3);
            let mut result: Vec<PeerId> =
                hops.into_iter().filter(|h| connected.contains(h)).collect();
            if result.is_empty() {
                result.extend(hinted);
            }
            if result.is_empty() {
                // Fallback: try routing to dest directly
                if connected.contains(dest) {
                    result.push(*dest);
                } else {
                    // Destination unknown — pick a random connected peer and
                    // let relay-decided routing figure it out hop-by-hop.
                    use rand::seq::SliceRandom;
                    let mut rng = rand::thread_rng();
                    let mut candidates: Vec<PeerId> = connected.to_vec();
                    candidates.shuffle(&mut rng);
                    if let Some(peer) = candidates.first() {
                        log::debug!(
                            "plan_circuit_path: no route to {:?}, using random first hop {:?}",
                            target,
                            peer,
                        );
                        result.push(*peer);
                    }
                }
            }
            result
        };

        drop(rt);
        (waypoints, first_hops)
    }

    /// Set up a Connection over an already-built circuit (sends STREAM_BEGIN, wires data channels).
    ///
    /// Uses TCP-style retransmission with exponential backoff and jitter:
    /// retries StreamBegin up to `MAX_STREAM_RETRIES` times if no response,
    /// because relay cells can be silently dropped under link congestion.
    async fn setup_circuit_connection(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        circuit_id: u32,
    ) -> Result<tarnet_api::service::Connection> {
        // A backend may send a greeting as soon as it accepts. Register the
        // receive channel before STREAM_BEGIN so that first DATA is buffered.
        let conn = self
            .circuit_connection(service_id, mode, port, circuit_id)
            .await;
        let stream_begin_payload = build_stream_begin_payload(&service_id, mode, port);
        self.wait_stream_connected(
            circuit_id,
            RelayCellCommand::StreamBegin,
            stream_begin_payload,
        )
        .await?;
        Ok(conn)
    }

    pub(super) async fn wait_stream_connected(
        &self,
        circuit_id: u32,
        command: RelayCellCommand,
        payload: Vec<u8>,
    ) -> Result<()> {
        const MAX_STREAM_RETRIES: u32 = 5;
        const INITIAL_TIMEOUT_MS: u64 = 1000;
        let mut timeout_ms = INITIAL_TIMEOUT_MS;

        for attempt in 0..=MAX_STREAM_RETRIES {
            // Register a fresh pending connect each attempt.
            let (connect_tx, connect_rx) = oneshot::channel::<bool>();
            self.endpoints
                .pending_connects
                .lock()
                .await
                .insert(circuit_id, connect_tx);

            // Send STREAM_BEGIN.
            {
                let stream_begin = RelayCell {
                    command,
                    stream_id: 0,
                    data: payload.clone(),
                };
                let mut circuits = self.circuits.outbound.lock().await;
                let circuit = match circuits.get_mut(&circuit_id) {
                    Some(c) => c,
                    None => return Err(Error::Protocol("circuit gone during stream setup".into())),
                };
                let (fh, cid, cell) = circuit.send_relay_cell(&stream_begin);
                drop(circuits);

                let encoded = encode_circuit_relay_cell(cid, &cell);
                self.send_to_peer_critical(&fh, &encoded).await?;
            }

            // Wait for StreamConnected or StreamRefused.
            match tokio::time::timeout(Duration::from_millis(timeout_ms), connect_rx).await {
                Ok(Ok(true)) => break, // accepted
                Ok(Ok(false)) => {
                    return Err(Error::Protocol(
                        "stream refused: remote is not listening on this ServiceId/port".into(),
                    ));
                }
                Ok(Err(_)) => {
                    return Err(Error::Protocol("stream connect channel dropped".into()));
                }
                Err(_) => {
                    // Timeout — retransmit with exponential backoff + jitter.
                    if attempt == MAX_STREAM_RETRIES {
                        self.endpoints
                            .pending_connects
                            .lock()
                            .await
                            .remove(&circuit_id);
                        return Err(Error::Protocol(
                            "stream connect timeout after retries".into(),
                        ));
                    }
                    log::debug!(
                        "StreamBegin timeout on circuit {} (attempt {}/{}), retrying",
                        circuit_id,
                        attempt + 1,
                        MAX_STREAM_RETRIES,
                    );
                    // Exponential backoff: 1s, 2s, 4s, 8s, 16s
                    timeout_ms *= 2;
                    // Add jitter: ±25% of current timeout
                    let jitter = (timeout_ms / 4) as i64;
                    let jitter_val =
                        (rand::random::<u64>() % (jitter as u64 * 2 + 1)) as i64 - jitter;
                    timeout_ms = (timeout_ms as i64 + jitter_val).max(500) as u64;
                }
            }
        }

        Ok(())
    }

    /// Wire an application connection to an outbound circuit. Shared by direct
    /// streams and both sides of a bridged hidden-service circuit.
    pub(super) async fn circuit_connection(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        circuit_id: u32,
    ) -> Connection {
        let peer = self
            .circuits
            .outbound
            .lock()
            .await
            .get(&circuit_id)
            .map(|c| c.first_hop)
            .unwrap_or(self.peer_id());
        self.stream_connection(
            service_id,
            mode,
            port,
            CircuitKey {
                circuit_id,
                from_peer: peer,
            },
            true,
        )
        .await
    }
}
