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
        OutboundCircuit {
            first_hop_circuit_id: 7,
            first_hop: peer,
            hop_keys: vec![HopKey::from_shared_secret(&[42; 32])],
            state: CircuitPhase::Ready,
            waypoints: vec![peer],
            last_activity: Instant::now(),
            forward_nonce: 0,
            nonce_domain: rand::random(),
            backward_replay: CellReplayWindow::new(),
            assembler: Default::default(),
        }
    }

    #[test]
    fn backward_origins_have_distinct_nonces_and_replays_are_rejected() {
        let mut outbound = circuit(PeerId([1; 32]));
        let first = outbound.hop_keys[0].clone();
        let last = HopKey::from_shared_secret(&[43; 32]);
        outbound.hop_keys.push(last.clone());
        let decode = |encoded: Vec<u8>| -> [u8; CELL_SIZE] {
            CircuitRelayMsg::from_bytes(&WireMessage::decode(&encoded).unwrap().payload)
                .unwrap()
                .data
                .try_into()
                .unwrap()
        };
        let first_reply = decode(encrypt_backward_cell(
            first.backward_key,
            first.backward_digest,
            first.nonce_prefix,
            0,
            7,
            RelayCellCommand::Extended,
            b"first hop",
        ));
        let mut corrupted = first_reply;
        corrupted[CELL_SIZE - 1] ^= 1;
        assert!(outbound.recv_from_hop(&mut corrupted, 0).is_err());
        assert_eq!(
            outbound
                .recv_from_hop(&mut first_reply.clone(), 0)
                .unwrap()
                .data,
            b"first hop"
        );

        let mut last_reply = decode(encrypt_backward_cell(
            last.backward_key,
            last.backward_digest,
            last.nonce_prefix,
            0,
            7,
            RelayCellCommand::Data,
            b"last hop",
        ));
        let mut relay = HopCrypto {
            key: first.backward_key,
            digest_key: first.backward_digest,
            nonce_prefix: first.nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: CellReplayWindow::new(),
        };
        assert!(relay.process_cell(&mut last_reply));
        assert_ne!(cell_nonce(&first_reply), cell_nonce(&last_reply));
        let replay = last_reply;
        assert_eq!(
            outbound.recv_relay_cell(&mut last_reply).unwrap().data,
            b"last hop"
        );
        assert!(outbound.recv_relay_cell(&mut replay.clone()).is_err());
        // Adding an origin must not reset the first origin's replay protection.
        assert!(outbound.recv_from_hop(&mut first_reply.clone(), 0).is_err());
    }

    #[test]
    fn forward_mac_failure_does_not_consume_nonce_and_replay_is_rejected() {
        let hop = HopKey::from_shared_secret(&[42; 32]);
        let body = write_cell_body(RelayCellCommand::Data, 0, b"payload", &hop.forward_digest);
        let mut cell = [0; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        set_cell_nonce(&mut cell, &[7; 16], 0);
        hop.encrypt_forward(&mut cell);
        let mut decrypt = HopCrypto {
            key: hop.forward_key,
            digest_key: hop.forward_digest,
            nonce_prefix: hop.nonce_prefix,
            op: CryptoOp::Decrypt,
            replay: CellReplayWindow::new(),
        };
        let mut bad = cell;
        bad[CELL_SIZE - 1] ^= 1;
        assert!(!decrypt.process_cell(&mut bad));
        assert!(decrypt.process_cell(&mut cell.clone()));
        assert!(!decrypt.process_cell(&mut cell));
    }

    #[test]
    fn nonce_domains_change_at_each_onion_hop() {
        let hops: Vec<_> = (1..=3)
            .map(|n| HopKey::from_shared_secret(&[n; 32]))
            .collect();
        let mut cell = [0; CELL_SIZE];
        set_cell_nonce(&mut cell, &[9; 16], 0);
        let raw = cell_nonce(&cell);
        let mut domains = std::collections::HashSet::new();
        for hop in hops.iter().rev() {
            hop.encrypt_forward(&mut cell);
            assert!(domains.insert(cell_nonce(&cell)));
            assert_ne!(cell_nonce(&cell), raw);
        }
        for hop in &hops {
            let mut crypto = HopCrypto {
                key: hop.forward_key,
                digest_key: hop.forward_digest,
                nonce_prefix: hop.nonce_prefix,
                op: CryptoOp::Decrypt,
                replay: CellReplayWindow::new(),
            };
            assert!(crypto.process_cell(&mut cell));
        }
        assert_eq!(cell_nonce(&cell), raw);
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
                &[]
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

/// Encrypt a relay cell for backward transmission from an endpoint to the circuit initiator.
/// Returns the encoded wire message bytes ready to send.
pub(super) fn encrypt_backward_cell(
    bwd_key: [u8; 32],
    bwd_digest: [u8; 32],
    nonce_prefix: [u8; 16],
    nonce: u64,
    circuit_id: u32,
    command: RelayCellCommand,
    data: &[u8],
) -> Vec<u8> {
    let body = write_cell_body(command, 0, data, &bwd_digest);
    encrypt_backward_body(bwd_key, bwd_digest, nonce_prefix, nonce, circuit_id, body)
}

/// Encrypt one piece of a (possibly multi-cell) backward relay message.
fn encrypt_backward_piece(
    bwd_key: [u8; 32],
    bwd_digest: [u8; 32],
    nonce_prefix: [u8; 16],
    nonce: u64,
    circuit_id: u32,
    piece: &RelayPiece,
) -> Vec<u8> {
    let body = piece.to_cell(&bwd_digest);
    encrypt_backward_body(bwd_key, bwd_digest, nonce_prefix, nonce, circuit_id, body)
}

fn encrypt_backward_body(
    bwd_key: [u8; 32],
    bwd_digest: [u8; 32],
    nonce_prefix: [u8; 16],
    nonce: u64,
    circuit_id: u32,
    body: [u8; CELL_BODY_SIZE],
) -> Vec<u8> {
    let mut cell = [0u8; CELL_SIZE];
    cell[..CELL_BODY_SIZE].copy_from_slice(&body);
    set_cell_nonce(&mut cell, &backward_nonce_domain(&nonce_prefix), nonce);
    let mut crypto = HopCrypto {
        key: bwd_key,
        digest_key: bwd_digest,
        nonce_prefix,
        op: CryptoOp::Encrypt,
        replay: CellReplayWindow::new(),
    };
    crypto.process_cell(&mut cell);

    encode_circuit_relay_cell(circuit_id, &cell)
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
        let cell_data = &payload[4..];

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

                // Build the encoded forward message while still holding the table lock
                // (we need mutable crypto), then release the lock before I/O.
                // encode_circuit_relay_cell avoids the two extra Vec allocations that
                // cell.to_vec() + CircuitRelayMsg::to_wire().encode() would produce.
                // Forward relay: peel one onion layer and pass to the next hop.
                // MAC verification is NOT possible here — the outermost hop MAC
                // was already consumed by the previous relay (or by us when this
                // was still an Endpoint entry).  Inner hop MACs are overwritten
                // during onion wrapping, so only the outermost layer's MAC is
                // ever verifiable.  Link-layer integrity protects the hop.
                let encoded = if let Some(ref mut hop_crypto) = crypto {
                    if cell_data.len() == CELL_SIZE {
                        let mut cell = [0u8; CELL_SIZE];
                        cell.copy_from_slice(cell_data);
                        if hop_crypto.op == CryptoOp::Encrypt
                            && cell_nonce(&cell)[..16]
                                == backward_nonce_domain(&hop_crypto.nonce_prefix)
                        {
                            return Err(Error::Crypto(
                                "relay cannot reuse its own backward nonce domain".into(),
                            ));
                        }
                        if !hop_crypto.process_cell(&mut cell) {
                            return Ok(());
                        }
                        // A forwarding hop still recognises TRUNCATE addressed
                        // to it: the initiator uses it to undo an EXTEND whose
                        // reply never came. Any other cell fails our digest.
                        if hop_crypto.op == CryptoOp::Decrypt {
                            let body: &[u8; CELL_BODY_SIZE] =
                                cell[..CELL_BODY_SIZE].try_into().unwrap();
                            if let Ok(piece) = RelayPiece::from_cell(body, &hop_crypto.digest_key) {
                                if piece.command == RelayCellCommand::Truncate {
                                    drop(table);
                                    return self.handle_truncate(from, circuit_id).await;
                                }
                            }
                        }
                        encode_circuit_relay_cell(next_id, &cell)
                    } else {
                        encode_circuit_relay_cell(next_id, cell_data)
                    }
                } else {
                    encode_circuit_relay_cell(next_id, cell_data)
                };
                drop(table);

                self.stats.record_relay(encoded.len() as u64);
                self.send_to_peer(&next_hop, &encoded).await
            }
            Some(CircuitAction::Endpoint { crypto, .. }) => {
                // Apply onion layer decryption if present.
                // Decrypt into a stack buffer to avoid a heap allocation.
                let mut cell_buf = [0u8; CELL_SIZE];
                let decrypted: &[u8] = if let Some(ref mut hop_crypto) = crypto {
                    if cell_data.len() == CELL_SIZE {
                        cell_buf.copy_from_slice(cell_data);
                        // In multi-hop circuits, the cell-level MAC is only
                        // valid for the outermost layer (already verified by the
                        // first relay). The relay cell's internal digest provides
                        // integrity at the endpoint, so we don't bail on MAC failure.
                        if !hop_crypto.process_cell(&mut cell_buf) {
                            return Ok(());
                        }
                        &cell_buf
                    } else {
                        cell_data
                    }
                } else {
                    cell_data
                };
                drop(table);

                self.handle_endpoint_relay_cell(from, circuit_id, decrypted)
                    .await
            }
            None => {
                drop(table);

                // Check if this is a backward cell for an outbound circuit we initiated.
                let mut circuits = self.circuits.outbound.lock().await;
                if let Some(circuit) = circuits.get_mut(&circuit_id) {
                    if from == circuit.first_hop && cell_data.len() == CELL_SIZE {
                        let mut cell = [0u8; CELL_SIZE];
                        cell.copy_from_slice(cell_data);
                        let decoded = circuit.recv_relay_message(&mut cell);
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
                                // INTRODUCE forwarded to us (the hidden service) through our
                                // intro point circuit.
                                self.handle_introduce_at_service(circuit_id, &relay_cell.data)
                                    .await;
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

    /// Handle a fully-decrypted relay cell at the circuit endpoint.
    async fn handle_endpoint_relay_cell(
        &self,
        from: PeerId,
        circuit_id: u32,
        cell_data: &[u8],
    ) -> Result<()> {
        if cell_data.len() != CELL_SIZE {
            log::debug!(
                "Endpoint relay cell wrong size: {} (expected {})",
                cell_data.len(),
                CELL_SIZE
            );
            return Ok(());
        }

        let key = CircuitKey {
            circuit_id,
            from_peer: from,
        };
        let body: &[u8; CELL_BODY_SIZE] = cell_data[..CELL_BODY_SIZE].try_into().unwrap();
        // Pieces of a larger message are held on the circuit entry, so they
        // go away with the circuit.
        let relay_cell = {
            let mut table = self.circuits.table.lock().await;
            let Some(CircuitAction::Endpoint {
                crypto: Some(crypto),
                assembler,
                ..
            }) = table.lookup_mut(&key)
            else {
                log::debug!("No endpoint crypto for circuit_id={}", circuit_id);
                return Ok(());
            };
            let piece = match RelayPiece::from_cell(body, &crypto.digest_key) {
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
            let (bwd_key, bwd_digest, nonce_prefix, nonce) = self
                .get_hop_backward_crypto(circuit_id, from)
                .await
                .ok_or_else(|| Error::Protocol("no backward keys for circuit".into()))?;
            let encoded = encrypt_backward_piece(
                bwd_key,
                bwd_digest,
                nonce_prefix,
                nonce,
                circuit_id,
                &piece,
            );
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
        let downstream = {
            let mut table = self.circuits.table.lock().await;
            match table.lookup(&key).cloned() {
                Some(CircuitAction::Forward {
                    next_hop,
                    next_circuit_id,
                    crypto: Some(crypto),
                }) if crypto.op == CryptoOp::Decrypt => {
                    table.remove(&CircuitKey {
                        circuit_id: next_circuit_id,
                        from_peer: next_hop,
                    });
                    table.insert(
                        key,
                        CircuitAction::Endpoint {
                            assembler: Default::default(),
                            origin_hop: from,
                            crypto: Some(crypto),
                        },
                    );
                    Some((next_hop, next_circuit_id))
                }
                Some(CircuitAction::Endpoint { .. }) => None,
                _ => return Ok(()),
            }
        };
        if let Some((next_hop, next_circuit_id)) = downstream {
            log::debug!(
                "TRUNCATE on circuit_id={} from {:?}: dropping leg to {:?}",
                circuit_id,
                from,
                next_hop
            );
            self.circuits.relay_extend_pending.lock().await.remove(&CircuitKey {
                circuit_id: next_circuit_id,
                from_peer: next_hop,
            });
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

        if !self.has_matching_listener(service_id, mode, &port).await {
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

    /// Handle an EXTEND relay cell at a relay that is the current circuit endpoint.
    /// The relay forwards a CircuitCreate to the next hop and changes its own entry
    /// from Endpoint to Forward. The relay does NOT do a DH — the DH is between
    /// the circuit initiator and the target hop.
    async fn handle_extend_at_relay(
        &self,
        from: PeerId,
        inbound_circuit_id: u32,
        extend_data: &[u8],
    ) -> Result<()> {
        let ExtendRequest {
            kem_algo,
            eph_pk: initiator_ephemeral,
            destination,
            hints: _,
        } = parse_extend_payload(extend_data)?;

        // DV routing: if destination is our direct neighbor, extend there (reached).
        // Otherwise, look up our routing table for the best next_hop.
        let (target, reached) = {
            let links = self.links.lock().await;
            if links.contains_key(&destination) {
                (destination, true)
            } else {
                drop(links);
                let rt = self.routing_table.lock().await;
                match rt.lookup(&destination) {
                    Some(route) => {
                        let nh = route.next_hop;
                        drop(rt);
                        let links = self.links.lock().await;
                        if links.contains_key(&nh) {
                            (nh, false)
                        } else {
                            log::warn!(
                                "EXTEND: next_hop {:?} for destination {:?} has no link",
                                nh,
                                destination
                            );
                            drop(links);
                            self.send_endpoint_relay_cell(
                                from,
                                inbound_circuit_id,
                                RelayCellCommand::Extended,
                                &[],
                            )
                            .await
                            .ok();
                            return Ok(());
                        }
                    }
                    None => {
                        log::warn!(
                            "EXTEND: no route to {:?}, sending error EXTENDED back",
                            destination
                        );
                        drop(rt);
                        self.send_endpoint_relay_cell(
                            from,
                            inbound_circuit_id,
                            RelayCellCommand::Extended,
                            &[],
                        )
                        .await
                        .ok();
                        return Ok(());
                    }
                }
            }
        };

        let next_hop = target;
        let we_initiated_next = {
            let links = self.links.lock().await;
            links
                .get(&next_hop)
                .map(|l| l.is_initiator())
                .unwrap_or(true)
        };

        // Reserve IDs in the same lock order as build_circuit and CREATE.
        let reserved = self.circuits.pending_create_peers.lock().await;
        let outbound = self.circuits.outbound.lock().await;
        // Get the existing Endpoint crypto (our layer's crypto from hop 1 setup).
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

        // Allocate outbound circuit ID for the new leg.
        let outbound_id = table.alloc_id(we_initiated_next, |id| {
            outbound.contains_key(&id) || reserved.contains_key(&id)
        });

        // Build backward crypto for the Forward entry.
        // With explicit nonces in the cell, the relay reads the nonce from
        // the cell trailer — no per-relay counter needed.
        let bwd_crypto = {
            let map = self.circuits.hop_backward_keys.lock().await;
            map.get(&(inbound_circuit_id, from))
                .map(|&(key, digest_key, nonce_prefix, _)| HopCrypto {
                    key,
                    digest_key,
                    nonce_prefix,
                    op: CryptoOp::Encrypt,
                    replay: CellReplayWindow::new(),
                })
        };

        // Change Endpoint → Forward (keep existing decrypt crypto for forward direction)
        table.insert(
            inbound_key,
            CircuitAction::Forward {
                next_hop,
                next_circuit_id: outbound_id,
                crypto: existing_crypto,
            },
        );

        // Backward entry: cells from next_hop → encrypt our layer, forward to upstream
        table.insert(
            CircuitKey {
                circuit_id: outbound_id,
                from_peer: next_hop,
            },
            CircuitAction::Forward {
                next_hop: from,
                next_circuit_id: inbound_circuit_id,
                crypto: bwd_crypto,
            },
        );
        drop(table);

        drop(outbound);
        drop(reserved);
        // Remember this pending extend so when CircuitCreated arrives from next_hop,
        // we can route the EXTENDED reply back.
        self.circuits.relay_extend_pending.lock().await.insert(
            CircuitKey {
                circuit_id: outbound_id,
                from_peer: next_hop,
            },
            (from, inbound_circuit_id, reached, Instant::now()),
        );

        // Send CircuitCreate to next_hop with algo + initiator's ephemeral pubkey.
        let mut create_payload = Vec::with_capacity(1 + initiator_ephemeral.len());
        create_payload.push(kem_algo);
        create_payload.extend_from_slice(&initiator_ephemeral);
        let create = CircuitCreateMsg {
            circuit_id: outbound_id,
            encrypted_payload: create_payload,
        };
        self.send_to_peer_critical(&next_hop, &create.to_wire().encode())
            .await
    }

    /// Handle CircuitCreate — a peer wants us to be a hop in a circuit.
    /// In telescoping construction, the CREATE recipient always installs an Endpoint entry.
    /// Extension to further hops is done via EXTEND relay cells.
    pub(super) async fn handle_circuit_create(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = CircuitCreateMsg::from_bytes(payload)?;
        log::debug!(
            "CircuitCreate from {:?}: circuit_id={}, payload={} bytes",
            from,
            msg.circuit_id,
            msg.encrypted_payload.len()
        );

        if msg.encrypted_payload.len() < 2 {
            return Err(Error::Wire("CircuitCreate payload too short".into()));
        }

        // A resend of a CREATE we already answered: the initiator never saw our
        // reply. Answer identically; fresh keys would not match theirs.
        let create_hash = *blake3::hash(&msg.encrypted_payload).as_bytes();
        let key = CircuitKey {
            circuit_id: msg.circuit_id,
            from_peer: from,
        };
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

        // Parse KEM algo and initiator's ephemeral public key.
        let offer_algo = tarnet_api::types::KemAlgo::from_u8(msg.encrypted_payload[0])
            .map_err(|e| Error::Wire(format!("CircuitCreate unknown KEM algo: {}", e)))?;
        let initiator_pubkey = &msg.encrypted_payload[1..];

        // Accept the KEM offer: encapsulate to the initiator's ephemeral pubkey.
        let (shared_bytes, reply_ciphertext) = kex_accept(offer_algo, initiator_pubkey)?;

        let hop_keys = derive_hop_keys(&shared_bytes);

        // Install Endpoint entry with forward (decrypt) crypto.
        // Also store backward crypto info for use when this entry becomes a Forward
        // entry (if an EXTEND comes later).
        let reserved = self.circuits.pending_create_peers.lock().await;
        let outbound = self.circuits.outbound.lock().await;
        let mut table = self.circuits.table.lock().await;
        if table
            .lookup(&CircuitKey {
                circuit_id: msg.circuit_id,
                from_peer: from,
            })
            .is_some()
            || outbound
                .get(&msg.circuit_id)
                .is_some_and(|c| c.first_hop == from)
            || reserved.get(&msg.circuit_id) == Some(&from)
        {
            return Err(Error::Protocol(
                "circuit ID already in use on this link".into(),
            ));
        }
        table.insert(
            CircuitKey {
                circuit_id: msg.circuit_id,
                from_peer: from,
            },
            CircuitAction::Endpoint {
                assembler: Default::default(),
                origin_hop: from,
                crypto: Some(HopCrypto {
                    key: hop_keys.forward_key,
                    digest_key: hop_keys.forward_digest,
                    nonce_prefix: hop_keys.nonce_prefix,
                    op: CryptoOp::Decrypt,
                    replay: CellReplayWindow::new(),
                }),
            },
        );
        drop(table);

        drop(outbound);
        drop(reserved);
        // Store backward crypto keying material for later EXTEND handling.
        // We need this when converting Endpoint → Forward.
        self.store_hop_backward_crypto(
            msg.circuit_id,
            from,
            hop_keys.backward_key,
            hop_keys.backward_digest,
            hop_keys.nonce_prefix,
        )
        .await;

        // Reply with CircuitCreated containing the KEM ciphertext (TLV format).
        let reply = CircuitCreatedMsg {
            circuit_id: msg.circuit_id,
            encrypted_reply: build_extended_payload(offer_algo as u8, &reply_ciphertext),
        };
        let reply = reply.to_wire().encode();
        {
            let mut cache = self.circuits.created_replies.lock().await;
            let now = Instant::now();
            cache.retain(|_, (_, _, at)| now.duration_since(*at) < CREATED_REPLY_TTL);
            cache.insert(key, (create_hash, reply.clone(), now));
        }
        self.send_to_peer_critical(&from, &reply).await
    }

    /// Handle CircuitCreated — confirmation that a circuit hop was set up.
    pub(super) async fn handle_circuit_created(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = CircuitCreatedMsg::from_bytes(payload)?;
        log::debug!(
            "CircuitCreated from {:?}: circuit_id={}",
            from,
            msg.circuit_id,
        );

        // Check if this is for a relay extend we're forwarding.
        let relay_pending = {
            let mut pending = self.circuits.relay_extend_pending.lock().await;
            let expected = self
                .circuits
                .table
                .lock()
                .await
                .lookup(&CircuitKey {
                    circuit_id: msg.circuit_id,
                    from_peer: from,
                })
                .is_some();
            if expected {
                pending.remove(&CircuitKey {
                    circuit_id: msg.circuit_id,
                    from_peer: from,
                })
            } else {
                None
            }
        };

        if let Some((inbound_from, inbound_circuit_id, reached, _created)) = relay_pending {
            // We're a relay that forwarded a CREATE on behalf of an EXTEND.
            // Wrap the CircuitCreated reply as an EXTENDED relay cell and send
            // it back through the inbound circuit.

            // The backward crypto for the inbound circuit must still exist.
            let bwd_info = self
                .circuits
                .hop_backward_keys
                .lock()
                .await
                .contains_key(&(inbound_circuit_id, inbound_from));

            // The CircuitCreated encrypted_reply already has the flags byte
            // (from build_extended_payload). Set the reached flag if this
            // extend landed on the requested destination.
            let mut reply_data = msg.encrypted_reply;
            if reached && !reply_data.is_empty() {
                reply_data[0] |= EXTENDED_FLAG_REACHED;
            }
            if !bwd_info {
                return Err(Error::Protocol("backward circuit gone".into()));
            }
            return self
                .send_endpoint_relay_cell(
                    inbound_from,
                    inbound_circuit_id,
                    RelayCellCommand::Extended,
                    &reply_data,
                )
                .await;
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
            .retain(|id, (peer, cid, _, _)| {
                *id != key && !(*peer == from && *cid == msg.circuit_id)
            });
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
        let service_id = parse_intro_register_payload(payload)?;
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
        let reply = RelayCell {
            command: RelayCellCommand::IntroRegistered,
            stream_id: 0,
            data: vec![],
        };
        // Send backward relay cell
        let bwd_info = self.get_hop_backward_crypto(circuit_id, from).await;
        let (bwd_key, bwd_digest, nonce_prefix, nonce) =
            bwd_info.ok_or_else(|| Error::Protocol("backward circuit gone".into()))?;
        let body = reply.to_cell(&bwd_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        set_cell_nonce(&mut cell, &backward_nonce_domain(&nonce_prefix), nonce);
        let mut crypto = HopCrypto {
            key: bwd_key,
            digest_key: bwd_digest,
            nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: CellReplayWindow::new(),
        };
        crypto.process_cell(&mut cell);
        let encoded = encode_circuit_relay_cell(circuit_id, &cell);
        self.send_to_peer_critical(&from, &encoded).await
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
        let (target_sid, sealed) = match parse_introduce_cell(payload) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[B-INTRO] malformed INTRODUCE cell: {}", e);
                return Ok(());
            }
        };

        // Look up the registration for the requested service. The INTRODUCE
        // arrives on the client's circuit to this intro point; we forward it on
        // the matching service's circuit.
        let regs = self.hidden.intro_registrations.lock().await;
        let service_entry = regs.iter().find(|(_, (sid, _))| *sid == target_sid);
        let (service_circuit_id, service_from) = match service_entry {
            Some((&cid, (_sid, peer))) => (cid, *peer),
            None => {
                log::warn!(
                    "[B-INTRO] No service {:?} registered at this intro point",
                    target_sid
                );
                return Ok(());
            }
        };
        drop(regs);

        // Send the (still-sealed) INTRODUCE data as a relay cell to the service.
        let _ = self
            .send_endpoint_relay_cell(
                service_from,
                service_circuit_id.circuit_id,
                RelayCellCommand::Introduce,
                sealed,
            )
            .await;

        // Send IntroduceAck back to the client
        let ack = RelayCell {
            command: RelayCellCommand::IntroduceAck,
            stream_id: 0,
            data: vec![],
        };
        let bwd_info = self.get_hop_backward_crypto(circuit_id, from).await;
        let (bwd_key, bwd_digest, nonce_prefix, nonce) =
            bwd_info.ok_or_else(|| Error::Protocol("backward circuit gone".into()))?;
        let body = ack.to_cell(&bwd_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        set_cell_nonce(&mut cell, &backward_nonce_domain(&nonce_prefix), nonce);
        let mut crypto = HopCrypto {
            key: bwd_key,
            digest_key: bwd_digest,
            nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: CellReplayWindow::new(),
        };
        crypto.process_cell(&mut cell);
        let encoded = encode_circuit_relay_cell(circuit_id, &cell);
        self.send_to_peer_critical(&from, &encoded).await
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
        let cookie = parse_rendezvous_join_payload(payload)?;
        log::info!(
            "RendezvousJoin: cookie lookup on circuit_id={} from {:?}",
            circuit_id,
            from,
        );

        let mut table = self.hidden.rendezvous.lock().await;
        let entry = match table.get_mut(&cookie) {
            Some(e) => e,
            None => {
                log::debug!("RendezvousJoin: unknown cookie");
                return Ok(());
            }
        };

        entry.service_circuit_id = Some(circuit_id);
        entry.service_from = Some(from);
        let client_circuit_id = entry.client_circuit_id;
        let client_from = entry.client_from;
        drop(table);

        // Install circuit table forwarding entries to bridge the two circuits.
        let mut ct = self.circuits.table.lock().await;
        ct.insert(
            CircuitKey {
                circuit_id: client_circuit_id,
                from_peer: client_from,
            },
            CircuitAction::Forward {
                next_hop: from,
                next_circuit_id: circuit_id,
                crypto: None,
            },
        );
        ct.insert(
            CircuitKey {
                circuit_id,
                from_peer: from,
            },
            CircuitAction::Forward {
                next_hop: client_from,
                next_circuit_id: client_circuit_id,
                crypto: None,
            },
        );
        drop(ct);

        // Send RendezvousJoined to client through client's circuit.
        let joined = RelayCell {
            command: RelayCellCommand::RendezvousJoined,
            stream_id: 0,
            data: vec![],
        };
        let bwd_info = self
            .get_hop_backward_crypto(client_circuit_id, client_from)
            .await;
        let (bwd_key, bwd_digest, nonce_prefix, nonce) =
            bwd_info.ok_or_else(|| Error::Protocol("backward circuit gone".into()))?;
        let body = joined.to_cell(&bwd_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        set_cell_nonce(&mut cell, &backward_nonce_domain(&nonce_prefix), nonce);
        let mut crypto = HopCrypto {
            key: bwd_key,
            digest_key: bwd_digest,
            nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: CellReplayWindow::new(),
        };
        crypto.process_cell(&mut cell);
        let encoded = encode_circuit_relay_cell(client_circuit_id, &cell);
        self.send_to_peer_critical(&client_from, &encoded)
            .await
    }

    async fn store_hop_backward_crypto(
        &self,
        circuit_id: u32,
        from_peer: PeerId,
        bwd_key: [u8; 32],
        bwd_digest: [u8; 32],
        nonce_prefix: [u8; 16],
    ) {
        self.circuits.hop_backward_keys.lock().await.insert(
            (circuit_id, from_peer),
            (bwd_key, bwd_digest, nonce_prefix, 0),
        );
    }

    /// Get backward crypto keys for a circuit hop, returning and incrementing the nonce.
    async fn get_hop_backward_crypto(
        &self,
        circuit_id: u32,
        from_peer: PeerId,
    ) -> Option<([u8; 32], [u8; 32], [u8; 16], u64)> {
        let mut map = self.circuits.hop_backward_keys.lock().await;
        let entry = map.get_mut(&(circuit_id, from_peer))?;
        let nonce = entry.3;
        entry.3 = entry.3.checked_add(1)?;
        Some((entry.0, entry.1, entry.2, nonce))
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
        let hops_built = circuit.hop_keys.len();
        let (first_hop, cid, cells) = circuit.send_relay_message(message)?;
        drop(circuits);
        for cell in &cells {
            let encoded = encode_circuit_relay_cell(cid, cell);
            self.send_to_peer_critical(&first_hop, &encoded).await?;
        }
        Ok(hops_built)
    }

    /// One EXTEND step toward `waypoint`. If the reply doesn't come in time,
    /// truncate back to the hops already built and try again, so a lost cell
    /// costs one step rather than the whole circuit.
    async fn extend_step(
        &self,
        circuit_id: u32,
        first_hop: PeerId,
        kem_algo: tarnet_api::types::KemAlgo,
        waypoint: &PeerId,
    ) -> Result<(KexOffer, Vec<u8>)> {
        for attempt in 1..=EXTEND_ATTEMPTS {
            let kex = KexOffer::new(kem_algo);
            let extend_cell = RelayCell {
                command: RelayCellCommand::Extend,
                stream_id: 0,
                data: build_extend_payload(kex.algo_byte(), &kex.pubkey_bytes(), waypoint, &[]),
            };

            // Register before sending: a fast EXTENDED reply must not be lost.
            let (tx, rx) = oneshot::channel();
            self.circuits
                .pending_extends
                .lock()
                .await
                .insert(circuit_id, tx);

            let hops_built = self.send_to_last_hop(circuit_id, &extend_cell).await?;
            // The reply carries a ciphertext about as large as the key.
            let timeout = self
                .extend_step_timeout(first_hop, hops_built, extend_cell.data.len() * 2)
                .await;

            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(data)) => return Ok((kex, data)),
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
        Err(Error::Protocol("circuit extend timed out".into()))
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

    pub async fn build_circuit(&self, first_hop: PeerId, waypoints: Vec<PeerId>) -> Result<u32> {
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

        // --- Hop 1: CircuitCreate directly to first hop ---
        let kem_algo = self.identity.identity.kem_algo();
        let kex = KexOffer::new(kem_algo);

        // CircuitCreate payload: kem_algo(1) || pubkey(variable).
        let mut create_payload = Vec::with_capacity(1 + kex.pubkey_bytes().len());
        create_payload.push(kex.algo_byte());
        create_payload.extend_from_slice(&kex.pubkey_bytes());

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
            let wait = resend_interval
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

        let (_reached, _reply_algo, hop_ciphertext) = parse_extended_payload(&reply)?;
        let shared_bytes = kex.complete(&hop_ciphertext)?;
        hop_keys.push(HopKey::from_shared_secret(&shared_bytes));

        log::debug!("Circuit hop 1 ({:?}) established", first_hop);

        // Store the partial circuit so backward relay cells can be decrypted
        // during construction of subsequent hops.
        {
            let circuit = OutboundCircuit {
                first_hop_circuit_id: circuit_id,
                first_hop,
                hop_keys: hop_keys.clone(),
                state: CircuitPhase::Extending { hops_built: 1 },
                waypoints: waypoints.clone(),
                last_activity: Instant::now(),
                forward_nonce: 0,
                nonce_domain: rand::random(),
                backward_replay: CellReplayWindow::new(),
                assembler: Default::default(),
            };
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

        // --- Route toward each waypoint via DV ---
        // If first_hop is already the first waypoint, skip it.
        let start_wp = if first_hop == waypoints[0] { 1 } else { 0 };
        const MAX_EXTENDS_PER_WAYPOINT: usize = 10;

        for wp_idx in start_wp..waypoints.len() {
            let waypoint = waypoints[wp_idx];

            for extend_count in 0..MAX_EXTENDS_PER_WAYPOINT {
                let (kex, reply) = self
                    .extend_step(circuit_id, first_hop, kem_algo, &waypoint)
                    .await?;

                if reply.is_empty() {
                    return Err(Error::Protocol(format!(
                        "extend failed: relay has no route to {:?}",
                        waypoint
                    )));
                }

                let (reached, _ext_algo, ext_ciphertext) = parse_extended_payload(&reply)?;
                let shared_bytes = kex.complete(&ext_ciphertext)?;
                let new_hop_key = HopKey::from_shared_secret(&shared_bytes);

                // Update the partial circuit with the new hop key.
                let hops_built = {
                    let mut circuits = self.circuits.outbound.lock().await;
                    let circuit = circuits
                        .get_mut(&circuit_id)
                        .ok_or_else(|| Error::Protocol("circuit gone during extension".into()))?;
                    circuit.hop_keys.push(new_hop_key);
                    // The former endpoint saw the previous clear domain.
                    // Rotate it when extending so it cannot recover new hop masks.
                    circuit.nonce_domain = rand::random();
                    let hops = circuit.hop_keys.len();
                    circuit.state = CircuitPhase::Extending { hops_built: hops };
                    hops
                };

                log::debug!(
                    "Circuit hop {} established (waypoint {:?}, reached={})",
                    hops_built,
                    waypoint,
                    reached
                );

                if reached {
                    break;
                }

                if extend_count == MAX_EXTENDS_PER_WAYPOINT - 1 {
                    return Err(Error::Protocol(format!(
                        "waypoint {:?} too far (>{} hops)",
                        waypoint, MAX_EXTENDS_PER_WAYPOINT
                    )));
                }
            }
        }

        // Mark circuit as ready.
        let final_hops = {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits
                .get_mut(&circuit_id)
                .ok_or_else(|| Error::Protocol("circuit gone during construction".into()))?;
            circuit.state = CircuitPhase::Ready;
            circuit.hop_keys.len()
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
                if let Ok(dest_peer) = crate::tns::verify_peer_record(record, &service_id) {
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
                    .connect_via_rendezvous(service_id, mode, port, &intro_points)
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
        let (waypoints, first_hops) =
            self.plan_circuit_path(dest_peer, min_hops, connected).await;

        // No route: bounded route search (RouteSearch) is not implemented yet.
        if first_hops.is_empty() {
            log::info!("try_connect_to_peer: no route to {:?}", dest_peer);
            return None;
        }

        self.try_build_with_hops(service_id, mode, port, dest_peer, &waypoints, &first_hops)
            .await
    }

    /// Try each first_hop candidate to build a circuit and establish a connection.
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
    ) -> Option<tarnet_api::service::Connection> {
        const BUILD_ATTEMPTS: u32 = 3;
        for attempt in 0..BUILD_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(200 << attempt)).await;
            }
            for first_hop in first_hops {
                match self.build_circuit(*first_hop, waypoints.to_vec()).await {
                    Ok(circuit_id) => {
                        match self
                            .setup_circuit_connection(service_id, mode, port, circuit_id)
                            .await
                        {
                            Ok(conn) => return Some(conn),
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
        None
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
        let rt = self.routing_table.lock().await;

        // --- Choose waypoints ---
        let waypoints = if min_hops <= 1 {
            vec![*dest]
        } else {
            // Pick (min_hops - 1) random intermediate waypoints from known peers.
            let mut candidates: Vec<PeerId> = rt
                .all_destinations()
                .map(|(p, _)| *p)
                .filter(|p| *p != *dest && *p != self.peer_id())
                .collect();
            // Also include connected peers not in routing table
            for p in connected {
                if *p != *dest && *p != self.peer_id() && !candidates.contains(p) {
                    candidates.push(*p);
                }
            }

            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            candidates.shuffle(&mut rng);

            let num_intermediates = (min_hops - 1).min(candidates.len());
            let mut wps: Vec<PeerId> = candidates.into_iter().take(num_intermediates).collect();
            wps.push(*dest);
            wps
        };

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
