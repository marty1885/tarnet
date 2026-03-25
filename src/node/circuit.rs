use super::*;

/// Encrypt a relay cell for backward transmission from an endpoint to the circuit initiator.
/// Returns the encoded wire message bytes ready to send.
fn encrypt_backward_cell(
    bwd_key: [u8; 32],
    bwd_digest: [u8; 32],
    nonce_prefix: [u8; 16],
    nonce: u64,
    circuit_id: u32,
    command: RelayCellCommand,
    data: &[u8],
) -> Vec<u8> {
    let body = write_cell_body(command, 0, data, &bwd_digest);
    let mut cell = [0u8; CELL_SIZE];
    cell[..CELL_BODY_SIZE].copy_from_slice(&body);
    cell[CELL_BODY_SIZE..CELL_BODY_SIZE + 8].copy_from_slice(&nonce.to_le_bytes());
    let mut crypto = HopCrypto {
        key: bwd_key,
        digest_key: bwd_digest,
        nonce_prefix,
        op: CryptoOp::Encrypt,
        replay: ReplayWindow::new(),
    };
    crypto.process_cell(&mut cell);

    encode_circuit_relay_cell(circuit_id, &cell)
}

impl Node {
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
                        hop_crypto.process_cell(&mut cell);
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
                        hop_crypto.process_cell(&mut cell_buf);
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
                        // Update circuit liveness on any backward cell
                        circuit.last_activity = Instant::now();

                        let mut cell = [0u8; CELL_SIZE];
                        cell.copy_from_slice(cell_data);
                        circuit.unwrap_backward(&mut cell);

                        // Try to parse as a relay cell using the last hop's backward MAC.
                        let digest_key = circuit.hop_keys.last().unwrap().backward_digest;
                        drop(circuits);

                        let body: &[u8; CELL_BODY_SIZE] =
                            cell[..CELL_BODY_SIZE].try_into().unwrap();
                        if let Ok(relay_cell) = RelayCell::from_cell(body, &digest_key) {
                            if relay_cell.command == RelayCellCommand::Extended {
                                // This is an EXTENDED reply during circuit construction.
                                let mut pending = self.circuits.pending_extends.lock().await;
                                if let Some(tx) = pending.remove(&circuit_id) {
                                    let _ = tx.send(relay_cell.data);
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::Sendme {
                                // Endpoint sent us a SENDME — open our send window.
                                let mut circuits = self.circuits.outbound.lock().await;
                                if let Some(circuit) = circuits.get_mut(&circuit_id) {
                                    circuit.congestion.on_sendme();
                                    log::trace!(
                                        "Circuit {} SENDME received: cwnd={}, inflight={}",
                                        circuit_id,
                                        circuit.congestion.cwnd,
                                        circuit.congestion.inflight
                                    );
                                }
                                drop(circuits);
                                // Wake the send task if it's waiting on the window.
                                let notifies = self.circuits.sendme_notify.lock().await;
                                if let Some(notify) = notifies.get(&circuit_id) {
                                    notify.notify_one();
                                }
                                return Ok(());
                            }
                            if relay_cell.command == RelayCellCommand::Data {
                                // Track receive-side flow control and send SENDME if needed.
                                let should_sendme = {
                                    let mut circuits = self.circuits.outbound.lock().await;
                                    if let Some(circuit) = circuits.get_mut(&circuit_id) {
                                        if !circuit.congestion.can_receive() {
                                            log::warn!(
                                                "Circuit {} initiator receive window exhausted, dropping backward DATA",
                                                circuit_id
                                            );
                                            return Ok(());
                                        }
                                        let digest = relay_cell_digest_for_sendme(&relay_cell.data);
                                        circuit.congestion.on_deliver(digest)
                                    } else {
                                        false
                                    }
                                };

                                // Deliver backward DATA BEFORE sending SENDME to
                                // avoid out-of-order delivery (spawned task race).
                                let txs = self.endpoints.data_txs.lock().await;
                                if let Some(tx) = txs.get(&circuit_id) {
                                    let _ = tx.send(relay_cell.data).await;
                                }
                                drop(txs);

                                if should_sendme {
                                    for _ in 0..2 {
                                        self.send_circuit_data_cmd(
                                            circuit_id,
                                            RelayCellCommand::Sendme,
                                            &[],
                                        )
                                        .await?;
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

        // We need the MAC key to parse. Get it from the endpoint crypto entry.
        let table = self.circuits.table.lock().await;
        let key = CircuitKey {
            circuit_id,
            from_peer: from,
        };
        let digest_key = match table.lookup(&key) {
            Some(CircuitAction::Endpoint {
                crypto: Some(c), ..
            }) => c.digest_key,
            _ => {
                log::debug!("No endpoint crypto for circuit_id={}", circuit_id);
                return Ok(());
            }
        };
        drop(table);

        let body: &[u8; CELL_BODY_SIZE] = cell_data[..CELL_BODY_SIZE].try_into().unwrap();
        let relay_cell = match RelayCell::from_cell(body, &digest_key) {
            Ok(rc) => rc,
            Err(e) => {
                log::warn!(
                    "Relay cell parse failed at endpoint circuit_id={}: {}",
                    circuit_id,
                    e
                );
                return Ok(());
            }
        };

        match relay_cell.command {
            RelayCellCommand::Extend => {
                self.handle_extend_at_relay(from, circuit_id, &relay_cell.data)
                    .await
            }
            RelayCellCommand::Data => {
                // Check receiver-side flow control before delivering.
                let should_sendme = {
                    let mut cw_map = self.endpoints.recv_congestion.lock().await;
                    if let Some(cw) = cw_map.get_mut(&circuit_id) {
                        if !cw.can_receive() {
                            log::warn!(
                                "Circuit {} receive window exhausted, dropping DATA cell ({} bytes)",
                                circuit_id,
                                relay_cell.data.len()
                            );
                            return Ok(());
                        }
                        // Compute digest of this cell for authenticated SENDME
                        let digest = crate::circuit::relay_cell_digest_for_sendme(&relay_cell.data);
                        cw.on_deliver(digest)
                    } else {
                        false
                    }
                };

                // Deliver to application layer BEFORE sending SENDME.
                // Because each message is handled in a spawned task,
                // awaiting the SENDME send can let a subsequent DATA cell's
                // task overtake this one and deliver out of order.
                let txs = self.endpoints.data_txs.lock().await;
                if let Some(tx) = txs.get(&circuit_id) {
                    let _ = tx.send(relay_cell.data).await;
                } else {
                    log::debug!(
                        "No connection for circuit_id={}, {} bytes dropped",
                        circuit_id,
                        relay_cell.data.len()
                    );
                }

                // Send SENDME back to the initiator if threshold reached.
                // Done AFTER data delivery to avoid out-of-order reordering
                // (the await here could let the next cell's task overtake us).
                // Sent twice for redundancy on lossy links.
                if should_sendme {
                    for _ in 0..2 {
                        self.send_endpoint_relay_cell(
                            from,
                            circuit_id,
                            RelayCellCommand::Sendme,
                            &[],
                        )
                        .await?;
                    }
                }
                Ok(())
            }
            RelayCellCommand::StreamBegin => {
                self.handle_stream_begin(from, circuit_id, &relay_cell.data)
                    .await
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
            RelayCellCommand::Sendme => {
                // Initiator sent us a SENDME — open our backward send window.
                let mut map = self.endpoints.send_congestion.lock().await;
                if let Some((cw, notify)) = map.get_mut(&circuit_id) {
                    cw.on_sendme();
                    log::trace!(
                        "Endpoint circuit {} SENDME: cwnd={}, inflight={}",
                        circuit_id,
                        cw.cwnd,
                        cw.inflight,
                    );
                    notify.notify_one();
                }
                Ok(())
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
        let (bwd_key, bwd_digest, nonce_prefix, nonce) = self
            .get_hop_backward_crypto(circuit_id, from)
            .await
            .ok_or_else(|| Error::Protocol("no backward keys for circuit".into()))?;

        let encoded = encrypt_backward_cell(
            bwd_key,
            bwd_digest,
            nonce_prefix,
            nonce,
            circuit_id,
            command,
            data,
        );
        self.send_to_peer(&from, &encoded).await
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
        let (service_id, mode, port) = parse_stream_begin_payload(payload)?;

        // Idempotent: if we already set up a stream on this circuit,
        // just re-send StreamConnected (the first one may have been dropped).
        {
            let data_txs = self.endpoints.data_txs.lock().await;
            if data_txs.contains_key(&circuit_id) {
                drop(data_txs);
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

        // Create data channels for the incoming Connection.
        let (app_tx, circuit_rx) = mpsc::channel::<Vec<u8>>(256);
        let (circuit_tx, app_rx) = mpsc::channel::<Vec<u8>>(256);

        // Register the circuit_tx so incoming DATA cells are forwarded to the connection.
        self.endpoints
            .data_txs
            .lock()
            .await
            .insert(circuit_id, circuit_tx);
        // Track ownership for per-peer stream limiting.
        self.endpoints
            .stream_owners
            .lock()
            .await
            .insert(circuit_id, from);
        // Initialize endpoint-side receive window for flow control.
        self.endpoints
            .recv_congestion
            .lock()
            .await
            .insert(circuit_id, CongestionWindow::new());

        // Spawn a task to send outgoing data as relay cells back through the circuit.
        // At the endpoint, we send backward relay cells: encrypt with our backward key
        // and send to the upstream peer.
        let send_notify = Arc::new(tokio::sync::Notify::new());
        self.endpoints
            .send_congestion
            .lock()
            .await
            .insert(circuit_id, (CongestionWindow::new(), send_notify.clone()));

        let links = self.links.clone();
        let hop_backward_keys = self.circuits.hop_backward_keys.clone();
        let send_cw = self.endpoints.send_congestion.clone();
        tokio::spawn(async move {
            let mut rx = circuit_rx;
            while let Some(data) = rx.recv().await {
                // Process chunks inline — no intermediate Vec<Vec<u8>> needed.
                let mut broken = false;
                let num_chunks = (data.len() + CELL_PAYLOAD_MAX - 1) / CELL_PAYLOAD_MAX.max(1);
                for i in 0..num_chunks {
                    let start = i * CELL_PAYLOAD_MAX;
                    let end = (start + CELL_PAYLOAD_MAX).min(data.len());
                    let chunk = &data[start..end];

                    // Wait until the congestion window allows sending.
                    loop {
                        let can_send = {
                            let mut map = send_cw.lock().await;
                            if let Some((cw, _)) = map.get_mut(&circuit_id) {
                                cw.check_stall();
                                cw.can_send()
                            } else {
                                false
                            }
                        };
                        if can_send {
                            break;
                        }
                        tokio::select! {
                            _ = send_notify.notified() => {}
                            _ = tokio::time::sleep(SENDME_STALL_TIMEOUT) => {}
                        }
                    }

                    // Record the send.
                    {
                        let mut map = send_cw.lock().await;
                        if let Some((cw, _)) = map.get_mut(&circuit_id) {
                            cw.on_send();
                        }
                    }

                    // Get the backward crypto for this circuit.
                    let bwd_info = {
                        let mut map = hop_backward_keys.lock().await;
                        if let Some(entry) = map.get_mut(&(circuit_id, from)) {
                            let nonce = entry.3;
                            entry.3 += 1;
                            Some((entry.0, entry.1, entry.2, nonce))
                        } else {
                            None
                        }
                    };

                    let (bwd_key, bwd_digest, nonce_prefix, nonce) = match bwd_info {
                        Some(info) => info,
                        None => {
                            broken = true;
                            break;
                        }
                    };

                    let encoded = encrypt_backward_cell(
                        bwd_key,
                        bwd_digest,
                        nonce_prefix,
                        nonce,
                        circuit_id,
                        RelayCellCommand::Data,
                        chunk,
                    );
                    let links_guard = links.lock().await;
                    if let Some(link) = links_guard.get(&from) {
                        let _ = link.send_message(&encoded).await;
                    }
                }
                if broken {
                    break;
                }
            }
        });

        // Build the Connection and route it to the matching listener.
        let conn = tarnet_api::service::Connection::new(
            service_id, mode, port, circuit_id, app_tx, app_rx,
        );

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
            self.endpoints.data_txs.lock().await.remove(&circuit_id);
            self.endpoints
                .stream_owners
                .lock()
                .await
                .remove(&circuit_id);
            self.endpoints
                .recv_congestion
                .lock()
                .await
                .remove(&circuit_id);
            self.endpoints
                .send_congestion
                .lock()
                .await
                .remove(&circuit_id);
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
        let (kem_algo, initiator_ephemeral, destination) = parse_extend_payload(extend_data)?;

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
            table
                .lookup(&CircuitKey {
                    circuit_id: id,
                    from_peer: next_hop,
                })
                .is_some()
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
                    replay: ReplayWindow::new(),
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

        // Remember this pending extend so when CircuitCreated arrives from next_hop,
        // we can route the EXTENDED reply back.
        self.circuits
            .relay_extend_pending
            .lock()
            .await
            .insert(outbound_id, (from, inbound_circuit_id, reached, Instant::now()));

        // Send CircuitCreate to next_hop with algo + initiator's ephemeral pubkey.
        let mut create_payload = Vec::with_capacity(1 + initiator_ephemeral.len());
        create_payload.push(kem_algo);
        create_payload.extend_from_slice(&initiator_ephemeral);
        let create = CircuitCreateMsg {
            circuit_id: outbound_id,
            encrypted_payload: create_payload,
        };
        self.send_to_peer(&next_hop, &create.to_wire().encode())
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
        let mut table = self.circuits.table.lock().await;
        table.insert(
            CircuitKey {
                circuit_id: msg.circuit_id,
                from_peer: from,
            },
            CircuitAction::Endpoint {
                origin_hop: from,
                crypto: Some(HopCrypto {
                    key: hop_keys.forward_key,
                    digest_key: hop_keys.forward_digest,
                    nonce_prefix: hop_keys.nonce_prefix,
                    op: CryptoOp::Decrypt,
                    replay: ReplayWindow::new(),
                }),
            },
        );
        drop(table);

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
        self.send_to_peer(&from, &reply.to_wire().encode()).await
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
        let relay_pending = self
            .circuits
            .relay_extend_pending
            .lock()
            .await
            .remove(&msg.circuit_id);

        if let Some((inbound_from, inbound_circuit_id, reached, _created)) = relay_pending {
            // We're a relay that forwarded a CREATE on behalf of an EXTEND.
            // Wrap the CircuitCreated reply as an EXTENDED relay cell and send
            // it back through the inbound circuit.

            // Get the backward crypto for the inbound circuit.
            let bwd_info = self
                .get_hop_backward_crypto(inbound_circuit_id, inbound_from)
                .await;

            // The CircuitCreated encrypted_reply already has the flags byte
            // (from build_extended_payload). Set the reached flag if this
            // extend landed on the requested destination.
            let mut reply_data = msg.encrypted_reply;
            if reached && !reply_data.is_empty() {
                reply_data[0] |= EXTENDED_FLAG_REACHED;
            }
            let reply_cell = RelayCell {
                command: RelayCellCommand::Extended,
                stream_id: 0,
                data: reply_data,
            };

            // Serialize with backward MAC key and encrypt with backward key.
            let bwd_digest = bwd_info.map(|(_, m, _, _)| m).unwrap_or([0u8; 32]);
            let body = reply_cell.to_cell(&bwd_digest);
            let mut cell = [0u8; CELL_SIZE];
            cell[..CELL_BODY_SIZE].copy_from_slice(&body);

            if let Some((bwd_key, bwd_digest_key, nonce_prefix, nonce)) = bwd_info {
                cell[CELL_BODY_SIZE..CELL_BODY_SIZE + 8].copy_from_slice(&nonce.to_le_bytes());
                let mut crypto = HopCrypto {
                    key: bwd_key,
                    digest_key: bwd_digest_key,
                    nonce_prefix,
                    op: CryptoOp::Encrypt,
                    replay: ReplayWindow::new(),
                };
                crypto.process_cell(&mut cell);
            }

            let encoded = encode_circuit_relay_cell(inbound_circuit_id, &cell);
            return self
                .send_to_peer(&inbound_from, &encoded)
                .await;
        }

        // Otherwise, this is for the circuit initiator.
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

        let mut table = self.circuits.table.lock().await;
        if let Some(action) = table.remove(&key) {
            // Propagate destroy to the next hop
            if let CircuitAction::Forward {
                next_hop,
                next_circuit_id,
                ..
            } = action
            {
                drop(table);
                let destroy = CircuitDestroyMsg {
                    circuit_id: next_circuit_id,
                };
                let _ = self
                    .send_to_peer(&next_hop, &destroy.to_wire().encode())
                    .await;
            }
            log::debug!(
                "Circuit destroyed: circuit_id={} from {:?}",
                msg.circuit_id,
                from
            );
        }

        // Clean up connection state.
        self.endpoints.data_txs.lock().await.remove(&msg.circuit_id);
        self.endpoints
            .stream_owners
            .lock()
            .await
            .remove(&msg.circuit_id);
        self.endpoints
            .recv_congestion
            .lock()
            .await
            .remove(&msg.circuit_id);
        self.endpoints
            .send_congestion
            .lock()
            .await
            .remove(&msg.circuit_id);
        self.circuits
            .sendme_notify
            .lock()
            .await
            .remove(&msg.circuit_id);
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
        self.hidden
            .intro_registrations
            .lock()
            .await
            .remove(&msg.circuit_id);
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
        self.hidden
            .intro_registrations
            .lock()
            .await
            .insert(circuit_id, (service_id.clone(), from));

        // Send IntroRegistered back (empty payload)
        let reply = RelayCell {
            command: RelayCellCommand::IntroRegistered,
            stream_id: 0,
            data: vec![],
        };
        // Send backward relay cell
        let bwd_info = self.get_hop_backward_crypto(circuit_id, from).await;
        let (bwd_key, bwd_digest, nonce_prefix, nonce) =
            bwd_info.unwrap_or(([0u8; 32], [0u8; 32], [0u8; 16], 0));
        let body = reply.to_cell(&bwd_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        cell[CELL_BODY_SIZE..CELL_BODY_SIZE + 8].copy_from_slice(&nonce.to_le_bytes());
        let mut crypto = HopCrypto {
            key: bwd_key,
            digest_key: bwd_digest,
            nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: ReplayWindow::new(),
        };
        crypto.process_cell(&mut cell);
        let encoded = encode_circuit_relay_cell(circuit_id, &cell);
        self.send_to_peer(&from, &encoded).await
    }

    /// Handle INTRODUCE at an intro point: forward the INTRODUCE data to the registered service.
    async fn handle_introduce(&self, from: PeerId, circuit_id: u32, payload: &[u8]) -> Result<()> {
        log::info!(
            "Introduce received at intro point on circuit_id={}",
            circuit_id,
        );

        // Look up which service registered on this intro point.
        // The INTRODUCE arrives on the client's circuit to this intro point.
        // We need to find the service's circuit and the peer that registered it.
        let regs = self.hidden.intro_registrations.lock().await;
        let service_entry = regs.iter().next();
        let (service_circuit_id, _service_id, service_from) = match service_entry {
            Some((&cid, (sid, peer))) => (cid, sid.clone(), *peer),
            None => {
                log::warn!("[B-INTRO] No service registered at this intro point");
                return Ok(());
            }
        };
        drop(regs);

        // Send the INTRODUCE data as a relay cell to the service
        let intro_cell = RelayCell {
            command: RelayCellCommand::Introduce,
            stream_id: 0,
            data: payload.to_vec(),
        };
        let bwd_info = self
            .get_hop_backward_crypto(service_circuit_id, service_from)
            .await;
        let (bwd_key, bwd_digest, nonce_prefix, nonce) =
            bwd_info.unwrap_or(([0u8; 32], [0u8; 32], [0u8; 16], 0));
        let body = intro_cell.to_cell(&bwd_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        cell[CELL_BODY_SIZE..CELL_BODY_SIZE + 8].copy_from_slice(&nonce.to_le_bytes());
        let mut crypto = HopCrypto {
            key: bwd_key,
            digest_key: bwd_digest,
            nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: ReplayWindow::new(),
        };
        crypto.process_cell(&mut cell);
        let encoded = encode_circuit_relay_cell(service_circuit_id, &cell);
        let _ = self
            .send_to_peer(&service_from, &encoded)
            .await;

        // Send IntroduceAck back to the client
        let ack = RelayCell {
            command: RelayCellCommand::IntroduceAck,
            stream_id: 0,
            data: vec![],
        };
        let bwd_info = self.get_hop_backward_crypto(circuit_id, from).await;
        let (bwd_key, bwd_digest, nonce_prefix, nonce) =
            bwd_info.unwrap_or(([0u8; 32], [0u8; 32], [0u8; 16], 0));
        let body = ack.to_cell(&bwd_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        cell[CELL_BODY_SIZE..CELL_BODY_SIZE + 8].copy_from_slice(&nonce.to_le_bytes());
        let mut crypto = HopCrypto {
            key: bwd_key,
            digest_key: bwd_digest,
            nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: ReplayWindow::new(),
        };
        crypto.process_cell(&mut cell);
        let encoded = encode_circuit_relay_cell(circuit_id, &cell);
        self.send_to_peer(&from, &encoded).await
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
            bwd_info.unwrap_or(([0u8; 32], [0u8; 32], [0u8; 16], 0));
        let body = joined.to_cell(&bwd_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        cell[CELL_BODY_SIZE..CELL_BODY_SIZE + 8].copy_from_slice(&nonce.to_le_bytes());
        let mut crypto = HopCrypto {
            key: bwd_key,
            digest_key: bwd_digest,
            nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: ReplayWindow::new(),
        };
        crypto.process_cell(&mut cell);
        let encoded = encode_circuit_relay_cell(client_circuit_id, &cell);
        self.send_to_peer(&client_from, &encoded)
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
        entry.3 += 1;
        Some((entry.0, entry.1, entry.2, nonce))
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
            let oc = self.circuits.outbound.lock().await;
            self.circuits
                .table
                .lock()
                .await
                .alloc_id(we_initiated, |id| oc.contains_key(&id))
        };

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
        self.send_to_peer(&first_hop, &create.to_wire().encode())
            .await?;

        // Wait for CircuitCreated
        let reply = rx
            .await
            .map_err(|_| Error::Protocol("circuit create channel dropped".into()))?;

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
                congestion: CongestionWindow::new(),
                last_activity: Instant::now(),
                forward_nonce: 0,
            };
            let managed = self.manage_circuit(circuit_id, circuit);
            self.circuits
                .outbound
                .lock()
                .await
                .insert(circuit_id, managed);
        }

        // --- Route toward each waypoint via DV ---
        // If first_hop is already the first waypoint, skip it.
        let start_wp = if first_hop == waypoints[0] { 1 } else { 0 };
        const MAX_EXTENDS_PER_WAYPOINT: usize = 10;

        for wp_idx in start_wp..waypoints.len() {
            let waypoint = waypoints[wp_idx];

            for extend_count in 0..MAX_EXTENDS_PER_WAYPOINT {
                let kex = KexOffer::new(kem_algo);

                let extend_data =
                    build_extend_payload(kex.algo_byte(), &kex.pubkey_bytes(), &waypoint);

                let extend_cell = RelayCell {
                    command: RelayCellCommand::Extend,
                    stream_id: 0,
                    data: extend_data,
                };

                // Get the current circuit from outbound_circuits to wrap the cell.
                {
                    let mut circuits = self.circuits.outbound.lock().await;
                    let circuit = circuits.get_mut(&circuit_id).unwrap();
                    let current_endpoint_idx = circuit.hop_keys.len() - 1;
                    let (first_hop_send, cid, cell_bytes) =
                        circuit.send_to_hop(&extend_cell, current_endpoint_idx);

                    drop(circuits);

                    let encoded = encode_circuit_relay_cell(cid, &cell_bytes);
                    self.send_to_peer(&first_hop_send, &encoded)
                        .await?;
                }

                // Register for the backward EXTENDED cell
                let (tx, rx) = oneshot::channel();
                self.circuits
                    .pending_extends
                    .lock()
                    .await
                    .insert(circuit_id, tx);

                let reply = match tokio::time::timeout(Duration::from_millis(1500), rx).await {
                    Ok(Ok(data)) => data,
                    Ok(Err(_)) => {
                        self.circuits.pending_extends.lock().await.remove(&circuit_id);
                        return Err(Error::Protocol("circuit extend channel dropped".into()));
                    }
                    Err(_) => {
                        self.circuits.pending_extends.lock().await.remove(&circuit_id);
                        return Err(Error::Protocol("circuit extend timed out".into()));
                    }
                };

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
                    let circuit = circuits.get_mut(&circuit_id).unwrap();
                    circuit.hop_keys.push(new_hop_key);
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
            let circuit = circuits.get_mut(&circuit_id).unwrap();
            circuit.state = CircuitPhase::Ready;
            circuit.hop_keys.len()
        };

        log::info!(
            "Circuit built: circuit_id={}, {} hops, {} waypoints",
            circuit_id,
            final_hops,
            waypoints.len()
        );
        Ok(circuit_id)
    }

    /// Send a DATA relay cell through an established outbound circuit.
    /// Blocks if the congestion window is full (waits for SENDME from endpoint).
    pub async fn send_circuit_data(&self, circuit_id: u32, data: &[u8]) -> Result<()> {
        // Wait until the congestion window allows sending.
        loop {
            let can_send = {
                let mut circuits = self.circuits.outbound.lock().await;
                let circuit = circuits
                    .get_mut(&circuit_id)
                    .ok_or_else(|| Error::Protocol("no such outbound circuit".into()))?;
                if circuit.state != CircuitPhase::Ready {
                    return Err(Error::Protocol("circuit not ready".into()));
                }
                circuit.congestion.check_stall();
                circuit.congestion.can_send()
            };
            if can_send {
                break;
            }
            // Wait for SENDME or stall timeout.
            let notify = {
                let map = self.circuits.sendme_notify.lock().await;
                map.get(&circuit_id).cloned()
            };
            if let Some(notify) = notify {
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(SENDME_STALL_TIMEOUT) => {}
                }
            } else {
                // No notify registered — just proceed (backward compat / control cells).
                break;
            }
        }

        let mut circuits = self.circuits.outbound.lock().await;
        let circuit = circuits
            .get_mut(&circuit_id)
            .ok_or_else(|| Error::Protocol("no such outbound circuit".into()))?;

        let (first_hop, cid, cell) = circuit.send_data_cell(data);
        circuit.congestion.on_send();
        drop(circuits);

        let encoded = encode_circuit_relay_cell(cid, &cell);
        self.send_to_peer(&first_hop, &encoded).await
    }

    /// Send an arbitrary relay cell command through an outbound circuit (e.g. SENDME).
    /// Does not count against the congestion window.
    async fn send_circuit_data_cmd(
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
                    client_rx,
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
                    server_rx,
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
        let (waypoints, mut first_hops) =
            self.plan_circuit_path(dest_peer, min_hops, connected).await;

        // If no first hops found (destination beyond DV horizon), try a route probe.
        // The probe walks the network and caches the route on success.
        if first_hops.is_empty() {
            log::info!(
                "try_connect_to_peer: no route to {:?}, starting route probe",
                dest_peer
            );
            if let Some(_cost) = self.route_probe(*dest_peer).await {
                log::info!(
                    "try_connect_to_peer: route probe found {:?}, re-planning",
                    dest_peer
                );
                let (new_waypoints, new_first_hops) =
                    self.plan_circuit_path(dest_peer, min_hops, connected).await;
                // Use the freshly discovered route.
                first_hops = new_first_hops;
                // Re-plan may give different waypoints too.
                return self
                    .try_build_with_hops(
                        service_id,
                        mode,
                        port,
                        dest_peer,
                        &new_waypoints,
                        &first_hops,
                    )
                    .await;
            } else {
                log::info!(
                    "try_connect_to_peer: route probe for {:?} failed",
                    dest_peer
                );
                return None;
            }
        }

        self.try_build_with_hops(service_id, mode, port, dest_peer, &waypoints, &first_hops)
            .await
    }

    /// Try each first_hop candidate to build a circuit and establish a connection.
    async fn try_build_with_hops(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        dest_peer: &PeerId,
        waypoints: &[PeerId],
        first_hops: &[PeerId],
    ) -> Option<tarnet_api::service::Connection> {
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
                        "circuit_connect: build_circuit to {:?} failed: {}",
                        dest_peer,
                        e
                    );
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
        const MAX_STREAM_RETRIES: u32 = 5;
        const INITIAL_TIMEOUT_MS: u64 = 1000;

        let stream_begin_payload = build_stream_begin_payload(&service_id, mode, port);
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
                    command: RelayCellCommand::StreamBegin,
                    stream_id: 0,
                    data: stream_begin_payload.clone(),
                };
                let mut circuits = self.circuits.outbound.lock().await;
                let circuit = match circuits.get_mut(&circuit_id) {
                    Some(c) => c,
                    None => return Err(Error::Protocol("circuit gone during stream setup".into())),
                };
                let (fh, cid, cell) = circuit.send_relay_cell(&stream_begin);
                drop(circuits);

                let encoded = encode_circuit_relay_cell(cid, &cell);
                self.send_to_peer(&fh, &encoded).await?;
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

        // Set up data channels for the Connection.
        let (app_tx, circuit_rx) = mpsc::channel::<Vec<u8>>(256);
        let (circuit_tx, app_rx) = mpsc::channel::<Vec<u8>>(256);

        // Store the sender so incoming DATA cells can be forwarded to the app.
        self.endpoints
            .data_txs
            .lock()
            .await
            .insert(circuit_id, circuit_tx);

        // Spawn a task to forward outgoing data through the circuit.
        // Read first_hop from the circuit on each send so multipath failover
        // (which replaces the circuit) is transparent to this task.
        let sendme_notify = Arc::new(tokio::sync::Notify::new());
        self.circuits
            .sendme_notify
            .lock()
            .await
            .insert(circuit_id, sendme_notify.clone());

        let node_circuits = self.circuits.outbound.clone();
        let node_links = self.links.clone();
        tokio::spawn(async move {
            let mut rx = circuit_rx;
            while let Some(data) = rx.recv().await {
                // Process chunks inline — no intermediate Vec<Vec<u8>> needed.
                let mut broken = false;
                let num_chunks = (data.len() + CELL_PAYLOAD_MAX - 1) / CELL_PAYLOAD_MAX.max(1);
                for i in 0..num_chunks {
                    let start = i * CELL_PAYLOAD_MAX;
                    let end = (start + CELL_PAYLOAD_MAX).min(data.len());
                    let chunk = &data[start..end];

                    // Wait until congestion window allows sending.
                    loop {
                        let can_send = {
                            let mut circuits = node_circuits.lock().await;
                            if let Some(c) = circuits.get_mut(&circuit_id) {
                                c.congestion.check_stall();
                                c.congestion.can_send()
                            } else {
                                false
                            }
                        };
                        if can_send {
                            break;
                        }
                        tokio::select! {
                            _ = sendme_notify.notified() => {}
                            _ = tokio::time::sleep(SENDME_STALL_TIMEOUT) => {}
                        }
                    }

                    let mut circuits = node_circuits.lock().await;
                    if let Some(circuit) = circuits.get_mut(&circuit_id) {
                        let (first_hop, cid, cell) = circuit.send_data_cell(chunk);
                        circuit.congestion.on_send();
                        drop(circuits);

                        let encoded = encode_circuit_relay_cell(cid, &cell);
                        let links = node_links.lock().await;
                        if let Some(link) = links.get(&first_hop) {
                            let _ = link.send_message(&encoded).await;
                        }
                    } else {
                        broken = true;
                        break;
                    }
                }
                if broken {
                    break;
                }
            }
        });

        let conn = tarnet_api::service::Connection::new(
            service_id,
            mode,
            port.to_string(),
            circuit_id,
            app_tx,
            app_rx,
        );

        log::info!(
            "Connected to {:?} mode {:?} port {} via circuit {}",
            service_id,
            mode,
            port,
            circuit_id
        );

        Ok(conn)
    }
}
