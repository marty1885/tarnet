use super::*;

impl Node {
    pub async fn connect_via_rendezvous(
        &self,
        service_id: tarnet_api::types::ServiceId,
        port: u16,
        intro_points: &[(PeerId, u8, Vec<u8>)],
    ) -> Result<tarnet_api::service::Connection> {
        let connected = self.connected_peers().await;
        if connected.is_empty() {
            return Err(Error::Protocol("no connected peers for rendezvous".into()));
        }

        // Pick a rendezvous point (any connected peer)
        let rendezvous_peer = connected[0];

        // Generate a random cookie
        let mut cookie = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cookie);

        // Build circuit to rendezvous point
        let rend_circuit_id = self.build_circuit(rendezvous_peer, vec![rendezvous_peer]).await?;

        // Send RendezvousEstablish(cookie)
        let establish_cell = RelayCell {
            command: RelayCellCommand::RendezvousEstablish,
            stream_id: 0,
            data: build_rendezvous_establish_payload(&cookie),
        };
        {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits.get_mut(&rend_circuit_id).unwrap();
            let (fh, cid, cell) = circuit.send_relay_cell(&establish_cell);
            drop(circuits);

            let msg = CircuitRelayMsg {
                circuit_id: cid,
                data: cell.to_vec(),
            };
            self.send_to_peer(&fh, &msg.to_wire().encode()).await?;
        }

        // Build circuit to an intro point
        let (intro_peer, kem_algo_byte, ref kem_pubkey) = intro_points[0];
        let intro_circuit_id = self.build_circuit(intro_peer, vec![intro_peer]).await?;

        // KEM encapsulate to the service's KEM public key.
        // Only the real service can decapsulate to recover the shared secret.
        let kem_algo = tarnet_api::types::KemAlgo::from_u8(kem_algo_byte)
            .map_err(|e| Error::Protocol(format!("intro point unknown KEM algo: {}", e)))?;
        let (shared_secret, kem_ciphertext) =
            crate::identity::KemKeypair::encapsulate_to(kem_pubkey, kem_algo)
                .map_err(|e| Error::Crypto(format!("INTRODUCE KEM encapsulate failed: {}", e)))?;

        // Register oneshot receivers BEFORE sending, to avoid the race where
        // the response arrives on localhost before the sender is inserted.
        let (ack_tx, ack_rx) = oneshot::channel();
        let (joined_tx, joined_rx) = oneshot::channel();
        {
            let mut pending = self.circuits.pending_extends.lock().await;
            pending.insert(intro_circuit_id, ack_tx);
            pending.insert(rend_circuit_id, joined_tx);
        }

        // Send encrypted INTRODUCE through intro circuit.
        // The payload is encrypted to the service's KEM public key so the intro
        // point cannot learn the rendezvous peer or cookie.
        let introduce_cell = RelayCell {
            command: RelayCellCommand::Introduce,
            stream_id: 0,
            data: build_introduce_payload(
                &rendezvous_peer,
                &cookie,
                &kem_ciphertext,
                &shared_secret,
            ),
        };
        {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits.get_mut(&intro_circuit_id).unwrap();
            let (fh, cid, cell) = circuit.send_relay_cell(&introduce_cell);
            drop(circuits);

            let msg = CircuitRelayMsg {
                circuit_id: cid,
                data: cell.to_vec(),
            };
            self.send_to_peer(&fh, &msg.to_wire().encode()).await?;
        }
        // Wait for IntroduceAck
        let _ack = tokio::time::timeout(Duration::from_secs(10), ack_rx)
            .await
            .map_err(|_| Error::Protocol("IntroduceAck timeout".into()))?
            .map_err(|_| Error::Protocol("IntroduceAck channel dropped".into()))?;
        let _joined = tokio::time::timeout(Duration::from_secs(10), joined_rx)
            .await
            .map_err(|_| Error::Protocol("RendezvousJoined timeout".into()))?
            .map_err(|_| Error::Protocol("RendezvousJoined channel dropped".into()))?;

        // Derive e2e hop key from the same KEM shared secret used for INTRODUCE encryption.
        let e2e_hop = crate::circuit::HopKey::from_shared_secret(&shared_secret);
        {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits.get_mut(&rend_circuit_id).unwrap();
            // Replace all hop keys with only the e2e key. The rendezvous point
            // bridges the two circuits at the cell level (Forward with no crypto),
            // so circuit-level encryption must be removed.
            circuit.hop_keys = vec![e2e_hop];
        }

        log::info!(
            "Rendezvous established for {:?} on circuit_id={} (e2e encrypted)",
            service_id,
            rend_circuit_id,
        );

        // The rendezvous circuit is now bridged — set up data channels.
        // Set up data channels for the Connection.
        let (app_tx, circuit_rx) = mpsc::channel::<Vec<u8>>(256);
        let (circuit_tx, app_rx) = mpsc::channel::<Vec<u8>>(256);

        self.endpoints.data_txs
            .lock()
            .await
            .insert(rend_circuit_id, circuit_tx);

        let rend_sendme_notify = Arc::new(tokio::sync::Notify::new());
        self.circuits.sendme_notify
            .lock()
            .await
            .insert(rend_circuit_id, rend_sendme_notify.clone());

        let node_circuits = self.circuits.outbound.clone();
        let node_links = self.links.clone();
        tokio::spawn(async move {
            let mut rx = circuit_rx;
            while let Some(data) = rx.recv().await {
                // Wait until congestion window allows sending.
                loop {
                    let can_send = {
                        let mut circuits = node_circuits.lock().await;
                        if let Some(c) = circuits.get_mut(&rend_circuit_id) {
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
                        _ = rend_sendme_notify.notified() => {}
                        _ = tokio::time::sleep(SENDME_STALL_TIMEOUT) => {}
                    }
                }

                let mut circuits = node_circuits.lock().await;
                if let Some(circuit) = circuits.get_mut(&rend_circuit_id) {
                    let relay_cell = RelayCell {
                        command: RelayCellCommand::Data,
                        stream_id: 0,
                        data,
                    };
                    let (first_hop, cid, cell) = circuit.send_relay_cell(&relay_cell);
                    circuit.congestion.on_send();
                    drop(circuits);

                    let msg = CircuitRelayMsg {
                        circuit_id: cid,
                        data: cell.to_vec(),
                    };
                    let links = node_links.lock().await;
                    if let Some(link) = links.get(&first_hop) {
                        let _ = link.send_message(&msg.to_wire().encode()).await;
                    }
                } else {
                    break;
                }
            }
        });

        let conn = tarnet_api::service::Connection::new(
            service_id,
            port,
            rend_circuit_id,
            app_tx,
            app_rx,
        );

        Ok(conn)
    }

    /// Register a listener for incoming circuit connections (idempotent).
    pub async fn circuit_listen(
        &self,
        service_id: tarnet_api::types::ServiceId,
        port: u16,
    ) -> Result<()> {
        let mut listeners = self.listeners.lock().await;
        if listeners.iter().any(|(s, p)| *s == service_id && *p == port) {
            return Ok(());
        }
        listeners.push((service_id, port));
        log::info!("Listening on {:?} port {}", service_id, port);
        Ok(())
    }

    /// Accept the next incoming circuit connection.
    pub async fn circuit_accept(&self) -> Result<tarnet_api::service::Connection> {
        // Take the receiver on first call, then keep using it.
        let mut rx_guard = self.incoming_connections_rx.lock().await;
        let rx = rx_guard
            .as_mut()
            .ok_or_else(|| Error::Protocol("accept receiver already taken".into()))?;
        rx.recv()
            .await
            .ok_or_else(|| Error::Protocol("incoming connection channel closed".into()))
    }

    /// Publish a hidden service with introduction points.
    pub async fn publish_hidden_service(
        &self,
        service_id: tarnet_api::types::ServiceId,
        num_intro_points: usize,
    ) -> Result<()> {
        let connected = self.connected_peers().await;
        if connected.is_empty() {
            return Err(Error::Protocol("no connected peers for intro points".into()));
        }

        let count = num_intro_points.min(connected.len());
        let mut intro_records = Vec::new();
        let mut intro_circuits = Vec::new();

        for i in 0..count {
            let intro_peer = connected[i % connected.len()];

            // Build a circuit to the intro point
            let circuit_id = self.build_circuit(intro_peer, vec![intro_peer]).await?;

            // Send IntroRegister relay cell
            let register_cell = RelayCell {
                command: RelayCellCommand::IntroRegister,
                stream_id: 0,
                data: build_intro_register_payload(&service_id),
            };
            {
                let mut circuits = self.circuits.outbound.lock().await;
                let circuit = circuits
                    .get_mut(&circuit_id)
                    .ok_or_else(|| Error::Protocol("circuit disappeared".into()))?;
                let (fh, cid, cell) = circuit.send_relay_cell(&register_cell);
                drop(circuits);

                let msg = CircuitRelayMsg {
                    circuit_id: cid,
                    data: cell.to_vec(),
                };
                self.send_to_peer(&fh, &msg.to_wire().encode()).await?;
            }

            // Wait for IntroRegistered
            let (tx, rx) = oneshot::channel();
            self.circuits.pending_extends
                .lock()
                .await
                .insert(circuit_id, tx);

            let _reply = tokio::time::timeout(Duration::from_secs(5), rx)
                .await
                .map_err(|_| Error::Protocol("IntroRegister timeout".into()))?
                .map_err(|_| Error::Protocol("IntroRegister channel dropped".into()))?;

            log::info!(
                "Intro point registered: {:?} on circuit_id={}",
                intro_peer,
                circuit_id,
            );

            intro_records.push(crate::tns::TnsRecord::IntroductionPoint {
                relay_peer_id: intro_peer,
                kem_algo: 0, // filled in below after we have the service keypair
                kem_pubkey: Vec::new(),
            });
            intro_circuits.push((intro_peer, circuit_id));
        }

        // Store intro circuits for later use
        self.hidden.intros
            .lock()
            .await
            .insert(service_id, intro_circuits);

        // Publish intro records via TNS using the service keypair
        let zone_keypair = {
            let is = self.identity_store.lock().await;
            match is.keypair_for(&service_id) {
                Some(kp) => crate::identity::Keypair::from_full_bytes(&kp.to_full_bytes()).unwrap(),
                None => {
                    // Fallback to node identity if service keypair not found
                    crate::identity::Keypair::from_full_bytes(&self.identity.to_full_bytes()).unwrap()
                }
            }
        };

        // Fill in the service's KEM pubkey in all intro records
        let service_kem_algo = zone_keypair.identity.kem_algo() as u8;
        let service_kem_pubkey = zone_keypair.identity.kem.kem_pubkey_bytes();
        for record in &mut intro_records {
            if let crate::tns::TnsRecord::IntroductionPoint {
                kem_algo,
                kem_pubkey,
                ..
            } = record
            {
                *kem_algo = service_kem_algo;
                *kem_pubkey = service_kem_pubkey.clone();
            }
        }

        crate::tns::publish(self, &zone_keypair, "intro", &intro_records, 600).await?;

        log::info!(
            "Hidden service published: {:?} with {} intro points",
            service_id,
            count,
        );

        Ok(())
    }

    /// Tear down all intro circuits for a hidden service and remove tracking state.
    pub(super) async fn teardown_hidden_service(&self, service_id: &tarnet_api::types::ServiceId) {
        let removed = self.hidden.intros.lock().await.remove(service_id);
        self.hidden.last_publish.lock().await.remove(service_id);
        // Remove the listener registration for this ServiceId
        self.listeners.lock().await.retain(|(s, _)| s != service_id);
        if let Some(circuits) = removed {
            log::info!(
                "Tearing down {} intro circuit(s) for {:?}",
                circuits.len(),
                service_id
            );
            // Circuits will be cleaned up via their drop guards
            let mut oc = self.circuits.outbound.lock().await;
            for (_, circuit_id) in circuits {
                oc.remove(&circuit_id);
            }
        }
    }

    /// Publish a signed peer record for a public identity in TNS.
    /// This allows other nodes to resolve ServiceId → PeerId without scanning.
    pub async fn publish_peer_record(
        &self,
        service_id: tarnet_api::types::ServiceId,
    ) -> Result<()> {
        let zone_keypair = {
            let is = self.identity_store.lock().await;
            match is.keypair_for(&service_id) {
                Some(kp) => crate::identity::Keypair::from_full_bytes(&kp.to_full_bytes()).unwrap(),
                None => {
                    return Err(Error::Protocol("no keypair found for service".into()));
                }
            }
        };

        let peer_id = self.peer_id();
        let record = crate::tns::build_peer_record(&zone_keypair, &peer_id);
        crate::tns::publish(self, &zone_keypair, "peer", &[record], 600).await?;

        log::info!("Published peer record for {:?} → {:?}", service_id, peer_id);
        Ok(())
    }

    /// Publish peer records for all public identities.
    /// Re-publishes periodically to keep DHT records alive.
    pub(super) async fn maintain_peer_records(&self) {
        let public_identities: Vec<tarnet_api::types::ServiceId> = {
            let store = self.identity_store.lock().await;
            store
                .list()
                .into_iter()
                .filter_map(|(_, sid, privacy, _, _, _, _)| match privacy {
                    tarnet_api::types::PrivacyLevel::Public => Some(sid),
                    _ => None,
                })
                .collect()
        };

        if public_identities.is_empty() {
            return;
        }

        let connected = self.connected_peers().await;
        if connected.is_empty() {
            log::debug!("maintain_peer_records: no peers, skipping");
            return;
        }

        for sid in public_identities {
            match self.publish_peer_record(sid).await {
                Ok(()) => {}
                Err(e) => {
                    log::warn!("Failed to publish peer record for {:?}: {}", sid, e);
                }
            }
        }
    }

    /// Scan identity_store for all Hidden identities and ensure each has
    /// active intro points. Re-publishes if approaching TTL expiry or if
    /// intro circuits have failed.
    pub(super) async fn maintain_hidden_services(&self) {
        let hidden_identities: Vec<(tarnet_api::types::ServiceId, u8)> = {
            let store = self.identity_store.lock().await;
            store
                .list()
                .into_iter()
                .filter_map(|(_, sid, privacy, _, _, _, _)| match privacy {
                    tarnet_api::types::PrivacyLevel::Hidden { intro_points } => {
                        Some((sid, intro_points))
                    }
                    _ => None,
                })
                .collect()
        };

        if hidden_identities.is_empty() {
            return;
        }

        let connected = self.connected_peers().await;
        if connected.is_empty() {
            log::debug!("maintain_hidden_services: no peers, skipping");
            return;
        }

        for (sid, desired_intros) in hidden_identities {
            // Ensure circuit_listen is registered for this ServiceId (idempotent)
            let _ = self.circuit_listen(sid, 0).await;

            // Check if we need to (re)publish
            let needs_publish = {
                let intros = self.hidden.intros.lock().await;
                let last_pub = self.hidden.last_publish.lock().await;
                let has_enough = intros
                    .get(&sid)
                    .map(|v| v.len() >= desired_intros as usize)
                    .unwrap_or(false);
                let expired = last_pub
                    .get(&sid)
                    .map(|t| t.elapsed() > HIDDEN_SERVICE_REPUBLISH_AFTER)
                    .unwrap_or(true); // never published
                !has_enough || expired
            };

            if !needs_publish {
                continue;
            }

            // Tear down stale intro circuits before re-publishing
            {
                let mut intros = self.hidden.intros.lock().await;
                if let Some(old) = intros.remove(&sid) {
                    let mut oc = self.circuits.outbound.lock().await;
                    for (_, circuit_id) in old {
                        oc.remove(&circuit_id);
                    }
                }
            }

            match self.publish_hidden_service(sid, desired_intros as usize).await {
                Ok(()) => {
                    self.hidden.last_publish
                        .lock()
                        .await
                        .insert(sid, Instant::now());
                    log::info!("Hidden service {:?} maintained successfully", sid);
                }
                Err(e) => {
                    log::warn!("Failed to maintain hidden service {:?}: {}", sid, e);
                }
            }
        }
    }

    /// Handle an INTRODUCE message arriving at the service (forwarded by intro point).
    pub(super) async fn handle_introduce_at_service(
        &self,
        _intro_circuit_id: u32,
        payload: &[u8],
    ) {
        // Decrypt the INTRODUCE payload using our service KEM keypair.
        // The client encrypted it to our KEM public key so the intro point can't read it.
        let service_keypair = {
            let is = self.identity_store.lock().await;
            let sid = is.default_service_id();
            match is.keypair_for(&sid) {
                Some(kp) => crate::identity::Keypair::from_full_bytes(&kp.to_full_bytes()).unwrap(),
                None => crate::identity::Keypair::from_full_bytes(&self.identity.to_full_bytes()).unwrap(),
            }
        };

        let (rendezvous_peer, cookie, shared_secret) =
            match parse_introduce_payload(payload, &service_keypair.identity.kem) {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("Failed to parse INTRODUCE at service: {}", e);
                    return;
                }
            };

        log::info!(
            "Service received INTRODUCE: rendezvous={:?}",
            rendezvous_peer,
        );

        // Build a circuit to the rendezvous peer
        let circuit_id = match self.build_circuit(rendezvous_peer, vec![rendezvous_peer]).await {
            Ok(id) => id,
            Err(e) => {
                log::debug!("Failed to build circuit to rendezvous: {}", e);
                return;
            }
        };

        // Send RendezvousJoin(cookie) BEFORE adding the e2e hop, because the
        // rendezvous point needs to read this cell (it only has circuit-level crypto).
        let join_cell = RelayCell {
            command: RelayCellCommand::RendezvousJoin,
            stream_id: 0,
            data: cookie.to_vec(),
        };
        {
            let mut circuits = self.circuits.outbound.lock().await;
            if let Some(circuit) = circuits.get_mut(&circuit_id) {
                let (fh, cid, cell) = circuit.send_relay_cell(&join_cell);
                drop(circuits);

                let msg = CircuitRelayMsg {
                    circuit_id: cid,
                    data: cell.to_vec(),
                };
                if let Err(e) = self.send_to_peer(&fh, &msg.to_wire().encode()).await {
                    log::debug!("Failed to send RendezvousJoin: {}", e);
                    return;
                }
            } else {
                log::debug!("Circuit disappeared during rendezvous join");
                return;
            }
        }

        // Now add e2e HopKey and replace all hop keys with only the e2e key.
        // The rendezvous point bridges the two circuits at the cell level
        // (Forward with no crypto), so circuit-level encryption must be removed.
        let e2e_hop =
            crate::circuit::HopKey::from_shared_secret_responder(&shared_secret);
        {
            let mut circuits = self.circuits.outbound.lock().await;
            if let Some(circuit) = circuits.get_mut(&circuit_id) {
                circuit.hop_keys = vec![e2e_hop];
            }
        }

        log::info!(
            "Service sent RendezvousJoin on circuit_id={} (e2e encrypted)",
            circuit_id,
        );

        // Set up data channels for the incoming rendezvous connection.
        let (app_tx, circuit_rx) = mpsc::channel::<Vec<u8>>(256);
        let (circuit_tx, app_rx) = mpsc::channel::<Vec<u8>>(256);

        self.endpoints.data_txs
            .lock()
            .await
            .insert(circuit_id, circuit_tx);

        let svc_sendme_notify = Arc::new(tokio::sync::Notify::new());
        self.circuits.sendme_notify
            .lock()
            .await
            .insert(circuit_id, svc_sendme_notify.clone());

        let node_circuits = self.circuits.outbound.clone();
        let node_links = self.links.clone();
        tokio::spawn(async move {
            let mut rx = circuit_rx;
            while let Some(data) = rx.recv().await {
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
                        _ = svc_sendme_notify.notified() => {}
                        _ = tokio::time::sleep(SENDME_STALL_TIMEOUT) => {}
                    }
                }

                let mut circuits = node_circuits.lock().await;
                if let Some(circuit) = circuits.get_mut(&circuit_id) {
                    let relay_cell = RelayCell {
                        command: RelayCellCommand::Data,
                        stream_id: 0,
                        data,
                    };
                    let (first_hop, cid, cell) = circuit.send_relay_cell(&relay_cell);
                    circuit.congestion.on_send();
                    drop(circuits);

                    let msg = CircuitRelayMsg {
                        circuit_id: cid,
                        data: cell.to_vec(),
                    };
                    let links = node_links.lock().await;
                    if let Some(link) = links.get(&first_hop) {
                        let _ = link.send_message(&msg.to_wire().encode()).await;
                    }
                } else {
                    break;
                }
            }
        });

        let service_id = self.default_service_id().await;
        let conn = tarnet_api::service::Connection::new(
            service_id,
            0,
            circuit_id,
            app_tx,
            app_rx,
        );
        let _ = self.incoming_connections_tx.send(conn).await;
    }
}
