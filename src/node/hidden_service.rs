use super::*;

const ANY_PORT: &str = "*";

fn port_matches(listener_port: &str, port: &str) -> bool {
    listener_port == ANY_PORT || listener_port == port
}

fn listener_matches(
    listener: &Listener,
    service_id: tarnet_api::types::ServiceId,
    mode: tarnet_api::service::PortMode,
    port: &str,
) -> bool {
    listener.mode == mode
        && port_matches(&listener.port, port)
        && (listener.service_id.is_all() || listener.service_id == service_id)
}

fn listeners_overlap(a: &Listener, b: &Listener) -> bool {
    let port_overlap = port_matches(&a.port, &b.port) || port_matches(&b.port, &a.port);
    let service_overlap =
        a.service_id.is_all() || b.service_id.is_all() || a.service_id == b.service_id;
    a.mode == b.mode && port_overlap && service_overlap
}

impl Node {
    pub async fn connect_via_rendezvous(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        intro_points: &[(PeerId, u8, Vec<u8>)],
    ) -> Result<tarnet_api::service::Connection> {
        if intro_points.is_empty() {
            return Err(Error::Protocol(
                "no introduction points for rendezvous".into(),
            ));
        }
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
        let rend_circuit_id = self
            .build_circuit(rendezvous_peer, vec![rendezvous_peer])
            .await?;
        let mut rend_attempt = self.circuit_attempt_guard(rend_circuit_id);

        // Send RendezvousEstablish(cookie)
        let establish_cell = RelayCell {
            command: RelayCellCommand::RendezvousEstablish,
            stream_id: 0,
            data: build_rendezvous_establish_payload(&cookie),
        };
        {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits
                .get_mut(&rend_circuit_id)
                .ok_or_else(|| Error::Protocol("rendezvous circuit disappeared".into()))?;
            let (fh, cid, cell) = circuit.send_relay_cell(&establish_cell);
            drop(circuits);

            let encoded = encode_circuit_relay_cell(cid, &cell);
            self.send_to_peer_critical(&fh, &encoded).await?;
        }

        // Build circuit to an intro point
        let (intro_peer, kem_algo_byte, ref kem_pubkey) = intro_points[0];
        let intro_circuit_id = self.build_circuit(intro_peer, vec![intro_peer]).await?;
        let _intro_attempt = self.circuit_attempt_guard(intro_circuit_id);

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
        let sealed = build_introduce_payload(
            &rendezvous_peer,
            &cookie,
            mode,
            port,
            &kem_ciphertext,
            &shared_secret,
        );
        let introduce_cell = RelayCell {
            command: RelayCellCommand::Introduce,
            stream_id: 0,
            // Prefix the target ServiceId so the intro point forwards to the
            // right service circuit when it hosts more than one service.
            data: build_introduce_cell(&service_id, &sealed),
        };
        {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits
                .get_mut(&intro_circuit_id)
                .ok_or_else(|| Error::Protocol("introduction circuit disappeared".into()))?;
            let (fh, cid, cell) = circuit.send_relay_cell(&introduce_cell);
            drop(circuits);

            let encoded = encode_circuit_relay_cell(cid, &cell);
            self.send_to_peer_critical(&fh, &encoded).await?;
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
            let circuit = circuits
                .get_mut(&rend_circuit_id)
                .ok_or_else(|| Error::Protocol("rendezvous circuit disappeared".into()))?;
            // Replace all hop keys with only the e2e key. The rendezvous point
            // bridges the two circuits at the cell level (Forward with no crypto),
            // so circuit-level encryption must be removed.
            circuit.hop_keys = vec![e2e_hop];
            circuit.nonce_domain = rand::random();
        }

        log::info!(
            "Rendezvous established for {:?} on circuit_id={} (e2e encrypted)",
            service_id,
            rend_circuit_id,
        );

        let conn = self
            .circuit_connection(service_id, mode, port, rend_circuit_id)
            .await;
        self.wait_stream_connected(
            rend_circuit_id,
            RelayCellCommand::RendezvousReady,
            Vec::new(),
        )
        .await?;
        // The introduction circuit is only needed for the handshake.
        self.destroy_circuit(intro_circuit_id).await?;
        rend_attempt.armed = false;
        Ok(conn)
    }

    /// Register a listener for incoming circuit connections.
    pub async fn circuit_listen(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        options: ListenerOptions,
    ) -> Result<Listener> {
        let mut listeners = self.listeners.lock().await;
        let pending = Listener {
            id: 0,
            service_id,
            mode,
            port: port.to_string(),
            options,
        };

        for existing in listeners.values() {
            if listeners_overlap(&existing.listener, &pending)
                && !(existing.listener.options.reuse_port && options.reuse_port)
            {
                return Err(Error::Protocol(format!(
                    "listener overlap on {:?} port {}",
                    service_id, port
                )));
            }
        }

        let listener_id = loop {
            let id = self.listener_next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 && !listeners.contains_key(&id) {
                break id;
            }
        };
        let listener = Listener {
            id: listener_id,
            service_id,
            mode,
            port: port.to_string(),
            options,
        };
        let (tx, rx) = mpsc::channel(64);
        listeners.insert(
            listener_id,
            Arc::new(ListenerState {
                listener: listener.clone(),
                tx: Mutex::new(Some(tx)),
                rx: Mutex::new(rx),
            }),
        );
        log::info!("Listening on {:?} port {}", service_id, port);
        Ok(listener)
    }

    /// Accept the next incoming circuit connection.
    pub async fn circuit_accept(&self, listener_id: u32) -> Result<Connection> {
        let listener = {
            let listeners = self.listeners.lock().await;
            listeners
                .get(&listener_id)
                .cloned()
                .ok_or_else(|| Error::Protocol("unknown listener id".into()))?
        };
        let mut rx = listener.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::Protocol("listener channel closed".into()))
    }

    pub async fn circuit_close_listener(&self, listener_id: u32) -> Result<()> {
        let removed = self.listeners.lock().await.remove(&listener_id);
        match removed {
            Some(listener) => {
                listener.tx.lock().await.take();
                listener.rx.lock().await.close();
                Ok(())
            }
            None => Err(Error::Protocol("unknown listener id".into())),
        }
    }

    pub(super) async fn has_matching_listener(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
    ) -> bool {
        let listeners = self.listeners.lock().await;
        listeners
            .values()
            .any(|listener| listener_matches(&listener.listener, service_id, mode, port))
    }

    pub(super) async fn dispatch_incoming_connection(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        conn: Connection,
    ) -> ListenerDispatch {
        let listeners = {
            let listeners = self.listeners.lock().await;
            let mut matches: Vec<_> = listeners
                .values()
                .filter(|listener| listener_matches(&listener.listener, service_id, mode, port))
                .cloned()
                .collect();
            matches.sort_by_key(|listener| listener.listener.id);
            matches
        };

        if listeners.is_empty() {
            return ListenerDispatch::NoListener;
        }

        let index = if listeners.len() == 1 {
            0
        } else {
            (self.listener_rr.fetch_add(1, Ordering::Relaxed) as usize) % listeners.len()
        };

        let tx = listeners[index].tx.lock().await.clone();
        match tx {
            Some(tx) => match tx.try_send(conn) {
                Ok(()) => ListenerDispatch::Enqueued,
                Err(_) => ListenerDispatch::QueueFull,
            },
            None => ListenerDispatch::NoListener,
        }
    }

    /// Publish a hidden service with introduction points.
    pub async fn publish_hidden_service(
        &self,
        service_id: tarnet_api::types::ServiceId,
        num_intro_points: usize,
    ) -> Result<()> {
        let connected = self.connected_peers().await;
        if connected.is_empty() {
            return Err(Error::Protocol(
                "no connected peers for intro points".into(),
            ));
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

                let encoded = encode_circuit_relay_cell(cid, &cell);
                self.send_to_peer_critical(&fh, &encoded).await?;
            }

            // Wait for IntroRegistered
            let (tx, rx) = oneshot::channel();
            self.circuits
                .pending_extends
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
        self.hidden
            .intros
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
                    crate::identity::Keypair::from_full_bytes(&self.identity.to_full_bytes())
                        .unwrap()
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

    /// Re-publish every owned, published TNS zone label so names stay resolvable.
    ///
    /// TNS zones are published once by the operator (via `tns_set_label` /
    /// `tns_publish`); the label DB (`publish = true`) is the durable source of
    /// truth, while the DHT copy is soft state that now honours its TTL. Without
    /// this loop a name would resolve only for one TTL and then vanish — the old
    /// behaviour where it lived forever was an artifact of replication resetting
    /// the record clock, not a design feature. Mirrors `maintain_peer_records`:
    /// each round re-mints with a fresh sequence (so it supersedes the prior
    /// copy) and a full TTL; stopping the daemon — or removing the label — lets
    /// the name expire within one TTL.
    pub(super) async fn maintain_tns_zones(&self) {
        let Some(db) = self.db.clone() else { return };

        if self.connected_peers().await.is_empty() {
            log::debug!("maintain_tns_zones: no peers, skipping");
            return;
        }

        // Snapshot (identity label, owned keypair) pairs up front so we hold the
        // identity_store lock only briefly — not across the DB reads / async
        // publishes below. The label DB is keyed by the identity's label, which
        // is exactly what `identity_store.list()` yields.
        let identities: Vec<(String, crate::identity::Keypair)> = {
            let is = self.identity_store.lock().await;
            is.list()
                .into_iter()
                .filter_map(|(label, sid, ..)| {
                    is.keypair_for(&sid).map(|kp| {
                        (
                            label,
                            crate::identity::Keypair::from_full_bytes(&kp.to_full_bytes())
                                .expect("round-trip of a stored keypair"),
                        )
                    })
                })
                .collect()
        };

        let mut republished = 0usize;
        for (id_label, keypair) in &identities {
            let labels = match db.label_list(id_label) {
                Ok(labels) => labels,
                Err(e) => {
                    log::warn!("maintain_tns_zones: label_list({}) failed: {}", id_label, e);
                    continue;
                }
            };
            for (label, blobs, publish) in labels {
                if !publish {
                    continue;
                }
                let records: Vec<crate::tns::TnsRecord> = blobs
                    .iter()
                    .filter_map(|b| crate::tns::tns_record_from_bytes(b).ok().map(|(r, _)| r))
                    .collect();
                if records.is_empty() {
                    continue;
                }
                match crate::tns::publish(self, keypair, &label, &records, TNS_REPUBLISH_TTL).await {
                    Ok(()) => republished += 1,
                    Err(e) => log::warn!(
                        "maintain_tns_zones: republish {}/{} failed: {}",
                        id_label,
                        label,
                        e
                    ),
                }
            }
        }
        if republished > 0 {
            log::debug!("Republished {} TNS label(s)", republished);
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

            match self
                .publish_hidden_service(sid, desired_intros as usize)
                .await
            {
                Ok(()) => {
                    self.hidden
                        .last_publish
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
    pub(super) async fn handle_introduce_at_service(&self, intro_circuit_id: u32, payload: &[u8]) {
        // Resolve which hidden service this INTRODUCE is for. The cell arrived on
        // the circuit we built to an intro point when publishing one specific
        // service, so map that circuit back to the owning service. Using the
        // default identity here would decrypt with the wrong key for every
        // non-default hidden service and silently drop the connection.
        let service_sid = {
            let intros = self.hidden.intros.lock().await;
            intros.iter().find_map(|(sid, circuits)| {
                circuits
                    .iter()
                    .any(|(_, cid)| *cid == intro_circuit_id)
                    .then_some(*sid)
            })
        };
        let service_sid = match service_sid {
            Some(sid) => sid,
            None => {
                log::debug!(
                    "INTRODUCE on circuit {} not owned by any hidden service, dropping",
                    intro_circuit_id
                );
                return;
            }
        };

        // Decrypt the INTRODUCE payload using that service's KEM keypair.
        // The client encrypted it to our KEM public key so the intro point can't read it.
        let service_keypair = {
            let is = self.identity_store.lock().await;
            match is.keypair_for(&service_sid) {
                Some(kp) => crate::identity::Keypair::from_full_bytes(&kp.to_full_bytes()).unwrap(),
                None => {
                    log::debug!(
                        "No keypair for hidden service {:?}, dropping INTRODUCE",
                        service_sid
                    );
                    return;
                }
            }
        };

        let (rendezvous_peer, cookie, mode, port, shared_secret) =
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
        let circuit_id = match self
            .build_circuit(rendezvous_peer, vec![rendezvous_peer])
            .await
        {
            Ok(id) => id,
            Err(e) => {
                log::debug!("Failed to build circuit to rendezvous: {}", e);
                return;
            }
        };
        let mut attempt = self.circuit_attempt_guard(circuit_id);

        let (ready_tx, ready_rx) = oneshot::channel();
        self.circuits
            .pending_extends
            .lock()
            .await
            .insert(circuit_id, ready_tx);

        // Encode JOIN with the rendezvous keys, but install the e2e receiver
        // before sending it: the client may answer immediately.
        let join_cell = RelayCell {
            command: RelayCellCommand::RendezvousJoin,
            stream_id: 0,
            data: cookie.to_vec(),
        };
        let (fh, cid, cell) = {
            let mut circuits = self.circuits.outbound.lock().await;
            let Some(circuit) = circuits.get_mut(&circuit_id) else {
                return;
            };
            let encoded = circuit.send_relay_cell(&join_cell);
            circuit.hop_keys = vec![crate::circuit::HopKey::from_shared_secret_responder(
                &shared_secret,
            )];
            circuit.nonce_domain = rand::random();
            encoded
        };
        let conn = self
            .circuit_connection(service_sid, mode, &port, circuit_id)
            .await;
        let encoded = encode_circuit_relay_cell(cid, &cell);
        if let Err(e) = self.send_to_peer_critical(&fh, &encoded).await {
            log::debug!("Failed to send RendezvousJoin: {}", e);
            return;
        }

        // Do not expose the backend until the client has installed e2e keys
        // and its receive channel. Ready is retried and acknowledged by the client.
        if !matches!(
            tokio::time::timeout(Duration::from_secs(60), ready_rx).await,
            Ok(Ok(_))
        ) {
            log::debug!("Hidden-service client did not become ready");
            return;
        }
        attempt.armed = false;
        let port_name = conn.port.clone();
        match self
            .dispatch_incoming_connection(service_sid, mode, &port_name, conn)
            .await
        {
            ListenerDispatch::Enqueued => {}
            ListenerDispatch::NoListener => {
                log::debug!(
                    "Dropping hidden-service connection: no listener for {:?}",
                    service_sid
                );
            }
            ListenerDispatch::QueueFull => {
                log::warn!(
                    "Dropping hidden-service connection: listener queue full for {:?}",
                    service_sid
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        reuse_port: bool,
    ) -> Listener {
        Listener {
            id: 1,
            service_id,
            mode,
            port: port.to_string(),
            options: ListenerOptions { reuse_port },
        }
    }

    #[test]
    fn listener_matching_and_overlap_follow_wildcards() {
        let mode = tarnet_api::service::PortMode::ReliableOrdered;
        let exact = listener(tarnet_api::types::ServiceId::LOCAL, mode, "80", false);
        let any_port = listener(tarnet_api::types::ServiceId::LOCAL, mode, ANY_PORT, false);
        let any_service = listener(tarnet_api::types::ServiceId::ALL, mode, "80", false);

        assert!(listener_matches(
            &exact,
            tarnet_api::types::ServiceId::LOCAL,
            mode,
            "80"
        ));
        assert!(!listener_matches(
            &exact,
            tarnet_api::types::ServiceId::LOCAL,
            mode,
            "81"
        ));
        assert!(listener_matches(
            &any_port,
            tarnet_api::types::ServiceId::LOCAL,
            mode,
            "81"
        ));
        assert!(listener_matches(
            &any_service,
            tarnet_api::types::ServiceId::LOCAL,
            mode,
            "80"
        ));

        assert!(listeners_overlap(&exact, &any_port));
        assert!(listeners_overlap(&exact, &any_service));
        assert!(!listeners_overlap(
            &exact,
            &listener(tarnet_api::types::ServiceId::LOCAL, mode, "81", false)
        ));
        assert!(!listeners_overlap(
            &exact,
            &listener(
                tarnet_api::types::ServiceId::LOCAL,
                tarnet_api::service::PortMode::UnreliableUnordered,
                "80",
                false,
            )
        ));
    }
}
