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

/// Rendezvous points a client tries before giving up.
const RENDEZVOUS_ATTEMPTS: usize = 3;
/// How long a client waits for the service to join at the rendezvous
/// point: the service builds a multi-hop circuit first.
const JOIN_TIMEOUT: Duration = Duration::from_secs(20);
/// Rounds of relays tried when registering intro points.
const INTRO_ROUNDS: usize = 3;

impl Node {
    /// The neighbour to send a CREATE for `dest` to, using `hints` when we
    /// have no route.
    async fn first_hop_toward(&self, dest: &PeerId, hints: &[PeerId]) -> Option<PeerId> {
        self.next_hop_toward(dest, hints, &self.peer_id()).await
    }

    /// Build a circuit to `target` through `hops - 1` random waypoints first,
    /// reaching `target` with `target_hints` if given. Fails rather than
    /// using fewer waypoints.
    pub(super) async fn build_private_circuit(
        &self,
        target: PeerId,
        target_hints: &[PeerId],
        hops: usize,
        exclude: &[PeerId],
    ) -> Result<u32> {
        // Intro records carry no hints: reach the target by its address.
        let target_hints = if target_hints.is_empty() {
            self.relay_hints(&target).await
        } else {
            target_hints.to_vec()
        };
        let target_hints = target_hints.as_slice();
        let mut avoid = exclude.to_vec();
        avoid.push(target);
        let want = hops.saturating_sub(1);
        let mut waypoints = self.pick_relays(want, &avoid).await;
        if waypoints.len() < want {
            return Err(Error::Protocol(format!(
                "{} relays needed for {} hops, {} known",
                want,
                hops,
                waypoints.len()
            )));
        }
        let first_hints = if waypoints.is_empty() {
            target_hints.to_vec()
        } else {
            self.relay_hints(&waypoints[0]).await
        };
        waypoints.push(target);
        let first_hop = self
            .first_hop_toward(&waypoints[0], &first_hints)
            .await
            .ok_or_else(|| Error::Protocol(format!("no route to {:?}", waypoints[0])))?;
        self.build_circuit_hinted(first_hop, waypoints, target_hints)
            .await
    }

    /// An identity's hop count (1 for unknown identities).
    pub(super) async fn identity_hops(&self, sid: &tarnet_api::types::ServiceId) -> usize {
        self.identity_store
            .lock()
            .await
            .get_by_service_id(sid)
            .map_or(1, |id| id.outbound_hops.max(1) as usize)
    }

    /// Seal a relay message to a circuit's last hop and send it.
    async fn send_on_circuit(&self, circuit_id: u32, message: &RelayCell) -> Result<()> {
        let (first_hop, cid, cells) = {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits
                .get_mut(&circuit_id)
                .ok_or_else(|| Error::Protocol("circuit disappeared".into()))?;
            circuit.send_relay_message(message)?
        };
        for cell in &cells {
            self.send_to_peer_critical(&first_hop, &encode_circuit_relay_cell(cid, cell))
                .await?;
        }
        Ok(())
    }

    /// Connect to a hidden service through one of its intro points. `hops` is
    /// the client's hop count to the intro and rendezvous points. A
    /// rendezvous point that doesn't work out (for instance the service's own
    /// host) is replaced by another.
    pub async fn connect_via_rendezvous(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        intro_points: &[(PeerId, u8, Vec<u8>)],
        hops: usize,
    ) -> Result<tarnet_api::service::Connection> {
        if intro_points.is_empty() {
            return Err(Error::Protocol(
                "no introduction points for rendezvous".into(),
            ));
        }
        let mut tried = Vec::new();
        let mut last_err = Error::Protocol("no rendezvous point available".into());
        for _ in 0..RENDEZVOUS_ATTEMPTS {
            match self
                .try_rendezvous(service_id, mode, port, intro_points, hops, &mut tried)
                .await
            {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    log::debug!("Rendezvous attempt for {:?} failed: {}", service_id, e);
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    async fn try_rendezvous(
        &self,
        service_id: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        intro_points: &[(PeerId, u8, Vec<u8>)],
        hops: usize,
        tried: &mut Vec<PeerId>,
    ) -> Result<tarnet_api::service::Connection> {
        use rand::seq::SliceRandom;
        let (intro_peer, kem_algo_byte, kem_pubkey) = intro_points
            .choose(&mut rand::thread_rng())
            .expect("intro points checked non-empty")
            .clone();

        // Rendezvous point: a random relay, preferably not the intro point.
        let mut avoid = tried.clone();
        avoid.push(intro_peer);
        let mut rp = self.pick_relays(1, &avoid).await;
        if rp.is_empty() {
            rp = self.pick_relays(1, tried).await;
        }
        let rendezvous_peer = *rp
            .first()
            .ok_or_else(|| Error::Protocol("no relay for a rendezvous point".into()))?;
        tried.push(rendezvous_peer);
        // How to reach it: only nodes near the rendezvous point, so the
        // service learns nothing about where we are.
        let rendezvous_hints = self.relay_hints(&rendezvous_peer).await;

        let mut cookie = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cookie);

        let rend_circuit_id = self
            .build_private_circuit(rendezvous_peer, &rendezvous_hints, hops, &[intro_peer])
            .await?;
        let mut rend_attempt = self.circuit_attempt_guard(rend_circuit_id);
        self.send_on_circuit(
            rend_circuit_id,
            &RelayCell {
                command: RelayCellCommand::RendezvousEstablish,
                stream_id: 0,
                data: build_rendezvous_establish_payload(&cookie),
            },
        )
        .await?;

        // We may be one of the service's intro points ourselves; then the
        // INTRODUCE needs no circuit.
        let intro_circuit_id = if intro_peer == self.peer_id() {
            None
        } else {
            Some(
                self.build_private_circuit(intro_peer, &[], hops, &[rendezvous_peer])
                    .await?,
            )
        };
        let _intro_attempt = intro_circuit_id.map(|id| self.circuit_attempt_guard(id));

        // Seal the introduction to the service's KEM key; only the service
        // can read it. A fresh client key lets the service's answer give the
        // end-to-end key forward secrecy.
        let kem_algo = tarnet_api::types::KemAlgo::from_u8(kem_algo_byte)
            .map_err(|e| Error::Protocol(format!("intro point unknown KEM algo: {}", e)))?;
        let (static_secret, kem_ciphertext) =
            crate::identity::KemKeypair::encapsulate_to(&kem_pubkey, kem_algo)
                .map_err(|e| Error::Crypto(format!("INTRODUCE KEM encapsulate failed: {}", e)))?;
        let client_kex = KexOffer::new(self.identity.identity.kem_algo());
        let introduction = crate::circuit::Introduction {
            rendezvous: rendezvous_peer,
            rendezvous_hints: rendezvous_hints.clone(),
            cookie,
            mode,
            port: port.to_string(),
            client_kem_algo: client_kex.algo_byte(),
            client_eph_pk: client_kex.pubkey_bytes(),
        };
        let sealed = build_introduce_payload(&introduction, &kem_ciphertext, &static_secret);

        // Register receivers before sending: replies may be immediate.
        let (joined_tx, joined_rx) = oneshot::channel();
        self.circuits
            .pending_extends
            .lock()
            .await
            .insert(rend_circuit_id, joined_tx);
        match intro_circuit_id {
            Some(intro_circuit_id) => {
                let (ack_tx, ack_rx) = oneshot::channel();
                self.circuits
                    .pending_extends
                    .lock()
                    .await
                    .insert(intro_circuit_id, ack_tx);
                self.send_on_circuit(
                    intro_circuit_id,
                    &RelayCell {
                        command: RelayCellCommand::Introduce,
                        stream_id: 0,
                        data: build_introduce_cell(&service_id, &[], &sealed),
                    },
                )
                .await?;
                tokio::time::timeout(Duration::from_secs(10), ack_rx)
                    .await
                    .map_err(|_| Error::Protocol("IntroduceAck timeout".into()))?
                    .map_err(|_| Error::Protocol("IntroduceAck channel dropped".into()))?;
            }
            None => {
                if !self.forward_introduce(&service_id, &sealed).await {
                    return Err(Error::Protocol("service not registered at our intro point".into()));
                }
            }
        }
        let join = tokio::time::timeout(JOIN_TIMEOUT, joined_rx)
            .await
            .map_err(|_| Error::Protocol("RendezvousJoined timeout".into()))?
            .map_err(|_| Error::Protocol("RendezvousJoined channel dropped".into()))?;

        // The service proves it read the introduction and answered our key.
        let (join_ct, confirm) = crate::circuit::parse_join(&join)?;
        let eph_secret = client_kex.complete(join_ct)?;
        let (e2e, expected) =
            crate::circuit::rendezvous_keys(&static_secret, &eph_secret, &sealed, join_ct);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&confirm[..], &expected[..])) {
            return Err(Error::Crypto("rendezvous confirmation failed".into()));
        }
        {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits
                .get_mut(&rend_circuit_id)
                .ok_or_else(|| Error::Protocol("rendezvous circuit disappeared".into()))?;
            // The end-to-end layer rides inside every hop's layer.
            circuit.layers.push(e2e);
        }
        log::info!(
            "Rendezvous established for {:?} on circuit_id={}",
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
        if let Some(intro_circuit_id) = intro_circuit_id {
            self.destroy_circuit(intro_circuit_id).await?;
        }
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

    /// Publish a hidden service with introduction points: random relays,
    /// each reached by a circuit with the service identity's hop count and
    /// registered with a signature bound to that circuit.
    pub async fn publish_hidden_service(
        &self,
        service_id: tarnet_api::types::ServiceId,
        num_intro_points: usize,
    ) -> Result<()> {
        let zone_keypair = {
            let is = self.identity_store.lock().await;
            let kp = is
                .keypair_for(&service_id)
                .ok_or_else(|| Error::Protocol("no keypair for hidden service".into()))?;
            crate::identity::Keypair::from_full_bytes(&kp.to_full_bytes()).unwrap()
        };
        // A Hidden identity has no peer record. Drop it before anything can
        // fail, and re-sign at once, so a root naming this host is never
        // signed again (copies already out there expire).
        self.drop_zone_label(&service_id, "peer").await;
        let hops = self.identity_hops(&service_id).await;
        let mut intro_records = Vec::new();
        let mut intro_circuits: Vec<(PeerId, u32)> = Vec::new();
        let mut tried: Vec<PeerId> = Vec::new();
        // A build to a sampled relay can fail (a lost CREATE, stale hints):
        // try others rather than publish fewer intro points, a few rounds.
        for _ in 0..INTRO_ROUNDS {
            let want = num_intro_points.saturating_sub(intro_circuits.len());
            if want == 0 {
                break;
            }
            let candidates = self.pick_relays(want, &tried).await;
            if candidates.is_empty() {
                break;
            }
            for intro_peer in candidates {
                tried.push(intro_peer);
                match self
                    .register_intro_point(&zone_keypair, service_id, intro_peer, hops)
                    .await
                {
                    Ok(circuit_id) => {
                        log::info!(
                            "Intro point registered: {:?} on circuit_id={}",
                            intro_peer,
                            circuit_id,
                        );
                        intro_records.push(crate::tns::TnsRecord::IntroductionPoint {
                            relay_peer_id: intro_peer,
                            kem_algo: zone_keypair.identity.kem_algo() as u8,
                            kem_pubkey: zone_keypair.identity.kem.kem_pubkey_bytes(),
                        });
                        intro_circuits.push((intro_peer, circuit_id));
                    }
                    Err(e) => log::info!("Intro point {:?} failed: {}", intro_peer, e),
                }
            }
        }
        if intro_circuits.is_empty() {
            // Stop advertising intro points that lead nowhere. The zone's
            // other labels are kept alive by `maintain_hidden_service`.
            self.drop_zone_label(&service_id, "intro").await;
            return Err(Error::Protocol(if tried.is_empty() {
                "no relays for intro points".into()
            } else {
                "no intro point could be registered".into()
            }));
        }
        let count = intro_circuits.len();
        self.hidden
            .intros
            .lock()
            .await
            .insert(service_id, intro_circuits);

        let intro = crate::tns::serialize_record_set(&intro_records);
        // Re-signs the zone publication even if the intro set is unchanged: this is
        // the hidden zone's refresh timer.
        crate::tns::set_zone_label(self, &zone_keypair, "intro", Some(intro)).await?;
        crate::tns::refresh_zone(self, &zone_keypair).await?;

        log::info!(
            "Hidden service published: {:?} with {} intro points",
            service_id,
            count,
        );
        Ok(())
    }

    /// The intro points a hidden service of ours is registered at (testing).
    #[doc(hidden)]
    pub async fn hidden_intro_peers(&self, service_id: &tarnet_api::types::ServiceId) -> Vec<PeerId> {
        self.hidden
            .intros
            .lock()
            .await
            .get(service_id)
            .map(|v| v.iter().map(|(peer, _)| *peer).collect())
            .unwrap_or_default()
    }

    /// Build a circuit to `intro_peer` and register the service there.
    async fn register_intro_point(
        &self,
        zone_keypair: &crate::identity::Keypair,
        service_id: tarnet_api::types::ServiceId,
        intro_peer: PeerId,
        hops: usize,
    ) -> Result<u32> {
        let circuit_id = self.build_private_circuit(intro_peer, &[], hops, &[]).await?;
        let mut attempt = self.circuit_attempt_guard(circuit_id);
        let transcript = self
            .circuits
            .outbound
            .lock()
            .await
            .get(&circuit_id)
            .and_then(|c| c.transcripts.last().copied())
            .ok_or_else(|| Error::Protocol("circuit disappeared".into()))?;
        let sig = zone_keypair.sign(&crate::circuit::intro_register_message(&intro_peer, &transcript));
        let register = RelayCell {
            command: RelayCellCommand::IntroRegister,
            stream_id: 0,
            data: build_intro_register_payload(
                &service_id,
                &zone_keypair.identity.signing.signing_pubkey_bytes(),
                &sig,
            ),
        };
        let (tx, rx) = oneshot::channel();
        self.circuits
            .pending_extends
            .lock()
            .await
            .insert(circuit_id, tx);
        self.send_on_circuit(circuit_id, &register).await?;
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| Error::Protocol("IntroRegister timeout".into()))?
            .map_err(|_| Error::Protocol("IntroRegister channel dropped".into()))?;
        attempt.armed = false;
        Ok(circuit_id)
    }

    /// Drop one of the identity's own labels (`peer`, `intro`) from its zone,
    /// re-signing the root without it if it was there. Unlike
    /// [`crate::tns::set_zone_label`] the drop sticks even if the re-sign
    /// fails: a Hidden zone's `peer` label must never be signed again.
    pub(super) async fn drop_zone_label(
        &self,
        service_id: &tarnet_api::types::ServiceId,
        label: &str,
    ) {
        let Some(kp) = self.keypair_for_service(service_id).await else {
            return;
        };
        if let Err(e) = crate::tns::retire_zone_label(self, &kp, label).await {
            log::warn!(
                "Retiring zone {:?} label '{}' failed: {}",
                service_id,
                label,
                e
            );
        }
    }

    /// Tear down all intro circuits for a hidden service and remove tracking
    /// state, including its intro points in its zone.
    pub(super) async fn teardown_hidden_service(&self, service_id: &tarnet_api::types::ServiceId) {
        self.drop_zone_label(service_id, "intro").await;
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
        // Re-signs the zone publication, with every label the zone publishes: this
        // is the zone's refresh timer.
        let peer = crate::tns::serialize_record_set(&[record]);
        crate::tns::set_zone_label(self, &zone_keypair, "peer", Some(peer)).await?;
        crate::tns::refresh_zone(self, &zone_keypair).await?;

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

    /// Start a maintenance task for every Hidden identity that lacks one.
    ///
    /// Each identity gets its own task with its own random timing. A single
    /// loop republishing all of them back to back would link the identities:
    /// an observer seeing their intro records refreshed together learns they
    /// share a host.
    pub(super) async fn maintain_hidden_services(self: &Arc<Self>) {
        let hidden_identities: Vec<tarnet_api::types::ServiceId> = {
            let store = self.identity_store.lock().await;
            store
                .list()
                .into_iter()
                .filter_map(|(_, sid, privacy, _, _, _, _)| match privacy {
                    tarnet_api::types::PrivacyLevel::Hidden { .. } => Some(sid),
                    _ => None,
                })
                .collect()
        };

        let mut maintained = self.hidden.maintained.lock().await;
        for sid in hidden_identities {
            if maintained.insert(sid) {
                let node = self.clone();
                tokio::spawn(async move { node.maintain_hidden_service(sid).await });
            }
        }
    }

    /// Desired intro point count if `sid` is still a Hidden identity.
    async fn hidden_intro_points(&self, sid: &tarnet_api::types::ServiceId) -> Option<u8> {
        let store = self.identity_store.lock().await;
        store
            .list()
            .into_iter()
            .find_map(|(_, s, privacy, _, _, _, _)| match privacy {
                tarnet_api::types::PrivacyLevel::Hidden { intro_points } if s == *sid => {
                    Some(intro_points)
                }
                _ => None,
            })
    }

    /// Keep one Hidden identity's intro points alive until it stops being
    /// Hidden. Republishes when intro circuits have failed, or once the
    /// records are past a random point between a third and half of their TTL,
    /// drawn afresh after every publish.
    async fn maintain_hidden_service(&self, sid: tarnet_api::types::ServiceId) {
        use rand::Rng;
        // Intro labels and the key descriptor share this bounded lifetime.
        let ttl = Duration::from_secs(crate::tns::ZONE_ROOT_TTL as u64);
        let draw_republish_after = || rand::thread_rng().gen_range(ttl / 3..ttl / 2);
        let mut republish_after = draw_republish_after();
        let mut warned_no_intros = false;

        loop {
            let wait = rand::thread_rng().gen_range(HIDDEN_SERVICE_CHECK_INTERVAL);
            tokio::time::sleep(wait).await;

            let Some(desired_intros) = self.hidden_intro_points(&sid).await else {
                self.hidden.maintained.lock().await.remove(&sid);
                return;
            };

            // Hidden with no intro points: nobody can connect, but the zone's
            // other labels (delegations, aliases, text) are still served.
            if desired_intros == 0 {
                if !warned_no_intros {
                    log::warn!(
                        "Hidden identity {:?} has 0 intro points: it cannot be reached, only its names are published",
                        sid
                    );
                    warned_no_intros = true;
                }
                self.drop_zone_label(&sid, "intro").await;
                if self.refresh_zone_if_stale(sid, republish_after).await {
                    republish_after = draw_republish_after();
                }
                continue;
            }
            warned_no_intros = false;

            if self.connected_peers().await.is_empty() {
                log::debug!("maintain_hidden_service: no peers, skipping");
                continue;
            }

            let needs_publish = {
                let intros = self.hidden.intros.lock().await;
                let last_pub = self.hidden.last_publish.lock().await;
                let has_enough = intros
                    .get(&sid)
                    .map(|v| v.len() >= desired_intros as usize)
                    .unwrap_or(false);
                let stale = last_pub
                    .get(&sid)
                    .map(|t| t.elapsed() > republish_after)
                    .unwrap_or(true); // never published
                !has_enough || stale
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
                    republish_after = draw_republish_after();
                    log::info!("Hidden service {:?} maintained successfully", sid);
                }
                Err(e) => {
                    log::warn!("Failed to maintain hidden service {:?}: {}", sid, e);
                    // Keep the zone's other labels alive until intro points
                    // can be had again (which is retried every check).
                    if self.refresh_zone_if_stale(sid, republish_after).await {
                        republish_after = draw_republish_after();
                    }
                }
            }
        }
    }

    /// Re-sign a Hidden zone that has no intro points, if it was last signed
    /// longer than `republish_after` ago, so its other labels don't expire.
    /// Returns whether it was re-signed.
    async fn refresh_zone_if_stale(&self, sid: tarnet_api::types::ServiceId, republish_after: Duration) -> bool {
        let stale = self
            .hidden
            .last_publish
            .lock()
            .await
            .get(&sid)
            .map_or(true, |t| t.elapsed() > republish_after);
        if !stale {
            return false;
        }
        let Some(kp) = self.keypair_for_service(&sid).await else {
            return false;
        };
        if let Err(e) = crate::tns::refresh_zone(self, &kp).await {
            log::warn!("Re-signing hidden zone {:?} failed: {}", sid, e);
            return false;
        }
        self.hidden.last_publish.lock().await.insert(sid, Instant::now());
        true
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

        let digest = *blake3::hash(payload).as_bytes();
        if self.hidden.introduce_seen.lock().await.contains_key(&digest) {
            log::debug!("Replayed INTRODUCE for {:?}, dropping", service_sid);
            return;
        }
        let (intro, static_secret) =
            match parse_introduce_payload(payload, &service_keypair.identity.kem) {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("Failed to parse INTRODUCE at service: {}", e);
                    return;
                }
            };
        // Remembered only once it decrypted, so junk can't fill the table;
        // a racing copy loses here.
        if self.hidden.introduce_seen.lock().await.try_insert(digest, ()).is_err() {
            log::debug!("Replayed (or too many) INTRODUCE for {:?}, dropping", service_sid);
            return;
        }
        log::info!("Service received INTRODUCE: rendezvous={:?}", intro.rendezvous);

        // Answer the client's ephemeral key: the end-to-end key then needs
        // both it and the service key, which gives forward secrecy.
        let Ok(client_algo) = tarnet_api::types::KemAlgo::from_u8(intro.client_kem_algo) else {
            return;
        };
        let Ok((eph_secret, join_ct)) = kex_accept(client_algo, &intro.client_eph_pk) else {
            return;
        };
        let (e2e, confirm) =
            crate::circuit::rendezvous_keys(&static_secret, &eph_secret, payload, &join_ct);

        // The client may have picked our host as rendezvous point without
        // knowing it. Our circuit then goes out through a waypoint and back,
        // so nothing looks different from outside.
        let mut hops = self.identity_hops(&service_sid).await;
        if intro.rendezvous == self.peer_id() {
            hops = hops.max(2);
        }
        let circuit_id = match self
            .build_private_circuit(intro.rendezvous, &intro.rendezvous_hints, hops, &[])
            .await {
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

        // Seal JOIN to the rendezvous point, then add the end-to-end layer
        // before sending: the client may answer immediately.
        let join_cell = RelayCell {
            command: RelayCellCommand::RendezvousJoin,
            stream_id: 0,
            data: crate::circuit::build_rendezvous_join_payload(
                &intro.cookie,
                &crate::circuit::build_join(&join_ct, &confirm),
            ),
        };
        let sealed_join = {
            let mut circuits = self.circuits.outbound.lock().await;
            let Some(circuit) = circuits.get_mut(&circuit_id) else {
                return;
            };
            let Ok(sealed) = circuit.send_relay_message(&join_cell) else {
                return;
            };
            circuit.layers.push(e2e.responder());
            sealed
        };
        let (mode, port) = (intro.mode, intro.port);
        let conn = self
            .circuit_connection(service_sid, mode, &port, circuit_id)
            .await;
        let (fh, cid, cells) = sealed_join;
        for cell in &cells {
            if let Err(e) = self
                .send_to_peer_critical(&fh, &encode_circuit_relay_cell(cid, cell))
                .await
            {
                log::debug!("Failed to send RendezvousJoin: {}", e);
                return;
            }
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

    /// Link-up republish carries only the node's own records, never an
    /// identity's (a Hidden one's would let a watcher trigger it by opening a
    /// link to a suspected host): those have their owners' timers.
    #[tokio::test]
    async fn hidden_identity_records_are_not_event_republished() {
        use tarnet_api::types::{IdentityScheme, PrivacyLevel};

        let node = Node::new(Keypair::generate());
        let hidden = node
            .create_identity("h", PrivacyLevel::Hidden { intro_points: 1 }, 1, IdentityScheme::Ed25519)
            .await
            .unwrap();
        let public = node
            .create_identity("p", PrivacyLevel::Public, 1, IdentityScheme::Ed25519)
            .await
            .unwrap();
        let hidden_kp = node.keypair_for_service(&hidden).await.unwrap();
        let public_kp = node.keypair_for_service(&public).await.unwrap();
        for kp in [&hidden_kp, &public_kp] {
            let record = crate::dht::VerifiedRecord::new_zone_key(
                kp,
                node.next_dht_sequence().await,
                Duration::from_secs(600),
            );
            node.dht_publish(record).await.unwrap();
        }

        let signers: Vec<PeerId> = node
            .own_records_to_republish()
            .await
            .iter()
            .map(|r| r.signer)
            .collect();
        assert!(!signers.contains(&hidden_kp.peer_id()));
        assert!(!signers.contains(&public_kp.peer_id()));
        node.dht_put_signed_content(b"node's own", 600).await.unwrap();
        assert_eq!(node.own_records_to_republish().await.len(), 1);
    }
}
