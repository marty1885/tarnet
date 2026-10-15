use super::*;

impl Node {
    pub async fn create_identity(
        &self,
        label: &str,
        privacy: tarnet_api::types::PrivacyLevel,
        outbound_hops: u8,
        scheme: tarnet_api::types::IdentityScheme,
    ) -> Result<tarnet_api::types::ServiceId> {
        let sid = self
            .identity_store
            .lock()
            .await
            .create(label, privacy, outbound_hops, scheme)
            .map_err(|e| Error::Protocol(e.to_string()))?;

        // Write-through: persist the new identity
        if let Some(db) = &self.db {
            let is = self.identity_store.lock().await;
            if let Some(id_entry) = is.get(label) {
                let id_kp = &id_entry.keypair;
                let pi = PersistedIdentity {
                    label: label.to_string(),
                    scheme: id_kp.scheme() as u8,
                    signing_key_material: id_kp.identity.signing.to_bytes(),
                    kem_key_material: id_kp.identity.kem.to_bytes(),
                    signing_algo: id_kp.identity.signing_algo() as u8,
                    kem_algo: id_kp.identity.kem_algo() as u8,
                    privacy,
                    outbound_hops,
                    is_default: label == "default",
                };
                drop(is);
                if let Err(e) = db.save_identity(&pi) {
                    log::error!("Failed to persist new identity '{}' to disk: {}", label, e);
                }
            }
        }

        match privacy {
            tarnet_api::types::PrivacyLevel::Hidden { intro_points } => {
                match self
                    .publish_hidden_service(sid, intro_points as usize)
                    .await
                {
                    Ok(()) => {
                        self.hidden
                            .last_publish
                            .lock()
                            .await
                            .insert(sid, Instant::now());
                    }
                    Err(e) => {
                        log::warn!(
                            "Immediate hidden service publish for '{}' failed (will retry): {}",
                            label,
                            e
                        );
                    }
                }
            }
            tarnet_api::types::PrivacyLevel::Public => {
                if let Err(e) = self.publish_peer_record(sid).await {
                    log::warn!(
                        "Immediate peer record publish for '{}' failed (will retry): {}",
                        label,
                        e
                    );
                }
            }
        }

        Ok(sid)
    }

    /// List all identities: (label, service_id, privacy, outbound_hops, scheme, signing_algo, kem_algo).
    pub async fn list_identities(
        &self,
    ) -> Vec<(
        String,
        tarnet_api::types::ServiceId,
        tarnet_api::types::PrivacyLevel,
        u8,
        tarnet_api::types::IdentityScheme,
        tarnet_api::types::SigningAlgo,
        tarnet_api::types::KemAlgo,
    )> {
        self.identity_store.lock().await.list()
    }

    /// Update an identity's privacy and outbound_hops.
    /// Returns the previous (privacy, outbound_hops).
    /// Handles privacy transitions: publishes intro points when switching to Hidden,
    /// tears them down when switching to Public.
    pub async fn update_identity(
        &self,
        label: &str,
        privacy: tarnet_api::types::PrivacyLevel,
        outbound_hops: u8,
    ) -> Result<(tarnet_api::types::PrivacyLevel, u8)> {
        let (old_privacy, old_hops) = self
            .identity_store
            .lock()
            .await
            .update(label, privacy, outbound_hops)
            .map_err(|e| Error::Protocol(e.to_string()))?;

        // Write-through: persist updated identity
        if let Some(db) = &self.db {
            let is = self.identity_store.lock().await;
            if let Some(id_entry) = is.get(label) {
                let id_kp = &id_entry.keypair;
                let pi = PersistedIdentity {
                    label: label.to_string(),
                    scheme: id_kp.scheme() as u8,
                    signing_key_material: id_kp.identity.signing.to_bytes(),
                    kem_key_material: id_kp.identity.kem.to_bytes(),
                    signing_algo: id_kp.identity.signing_algo() as u8,
                    kem_algo: id_kp.identity.kem_algo() as u8,
                    privacy,
                    outbound_hops,
                    is_default: label == "default",
                };
                drop(is);
                if let Err(e) = db.save_identity(&pi) {
                    log::error!("Failed to persist updated identity '{}' to disk: {}", label, e);
                }
            }
        }

        // Resolve ServiceId for this identity
        let sid = self
            .identity_store
            .lock()
            .await
            .get(label)
            .map(|id| id.service_id());

        if let Some(sid) = sid {
            use tarnet_api::types::PrivacyLevel as PL;
            match (old_privacy, privacy) {
                // Public → Hidden: publish intro points
                (PL::Public, PL::Hidden { intro_points }) => {
                    match self
                        .publish_hidden_service(sid, intro_points as usize)
                        .await
                    {
                        Ok(()) => {
                            self.hidden
                                .last_publish
                                .lock()
                                .await
                                .insert(sid, Instant::now());
                        }
                        Err(e) => {
                            log::warn!(
                                "Hidden service publish after update of '{}' failed (will retry): {}",
                                label, e
                            );
                        }
                    }
                }
                // Hidden → Public: tear down intro points, publish peer record
                (PL::Hidden { .. }, PL::Public) => {
                    self.teardown_hidden_service(&sid).await;
                    if let Err(e) = self.publish_peer_record(sid).await {
                        log::warn!(
                            "Peer record publish after Hidden→Public for '{}' failed (will retry): {}",
                            label, e
                        );
                    }
                }
                // Hidden → Hidden with different intro count: rebuild
                (
                    PL::Hidden {
                        intro_points: old_n,
                    },
                    PL::Hidden {
                        intro_points: new_n,
                    },
                ) if old_n != new_n => {
                    self.teardown_hidden_service(&sid).await;
                    match self.publish_hidden_service(sid, new_n as usize).await {
                        Ok(()) => {
                            self.hidden
                                .last_publish
                                .lock()
                                .await
                                .insert(sid, Instant::now());
                        }
                        Err(e) => {
                            log::warn!(
                                "Hidden service re-publish for '{}' failed (will retry): {}",
                                label,
                                e
                            );
                        }
                    }
                }
                _ => {} // No transition needed
            }
        }

        Ok((old_privacy, old_hops))
    }

    /// Delete an identity by label.
    /// Tears down hidden services and removes from store + database.
    pub async fn delete_identity(&self, label: &str) -> Result<()> {
        // Get the ServiceId before removing so we can clean up.
        let sid = self
            .identity_store
            .lock()
            .await
            .get(label)
            .map(|id| id.service_id())
            .ok_or_else(|| Error::Protocol("identity not found".to_string()))?;

        // Tear down hidden service if it was running.
        self.teardown_hidden_service(&sid).await;

        // Remove from in-memory store.
        self.identity_store
            .lock()
            .await
            .remove(label)
            .map_err(|e| Error::Protocol(e.to_string()))?;

        // Remove from database.
        if let Some(db) = &self.db {
            if let Err(e) = db.delete_identity(label) {
                log::error!("Failed to delete identity '{}' from disk: {}", label, e);
            }
        }

        Ok(())
    }

    pub async fn create_hello_record(&self) -> HelloRecord {
        let global_addrs = self.global_addrs.lock().await.clone();
        let introducers = self.introducers.lock().await.clone();
        let mut transports = collect_transport_types(&global_addrs);
        if self.webrtc_connector.is_some()
            && !transports.iter().any(|t| *t == TransportType::WebRtc)
        {
            transports.push(TransportType::WebRtc);
        }
        HelloRecord {
            peer_id: self.peer_id(),
            capabilities: capabilities::RELAY
                | capabilities::TUNNEL
                | self.landmark_capabilities().await,
            signaling_secret: self.signaling_secret,
            transports,
            introducers,
            global_addresses: global_addrs,
        }
    }

    /// Next monotonic hello sequence, persisted so it survives restart.
    async fn next_hello_sequence(&self) -> u64 {
        let mut seq = self.hello_sequence.lock().await;
        *seq += 1;
        let sequence = *seq;
        self.db_set_metadata("hello_sequence", sequence);
        sequence
    }

    /// Publish our hello record to the local DHT store and send PUT walks.
    pub async fn publish_hello(&self) {
        let hello = self.create_hello_record().await;
        let sequence = self.next_hello_sequence().await;
        let record = crate::dht::VerifiedRecord::new_hello(
            &self.identity,
            &hello.to_bytes(),
            sequence,
            Duration::from_secs(HELLO_TTL as u64),
        );
        if let Err(e) = self.dht_publish(record).await {
            log::warn!("Hello record not published: {}", e);
            return;
        }
        log::info!(
            "Published hello record ({} global addrs, {} introducers)",
            hello.global_addresses.len(),
            hello.introducers.len()
        );
    }

    /// Look up a peer's hello record from the local DHT store.
    pub async fn lookup_hello(&self, peer_id: &PeerId) -> Option<HelloRecord> {
        self.dht_store.lock().await.hello_of(peer_id)
    }

    /// A peer's hello record: from the local store, else searched for in the
    /// DHT until `timeout`.
    pub async fn find_hello(&self, peer_id: &PeerId, timeout: Duration) -> Option<HelloRecord> {
        if let Some(hello) = self.lookup_hello(peer_id).await {
            return Some(hello);
        }
        let mut search = self.dht_search_hello(peer_id, Instant::now() + timeout).await;
        loop {
            if let Some(hello) = self.lookup_hello(peer_id).await {
                return Some(hello);
            }
            search.next().await?;
        }
    }

    /// Send GET walks for a peer's hello record.
    /// Uses anonymous query token routing for reply privacy.
    pub async fn request_hello(&self, target: &PeerId) -> Result<()> {
        let key = crate::dht::identity_address_key(target);
        self.dht_walker.launch_get(key.as_bytes(), None).await;
        Ok(())
    }
}
