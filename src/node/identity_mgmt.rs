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
                let pi = PersistedIdentity::from_keypair(
                    label,
                    id_kp,
                    privacy,
                    outbound_hops,
                    label == "default",
                );
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
        if self
            .identity_store
            .lock()
            .await
            .get(label)
            .is_some_and(|id| id.ephemeral)
        {
            return Err(Error::Protocol("throwaway identities are configured when created".into()));
        }
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
                let pi = PersistedIdentity::from_keypair(
                    label,
                    id_kp,
                    privacy,
                    outbound_hops,
                    label == "default",
                );
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
        let ephemeral = {
            let store = self.identity_store.lock().await;
            let id = store
                .get(label)
                .ok_or_else(|| Error::Protocol("identity not found".to_string()))?;
            id.ephemeral
        };
        if ephemeral {
            return Err(Error::Protocol("a throwaway identity is dropped, not deleted".into()));
        }
        self.remove_identity(label).await
    }

    /// The one teardown path, for deleted identities and dropped throwaways
    /// alike (`docs/spec/identity.md`, "Persistence invariants"): everything
    /// the identity holds goes, in memory and on disk. Records already out in
    /// the network run out their TTL; nothing announces the removal.
    async fn remove_identity(&self, label: &str) -> Result<()> {
        let (sid, signer) = {
            let store = self.identity_store.lock().await;
            let id = store
                .get(label)
                .ok_or_else(|| Error::Protocol("identity not found".to_string()))?;
            (id.service_id(), id.keypair.peer_id())
        };
        // Refuse the default before tearing anything down.
        if self.identity_store.lock().await.default_service_id() == sid {
            return Err(Error::Protocol("cannot delete the default identity".into()));
        }
        let db = self.db_for(&sid).await.cloned();

        // Hidden service: intro points, their circuits and refresh state.
        self.teardown_hidden_service(&sid).await;

        // Listeners bound to it.
        let listener_ids: Vec<u32> = self
            .listeners
            .lock()
            .await
            .iter()
            .filter(|(_, l)| l.listener.service_id == sid)
            .map(|(id, _)| *id)
            .collect();
        for id in listener_ids {
            let _ = self.circuit_close_listener(id).await;
        }

        // Its zone's working set: nothing re-signs or refreshes it again.
        self.zone_published.lock().await.remove(&sid);
        self.tns_cache().lock().await.forget_zone(&sid);

        // Its own DHT records stop being republished and leave the database.
        self.ephemeral_sequences.lock().unwrap().remove(&sid);
        let mut owned = self.ephemeral_records.lock().await.remove(&sid).unwrap_or_default();
        {
            let mut store = self.dht_store.lock().await;
            owned.extend(store.local_records_by(&signer));
            for (key, signer) in &owned {
                store.forget_local(key, signer);
            }
        }

        // Out of the store; its keys are erased on drop.
        self.identity_store
            .lock()
            .await
            .remove(label)
            .map_err(|e| Error::Protocol(e.to_string()))?;

        if let Some(db) = db {
            if let Err(e) = db.delete_identity(label) {
                log::error!("Failed to delete identity '{}' from disk: {}", label, e);
            }
            if let Err(e) = db.delete_identity_state(&sid) {
                log::error!("Failed to delete identity '{}' state from disk: {}", label, e);
            }
        }
        Ok(())
    }

    /// Create a throwaway identity (`docs/spec/identity.md`, "Throwaway
    /// identities"): memory only, Hidden by default with at least 3 hops, or
    /// Public with the caller's hops. Hybrid unless ECC is asked for.
    pub async fn create_ephemeral_identity(
        &self,
        options: tarnet_api::service::EphemeralOptions,
    ) -> Result<tarnet_api::types::ServiceId> {
        use tarnet_api::types::{IdentityScheme, PrivacyLevel};
        let hops = match options.privacy {
            PrivacyLevel::Hidden { .. } => options.outbound_hops.max(3),
            PrivacyLevel::Public => options.outbound_hops.max(1),
        };
        let keypair = match options.scheme {
            IdentityScheme::Ed25519 => Keypair::generate_ed25519(),
            IdentityScheme::FalconEd25519 => self.take_pooled_hybrid_keypair().await,
        };
        let sid = self
            .identity_store
            .lock()
            .await
            .insert_ephemeral(keypair, options.privacy, hops);
        log::info!("Created throwaway identity {:?}", sid);
        Ok(sid)
    }

    /// Whether `sid` is a throwaway identity held here.
    pub async fn is_ephemeral_identity(&self, sid: &tarnet_api::types::ServiceId) -> bool {
        self.identity_store.lock().await.is_ephemeral(sid)
    }

    /// Drop a throwaway identity: its listeners close, its hidden service and
    /// records go, its keys are erased. Later connections to it are refused
    /// like those to a ServiceId this node doesn't host.
    pub async fn drop_ephemeral_identity(&self, sid: &tarnet_api::types::ServiceId) -> Result<()> {
        let label = {
            let store = self.identity_store.lock().await;
            match store.get_by_service_id(sid) {
                Some(id) if id.ephemeral => id.label.clone(),
                Some(_) => return Err(Error::Protocol("not a throwaway identity".into())),
                None => return Err(Error::Protocol("identity not found".into())),
            }
        };
        self.remove_identity(&label).await?;
        log::info!("Dropped throwaway identity {:?}", sid);
        Ok(())
    }

    /// A hybrid key pair from the pool, refilled in the background, so a
    /// throwaway is created without waiting for Falcon key generation.
    async fn take_pooled_hybrid_keypair(&self) -> Keypair {
        const POOL: usize = 2;
        let pooled = self.ephemeral_key_pool.lock().unwrap().pop();
        let pool = self.ephemeral_key_pool.clone();
        tokio::task::spawn_blocking(move || {
            while pool.lock().unwrap().len() < POOL {
                let kp = Keypair::generate();
                pool.lock().unwrap().push(kp);
            }
        });
        match pooled {
            Some(kp) => kp,
            None => tokio::task::spawn_blocking(Keypair::generate)
                .await
                .expect("key generation task"),
        }
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
        self.search_hello(peer_id, timeout, false).await
    }

    /// Search the DHT for `peer`'s hello until `timeout`, keeping the newest
    /// version seen: the search's whole span if `all`, else only what has
    /// arrived by the time the first one does.
    pub(super) async fn search_hello(&self, peer: &PeerId, timeout: Duration, all: bool) -> Option<HelloRecord> {
        let key = crate::dht::identity_address_key(peer);
        let mut search = self.dht_search(key, Instant::now() + timeout).await;
        let mut best: Option<(u64, HelloRecord)> = None;
        while let Some(rec) = search.next().await {
            let seq = rec.record().sequence;
            if let Some(hello) = crate::dht::hello_from_record(peer, rec.record()) {
                if best.as_ref().map_or(true, |(s, _)| seq > *s) {
                    best = Some((seq, hello));
                }
            }
            if best.is_some() && !all && search.is_idle() {
                break;
            }
        }
        best.map(|(_, h)| h)
    }
}

/// The bytes an application signature covers: a domain no daemon message
/// uses, the context's length and the context, then the message.
pub fn app_signed_message(context: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(context.len()).map_err(|_| Error::Protocol("signature context too long".into()))?;
    let mut out = b"tarnet app sig v2".to_vec();
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(context);
    out.extend_from_slice(msg);
    Ok(out)
}

/// Check an application signature by `sid` (see [`Node::identity_sign`]).
pub fn verify_app_signature(
    sid: &tarnet_api::types::ServiceId,
    context: &[u8],
    msg: &[u8],
    bundle: &[u8],
    sig: &[u8],
) -> bool {
    let Ok(signed) = app_signed_message(context, msg) else {
        return false;
    };
    crate::identity::verify_signed(crate::identity::SignedBy::Service(sid), None, bundle, &signed, sig)
}

impl Node {
    async fn identity_keypair(&self, sid: &tarnet_api::types::ServiceId) -> Result<Keypair> {
        self.identity_store
            .lock()
            .await
            .keypair_for(sid)
            .cloned()
            .ok_or_else(|| Error::Protocol("unknown identity".into()))
    }

    /// Sign as `sid` under the application domain. Returns the identity's
    /// key bundle and the signature. The daemon never signs raw bytes for
    /// an application, so nothing signed here verifies as a daemon message.
    pub async fn identity_sign(
        &self,
        sid: &tarnet_api::types::ServiceId,
        context: &[u8],
        msg: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let kp = self.identity_keypair(sid).await?;
        let signed = app_signed_message(context, msg)?;
        Ok((kp.identity.signing.signing_pubkey_bytes(), kp.sign(&signed)))
    }

    /// Decapsulate a hybrid KEM ciphertext to `sid`'s static key. The secret
    /// leaves only through a KDF bound to `context`.
    pub async fn identity_kem_decap(
        &self,
        sid: &tarnet_api::types::ServiceId,
        context: &[u8],
        ciphertext: &[u8],
    ) -> Result<[u8; 32]> {
        let kp = self.identity_keypair(sid).await?;
        let ss = zeroize::Zeroizing::new(
            kp.identity
                .kem
                .decapsulate(ciphertext)
                .map_err(|e| Error::Crypto(e.into()))?,
        );
        let len = u16::try_from(context.len()).map_err(|_| Error::Protocol("KEM context too long".into()))?;
        Ok(blake3::Hasher::new_derive_key("tarnet app kem v2")
            .update(&len.to_be_bytes())
            .update(context)
            .update(&*ss)
            .finalize()
            .into())
    }

    /// `sid`'s static hybrid KEM public key.
    pub async fn identity_kem_pubkey(&self, sid: &tarnet_api::types::ServiceId) -> Result<Vec<u8>> {
        Ok(self.identity_keypair(sid).await?.identity.kem.kem_pubkey_bytes())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    //! The persistence invariants of `docs/spec/identity.md`: deleting an
    //! identity or dropping a throwaway leaves nothing behind, and a
    //! throwaway never reaches disk.
    use super::*;
    use tarnet_api::service::{EphemeralOptions, ListenerOptions, PortMode};
    use tarnet_api::types::{IdentityScheme, PrivacyLevel, ServiceId};

    fn temp_db(name: &str) -> (Arc<crate::state::StateDb>, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("tarnet-{}-{}.sqlite3", name, rand::random::<u64>()));
        (Arc::new(crate::state::StateDb::open(&path).unwrap()), path)
    }

    fn rows(db: &crate::state::StateDb, sql: &str, param: &[u8]) -> i64 {
        let conn = db.lock_for_test();
        conn.query_row(sql, rusqlite::params![param], |r| r.get(0)).unwrap()
    }

    /// Every table the persistence invariants know about. A new table must be
    /// added here *and* to the startup sweep and `assert_no_trace`.
    const KNOWN_TABLES: [&str; 7] = [
        "dht_records",
        "identities",
        "metadata",
        "pools",
        "tns_labels",
        "tns_records",
        "tns_tombstones",
    ];

    #[test]
    fn schema_registry_knows_every_table() {
        let (db, path) = temp_db("schema");
        assert_eq!(db.table_names(), KNOWN_TABLES, "register new tables with the sweep and assert_no_trace");
        let _ = std::fs::remove_file(path);
    }

    /// Nothing of the identity `(sid, signer, label)` remains anywhere.
    async fn assert_no_trace(node: &Node, sid: &ServiceId, signer: &PeerId, label: &str) {
        assert!(node.identity_store.lock().await.get_by_service_id(sid).is_none());
        assert!(node.identity_store.lock().await.get(label).is_none());
        assert!(!node.listeners.lock().await.values().any(|l| l.listener.service_id == *sid));
        assert!(!node.zone_published.lock().await.contains_key(sid));
        assert!(!node.hidden.intros.lock().await.contains_key(sid));
        assert!(node.dht_store.lock().await.local_records_by(signer).is_empty());
        assert!(!node.ephemeral_records.lock().await.contains_key(sid));
        assert!(!node.own_records_to_republish().await.iter().any(|r| r.signer == *signer));
        if let Some(db) = &node.db {
            let key = tarnet_api::types::encode_base32(sid.as_bytes());
            assert_eq!(rows(db, "SELECT COUNT(*) FROM identities WHERE label = ?1", label.as_bytes()), 0);
            assert_eq!(rows(db, "SELECT COUNT(*) FROM tns_labels WHERE identity = CAST(?1 AS TEXT)", key.as_bytes()), 0);
            assert_eq!(rows(db, "SELECT COUNT(*) FROM tns_records WHERE identity = CAST(?1 AS TEXT)", key.as_bytes()), 0);
            assert_eq!(rows(db, "SELECT COUNT(*) FROM tns_tombstones WHERE sid = ?1", sid.as_bytes()), 0);
            assert_eq!(rows(db, "SELECT COUNT(*) FROM dht_records WHERE signer = ?1", signer.as_bytes()), 0);
        }
    }

    /// Give an identity state in every place one can have it.
    async fn use_everything(node: &Node, sid: &ServiceId) {
        let kp = node.keypair_for_service(sid).await.unwrap();
        node.dht_put_signed_content_as(&kp, b"signed by it", 600).await.unwrap();
        crate::tns::publish(node, &kp, "www", &[crate::tns::TnsRecord::Text("hi".into())])
            .await
            .unwrap();
        crate::tns::unpublish(node, &kp, "old").await.unwrap();
        node.circuit_listen(*sid, PortMode::ReliableOrdered, "80", ListenerOptions::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn deleting_an_identity_leaves_no_trace_and_names_are_not_inherited() {
        let (db, path) = temp_db("delete");
        let node = Node::with_db(Keypair::generate(), db.clone(), crate::state::StorageLimits::default());
        let sid = node
            .create_identity("alice", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT)
            .await
            .unwrap();
        let signer = node.keypair_for_service(&sid).await.unwrap().peer_id();
        use_everything(&node, &sid).await;
        // A label filed the way the API files them: under the ServiceId.
        let key = tarnet_api::types::encode_base32(sid.as_bytes());
        db.label_set(&key, "ssh", &[crate::tns::tns_record_to_bytes(&crate::tns::TnsRecord::Text("x".into()))], true)
            .unwrap();
        assert!(!node.dht_store.lock().await.local_records_by(&signer).is_empty());

        node.delete_identity("alice").await.unwrap();
        assert_no_trace(&node, &sid, &signer, "alice").await;

        // A new identity reusing the name starts empty.
        let again = node
            .create_identity("alice", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT)
            .await
            .unwrap();
        assert!(node.zone_label_keys(&again).await.iter().all(|k| k != "alice"));
        assert!(db.label_list(&tarnet_api::types::encode_base32(again.as_bytes())).unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn a_throwaway_never_reaches_disk_and_drops_without_a_trace() {
        let (db, path) = temp_db("throwaway");
        let node = Node::with_db(Keypair::generate(), db.clone(), crate::state::StorageLimits::default());
        let count = |table: &str| rows(&db, &format!("SELECT COUNT(*) FROM {table} WHERE ?1 IS NOT NULL"), b"x");
        let before: Vec<i64> = KNOWN_TABLES.iter().map(|t| count(t)).collect();

        let sid = node
            .create_ephemeral_identity(EphemeralOptions {
                privacy: PrivacyLevel::Public,
                outbound_hops: 1,
                scheme: IdentityScheme::DEFAULT,
            })
            .await
            .unwrap();
        let signer = node.keypair_for_service(&sid).await.unwrap().peer_id();
        use_everything(&node, &sid).await;
        node.publish_peer_record(sid).await.unwrap();

        // Alive and in use, yet not one row was written for it.
        let during: Vec<i64> = KNOWN_TABLES.iter().map(|t| count(t)).collect();
        assert_eq!(before, during, "a throwaway wrote to {:?}", KNOWN_TABLES);
        // Not republished by the node on its behalf, nor exported.
        assert!(!node.own_records_to_republish().await.iter().any(|r| r.signer == signer));
        assert!(node.identity_store.lock().await.export_all().iter().all(|e| !e.0.starts_with('~')));

        // It can't be deleted like a persistent identity, nor updated.
        let label = node.identity_store.lock().await.get_by_service_id(&sid).unwrap().label.clone();
        assert!(node.delete_identity(&label).await.is_err());
        assert!(node.update_identity(&label, PrivacyLevel::Public, 2).await.is_err());

        node.drop_ephemeral_identity(&sid).await.unwrap();
        assert_no_trace(&node, &sid, &signer, &label).await;
        assert!(node.drop_ephemeral_identity(&sid).await.is_err());

        // Gone after a restart too (it was never written).
        drop(node);
        let restarted = Node::with_db(Keypair::generate(), db.clone(), crate::state::StorageLimits::default());
        assert_no_trace(&restarted, &sid, &signer, &label).await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn startup_sweep_removes_rows_of_identities_that_no_longer_exist() {
        let (db, path) = temp_db("sweep");
        let identity = Keypair::generate();
        let node = Node::with_db(identity.clone(), db.clone(), crate::state::StorageLimits::default());
        // State a crash left behind for an identity that is gone.
        let ghost = Keypair::generate();
        let gsid = ghost.identity.service_id();
        db.label_set(&tarnet_api::types::encode_base32(gsid.as_bytes()), "www", &[], true)
            .unwrap();
        db.set_tns_tombstone(&gsid, "old", true).unwrap();
        node.dht_put_signed_content_as(&ghost, b"orphan", 600).await.unwrap();
        // ... and live state that must survive.
        node.dht_put_signed_content(b"default's", 600).await.unwrap();
        drop(node);

        let restarted = Node::with_db(identity, db.clone(), crate::state::StorageLimits::default());
        assert_no_trace(&restarted, &gsid, &ghost.peer_id(), "ghost").await;
        let default_signer = {
            let store = restarted.identity_store.lock().await;
            store.default_identity().keypair.peer_id()
        };
        assert_eq!(restarted.dht_store.lock().await.local_records_by(&default_signer).len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn identity_rules_at_creation() {
        let node = Node::new(Keypair::generate());
        // Persistent identities are hybrid, and '~' names are reserved.
        assert!(node
            .create_identity("ecc", PrivacyLevel::Public, 1, IdentityScheme::Ed25519)
            .await
            .is_err());
        assert!(node
            .create_identity("~mine", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT)
            .await
            .is_err());
        // Hidden throwaways get at least 3 hops; Public ones the caller's.
        let hidden = node.create_ephemeral_identity(EphemeralOptions::default()).await.unwrap();
        let ecc = node
            .create_ephemeral_identity(EphemeralOptions {
                privacy: PrivacyLevel::Public,
                outbound_hops: 1,
                scheme: IdentityScheme::Ed25519,
            })
            .await
            .unwrap();
        let store = node.identity_store.lock().await;
        assert!(store.get_by_service_id(&hidden).unwrap().outbound_hops >= 3);
        let ecc_id = store.get_by_service_id(&ecc).unwrap();
        assert_eq!(ecc_id.outbound_hops, 1);
        assert_eq!(ecc_id.keypair.scheme(), IdentityScheme::Ed25519);
        assert!(store.is_ephemeral(&hidden) && store.is_ephemeral(&ecc));
    }
}
