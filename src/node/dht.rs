use super::*;

/// Compute a 64-byte BLAKE3 hash (used for content-addressed DHT keys).
pub(super) fn blake3_hash_64(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    blake3::Hasher::new()
        .update(input)
        .finalize_xof()
        .fill(&mut out);
    out
}

/// What launching DHT walks needs, cloneable into a [`DhtSearch`] so a search
/// can relaunch rounds without a handle to the node.
#[derive(Clone)]
pub(crate) struct DhtWalker {
    pub(super) local: PeerId,
    pub(super) links: Arc<Mutex<LinkTable>>,
    pub(super) routing_table: Arc<Mutex<RoutingTable>>,
    /// Neighbours' `DhtNeighbor` store flags; missing means "assume it stores".
    pub(super) neighbor_stores: Arc<Mutex<HashMap<PeerId, bool>>>,
    pub(super) query_tokens: Arc<Mutex<HashMap<[u8; 32], (PeerId, Instant)>>>,
}

impl DhtWalker {
    pub(super) async fn neighbors(&self) -> Vec<DhtNeighbor> {
        let peers: Vec<PeerId> = self.links.lock().await.iter().map(|(p, _)| *p).collect();
        let stores = self.neighbor_stores.lock().await;
        peers
            .into_iter()
            .map(|p| DhtNeighbor::new(p, stores.get(&p).copied().unwrap_or(true)))
            .collect()
    }

    /// ρ for the current network size (routing-table destinations + us) and
    /// degree.
    pub(super) async fn walk_count(&self) -> usize {
        let n = self.routing_table.lock().await.len() + 1;
        let d = self.links.lock().await.iter().count();
        crate::dht::walk_count(n, d)
    }

    /// Send `count` walks, the i-th built by `build(i)`, through distinct random
    /// neighbours (cycling once every neighbour has one). Returns how many were
    /// handed to a link.
    pub(super) async fn launch(&self, count: usize, mut build: impl FnMut(usize) -> Vec<u8>) -> usize {
        use rand::seq::SliceRandom;
        let links = self.links.lock().await;
        let mut peers: Vec<PeerId> = links.iter().map(|(p, _)| *p).collect();
        if peers.is_empty() {
            return 0;
        }
        peers.shuffle(&mut rand::thread_rng());
        let mut sent = 0;
        for i in 0..count {
            let peer = peers[i % peers.len()];
            if let Some(link) = links.get(&peer) {
                if link.send_deferred(&build(i)).await.is_ok() {
                    sent += 1;
                }
            }
        }
        sent
    }

    /// Launch one round of GET walks for `key`, each under a fresh query token
    /// registered with us as originator. `search`, if given, is registered for
    /// every token before any walk leaves, so no fast reply is missed.
    pub(super) async fn launch_get(
        &self,
        key: &[u8; 64],
        search: Option<(&SearchRegistry, &mpsc::Sender<crate::dht::VerifiedRecord>)>,
    ) -> Vec<[u8; 32]> {
        let count = self.walk_count().await;
        let tokens: Vec<[u8; 32]> = (0..count).map(|_| random_token()).collect();
        {
            let mut qt = self.query_tokens.lock().await;
            let now = Instant::now();
            for t in &tokens {
                qt.insert(*t, (self.local, now));
            }
        }
        if let Some((registry, tx)) = search {
            let mut reg = registry.lock().unwrap();
            for t in &tokens {
                reg.insert(*t, tx.clone());
            }
        }
        self.launch(count, |i| {
            DhtGetMsg {
                walk: WalkHeader::origin(),
                key: *key,
                query_token: tokens[i],
            }
            .to_wire()
            .encode()
        })
        .await;
        tokens
    }

    /// Launch one round of WATCH walks for `key`. Returns (first hop, token)
    /// per walk.
    pub(super) async fn launch_watch(&self, key: &[u8; 64], expiration_secs: u32) -> Vec<[u8; 32]> {
        let count = self.walk_count().await;
        let tokens: Vec<[u8; 32]> = (0..count).map(|_| random_token()).collect();
        self.launch(count, |i| {
            DhtWatchMsg {
                walk: WalkHeader::origin(),
                key: *key,
                query_token: tokens[i],
                expiration_secs,
            }
            .to_wire()
            .encode()
        })
        .await;
        tokens
    }
}

pub(super) type SearchRegistry =
    std::sync::Mutex<HashMap<[u8; 32], mpsc::Sender<crate::dht::VerifiedRecord>>>;

fn random_token() -> [u8; 32] {
    let mut t = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut t);
    t
}

/// A key this node watches, with the tokens of its live watch walks.
pub(super) struct LocalWatch {
    pub(super) expires_at: Instant,
    pub(super) tokens: Vec<[u8; 32]>,
}

impl Node {
    /// Next routing step for a walk this node received from `from`.
    pub(super) async fn dht_walk_step(
        &self,
        key: &DhtId,
        header: &WalkHeader,
        from: &PeerId,
    ) -> WalkStep {
        let neighbors = self.dht_walker.neighbors().await;
        crate::dht::walk_step(
            &self.peer_id(),
            self.dht_stores,
            key,
            header,
            from,
            &neighbors,
            &mut rand::thread_rng(),
        )
    }

    /// Tell every watcher registered here (except via `exclude`) about `put`.
    pub(super) async fn notify_dht_watchers(&self, put: &DhtPutMsg, exclude: Option<&PeerId>) {
        let watchers = self.dht_watches.lock().await.get_watchers(&put.key);
        if watchers.is_empty() {
            return;
        }
        let links = self.links.lock().await;
        for (token, via_peer) in watchers {
            if Some(&via_peer) == exclude {
                continue;
            }
            let notify = DhtWatchNotifyMsg {
                query_token: token,
                put: put.clone(),
            };
            if let Some(link) = links.get(&via_peer) {
                let _ = link.send_deferred(&notify.to_wire().encode()).await;
            }
        }
    }

    /// Republish every record this node published itself (hellos excepted:
    /// they have their own timer). Owners republishing is what keeps records
    /// alive; there is no replication sweep.
    pub(crate) async fn dht_republish_own(&self) {
        let records = self.own_records_to_republish().await;
        for record in &records {
            let encoded = record.to_put_msg().to_wire().encode();
            let count = self.dht_walker.walk_count().await;
            self.dht_walker.launch(count, |_| encoded.clone()).await;
        }
        if !records.is_empty() {
            log::debug!("Republished {} own DHT records", records.len());
        }
    }

    /// The records [`dht_republish_own`](Self::dht_republish_own) sends: our
    /// own records minus hellos and minus anything signed by a Hidden identity.
    ///
    /// This republish runs on link-up and alongside the node's other records,
    /// so a Hidden identity's records in it would leave together with records
    /// tied to this node — a watcher could open a link to a suspected host and
    /// see the hidden service's re-PUT follow. Hidden identities republish only
    /// from `maintain_hidden_services`, on their own timer.
    pub(super) async fn own_records_to_republish(&self) -> Vec<DhtRecord> {
        let hidden = self.hidden_identity_signers().await;
        let store = self.dht_store.lock().await;
        store
            .records_by_origin()
            .0
            .into_iter()
            .filter(|r| r.record_type != RecordType::Hello && !hidden.contains(&r.signer))
            .cloned()
            .collect()
    }

    /// Relaunch watch walks for every live local watch (fresh tokens), and
    /// drop expired ones. Paths change with the topology, so watches are kept
    /// alive by the watcher rather than by the nodes on the old path.
    pub(crate) async fn dht_refresh_watches(&self) {
        let now = Instant::now();
        let live: Vec<([u8; 64], u32)> = {
            let mut watches = self.local_watches.lock().await;
            watches.retain(|_, w| w.expires_at > now);
            watches
                .iter()
                .map(|(k, w)| (*k, w.expires_at.duration_since(now).as_secs().max(1) as u32))
                .collect()
        };
        for (key, remaining) in live {
            let tokens = self.dht_walker.launch_watch(&key, remaining).await;
            if let Some(w) = self.local_watches.lock().await.get_mut(&key) {
                // Keep the previous round's tokens until their paths expire, so
                // a notification already in flight still lands.
                w.tokens.drain(..w.tokens.len().saturating_sub(MAX_WALKS));
                w.tokens.extend(tokens);
            }
        }
    }

    /// Next monotonic sequence for signed-content / signed-at-key records,
    /// persisted so it survives restart.
    async fn next_signed_content_sequence(&self) -> u64 {
        let mut seq = self.signed_content_sequence.lock().await;
        *seq += 1;
        let sequence = *seq;
        self.db_set_metadata("signed_content_sequence", sequence);
        sequence
    }

    /// The single publish path: persist a freshly-minted record, store it
    /// locally, and send ρ PUT walks. The `DhtPutMsg` is *derived* from the
    /// record via [`to_put_msg`](crate::dht::DhtRecord::to_put_msg), never built
    /// in parallel — so the wire copy and the stored copy can't drift.
    pub(crate) async fn dht_publish(&self, record: crate::dht::VerifiedRecord) {
        let put = record.record().to_put_msg();
        let accepted = self.dht_store.lock().await.put(record.clone());
        if accepted {
            self.db_upsert_dht_record(record.record());
        }
        self.notify_dht_watchers(&put, None).await;
        let encoded = put.to_wire().encode();
        let count = self.dht_walker.walk_count().await;
        self.dht_walker.launch(count, |_| encoded.clone()).await;
    }

    /// Content-addressed DHT put: stores locally and sends PUT walks.
    /// Returns the inner hash (64 bytes) needed for retrieval.
    pub async fn dht_put_content(&self, value: &[u8]) -> [u8; 64] {
        let (record, inner_hash) =
            crate::dht::VerifiedRecord::new_content(value, Duration::from_secs(3600));
        self.dht_publish(record).await;

        let hash_hex: String = inner_hash.iter().map(|b| format!("{:02x}", b)).collect();
        log::info!("DHT content put (inner hash: {})", hash_hex);
        inner_hash
    }

    /// Content-addressed DHT get: looks up by outer hash, decrypts with inner hash.
    pub async fn dht_get_content(&self, inner_hash: &[u8; 64]) -> Option<Vec<u8>> {
        let outer_hash: [u8; 64] = blake3_hash_64(inner_hash);
        let key = DhtId(outer_hash);

        let store = self.dht_store.lock().await;
        let records = store.get(&key);
        for record in records {
            if let Ok(plaintext) = crate::dht::content_address_get(inner_hash, &record.value) {
                return Some(plaintext);
            }
        }
        None
    }

    /// Send GET walks for a content-addressed key.
    /// Uses anonymous query token routing for reply privacy.
    pub async fn request_content(&self, inner_hash: &[u8; 64]) -> Result<()> {
        let outer_hash: [u8; 64] = blake3_hash_64(inner_hash);
        self.dht_walker.launch_get(&outer_hash, None).await;
        Ok(())
    }

    /// Watch a DHT key for changes: sends ρ watch walks, refreshed by the
    /// node's periodic task until `expiration_secs` passes.
    pub async fn dht_watch(&self, key: &DhtId, expiration_secs: u32) {
        let key_bytes = *key.as_bytes();
        let expiration_secs = expiration_secs.min(crate::dht::MAX_WATCH_EXPIRATION_SECS);
        let tokens = self.dht_walker.launch_watch(&key_bytes, expiration_secs).await;
        let mut watches = self.local_watches.lock().await;
        let w = watches.entry(key_bytes).or_insert(LocalWatch {
            expires_at: Instant::now(),
            tokens: Vec::new(),
        });
        w.expires_at = Instant::now() + Duration::from_secs(expiration_secs as u64);
        w.tokens.extend(tokens);
        log::debug!("Watching DHT key {:?}", key);
    }

    /// Stop watching a DHT key. Registrations along the walks expire on their
    /// own; notifications that still arrive are dropped here.
    pub async fn dht_unwatch(&self, key: &DhtId) {
        self.local_watches.lock().await.remove(key.as_bytes());
    }

    /// Take the DHT watch notification receiver.
    pub async fn take_dht_watch_receiver(&self) -> Option<mpsc::Receiver<(DhtId, DhtRecord)>> {
        self.dht_watch_rx.lock().await.take()
    }

    // ── Signed Content DHT ──

    /// Signed content-addressed DHT put: encrypts the value via content-addressing,
    /// signs the record, stores locally as SignedContent, and propagates via
    /// probabilistic PUT. Multiple publishers can store at the same key — each
    /// signer's record is stored independently (supplemental).
    ///
    /// The value is encrypted so DHT storage nodes see only an opaque blob.
    /// Self-authentication happens on retrieval: only holders of the inner hash
    /// (derived from the plaintext) can decrypt and verify.
    ///
    /// Returns the inner hash (64 bytes) needed for retrieval.
    pub async fn dht_put_signed_content(&self, value: &[u8], ttl_secs: u32) -> [u8; 64] {
        let sequence = self.next_signed_content_sequence().await;
        let (record, inner_hash) = crate::dht::VerifiedRecord::new_signed_content(
            &self.identity,
            value,
            sequence,
            Duration::from_secs(ttl_secs as u64),
        );
        self.dht_publish(record).await;

        log::info!("DHT signed content put");
        inner_hash
    }

    /// Retrieve all valid signed content records at a content-addressed key.
    /// Takes the inner hash (BLAKE2b-512 of the original plaintext), computes
    /// the DHT key, fetches all records, attempts decryption on each, and returns
    /// the signer PeerId for each successfully decrypted record along with the
    /// decrypted plaintext.
    ///
    /// Invalid records (spam, garbage from storage nodes) silently fail decryption
    /// and are excluded from results.
    pub async fn dht_get_signed_content(&self, inner_hash: &[u8; 64]) -> Vec<(PeerId, Vec<u8>)> {
        let outer_hash: [u8; 64] = blake3_hash_64(inner_hash);
        let key = DhtId(outer_hash);

        let store = self.dht_store.lock().await;
        let records = store.get(&key);
        let mut results = Vec::new();
        for record in records {
            if record.record_type != RecordType::SignedContent {
                continue;
            }
            let inner_blob = match crate::dht::signed_record_decrypt(&key, &record.value) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(plaintext) = crate::dht::content_address_get(inner_hash, &inner_blob) {
                results.push((PeerId(record.signer), plaintext));
            }
        }
        results
    }

    /// Send GET walks for a signed content-addressed key.
    /// Uses anonymous query token routing for reply privacy.
    pub async fn request_signed_content(&self, inner_hash: &[u8; 64]) -> Result<()> {
        let outer_hash: [u8; 64] = blake3_hash_64(inner_hash);
        self.dht_walker.launch_get(&outer_hash, None).await;
        Ok(())
    }

    // ── TNS support: arbitrary-key DHT operations ──

    /// Next monotonic, restart-persisted sequence for signed-at-key records.
    /// Callers that must embed the sequence in a value *before* publishing (the
    /// TNS/pool self-authenticating bundle signs over it) take it here and pass
    /// it back into [`dht_put_signed_at_key`], so both layers agree on it.
    pub async fn next_dht_sequence(&self) -> u64 {
        self.next_signed_content_sequence().await
    }

    /// Store signed content at an arbitrary DHT key (not content-addressed).
    /// `signer_keypair` is the *disposable* per-label key (not the zone master);
    /// `value` is stored verbatim (the caller seals it); `sequence` must be the
    /// same value the caller bound into `value`.
    pub async fn dht_put_signed_at_key(
        &self,
        signer_keypair: &crate::identity::Keypair,
        key: DhtId,
        value: &[u8],
        sequence: u64,
        ttl_secs: u32,
    ) -> Result<()> {
        let record = crate::dht::VerifiedRecord::new_signed_at_key(
            signer_keypair,
            key,
            value,
            sequence,
            Duration::from_secs(ttl_secs as u64),
        );
        self.dht_publish(record).await;

        log::info!("TNS signed put at key {:?}", key);
        Ok(())
    }

    /// Publish a self-addressed TNS zone root: signed by the zone key at
    /// `zone_root_key(zone_sid)`. Only the zone owner can write there (the ingest
    /// gate enforces it), so the location carries no foreign-signer flood surface.
    /// `value` is the caller's already-sealed root blob, stored verbatim.
    pub async fn dht_put_zone_root(
        &self,
        zone_keypair: &crate::identity::Keypair,
        value: &[u8],
        sequence: u64,
        ttl_secs: u32,
    ) -> Result<()> {
        let record = crate::dht::VerifiedRecord::new_zone_root(
            zone_keypair,
            value,
            sequence,
            Duration::from_secs(ttl_secs as u64),
        );
        self.dht_publish(record).await;
        log::info!("TNS zone root put for {:?}", zone_keypair.identity.service_id());
        Ok(())
    }

    /// Update one label in an owned zone's published working set and return the
    /// full current map (`label → serialized TnsRecord set`) together with a fresh
    /// monotonic sequence. `records = Some(..)` upserts the label; `None` removes
    /// it. The map is the durable source of truth the zone root is rebuilt from;
    /// it is hydrated lazily from the `tns_zone_records` table on first touch and
    /// written through on change, so it survives restart and accumulates across
    /// every publisher path.
    ///
    /// The sequence is allocated *inside* the same critical section as the
    /// snapshot, so a higher sequence always corresponds to a same-or-newer
    /// snapshot. Without this, two concurrent publishers (e.g. a hidden service's
    /// "intro" and "peer") could invert — a stale, smaller snapshot winning with a
    /// higher sequence and silently dropping the other label from the root.
    pub(crate) async fn zone_published_update(
        &self,
        zone_sid: &tarnet_api::types::ServiceId,
        label: &str,
        records: Option<Vec<u8>>,
    ) -> (std::collections::BTreeMap<String, Vec<u8>>, u64) {
        let mut map = self.zone_published.lock().await;
        // Lazy hydrate from the DB the first time we touch this zone.
        if !map.contains_key(zone_sid) {
            let mut loaded = std::collections::BTreeMap::new();
            if let Some(db) = &self.db {
                if let Ok(rows) = db.zone_record_list(zone_sid.as_bytes()) {
                    loaded.extend(rows);
                }
            }
            map.insert(*zone_sid, loaded);
        }
        let entry = map.get_mut(zone_sid).expect("hydrated above");
        match &records {
            Some(blob) => {
                entry.insert(label.to_string(), blob.clone());
            }
            None => {
                entry.remove(label);
            }
        }
        let snapshot = entry.clone();
        // Allocate the sequence under the map lock so seq and snapshot can't
        // invert across concurrent publishers.
        let sequence = self.next_signed_content_sequence().await;
        // Write through to durable storage (best-effort; the in-memory copy is
        // authoritative for this process either way).
        if let Some(db) = &self.db {
            let res = match &records {
                Some(blob) => db.zone_record_set(zone_sid.as_bytes(), label, blob),
                None => db.zone_record_remove(zone_sid.as_bytes(), label),
            };
            if let Err(e) = res {
                log::warn!("zone_published_update: db write failed: {}", e);
            }
        }
        (snapshot, sequence)
    }

    /// Get all non-expired records at an arbitrary DHT key from local store.
    pub async fn dht_get_records_at_key(&self, key: &DhtId) -> Vec<crate::dht::DhtRecord> {
        self.dht_store
            .lock()
            .await
            .get(key)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Insert a record directly into the local DHT store, bypassing propagation,
    /// link-up store-dump, and replication. Test-only seam: it is the only way to
    /// place a record on a node such that a *peer* can obtain it solely via a
    /// DhtGet pull (every production path pushes a full copy, masking the
    /// GET-response code path).
    #[doc(hidden)]
    pub async fn dht_store_insert_local_for_test(&self, record: crate::dht::DhtRecord) {
        self.dht_store
            .lock()
            .await
            .put(crate::dht::VerifiedRecord::locally_trusted(record));
    }

    /// Send GET walks for an arbitrary key.
    /// Uses anonymous query token routing for reply privacy.
    pub async fn request_dht_key(&self, key: &DhtId) -> Result<()> {
        self.dht_walker.launch_get(key.as_bytes(), None).await;
        Ok(())
    }

    /// Issue a DHT search for `key` and return a [`DhtSearch`] stream that yields
    /// distinct, infra-verified records as responses route back, ending at
    /// `deadline`. This is the single read primitive: it ties the act of reading
    /// search results to actually having issued the query, and replaces the old
    /// "fire a `request_*` then busy-poll the store" pattern. Dropping the
    /// returned stream cancels the search (RAII) — callers terminate simply by
    /// breaking their loop or letting it fall out of scope.
    ///
    /// Walks find a record only probabilistically, so the search relaunches a
    /// fresh round of walks every [`SEARCH_RELAUNCH_INTERVAL`], up to
    /// [`SEARCH_ROUNDS`] rounds (keys can hold several records, so finding one
    /// does not stop the rounds; dropping the search does).
    pub async fn dht_search(&self, key: DhtId, deadline: Instant) -> DhtSearch {
        // Bounded: the stream is used as a wake-up signal and callers re-read the
        // store (which holds every delivered record), so a dropped send is
        // harmless — the next wake still sees the complete picture.
        let (tx, rx) = mpsc::channel(16);
        let tokens = self
            .dht_walker
            .launch_get(key.as_bytes(), Some((&self.dht_searches, &tx)))
            .await;

        DhtSearch {
            rx,
            tx,
            key,
            tokens,
            deadline,
            rounds_left: SEARCH_ROUNDS - 1,
            next_round: Instant::now() + SEARCH_RELAUNCH_INTERVAL,
            seen: HashSet::new(),
            walker: self.dht_walker.clone(),
            registry: self.dht_searches.clone(),
        }
    }

    /// [`dht_search`](Self::dht_search) for a content-addressed key: derives the
    /// outer lookup hash from `inner_hash` (the same derivation
    /// [`request_content`](Self::request_content) /
    /// [`request_signed_content`](Self::request_signed_content) use). Serves both
    /// plain and signed content gets — they share the lookup key and differ only
    /// in how the caller decrypts the streamed records.
    pub async fn dht_search_content(&self, inner_hash: &[u8; 64], deadline: Instant) -> DhtSearch {
        let outer_hash: [u8; 64] = blake3_hash_64(inner_hash);
        self.dht_search(DhtId(outer_hash), deadline).await
    }

    /// [`dht_search`](Self::dht_search) for a peer's hello record, keyed by the
    /// identity-addressed DHT key for `target`.
    pub async fn dht_search_hello(&self, target: &PeerId, deadline: Instant) -> DhtSearch {
        let key = crate::dht::identity_address_key(target);
        self.dht_search(key, deadline).await
    }
}

/// Search rounds (initial + relaunches) before a search just waits out its
/// deadline.
const SEARCH_ROUNDS: u32 = 3;
/// Time between search rounds.
const SEARCH_RELAUNCH_INTERVAL: Duration = Duration::from_millis(1500);

/// A live DHT search: an async stream of distinct, infra-verified records routed
/// back for one query. The only way to consume search results, so a caller
/// cannot read results without having issued the query (the read-side mirror of
/// the typed publish constructors). [`Drop`] deregisters the query tokens,
/// cancelling the search.
pub struct DhtSearch {
    rx: mpsc::Receiver<crate::dht::VerifiedRecord>,
    tx: mpsc::Sender<crate::dht::VerifiedRecord>,
    key: DhtId,
    /// Query tokens of every walk launched so far.
    tokens: Vec<[u8; 32]>,
    deadline: Instant,
    rounds_left: u32,
    next_round: Instant,
    /// Fingerprints of records already yielded, so a record delivered over
    /// multiple walks is surfaced once.
    seen: HashSet<[u8; 64]>,
    walker: DhtWalker,
    registry: Arc<SearchRegistry>,
}

impl DhtSearch {
    /// Await the next distinct verified record, or `None` once the deadline
    /// passes (or the node shuts the channel). Records are guaranteed to have
    /// cleared the trust gate — invalid records never reach application logic.
    pub async fn next(&mut self) -> Option<crate::dht::VerifiedRecord> {
        loop {
            let now = Instant::now();
            if now >= self.deadline {
                return None;
            }
            let relaunch = self.rounds_left > 0;
            let wake = if relaunch {
                self.next_round.min(self.deadline)
            } else {
                self.deadline
            };
            let rec = tokio::select! {
                r = self.rx.recv() => r?,
                _ = tokio::time::sleep(wake.saturating_duration_since(now)) => {
                    if relaunch && Instant::now() >= self.next_round {
                        self.rounds_left -= 1;
                        self.next_round = Instant::now() + SEARCH_RELAUNCH_INTERVAL;
                        let tokens = self
                            .walker
                            .launch_get(self.key.as_bytes(), Some((&self.registry, &self.tx)))
                            .await;
                        self.tokens.extend(tokens);
                    }
                    continue;
                }
            };
            let r = rec.record();
            let mut fp_input = Vec::with_capacity(64 + 1 + 8 + 32 + r.value.len());
            fp_input.extend_from_slice(r.key.as_bytes());
            fp_input.push(r.record_type.as_u8());
            fp_input.extend_from_slice(&r.sequence.to_be_bytes());
            fp_input.extend_from_slice(&r.signer);
            fp_input.extend_from_slice(&r.value);
            let fp = blake3_hash_64(&fp_input);
            if self.seen.insert(fp) {
                return Some(rec);
            }
        }
    }
}

impl Drop for DhtSearch {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.registry.lock() {
            for token in &self.tokens {
                reg.remove(token);
            }
        }
    }
}
