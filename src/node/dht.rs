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

impl Node {
    /// Forward a DHT message to targeted peers using R5N-style hybrid routing:
    /// a short random-walk prefix (`params.random_hops`) for originator
    /// decorrelation, then greedy convergence toward the key. Advisory bloom is
    /// respected for non-critical peers but overridden for k-closest to resist
    /// bloom-stuffing attacks.
    pub(super) async fn dht_forward(
        &self,
        key: &DhtId,
        old_bloom: [u8; 256],
        hop_count: u8,
        encoded: &[u8],
        from: PeerId,
    ) {
        let bloom = BloomFilter::from_bytes(old_bloom);

        let kb = self.kbucket.lock().await;
        let all_peers = kb.all_peers();
        let l2nse = kb.estimate_l2nse();
        drop(kb);

        let params = DhtQueryParams::from_l2nse(l2nse);
        let targets = if hop_count < params.random_hops {
            random_select(&all_peers, params.fan_out)
        } else {
            probabilistic_select(key, &all_peers, params.fan_out)
        };

        let links = self.links.lock().await;
        if targets.is_empty() {
            for (peer_id, link) in links.iter() {
                if *peer_id != from && !bloom.contains(peer_id) {
                    let _ = link.send_deferred(encoded).await;
                }
            }
        } else {
            for (pid, _) in &targets {
                if *pid != from
                    && (!bloom.contains(pid) || is_k_closest(pid, key, &all_peers, DHT_K))
                {
                    if let Some(link) = links.get(pid) {
                        let _ = link.send_deferred(encoded).await;
                    }
                }
            }
        }
    }

    /// Compute DHT query parameters from the current L2NSE estimate.
    pub async fn dht_query_params(&self) -> DhtQueryParams {
        let kb = self.kbucket.lock().await;
        DhtQueryParams::from_l2nse(kb.estimate_l2nse())
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
    /// locally, and fan the derived PUT out to the L2NSE-selected peers (falling
    /// back to all direct neighbors). The `DhtPutMsg` is *derived* from the
    /// record via [`to_put_msg`](crate::dht::DhtRecord::to_put_msg), never built
    /// in parallel — so the wire copy and the stored copy can't drift.
    pub(crate) async fn dht_publish(
        &self,
        record: crate::dht::VerifiedRecord,
        params: DhtQueryParams,
    ) {
        let put = record
            .record()
            .to_put_msg(&self.peer_id(), params.hop_limit);
        let key = DhtId(put.key);
        self.db_upsert_dht_record(record.record());
        self.dht_store.lock().await.put(record);

        let encoded = put.to_wire().encode();
        let kb = self.kbucket.lock().await;
        let all_peers = kb.all_peers();
        drop(kb);
        let targets = probabilistic_select(&key, &all_peers, params.fan_out);

        let links = self.links.lock().await;
        if targets.is_empty() {
            for (_, link) in links.iter() {
                let _ = link.send_deferred(&encoded).await;
            }
        } else {
            for (pid, _) in &targets {
                if let Some(link) = links.get(pid) {
                    let _ = link.send_deferred(&encoded).await;
                }
            }
            for (pid, link) in links.iter() {
                if !targets.iter().any(|(p, _)| p == pid) {
                    let _ = link.send_deferred(&encoded).await;
                }
            }
        }
    }

    /// Content-addressed DHT put: stores locally and sends to targeted peers.
    /// Returns the inner hash (64 bytes) needed for retrieval.
    pub async fn dht_put_content(&self, value: &[u8]) -> [u8; 64] {
        let params = self.dht_query_params().await;
        self.dht_put_content_with_params(value, params).await
    }

    /// Like [`dht_put_content`] but with application-tunable query parameters.
    pub async fn dht_put_content_with_params(
        &self,
        value: &[u8],
        params: DhtQueryParams,
    ) -> [u8; 64] {
        let (record, inner_hash) =
            crate::dht::VerifiedRecord::new_content(value, Duration::from_secs(3600));
        self.dht_publish(record, params).await;

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

    /// Send a DHT GET request to neighbors for a content-addressed key.
    /// Uses anonymous query token routing for reply privacy.
    pub async fn request_content(&self, inner_hash: &[u8; 64]) -> Result<()> {
        let params = self.dht_query_params().await;
        self.request_content_with_params(inner_hash, params).await
    }

    /// Like [`request_content`] but with application-tunable query parameters.
    pub async fn request_content_with_params(
        &self,
        inner_hash: &[u8; 64],
        params: DhtQueryParams,
    ) -> Result<()> {
        let outer_hash: [u8; 64] = blake3_hash_64(inner_hash);
        let mut bloom = BloomFilter::new();
        bloom.insert(&self.peer_id());
        let mut query_token = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut query_token);
        self.query_tokens
            .lock()
            .await
            .insert(query_token, (self.peer_id(), Instant::now()));
        let get = DhtGetMsg {
            key: outer_hash,
            query_token,
            hop_count: 0,
            hop_limit: params.hop_limit,
            bloom: bloom.to_bytes(),
        };
        let encoded = get.to_wire().encode();

        let links = self.links.lock().await;
        for (peer_id, link) in links.iter() {
            if let Err(e) = link.send_message(&encoded).await {
                log::warn!("Failed to send content DHT GET to {:?}: {}", peer_id, e);
            }
        }
        Ok(())
    }

    /// Watch a DHT key for changes. Sends DhtWatch to all neighbors.
    /// Uses per-neighbor query tokens for anonymous notification routing.
    pub async fn dht_watch(&self, key: &DhtId, expiration_secs: u32) {
        let key_bytes = *key.as_bytes();
        self.local_watches.lock().await.insert(key_bytes);

        let links = self.links.lock().await;
        for (_, link) in links.iter() {
            // Fresh token per neighbor so notifications route back correctly
            let mut token = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut token);
            self.query_tokens
                .lock()
                .await
                .insert(token, (self.peer_id(), Instant::now()));
            let watch = DhtWatchMsg {
                key: key_bytes,
                query_token: token,
                expiration_secs,
            };
            let _ = link.send_message(&watch.to_wire().encode()).await;
        }
        log::debug!("Watching DHT key {:?}", key);
    }

    /// Stop watching a DHT key. Sends DhtWatch with expiration=0 to all neighbors.
    pub async fn dht_unwatch(&self, key: &DhtId) {
        let key_bytes = *key.as_bytes();
        self.local_watches.lock().await.remove(&key_bytes);

        let links = self.links.lock().await;
        for (_, link) in links.iter() {
            // Use a fresh token for cancellation (zero-expiry signals cancel)
            let mut token = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut token);
            let watch = DhtWatchMsg {
                key: key_bytes,
                query_token: token,
                expiration_secs: 0,
            };
            let _ = link.send_message(&watch.to_wire().encode()).await;
        }
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
        let params = self.dht_query_params().await;
        self.dht_publish(record, params).await;

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

    /// Send a DHT GET request to neighbors for a signed content-addressed key.
    /// Uses anonymous query token routing for reply privacy.
    pub async fn request_signed_content(&self, inner_hash: &[u8; 64]) -> Result<()> {
        let outer_hash: [u8; 64] = blake3_hash_64(inner_hash);
        let mut bloom = BloomFilter::new();
        bloom.insert(&self.peer_id());
        let mut query_token = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut query_token);
        self.query_tokens
            .lock()
            .await
            .insert(query_token, (self.peer_id(), Instant::now()));
        let params = self.dht_query_params().await;
        let get = DhtGetMsg {
            key: outer_hash,
            query_token,
            hop_count: 0,
            hop_limit: params.hop_limit,
            bloom: bloom.to_bytes(),
        };
        let encoded = get.to_wire().encode();

        let links = self.links.lock().await;
        for (peer_id, link) in links.iter() {
            if let Err(e) = link.send_message(&encoded).await {
                log::warn!(
                    "Failed to send signed content DHT GET to {:?}: {}",
                    peer_id,
                    e
                );
            }
        }
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
        let params = self.dht_query_params().await;
        self.dht_publish(record, params).await;

        log::info!("TNS signed put at key {:?}", key);
        Ok(())
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

    /// Send a DHT GET request for an arbitrary key.
    /// Uses anonymous query token routing for reply privacy.
    pub async fn request_dht_key(&self, key: &DhtId) -> Result<()> {
        let mut bloom = BloomFilter::new();
        bloom.insert(&self.peer_id());
        let mut query_token = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut query_token);
        self.query_tokens
            .lock()
            .await
            .insert(query_token, (self.peer_id(), Instant::now()));
        let params = self.dht_query_params().await;
        let get = DhtGetMsg {
            key: *key.as_bytes(),
            query_token,
            hop_count: 0,
            hop_limit: params.hop_limit,
            bloom: bloom.to_bytes(),
        };
        let encoded = get.to_wire().encode();

        let links = self.links.lock().await;
        for (peer_id, link) in links.iter() {
            if let Err(e) = link.send_message(&encoded).await {
                log::warn!("Failed to send TNS DHT GET to {:?}: {}", peer_id, e);
            }
        }
        Ok(())
    }

    /// Issue a DHT search for `key` and return a [`DhtSearch`] stream that yields
    /// distinct, infra-verified records as responses route back, ending at
    /// `deadline`. This is the single read primitive: it ties the act of reading
    /// search results to actually having issued the query, and replaces the old
    /// "fire a `request_*` then busy-poll the store" pattern. Dropping the
    /// returned stream cancels the search (RAII) — callers terminate simply by
    /// breaking their loop or letting it fall out of scope.
    pub async fn dht_search(&self, key: DhtId, deadline: Instant) -> DhtSearch {
        let mut bloom = BloomFilter::new();
        bloom.insert(&self.peer_id());
        let mut query_token = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut query_token);
        self.query_tokens
            .lock()
            .await
            .insert(query_token, (self.peer_id(), Instant::now()));
        // Bounded: the stream is used as a wake-up signal and callers re-read the
        // store (which holds every delivered record), so a dropped send is
        // harmless — the next wake still sees the complete picture.
        let (tx, rx) = mpsc::channel(16);
        self.dht_searches.lock().unwrap().insert(query_token, tx);

        let params = self.dht_query_params().await;
        let get = DhtGetMsg {
            key: *key.as_bytes(),
            query_token,
            hop_count: 0,
            hop_limit: params.hop_limit,
            bloom: bloom.to_bytes(),
        };
        let encoded = get.to_wire().encode();
        {
            let links = self.links.lock().await;
            for (peer_id, link) in links.iter() {
                if let Err(e) = link.send_message(&encoded).await {
                    log::warn!("Failed to send DHT search GET to {:?}: {}", peer_id, e);
                }
            }
        }

        DhtSearch {
            rx,
            token: query_token,
            deadline,
            seen: HashSet::new(),
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

/// A live DHT search: an async stream of distinct, infra-verified records routed
/// back for one query. The only way to consume search results, so a caller
/// cannot read results without having issued the query (the read-side mirror of
/// the typed publish constructors). [`Drop`] deregisters the query token,
/// cancelling the search.
pub struct DhtSearch {
    rx: mpsc::Receiver<crate::dht::VerifiedRecord>,
    token: [u8; 32],
    deadline: Instant,
    /// Fingerprints of records already yielded, so a record delivered over
    /// multiple R5N paths is surfaced once.
    seen: HashSet<[u8; 64]>,
    registry: Arc<std::sync::Mutex<HashMap<[u8; 32], mpsc::Sender<crate::dht::VerifiedRecord>>>>,
}

impl DhtSearch {
    /// Await the next distinct verified record, or `None` once the deadline
    /// passes (or the node shuts the channel). Records are guaranteed to have
    /// cleared the trust gate — invalid records never reach application logic.
    pub async fn next(&mut self) -> Option<crate::dht::VerifiedRecord> {
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let rec = tokio::select! {
                r = self.rx.recv() => r?,
                _ = tokio::time::sleep(remaining) => return None,
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
            reg.remove(&self.token);
        }
    }
}
