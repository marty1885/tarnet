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
    /// random walk for the first l2nse hops, then greedy convergence toward the key.
    /// Advisory bloom is respected for non-critical peers but overridden for
    /// k-closest to resist bloom-stuffing attacks.
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
        let targets = if hop_count < (l2nse.round().min(255.0) as u8) {
            random_select(&all_peers, params.fan_out)
        } else {
            probabilistic_select(key, &all_peers, params.fan_out)
        };

        let links = self.links.lock().await;
        if targets.is_empty() {
            for (peer_id, link) in links.iter() {
                if *peer_id != from && !bloom.contains(peer_id) {
                    let _ = link.send_message(encoded).await;
                }
            }
        } else {
            for (pid, _) in &targets {
                if *pid != from
                    && (!bloom.contains(pid) || is_k_closest(pid, key, &all_peers, DHT_K))
                {
                    if let Some(link) = links.get(pid) {
                        let _ = link.send_message(encoded).await;
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
        let inner_hash: [u8; 64] = blake3_hash_64(value);
        let (key, blob) = crate::dht::content_address_put(value);

        let record = crate::dht::DhtRecord {
            key: key.clone(),
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            signer_algo: 0,
            signer_pubkey: Vec::new(),
            value: blob.clone(),
            ttl: Duration::from_secs(3600),
            stored_at: std::time::Instant::now(),
            signature: Vec::new(),
        };
        self.db_upsert_dht_record(&record);
        self.dht_store.lock().await.put(record);

        let mut bloom = BloomFilter::new();
        bloom.insert(&self.peer_id());
        let put = DhtPutMsg {
            key: *key.as_bytes(),
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            ttl: 3600,
            value: blob,
            signature: Vec::new(),
            signer_algo: 0,
            signer_pubkey: Vec::new(),
            hop_count: 0,
            hop_limit: params.hop_limit,
            bloom: bloom.to_bytes(),
        };
        let encoded = put.to_wire().encode();

        let kb = self.kbucket.lock().await;
        let all_peers = kb.all_peers();
        let targets = probabilistic_select(&key, &all_peers, params.fan_out);
        drop(kb);

        let links = self.links.lock().await;
        if targets.is_empty() {
            for (_, link) in links.iter() {
                let _ = link.send_message(&encoded).await;
            }
        } else {
            for (pid, _) in &targets {
                if let Some(link) = links.get(pid) {
                    let _ = link.send_message(&encoded).await;
                }
            }
            for (pid, link) in links.iter() {
                if !targets.iter().any(|(p, _)| p == pid) {
                    let _ = link.send_message(&encoded).await;
                }
            }
        }

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
        let inner_hash: [u8; 64] = blake3_hash_64(value);
        let (key, blob) = crate::dht::content_address_put(value);

        let mut seq = self.signed_content_sequence.lock().await;
        *seq += 1;
        let sequence = *seq;
        self.db_set_metadata("signed_content_sequence", sequence);
        drop(seq);

        let signer = *self.peer_id().as_bytes();
        let mut bloom = BloomFilter::new();
        bloom.insert(&self.peer_id());
        let mut put = DhtPutMsg {
            key: *key.as_bytes(),
            record_type: RecordType::SignedContent,
            sequence,
            signer,
            ttl: ttl_secs,
            value: blob.clone(),
            signature: Vec::new(),
            signer_algo: self.identity.identity.signing.algo() as u8,
            signer_pubkey: self.identity.identity.signing.signing_pubkey_bytes(),
            hop_count: 0,
            hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
            bloom: bloom.to_bytes(),
        };
        put.signature = self.identity.sign(&put.signable_bytes());

        let record = crate::dht::DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence,
            signer,
            signer_algo: put.signer_algo,
            signer_pubkey: put.signer_pubkey.clone(),
            value: blob,
            ttl: Duration::from_secs(ttl_secs as u64),
            stored_at: std::time::Instant::now(),
            signature: put.signature.clone(),
        };
        self.db_upsert_dht_record(&record);
        self.dht_store.lock().await.put(record);

        // L2NSE-driven propagation to targeted peers
        let kb = self.kbucket.lock().await;
        let all_peers = kb.all_peers();
        let l2nse = kb.estimate_l2nse();
        drop(kb);
        let params = DhtQueryParams::from_l2nse(l2nse);
        put.hop_limit = params.hop_limit;
        let targets = probabilistic_select(&key, &all_peers, params.fan_out);

        let encoded = put.to_wire().encode();
        let links = self.links.lock().await;
        if targets.is_empty() {
            for (_, link) in links.iter() {
                let _ = link.send_message(&encoded).await;
            }
        } else {
            for (pid, _) in &targets {
                if let Some(link) = links.get(pid) {
                    let _ = link.send_message(&encoded).await;
                }
            }
            // Also send to direct neighbors not in selected set
            for (pid, link) in links.iter() {
                if !targets.iter().any(|(p, _)| p == pid) {
                    let _ = link.send_message(&encoded).await;
                }
            }
        }

        log::info!("DHT signed content put (key: {:?})", key);
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
            if let Ok(plaintext) = crate::dht::content_address_get(inner_hash, &record.value) {
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

    /// Store signed content at an arbitrary DHT key (not content-addressed).
    /// The caller provides the signing keypair (zone key), the DHT key, the
    /// already-encrypted value, and a TTL.
    pub async fn dht_put_signed_at_key(
        &self,
        signer_keypair: &crate::identity::Keypair,
        key: DhtId,
        value: &[u8],
        ttl_secs: u32,
    ) -> Result<()> {
        let mut seq = self.signed_content_sequence.lock().await;
        *seq += 1;
        let sequence = *seq;
        self.db_set_metadata("signed_content_sequence", sequence);
        drop(seq);

        let signer = *signer_keypair.peer_id().as_bytes();
        let mut bloom = BloomFilter::new();
        bloom.insert(&self.peer_id());
        let mut put = DhtPutMsg {
            key: *key.as_bytes(),
            record_type: RecordType::SignedContent,
            sequence,
            signer,
            ttl: ttl_secs,
            value: value.to_vec(),
            signature: Vec::new(),
            signer_algo: signer_keypair.identity.signing.algo() as u8,
            signer_pubkey: signer_keypair.identity.signing.signing_pubkey_bytes(),
            hop_count: 0,
            hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
            bloom: bloom.to_bytes(),
        };
        put.signature = signer_keypair.sign(&put.signable_bytes());

        let record = crate::dht::DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence,
            signer,
            signer_algo: put.signer_algo,
            signer_pubkey: put.signer_pubkey.clone(),
            value: value.to_vec(),
            ttl: Duration::from_secs(ttl_secs as u64),
            stored_at: std::time::Instant::now(),
            signature: put.signature.clone(),
        };
        self.db_upsert_dht_record(&record);
        self.dht_store.lock().await.put(record);

        // L2NSE-driven propagation
        let kb = self.kbucket.lock().await;
        let all_peers = kb.all_peers();
        let l2nse = kb.estimate_l2nse();
        drop(kb);
        let params = DhtQueryParams::from_l2nse(l2nse);
        put.hop_limit = params.hop_limit;
        let targets = probabilistic_select(&key, &all_peers, params.fan_out);

        let encoded = put.to_wire().encode();
        let links = self.links.lock().await;
        if targets.is_empty() {
            for (_, link) in links.iter() {
                let _ = link.send_message(&encoded).await;
            }
        } else {
            for (pid, _) in &targets {
                if let Some(link) = links.get(pid) {
                    let _ = link.send_message(&encoded).await;
                }
            }
            for (pid, link) in links.iter() {
                if !targets.iter().any(|(p, _)| p == pid) {
                    let _ = link.send_message(&encoded).await;
                }
            }
        }

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
}
