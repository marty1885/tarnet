use std::collections::HashMap;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::{Rng, RngCore};

use crate::identity::{dht_id_from_peer_id, Keypair};
use crate::state::{PersistedRecord, StorageLimits};
use crate::types::{DhtId, PeerId, RecordType, Result};

/// 64-byte XOF hash.
fn hash_64(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    blake3::Hasher::new()
        .update(input)
        .finalize_xof()
        .fill(&mut out);
    out
}

/// Replication factor.
pub const DHT_K: usize = 20;
/// Maximum entries per k-bucket.
pub const KBUCKET_SIZE: usize = 20;

/// Application-tunable parameters for DHT queries.
#[derive(Debug, Clone, Copy)]
pub struct DhtQueryParams {
    /// Maximum hops a PUT/GET will travel.
    pub hop_limit: u8,
    /// Number of peers to forward to at each hop.
    pub fan_out: usize,
}

impl Default for DhtQueryParams {
    fn default() -> Self {
        Self {
            hop_limit: 10,
            fan_out: DHT_K,
        }
    }
}

impl DhtQueryParams {
    /// Compute query parameters from an L2NSE (log₂ network size estimate).
    ///
    /// - `hop_limit`: L2NSE + 2, floored at 4, capped at 20.
    /// - `fan_out`: DHT_K for small networks, scales up slowly for large ones.
    pub fn from_l2nse(l2nse: f64) -> Self {
        let hop_limit = (l2nse + 2.0).round().clamp(4.0, 20.0) as u8;
        let fan_out = if l2nse < 5.0 {
            DHT_K
        } else {
            (l2nse * 2.0)
                .round()
                .clamp(DHT_K as f64, (DHT_K * 2) as f64) as usize
        };
        Self { hop_limit, fan_out }
    }
}

/// A stored DHT record.
#[derive(Debug, Clone)]
pub struct DhtRecord {
    pub key: DhtId,
    pub record_type: RecordType,
    pub sequence: u64,
    pub signer: [u8; 32],
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
    pub value: Vec<u8>,
    pub ttl: Duration,
    pub stored_at: Instant,
    pub signature: Vec<u8>,
}

impl DhtRecord {
    pub fn is_expired(&self) -> bool {
        self.stored_at.elapsed() > self.ttl
    }

    /// Build the wire `DhtResponseRecord` for this stored record. Copies *every*
    /// signed field (notably `signer_pubkey`) by construction, so a GET response
    /// can never silently drop a field the verifier needs — the original
    /// "resolution only works via push" bug was a hand-copy that omitted it.
    pub fn to_response_record(&self) -> crate::wire::DhtResponseRecord {
        crate::wire::DhtResponseRecord {
            record_type: self.record_type,
            sequence: self.sequence,
            signer: self.signer,
            ttl: self.remaining_ttl().as_secs() as u32,
            value: self.value.clone(),
            signature: self.signature.clone(),
            signer_algo: self.signer_algo,
            signer_pubkey: self.signer_pubkey.clone(),
        }
    }

    /// Build a wire `DhtPutMsg` to (re)propagate this stored record, with the
    /// originator seeded into the bloom filter. Same guarantee as
    /// [`to_response_record`](Self::to_response_record): all signed fields are
    /// copied, never re-derived or omitted. Carries the full stored `ttl`
    /// (matching the existing replication / link-up propagation behavior).
    pub fn to_put_msg(&self, originator: &PeerId, hop_limit: u8) -> crate::wire::DhtPutMsg {
        let mut bloom = BloomFilter::new();
        bloom.insert(originator);
        crate::wire::DhtPutMsg {
            key: *self.key.as_bytes(),
            record_type: self.record_type,
            sequence: self.sequence,
            signer: self.signer,
            ttl: self.ttl.as_secs() as u32,
            value: self.value.clone(),
            signature: self.signature.clone(),
            signer_algo: self.signer_algo,
            signer_pubkey: self.signer_pubkey.clone(),
            hop_count: 0,
            hop_limit,
            bloom: bloom.to_bytes(),
        }
    }

    fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.stored_at.elapsed())
    }
}

/// Canonical bytes covered by a signed DHT record's signature:
/// `key || record_type || sequence(BE) || value`.
///
/// Single source of truth: [`crate::wire::DhtPutMsg::signable_bytes`] and
/// [`verify_incoming_record`] both build the signable through this, so the signed
/// layout can never drift between the signing side and the verifying side.
pub fn record_signable(key: &[u8; 64], record_type: RecordType, sequence: u64, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + 1 + 8 + value.len());
    buf.extend_from_slice(key);
    buf.push(record_type.as_u8());
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(value);
    buf
}

/// Build and sign a `DhtRecord`: derives `signer` / `signer_algo` /
/// `signer_pubkey` from the keypair and signs the canonical signable. This is
/// the single place publish-side signing happens, so `signer` can never drift
/// from the pubkey that signed (the binding the ingest gate re-checks).
fn sign_record(
    kp: &Keypair,
    key: DhtId,
    record_type: RecordType,
    sequence: u64,
    value: Vec<u8>,
    ttl: Duration,
) -> DhtRecord {
    let signature = kp.sign(&record_signable(key.as_bytes(), record_type, sequence, &value));
    DhtRecord {
        key,
        record_type,
        sequence,
        signer: *kp.peer_id().as_bytes(),
        signer_algo: kp.identity.signing.algo() as u8,
        signer_pubkey: kp.identity.signing.signing_pubkey_bytes(),
        value,
        ttl,
        stored_at: Instant::now(),
        signature,
    }
}

/// The single gate every inbound signed record must pass before it is trusted or
/// stored. Returns `Err(reason)` (suitable for logging) when the record must be
/// dropped.
///
/// Every DHT ingest path — `DhtPut`, `DhtGetResponse`, `DhtWatchNotify` — routes
/// through here, so the invariants (signer pubkey present, pubkey bound to the
/// claimed signer PeerId, signature valid over the canonical signable) are
/// enforced identically. Previously these were hand-coded per handler and had
/// drifted: GET responses verified against an absent pubkey, and watch notifies
/// skipped the pubkey↔signer binding entirely.
pub fn verify_incoming_record(
    key: &[u8; 64],
    record_type: RecordType,
    sequence: u64,
    value: &[u8],
    signer: &[u8; 32],
    signer_algo: u8,
    signer_pubkey: &[u8],
    signature: &[u8],
) -> std::result::Result<(), &'static str> {
    if !record_type.is_signed() {
        return Ok(());
    }
    let algo =
        tarnet_api::types::SigningAlgo::from_u8(signer_algo).map_err(|_| "unknown signer algo")?;
    if signer_pubkey.is_empty() {
        return Err("missing signer pubkey");
    }
    if crate::identity::peer_id_from_signing_pubkey(signer_pubkey) != PeerId(*signer) {
        return Err("signer pubkey does not match signer PeerId");
    }
    let signable = record_signable(key, record_type, sequence, value);
    if !crate::identity::verify(algo, signer_pubkey, &signable, signature) {
        return Err("invalid signature");
    }
    Ok(())
}

/// A [`DhtRecord`] that is safe to store: it either passed the trust gate
/// ([`verify_incoming`](Self::verify_incoming)) or originated from a source this
/// node already trusts ([`locally_trusted`](Self::locally_trusted)).
///
/// This is "parse, don't validate" applied to the DHT store: the inner record is
/// private and there is no public constructor that skips both checks, so the only
/// way to obtain a `VerifiedRecord` is to go through one of the two paths below.
/// Because [`DhtStore::put`] accepts *only* `VerifiedRecord`, it is impossible —
/// on any present or future code path — to store a record whose signature was
/// never checked. The compiler enforces what call-site discipline used to.
#[derive(Clone)]
pub struct VerifiedRecord(DhtRecord);

impl VerifiedRecord {
    /// Trust gate for records arriving from the network. Routes through
    /// [`verify_incoming_record`]; returns `Err(reason)` (suitable for logging)
    /// when the record must be dropped. This is the ONLY way an inbound,
    /// attacker-influenced record can become storable.
    pub fn verify_incoming(record: DhtRecord) -> std::result::Result<Self, &'static str> {
        verify_incoming_record(
            record.key.as_bytes(),
            record.record_type,
            record.sequence,
            &record.value,
            &record.signer,
            record.signer_algo,
            &record.signer_pubkey,
            &record.signature,
        )?;
        Ok(Self(record))
    }

    /// Trust a record by origin rather than by re-checking its signature: one
    /// this node just minted and signed itself (the publish path), or a test
    /// fixture. Callers must have produced the signature themselves — never pass
    /// an externally-sourced record here; use [`verify_incoming`](Self::verify_incoming)
    /// for that.
    ///
    /// Prefer the typed publish constructors ([`new_content`](Self::new_content),
    /// [`new_signed_content`](Self::new_signed_content),
    /// [`new_signed_at_key`](Self::new_signed_at_key), [`new_hello`](Self::new_hello))
    /// over this: they apply the correct encryption and signing for the record
    /// type *by construction*, so there is no per-call-site chance to forget a
    /// step. This bare escape hatch exists for self-minted records that don't fit
    /// a constructor and for test fixtures with dummy signatures.
    pub fn locally_trusted(record: DhtRecord) -> Self {
        Self(record)
    }

    // ── Typed publish constructors ──
    //
    // Each mints a record that is valid *by construction*: it derives the key,
    // applies the encryption appropriate to the record type, and signs (where
    // the type is signed) with fields derived from the keypair. Because these
    // return a `VerifiedRecord` and `DhtStore::put` accepts only `VerifiedRecord`,
    // a publish path physically cannot store a record that skipped encryption or
    // signing. This is the publish-side mirror of [`verify_incoming`].

    /// Mint an unsigned, content-addressed record. The value is content-addressed
    /// (key = `H(H(v))`, enc-key = `H(v)`), so storage nodes hold only an opaque
    /// blob. Returns the record and the inner hash a reader needs to fetch and
    /// decrypt it.
    pub fn new_content(plaintext: &[u8], ttl: Duration) -> (Self, [u8; 64]) {
        let inner_hash = hash_64(plaintext);
        let (key, blob) = content_address_put(plaintext);
        let record = DhtRecord {
            key,
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            signer_algo: 0,
            signer_pubkey: Vec::new(),
            value: blob,
            ttl,
            stored_at: Instant::now(),
            signature: Vec::new(),
        };
        (Self(record), inner_hash)
    }

    /// Mint a signed, content-addressed record. The value is content-addressed
    /// and then wrapped with [`signed_record_encrypt`] under the lookup key, so
    /// storage nodes see only a blob; the record is signed by `signer`. Returns
    /// the record and the inner hash a reader needs to fetch and decrypt it.
    pub fn new_signed_content(
        signer: &Keypair,
        plaintext: &[u8],
        sequence: u64,
        ttl: Duration,
    ) -> (Self, [u8; 64]) {
        let inner_hash = hash_64(plaintext);
        let (key, blob) = content_address_put(plaintext);
        let value = signed_record_encrypt(&key, &blob);
        let record = sign_record(signer, key, RecordType::SignedContent, sequence, value, ttl);
        (Self(record), inner_hash)
    }

    /// Mint a signed record at an arbitrary lookup key (TNS / pool). `value` is
    /// the caller's payload, stored verbatim — the caller is responsible for any
    /// confidentiality (e.g. the TNS layer AEAD-seals a self-authenticating
    /// bundle). `signer` here is a *disposable* per-label key, not the zone's
    /// master key, so the master signing pubkey never appears on the DHT.
    pub fn new_signed_at_key(
        signer: &Keypair,
        key: DhtId,
        value: &[u8],
        sequence: u64,
        ttl: Duration,
    ) -> Self {
        Self(sign_record(
            signer,
            key,
            RecordType::SignedContent,
            sequence,
            value.to_vec(),
            ttl,
        ))
    }

    /// Mint a Hello record at the identity-addressed key for `identity`. The
    /// serialized hello bytes are wrapped with [`signed_record_encrypt`] under
    /// the key so storage nodes see only a blob, then signed by `identity`.
    pub fn new_hello(identity: &Keypair, hello_bytes: &[u8], sequence: u64, ttl: Duration) -> Self {
        let key = identity_address_key(&identity.peer_id());
        let encrypted = signed_record_encrypt(&key, hello_bytes);
        Self(sign_record(
            identity,
            key,
            RecordType::Hello,
            sequence,
            encrypted,
            ttl,
        ))
    }

    // ── Ingest constructors ──
    //
    // Build a record from a wire message and run it through the trust gate in one
    // step, so the inbound handlers never hand-assemble a `DhtRecord` literal
    // (the historical source of dropped-field bugs).

    /// Build and verify a record from an inbound [`DhtPutMsg`](crate::wire::DhtPutMsg).
    pub fn from_put_msg(
        put: &crate::wire::DhtPutMsg,
    ) -> std::result::Result<Self, &'static str> {
        Self::verify_incoming(DhtRecord {
            key: DhtId(put.key),
            record_type: put.record_type,
            sequence: put.sequence,
            signer: put.signer,
            signer_algo: put.signer_algo,
            signer_pubkey: put.signer_pubkey.clone(),
            value: put.value.clone(),
            ttl: Duration::from_secs(put.ttl as u64),
            stored_at: Instant::now(),
            signature: put.signature.clone(),
        })
    }

    /// Build and verify a record from an inbound
    /// [`DhtResponseRecord`](crate::wire::DhtResponseRecord) at `key`.
    pub fn from_response_record(
        key: DhtId,
        rec: &crate::wire::DhtResponseRecord,
    ) -> std::result::Result<Self, &'static str> {
        Self::verify_incoming(DhtRecord {
            key,
            record_type: rec.record_type,
            sequence: rec.sequence,
            signer: rec.signer,
            signer_algo: rec.signer_algo,
            signer_pubkey: rec.signer_pubkey.clone(),
            value: rec.value.clone(),
            ttl: Duration::from_secs(rec.ttl as u64),
            stored_at: Instant::now(),
            signature: rec.signature.clone(),
        })
    }

    /// Borrow the inner record (e.g. to persist it).
    pub fn record(&self) -> &DhtRecord {
        &self.0
    }

    /// Consume and yield the inner record.
    pub fn into_inner(self) -> DhtRecord {
        self.0
    }
}

/// Local DHT storage. Supports multiple records per key (supplemental).
pub struct DhtStore {
    records: HashMap<[u8; 64], Vec<DhtRecord>>,
    local_id: DhtId,
    limits: StorageLimits,
}

impl DhtStore {
    pub fn new(local_peer: &PeerId) -> Self {
        Self::with_limits(local_peer, StorageLimits::default())
    }

    pub fn with_limits(local_peer: &PeerId, limits: StorageLimits) -> Self {
        Self {
            records: HashMap::new(),
            local_id: dht_id_from_peer_id(local_peer),
            limits,
        }
    }

    /// Store a record locally with type-aware replacement policy.
    /// - Hello: same signer + higher sequence replaces existing.
    /// - SignedContent: add if new signer (supplemental), same signer replaces.
    /// - Content: first write wins (single record per key).
    pub fn put(&mut self, record: VerifiedRecord) {
        let record = record.into_inner();
        self.expire();
        if record.value.len() > self.limits.max_value_bytes {
            return;
        }

        let key = *record.key.as_bytes();
        let entries = self.records.entry(key).or_default();

        match record.record_type {
            RecordType::Hello => {
                // Same signer + strictly higher sequence replaces
                upsert_by_signer(entries, record, false);
            }
            RecordType::SignedContent => {
                // Different signers are supplemental; same signer replaces if >= sequence
                upsert_by_signer(entries, record, true);
            }
            RecordType::Content => {
                // Keep up to N candidates to resist poisoning attacks.
                // The authentic record is identified at retrieval time via
                // content-address decryption; storage nodes cannot verify.
                const MAX_CONTENT_CANDIDATES: usize = 5;
                if entries.len() < MAX_CONTENT_CANDIDATES
                    && !entries.iter().any(|r| r.value == record.value)
                {
                    entries.push(record);
                }
            }
            RecordType::Unknown(_) => {
                // Best-effort store-and-relay: same signer + strictly higher sequence replaces
                upsert_by_signer(entries, record, false);
            }
        }

        self.enforce_key_limits(&key);
        self.enforce_global_limits();
    }

    /// Retrieve all non-expired records at a key.
    pub fn get(&self, key: &DhtId) -> Vec<&DhtRecord> {
        match self.records.get(key.as_bytes()) {
            Some(entries) => entries.iter().filter(|r| !r.is_expired()).collect(),
            None => Vec::new(),
        }
    }

    /// Remove expired records.
    pub fn expire(&mut self) {
        for entries in self.records.values_mut() {
            entries.retain(|r| !r.is_expired());
        }
        self.records.retain(|_, v| !v.is_empty());
    }

    /// Our DHT ID.
    pub fn local_id(&self) -> &DhtId {
        &self.local_id
    }

    pub fn limits(&self) -> StorageLimits {
        self.limits
    }

    /// Number of distinct keys with non-expired records.
    pub fn key_count(&self) -> usize {
        self.records
            .iter()
            .filter(|(_, v)| v.iter().any(|r| !r.is_expired()))
            .count()
    }

    /// Total number of non-expired records across all keys.
    pub fn record_count(&self) -> usize {
        self.records
            .values()
            .flat_map(|v| v.iter())
            .filter(|r| !r.is_expired())
            .count()
    }

    /// Iterate over all non-expired records.
    pub fn all_records(&self) -> Vec<&DhtRecord> {
        self.records
            .values()
            .flat_map(|entries| entries.iter())
            .filter(|r| !r.is_expired())
            .collect()
    }

    pub fn export_records(&self) -> Vec<PersistedRecord> {
        self.all_records()
            .into_iter()
            .filter_map(PersistedRecord::from_live)
            .collect()
    }

    /// Re-verify each persisted record on the way back in, dropping any that no
    /// longer pass the trust gate (DB corruption or tampering). Records that
    /// passed verification when first accepted re-verify here, since their signed
    /// fields round-trip faithfully through persistence.
    pub fn import_records(&mut self, records: Vec<PersistedRecord>) {
        for record in records {
            match VerifiedRecord::verify_incoming(record.into_live()) {
                Ok(verified) => self.put(verified),
                Err(reason) => {
                    log::warn!("dropping persisted DHT record on load: {}", reason)
                }
            }
        }
    }

    fn total_record_count(&self) -> usize {
        self.records.values().map(Vec::len).sum()
    }

    fn total_bytes(&self) -> usize {
        self.records
            .values()
            .flat_map(|entries| entries.iter())
            .map(record_cost)
            .sum()
    }

    fn enforce_key_limits(&mut self, key: &[u8; 64]) {
        let max_records_per_key = self.limits.max_records_per_key;
        let max_bytes_per_key = self.limits.max_bytes_per_key;

        if let Some(entries) = self.records.get_mut(key) {
            let mut byte_total: usize = entries.iter().map(record_cost).sum();
            while entries.len() > max_records_per_key || byte_total > max_bytes_per_key {
                if let Some(idx) = oldest_record_index(entries) {
                    byte_total -= record_cost(&entries[idx]);
                    entries.remove(idx);
                } else {
                    break;
                }
            }
        }

        self.records.retain(|_, v| !v.is_empty());
    }

    fn enforce_global_limits(&mut self) {
        let mut record_count = self.total_record_count();
        let mut byte_count = self.total_bytes();

        while record_count > self.limits.max_records || byte_count > self.limits.max_total_bytes {
            let Some((key, idx)) = self.oldest_record_location() else {
                break;
            };
            if let Some(entries) = self.records.get_mut(&key) {
                byte_count -= record_cost(&entries[idx]);
                entries.remove(idx);
                record_count -= 1;
                if entries.is_empty() {
                    self.records.remove(&key);
                }
            }
        }
    }

    fn oldest_record_location(&self) -> Option<([u8; 64], usize)> {
        self.records
            .iter()
            .flat_map(|(key, entries)| {
                entries
                    .iter()
                    .enumerate()
                    .map(move |(idx, record)| (*key, idx, record.stored_at))
            })
            .min_by_key(|(_, _, stored_at)| *stored_at)
            .map(|(key, idx, _)| (key, idx))
    }
}

/// Upsert a record by signer: if a record with the same signer exists, replace it
/// if the new sequence is higher (or equal when `allow_equal` is true); otherwise append.
/// Returns whether the record was stored.
fn upsert_by_signer(entries: &mut Vec<DhtRecord>, record: DhtRecord, allow_equal: bool) -> bool {
    if let Some(existing) = entries.iter_mut().find(|r| r.signer == record.signer) {
        if record.sequence > existing.sequence
            || (allow_equal && record.sequence == existing.sequence)
        {
            *existing = record;
            return true;
        }
        false
    } else {
        entries.push(record);
        true
    }
}

fn oldest_record_index(entries: &[DhtRecord]) -> Option<usize> {
    entries
        .iter()
        .enumerate()
        .min_by_key(|(_, record)| record.stored_at)
        .map(|(idx, _)| idx)
}

fn record_cost(record: &DhtRecord) -> usize {
    // key(64) + record_type(1) + sequence(8) + signer(32) + signer_algo(1) + ttl(8) + stored_at(8) + signature + value
    64 + 1 + 8 + 32 + 1 + 8 + 8 + record.signature.len() + record.value.len()
}

/// A remote watch on a DHT key, identified by query_token for anonymous
/// notification routing. The storing node never learns the watcher's identity.
#[derive(Debug, Clone)]
pub struct DhtWatch {
    /// Opaque token used to route notifications back hop-by-hop.
    pub query_token: [u8; 32],
    /// Direct neighbor that forwarded this watch (for sending notifications).
    pub via_peer: PeerId,
    pub expires_at: Instant,
}

/// Table of remote watches on DHT keys, indexed by query_token.
pub struct DhtWatchTable {
    watches: HashMap<[u8; 64], Vec<DhtWatch>>,
}

impl DhtWatchTable {
    pub fn new() -> Self {
        Self {
            watches: HashMap::new(),
        }
    }

    /// Total number of active remote watch subscriptions.
    pub fn watch_count(&self) -> usize {
        self.watches.values().map(|v| v.len()).sum()
    }

    /// Set or cancel a watch. expiration_secs=0 cancels by query_token.
    pub fn set_watch(
        &mut self,
        key: [u8; 64],
        query_token: [u8; 32],
        via_peer: PeerId,
        expiration_secs: u32,
    ) {
        if expiration_secs == 0 {
            // Cancel by token
            if let Some(entries) = self.watches.get_mut(&key) {
                entries.retain(|w| w.query_token != query_token);
                if entries.is_empty() {
                    self.watches.remove(&key);
                }
            }
            return;
        }

        let expires_at = Instant::now() + Duration::from_secs(expiration_secs as u64);
        let entries = self.watches.entry(key).or_default();
        // Refresh if same token already watching
        if let Some(existing) = entries.iter_mut().find(|w| w.query_token == query_token) {
            existing.expires_at = expires_at;
            existing.via_peer = via_peer;
        } else {
            entries.push(DhtWatch {
                query_token,
                via_peer,
                expires_at,
            });
        }
    }

    /// Get all non-expired watchers for a key: returns (query_token, via_peer).
    pub fn get_watchers(&self, key: &[u8; 64]) -> Vec<([u8; 32], PeerId)> {
        let now = Instant::now();
        match self.watches.get(key) {
            Some(entries) => entries
                .iter()
                .filter(|w| w.expires_at > now)
                .map(|w| (w.query_token, w.via_peer))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Remove expired watches.
    pub fn expire(&mut self) {
        let now = Instant::now();
        for entries in self.watches.values_mut() {
            entries.retain(|w| w.expires_at > now);
        }
        self.watches.retain(|_, v| !v.is_empty());
    }

    /// Remove all watches routed through a specific peer (link went down).
    pub fn remove_peer(&mut self, peer: &PeerId) {
        for entries in self.watches.values_mut() {
            entries.retain(|w| w.via_peer != *peer);
        }
        self.watches.retain(|_, v| !v.is_empty());
    }
}

// ── K-Bucket Routing Table ──

/// Entry in a k-bucket.
#[derive(Debug, Clone)]
pub struct KBucketEntry {
    pub peer_id: PeerId,
    pub dht_id: DhtId,
    pub last_seen: Instant,
}

/// K-bucket routing table organizing peers by XOR distance.
pub struct KBucketTable {
    buckets: Vec<Vec<KBucketEntry>>,
    pub local_id: DhtId,
}

impl KBucketTable {
    pub fn new(local_peer: &PeerId) -> Self {
        let local_id = dht_id_from_peer_id(local_peer);
        Self {
            buckets: (0..512).map(|_| Vec::new()).collect(),
            local_id,
        }
    }

    /// Find the bucket index for a given DHT ID (highest differing bit).
    pub fn bucket_index(&self, id: &DhtId) -> usize {
        let dist = self.local_id.xor_distance(id);
        // Find the highest set bit
        for byte_idx in 0..64 {
            let byte = dist.0[byte_idx];
            if byte != 0 {
                let bit = 7 - byte.leading_zeros() as usize;
                return (63 - byte_idx) * 8 + bit;
            }
        }
        0 // same ID
    }

    /// Insert a peer into the appropriate k-bucket.
    pub fn insert(&mut self, peer_id: PeerId, dht_id: DhtId) {
        if dht_id == self.local_id {
            return; // don't insert ourselves
        }
        let idx = self.bucket_index(&dht_id);
        let bucket = &mut self.buckets[idx];

        // If already present, update last_seen
        if let Some(entry) = bucket.iter_mut().find(|e| e.peer_id == peer_id) {
            entry.last_seen = Instant::now();
            return;
        }

        if bucket.len() < KBUCKET_SIZE {
            bucket.push(KBucketEntry {
                peer_id,
                dht_id,
                last_seen: Instant::now(),
            });
        } else {
            // Sybil-resistant eviction: prefer long-lived peers.
            // Discard the new peer unless the least-recently-seen bucket
            // member hasn't been heard from in over 5 minutes (likely dead).
            // This prevents an attacker from flushing established peers by
            // generating fresh identities — new nodes are discarded when the
            // bucket is healthy.
            const STALE_THRESHOLD: Duration = Duration::from_secs(300);
            if let Some(oldest_idx) = bucket
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(i, _)| i)
            {
                if bucket[oldest_idx].last_seen.elapsed() > STALE_THRESHOLD {
                    bucket[oldest_idx] = KBucketEntry {
                        peer_id,
                        dht_id,
                        last_seen: Instant::now(),
                    };
                }
                // Otherwise: bucket is full of active peers — discard the new one.
            }
        }
    }

    /// Find the k closest peers to a given key.
    pub fn closest_peers(&self, key: &DhtId, k: usize) -> Vec<(PeerId, DhtId)> {
        let mut all_peers: Vec<(PeerId, DhtId, DhtId)> = Vec::new();
        for bucket in &self.buckets {
            for entry in bucket {
                let dist = key.xor_distance(&entry.dht_id);
                all_peers.push((entry.peer_id, entry.dht_id, dist));
            }
        }
        all_peers.sort_by(|a, b| a.2.cmp(&b.2));
        all_peers
            .into_iter()
            .take(k)
            .map(|(pid, did, _)| (pid, did))
            .collect()
    }

    /// Get all known peers (for iteration).
    pub fn all_peers(&self) -> Vec<(PeerId, DhtId)> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.iter().map(|e| (e.peer_id, e.dht_id)))
            .collect()
    }

    /// Total number of peers in the table.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Estimate log₂ of network size from k-bucket occupancy.
    ///
    /// In a Kademlia-style DHT with uniformly distributed IDs, bucket `i`
    /// is expected to hold `N / 2^(512−i)` peers.  We scan from the highest
    /// bucket downward: the first non-full bucket gives the best estimate
    /// because full buckets are capped by `KBUCKET_SIZE` and lose information.
    ///
    /// With very few peers the bucket-based estimate is unreliable — two
    /// random peers land in bucket ~511, producing l2nse ≈ 512 which
    /// overflows u8 casts and `2u64.pow()`.  We use the number of
    /// *populated* buckets as a confidence bound: in a network of N
    /// uniformly-distributed nodes we expect ~log₂(N) distinct occupied
    /// buckets, so the bucket-based estimate should never vastly exceed
    /// the populated count.  This naturally constrains the estimate at
    /// startup while converging to the accurate bucket-based value once
    /// enough peers are known.
    ///
    /// Returns at least 1.0 (a network of two: us and one peer).
    pub fn estimate_l2nse(&self) -> f64 {
        let total_peers = self.len();
        if total_peers == 0 {
            return 1.0;
        }

        // Confidence bound: the number of distinct occupied buckets tracks
        // log₂(N) and is immune to the "few peers in high buckets" problem.
        let populated = self.buckets.iter().filter(|b| !b.is_empty()).count() as f64;

        // Walk from the top bucket down to find the best estimator.
        let raw = 'estimate: {
            for i in (0..self.buckets.len()).rev() {
                let count = self.buckets[i].len();
                if count == 0 {
                    continue;
                }
                if count < KBUCKET_SIZE {
                    // Partially filled: log₂(N) ≈ (i + 1) + log₂(count)
                    break 'estimate (i + 1) as f64 + (count as f64).log2();
                }
                // Full bucket — lower bound only.
                break 'estimate (i + 1) as f64 + (KBUCKET_SIZE as f64).log2();
            }
            1.0
        };

        // The bucket-based estimate refines within-bucket counts but can be
        // wildly off when only a handful of high buckets are populated.
        // Cap it to populated_count + small margin, then hard-clamp.
        raw.min(populated + 3.0).clamp(1.0, 30.0)
    }
}

// ── Bloom Filter ──

/// Simple 256-byte (2048-bit) bloom filter with 4 hash functions.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    pub bits: [u8; 256],
}

impl BloomFilter {
    pub fn new() -> Self {
        Self { bits: [0u8; 256] }
    }

    pub fn from_bytes(bytes: [u8; 256]) -> Self {
        Self { bits: bytes }
    }

    /// Insert a PeerId into the bloom filter.
    pub fn insert(&mut self, peer: &PeerId) {
        let hash: [u8; 64] = hash_64(peer.as_bytes());
        for i in 0..4 {
            let idx = u16::from_be_bytes([hash[i * 2], hash[i * 2 + 1]]) as usize % 2048;
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    /// Check if a PeerId might be in the bloom filter.
    pub fn contains(&self, peer: &PeerId) -> bool {
        let hash: [u8; 64] = hash_64(peer.as_bytes());
        for i in 0..4 {
            let idx = u16::from_be_bytes([hash[i * 2], hash[i * 2 + 1]]) as usize % 2048;
            if self.bits[idx / 8] & (1 << (idx % 8)) == 0 {
                return false;
            }
        }
        true
    }

    pub fn to_bytes(&self) -> [u8; 256] {
        self.bits
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a peer is among the k closest to a key.
pub fn is_k_closest(peer: &PeerId, key: &DhtId, peers: &[(PeerId, DhtId)], k: usize) -> bool {
    k_closest(key, peers, k).contains(peer)
}

/// Find the k closest peers to a key from a list of known peers.
pub fn k_closest(key: &DhtId, peers: &[(PeerId, DhtId)], k: usize) -> Vec<PeerId> {
    let mut with_dist: Vec<_> = peers
        .iter()
        .map(|(pid, did)| (pid, key.xor_distance(did)))
        .collect();
    with_dist.sort_by(|a, b| a.1.cmp(&b.1));
    with_dist.into_iter().take(k).map(|(pid, _)| *pid).collect()
}

/// Probabilistic forwarding: select up to `k` peers from the `3k` closest,
/// weighted by inverse XOR distance. Peers closer to the key are more likely
/// to be selected, but any peer in the candidate set has a chance. This gives
/// plausible deniability — an observer can't tell if a forward was targeted or
/// random — while still converging toward the key in O(log n) hops.
pub fn probabilistic_select(
    key: &DhtId,
    peers: &[(PeerId, DhtId)],
    k: usize,
) -> Vec<(PeerId, DhtId)> {
    if peers.is_empty() {
        return Vec::new();
    }

    // Gather 3k candidates sorted by distance
    let candidate_pool = k * 3;
    let mut candidates: Vec<(PeerId, DhtId, DhtId)> = peers
        .iter()
        .map(|(pid, did)| (*pid, *did, key.xor_distance(did)))
        .collect();
    candidates.sort_by(|a, b| a.2.cmp(&b.2));
    candidates.truncate(candidate_pool);

    if candidates.len() <= k {
        return candidates
            .into_iter()
            .map(|(pid, did, _)| (pid, did))
            .collect();
    }

    // Weight by inverse rank^2: rank 1 gets weight 1.0, rank 2 gets 0.25, etc.
    // This biases heavily toward closer peers while still giving further peers a shot.
    let weights: Vec<f64> = candidates
        .iter()
        .enumerate()
        .map(|(i, _)| 1.0 / ((i + 1) as f64).powi(2))
        .collect();
    let mut total_weight: f64 = weights.iter().sum();

    let mut rng = rand::thread_rng();
    let mut selected = Vec::with_capacity(k);
    let mut used = vec![false; candidates.len()];

    for _ in 0..k {
        if total_weight <= 0.0 {
            break;
        }
        let mut r: f64 = rng.gen::<f64>() * total_weight;
        let mut pick = 0;
        for (i, &w) in weights.iter().enumerate() {
            if used[i] {
                continue;
            }
            r -= w;
            if r <= 0.0 {
                pick = i;
                break;
            }
            pick = i;
        }
        if !used[pick] {
            used[pick] = true;
            total_weight -= weights[pick];
            let (pid, did, _) = &candidates[pick];
            selected.push((*pid, *did));
        }
    }

    selected
}

/// Random peer selection for the random-walk phase of R5N-style routing.
/// Picks up to `k` peers uniformly at random from the full peer set.
pub fn random_select(peers: &[(PeerId, DhtId)], k: usize) -> Vec<(PeerId, DhtId)> {
    if peers.len() <= k {
        return peers.to_vec();
    }
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    let mut shuffled = peers.to_vec();
    shuffled.shuffle(&mut rng);
    shuffled.truncate(k);
    shuffled
}

/// Content-addressed PUT: key = BLAKE3(BLAKE3(value)), stored value = XChaCha20-Poly1305(value, key=BLAKE3(value))
/// Self-authenticating: you need the content hash to look up AND decrypt.
pub fn content_address_put(value: &[u8]) -> (DhtId, Vec<u8>) {
    // Inner hash = BLAKE3(value) — used as encryption key
    let inner_hash: [u8; 64] = hash_64(value);
    // Outer hash = BLAKE3(inner_hash) — used as DHT key
    let outer_hash: [u8; 64] = hash_64(&inner_hash);
    let key = DhtId(outer_hash);

    // Derive 32-byte encryption key from inner hash
    let enc_key: [u8; 32] = *blake3::hash(&inner_hash).as_bytes();

    // Encrypt value with XChaCha20-Poly1305
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: value,
                aad: b"",
            },
        )
        .expect("AEAD encryption should not fail");

    // Stored blob: nonce || ciphertext+tag
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    (key, blob)
}

/// Content-addressed GET: decrypt using the content hash.
/// `content_hash` is BLAKE3(value) (the inner hash you must know a priori).
pub fn content_address_get(content_hash: &[u8; 64], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 + 16 {
        return Err(crate::types::Error::Wire("content blob too short".into()));
    }
    let nonce = &blob[..24];
    let ciphertext_with_tag = &blob[24..];

    let enc_key: [u8; 32] = *blake3::hash(content_hash).as_bytes();
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    let plaintext = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext_with_tag,
                aad: b"",
            },
        )
        .map_err(|_| crate::types::Error::Crypto("content AEAD decryption failed".into()))?;

    // Verify: BLAKE3(plaintext) should equal content_hash
    let check: [u8; 64] = hash_64(&plaintext);
    if check != *content_hash {
        return Err(crate::types::Error::Crypto(
            "content hash mismatch after decryption".into(),
        ));
    }

    Ok(plaintext)
}

/// Identity-addressed key: BLAKE2b(peer_pubkey)
pub fn identity_address_key(peer_id: &PeerId) -> DhtId {
    dht_id_from_peer_id(peer_id)
}

/// Encrypt the value of a signed or hello DHT record so that storage nodes
/// cannot read the content.  The encryption key is derived from the DHT
/// lookup key (which the querier already knows).
///
/// Layout of the returned blob: `nonce (24 bytes) || ciphertext+tag`.
pub fn signed_record_encrypt(dht_key: &DhtId, value: &[u8]) -> Vec<u8> {
    let enc_key: [u8; 32] = *blake3::hash(dht_key.as_bytes()).as_bytes();

    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: value,
                aad: b"",
            },
        )
        .expect("AEAD encryption should not fail");

    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob
}

/// Decrypt the value of a signed or hello DHT record using the DHT lookup key.
pub fn signed_record_decrypt(dht_key: &DhtId, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 + 16 {
        return Err(crate::types::Error::Wire(
            "signed record blob too short".into(),
        ));
    }
    let nonce = &blob[..24];
    let ciphertext_with_tag = &blob[24..];

    let enc_key: [u8; 32] = *blake3::hash(dht_key.as_bytes()).as_bytes();
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext_with_tag,
                aad: b"",
            },
        )
        .map_err(|_| crate::types::Error::Crypto("signed record AEAD decryption failed".into()))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;
    use crate::state::StorageLimits;

    /// Store a hand-built record in tests without going through the signature
    /// gate. These fixtures carry dummy signatures by design; `locally_trusted`
    /// is the sanctioned bypass for records the test itself constructs.
    fn put(store: &mut DhtStore, record: DhtRecord) {
        store.put(VerifiedRecord::locally_trusted(record));
    }

    /// Mint a genuinely-signed record, exactly as the publish path builds one:
    /// `signer`, `signer_algo`, and `signer_pubkey` are derived from `kp`, and the
    /// signature actually covers the canonical signable — so it passes the gate.
    fn signed_record(
        kp: &Keypair,
        key: DhtId,
        record_type: RecordType,
        sequence: u64,
        value: Vec<u8>,
    ) -> DhtRecord {
        let signature = kp.sign(&record_signable(key.as_bytes(), record_type, sequence, &value));
        DhtRecord {
            key,
            record_type,
            sequence,
            signer: *kp.peer_id().as_bytes(),
            signer_algo: kp.identity.signing.algo() as u8,
            signer_pubkey: kp.identity.signing.signing_pubkey_bytes(),
            value,
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signature,
        }
    }

    // ── Trust gate: VerifiedRecord::verify_incoming ──

    #[test]
    fn verify_incoming_accepts_genuine_signed_record() {
        let kp = Keypair::generate();
        let rec = signed_record(&kp, DhtId([0x01; 64]), RecordType::SignedContent, 1, b"payload".to_vec());
        assert!(VerifiedRecord::verify_incoming(rec).is_ok());
    }

    #[test]
    fn verify_incoming_rejects_empty_pubkey() {
        // The exact field the original DhtGet responder stripped: an otherwise
        // valid record with no signer pubkey must be rejected, never stored.
        let kp = Keypair::generate();
        let mut rec = signed_record(&kp, DhtId([0x02; 64]), RecordType::SignedContent, 1, b"x".to_vec());
        rec.signer_pubkey = Vec::new();
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("missing signer pubkey")
        );
    }

    #[test]
    fn verify_incoming_rejects_pubkey_not_bound_to_signer() {
        // The DhtWatchNotify forgery hole: a valid pubkey + signature pair, but
        // the record claims a *different* signer PeerId than the pubkey hashes to.
        let attacker = Keypair::generate();
        let victim = Keypair::generate();
        let mut rec = signed_record(&attacker, DhtId([0x03; 64]), RecordType::SignedContent, 1, b"x".to_vec());
        rec.signer = *victim.peer_id().as_bytes();
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("signer pubkey does not match signer PeerId")
        );
    }

    #[test]
    fn verify_incoming_rejects_tampered_value() {
        let kp = Keypair::generate();
        let mut rec = signed_record(&kp, DhtId([0x04; 64]), RecordType::SignedContent, 1, b"original".to_vec());
        rec.value = b"tampered".to_vec(); // signature no longer covers the value
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("invalid signature")
        );
    }

    #[test]
    fn verify_incoming_rejects_tampered_sequence() {
        let kp = Keypair::generate();
        let mut rec = signed_record(&kp, DhtId([0x05; 64]), RecordType::SignedContent, 1, b"v".to_vec());
        rec.sequence = 999; // signable includes the sequence, so the sig breaks
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("invalid signature")
        );
    }

    #[test]
    fn verify_incoming_rejects_unknown_algo() {
        let kp = Keypair::generate();
        let mut rec = signed_record(&kp, DhtId([0x06; 64]), RecordType::SignedContent, 1, b"v".to_vec());
        rec.signer_algo = 0xFF;
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("unknown signer algo")
        );
    }

    #[test]
    fn verify_incoming_skips_unsigned_content() {
        // Content is not a signed type — an empty pubkey / signature is expected
        // and the gate must let it through unchanged.
        let rec = DhtRecord {
            key: DhtId([0x07; 64]),
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            signer_algo: 0,
            signer_pubkey: Vec::new(),
            value: b"blob".to_vec(),
            ttl: Duration::from_secs(60),
            stored_at: Instant::now(),
            signature: Vec::new(),
        };
        assert!(VerifiedRecord::verify_incoming(rec).is_ok());
    }

    // ── DB reload re-verification: import_records ──

    #[test]
    fn import_records_keeps_valid_persisted_record() {
        let kp = Keypair::generate();
        let key = DhtId([0x08; 64]);
        let mut store = DhtStore::new(&kp.peer_id());
        put(&mut store, signed_record(&kp, key, RecordType::SignedContent, 1, b"persist".to_vec()));

        let exported = store.export_records();
        assert_eq!(exported.len(), 1);

        let mut reloaded = DhtStore::new(&kp.peer_id());
        reloaded.import_records(exported);
        assert_eq!(reloaded.get(&key).len(), 1, "valid persisted record survives reload");
    }

    #[test]
    fn import_records_drops_tampered_persisted_record() {
        let kp = Keypair::generate();
        let key = DhtId([0x09; 64]);
        let mut store = DhtStore::new(&kp.peer_id());
        put(&mut store, signed_record(&kp, key, RecordType::SignedContent, 1, b"genuine".to_vec()));

        let mut exported = store.export_records();
        assert_eq!(exported.len(), 1);
        // Corrupt the on-disk value so its stored signature no longer matches.
        exported[0].value = b"corrupted on disk".to_vec();

        let mut reloaded = DhtStore::new(&kp.peer_id());
        reloaded.import_records(exported);
        assert!(reloaded.get(&key).is_empty(), "tampered persisted record is dropped on load");
    }

    // ── Construction helpers: guard against re-stripping signed fields ──

    #[test]
    fn to_response_record_round_trips_through_verify() {
        // The exact regression that broke vhost: a GET response that dropped
        // signer_pubkey could never re-verify on the receiving node. Rebuild a
        // DhtRecord from the response fields and confirm it clears the gate.
        let kp = Keypair::generate();
        let key = DhtId([0x0A; 64]);
        let original = signed_record(&kp, key, RecordType::SignedContent, 1, b"resp".to_vec());
        let resp = original.to_response_record();
        assert!(!resp.signer_pubkey.is_empty(), "response must carry the signer pubkey");

        let rebuilt = DhtRecord {
            key,
            record_type: resp.record_type,
            sequence: resp.sequence,
            signer: resp.signer,
            signer_algo: resp.signer_algo,
            signer_pubkey: resp.signer_pubkey.clone(),
            value: resp.value.clone(),
            ttl: Duration::from_secs(resp.ttl as u64),
            stored_at: Instant::now(),
            signature: resp.signature.clone(),
        };
        assert!(VerifiedRecord::verify_incoming(rebuilt).is_ok());
    }

    #[test]
    fn to_put_msg_carries_pubkey_and_matching_signable() {
        let kp = Keypair::generate();
        let key = DhtId([0x0B; 64]);
        let rec = signed_record(&kp, key, RecordType::SignedContent, 1, b"put".to_vec());
        let put = rec.to_put_msg(&PeerId([0x77; 32]), 5);

        assert!(!put.signer_pubkey.is_empty(), "put msg must carry the signer pubkey");
        assert_eq!(put.hop_limit, 5);
        // Signing side (wire) and verifying side (dht) must agree on the bytes.
        assert_eq!(
            put.signable_bytes(),
            record_signable(&put.key, put.record_type, put.sequence, &put.value)
        );
    }

    #[test]
    fn content_address_roundtrip() {
        let data = b"hello content-addressed DHT";
        let (key, blob) = content_address_put(data);

        // To retrieve, we need the inner hash of original data
        let inner_hash: [u8; 64] = hash_64(data);

        // Verify the key is hash(inner_hash)
        let expected_key: [u8; 64] = hash_64(&inner_hash);
        assert_eq!(*key.as_bytes(), expected_key);

        let decrypted = content_address_get(&inner_hash, &blob).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn content_address_wrong_hash() {
        let data = b"secret data";
        let (_key, blob) = content_address_put(data);
        let wrong_hash = [0u8; 64];
        assert!(content_address_get(&wrong_hash, &blob).is_err());
    }

    #[test]
    fn k_closest_ordering() {
        let target = DhtId([0u8; 64]);
        let mut peers = Vec::new();
        for i in 0..10u8 {
            let pid = PeerId([i; 32]);
            let did = dht_id_from_peer_id(&pid);
            peers.push((pid, did));
        }
        let closest = k_closest(&target, &peers, 3);
        assert_eq!(closest.len(), 3);
    }

    #[test]
    fn dht_store_expiry() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0u8; 64]);
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            value: vec![1, 2, 3],
            ttl: Duration::from_secs(0), // already expired
            stored_at: Instant::now() - Duration::from_secs(1),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert!(store.get(&key).is_empty()); // expired
        store.expire();
        assert_eq!(store.records.len(), 0);
    }


    #[test]
    fn hello_higher_sequence_replaces() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xAA; 64]);
        let signer = [0x11; 32];

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Hello,
            sequence: 1,
            signer,
            value: b"old hello".to_vec(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"old hello");

        // Higher sequence replaces
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Hello,
            sequence: 5,
            signer,
            value: b"new hello".to_vec(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"new hello");
        assert_eq!(store.get(&key)[0].sequence, 5);
    }

    #[test]
    fn hello_lower_sequence_ignored() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xBB; 64]);
        let signer = [0x22; 32];

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Hello,
            sequence: 10,
            signer,
            value: b"current".to_vec(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });

        // Lower sequence should be ignored
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Hello,
            sequence: 3,
            signer,
            value: b"stale".to_vec(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"current");
        assert_eq!(store.get(&key)[0].sequence, 10);
    }

    #[test]
    fn signed_content_supplemental() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xCC; 64]);

        // Two different signers → both stored (supplemental)
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 0,
            signer: [0x11; 32],
            value: b"from signer A".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 0,
            signer: [0x22; 32],
            value: b"from signer B".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 2);
    }

    #[test]
    fn signed_content_same_signer_replaces() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xDD; 64]);
        let signer = [0x33; 32];

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 0,
            signer,
            value: b"version 1".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 0,
            signer,
            value: b"version 2".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"version 2");
    }

    #[test]
    fn signed_content_lower_sequence_ignored() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xDD; 64]);
        let signer = [0x44; 32];

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 10,
            signer,
            value: b"current".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        // Lower sequence should be ignored
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 3,
            signer,
            value: b"stale".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"current");
        assert_eq!(store.get(&key)[0].sequence, 10);
    }

    #[test]
    fn signed_content_higher_sequence_replaces() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xDD; 64]);
        let signer = [0x55; 32];

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 1,
            signer,
            value: b"old".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 5,
            signer,
            value: b"new".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"new");
        assert_eq!(store.get(&key)[0].sequence, 5);
    }

    #[test]
    fn signed_content_self_authenticating_roundtrip() {
        // Simulate the full flow: content_address_put + multiple signers + content_address_get
        let topic = b"secret-group-key||llama-70b";

        // Two providers encrypt the same topic
        let (key1, blob1) = content_address_put(topic);
        let (key2, blob2) = content_address_put(topic);

        // Keys must be identical (same content)
        assert_eq!(key1, key2);
        // Blobs differ (different random nonces)
        assert_ne!(blob1, blob2);

        let mut store = DhtStore::new(&PeerId([0u8; 32]));
        put(&mut store, DhtRecord {
            key: key1,
            record_type: RecordType::SignedContent,
            sequence: 1,
            signer: [0x11; 32],
            value: blob1.clone(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        put(&mut store, DhtRecord {
            key: key1,
            record_type: RecordType::SignedContent,
            sequence: 1,
            signer: [0x22; 32],
            value: blob2.clone(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });

        // Both stored (different signers)
        let records = store.get(&key1);
        assert_eq!(records.len(), 2);

        // Both decrypt correctly with the inner hash
        let inner_hash: [u8; 64] = hash_64(topic);
        for record in records {
            let plaintext = content_address_get(&inner_hash, &record.value).unwrap();
            assert_eq!(plaintext, topic);
        }

        // Garbage blob at same key fails decryption
        let garbage = vec![0xDEu8; 100];
        assert!(content_address_get(&inner_hash, &garbage).is_err());
    }

    #[test]
    fn content_keeps_multiple_candidates() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xEE; 64]);

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            value: b"first".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            value: b"second".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        // Both candidates kept (anti-poisoning)
        assert_eq!(store.get(&key).len(), 2);

        // Duplicate values are deduplicated
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            value: b"first".to_vec(),
            ttl: Duration::from_secs(3600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 2);
    }

    #[test]
    fn get_empty_key_returns_empty() {
        let peer = PeerId([1u8; 32]);
        let store = DhtStore::new(&peer);
        let key = DhtId([0xFF; 64]);
        assert!(store.get(&key).is_empty());
    }

    #[test]
    fn dht_store_unknown_record_type() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xAA; 64]);
        let signer = [0x11; 32];

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Unknown(7),
            sequence: 1,
            signer,
            value: b"unknown v1".to_vec(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"unknown v1");

        // Higher sequence replaces
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Unknown(7),
            sequence: 5,
            signer,
            value: b"unknown v2".to_vec(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"unknown v2");
        assert_eq!(store.get(&key)[0].sequence, 5);
    }

    #[test]
    fn watch_table_add_and_get() {
        let mut table = DhtWatchTable::new();
        let key = [0xAA; 64];
        let token = [0x11; 32];
        let peer = PeerId([1u8; 32]);
        table.set_watch(key, token, peer, 300);
        let watchers = table.get_watchers(&key);
        assert_eq!(watchers.len(), 1);
        assert_eq!(watchers[0], (token, peer));
    }

    #[test]
    fn watch_table_cancel() {
        let mut table = DhtWatchTable::new();
        let key = [0xBB; 64];
        let token = [0x22; 32];
        let peer = PeerId([2u8; 32]);
        table.set_watch(key, token, peer, 300);
        assert_eq!(table.get_watchers(&key).len(), 1);
        table.set_watch(key, token, peer, 0); // cancel
        assert!(table.get_watchers(&key).is_empty());
    }

    #[test]
    fn watch_table_expiry() {
        let mut table = DhtWatchTable::new();
        let key = [0xCC; 64];
        let peer = PeerId([3u8; 32]);

        // Add a watch that's already expired
        let entries = table.watches.entry(key).or_default();
        entries.push(DhtWatch {
            query_token: [0x33; 32],
            via_peer: peer,
            expires_at: Instant::now() - Duration::from_secs(1),
        });

        // Should not return expired watcher
        assert!(table.get_watchers(&key).is_empty());

        // Expire should clean up
        table.expire();
        assert!(table.watches.is_empty());
    }

    #[test]
    fn watch_table_remove_peer() {
        let mut table = DhtWatchTable::new();
        let key = [0xDD; 64];
        let peer_a = PeerId([4u8; 32]);
        let peer_b = PeerId([5u8; 32]);
        table.set_watch(key, [0x44; 32], peer_a, 300);
        table.set_watch(key, [0x55; 32], peer_b, 300);
        assert_eq!(table.get_watchers(&key).len(), 2);

        table.remove_peer(&peer_a);
        let watchers = table.get_watchers(&key);
        assert_eq!(watchers.len(), 1);
        assert_eq!(watchers[0], ([0x55; 32], peer_b));
    }

    #[test]
    fn watch_table_duplicate_refresh() {
        let mut table = DhtWatchTable::new();
        let key = [0xEE; 64];
        let token = [0x66; 32];
        let peer = PeerId([6u8; 32]);
        table.set_watch(key, token, peer, 300);
        table.set_watch(key, token, peer, 600); // refresh
        let watchers = table.get_watchers(&key);
        assert_eq!(watchers.len(), 1); // still only one entry
    }

    #[test]
    fn dht_store_rejects_oversized_values() {
        let peer = PeerId([9u8; 32]);
        let mut store = DhtStore::with_limits(
            &peer,
            StorageLimits {
                max_records: 8,
                max_total_bytes: 4096,
                max_records_per_key: 4,
                max_bytes_per_key: 1024,
                max_value_bytes: 16,
            },
        );
        let key = DhtId([0xAB; 64]);
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Content,
            sequence: 0,
            signer: [0u8; 32],
            value: vec![0x55; 32],
            ttl: Duration::from_secs(60),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });

        assert!(store.get(&key).is_empty());
    }

    #[test]
    fn dht_store_enforces_global_record_limit() {
        let peer = PeerId([10u8; 32]);
        let mut store = DhtStore::with_limits(
            &peer,
            StorageLimits {
                max_records: 2,
                max_total_bytes: 4096,
                max_records_per_key: 4,
                max_bytes_per_key: 4096,
                max_value_bytes: 128,
            },
        );

        for i in 0..3u8 {
            put(&mut store, DhtRecord {
                key: DhtId([i; 64]),
                record_type: RecordType::Unknown(9),
                sequence: i as u64,
                signer: [i; 32],
                value: vec![i; 8],
                ttl: Duration::from_secs(60),
                stored_at: Instant::now() + Duration::from_millis(i as u64),
                signer_algo: 1,
                signer_pubkey: vec![],
                signature: vec![0u8; 64],
            });
        }

        assert_eq!(store.all_records().len(), 2);
        assert!(store.get(&DhtId([0; 64])).is_empty());
    }

    // ── L2NSE tests ──

    #[test]
    fn l2nse_empty_table() {
        let kp = Keypair::generate();
        let kb = KBucketTable::new(&kp.peer_id());
        assert_eq!(kb.estimate_l2nse(), 1.0);
    }

    #[test]
    fn l2nse_single_peer() {
        let kp = Keypair::generate();
        let mut kb = KBucketTable::new(&kp.peer_id());
        let other = Keypair::generate();
        kb.insert(other.peer_id(), dht_id_from_peer_id(&other.peer_id()));
        let est = kb.estimate_l2nse();
        // With 1 peer in a single bucket, the estimate should be modest.
        assert!(est >= 1.0, "l2nse should be at least 1.0, got {}", est);
    }

    #[test]
    fn l2nse_grows_with_peers() {
        let kp = Keypair::generate();
        let mut kb = KBucketTable::new(&kp.peer_id());

        // Insert 5 peers and record estimate
        for _ in 0..5 {
            let other = Keypair::generate();
            kb.insert(other.peer_id(), dht_id_from_peer_id(&other.peer_id()));
        }
        let est_5 = kb.estimate_l2nse();

        // Insert 50 more peers
        for _ in 0..50 {
            let other = Keypair::generate();
            kb.insert(other.peer_id(), dht_id_from_peer_id(&other.peer_id()));
        }
        let est_55 = kb.estimate_l2nse();

        assert!(
            est_55 > est_5,
            "l2nse should grow with more peers: {} vs {}",
            est_55,
            est_5
        );
    }

    #[test]
    fn dht_query_params_from_l2nse_small_network() {
        let params = DhtQueryParams::from_l2nse(1.0);
        assert_eq!(params.hop_limit, 4); // floor
        assert_eq!(params.fan_out, DHT_K); // floor
    }

    #[test]
    fn dht_query_params_from_l2nse_medium_network() {
        let params = DhtQueryParams::from_l2nse(10.0);
        assert_eq!(params.hop_limit, 12);
        assert_eq!(params.fan_out, 20); // 10*2 = 20 = DHT_K
    }

    #[test]
    fn dht_query_params_from_l2nse_large_network() {
        let params = DhtQueryParams::from_l2nse(18.0);
        assert_eq!(params.hop_limit, 20); // cap
        assert_eq!(params.fan_out, 36); // 18*2 = 36
    }

    #[test]
    fn random_select_returns_k_or_fewer() {
        let peers: Vec<(PeerId, DhtId)> = (0..10u8)
            .map(|i| {
                let pid = PeerId([i; 32]);
                let did = dht_id_from_peer_id(&pid);
                (pid, did)
            })
            .collect();

        let selected = random_select(&peers, 5);
        assert_eq!(selected.len(), 5);

        // When k >= peers.len(), return all
        let selected = random_select(&peers, 20);
        assert_eq!(selected.len(), 10);
    }

    #[test]
    fn l2nse_few_peers_bounded() {
        // Two random peers land in high buckets (~511).  The estimate
        // must stay bounded and not overflow u8 casts or 2^x.
        let local = Keypair::generate();
        let mut kb = KBucketTable::new(&local.peer_id());
        for _ in 0..2 {
            let kp = Keypair::generate();
            let pid = kp.peer_id();
            let did = dht_id_from_peer_id(&pid);
            kb.insert(pid, did);
        }
        let l2nse = kb.estimate_l2nse();
        assert!(l2nse >= 1.0, "l2nse too low: {l2nse}");
        assert!(l2nse <= 10.0, "l2nse too high for 2 peers: {l2nse}");
        // Verify downstream consumers don't overflow
        let hop_phase = l2nse.round().min(255.0) as u8;
        assert!(hop_phase > 0, "random walk phase must not wrap to 0");
        let nse = 2u64.saturating_pow(l2nse.round().min(63.0) as u32);
        assert!(nse > 0, "nse display must not overflow to 0");
    }

    #[test]
    fn signed_record_encrypt_roundtrip() {
        let dht_key = DhtId([0xAB; 64]);
        let plaintext = b"hello record payload";
        let blob = signed_record_encrypt(&dht_key, plaintext);
        // blob should be nonce(24) + ciphertext + tag(16)
        assert!(blob.len() >= 24 + 16 + plaintext.len());
        let decrypted = signed_record_decrypt(&dht_key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn signed_record_wrong_key_fails() {
        let dht_key = DhtId([0xAB; 64]);
        let wrong_key = DhtId([0xCD; 64]);
        let blob = signed_record_encrypt(&dht_key, b"secret");
        assert!(signed_record_decrypt(&wrong_key, &blob).is_err());
    }

    #[test]
    fn signed_record_short_blob_fails() {
        let dht_key = DhtId([0xAB; 64]);
        assert!(signed_record_decrypt(&dht_key, &[0u8; 10]).is_err());
    }
}
