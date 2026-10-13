use std::collections::HashMap;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::{Rng, RngCore};

use crate::identity::{dht_id_from_peer_id, Keypair};
use crate::state::{PersistedRecord, StorageLimits};
use crate::types::{DhtId, PeerId, RecordType, Result};
use crate::wire::{walk_flags, WalkHeader};
use tarnet_api::types::ServiceId;

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

/// Probability that a node receiving a walking message ends the random phase
/// (spec: *q*). Mean random-phase length is 1/q hops.
pub const WALK_END_PROBABILITY: f64 = 1.0 / 3.0;

/// Greedy steps a walk may take after its random phase. Greedy steps strictly
/// approach the key, so this only bounds `DELIVER` detours and misbehaving
/// peers.
pub const GREEDY_BUDGET: u8 = 32;

/// Upper bound on walks per PUT, and per GET/WATCH round.
pub const MAX_WALKS: usize = 32;

/// Number of independent walks for one PUT, or one GET/WATCH round (spec: ρ).
///
/// With greedy routing over direct links a key has about N/(d+1) local minima.
/// ρ PUT walks and ρ GET walks meet with probability ≈ 1 − e^(−ρ²(d+1)/N), so
/// ρ = √(3N/(d+1)) targets ≈ 95% per round.
pub fn walk_count(network_size: usize, degree: usize) -> usize {
    let n = network_size.max(1) as f64;
    let d = degree.max(1) as f64;
    ((3.0 * n / (d + 1.0)).sqrt().ceil() as usize).clamp(2, MAX_WALKS)
}

/// A direct link as the DHT sees it.
#[derive(Debug, Clone, Copy)]
pub struct DhtNeighbor {
    pub peer: PeerId,
    pub id: DhtId,
    /// Whether the neighbour stores records for others (from its `DhtNeighbor`
    /// message; assumed true until one arrives).
    pub stores: bool,
}

impl DhtNeighbor {
    pub fn new(peer: PeerId, stores: bool) -> Self {
        Self {
            peer,
            id: dht_id_from_peer_id(&peer),
            stores,
        }
    }
}

/// What a node does with a walk it received. See `docs/spec/dht.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkStep {
    /// This node is the end of the walk.
    End,
    /// Forward to the peer with the updated header.
    Forward(PeerId, WalkHeader),
    /// No usable neighbour; the walk stops here without an end node.
    Drop,
}

/// Decide the next step of a PUT/GET/WATCH walk at `local`, which received it
/// from `from`.
pub fn walk_step<R: Rng + ?Sized>(
    local: &PeerId,
    local_stores: bool,
    key: &DhtId,
    header: &WalkHeader,
    from: &PeerId,
    neighbors: &[DhtNeighbor],
    rng: &mut R,
) -> WalkStep {
    use rand::seq::SliceRandom;

    let mut h = *header;
    if h.walking() {
        // A node whose only neighbour is the sender ends the random phase:
        // bouncing back adds traffic on that one link and no mixing.
        if !rng.gen_bool(WALK_END_PROBABILITY) {
            let others: Vec<&DhtNeighbor> = neighbors.iter().filter(|n| n.peer != *from).collect();
            if let Some(n) = others.choose(rng) {
                return WalkStep::Forward(n.peer, h);
            }
        }
        h.flags &= !walk_flags::WALKING;
        h.greedy_budget = GREEDY_BUDGET;
    }

    if h.deliver() {
        if local_stores {
            return WalkStep::End;
        }
        return deliver_step(local, key, h, neighbors, rng);
    }

    if h.greedy_budget == 0 {
        return if local_stores { WalkStep::End } else { WalkStep::Drop };
    }
    let local_dist = dht_id_from_peer_id(local).xor_distance(key);
    if let Some(best) = neighbors.iter().min_by_key(|n| n.id.xor_distance(key)) {
        if best.id.xor_distance(key) < local_dist {
            h.greedy_budget -= 1;
            return WalkStep::Forward(best.peer, h);
        }
    }
    if local_stores {
        return WalkStep::End;
    }
    // A relay-only local minimum hands the walk to its closest storing
    // neighbour, the same one whichever side the walk came from.
    h.flags |= walk_flags::DELIVER;
    deliver_step(local, key, h, neighbors, rng)
}

/// `DELIVER` forwarding at a relay-only node: record ourselves in the bloom and
/// pass to the closest storing neighbour not yet visited (else the closest
/// unvisited neighbour).
fn deliver_step<R: Rng + ?Sized>(
    local: &PeerId,
    key: &DhtId,
    mut h: WalkHeader,
    neighbors: &[DhtNeighbor],
    rng: &mut R,
) -> WalkStep {
    if h.greedy_budget == 0 {
        return WalkStep::Drop;
    }
    h.greedy_budget -= 1;
    if h.bloom == [0u8; 256] {
        h.bloom_salt = rng.gen();
    }
    let mut bloom = BloomFilter::from_bytes(h.bloom);
    bloom.insert(h.bloom_salt, local);
    h.bloom = bloom.to_bytes();

    let unvisited = || {
        neighbors
            .iter()
            .filter(|n| n.peer != *local && !bloom.contains(h.bloom_salt, &n.peer))
    };
    let target = unvisited()
        .filter(|n| n.stores)
        .min_by_key(|n| n.id.xor_distance(key))
        .or_else(|| unvisited().min_by_key(|n| n.id.xor_distance(key)));
    match target {
        Some(n) => WalkStep::Forward(n.peer, h),
        None => WalkStep::Drop,
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
    /// copied, never re-derived or omitted.
    ///
    /// Carries the *remaining* TTL, not the full original — exactly like
    /// [`to_response_record`](Self::to_response_record). Propagating the full
    /// TTL let replication resurrect a record's clock on every hop: each
    /// `SignedContent` round (which replaces on equal sequence) reset
    /// `stored_at`, so k-closest holders mutually refreshed a record to full
    /// life every replication interval and it never expired — outliving the
    /// publisher. With remaining TTL, a record ages toward a single fixed
    /// deadline (publish time + TTL) no matter how many times it is replicated.
    ///
    /// Note the TTL carried here is NOT authenticated — it is deliberately not
    /// part of the signed bytes (`record_signable`) because it is rewritten on
    /// every hop. Lifetime integrity therefore does not rest on the signature; it
    /// rests on two things: `upsert_by_signer` never lets an equal-sequence
    /// replace shorten a record's life (so a replayed `ttl=0` cannot force-expire
    /// it), and storage is ultimately capacity-bound (evicted oldest-first under
    /// pressure regardless of TTL). The record reaches its deadline and expires
    /// unless the owner republishes with a higher sequence (pool lease refresh,
    /// hello/peer/intro maintenance, TNS republish).
    pub fn to_put_msg(&self) -> crate::wire::DhtPutMsg {
        crate::wire::DhtPutMsg {
            walk: WalkHeader::origin(),
            key: *self.key.as_bytes(),
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
///
/// `ttl` is intentionally NOT covered. Each forward ships the *remaining* TTL
/// (see [`DhtRecord::to_put_msg`]), so the field is mutated per hop and cannot be
/// signed. The consequence is that an incoming `ttl` is attacker-influenced; the
/// store must therefore never trust it to shorten a record. That invariant lives
/// in [`upsert_by_signer`] (equal-sequence replace keeps the later deadline), not
/// here. Do not "fix" this by adding `ttl` to the signable — it would break
/// remaining-ttl replication. The model is capacity-bound, not ttl-trusting.
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
    // Self-addressed records (zone roots) must live at the hash of their own
    // signer's ServiceId. This is the anti-flood / anti-squat invariant: a
    // record at `zone_root_key(sid)` is accepted only if its signer's pubkey
    // hashes to `sid`, so only the zone-key holder can ever write there and no
    // foreign signer can pile junk at the location to evict the real record.
    if record_type.is_self_addressed() {
        let expected = zone_root_key(&ServiceId::from_signing_pubkey(signer_pubkey));
        if expected.as_bytes() != key {
            return Err("self-addressed record not stored at its own key");
        }
    }
    // Hellos are identity-addressed: every hello this node mints lives at
    // `identity_address_key(signer)`. Holding foreign hellos to the same rule
    // stops anyone stacking hellos at another peer's key to crowd its real one
    // out (the store also never evicts a hello for other records at its key).
    if record_type == RecordType::Hello
        && identity_address_key(&PeerId(*signer)).as_bytes() != key
    {
        return Err("hello not stored at its signer's identity key");
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

    /// Mint a self-addressed TNS zone-root record. Stored at `zone_root_key(sid)`
    /// where `sid` is `zone_keypair`'s ServiceId, and signed by `zone_keypair`
    /// itself — so the ingest gate's self-address check passes only because the
    /// signer's pubkey hashes to `sid`. `value` is the caller's already-sealed
    /// zone-root blob (see the TNS layer); it is stored verbatim. Because the
    /// key is fixed by `sid` and the signer is the zone key, only the zone owner
    /// can ever write here — there is no foreign-signer flood surface.
    pub fn new_zone_root(
        zone_keypair: &Keypair,
        value: &[u8],
        sequence: u64,
        ttl: Duration,
    ) -> Self {
        let key = zone_root_key(&zone_keypair.identity.service_id());
        Self(sign_record(
            zone_keypair,
            key,
            RecordType::ZoneRoot,
            sequence,
            value.to_vec(),
            ttl,
        ))
    }

    /// Mint a Hello record at the identity-addressed key for `identity`. The
    /// serialized hello bytes are wrapped with [`signed_record_encrypt`] under
    /// the key (readable by anyone holding the record — hellos are public by
    /// design), then signed by `identity`.
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
/// Who handed this node a stored record. Eviction is fair-shared across
/// sources, so a flood arriving over one link can only displace that link's
/// own share of the store, never everyone else's records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordSource {
    /// Minted by this node, or reloaded from its own database.
    Local,
    /// Delivered by this direct link peer.
    Peer(PeerId),
}

#[derive(Debug, Clone)]
struct StoredRecord {
    record: DhtRecord,
    source: RecordSource,
}

/// Longest lifetime any record may hold in the store. `ttl` is not covered by
/// the signature (see [`record_signable`]), so an inbound value is
/// attacker-chosen; without a ceiling a replayed old record could be pinned for
/// up to `u32::MAX` seconds.
pub const MAX_RECORD_TTL: Duration = Duration::from_secs(24 * 3600);

/// Ceiling for hello records, which are republished every few minutes and
/// carry reachability data that goes stale quickly.
pub const MAX_HELLO_TTL: Duration = Duration::from_secs(3600);

/// The TTL ceiling for a record type.
pub fn max_ttl(record_type: RecordType) -> Duration {
    match record_type {
        RecordType::Hello => MAX_HELLO_TTL,
        _ => MAX_RECORD_TTL,
    }
}

/// Clamp a wire `ttl` (seconds) to the ceiling for its record type, so a
/// forwarded message never carries a longer lifetime than we would store.
pub fn clamp_ttl_secs(record_type: RecordType, ttl: u32) -> u32 {
    ttl.min(max_ttl(record_type).as_secs() as u32)
}

/// Content candidates kept per key. Storage cannot tell the authentic blob
/// from junk (only a reader holding the inner hash can), so it keeps several.
const MAX_CONTENT_CANDIDATES: usize = 5;

pub struct DhtStore {
    records: HashMap<[u8; 64], Vec<StoredRecord>>,
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

    /// Store a record this node minted or reloaded itself. See [`put_from`](Self::put_from).
    pub fn put(&mut self, record: VerifiedRecord) -> bool {
        self.put_from(record, RecordSource::Local)
    }

    /// Store a record with type-aware replacement policy, attributing it to
    /// `source` for fair-share eviction.
    /// - Hello / ZoneRoot / Unknown: same signer + higher sequence replaces.
    /// - SignedContent: add if new signer (supplemental), same signer replaces.
    /// - Content: up to [`MAX_CONTENT_CANDIDATES`] distinct blobs; when full, a
    ///   random candidate makes room, so whoever fills the slots first cannot
    ///   lock the authentic blob out.
    ///
    /// The stored TTL is clamped to [`max_ttl`] for the record type.
    pub fn put_from(&mut self, record: VerifiedRecord, source: RecordSource) -> bool {
        let mut record = record.into_inner();
        self.expire();
        if record.value.len() > self.limits.max_value_bytes {
            return false;
        }
        record.ttl = record.ttl.min(max_ttl(record.record_type));

        let key = *record.key.as_bytes();
        let entries = self.records.entry(key).or_default();

        let stored = match record.record_type {
            RecordType::Hello => {
                // Same signer + strictly higher sequence replaces
                upsert_by_signer(entries, record, source, false)
            }
            RecordType::SignedContent => {
                // Different signers are supplemental; same signer replaces if >= sequence
                upsert_by_signer(entries, record, source, true)
            }
            RecordType::ZoneRoot => {
                // Self-addressed: the ingest gate guarantees the signer's ServiceId
                // hashes to this key, so every record here shares one signer — the
                // zone owner. Same signer + strictly higher sequence replaces.
                upsert_by_signer(entries, record, source, false)
            }
            RecordType::Content => {
                let candidates: Vec<usize> = entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| e.record.record_type == RecordType::Content)
                    .map(|(i, _)| i)
                    .collect();
                if candidates
                    .iter()
                    .any(|&i| entries[i].record.value == record.value)
                {
                    false
                } else {
                    if candidates.len() >= MAX_CONTENT_CANDIDATES {
                        let victim = candidates[rand::thread_rng().gen_range(0..candidates.len())];
                        entries.remove(victim);
                    }
                    entries.push(StoredRecord { record, source });
                    true
                }
            }
            RecordType::Unknown(_) => {
                // Best-effort store-and-relay: same signer + strictly higher sequence replaces
                upsert_by_signer(entries, record, source, false)
            }
        };

        if stored {
            self.enforce_key_limits(&key);
            self.enforce_global_limits();
        }
        stored
    }

    /// Retrieve all non-expired records at a key.
    pub fn get(&self, key: &DhtId) -> Vec<&DhtRecord> {
        match self.records.get(key.as_bytes()) {
            Some(entries) => entries
                .iter()
                .map(|e| &e.record)
                .filter(|r| !r.is_expired())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Remove expired records.
    pub fn expire(&mut self) {
        for entries in self.records.values_mut() {
            entries.retain(|e| !e.record.is_expired());
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
            .filter(|(_, v)| v.iter().any(|e| !e.record.is_expired()))
            .count()
    }

    /// Total number of non-expired records across all keys.
    pub fn record_count(&self) -> usize {
        self.records
            .values()
            .flat_map(|v| v.iter())
            .filter(|e| !e.record.is_expired())
            .count()
    }

    /// Iterate over all non-expired records.
    pub fn all_records(&self) -> Vec<&DhtRecord> {
        self.records
            .values()
            .flat_map(|entries| entries.iter())
            .map(|e| &e.record)
            .filter(|r| !r.is_expired())
            .collect()
    }

    /// Non-expired records split by origin: `(ours, everyone else's)`, where
    /// "ours" are those with source [`RecordSource::Local`].
    pub fn records_by_origin(&self) -> (Vec<&DhtRecord>, Vec<&DhtRecord>) {
        let mut ours = Vec::new();
        let mut theirs = Vec::new();
        for e in self.records.values().flat_map(|entries| entries.iter()) {
            if e.record.is_expired() {
                continue;
            }
            if e.source == RecordSource::Local {
                ours.push(&e.record);
            } else {
                theirs.push(&e.record);
            }
        }
        (ours, theirs)
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
            let Some(live) = record.into_live() else {
                continue;
            };
            match VerifiedRecord::verify_incoming(live) {
                Ok(verified) => {
                    let _ = self.put(verified);
                }
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
            .map(|e| record_cost(&e.record))
            .sum()
    }

    /// Bring one key back within its record/byte budget. Owner-bound records
    /// (a zone root, or a hello at its signer's own key — the only places those
    /// types can be stored) are never evicted to make room for other records at
    /// the same key: they are the reason the key exists, and foreign records
    /// piling onto it must not be able to push them out.
    fn enforce_key_limits(&mut self, key: &[u8; 64]) {
        let max_records_per_key = self.limits.max_records_per_key;
        let max_bytes_per_key = self.limits.max_bytes_per_key;

        if let Some(entries) = self.records.get_mut(key) {
            let mut byte_total: usize = entries.iter().map(|e| record_cost(&e.record)).sum();
            while entries.len() > max_records_per_key || byte_total > max_bytes_per_key {
                let victim = fair_share_victim(
                    entries
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| !is_owner_bound(e.record.record_type)),
                );
                let Some(idx) = victim else {
                    break;
                };
                byte_total -= record_cost(&entries[idx].record);
                entries.remove(idx);
            }
        }

        self.records.retain(|_, v| !v.is_empty());
    }

    fn enforce_global_limits(&mut self) {
        let mut record_count = self.total_record_count();
        let mut byte_count = self.total_bytes();

        while record_count > self.limits.max_records || byte_count > self.limits.max_total_bytes {
            let victim = fair_share_victim(self.records.iter().flat_map(|(key, entries)| {
                entries.iter().enumerate().map(move |(idx, e)| ((*key, idx), e))
            }));
            let Some((key, idx)) = victim else {
                break;
            };
            if let Some(entries) = self.records.get_mut(&key) {
                byte_count -= record_cost(&entries[idx].record);
                entries.remove(idx);
                record_count -= 1;
                if entries.is_empty() {
                    self.records.remove(&key);
                }
            }
        }
    }
}

/// Record types that only the key's owner can write (enforced at ingest by
/// [`verify_incoming_record`]).
fn is_owner_bound(record_type: RecordType) -> bool {
    matches!(record_type, RecordType::Hello | RecordType::ZoneRoot)
}

/// Pick the record to evict: the oldest record from whichever source holds the
/// most of the candidates. Under normal load this approximates oldest-first;
/// under a flood from one link it evicts that link's records before anyone
/// else's.
fn fair_share_victim<'a, I: Copy>(
    candidates: impl Iterator<Item = (I, &'a StoredRecord)> + Clone,
) -> Option<I> {
    let mut counts: HashMap<RecordSource, usize> = HashMap::new();
    for (_, e) in candidates.clone() {
        *counts.entry(e.source).or_default() += 1;
    }
    let heaviest = counts.into_iter().max_by_key(|(_, n)| *n)?.0;
    candidates
        .filter(|(_, e)| e.source == heaviest)
        .min_by_key(|(_, e)| e.record.stored_at)
        .map(|(id, _)| id)
}

/// Upsert a record by signer: if a record with the same signer exists, replace it
/// if the new sequence is higher (or equal when `allow_equal` is true); otherwise append.
/// Returns whether the record was stored.
fn upsert_by_signer(
    entries: &mut Vec<StoredRecord>,
    record: DhtRecord,
    source: RecordSource,
    allow_equal: bool,
) -> bool {
    if let Some(existing) = entries.iter_mut().find(|e| e.record.signer == record.signer) {
        // A strictly higher sequence is a genuinely newer record (sequence is
        // signed, so only the owner can produce one) — take it wholesale.
        if record.sequence > existing.record.sequence {
            *existing = StoredRecord { record, source };
            return true;
        }
        // Equal-sequence replace exists ONLY to refresh `stored_at` for
        // replication — it must never SHORTEN a record's life. `ttl` is not in
        // the signed bytes (it is rewritten per hop as remaining-ttl, see
        // `to_put_msg`), so a replayed equal-sequence record can carry an
        // attacker-chosen `ttl` — `ttl=0` would otherwise force-expire a healthy
        // copy. Keep the later deadline: a refresh may extend (bounded by
        // [`max_ttl`], which `put_from` applies before we get here) but can never
        // cut life short. The source is kept: a refresh does not transfer
        // ownership of the slot.
        if allow_equal && record.sequence == existing.record.sequence {
            let existing_remaining = existing.record.remaining_ttl();
            existing.record = record;
            if existing_remaining > existing.record.ttl {
                existing.record.ttl = existing_remaining;
            }
            return true;
        }
        false
    } else {
        entries.push(StoredRecord { record, source });
        true
    }
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

/// Cap on a watch's lifetime, regardless of the (wire-supplied) request. Watch
/// re-sends are short-lived: callers refresh at 300s (see node::mod re-send and
/// dht_watch). 1 hour gives ample slack over that cadence while bounding how
/// long an abandoned/forged watch can squat memory after its via_peer goes
/// quiet — without it, a u32::MAX request would pin an entry for ~136 years.
pub const MAX_WATCH_EXPIRATION_SECS: u32 = 3600;

/// Per-via_peer cap on distinct watches. A single neighbor proxies many local
/// app watches (one query_token per watched key), but 256 distinct keys from one
/// link is already generous; beyond it we assume abuse and refuse new entries.
const MAX_WATCHES_PER_PEER: usize = 256;

/// Global cap across all peers, bounding total watch memory independent of how
/// many peers participate (worst case ~8192 * (96B entry + 64B key) ≈ low MB).
const MAX_WATCHES_TOTAL: usize = 8192;

/// Table of remote watches on DHT keys, indexed by query_token.
pub struct DhtWatchTable {
    watches: HashMap<[u8; 64], Vec<DhtWatch>>,
    /// Running count of watches per via_peer, kept in sync with `watches` so the
    /// per-peer cap is O(1) to check instead of scanning every key on insert.
    per_peer_count: HashMap<PeerId, usize>,
    /// Running total of all watch entries (sum of `per_peer_count`), for the
    /// global cap without an O(total) scan.
    total_count: usize,
}

impl DhtWatchTable {
    pub fn new() -> Self {
        Self {
            watches: HashMap::new(),
            per_peer_count: HashMap::new(),
            total_count: 0,
        }
    }

    /// Total number of active remote watch subscriptions.
    pub fn watch_count(&self) -> usize {
        self.watches.values().map(|v| v.len()).sum()
    }

    /// Set or cancel a watch. expiration_secs=0 cancels by query_token.
    /// Returns false if a *new* watch was refused for exceeding a cap; refreshing
    /// an existing (key, query_token) and cancelling always succeed (return true).
    pub fn set_watch(
        &mut self,
        key: [u8; 64],
        query_token: [u8; 32],
        via_peer: PeerId,
        expiration_secs: u32,
    ) -> bool {
        if expiration_secs == 0 {
            // Cancel by token. Collect the via_peers of the entries being dropped
            // first, then decrement the per-peer/total counters — avoids holding a
            // mutable borrow on `self.watches` while touching `self.per_peer_count`.
            if let Some(entries) = self.watches.get_mut(&key) {
                let dropped: Vec<PeerId> = entries
                    .iter()
                    .filter(|w| w.query_token == query_token)
                    .map(|w| w.via_peer)
                    .collect();
                entries.retain(|w| w.query_token != query_token);
                let empty = entries.is_empty();
                for peer in &dropped {
                    self.decr_peer(peer);
                }
                self.total_count = self.total_count.saturating_sub(dropped.len());
                if empty {
                    self.watches.remove(&key);
                }
            }
            return true;
        }

        // Clamp the wire-supplied lifetime so a forged-large value can't pin an
        // entry effectively forever. 0 is handled above (cancel), so we never
        // clamp a cancel up into a live watch.
        let expiration_secs = expiration_secs.min(MAX_WATCH_EXPIRATION_SECS);
        let expires_at = Instant::now() + Duration::from_secs(expiration_secs as u64);
        let entries = self.watches.entry(key).or_default();
        // Refresh if same token already watching (must always succeed so legit
        // periodic refresh isn't broken once a peer is at its cap). The watch may
        // have re-arrived via a different neighbor; note the old via_peer so we
        // can fix the per-peer counters after the borrow ends.
        if let Some(existing) = entries.iter_mut().find(|w| w.query_token == query_token) {
            let prev_peer = existing.via_peer;
            existing.expires_at = expires_at;
            existing.via_peer = via_peer;
            if prev_peer != via_peer {
                self.decr_peer(&prev_peer);
                *self.per_peer_count.entry(via_peer).or_insert(0) += 1;
            }
            return true;
        }

        // New entry: enforce the per-peer and global caps before inserting.
        let peer_count = self.per_peer_count.get(&via_peer).copied().unwrap_or(0);
        if peer_count >= MAX_WATCHES_PER_PEER || self.total_count >= MAX_WATCHES_TOTAL {
            if entries.is_empty() {
                self.watches.remove(&key);
            }
            return false;
        }
        entries.push(DhtWatch {
            query_token,
            via_peer,
            expires_at,
        });
        *self.per_peer_count.entry(via_peer).or_insert(0) += 1;
        self.total_count += 1;
        true
    }

    /// Decrement the per-peer counter for `peer`, removing the map entry at zero.
    /// Saturating so a fixture that inserts straight into `watches` (bypassing the
    /// counters) can't drive a count below zero.
    fn decr_peer(&mut self, peer: &PeerId) {
        if let Some(c) = self.per_peer_count.get_mut(peer) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.per_peer_count.remove(peer);
            }
        }
    }

    /// Whether a live watch with this token is registered for `key`.
    pub fn has_token(&self, key: &[u8; 64], query_token: &[u8; 32]) -> bool {
        self.via_for_token(key, query_token).is_some()
    }

    /// The previous hop a watch walk with this token arrived from.
    pub fn via_for_token(&self, key: &[u8; 64], query_token: &[u8; 32]) -> Option<PeerId> {
        let now = Instant::now();
        self.watches.get(key)?.iter().find_map(|w| {
            (w.query_token == *query_token && w.expires_at > now).then_some(w.via_peer)
        })
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
        let per_peer = &mut self.per_peer_count;
        let mut removed = 0usize;
        for entries in self.watches.values_mut() {
            entries.retain(|w| {
                let keep = w.expires_at > now;
                if !keep {
                    if let Some(c) = per_peer.get_mut(&w.via_peer) {
                        *c = c.saturating_sub(1);
                    }
                    removed += 1;
                }
                keep
            });
        }
        per_peer.retain(|_, c| *c != 0);
        // saturating: fixtures may insert into `watches` without bumping the count.
        self.total_count = self.total_count.saturating_sub(removed);
        self.watches.retain(|_, v| !v.is_empty());
    }

    /// Remove all watches routed through a specific peer (link went down).
    pub fn remove_peer(&mut self, peer: &PeerId) {
        for entries in self.watches.values_mut() {
            let before = entries.len();
            entries.retain(|w| w.via_peer != *peer);
            self.total_count = self.total_count.saturating_sub(before - entries.len());
        }
        self.per_peer_count.remove(peer);
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

    fn peer_hash(salt: u32, peer: &PeerId) -> [u8; 64] {
        let mut input = Vec::with_capacity(19 + 4 + 32);
        input.extend_from_slice(b"tarnet dht bloom v1");
        input.extend_from_slice(&salt.to_be_bytes());
        input.extend_from_slice(peer.as_bytes());
        hash_64(&input)
    }

    /// Insert a PeerId into the bloom filter under `salt`.
    pub fn insert(&mut self, salt: u32, peer: &PeerId) {
        let hash = Self::peer_hash(salt, peer);
        for i in 0..4 {
            let idx = u16::from_be_bytes([hash[i * 2], hash[i * 2 + 1]]) as usize % 2048;
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    /// Check if a PeerId might be in the bloom filter under `salt`.
    pub fn contains(&self, salt: u32, peer: &PeerId) -> bool {
        let hash = Self::peer_hash(salt, peer);
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

    // Encrypt value with XChaCha20-Poly1305 under a nonce derived from the
    // content. The key is itself derived from the plaintext, so it only ever
    // seals this one plaintext and a fixed nonce leaks nothing. Making the blob a
    // pure function of the content means honest copies from every publisher are
    // byte-identical, so storage dedupes them into one candidate slot instead of
    // letting each fresh nonce consume another.
    let mut nonce_seed = Vec::with_capacity(32 + 64);
    nonce_seed.extend_from_slice(b"tarnet content-address nonce v1");
    nonce_seed.extend_from_slice(&inner_hash);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&hash_64(&nonce_seed)[..24]);

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

/// Self-addressed DHT key for a TNS zone root: a 64-byte XOF hash of a domain
/// separator and the zone's ServiceId. A resolver computes this from the name's
/// ServiceId alone; the ingest gate ([`verify_incoming_record`]) recomputes it
/// from a record's signer pubkey and rejects any zone-root record not stored
/// here, so the location is writable only by the holder of the zone key.
///
/// Domain-separated from per-label/content/identity keys so a zone root can
/// never collide with another record class's location.
pub fn zone_root_key(sid: &ServiceId) -> DhtId {
    let mut out = [0u8; 64];
    blake3::Hasher::new()
        .update(b"tarnet tns zone-root v1")
        .update(sid.as_bytes())
        .finalize_xof()
        .fill(&mut out);
    DhtId(out)
}

/// Encrypt the value of a signed or hello DHT record under a key derived from
/// the DHT lookup key. This is obfuscation, not confidentiality: anyone who
/// holds the record also holds its key (and for hellos, the signer's PeerId the
/// key is derived from), so storage nodes can read it. It only keeps the value
/// opaque to observers who see neither.
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
    fn zone_root_accepts_owner_at_self_address() {
        // A zone root signed by the zone key and stored at zone_root_key(its sid)
        // passes the gate — the legitimate publish path.
        let zone = Keypair::generate();
        let key = zone_root_key(&zone.identity.service_id());
        let rec = signed_record(&zone, key, RecordType::ZoneRoot, 1, b"root".to_vec());
        assert!(VerifiedRecord::verify_incoming(rec).is_ok());
    }

    #[test]
    fn zone_root_rejects_foreign_signer_flood() {
        // The anti-flood invariant: an attacker who knows the victim's zone sid
        // computes zone_root_key(sid) and tries to plant junk there, signed by
        // their OWN key. The gate rejects it — the location is writable only by
        // the holder of the zone key, so there is no foreign-signer record to
        // accumulate and no per-key eviction race (Finding 1, closed).
        let victim = Keypair::generate();
        let attacker = Keypair::generate();
        let victim_root = zone_root_key(&victim.identity.service_id());
        // Attacker signs a record for the victim's zone-root location.
        let rec = signed_record(&attacker, victim_root, RecordType::ZoneRoot, 99, b"junk".to_vec());
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("self-addressed record not stored at its own key")
        );
    }

    #[test]
    fn hello_rejected_at_foreign_identity_key() {
        let victim = Keypair::generate();
        let attacker = Keypair::generate();
        let victim_key = identity_address_key(&victim.peer_id());
        let rec = signed_record(&attacker, victim_key, RecordType::Hello, 1, b"junk".to_vec());
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("hello not stored at its signer's identity key")
        );
        // The owner's own hello at its own key passes.
        let own = signed_record(&victim, victim_key, RecordType::Hello, 1, b"hi".to_vec());
        assert!(VerifiedRecord::verify_incoming(own).is_ok());
    }

    // ── Store: eviction and slot policy ──

    fn small_limits() -> StorageLimits {
        StorageLimits {
            max_records: 6,
            max_total_bytes: 1 << 20,
            max_records_per_key: 4,
            max_bytes_per_key: 1 << 20,
            max_value_bytes: 1024,
        }
    }

    #[test]
    fn owner_bound_record_survives_flood_at_its_key() {
        let owner = Keypair::generate();
        let key = zone_root_key(&owner.identity.service_id());
        let mut store = DhtStore::with_limits(&PeerId([1; 32]), small_limits());
        let root = signed_record(&owner, key, RecordType::ZoneRoot, 1, b"root".to_vec());
        store.put_from(VerifiedRecord::verify_incoming(root).unwrap(), RecordSource::Peer(PeerId([2; 32])));

        // A flood of foreign SignedContent at the same key, each newer than the root.
        for _ in 0..10 {
            let junk = signed_record(&Keypair::generate(), key, RecordType::SignedContent, 1, b"junk".to_vec());
            store.put_from(VerifiedRecord::verify_incoming(junk).unwrap(), RecordSource::Peer(PeerId([3; 32])));
        }
        let at_key = store.get(&key);
        assert_eq!(at_key.len(), 4);
        assert!(at_key.iter().any(|r| r.record_type == RecordType::ZoneRoot));
    }

    #[test]
    fn global_eviction_targets_the_flooding_source() {
        let mut store = DhtStore::with_limits(&PeerId([1; 32]), small_limits());
        let honest = RecordSource::Peer(PeerId([2; 32]));
        let flooder = RecordSource::Peer(PeerId([3; 32]));
        let rec = |i: u8| DhtRecord {
            key: DhtId([i; 64]),
            record_type: RecordType::Unknown(9),
            sequence: 1,
            signer: [i; 32],
            signer_algo: 1,
            signer_pubkey: vec![],
            value: vec![i; 8],
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signature: vec![0u8; 64],
        };
        // Honest records arrive first, so oldest-first eviction would drop them.
        for i in 0..2 {
            store.put_from(VerifiedRecord::locally_trusted(rec(i)), honest);
        }
        for i in 10..30 {
            store.put_from(VerifiedRecord::locally_trusted(rec(i)), flooder);
        }
        assert_eq!(store.all_records().len(), 6);
        for i in 0..2 {
            assert_eq!(store.get(&DhtId([i; 64])).len(), 1, "honest record {} evicted", i);
        }
    }

    #[test]
    fn full_content_slots_still_admit_a_new_candidate() {
        let mut store = DhtStore::new(&PeerId([1; 32]));
        let (genuine, _) = VerifiedRecord::new_content(b"the real thing", Duration::from_secs(600));
        let key = genuine.record().key;
        for i in 0..MAX_CONTENT_CANDIDATES as u8 {
            put(&mut store, DhtRecord {
                key,
                record_type: RecordType::Content,
                sequence: 0,
                signer: [0; 32],
                signer_algo: 0,
                signer_pubkey: vec![],
                value: vec![i; 48],
                ttl: Duration::from_secs(600),
                stored_at: Instant::now(),
                signature: vec![],
            });
        }
        assert!(store.put(genuine.clone()));
        let at_key = store.get(&key);
        assert_eq!(at_key.len(), MAX_CONTENT_CANDIDATES);
        assert!(at_key.iter().any(|r| r.value == genuine.record().value));
    }

    #[test]
    fn content_blob_is_deterministic() {
        let (k1, b1) = content_address_put(b"same bytes");
        let (k2, b2) = content_address_put(b"same bytes");
        assert_eq!(k1, k2);
        assert_eq!(b1, b2);
        assert_eq!(content_address_get(&hash_64(b"same bytes"), &b1).unwrap(), b"same bytes");
    }

    #[test]
    fn stored_ttl_is_clamped_per_type() {
        let mut store = DhtStore::new(&PeerId([1; 32]));
        let kp = Keypair::generate();
        let mut hello = signed_record(&kp, identity_address_key(&kp.peer_id()), RecordType::Hello, 1, b"h".to_vec());
        hello.ttl = Duration::from_secs(u32::MAX as u64);
        store.put(VerifiedRecord::verify_incoming(hello).unwrap());
        let stored = store.all_records()[0].ttl;
        assert_eq!(stored, MAX_HELLO_TTL);
        assert_eq!(clamp_ttl_secs(RecordType::ZoneRoot, u32::MAX), MAX_RECORD_TTL.as_secs() as u32);
        assert_eq!(clamp_ttl_secs(RecordType::Hello, 600), 600);
    }

    #[test]
    fn zone_root_rejects_owner_at_wrong_key() {
        // Even the real zone key cannot place a zone root anywhere but its own
        // self-address — prevents a root from masquerading at another zone's slot.
        let zone = Keypair::generate();
        let wrong = zone_root_key(&Keypair::generate().identity.service_id());
        let rec = signed_record(&zone, wrong, RecordType::ZoneRoot, 1, b"root".to_vec());
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("self-addressed record not stored at its own key")
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
        let put = rec.to_put_msg();

        assert!(!put.signer_pubkey.is_empty(), "put msg must carry the signer pubkey");
        // Signing side (wire) and verifying side (dht) must agree on the bytes.
        assert_eq!(
            put.signable_bytes(),
            record_signable(&put.key, put.record_type, put.sequence, &put.value)
        );
    }

    #[test]
    fn to_put_msg_carries_remaining_not_full_ttl() {
        // Immortality guard: replication propagates a record via to_put_msg, and
        // the receiver stores it with stored_at = now. If the PUT carried the
        // *full* original TTL, every replication round would reset the record's
        // clock and (for SignedContent, which replaces on equal sequence) it
        // would never expire — outliving its publisher. The PUT must carry the
        // remaining TTL so the record ages toward one fixed deadline regardless
        // of how many times it is replicated.
        let kp = Keypair::generate();
        let mut rec = signed_record(&kp, DhtId([0x0C; 64]), RecordType::SignedContent, 1, b"v".to_vec());
        rec.ttl = Duration::from_secs(100);
        rec.stored_at = Instant::now() - Duration::from_secs(60);

        let put = rec.to_put_msg();
        // ~40s remaining, never the full 100s. Allow a second of slack for the
        // elapsed() call between construction and measurement.
        assert!(
            (38..=41).contains(&put.ttl),
            "expected ~40s remaining TTL, got {}",
            put.ttl
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
        // Blobs are identical too: the nonce is derived from the content, so
        // honest copies dedupe in storage.
        assert_eq!(blob1, blob2);

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

    // ── F3: watch table is bounded against a single-peer flood ──

    #[test]
    fn watch_table_clamps_expiration() {
        // A forged u32::MAX lifetime must be clamped to MAX_WATCH_EXPIRATION_SECS,
        // not honored as ~136 years — otherwise the entry is effectively permanent.
        let mut table = DhtWatchTable::new();
        let key = [0x01; 64];
        let peer = PeerId([1u8; 32]);
        assert!(table.set_watch(key, [0xAB; 32], peer, u32::MAX));
        let expires_at = table.watches[&key][0].expires_at;
        let cap = Instant::now() + Duration::from_secs(MAX_WATCH_EXPIRATION_SECS as u64);
        // Allow a little slack for the clock advancing between the two `now`s.
        assert!(expires_at <= cap + Duration::from_secs(1));
    }

    #[test]
    fn watch_table_zero_still_cancels_after_clamp() {
        // expiration_secs == 0 must keep its cancel semantics, never be clamped up.
        let mut table = DhtWatchTable::new();
        let key = [0x02; 64];
        let token = [0xCD; 32];
        let peer = PeerId([2u8; 32]);
        table.set_watch(key, token, peer, 300);
        assert_eq!(table.watch_count(), 1);
        table.set_watch(key, token, peer, 0);
        assert!(table.get_watchers(&key).is_empty());
        assert_eq!(table.watch_count(), 0);
    }

    #[test]
    fn watch_table_per_peer_cap_refuses_new_but_allows_refresh() {
        let mut table = DhtWatchTable::new();
        let peer = PeerId([3u8; 32]);
        // Fill the per-peer cap with distinct tokens (distinct keys to be safe).
        for i in 0..MAX_WATCHES_PER_PEER {
            let mut token = [0u8; 32];
            token[0] = (i & 0xff) as u8;
            token[1] = (i >> 8) as u8;
            let mut k = [0u8; 64];
            k[0..2].copy_from_slice(&token[0..2]);
            assert!(table.set_watch(k, token, peer, 300));
        }
        assert_eq!(table.watch_count(), MAX_WATCHES_PER_PEER);
        // One more *new* watch from the same peer is refused.
        assert!(!table.set_watch([0xFF; 64], [0xFF; 32], peer, 300));
        assert_eq!(table.watch_count(), MAX_WATCHES_PER_PEER);
        // But refreshing an existing watch still succeeds even at the cap.
        let mut existing_token = [0u8; 32];
        existing_token[0] = 0;
        let mut existing_key = [0u8; 64];
        existing_key[0..2].copy_from_slice(&existing_token[0..2]);
        assert!(table.set_watch(existing_key, existing_token, peer, 600));
        assert_eq!(table.watch_count(), MAX_WATCHES_PER_PEER);
    }

    #[test]
    fn watch_table_global_cap_refuses_new() {
        let mut table = DhtWatchTable::new();
        // Spread across many peers so the per-peer cap never trips first.
        let mut inserted = 0usize;
        'outer: for p in 0..=255u8 {
            let peer = PeerId([p; 32]);
            for i in 0..MAX_WATCHES_PER_PEER {
                if inserted >= MAX_WATCHES_TOTAL {
                    break 'outer;
                }
                let mut token = [0u8; 32];
                token[0] = p;
                token[1] = (i & 0xff) as u8;
                token[2] = (i >> 8) as u8;
                let mut k = [0u8; 64];
                k[0..3].copy_from_slice(&token[0..3]);
                assert!(table.set_watch(k, token, peer, 300));
                inserted += 1;
            }
        }
        assert_eq!(table.watch_count(), MAX_WATCHES_TOTAL);
        // A new watch from a fresh peer is refused at the global cap.
        let fresh = PeerId([0xAA; 32]);
        assert!(!table.set_watch([0xBE; 64], [0xEF; 32], fresh, 300));
        assert_eq!(table.watch_count(), MAX_WATCHES_TOTAL);
    }

    #[test]
    fn watch_table_counts_stay_consistent_through_cancel_and_remove_peer() {
        let mut table = DhtWatchTable::new();
        let peer_a = PeerId([7u8; 32]);
        let peer_b = PeerId([8u8; 32]);
        table.set_watch([0x10; 64], [0x10; 32], peer_a, 300);
        table.set_watch([0x11; 64], [0x11; 32], peer_a, 300);
        table.set_watch([0x12; 64], [0x12; 32], peer_b, 300);
        assert_eq!(table.watch_count(), 3);
        // Cancel frees a slot so a new watch is accepted again (count tracked).
        table.set_watch([0x10; 64], [0x10; 32], peer_a, 0);
        assert_eq!(table.watch_count(), 2);
        // remove_peer drops peer_a's remaining watch and clears its per-peer count.
        table.remove_peer(&peer_a);
        assert_eq!(table.watch_count(), 1);
        table.set_watch([0x13; 64], [0x13; 32], peer_a, 300);
        assert_eq!(table.watch_count(), 2);
    }

    // ── F2: a stale lower-sequence record is is_new BUT not accepted ──

    /// Replicates the (signer, sequence, record_type) exact-tuple test the DhtPut
    /// handler uses for `is_new`.
    fn is_new(store: &DhtStore, key: &DhtId, rec: &DhtRecord) -> bool {
        !store
            .get(key)
            .iter()
            .any(|r| r.signer == rec.signer && r.sequence == rec.sequence && r.record_type == rec.record_type)
    }

    #[test]
    fn stale_lower_seq_is_new_but_not_accepted() {
        // The exact case behind F2: a known signer's lower-sequence record has no
        // matching stored tuple (is_new=true) yet the store refuses it
        // (accepted=false). The handler must forward only on is_new && accepted —
        // forwarding on is_new alone re-floods this rejected record forever.
        let kp = Keypair::generate();
        let key = DhtId([0x70; 64]);
        let mut store = DhtStore::new(&PeerId([0u8; 32]));

        let high = signed_record(&kp, key, RecordType::SignedContent, 5, b"v5".to_vec());
        assert!(store.put(VerifiedRecord::verify_incoming(high).unwrap()));

        // Replay an older sequence from the same signer.
        let stale = signed_record(&kp, key, RecordType::SignedContent, 3, b"v3".to_vec());
        assert!(is_new(&store, &key, &stale), "lower seq has no exact tuple -> is_new");
        let accepted = store.put(VerifiedRecord::verify_incoming(stale).unwrap());
        assert!(!accepted, "store must reject the stale lower-seq record");
        // is_new && accepted == false -> the handler does NOT forward. (bug fixed)
    }

    #[test]
    fn equal_seq_refresh_is_accepted_but_not_new() {
        // The reason the gate is is_new && accepted, not accepted alone:
        // SignedContent uses allow_equal=true, so an equal-sequence re-arrival is
        // ACCEPTED (replaces) but is NOT new (tuple already present). Gating on
        // accepted alone would re-flood every refresh.
        let kp = Keypair::generate();
        let key = DhtId([0x71; 64]);
        let mut store = DhtStore::new(&PeerId([0u8; 32]));

        let first = signed_record(&kp, key, RecordType::SignedContent, 4, b"v4".to_vec());
        assert!(store.put(VerifiedRecord::verify_incoming(first).unwrap()));

        let again = signed_record(&kp, key, RecordType::SignedContent, 4, b"v4".to_vec());
        assert!(!is_new(&store, &key, &again), "equal-seq tuple already stored -> not new");
        let accepted = store.put(VerifiedRecord::verify_incoming(again).unwrap());
        assert!(accepted, "allow_equal=true: equal-seq replaces -> accepted");
        // is_new && accepted == false -> handler does NOT re-flood. (correct)
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

    // ── Walk routing ──

    fn neighbors(peers: &[(PeerId, bool)]) -> Vec<DhtNeighbor> {
        peers.iter().map(|(p, s)| DhtNeighbor::new(*p, *s)).collect()
    }

    fn greedy() -> WalkHeader {
        WalkHeader {
            flags: 0,
            greedy_budget: GREEDY_BUDGET,
            bloom_salt: 0,
            bloom: [0u8; 256],
        }
    }

    /// Peers sorted by distance to `key`, closest first.
    fn by_distance(key: &DhtId, n: usize) -> Vec<PeerId> {
        let mut peers: Vec<PeerId> = (0..n).map(|_| Keypair::generate().peer_id()).collect();
        peers.sort_by_key(|p| dht_id_from_peer_id(p).xor_distance(key));
        peers
    }

    #[test]
    fn walk_count_grows_with_size_and_shrinks_with_degree() {
        assert_eq!(walk_count(1, 0), 2);
        assert_eq!(walk_count(30, 4), 5); // ceil(sqrt(18))
        assert!(walk_count(1000, 8) > walk_count(1000, 32));
        assert_eq!(walk_count(10_000_000, 1), MAX_WALKS);
    }

    #[test]
    fn greedy_forwards_to_strictly_closer_neighbor() {
        let key = DhtId([0x11; 64]);
        let p = by_distance(&key, 3);
        let (closest, local, far) = (p[0], p[1], p[2]);
        let step = walk_step(&local, true, &key, &greedy(), &far, &neighbors(&[(far, true), (closest, true)]), &mut rand::thread_rng());
        match step {
            WalkStep::Forward(to, h) => {
                assert_eq!(to, closest);
                assert_eq!(h.greedy_budget, GREEDY_BUDGET - 1);
                assert_eq!(h.bloom, [0u8; 256], "greedy hops never enter the bloom");
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn storing_local_minimum_ends_the_walk() {
        let key = DhtId([0x22; 64]);
        let p = by_distance(&key, 3);
        let step = walk_step(&p[0], true, &key, &greedy(), &p[1], &neighbors(&[(p[1], true), (p[2], true)]), &mut rand::thread_rng());
        assert_eq!(step, WalkStep::End);
    }

    #[test]
    fn relay_only_minimum_hands_off_to_same_storer_from_either_side() {
        let key = DhtId([0x33; 64]);
        let p = by_distance(&key, 4);
        // p[0] is a relay-only local minimum; its neighbours p[1] (stores) and
        // p[2] (stores) and p[3] (relay-only).
        let local = p[0];
        let nbrs = neighbors(&[(p[1], true), (p[2], true), (p[3], false)]);
        for from in [p[1], p[2], p[3]] {
            let step = walk_step(&local, false, &key, &greedy(), &from, &nbrs, &mut rand::thread_rng());
            match step {
                WalkStep::Forward(to, h) => {
                    assert_eq!(to, p[1], "always the closest storing neighbour");
                    assert!(h.deliver());
                    let bloom = BloomFilter::from_bytes(h.bloom);
                    assert!(bloom.contains(h.bloom_salt, &local));
                    assert!(!bloom.contains(h.bloom_salt, &from), "only relay-only detour nodes are recorded");
                }
                other => panic!("expected deliver forward, got {other:?}"),
            }
        }
    }

    #[test]
    fn deliver_ends_at_first_storer_and_skips_visited_relays() {
        let key = DhtId([0x44; 64]);
        let p = by_distance(&key, 3);
        let mut h = greedy();
        h.flags = walk_flags::DELIVER;
        // A storing node receiving DELIVER is the end, even if not a minimum.
        assert_eq!(
            walk_step(&p[2], true, &key, &h, &p[0], &neighbors(&[(p[0], false), (p[1], true)]), &mut rand::thread_rng()),
            WalkStep::End
        );
        // A relay-only node on the detour skips relays already in the bloom.
        let mut bloom = BloomFilter::new();
        h.bloom_salt = 7;
        bloom.insert(7, &p[0]);
        h.bloom = bloom.to_bytes();
        let step = walk_step(&p[2], false, &key, &h, &p[0], &neighbors(&[(p[0], false), (p[1], false)]), &mut rand::thread_rng());
        assert!(matches!(step, WalkStep::Forward(to, _) if to == p[1]));
        // Nowhere left to go: dropped.
        bloom.insert(7, &p[1]);
        h.bloom = bloom.to_bytes();
        let step = walk_step(&p[2], false, &key, &h, &p[0], &neighbors(&[(p[0], false), (p[1], false)]), &mut rand::thread_rng());
        assert_eq!(step, WalkStep::Drop);
    }

    #[test]
    fn walking_phase_ends_with_probability_q_and_never_touches_bloom() {
        let key = DhtId([0x55; 64]);
        let p = by_distance(&key, 4);
        let nbrs = neighbors(&[(p[0], true), (p[1], true), (p[3], true)]);
        let mut rng = rand::thread_rng();
        let mut walked = 0;
        let trials = 3000;
        for _ in 0..trials {
            match walk_step(&p[2], true, &key, &WalkHeader::origin(), &p[3], &nbrs, &mut rng) {
                WalkStep::Forward(to, h) if h.walking() => {
                    walked += 1;
                    assert_ne!(to, p[3], "random phase avoids the sender when it can");
                    assert_eq!(h.bloom, [0u8; 256]);
                }
                // Ended the random phase here: greedy from p[2] goes to p[0].
                WalkStep::Forward(to, h) => {
                    assert_eq!(to, p[0]);
                    assert_eq!(h.greedy_budget, GREEDY_BUDGET - 1);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let frac = walked as f64 / trials as f64;
        assert!((frac - (1.0 - WALK_END_PROBABILITY)).abs() < 0.05, "continue fraction {frac}");
    }

    #[test]
    fn exhausted_budget_ends_at_storer_and_drops_at_relay() {
        let key = DhtId([0x66; 64]);
        let p = by_distance(&key, 2);
        let mut h = greedy();
        h.greedy_budget = 0;
        let nbrs = neighbors(&[(p[0], true)]);
        assert_eq!(walk_step(&p[1], true, &key, &h, &p[0], &nbrs, &mut rand::thread_rng()), WalkStep::End);
        assert_eq!(walk_step(&p[1], false, &key, &h, &p[0], &nbrs, &mut rand::thread_rng()), WalkStep::Drop);
    }

    /// Graph-level check of the walk rules: a PUT from one node and up to
    /// three rounds of GET walks from another meet (GET walks answer from any
    /// node holding the record, including the publisher itself).
    struct SimGraph {
        peers: Vec<PeerId>,
        stores: Vec<bool>,
        adj: Vec<Vec<usize>>,
    }

    impl SimGraph {
        fn new(n: usize) -> Self {
            Self {
                peers: (0..n).map(|_| Keypair::generate().peer_id()).collect(),
                stores: vec![true; n],
                adj: vec![Vec::new(); n],
            }
        }

        fn link(&mut self, a: usize, b: usize) {
            if a != b && !self.adj[a].contains(&b) {
                self.adj[a].push(b);
                self.adj[b].push(a);
            }
        }

        fn index(&self, p: &PeerId) -> usize {
            self.peers.iter().position(|q| q == p).unwrap()
        }

        /// Run one walk starting with the hop origin → first. Returns the nodes
        /// visited after the origin and the end node, if any.
        fn walk(&self, key: &DhtId, origin: usize, first: usize, rng: &mut impl Rng) -> (Vec<usize>, Option<usize>) {
            let mut header = WalkHeader::origin();
            let (mut from, mut at) = (origin, first);
            let mut visited = vec![at];
            for _ in 0..256 {
                let nbrs: Vec<DhtNeighbor> = self.adj[at]
                    .iter()
                    .map(|&i| DhtNeighbor::new(self.peers[i], self.stores[i]))
                    .collect();
                match walk_step(&self.peers[at], self.stores[at], key, &header, &self.peers[from], &nbrs, rng) {
                    WalkStep::End => return (visited, Some(at)),
                    WalkStep::Drop => return (visited, None),
                    WalkStep::Forward(next, h) => {
                        header = h;
                        from = at;
                        at = self.index(&next);
                        visited.push(at);
                    }
                }
            }
            panic!("walk did not terminate");
        }

        fn launch(&self, key: &DhtId, origin: usize, count: usize, rng: &mut impl Rng) -> Vec<(Vec<usize>, Option<usize>)> {
            use rand::seq::SliceRandom;
            let mut first = self.adj[origin].clone();
            first.shuffle(rng);
            (0..count).map(|i| self.walk(key, origin, first[i % first.len()], rng)).collect()
        }

        fn rho(&self, origin: usize) -> usize {
            walk_count(self.peers.len(), self.adj[origin].len())
        }

        /// Success rate of PUT-then-GET over `trials` random (key, publisher, reader).
        fn success_rate(&self, trials: usize, rng: &mut impl Rng) -> f64 {
            let n = self.peers.len();
            let mut ok = 0;
            for _ in 0..trials {
                let mut kb = [0u8; 64];
                rng.fill_bytes(&mut kb);
                let key = DhtId(kb);
                let publisher = rng.gen_range(0..n);
                let reader = loop {
                    let r = rng.gen_range(0..n);
                    if r != publisher {
                        break r;
                    }
                };
                let mut holders = vec![publisher];
                for (_, end) in self.launch(&key, publisher, self.rho(publisher), rng) {
                    holders.extend(end);
                }
                let found = (0..3).any(|_| {
                    self.launch(&key, reader, self.rho(reader), rng)
                        .iter()
                        .any(|(visited, _)| visited.iter().any(|v| holders.contains(v)))
                });
                if found {
                    ok += 1;
                }
            }
            ok as f64 / trials as f64
        }
    }

    #[test]
    fn walks_meet_on_random_graph_with_relay_only_nodes() {
        let mut rng = rand::thread_rng();
        let n = 200;
        let mut g = SimGraph::new(n);
        // Connected backbone plus random chords: average degree ≈ 4.
        for i in 1..n {
            let j = rng.gen_range(0..i);
            g.link(i, j);
        }
        for _ in 0..n {
            let (a, b) = (rng.gen_range(0..n), rng.gen_range(0..n));
            g.link(a, b);
        }
        for i in 0..n {
            g.stores[i] = rng.gen_bool(0.8);
        }
        let rate = g.success_rate(300, &mut rng);
        eprintln!("random graph rendezvous rate: {rate}");
        assert!(rate >= 0.9, "PUT/GET rendezvous rate {rate}");
    }

    #[test]
    fn walks_meet_across_relay_only_chains() {
        // Research-cluster shape: 8 storing machines, mostly joined through
        // chains of two relay-only boxes, a couple of direct links.
        let mut rng = rand::thread_rng();
        let machines = 8;
        let mut g = SimGraph::new(machines + 2 * 10);
        let mut next = machines;
        let chains = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7), (7, 0), (0, 4), (2, 6)];
        for (a, b) in chains {
            let (r1, r2) = (next, next + 1);
            next += 2;
            g.stores[r1] = false;
            g.stores[r2] = false;
            g.link(a, r1);
            g.link(r1, r2);
            g.link(r2, b);
        }
        g.link(1, 5);
        g.link(3, 7);
        // Only machines publish and read.
        let mut ok = 0;
        let trials = 300;
        for _ in 0..trials {
            let mut kb = [0u8; 64];
            rng.fill_bytes(&mut kb);
            let key = DhtId(kb);
            let publisher = rng.gen_range(0..machines);
            let reader = (publisher + rng.gen_range(1..machines)) % machines;
            let mut holders = vec![publisher];
            for (_, end) in g.launch(&key, publisher, g.rho(publisher), &mut rng) {
                if let Some(e) = end {
                    assert!(g.stores[e], "walks only end at storing nodes");
                    holders.push(e);
                }
            }
            if (0..3).any(|_| {
                g.launch(&key, reader, g.rho(reader), &mut rng)
                    .iter()
                    .any(|(visited, _)| visited.iter().any(|v| holders.contains(v)))
            }) {
                ok += 1;
            }
        }
        let rate = ok as f64 / trials as f64;
        eprintln!("relay-chain rendezvous rate: {rate}");
        assert!(rate >= 0.95, "PUT/GET rendezvous rate {rate}");
    }

    #[test]
    fn bloom_membership_depends_on_salt() {
        let peer = PeerId([9; 32]);
        let mut bloom = BloomFilter::new();
        bloom.insert(1, &peer);
        assert!(bloom.contains(1, &peer));
        assert!(!bloom.contains(2, &peer));
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
