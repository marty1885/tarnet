use std::collections::HashMap;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::{Rng, RngCore};

use crate::identity::{dht_id_from_peer_id, Keypair};
use crate::state::{PersistedRecord, StorageLimits};
use crate::types::{ContentHandle, DhtId, PeerId, RecordType, Result};
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
    pub signer: PeerId,
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
    pub value: Vec<u8>,
    /// When the record expires here, on this node's monotonic clock. Nodes
    /// share no clock: the wire carries the remaining `ttl` instead.
    pub expires: Instant,
    /// When this node stored it (eviction order only).
    pub stored_at: Instant,
    pub signature: Vec<u8>,
}

/// The `expires` of a record that has `ttl` left from now.
pub fn expires_in(ttl: Duration) -> Instant {
    Instant::now() + ttl
}

impl DhtRecord {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires
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
            ttl: self.wire_ttl(),
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
    /// Carries the *remaining* TTL, so however often a record is relayed or
    /// republished it ages toward one deadline. The TTL is not signed (nodes
    /// share no clock, so nothing absolute could be); see [`DhtStore`] for what
    /// stops a replay from extending a record.
    pub fn to_put_msg(&self) -> crate::wire::DhtPutMsg {
        crate::wire::DhtPutMsg {
            walk: WalkHeader::origin(),
            key: *self.key.as_bytes(),
            record_type: self.record_type,
            sequence: self.sequence,
            signer: self.signer,
            ttl: self.wire_ttl(),
            value: self.value.clone(),
            signature: self.signature.clone(),
            signer_algo: self.signer_algo,
            signer_pubkey: self.signer_pubkey.clone(),
        }
    }

    /// Time left until `expires`.
    pub fn remaining_ttl(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }

    /// Remaining whole seconds, as carried on the wire.
    fn wire_ttl(&self) -> u32 {
        self.remaining_ttl().as_secs().min(u32::MAX as u64) as u32
    }
}

/// Canonical bytes covered by a signed DHT record's signature:
/// `key || record_type || sequence(BE) || value`.
///
/// Single source of truth: [`crate::wire::DhtPutMsg::signable_bytes`] and
/// [`verify_incoming_record`] both build the signable through this, so the signed
/// layout can never drift between the signing side and the verifying side.
///
/// The TTL is not covered: each hop carries the *remaining* TTL, so it changes
/// in transit. Nodes clamp it to the type's cap, and the store never lets a
/// copy extend a record it holds or bring back one that expired here.
pub fn record_signable(key: &[u8; 64], record_type: RecordType, sequence: u64, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + 64 + 1 + 8 + value.len());
    // Domain-separated from everything else the same identity key signs.
    buf.extend_from_slice(b"tarnet dht record v1");
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
    let expires = expires_in(ttl.min(max_ttl(record_type)));
    let signature = kp.sign(&record_signable(key.as_bytes(), record_type, sequence, &value));
    DhtRecord {
        key,
        record_type,
        sequence,
        signer: kp.peer_id(),
        signer_algo: kp.identity.signing.algo() as u8,
        signer_pubkey: kp.identity.signing.signing_pubkey_bytes(),
        value,
        expires,
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
    signer: &PeerId,
    signer_algo: u8,
    signer_pubkey: &[u8],
    signature: &[u8],
) -> std::result::Result<(), &'static str> {
    if record_type == RecordType::Content {
        // Unsigned but self-certifying: the blob's hash fixes its key.
        if content_key_of_blob(value).as_bytes() != key {
            return Err("content not stored at its own key");
        }
        return Ok(());
    }
    if signer_pubkey.is_empty() {
        return Err("missing signer pubkey");
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
        && identity_address_key(signer).as_bytes() != key
    {
        return Err("hello not stored at its signer's identity key");
    }
    let signable = record_signable(key, record_type, sequence, value);
    if !crate::identity::verify_signed(
        crate::identity::SignedBy::Peer(signer),
        Some(signer_algo),
        signer_pubkey,
        &signable,
        signature,
    ) {
        return Err("not signed by its signer");
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

    /// Mint an unsigned, content-addressed record (a content-hash key, see
    /// [`content_address_put`]): storage nodes hold only an opaque blob, and
    /// can check it belongs at its key. Returns the record and the content handle a reader needs to fetch and
    /// decrypt it.
    pub fn new_content(plaintext: &[u8], ttl: Duration) -> (Self, ContentHandle) {
        let (key, blob, inner_hash) = content_address_put(plaintext);
        let record = DhtRecord {
            key,
            record_type: RecordType::Content,
            sequence: 0,
            signer: PeerId([0u8; 32]),
            signer_algo: 0,
            signer_pubkey: Vec::new(),
            value: blob,
            expires: expires_in(ttl.min(MAX_RECORD_TTL)),
            stored_at: Instant::now(),
            signature: Vec::new(),
        };
        (Self(record), inner_hash)
    }

    /// Mint a signed, content-addressed record. The value is content-addressed
    /// and then wrapped with [`signed_record_encrypt`] under the lookup key, so
    /// storage nodes see only a blob; the record is signed by `signer`. Returns
    /// the record and the content handle a reader needs to fetch and decrypt it.
    pub fn new_signed_content(
        signer: &Keypair,
        plaintext: &[u8],
        sequence: u64,
        ttl: Duration,
    ) -> (Self, ContentHandle) {
        let (key, blob, inner_hash) = content_address_put(plaintext);
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
            expires: expires_in(clamp_ttl(put.record_type, put.ttl)),
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
            expires: expires_in(clamp_ttl(rec.record_type, rec.ttl)),
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
    /// What it counts against the byte limits, fixed when stored.
    cost: usize,
}

/// Bookkeeping per stored record beyond its encoding: map slot, times,
/// source, vector headers.
const STORED_OVERHEAD: usize = 128;

impl StoredRecord {
    /// The cost is the record's own wire encoding (every field, signer key
    /// included, whatever fields records gain later) plus bookkeeping, so the
    /// byte limits can't drift from what a record actually holds.
    fn new(record: DhtRecord, source: RecordSource) -> Self {
        let cost = record.to_put_msg().record_bytes().len() + STORED_OVERHEAD;
        Self { record, source, cost }
    }
}

/// Longest lifetime any record may hold in the store. The TTL is unsigned, so
/// every node clamps whatever a sender claims to this.
pub const MAX_RECORD_TTL: Duration = Duration::from_secs(24 * 3600);

/// Ceiling for hello records, which are republished every few minutes and
/// carry reachability data that goes stale quickly.
pub const MAX_HELLO_TTL: Duration = Duration::from_secs(3600);

/// The TTL ceiling for a record type.
pub fn max_ttl(record_type: RecordType) -> Duration {
    match record_type {
        RecordType::Hello => MAX_HELLO_TTL,
        // A zone root is re-signed well within its lifetime: a replayed old
        // root can't be made to outlive it.
        RecordType::ZoneRoot => Duration::from_secs(crate::tns::ZONE_ROOT_TTL as u64),
        _ => MAX_RECORD_TTL,
    }
}

/// A wire TTL, clamped to the ceiling for its record type.
pub fn clamp_ttl(record_type: RecordType, ttl: u32) -> Duration {
    Duration::from_secs(ttl as u64).min(max_ttl(record_type))
}

/// [`clamp_ttl`] in wire seconds, for a message forwarded on.
pub fn clamp_ttl_secs(record_type: RecordType, ttl: u32) -> u32 {
    clamp_ttl(record_type, ttl).as_secs() as u32
}

/// What [`DhtStore::put_record`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutOutcome {
    /// The record is in the store now (new, newer, or an equal copy already
    /// held) and survived the storage limits.
    pub stored: bool,
    /// It is a version this store did not hold before: news for watchers.
    pub news: bool,
}

/// The records this node holds: those PUT walks ended here with, and its
/// own. A node with a database keeps it a mirror of the store: every change
/// to the store is written there by the store itself, under the same lock,
/// so the two can't disagree.
pub struct DhtStore {
    records: HashMap<[u8; 64], Vec<StoredRecord>>,
    local_id: DhtId,
    limits: StorageLimits,
    db: Option<std::sync::Arc<crate::state::StateDb>>,
    /// Records that expired here, by (key, signer): the highest dead
    /// sequence, and when to forget it.
    /// TTLs are unsigned and nodes share no clock, so a copy arriving later
    /// (a replay, or a slow relay) can't be told apart from a fresh one by its
    /// TTL; instead, a record that died here is never stored here again,
    /// unless its owner signs a higher sequence. Remembered for the type's
    /// TTL cap, the longest any copy could claim to live.
    dead: crate::bounded::BoundedMap<([u8; 64], [u8; 32]), u64>,
}

fn dead_id(record: &DhtRecord) -> [u8; 32] {
    *record.signer.as_bytes()
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
            db: None,
            dead: crate::bounded::BoundedMap::new(limits.max_records.saturating_mul(2), MAX_RECORD_TTL),
        }
    }

    /// A store mirrored in `db`, loaded from it. Rows the store no longer
    /// admits (expired, failing verification, over the limits, or written
    /// under a clock that has since gone back) are deleted.
    pub fn open(local_peer: &PeerId, limits: StorageLimits, db: std::sync::Arc<crate::state::StateDb>) -> Self {
        let mut store = Self::with_limits(local_peer, limits);
        if let Err(e) = db.delete_expired_dht_records() {
            log::warn!("Failed to delete expired DHT records: {}", e);
        }
        let rows = db.load_dht_records().unwrap_or_default();
        store.db = Some(db);
        store.import_records(rows);
        store
    }

    fn mirror_put(&self, e: &StoredRecord) {
        let Some(db) = &self.db else { return };
        if let Some(row) = PersistedRecord::from_stored(&e.record, e.source) {
            if let Err(err) = db.upsert_dht_record(&row) {
                log::warn!("Failed to persist DHT record: {}", err);
            }
        }
    }

    fn mirror_delete(&self, key: &[u8; 64], signer: &[u8; 32]) {
        let Some(db) = &self.db else { return };
        if let Err(e) = db.delete_dht_record(key, signer) {
            log::warn!("Failed to delete DHT record: {}", e);
        }
    }

    /// Store a record this node minted itself. See [`put_record`](Self::put_record).
    pub fn put(&mut self, record: VerifiedRecord) -> bool {
        self.put_record(record, RecordSource::Local).stored
    }

    /// [`put_record`](Self::put_record), reporting only whether the record is
    /// now stored.
    pub fn put_from(&mut self, record: VerifiedRecord, source: RecordSource) -> bool {
        self.put_record(record, source).stored
    }

    /// Store a record, attributing it to `source` for fair-share eviction.
    /// One version per signer at a key; a higher sequence replaces it.
    /// `SignedContent` and `Content` accept a repeat of the version held
    /// without extending it. Unsigned content is self-certifying (the ingest
    /// gate checks its key), so it has one valid version per key. Our own
    /// records ([`RecordSource::Local`]) are never evicted for others'.
    pub fn put_record(&mut self, record: VerifiedRecord, source: RecordSource) -> PutOutcome {
        let record = record.into_inner();
        self.expire();
        let refused = PutOutcome {
            stored: false,
            news: false,
        };
        if record.value.len() > self.limits.max_value_bytes {
            return refused;
        }
        if record.is_expired() || self.died_here(&record) {
            return refused;
        }

        let key = *record.key.as_bytes();
        let (signer, sequence, record_type) = (record.signer, record.sequence, record.record_type);
        let entries = self.records.entry(key).or_default();
        let held = entries.iter().find(|e| e.record.signer == signer).map(|e| e.record.sequence);
        // `SignedContent` and `Content` also accept a repeat of the version
        // held (it keeps the deadline held).
        let allow_equal = matches!(record_type, RecordType::SignedContent | RecordType::Content);
        if !upsert_by_signer(entries, record, source, allow_equal) {
            self.records.retain(|_, v| !v.is_empty());
            return refused;
        }
        let mut evicted = Vec::new();
        self.enforce_key_limits(&key, &mut evicted);
        self.enforce_global_limits(&mut evicted);
        for r in &evicted {
            self.mirror_delete(r.key.as_bytes(), r.signer.as_bytes());
        }
        let Some(e) = self.records.get(&key).and_then(|entries| {
            entries
                .iter()
                .find(|e| e.record.signer == signer && e.record.sequence == sequence && e.record.record_type == record_type)
        }) else {
            return refused;
        };
        let news = held.map_or(true, |seq| sequence > seq);
        if news {
            self.mirror_put(e);
        }
        PutOutcome { stored: true, news }
    }

    /// A relay-only node keeps only its own records: drop everyone else's.
    pub fn drop_replicas(&mut self) {
        let mut gone = Vec::new();
        for entries in self.records.values_mut() {
            entries.retain(|e| {
                if e.source == RecordSource::Local {
                    return true;
                }
                gone.push((*e.record.key.as_bytes(), *e.record.signer.as_bytes()));
                false
            });
        }
        self.records.retain(|_, v| !v.is_empty());
        for (key, signer) in &gone {
            self.mirror_delete(key, signer);
        }
    }

    /// `peer`'s hello, from its newest hello record here: signed by `peer`
    /// (the store only holds verified records), and naming `peer` itself.
    pub fn hello_of(&self, peer: &PeerId) -> Option<crate::wire::HelloRecord> {
        let key = identity_address_key(peer);
        self.get(&key)
            .into_iter()
            .filter(|r| r.record_type == RecordType::Hello && r.signer == *peer)
            .max_by_key(|r| r.sequence)
            .and_then(|r| hello_from_record(peer, r))
    }

    /// Every hello held here, each checked as [`hello_of`](Self::hello_of)
    /// checks it.
    pub fn hellos(&self) -> Vec<crate::wire::HelloRecord> {
        let signers: std::collections::HashSet<PeerId> = self
            .records
            .values()
            .flatten()
            .filter(|e| e.record.record_type == RecordType::Hello)
            .map(|e| e.record.signer)
            .collect();
        signers.iter().filter_map(|p| self.hello_of(p)).collect()
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

    /// Remove expired records, remembering each as dead here. Unsigned
    /// content is not remembered: it has no sequence an owner could raise,
    /// so remembering it would refuse its republish, and a replay can only
    /// bring back the one immutable blob its key admits.
    pub fn expire(&mut self) {
        let now = Instant::now();
        let mut gone = Vec::new();
        for entries in self.records.values_mut() {
            entries.retain(|e| {
                if e.record.is_expired() {
                    gone.push(e.record.clone());
                    false
                } else {
                    true
                }
            });
        }
        self.records.retain(|_, v| !v.is_empty());
        for r in &gone {
            self.mirror_delete(r.key.as_bytes(), r.signer.as_bytes());
            if r.record_type == RecordType::Content {
                continue;
            }
            // The lifetime restarts with each death: a later sequence that
            // died is remembered for the full cap after it died. Full: a
            // replay of this one may be stored again.
            let k = (*r.key.as_bytes(), dead_id(r));
            let seq = self.dead.get(&k).map_or(r.sequence, |s| (*s).max(r.sequence));
            let _ = self.dead.upsert(k, seq);
        }
        self.dead.expire(now);
    }

    /// The record (or an older sequence of it) expired here.
    fn died_here(&self, record: &DhtRecord) -> bool {
        self.dead
            .get(&(*record.key.as_bytes(), dead_id(record)))
            .is_some_and(|seq| record.sequence <= *seq)
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

    /// Our own non-expired records ([`RecordSource::Local`]).
    pub fn own_records(&self) -> Vec<&DhtRecord> {
        self.records
            .values()
            .flatten()
            .filter(|e| e.source == RecordSource::Local && !e.record.is_expired())
            .map(|e| &e.record)
            .collect()
    }

    pub fn export_records(&self) -> Vec<PersistedRecord> {
        self.records
            .values()
            .flat_map(|entries| entries.iter())
            .filter_map(|e| PersistedRecord::from_stored(&e.record, e.source))
            .collect()
    }

    /// Load persisted records, re-verifying each on the way back in (DB
    /// corruption or tampering): signed fields round-trip faithfully, so a
    /// record that passed when first accepted passes again. Rows no longer
    /// stored are deleted from the mirror.
    pub fn import_records(&mut self, records: Vec<PersistedRecord>) {
        for row in records {
            let (key, signer) = (row.key, row.signer);
            // Each record comes back with who handed it to us: a replica a
            // peer delivered stays a peer's after a restart, and is never
            // republished as ours.
            let stored = match row.into_stored() {
                None => false,
                Some((live, source)) => match VerifiedRecord::verify_incoming(live) {
                    Ok(verified) => self.put_record(verified, source).stored,
                    Err(reason) => {
                        log::warn!("dropping persisted DHT record on load: {}", reason);
                        false
                    }
                },
            };
            if !stored {
                self.mirror_delete(&key, &signer);
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
            .map(|e| e.cost)
            .sum()
    }

    /// Bring one key back within its record/byte budget. Owner-bound records
    /// (a zone root, or a hello at its signer's own key — the only places those
    /// types can be stored) are never evicted to make room for other records at
    /// the same key: they are the reason the key exists, and foreign records
    /// piling onto it must not be able to push them out.
    fn enforce_key_limits(&mut self, key: &[u8; 64], evicted: &mut Vec<DhtRecord>) {
        let max_records_per_key = self.limits.max_records_per_key;
        let max_bytes_per_key = self.limits.max_bytes_per_key;

        if let Some(entries) = self.records.get_mut(key) {
            let mut byte_total: usize = entries.iter().map(|e| e.cost).sum();
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
                byte_total -= entries[idx].cost;
                evicted.push(entries.remove(idx).record);
            }
        }

        self.records.retain(|_, v| !v.is_empty());
    }

    fn enforce_global_limits(&mut self, evicted: &mut Vec<DhtRecord>) {
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
                byte_count -= entries[idx].cost;
                evicted.push(entries.remove(idx).record);
                record_count -= 1;
                if entries.is_empty() {
                    self.records.remove(&key);
                }
            }
        }
    }
}

/// `peer`'s hello from a verified record: a hello at `peer`'s own key,
/// signed by `peer`, naming `peer`.
pub fn hello_from_record(peer: &PeerId, r: &DhtRecord) -> Option<crate::wire::HelloRecord> {
    let key = identity_address_key(peer);
    if r.record_type != RecordType::Hello || r.signer != *peer || r.key != key {
        return None;
    }
    let plain = signed_record_decrypt(&key, &r.value).ok()?;
    crate::wire::HelloRecord::from_bytes(&plain)
        .ok()
        .filter(|h| h.peer_id == *peer)
}

/// Record types that only the key's owner can write (enforced at ingest by
/// [`verify_incoming_record`]).
fn is_owner_bound(record_type: RecordType) -> bool {
    matches!(record_type, RecordType::Hello | RecordType::ZoneRoot)
}

/// Pick the record to evict: the oldest record from whichever source holds the
/// most of the candidates. Under normal load this approximates oldest-first;
/// under a flood from one link it evicts that link's records before anyone
/// else's. Our own records are never candidates: they are what we publish,
/// and nothing would put them back.
fn fair_share_victim<'a, I: Copy>(
    candidates: impl Iterator<Item = (I, &'a StoredRecord)> + Clone,
) -> Option<I> {
    let candidates = candidates.filter(|(_, e)| e.source != RecordSource::Local);
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
            *existing = StoredRecord::new(record, source);
            return true;
        }
        // An equal sequence is the same signed record again (a republish, or
        // a replay by anyone who saw it). `ttl` is not signed, so the copy
        // gains nothing: the record keeps its absolute deadline, which only a
        // higher sequence (signed, so only the owner's) can renew.
        if allow_equal && record.sequence == existing.record.sequence {
            return true;
        }
        false
    } else {
        entries.push(StoredRecord::new(record, source));
        true
    }
}

/// A remote watch on a DHT key, identified by query_token for anonymous
/// notification routing. The storing node never learns the watcher's identity.
#[derive(Debug, Clone)]
pub struct DhtWatch {
    /// Opaque token used to route notifications back hop-by-hop.
    pub query_token: [u8; 32],
    /// Direct neighbor that forwarded this watch (for sending notifications).
    pub via_peer: PeerId,
    /// Where we passed the watch on: notifications relayed back must come
    /// from it. `None` if the walk ended here.
    pub next: Option<PeerId>,
    pub expires_at: Instant,
    /// Newest sequence notified per signer, so a re-PUT of a record the
    /// watcher already has (a republish) notifies nothing.
    pub notified: HashMap<[u8; 32], u64>,
}

/// Signers whose last notified sequence a watch remembers. Past this the
/// oldest-looking entry is forgotten (it may then be notified once more).
const MAX_NOTIFIED_SIGNERS: usize = 64;

/// Cap on a watch's lifetime, regardless of the (wire-supplied) request.
/// Watchers relaunch their walks every minute asking for two minutes, so an
/// honest registration never needs this; it bounds how long an abandoned or
/// forged one can squat memory (a u32::MAX request would otherwise pin an
/// entry for ~136 years).
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
        // A watch belongs to the neighbour that registered it: only that
        // neighbour can cancel or refresh it, so a node that saw a token
        // can't cancel someone's watch or point its notifications elsewhere.
        let ours = |w: &DhtWatch| w.query_token == query_token && w.via_peer == via_peer;
        if expiration_secs == 0 {
            // Collect the via_peers of the entries being dropped first, then
            // decrement the per-peer/total counters — avoids holding a mutable
            // borrow on `self.watches` while touching `self.per_peer_count`.
            if let Some(entries) = self.watches.get_mut(&key) {
                let dropped: Vec<PeerId> = entries
                    .iter()
                    .filter(|w| ours(w))
                    .map(|w| w.via_peer)
                    .collect();
                entries.retain(|w| !ours(w));
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
        // An expired registration neither blocks its token nor comes back.
        self.prune(&key);
        if let Some(entries) = self.watches.get_mut(&key) {
            // Refresh (must always succeed, so a legit periodic refresh isn't
            // broken once a peer is at its cap).
            if let Some(existing) = entries.iter_mut().find(|w| ours(w)) {
                existing.expires_at = expires_at;
                return true;
            }
            // The token is someone else's.
            if entries.iter().any(|w| w.query_token == query_token) {
                return false;
            }
        }

        // New entry: enforce the per-peer and global caps, counting only
        // live watches.
        let full = |t: &Self| {
            t.per_peer_count.get(&via_peer).copied().unwrap_or(0) >= MAX_WATCHES_PER_PEER
                || t.total_count >= MAX_WATCHES_TOTAL
        };
        if full(self) {
            self.expire();
            if full(self) {
                return false;
            }
        }
        let entries = self.watches.entry(key).or_default();
        entries.push(DhtWatch {
            query_token,
            via_peer,
            next: None,
            expires_at,
            notified: HashMap::new(),
        });
        *self.per_peer_count.entry(via_peer).or_insert(0) += 1;
        self.total_count += 1;
        true
    }

    /// Drop `key`'s expired registrations.
    fn prune(&mut self, key: &[u8; 64]) {
        let now = Instant::now();
        let Some(entries) = self.watches.get_mut(key) else { return };
        let mut dropped = Vec::new();
        entries.retain(|w| {
            let live = w.expires_at > now;
            if !live {
                dropped.push(w.via_peer);
            }
            live
        });
        if entries.is_empty() {
            self.watches.remove(key);
        }
        self.total_count = self.total_count.saturating_sub(dropped.len());
        for peer in &dropped {
            self.decr_peer(peer);
        }
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

    /// Where to relay a notification under `query_token` that `from` sent:
    /// the watch's previous hop, if `from` is where the watch went next.
    pub fn relay_for(&self, key: &[u8; 64], query_token: &[u8; 32], from: &PeerId) -> Option<PeerId> {
        let now = Instant::now();
        self.watches.get(key)?.iter().find_map(|w| {
            (w.query_token == *query_token && w.expires_at > now && w.next == Some(*from))
                .then_some(w.via_peer)
        })
    }

    /// Record where a watch walk went next.
    pub fn set_next(&mut self, key: &[u8; 64], query_token: &[u8; 32], next: PeerId) {
        if let Some(w) = self
            .watches
            .get_mut(key)
            .and_then(|e| e.iter_mut().find(|w| w.query_token == *query_token))
        {
            w.next = Some(next);
        }
    }

    /// Get all non-expired watchers for a key: returns (query_token, via_peer).
    #[cfg(test)]
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

    /// Watchers of `key` that haven't been told of this version (`signer`'s
    /// record at `sequence`, or newer); marks them told. Call only with a
    /// verified record: whatever is passed here suppresses later news.
    pub fn watchers_for_news(
        &mut self,
        key: &[u8; 64],
        signer: &[u8; 32],
        sequence: u64,
    ) -> Vec<([u8; 32], PeerId)> {
        let now = Instant::now();
        let Some(entries) = self.watches.get_mut(key) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for w in entries.iter_mut().filter(|w| w.expires_at > now) {
            if w.notified.get(signer).is_some_and(|s| *s >= sequence) {
                continue;
            }
            if !w.notified.contains_key(signer) && w.notified.len() >= MAX_NOTIFIED_SIGNERS {
                if let Some(k) = w.notified.iter().min_by_key(|(_, s)| **s).map(|(k, _)| *k) {
                    w.notified.remove(&k);
                }
            }
            w.notified.insert(*signer, sequence);
            out.push((w.query_token, w.via_peer));
        }
        out
    }

    /// Someone is watching `key`.
    pub fn is_watched(&self, key: &[u8; 64]) -> bool {
        let now = Instant::now();
        self.watches
            .get(key)
            .is_some_and(|entries| entries.iter().any(|w| w.expires_at > now))
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

/// Content-hash keys (CHK), as in Freenet. A content **handle** is
/// `enc_key(32) || chk(32)`: the key that decrypts the blob, and the hash of
/// the blob itself. The DHT key is derived from `chk` alone, so a storing
/// node, which sees only the opaque blob, can check that the blob belongs at
/// its key ([`content_key_of_blob`]) and refuses anything else: exactly one
/// blob is valid per key, and junk can't compete with it. Convergent: the
/// same plaintext always gives the same handle, blob and key, so honest
/// copies from every publisher are identical.
///
/// Returns the DHT key, the blob to store, and the handle a reader needs.
pub fn content_address_put(value: &[u8]) -> (DhtId, Vec<u8>, ContentHandle) {
    // The key only ever seals this one plaintext, so a fixed nonce derived
    // from it leaks nothing, and makes the blob a pure function of the content.
    let enc_key = blake3::derive_key("tarnet content v2 encryption key", value);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&blake3::derive_key("tarnet content v2 nonce", &enc_key)[..24]);
    let ciphertext = XChaCha20Poly1305::new((&enc_key).into())
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

    let chk = *blake3::hash(&blob).as_bytes();
    let mut handle = [0u8; 64];
    handle[..32].copy_from_slice(&enc_key);
    handle[32..].copy_from_slice(&chk);
    let handle = ContentHandle(handle);
    (content_key(&handle), blob, handle)
}

/// The DHT key of the content a handle names.
pub fn content_key(handle: &ContentHandle) -> DhtId {
    content_key_of_chk(&handle.0[32..])
}

/// The only DHT key `blob` may be stored at as content.
pub fn content_key_of_blob(blob: &[u8]) -> DhtId {
    content_key_of_chk(blake3::hash(blob).as_bytes())
}

fn content_key_of_chk(chk: &[u8]) -> DhtId {
    let mut input = Vec::with_capacity(21 + 32);
    input.extend_from_slice(b"tarnet content key v2");
    input.extend_from_slice(chk);
    DhtId(hash_64(&input))
}

/// Content-addressed GET: check the blob against the handle and decrypt it.
pub fn content_address_get(handle: &ContentHandle, blob: &[u8]) -> Result<Vec<u8>> {
    let handle = handle.as_bytes();
    if blake3::hash(blob).as_bytes()[..] != handle[32..] {
        return Err(crate::types::Error::Crypto("content blob does not match its handle".into()));
    }
    if blob.len() < 24 + 16 {
        return Err(crate::types::Error::Wire("content blob too short".into()));
    }
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&handle[..32]);
    let plaintext = XChaCha20Poly1305::new((&enc_key).into())
        .decrypt(
            blob[..24].into(),
            Payload {
                msg: &blob[24..],
                aad: b"",
            },
        )
        .map_err(|_| crate::types::Error::Crypto("content AEAD decryption failed".into()))?;
    if blake3::derive_key("tarnet content v2 encryption key", &plaintext) != enc_key {
        return Err(crate::types::Error::Crypto("content handle does not match its plaintext".into()));
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
    /// Store a record as one a neighbour delivered (ours are never evicted).
    fn put(store: &mut DhtStore, record: DhtRecord) {
        store.put_from(VerifiedRecord::locally_trusted(record), RecordSource::Peer(PeerId([0xEE; 32])));
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
        signed_record_expiring(kp, key, record_type, sequence, value, expires_in(Duration::from_secs(600)))
    }

    fn signed_record_expiring(
        kp: &Keypair,
        key: DhtId,
        record_type: RecordType,
        sequence: u64,
        value: Vec<u8>,
        expires: Instant,
    ) -> DhtRecord {
        let signature = kp.sign(&record_signable(key.as_bytes(), record_type, sequence, &value));
        DhtRecord {
            key,
            record_type,
            sequence,
            signer: kp.peer_id(),
            signer_algo: kp.identity.signing.algo() as u8,
            signer_pubkey: kp.identity.signing.signing_pubkey_bytes(),
            value,
            expires,
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
        rec.signer = victim.peer_id();
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("not signed by its signer")
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
            signer: PeerId([i; 32]),
            signer_algo: 1,
            signer_pubkey: vec![],
            value: vec![i; 8],
            expires: expires_in(Duration::from_secs(600)),
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
    fn byte_limits_count_the_whole_record() {
        // Everything a record holds counts, signer key included (a hybrid
        // post-quantum key is most of a small record).
        let kp = Keypair::generate();
        let rec = signed_record(&kp, DhtId([0x61; 64]), RecordType::SignedContent, 1, b"v".to_vec());
        let pk = rec.signer_pubkey.len();
        let stored = StoredRecord::new(rec.clone(), RecordSource::Local);
        assert!(stored.cost >= pk + rec.signature.len() + rec.value.len() + 64);

        let limits = StorageLimits {
            max_total_bytes: stored.cost * 3,
            ..StorageLimits::default()
        };
        let mut store = DhtStore::with_limits(&PeerId([0; 32]), limits);
        for i in 0..10u8 {
            let r = signed_record(&kp, DhtId([i; 64]), RecordType::SignedContent, 1, b"v".to_vec());
            store.put_from(VerifiedRecord::verify_incoming(r).unwrap(), RecordSource::Peer(PeerId([7; 32])));
        }
        // Falcon signatures vary in length: two or three fit.
        assert!((2..=3).contains(&store.record_count()), "{} records", store.record_count());
        assert!(store.total_bytes() <= limits.max_total_bytes);
    }

    #[test]
    fn content_is_accepted_only_at_its_own_key() {
        // Self-certifying content: a storing node checks the blob against
        // the key, so junk can't sit at someone's content key and compete.
        let (genuine, handle) = VerifiedRecord::new_content(b"the real thing", Duration::from_secs(600));
        let key = genuine.record().key;
        assert_eq!(key, content_key(&handle));
        assert!(VerifiedRecord::verify_incoming(genuine.record().clone()).is_ok());
        let mut junk = genuine.record().clone();
        junk.value = vec![7; 48];
        assert!(VerifiedRecord::verify_incoming(junk).is_err());

        let mut store = DhtStore::new(&PeerId([1; 32]));
        assert!(store.put(genuine.clone()));
        assert!(store.put(genuine.clone()), "repeat of the one valid blob refused");
        assert_eq!(store.get(&key).len(), 1);
    }

    #[test]
    fn content_blob_is_deterministic() {
        let (k1, b1, h1) = content_address_put(b"same bytes");
        let (k2, b2, h2) = content_address_put(b"same bytes");
        assert_eq!((k1, &b1, h1), (k2, &b2, h2));
        assert_eq!(content_address_get(&h1, &b1).unwrap(), b"same bytes");
    }

    #[test]
    fn wire_ttl_is_clamped_per_type() {
        // The TTL is unsigned: whatever a sender claims, a hello lives at most
        // MAX_HELLO_TTL here, and minting clamps too.
        let kp = Keypair::generate();
        let key = identity_address_key(&kp.peer_id());
        let rec = signed_record(&kp, key, RecordType::Hello, 1, b"h".to_vec());
        let mut put = rec.to_put_msg();
        put.ttl = u32::MAX;
        let got = VerifiedRecord::from_put_msg(&put).unwrap();
        assert!(got.record().remaining_ttl() <= MAX_HELLO_TTL);
        assert_eq!(clamp_ttl_secs(RecordType::ZoneRoot, u32::MAX), crate::tns::ZONE_ROOT_TTL);
        assert_eq!(clamp_ttl_secs(RecordType::SignedContent, u32::MAX), MAX_RECORD_TTL.as_secs() as u32);
        let minted = VerifiedRecord::new_hello(&kp, b"h", 2, Duration::from_secs(u32::MAX as u64));
        assert!(minted.record().remaining_ttl() <= MAX_HELLO_TTL);
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
            Some("not signed by its signer")
        );
    }

    #[test]
    fn verify_incoming_rejects_tampered_sequence() {
        let kp = Keypair::generate();
        let mut rec = signed_record(&kp, DhtId([0x05; 64]), RecordType::SignedContent, 1, b"v".to_vec());
        rec.sequence = 999; // signable includes the sequence, so the sig breaks
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("not signed by its signer")
        );
    }

    #[test]
    fn verify_incoming_rejects_unknown_algo() {
        let kp = Keypair::generate();
        let mut rec = signed_record(&kp, DhtId([0x06; 64]), RecordType::SignedContent, 1, b"v".to_vec());
        rec.signer_algo = 0xFF;
        assert_eq!(
            VerifiedRecord::verify_incoming(rec).err(),
            Some("not signed by its signer")
        );
    }

    #[test]
    fn unsigned_content_needs_no_signature_but_its_own_key() {
        let (rec, _) = VerifiedRecord::new_content(b"blob", Duration::from_secs(60));
        let rec = rec.into_inner();
        assert!(rec.signature.is_empty() && rec.signer_pubkey.is_empty());
        assert!(VerifiedRecord::verify_incoming(rec.clone()).is_ok());
        let mut elsewhere = rec;
        elsewhere.key = DhtId([0x07; 64]);
        assert!(VerifiedRecord::verify_incoming(elsewhere).is_err());
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
            expires: expires_in(clamp_ttl(resp.record_type, resp.ttl)),
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
    fn to_put_msg_carries_the_remaining_ttl() {
        // Relays and republishes carry what is left, so a record ages toward
        // one deadline however often it is passed on.
        let kp = Keypair::generate();
        let rec = signed_record_expiring(
            &kp,
            DhtId([0x0C; 64]),
            RecordType::SignedContent,
            1,
            b"v".to_vec(),
            expires_in(Duration::from_secs(40)),
        );
        let put = rec.to_put_msg();
        assert!((38..=40).contains(&put.ttl), "carried {}s", put.ttl);
    }

    #[test]
    fn a_record_that_expired_here_is_not_stored_again() {
        // A replay (or a slow relay) of a record that died here carries a TTL
        // nobody can check; the store refuses it unless the owner signed a
        // higher sequence.
        let kp = Keypair::generate();
        let key = DhtId([0x0D; 64]);
        let mut store = DhtStore::new(&PeerId([0u8; 32]));
        let short = signed_record_expiring(
            &kp,
            key,
            RecordType::SignedContent,
            3,
            b"v".to_vec(),
            expires_in(Duration::from_millis(20)),
        );
        assert!(store.put(VerifiedRecord::locally_trusted(short)));
        std::thread::sleep(Duration::from_millis(30));
        store.expire();
        assert!(store.get(&key).is_empty());

        let replay = signed_record(&kp, key, RecordType::SignedContent, 3, b"v".to_vec());
        assert!(!store.put(VerifiedRecord::verify_incoming(replay).unwrap()));
        let older = signed_record(&kp, key, RecordType::SignedContent, 2, b"v".to_vec());
        assert!(!store.put(VerifiedRecord::verify_incoming(older).unwrap()));
        let newer = signed_record(&kp, key, RecordType::SignedContent, 4, b"v'".to_vec());
        assert!(store.put(VerifiedRecord::verify_incoming(newer).unwrap()));

        // Unsigned content has no sequence to raise, so it isn't remembered:
        // its owner can publish it again.
        let (content, _) = VerifiedRecord::new_content(b"blob", Duration::from_millis(20));
        assert!(store.put(content));
        std::thread::sleep(Duration::from_millis(30));
        store.expire();
        let (again, _) = VerifiedRecord::new_content(b"blob", Duration::from_secs(600));
        assert!(store.put(again));
    }

    #[test]
    fn content_address_roundtrip() {
        let data = b"hello content-addressed DHT";
        let (key, blob, handle) = content_address_put(data);
        // The key follows from the blob alone (what a storing node checks)
        // and from the handle (what a reader has).
        assert_eq!(key, content_key_of_blob(&blob));
        assert_eq!(key, content_key(&handle));
        assert_eq!(content_address_get(&handle, &blob).unwrap(), data);
    }

    #[test]
    fn content_address_wrong_handle() {
        let (_key, blob, handle) = content_address_put(b"secret data");
        assert!(content_address_get(&ContentHandle([0u8; 64]), &blob).is_err());
        // Right blob hash, wrong decryption key.
        let mut wrong = handle;
        wrong.0[0] ^= 1;
        assert!(content_address_get(&wrong, &blob).is_err());
        // A blob that isn't the one the handle names.
        let (_, other, _) = content_address_put(b"other data");
        assert!(content_address_get(&handle, &other).is_err());
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
            signer: PeerId([0u8; 32]),
            value: vec![1, 2, 3],
            expires: expires_in(Duration::from_secs(0)), // already expired
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
        let signer = PeerId([0x11; 32]);

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Hello,
            sequence: 1,
            signer,
            value: b"old hello".to_vec(),
            expires: expires_in(Duration::from_secs(600)),
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
            expires: expires_in(Duration::from_secs(600)),
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
        let signer = PeerId([0x22; 32]);

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Hello,
            sequence: 10,
            signer,
            value: b"current".to_vec(),
            expires: expires_in(Duration::from_secs(600)),
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
            expires: expires_in(Duration::from_secs(600)),
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
            signer: PeerId([0x11; 32]),
            value: b"from signer A".to_vec(),
            expires: expires_in(Duration::from_secs(3600)),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 0,
            signer: PeerId([0x22; 32]),
            value: b"from signer B".to_vec(),
            expires: expires_in(Duration::from_secs(3600)),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 2);
    }

    #[test]
    fn signed_content_same_signer_replaced_only_by_higher_sequence() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xDD; 64]);
        let signer = PeerId([0x33; 32]);

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 0,
            signer,
            value: b"version 1".to_vec(),
            expires: expires_in(Duration::from_secs(3600)),
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
            expires: expires_in(Duration::from_secs(3600)),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        // Equal sequence: the copy held is kept.
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"version 1");
        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 1,
            signer,
            value: b"version 3".to_vec(),
            expires: expires_in(Duration::from_secs(3600)),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        assert_eq!(store.get(&key).len(), 1);
        assert_eq!(store.get(&key)[0].value, b"version 3");
    }

    #[test]
    fn signed_content_lower_sequence_ignored() {
        let peer = PeerId([1u8; 32]);
        let mut store = DhtStore::new(&peer);
        let key = DhtId([0xDD; 64]);
        let signer = PeerId([0x44; 32]);

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 10,
            signer,
            value: b"current".to_vec(),
            expires: expires_in(Duration::from_secs(3600)),
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
            expires: expires_in(Duration::from_secs(3600)),
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
        let signer = PeerId([0x55; 32]);

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence: 1,
            signer,
            value: b"old".to_vec(),
            expires: expires_in(Duration::from_secs(3600)),
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
            expires: expires_in(Duration::from_secs(3600)),
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
        let (key1, blob1, _) = content_address_put(topic);
        let (key2, blob2, _) = content_address_put(topic);

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
            signer: PeerId([0x11; 32]),
            value: blob1.clone(),
            expires: expires_in(Duration::from_secs(600)),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });
        put(&mut store, DhtRecord {
            key: key1,
            record_type: RecordType::SignedContent,
            sequence: 1,
            signer: PeerId([0x22; 32]),
            value: blob2.clone(),
            expires: expires_in(Duration::from_secs(600)),
            stored_at: Instant::now(),
            signer_algo: 1,
            signer_pubkey: vec![],
            signature: vec![0u8; 64],
        });

        // Both stored (different signers)
        let records = store.get(&key1);
        assert_eq!(records.len(), 2);

        // Both decrypt correctly with the handle
        let (_, _, handle) = content_address_put(topic);
        for record in records {
            let plaintext = content_address_get(&handle, &record.value).unwrap();
            assert_eq!(plaintext, topic);
        }

        // Garbage blob at same key fails
        let garbage = vec![0xDEu8; 100];
        assert!(content_address_get(&handle, &garbage).is_err());
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
        let signer = PeerId([0x11; 32]);

        put(&mut store, DhtRecord {
            key,
            record_type: RecordType::Unknown(7),
            sequence: 1,
            signer,
            value: b"unknown v1".to_vec(),
            expires: expires_in(Duration::from_secs(600)),
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
            expires: expires_in(Duration::from_secs(600)),
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
    fn watchers_are_notified_only_of_news() {
        let mut table = DhtWatchTable::new();
        let key = [0xAB; 64];
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(table.set_watch(key, a, PeerId([3; 32]), 60));
        let (signer, other) = ([7u8; 32], [8u8; 32]);
        assert_eq!(table.watchers_for_news(&key, &signer, 5).len(), 1);
        // A republish of the same record, or an older one: nothing.
        assert!(table.watchers_for_news(&key, &signer, 5).is_empty());
        assert!(table.watchers_for_news(&key, &signer, 4).is_empty());
        // Newer, or another signer: news.
        assert_eq!(table.watchers_for_news(&key, &signer, 6).len(), 1);
        assert_eq!(table.watchers_for_news(&key, &other, 1).len(), 1);
        // A refreshed watch keeps what it was told; a new watcher hears it.
        assert!(table.set_watch(key, a, PeerId([3; 32]), 60));
        assert!(table.set_watch(key, b, PeerId([4; 32]), 60));
        let news = table.watchers_for_news(&key, &signer, 6);
        assert_eq!(news, vec![(b, PeerId([4; 32]))]);
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
            next: None,
            expires_at: Instant::now() - Duration::from_secs(1),
            notified: HashMap::new(),
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

    #[test]
    fn only_a_newer_version_is_news() {
        // What watchers hear of is decided by the store, in the same step
        // that stores: a replayed older sequence is neither stored nor news,
        // an equal one (a republish) is held but not news, a newer one is.
        let kp = Keypair::generate();
        let key = DhtId([0x70; 64]);
        let mut store = DhtStore::new(&PeerId([0u8; 32]));
        let put = |store: &mut DhtStore, seq: u64| {
            let r = signed_record(&kp, key, RecordType::SignedContent, seq, format!("v{}", seq).into_bytes());
            store.put_record(VerifiedRecord::verify_incoming(r).unwrap(), RecordSource::Peer(PeerId([7; 32])))
        };
        assert_eq!(put(&mut store, 5), PutOutcome { stored: true, news: true });
        assert_eq!(put(&mut store, 3), PutOutcome { stored: false, news: false });
        assert_eq!(put(&mut store, 5), PutOutcome { stored: true, news: false });
        assert_eq!(put(&mut store, 6), PutOutcome { stored: true, news: true });
    }

    #[test]
    fn equal_seq_copy_changes_nothing() {
        // The same signed record again (republish or replay) leaves the copy
        // held as it is; a higher sequence brings the owner's new deadline.
        let kp = Keypair::generate();
        let key = DhtId([0x72; 64]);
        let mut store = DhtStore::new(&PeerId([0u8; 32]));
        let first = signed_record_expiring(&kp, key, RecordType::SignedContent, 4, b"v4".to_vec(), expires_in(Duration::from_secs(60)));
        store.put(VerifiedRecord::verify_incoming(first.clone()).unwrap());
        let outcome = store.put_record(VerifiedRecord::verify_incoming(first.clone()).unwrap(), RecordSource::Local);
        assert!(outcome.stored);
        assert!(!outcome.news);
        assert_eq!(store.get(&key)[0].expires, first.expires);

        let newer = signed_record_expiring(&kp, key, RecordType::SignedContent, 5, b"v5".to_vec(), expires_in(Duration::from_secs(3600)));
        store.put(VerifiedRecord::verify_incoming(newer.clone()).unwrap());
        assert_eq!(store.get(&key)[0].expires, newer.expires);
    }

    #[test]
    fn unknown_record_types_are_signature_checked() {
        let kp = Keypair::generate();
        let key = DhtId([0x73; 64]);
        let genuine = signed_record(&kp, key, RecordType::Unknown(42), 1, b"future".to_vec());
        assert!(VerifiedRecord::verify_incoming(genuine.clone()).is_ok());

        // Forged sequence: the signature no longer covers it.
        let mut forged = genuine.clone();
        forged.sequence = u64::MAX;
        assert!(VerifiedRecord::verify_incoming(forged).is_err());
        // Spoofed signer: the pubkey doesn't hash to it.
        let mut spoofed = genuine.clone();
        spoofed.signer = PeerId([0x99; 32]);
        assert!(VerifiedRecord::verify_incoming(spoofed).is_err());
        // No signature material at all.
        let mut bare = genuine;
        bare.signer_pubkey.clear();
        bare.signature.clear();
        assert!(VerifiedRecord::verify_incoming(bare).is_err());
    }

    #[test]
    fn a_record_evicted_on_arrival_is_not_stored() {
        // A key holding its owner's hello, one record per key: the hello is
        // never evicted for other records, so a newcomer is evicted at once
        // and must not count as stored (nor be persisted).
        let limits = StorageLimits {
            max_records_per_key: 1,
            ..StorageLimits::default()
        };
        let mut store = DhtStore::with_limits(&PeerId([0u8; 32]), limits);
        let owner = Keypair::generate();
        let key = identity_address_key(&owner.peer_id());
        let hello = signed_record(&owner, key, RecordType::Hello, 1, b"hello".to_vec());
        assert!(store.put(VerifiedRecord::verify_incoming(hello).unwrap()));

        let other = Keypair::generate();
        let rec = signed_record(&other, key, RecordType::SignedContent, 1, b"junk".to_vec());
        let outcome = store.put_record(
            VerifiedRecord::verify_incoming(rec).unwrap(),
            RecordSource::Peer(PeerId([7; 32])),
        );
        assert!(!outcome.stored);
        assert!(!outcome.news);
        assert_eq!(store.get(&key).len(), 1);
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
            signer: PeerId([0u8; 32]),
            value: vec![0x55; 32],
            expires: expires_in(Duration::from_secs(60)),
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
                signer: PeerId([i; 32]),
                value: vec![i; 8],
                expires: expires_in(Duration::from_secs(60)),
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
