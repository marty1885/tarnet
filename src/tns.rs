//! TNS: Tarnet Name System — decentralized, anonymous, private name resolution.
//!
//! Names resolve relative to a zone's ServiceId (BLAKE3 hash of signing
//! pubkey). Each zone is a keypair. Records are encrypted so only the
//! resolver who knows the zone and label can look up and decrypt. Delegation
//! chains allow multi-zone name resolution (like DNS delegation but
//! cryptographic).
//!
//! No global root, no central authority, no squatting.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use futures_util::StreamExt;
use rand::RngCore;

use crate::identity::Keypair;
use crate::node::Node;
use crate::types::{DhtId, Error, PeerId, RecordType, Result};
use tarnet_api::types::ServiceId;

pub(crate) mod publication;

/// Re-export TnsRecord from the API crate (canonical definition).
pub use tarnet_api::service::TnsRecord;
/// Re-export TnsResolution from the API crate (canonical definition).
pub use tarnet_api::service::TnsResolution;

/// Maximum delegation/redirect hops before giving up.
pub const MAX_DELEGATION_DEPTH: usize = 16;
/// How long to wait for a single DHT lookup step.
const PER_STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for the entire resolution chain.
const TOTAL_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(30);
/// Negative cache TTL: how long to remember "name not found".
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
/// Maximum entries in the TNS cache.
const TNS_CACHE_MAX_ENTRIES: usize = 1024;

// ── Resolution Cache ──

/// Cached TNS resolution result with TTL tracking.
struct TnsCacheEntry {
    records: Vec<TnsRecord>,
    /// When this entry was cached.
    cached_at: Instant,
    /// How long this entry is valid (remaining TTL from DHT record).
    ttl: Duration,
}

impl TnsCacheEntry {
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.cached_at.elapsed())
    }
}

/// TTL-aware cache for TNS resolutions. Keyed by (zone, label).
/// Caches both positive results (records found) and negative results
/// (name not found) to avoid repeated DHT queries.
pub struct TnsCache {
    entries: HashMap<(ServiceId, String), TnsCacheEntry>,
    public_keys: HashMap<ServiceId, Vec<u8>>,
    versions: HashMap<(ServiceId, String), (u64, Instant)>,
}

impl TnsCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            public_keys: HashMap::new(),
            versions: HashMap::new(),
        }
    }

    /// Look up a cached result. Returns None if not cached or expired.
    pub fn get(&mut self, zone: &ServiceId, label: &str) -> Option<&Vec<TnsRecord>> {
        let key = (*zone, label.to_string());
        // Check expiry and remove if stale.
        if let Some(entry) = self.entries.get(&key) {
            if entry.is_expired() {
                self.entries.remove(&key);
                return None;
            }
        }
        self.entries.get(&key).map(|e| &e.records)
    }

    /// Insert a positive cache entry with TTL derived from the DHT record.
    pub fn insert(
        &mut self,
        zone: ServiceId,
        label: String,
        records: Vec<TnsRecord>,
        ttl: Duration,
    ) {
        self.evict_expired();
        if self.entries.len() >= TNS_CACHE_MAX_ENTRIES {
            // Evict the entry with the least remaining TTL.
            let worst = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.remaining_ttl())
                .map(|(k, _)| k.clone());
            if let Some(k) = worst {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(
            (zone, label),
            TnsCacheEntry {
                records,
                cached_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Forget what is cached for `label` in `zone` (it proved stale).
    pub fn forget(&mut self, zone: &ServiceId, label: &str) {
        self.entries.remove(&(*zone, label.to_string()));
    }

    /// Insert a negative cache entry (name not found).
    pub fn insert_negative(&mut self, zone: ServiceId, label: String) {
        self.insert(zone, label, Vec::new(), NEGATIVE_CACHE_TTL);
    }

    /// Remove expired entries.
    fn evict_expired(&mut self) {
        self.entries.retain(|_, e| !e.is_expired());
    }

    fn public_key(&self, sid: &ServiceId) -> Option<Vec<u8>> {
        self.public_keys.get(sid).cloned()
    }

    fn remember_public_key(&mut self, sid: ServiceId, pk: Vec<u8>) {
        if self.public_keys.len() >= TNS_CACHE_MAX_ENTRIES && !self.public_keys.contains_key(&sid) {
            if let Some(old) = self.public_keys.keys().next().copied() {
                self.public_keys.remove(&old);
            }
        }
        self.public_keys.insert(sid, pk);
    }

    /// Only called after full identity verification. Keep the floor after
    /// the answer expires; bounded eviction can eventually forget it.
    fn accept_version(&mut self, sid: ServiceId, label: &str, sequence: u64) -> bool {
        let key = (sid, label.to_string());
        if let Some((floor, _)) = self.versions.get(&key) {
            if sequence < *floor {
                return false;
            }
            if sequence == *floor {
                return true;
            }
        }
        if self.versions.len() >= TNS_CACHE_MAX_ENTRIES && !self.versions.contains_key(&key) {
            if let Some(old) = self
                .versions
                .iter()
                .min_by_key(|(_, (_, when))| *when)
                .map(|(k, _)| k.clone())
            {
                self.versions.remove(&old);
            }
        }
        self.entries.remove(&key);
        self.versions.insert(key, (sequence, Instant::now()));
        true
    }
}
/// Context string for record encryption key derivation.
const TNS_RECORD_ENC_LABEL: &str = "tarnet tns record enc";
/// Domain separator for the inner master signature that authenticates a record
/// set to its namespace owner.
const TNS_RECORD_DOMAIN: &[u8] = b"tarnet tns record v1";
/// Version byte for the authenticity bundle wire format.
const TNS_BUNDLE_VERSION: u8 = 1;
const TNS_TAG_SIZE: usize = 16;

// Wire tags
const TAG_IDENTITY: u8 = 0;
const TAG_ZONE: u8 = 1;
const TAG_CONTENT_REF: u8 = 2;
const TAG_TEXT: u8 = 3;
const TAG_ALIAS: u8 = 4;
const TAG_INTRO_POINT: u8 = 6;
const TAG_PEER: u8 = 7;
const TAG_SERVICE: u8 = 8;
const TAG_VHOST: u8 = 9;

fn encode_length_prefixed_string(buf: &mut Vec<u8>, tag: u8, s: &str) {
    buf.push(tag);
    let b = s.as_bytes();
    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
    buf.extend_from_slice(b);
}

fn decode_length_prefixed_string(rest: &[u8]) -> Result<(String, usize)> {
    if rest.len() < 2 {
        return Err(Error::Wire("truncated string".into()));
    }
    let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + len {
        return Err(Error::Wire("truncated string data".into()));
    }
    let s = String::from_utf8(rest[2..2 + len].to_vec())
        .map_err(|_| Error::Wire("invalid UTF-8".into()))?;
    Ok((s, 2 + len))
}

pub fn tns_record_to_bytes(record: &TnsRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    match record {
        TnsRecord::Identity(sid) => {
            buf.push(TAG_IDENTITY);
            buf.extend_from_slice(sid.as_bytes());
        }
        TnsRecord::Zone(sid) => {
            buf.push(TAG_ZONE);
            buf.extend_from_slice(sid.as_bytes());
        }
        TnsRecord::VHost(sid) => {
            buf.push(TAG_VHOST);
            buf.extend_from_slice(sid.as_bytes());
        }
        TnsRecord::ContentRef(hash) => {
            buf.push(TAG_CONTENT_REF);
            buf.extend_from_slice(hash);
        }
        TnsRecord::Text(s) => {
            encode_length_prefixed_string(&mut buf, TAG_TEXT, s);
        }
        TnsRecord::Alias(s) => {
            encode_length_prefixed_string(&mut buf, TAG_ALIAS, s);
        }
        TnsRecord::IntroductionPoint {
            relay_peer_id,
            kem_algo,
            kem_pubkey,
        } => {
            buf.push(TAG_INTRO_POINT);
            buf.extend_from_slice(relay_peer_id.as_bytes());
            buf.push(*kem_algo);
            let pk_len = kem_pubkey.len() as u16;
            buf.extend_from_slice(&pk_len.to_be_bytes());
            buf.extend_from_slice(kem_pubkey);
        }
        TnsRecord::Peer {
            signing_algo,
            signing_pubkey,
            peer_id,
            signature,
        } => {
            buf.push(TAG_PEER);
            buf.push(*signing_algo);
            let pk_len = signing_pubkey.len() as u16;
            buf.extend_from_slice(&pk_len.to_be_bytes());
            buf.extend_from_slice(signing_pubkey);
            buf.extend_from_slice(peer_id.as_bytes());
            let sig_len = signature.len() as u16;
            buf.extend_from_slice(&sig_len.to_be_bytes());
            buf.extend_from_slice(signature);
        }
        TnsRecord::Service { port, weight, meta } => {
            buf.push(TAG_SERVICE);
            let port_b = port.as_bytes();
            buf.extend_from_slice(&(port_b.len() as u16).to_be_bytes());
            buf.extend_from_slice(port_b);
            buf.extend_from_slice(&weight.to_be_bytes());
            buf.extend_from_slice(&(meta.len() as u16).to_be_bytes());
            buf.extend_from_slice(meta);
        }
    }
    buf
}

pub fn tns_record_from_bytes(data: &[u8]) -> Result<(TnsRecord, usize)> {
    if data.is_empty() {
        return Err(Error::Wire("TNSrecord: empty".into()));
    }
    let tag = data[0];
    let rest = &data[1..];
    match tag {
        TAG_IDENTITY => {
            if rest.len() < 32 {
                return Err(Error::Wire("TNSIdentity: too short".into()));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&rest[..32]);
            Ok((TnsRecord::Identity(ServiceId(id)), 1 + 32))
        }
        TAG_ZONE => {
            if rest.len() < 32 {
                return Err(Error::Wire("TNSZone: too short".into()));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&rest[..32]);
            Ok((TnsRecord::Zone(ServiceId(id)), 1 + 32))
        }
        TAG_VHOST => {
            if rest.len() < 32 {
                return Err(Error::Wire("TNSVHost: too short".into()));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&rest[..32]);
            Ok((TnsRecord::VHost(ServiceId(id)), 1 + 32))
        }
        TAG_CONTENT_REF => {
            if rest.len() < 64 {
                return Err(Error::Wire("TNSContentRef: too short".into()));
            }
            let mut hash = [0u8; 64];
            hash.copy_from_slice(&rest[..64]);
            Ok((TnsRecord::ContentRef(hash), 1 + 64))
        }
        TAG_TEXT => {
            let (s, consumed) = decode_length_prefixed_string(rest)?;
            Ok((TnsRecord::Text(s), 1 + consumed))
        }
        TAG_ALIAS => {
            let (s, consumed) = decode_length_prefixed_string(rest)?;
            Ok((TnsRecord::Alias(s), 1 + consumed))
        }
        TAG_INTRO_POINT => {
            if rest.len() < 32 + 1 + 2 {
                return Err(Error::Wire("TNSIntroPoint: too short".into()));
            }
            let mut relay = [0u8; 32];
            relay.copy_from_slice(&rest[..32]);
            let kem_algo = rest[32];
            let pk_len = u16::from_be_bytes([rest[33], rest[34]]) as usize;
            if rest.len() < 32 + 1 + 2 + pk_len {
                return Err(Error::Wire("TNSIntroPoint: KEM pubkey truncated".into()));
            }
            let kem_pubkey = rest[35..35 + pk_len].to_vec();
            Ok((
                TnsRecord::IntroductionPoint {
                    relay_peer_id: PeerId(relay),
                    kem_algo,
                    kem_pubkey,
                },
                1 + 32 + 1 + 2 + pk_len,
            ))
        }
        TAG_PEER => {
            // signing_algo(1) || pk_len(2) || signing_pubkey(pk_len) || peer_id(32) || sig_len(2) || signature(sig_len)
            if rest.len() < 1 + 2 {
                return Err(Error::Wire("TNSPeer: too short".into()));
            }
            let signing_algo = rest[0];
            let pk_len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
            let min = 1 + 2 + pk_len + 32 + 2;
            if rest.len() < min {
                return Err(Error::Wire("TNSPeer: signing pubkey truncated".into()));
            }
            let signing_pubkey = rest[3..3 + pk_len].to_vec();
            let offset = 3 + pk_len;
            let mut peer_id = [0u8; 32];
            peer_id.copy_from_slice(&rest[offset..offset + 32]);
            let sig_offset = offset + 32;
            if rest.len() < sig_offset + 2 {
                return Err(Error::Wire("TNSPeer: sig_len truncated".into()));
            }
            let sig_len = u16::from_be_bytes([rest[sig_offset], rest[sig_offset + 1]]) as usize;
            let sig_start = sig_offset + 2;
            if rest.len() < sig_start + sig_len {
                return Err(Error::Wire("TNSPeer: signature truncated".into()));
            }
            let signature = rest[sig_start..sig_start + sig_len].to_vec();
            let total = 1 + 1 + 2 + pk_len + 32 + 2 + sig_len;
            Ok((
                TnsRecord::Peer {
                    signing_algo,
                    signing_pubkey,
                    peer_id: PeerId(peer_id),
                    signature,
                },
                total,
            ))
        }
        TAG_SERVICE => {
            // port_len(2) || port(utf8) || weight(2) || meta_len(2) || meta
            if rest.len() < 2 {
                return Err(Error::Wire("TNSService: too short".into()));
            }
            let port_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if rest.len() < 2 + port_len + 2 + 2 {
                return Err(Error::Wire("TNSService: port truncated".into()));
            }
            let port = String::from_utf8(rest[2..2 + port_len].to_vec())
                .map_err(|_| Error::Wire("TNSService: invalid UTF-8 port".into()))?;
            let mut off = 2 + port_len;
            let weight = u16::from_be_bytes([rest[off], rest[off + 1]]);
            off += 2;
            let meta_len = u16::from_be_bytes([rest[off], rest[off + 1]]) as usize;
            off += 2;
            if rest.len() < off + meta_len {
                return Err(Error::Wire("TNSService: meta truncated".into()));
            }
            let meta = rest[off..off + meta_len].to_vec();
            Ok((
                TnsRecord::Service { port, weight, meta },
                1 + off + meta_len,
            ))
        }
        _ => Err(Error::Wire(format!("TNSrecord: unknown tag {}", tag))),
    }
}

// ── Record Set Serialization ──

/// Serialize a record set: u16 count || record_1 || record_2 || ...
pub fn serialize_record_set(records: &[TnsRecord]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for record in records {
        buf.extend_from_slice(&tns_record_to_bytes(record));
    }
    buf
}

/// Deserialize a record set.
pub fn deserialize_record_set(data: &[u8]) -> Result<Vec<TnsRecord>> {
    if data.len() < 2 {
        return Err(Error::Wire("TNSrecord set: too short".into()));
    }
    let count = u16::from_be_bytes([data[0], data[1]]) as usize;
    // Cap by the bytes present, not the claimed count (each record is >= 1 byte).
    let mut records = Vec::with_capacity(count.min(data.len() - 2));
    let mut offset = 2;
    for _ in 0..count {
        let (record, consumed) = tns_record_from_bytes(&data[offset..])?;
        records.push(record);
        offset += consumed;
    }
    Ok(records)
}

// ── Key Derivation ──

/// Legacy shared-namespace lookup used by closed resource pools.
/// Published TNS labels use `label_lookup_keys` and blinded keys instead.
pub fn tns_dht_key(zone: &ServiceId, label: &str) -> DhtId {
    let mut out = [0u8; 64];
    blake3::Hasher::new()
        .update(zone.as_bytes())
        .update(label.as_bytes())
        .finalize_xof()
        .fill(&mut out);
    DhtId(out)
}

/// Derive a 256-bit key from a context string, zone public key, and label.
fn derive_tns_key(context: &str, zone: &ServiceId, label: &str) -> [u8; 32] {
    blake3::derive_key(context, &{
        let mut buf = Vec::with_capacity(32 + label.len());
        buf.extend_from_slice(zone.as_bytes());
        buf.extend_from_slice(label.as_bytes());
        buf
    })
}

/// Legacy shared-namespace encryption key used by resource pools.
/// Opaque TNS publications use independent lane-bound encryption keys.
pub fn tns_encryption_key(zone: &ServiceId, label: &str) -> [u8; 32] {
    derive_tns_key(TNS_RECORD_ENC_LABEL, zone, label)
}

/// Independent lookup locations for a published label. The public key must
/// first be authenticated against its SID using the ZoneKey descriptor.
pub fn label_lookup_keys(public_key: &[u8], label: &str) -> Result<Vec<DhtId>> {
    (0..publication::LANES)
        .map(|lane| publication::label_key(public_key, label, lane).map(|(_, key)| key))
        .collect()
}

/// Derive the opaque wire port for a VHost endpoint (canonical, shared with the
/// listen side via the API crate). See [`tarnet_api::service::vhost_wire_port`].
pub use tarnet_api::service::vhost_wire_port;

/// Mint a fresh **disposable** DHT signing key for a record.
///
/// This key signs the DHT record but is NOT a trust root — authenticity is the
/// inner master signature in the bundle. Its only jobs are (a) carrying a signer
/// pubkey that reveals nothing about the zone owner and (b) preventing anyone
/// else from overwriting this record at the storage layer.
///
/// It MUST be post-quantum (default FalconEd25519 scheme): the disposable pubkey
/// is published in clear, so a non-PQ key would let a quantum adversary forge its
/// signature and overwrite the legitimate record with junk — a denial-of-
/// resolution. Falcon has no deterministic keygen from a seed, so this is random
/// per publish; republishes therefore land in new slots (bounded by TTL/LRU) and
/// readers dedup by author taking the max sequence.
pub(crate) fn disposable_record_key() -> Keypair {
    Keypair::generate()
}

// ── Confidentiality layer (seal/unseal) ──
//
// AEAD under a key derived from the *public* name (namespace + label). This hides
// the record from storage nodes and the network; it is NOT authentication —
// anyone who knows the name derives the same key. Authentication is the inner
// master signature (see the bundle layer below).

/// Seal plaintext under the name-derived key. Returns `nonce(24) || ct+tag`.
pub(crate) fn seal(namespace: &ServiceId, label: &str, plaintext: &[u8]) -> Vec<u8> {
    let enc_key = tns_encryption_key(namespace, label);
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .expect("AEAD encryption should not fail");
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob
}

/// Reverse of [`seal`].
pub(crate) fn unseal(namespace: &ServiceId, label: &str, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 + TNS_TAG_SIZE {
        return Err(Error::Wire("TNS blob too short for nonce+tag".into()));
    }
    let nonce = &blob[..24];
    let ciphertext_with_tag = &blob[24..];
    let enc_key = tns_encryption_key(namespace, label);
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext_with_tag,
                aad: b"",
            },
        )
        .map_err(|_| Error::Crypto("TNS AEAD decryption failed".into()))
}

// ── Authenticity layer (bundle) ──
//
// The bundle carries the namespace owner's master public key and a signature
// over the record set, *inside* the sealed blob. The resolver checks the
// signature to authenticate; storage nodes never see the master pubkey in clear.
// No homomorphic key-blinding is used, so this is fully PQ (the master signature
// is Falcon when the zone is PQ).

/// Canonical message the master signature covers. Binds namespace + label +
/// sequence so a record can't be replayed into another name or rolled within one.
fn bundle_signable(namespace: &ServiceId, label: &str, sequence: u64, records_ser: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(TNS_RECORD_DOMAIN.len() + 32 + 2 + label.len() + 8 + records_ser.len());
    m.extend_from_slice(TNS_RECORD_DOMAIN);
    m.extend_from_slice(namespace.as_bytes());
    m.extend_from_slice(&(label.len() as u16).to_be_bytes());
    m.extend_from_slice(label.as_bytes());
    m.extend_from_slice(&sequence.to_be_bytes());
    m.extend_from_slice(records_ser);
    m
}

/// Build the self-authenticating bundle (plaintext, before [`seal`]):
/// `ver(1) || algo(1) || pk_len(2) || master_pubkey || seq(8) || recs_len(4) ||
///  records || sig_len(2) || master_sig`.
pub(crate) fn build_bundle(
    owner: &Keypair,
    namespace: &ServiceId,
    label: &str,
    sequence: u64,
    records: &[TnsRecord],
) -> Vec<u8> {
    let records_ser = serialize_record_set(records);
    let pubkey = owner.identity.signing.signing_pubkey_bytes();
    let algo = owner.identity.signing_algo() as u8;
    let sig = owner.identity.sign(&bundle_signable(namespace, label, sequence, &records_ser));

    let mut b = Vec::with_capacity(1 + 1 + 2 + pubkey.len() + 8 + 4 + records_ser.len() + 2 + sig.len());
    b.push(TNS_BUNDLE_VERSION);
    b.push(algo);
    b.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
    b.extend_from_slice(&pubkey);
    b.extend_from_slice(&sequence.to_be_bytes());
    b.extend_from_slice(&(records_ser.len() as u32).to_be_bytes());
    b.extend_from_slice(&records_ser);
    b.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    b.extend_from_slice(&sig);
    b
}

/// Parse and verify a bundle. Returns `(records, sequence, author)` only if the
/// inner master signature is valid. When `require_owner` is true (single-owner
/// TNS zones), the author's ServiceId must equal `namespace`; pools pass false
/// (any member who knows the pool key may write, bound to the pool root).
pub(crate) fn open_bundle(
    namespace: &ServiceId,
    label: &str,
    plaintext: &[u8],
    require_owner: bool,
) -> Option<(Vec<TnsRecord>, u64, ServiceId)> {
    // ver(1) || algo(1) || pk_len(2)
    if plaintext.len() < 4 || plaintext[0] != TNS_BUNDLE_VERSION {
        return None;
    }
    let algo_byte = plaintext[1];
    let pk_len = u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize;
    let mut off = 4;
    if plaintext.len() < off + pk_len + 8 + 4 {
        return None;
    }
    let pubkey = &plaintext[off..off + pk_len];
    off += pk_len;
    let sequence = u64::from_be_bytes(plaintext[off..off + 8].try_into().ok()?);
    off += 8;
    let recs_len = u32::from_be_bytes(plaintext[off..off + 4].try_into().ok()?) as usize;
    off += 4;
    if plaintext.len() < off + recs_len + 2 {
        return None;
    }
    let records_ser = &plaintext[off..off + recs_len];
    off += recs_len;
    let sig_len = u16::from_be_bytes([plaintext[off], plaintext[off + 1]]) as usize;
    off += 2;
    if plaintext.len() < off + sig_len {
        return None;
    }
    let sig = &plaintext[off..off + sig_len];

    let signable = bundle_signable(namespace, label, sequence, records_ser);
    // The author is whoever holds the key; owners are checked below.
    if !crate::identity::verify_signed(crate::identity::SignedBy::AnyPeer, Some(algo_byte), pubkey, &signable, sig) {
        return None;
    }
    let author = ServiceId::from_signing_pubkey(pubkey);
    if require_owner && author != *namespace {
        return None;
    }
    let records = deserialize_record_set(records_ser).ok()?;
    Some((records, sequence, author))
}

// ── Resolution ──

/// Resolve a dot-separated name within a zone.
///
/// Name `a.b.c` in zone Z means: look up `c` in Z (expect Delegation to Z'),
/// then `b` in Z' (expect Delegation to Z''), then `a` in Z''.
///
/// Returns the terminal record set or a resolution error. Never hangs —
/// bounded by per-step and total timeouts plus a delegation depth limit.
pub async fn resolve(node: &Node, zone: ServiceId, name: &str) -> TnsResolution {
    match tokio::time::timeout(TOTAL_RESOLUTION_TIMEOUT, resolve_inner(node, zone, name, 0)).await
    {
        Ok(result) => result,
        Err(_) => TnsResolution::Error("total resolution timeout exceeded".into()),
    }
}

/// Resolve a name using the local node's context.
///
/// The entire name is resolved as labels in the local node's own zone.
/// Delegation records in intermediate labels are followed automatically.
///
/// Examples (assuming node identity = zone Z):
///   `server`         → look up "server" in Z
///   `www.blog`       → look up "blog" in Z (Delegation→Z'), then "www" in Z'
///   `svc.app.friend` → look up "friend" in Z (Delegation→Z'), "app" in Z', etc.
///
/// Petnames are just records in your own zone published as Delegation records.
/// There is no special petname lookup — petnames ARE zone records.
pub async fn resolve_name(node: &Node, name: &str) -> TnsResolution {
    let local_zone = node.default_service_id().await;
    resolve(node, local_zone, name).await
}

async fn resolve_inner(node: &Node, zone: ServiceId, name: &str, depth: usize) -> TnsResolution {
    if depth >= MAX_DELEGATION_DEPTH {
        return TnsResolution::Error("max delegation/redirect depth exceeded".into());
    }

    // Split into labels. "a.b.c" → resolve c first, then b, then a.
    let labels: Vec<&str> = name.split('.').rev().collect();
    if labels.is_empty() || labels.iter().any(|l| l.is_empty()) {
        return TnsResolution::Error("invalid name: empty label".into());
    }

    let mut current_zone = zone;
    let mut current_depth = depth;
    let mut label_idx = 0;

    while label_idx < labels.len() {
        if current_depth >= MAX_DELEGATION_DEPTH {
            return TnsResolution::Error("max delegation/redirect depth exceeded".into());
        }
        current_depth += 1;

        let label = labels[label_idx];
        let is_terminal = label_idx == labels.len() - 1;

        // Non-terminal labels may be a raw ServiceId (Crockford Base32
        // encoded).  This lets users address any zone directly without
        // needing a petname, e.g. `bob.<alice-service-id>`.
        // Parse-and-verify is purely local — no network, no timing attack.
        if !is_terminal {
            if let Some(zone_id) = try_parse_service_id(label) {
                current_zone = zone_id;
                label_idx += 1;
                continue;
            }
        }

        let records = fetch_records(node, &current_zone, label).await;

        if records.is_empty() {
            return TnsResolution::NotFound;
        }

        // Check for Alias — follow at both terminal and non-terminal positions.
        if let Some(alias_target) = records.iter().find_map(|r| match r {
            TnsRecord::Alias(s) => Some(s.clone()),
            _ => None,
        }) {
            // Build the remaining labels that still need resolving.
            let remaining: Vec<&str> = labels[label_idx + 1..].iter().rev().copied().collect();
            let new_name = if remaining.is_empty() {
                alias_target.clone()
            } else {
                format!("{}.{}", remaining.join("."), alias_target)
            };

            // Follow the alias in the current zone. Absolute aliases (rightmost
            // component is a raw ServiceId) are parsed naturally by resolve_inner.
            return Box::pin(resolve_inner(node, current_zone, &new_name, current_depth)).await;
        }

        if is_terminal {
            // A terminal VHost names a connectable endpoint. Surface the serving
            // SID together with the canonical label — `label`, the record's
            // authoritative position in `current_zone`, regardless of the path
            // (alias / delegation / raw-SID) the connector took to reach it.
            if let Some(serving) = records.iter().find_map(|r| match r {
                TnsRecord::VHost(sid) => Some(*sid),
                _ => None,
            }) {
                return TnsResolution::VHost {
                    serving,
                    canonical_label: label.to_string(),
                };
            }

            // If the terminal label is a Zone delegation, auto-follow into
            // that zone and resolve "@" (the apex) like any other name, so an
            // apex VHost, Alias or further delegation is honoured. This lets
            // petnames like `lacia.self` resolve to lacia's Identity record
            // published at @ by expose, mirroring how DNS follows NS
            // delegations to find apex A records.
            if let Some(zone_sid) = records.iter().find_map(|r| match r {
                TnsRecord::Zone(sid) => Some(*sid),
                _ => None,
            }) {
                return match Box::pin(resolve_inner(node, zone_sid, "@", current_depth)).await {
                    // No apex records — return the Zone records as-is.
                    TnsResolution::NotFound => TnsResolution::Records(records),
                    apex => apex,
                };
            }
            return TnsResolution::Records(records);
        }

        // Non-terminal: we need a Zone.
        // Look for Zone delegation.
        if let Some(next_zone) = records.iter().find_map(|r| match r {
            TnsRecord::Zone(sid) => Some(*sid),
            _ => None,
        }) {
            current_zone = next_zone;
            label_idx += 1;
        } else {
            return TnsResolution::Error(format!(
                "non-terminal label '{}' has no Zone or Alias",
                label
            ));
        }
    }

    TnsResolution::NotFound
}

/// The record set for a single label in a zone. For a zone we own, what we
/// hold locally is authoritative. Otherwise use the TTL cache, discover the
/// immutable public key, and search independent encrypted label lanes. Empty
/// means no authenticated positive answer, including a signed tombstone.
pub async fn lookup_label(node: &Node, zone: &ServiceId, label: &str) -> Vec<TnsRecord> {
    fetch_records(node, zone, label).await
}

async fn fetch_records(node: &Node, zone: &ServiceId, label: &str) -> Vec<TnsRecord> {
    // 1. Our own zone: local labels (published or not) and live publishers.
    if node.owns_zone(zone).await {
        return node.local_zone_label(zone, label).await.unwrap_or_default();
    }

    // 2. The TNS resolution cache.
    {
        let mut cache = node.tns_cache().lock().await;
        if let Some(cached) = cache.get(zone, label) {
            log::debug!("TNS cache hit: {:?}/{}", zone, label);
            return cached.clone();
        }
    }

    let deadline = Instant::now() + PER_STEP_TIMEOUT;
    let Some(pk) = fetch_zone_public_key(node, zone, deadline).await else {
        let mut cache = node.tns_cache().lock().await;
        if let Some(records) = cache.get(zone, label) {
            return records.clone();
        }
        cache.insert_negative(*zone, label.to_string());
        return Vec::new();
    };
    let floor = node
        .tns_cache()
        .lock()
        .await
        .versions
        .get(&(*zone, label.to_string()))
        .map_or(0, |(sequence, _)| *sequence);
    // Independent lanes are searched concurrently within ONE step budget.
    let searches = (0..publication::LANES).map(|lane| {
        let pk = &pk;
        async move {
            let (_, key) = publication::label_key(pk, label, lane).ok()?;
            let mut search = node.dht_search_tns(key, deadline).await;
            let mut best = None;
            while let Some(rec) = search.next().await {
                if let Some((records, sequence)) =
                    publication::open(zone, pk, label, lane, rec.record())
                {
                    let expires = rec.record().expires;
                    if sequence >= floor
                        && expires > Instant::now()
                        && best.as_ref().map_or(true, |(_, old, _)| sequence > *old)
                    {
                        best = Some((records, sequence, expires));
                    }
                }
                if best.is_some() && search.is_idle() {
                    break;
                }
            }
            best
        }
    });
    let mut searches: futures_util::stream::FuturesUnordered<_> = searches.collect();
    let mut best = None;
    let mut finish = deadline;
    while !searches.is_empty() {
        match tokio::time::timeout_at(finish.into(), searches.next()).await {
            Ok(Some(Some(candidate))) => {
                if best.is_none() {
                    // A missing lane cannot impose its entire timeout after
                    // another lane has supplied an authenticated answer.
                    finish = deadline.min(Instant::now() + Duration::from_millis(150));
                }
                if best
                    .as_ref()
                    .map_or(true, |(_, sequence, _)| candidate.1 > *sequence)
                {
                    best = Some(candidate);
                }
            }
            Ok(Some(None)) => {}
            _ => break,
        }
    }
    let mut cache = node.tns_cache().lock().await;
    if let Some((records, sequence, expires)) = best {
        if cache.accept_version(*zone, label, sequence) {
            let ttl = expires.saturating_duration_since(Instant::now());
            if !ttl.is_zero() {
                cache.insert(*zone, label.to_string(), records.clone(), ttl);
                return records;
            }
        }
    }
    // A concurrent successful lookup may have filled the cache while this
    // search only saw junk or an older version. Never overwrite that answer.
    if let Some(records) = cache.get(zone, label) {
        return records.clone();
    }
    cache.insert_negative(*zone, label.to_string());
    Vec::new()
}

async fn fetch_zone_public_key(
    node: &Node,
    zone: &ServiceId,
    deadline: Instant,
) -> Option<Vec<u8>> {
    if let Some(pk) = node.tns_cache().lock().await.public_key(zone) {
        return Some(pk);
    }
    let mut search = node.dht_search(crate::dht::zone_key(zone), deadline).await;
    while let Some(record) = search.next().await {
        let rec = record.record();
        if rec.record_type != RecordType::ZoneKey
            || rec.value != publication::KEY_MARKER
            || ServiceId::from_signing_pubkey(&rec.signer_pubkey) != *zone
            || crate::dht::VerifiedRecord::verify_incoming(rec.clone()).is_err()
        {
            continue;
        }
        let pk = rec.signer_pubkey.clone();
        node.tns_cache()
            .lock()
            .await
            .remember_public_key(*zone, pk.clone());
        return Some(pk);
    }
    None
}

/// Try to parse a label as a raw Crockford Base32-encoded ServiceId.
/// Returns `Some(id)` only if the decoded bytes are exactly 32 bytes.
fn try_parse_service_id(label: &str) -> Option<ServiceId> {
    use tarnet_api::types::decode_base32;
    let bytes = decode_base32(label).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(ServiceId(arr))
}

// ── Validation ──

/// Returns true if the record type is supplemental (can coexist with Zone).
fn is_supplemental(record: &TnsRecord) -> bool {
    matches!(record, TnsRecord::Text(_) | TnsRecord::ContentRef(_))
}

/// Validate an alias target string.
///
/// Valid forms:
/// - Bare label (no dots): e.g. `"@"`, `"www"` — relative to current zone
/// - Absolute: dotted name whose rightmost component is a raw Base32 ServiceId
///
/// Everything else is rejected (ambiguous multi-label without a zone anchor).
pub fn validate_alias_target(target: &str) -> Result<()> {
    if target.is_empty() {
        return Err(Error::Protocol("alias target is empty".into()));
    }
    if !target.contains('.') {
        // Bare label — always valid (relative).
        return Ok(());
    }
    // Dotted name — rightmost component must be a raw ServiceId.
    let rightmost = target.rsplit('.').next().unwrap();
    if try_parse_service_id(rightmost).is_some() {
        return Ok(());
    }
    Err(Error::Protocol(format!(
        "alias target '{}' is ambiguous: multi-label names must end with a raw ServiceId",
        target
    )))
}

/// Validate a record set for internal consistency.
///
/// Rules:
/// - Zone must be the sole non-supplemental record (GNS rule).
///   Text and ContentRef are supplemental and may coexist with Zone.
/// - VHost is likewise terminal and singular: it must be the sole
///   non-supplemental record at its label (so `Identity + VHost` — ambiguous
///   "entity or vhost?" — is rejected).
/// - Alias targets must be valid (bare label or absolute).
/// - Every length fits its u16 wire prefix, and so does the whole set (its
///   record-set length prefix), so nothing is silently truncated.
pub fn validate_records(records: &[TnsRecord]) -> Result<()> {
    if records.is_empty() {
        return Err(Error::Protocol("record set is empty".into()));
    }
    if records.len() > u16::MAX as usize {
        return Err(Error::Protocol("too many records at a label".into()));
    }
    for record in records {
        let field = match record {
            TnsRecord::Text(s) | TnsRecord::Alias(s) => s.len(),
            TnsRecord::Service { port, meta, .. } => port.len().max(meta.len()),
            TnsRecord::IntroductionPoint { kem_pubkey, .. } => kem_pubkey.len(),
            TnsRecord::Peer { signing_pubkey, signature, .. } => signing_pubkey.len().max(signature.len()),
            TnsRecord::Identity(_) | TnsRecord::Zone(_) | TnsRecord::VHost(_) | TnsRecord::ContentRef(_) => 0,
        };
        if field > u16::MAX as usize {
            return Err(Error::Protocol("record field too long".into()));
        }
    }
    if serialize_record_set(records).len() > u16::MAX as usize {
        return Err(Error::Protocol("record set too large".into()));
    }

    let has_zone = records.iter().any(|r| matches!(r, TnsRecord::Zone(_)));
    if has_zone {
        let non_supplemental_count = records.iter().filter(|r| !is_supplemental(r)).count();
        if non_supplemental_count > 1 {
            return Err(Error::Protocol(
                "Zone record must be the sole non-supplemental record at a label".into(),
            ));
        }
    }

    let has_vhost = records.iter().any(|r| matches!(r, TnsRecord::VHost(_)));
    if has_vhost {
        let non_supplemental_count = records.iter().filter(|r| !is_supplemental(r)).count();
        if non_supplemental_count > 1 {
            return Err(Error::Protocol(
                "VHost record must be the sole non-supplemental record at a label".into(),
            ));
        }
    }

    for record in records {
        if let TnsRecord::Alias(target) = record {
            validate_alias_target(target)?;
        }
    }

    Ok(())
}

/// Validate that published alias targets don't reference unpublished local labels.
///
/// Only call this when `publish=true`. Unpublished labels can alias anything.
pub fn validate_published_aliases(
    records: &[TnsRecord],
    db: &crate::state::StateDb,
    identity: &str,
) -> Result<()> {
    for record in records {
        if let TnsRecord::Alias(target) = record {
            // Only check bare labels (relative aliases within our zone).
            // Absolute aliases (with ServiceId) point outside our zone — can't validate.
            if target.contains('.') {
                continue;
            }
            // Check if the target label exists locally and is unpublished.
            if let Ok(Some((_, target_publish))) = db.label_get(identity, target) {
                if !target_publish {
                    return Err(Error::Protocol(format!(
                        "published alias target '{}' references an unpublished label",
                        target
                    )));
                }
            }
            // Target not in local store at all is fine — it may be published
            // in our zone via tns_publish directly (not through the label store).
        }
    }
    Ok(())
}

// ── Peer Record ──

/// Domain separator for peer record signatures.
const PEER_RECORD_DOMAIN: &[u8] = b"tarnet peer record";

/// Canonical bytes a Peer record's signature covers: `domain || peer_id`.
/// Single source of truth shared by [`build_peer_record`] (signing) and
/// [`verify_peer_record`] (verifying), so the layout can never drift between
/// the two sides.
fn peer_record_signable(peer_id: &PeerId) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PEER_RECORD_DOMAIN.len() + 32);
    msg.extend_from_slice(PEER_RECORD_DOMAIN);
    msg.extend_from_slice(peer_id.as_bytes());
    msg
}

/// Build a signed Peer record for a public service.
pub fn build_peer_record(keypair: &Keypair, peer_id: &PeerId) -> TnsRecord {
    let signing_algo = keypair.identity.signing_algo() as u8;
    let signing_pubkey = keypair.identity.signing.signing_pubkey_bytes();
    let signature = keypair.identity.sign(&peer_record_signable(peer_id));
    TnsRecord::Peer {
        signing_algo,
        signing_pubkey,
        peer_id: *peer_id,
        signature,
    }
}

/// Verify a Peer record against the expected ServiceId.
/// Returns the PeerId if valid, or an error if forged/mismatched.
pub fn verify_peer_record(record: &TnsRecord, expected_service_id: &ServiceId) -> Result<PeerId> {
    let TnsRecord::Peer {
        signing_algo,
        signing_pubkey,
        peer_id,
        signature,
    } = record
    else {
        return Err(Error::Protocol("not a Peer record".into()));
    };

    let msg = peer_record_signable(peer_id);
    if !crate::identity::verify_signed(
        crate::identity::SignedBy::Service(expected_service_id),
        Some(*signing_algo),
        signing_pubkey,
        &msg,
        signature,
    ) {
        return Err(Error::Crypto("Peer record not signed by its service".into()));
    }

    Ok(*peer_id)
}

// ── Publishing ──

// ── Opaque per-label publication ──

/// Label and bootstrap-descriptor TTL. Owners refresh within this bound.
pub const ZONE_ROOT_TTL: u32 = publication::TTL;

async fn publish_label_snapshot(
    node: &Node,
    owner: &Keypair,
    label: &str,
    set: Vec<u8>,
    sequence: u64,
    descriptor: bool,
) -> Result<()> {
    // Mining and private signing do not block the async executor. Bound the
    // job to one label's four candidates; the zone map stays local.
    let signer = {
        let bytes = zeroize::Zeroizing::new(owner.to_full_bytes());
        Keypair::from_full_bytes(&bytes).map_err(|e| Error::Crypto(e.into()))?
    };
    let label = label.to_string();
    let records =
        tokio::task::spawn_blocking(move || -> Result<Vec<crate::dht::VerifiedRecord>> {
            let mut records = Vec::new();
            if descriptor {
                records.push(crate::dht::VerifiedRecord::new_zone_key(
                    &signer,
                    sequence,
                    Duration::from_secs(publication::TTL as u64),
                ));
            }
            for lane in 0..publication::LANES {
                records.push(publication::build(&signer, &label, lane, sequence, &set)?);
            }
            Ok(records)
        })
        .await
        .map_err(|e| Error::Crypto(format!("TNS publication worker failed: {e}")))??;
    node.dht_publish_tns_batch(records).await
}

/// Refresh the local working set as independent label publications, including
/// persistent tombstones. No uploaded object contains the whole zone.
pub async fn refresh_zone(node: &Node, zone_keypair: &Keypair) -> Result<()> {
    let _guard = node.zone_publication.lock().await;
    let sid = zone_keypair.identity.service_id();
    let (map, sequence) = node.zone_signing_snapshot(&sid).await;
    if map.is_empty() {
        return node
            .dht_publish_tns_batch(vec![crate::dht::VerifiedRecord::new_zone_key(
                zone_keypair,
                sequence,
                Duration::from_secs(publication::TTL as u64),
            )])
            .await;
    }
    for (index, (label, set)) in map.into_iter().enumerate() {
        publish_label_snapshot(node, zone_keypair, &label, set, sequence, index == 0).await?;
    }
    Ok(())
}

pub async fn publish(
    node: &Node,
    zone_keypair: &Keypair,
    label: &str,
    records: &[TnsRecord],
) -> Result<()> {
    // The API boundary validates record semantics. The publication builder
    // independently bounds the complete serialized value before admission.
    if !set_zone_label(
        node,
        zone_keypair,
        label,
        Some(serialize_record_set(records)),
    )
    .await?
    {
        let _guard = node.zone_publication.lock().await;
        let (set, sequence) = node
            .zone_label_signing_snapshot(&zone_keypair.identity.service_id(), label)
            .await;
        if let Some(set) = set {
            publish_label_snapshot(node, zone_keypair, label, set, sequence, true).await?;
        }
    }
    Ok(())
}

pub async fn unpublish(node: &Node, zone_keypair: &Keypair, label: &str) -> Result<()> {
    set_zone_label(node, zone_keypair, label, None).await?;
    Ok(())
}

/// Update one published label. Size/capacity rejection publishes no partial
/// lane set and restores the previous working value. Successful withdrawals
/// remain signed empty record sets and survive restart.
pub(crate) async fn set_zone_label(
    node: &Node,
    zone_keypair: &Keypair,
    label: &str,
    set: Option<Vec<u8>>,
) -> Result<bool> {
    let _guard = node.zone_publication.lock().await;
    let sid = zone_keypair.identity.service_id();
    let Some(previous) = node.zone_published_update(&sid, label, set.clone()).await else {
        // A previous publication may have succeeded while its durable intent
        // write failed. Retrying withdrawal must retry that write as well.
        if set.is_none() {
            let (current, _) = node.zone_label_signing_snapshot(&sid, label).await;
            if current.is_some() {
                node.persist_zone_tombstone(&sid, label, true)?;
            }
        }
        return Ok(false);
    };
    let (snapshot, sequence) = node.zone_label_signing_snapshot(&sid, label).await;
    let snapshot = snapshot.unwrap_or_else(|| serialize_record_set(&[]));
    if let Err(e) =
        publish_label_snapshot(node, zone_keypair, label, snapshot, sequence, true).await
    {
        node.zone_published_revert(&sid, label, set.as_deref(), previous)
            .await;
        return Err(e);
    }
    node.persist_zone_tombstone(&sid, label, set.is_none())?;
    node.tns_cache().lock().await.forget(&sid, label);
    Ok(true)
}

/// Safety-sensitive withdrawal used for peer/intro lifecycle transitions.
/// Keep withdrawal intent even if capacity or connectivity prevents publication.
pub(crate) async fn retire_zone_label(
    node: &Node,
    zone_keypair: &Keypair,
    label: &str,
) -> Result<()> {
    let _guard = node.zone_publication.lock().await;
    let sid = zone_keypair.identity.service_id();
    node.zone_published_update(&sid, label, None).await;
    let (current, sequence) = node.zone_label_signing_snapshot(&sid, label).await;
    if current.is_none() {
        return Ok(());
    }
    node.persist_zone_tombstone(&sid, label, true)?;
    publish_label_snapshot(
        node,
        zone_keypair,
        label,
        serialize_record_set(&[]),
        sequence,
        true,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    async fn held_label(node: &Node, owner: &Keypair, label: &str) -> Vec<TnsRecord> {
        let sid = owner.identity.service_id();
        let pk = owner.identity.signing.signing_pubkey_bytes();
        let mut best = None;
        for lane in 0..publication::LANES {
            let (_, key) = publication::label_key(&pk, label, lane).unwrap();
            for r in node.dht_held(&key).await {
                if let Some((set, sequence)) = publication::open(&sid, &pk, label, lane, &r) {
                    if best.as_ref().map_or(true, |(_, old)| sequence > *old) {
                        best = Some((set, sequence));
                    }
                }
            }
        }
        best.expect("held authenticated label").0
    }

    #[tokio::test]
    async fn a_single_available_lane_resolves_without_waiting_for_missing_lanes() {
        let node = Node::new(Keypair::generate_ed25519());
        let owner = Keypair::generate();
        let sid = owner.identity.service_id();
        let descriptor = crate::dht::VerifiedRecord::new_zone_key(
            &owner,
            1,
            Duration::from_secs(publication::TTL as u64),
        );
        node.dht_publish(descriptor).await.unwrap();
        let set = serialize_record_set(&[TnsRecord::Text("reachable".into())]);
        let only_lane = publication::build(&owner, "ssh", 3, 1, &set).unwrap();
        node.dht_publish(only_lane).await.unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(2), lookup_label(&node, &sid, "ssh"))
            .await
            .unwrap();
        assert_eq!(answer, vec![TnsRecord::Text("reachable".into())]);
    }

    #[tokio::test]
    async fn edits_leave_other_label_publications_unchanged_and_failed_batches_publish_nothing() {
        let node = Node::new(Keypair::generate_ed25519());
        let owner = Keypair::generate_ed25519();
        publish(&node, &owner, "a", &[TnsRecord::Text("one".into())])
            .await
            .unwrap();
        let (_, q) =
            publication::label_key(&owner.identity.signing.signing_pubkey_bytes(), "a", 0).unwrap();
        let before = node.dht_held(&q).await[0].clone();
        publish(&node, &owner, "b", &[TnsRecord::Text("two".into())])
            .await
            .unwrap();
        let after = node.dht_held(&q).await[0].clone();
        assert_eq!(before.signer, after.signer);
        assert_eq!(before.expires, after.expires);

        let path = std::env::temp_dir().join(format!("tns-batch-{}.sqlite", rand::random::<u64>()));
        let db = std::sync::Arc::new(crate::state::StateDb::open(&path).unwrap());
        let mut limits = crate::state::StorageLimits::default();
        limits.max_records = 4;
        let small = Node::with_db(Keypair::generate_ed25519(), db.clone(), limits);
        let rejected = Keypair::generate_ed25519();
        assert!(publish(
            &small,
            &rejected,
            "x",
            &[TnsRecord::Text("too many lanes for this store".into())]
        )
        .await
        .is_err());
        assert!(small
            .dht_held(&crate::dht::zone_key(&rejected.identity.service_id()))
            .await
            .is_empty());
        for lane in 0..publication::LANES {
            let (_, q) = publication::label_key(
                &rejected.identity.signing.signing_pubkey_bytes(),
                "x",
                lane,
            )
            .unwrap();
            assert!(small.dht_held(&q).await.is_empty());
        }
        assert!(small
            .local_zone_label(&rejected.identity.service_id(), "x")
            .await
            .is_none());
        assert!(db.load_dht_records().unwrap().is_empty());
        drop(small);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn withdrawal_intent_survives_restart_and_overrides_stale_label_configuration() {
        let path =
            std::env::temp_dir().join(format!("tns-retire-{}.sqlite", rand::random::<u64>()));
        let db = std::sync::Arc::new(crate::state::StateDb::open(&path).unwrap());
        let owner = Keypair::generate_ed25519();
        let sid = owner.identity.service_id();
        let node = Node::with_db(
            Keypair::generate_ed25519(),
            db.clone(),
            crate::state::StorageLimits::default(),
        );
        let key = tarnet_api::types::encode_base32(sid.as_bytes());
        db.label_set(
            &key,
            "ssh",
            &[tns_record_to_bytes(&TnsRecord::Text("old".into()))],
            true,
        )
        .unwrap();
        publish(&node, &owner, "ssh", &[TnsRecord::Text("old".into())])
            .await
            .unwrap();
        unpublish(&node, &owner, "ssh").await.unwrap();
        assert_eq!(db.tns_tombstones(&sid).unwrap(), vec!["ssh"]);
        drop(node);
        let restarted = Node::with_db(
            Keypair::generate_ed25519(),
            db.clone(),
            crate::state::StorageLimits::default(),
        );
        refresh_zone(&restarted, &owner).await.unwrap();
        assert!(held_label(&restarted, &owner, "ssh").await.is_empty());
        publish(&restarted, &owner, "ssh", &[TnsRecord::Text("new".into())])
            .await
            .unwrap();
        assert!(db.tns_tombstones(&sid).unwrap().is_empty());
        assert_eq!(
            held_label(&restarted, &owner, "ssh").await,
            vec![TnsRecord::Text("new".into())]
        );
        drop(restarted);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verified_version_floor_survives_answer_expiry_and_rejects_rollback() {
        let sid = ServiceId([9; 32]);
        let mut cache = TnsCache::new();
        assert!(cache.accept_version(sid, "ssh", 7));
        cache.insert(
            sid,
            "ssh".into(),
            vec![TnsRecord::Text("new".into())],
            Duration::ZERO,
        );
        assert!(cache.get(&sid, "ssh").is_none());
        assert!(!cache.accept_version(sid, "ssh", 6));
        assert!(cache.accept_version(sid, "ssh", 7));
        assert!(cache.accept_version(sid, "ssh", 8));
    }

    #[test]
    fn record_roundtrip_identity() {
        let sid = ServiceId::from_signing_pubkey(&[0xAA; 32]);
        let record = TnsRecord::Identity(sid);
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn record_roundtrip_zone() {
        let sid = ServiceId::from_signing_pubkey(&[0xBB; 32]);
        let record = TnsRecord::Zone(sid);
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn record_roundtrip_vhost() {
        let sid = ServiceId::from_signing_pubkey(&[0xCD; 32]);
        let record = TnsRecord::VHost(sid);
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn vhost_wire_port_deterministic() {
        assert_eq!(
            vhost_wire_port("blog", "80"),
            vhost_wire_port("blog", "80")
        );
        // 64-char lowercase hex.
        let p = vhost_wire_port("blog", "80");
        assert_eq!(p.len(), 64);
        assert!(p.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn vhost_wire_port_no_label_port_aliasing() {
        // The MAC chain must not let the (label, port) boundary slide:
        // ("ab","c") and ("a","bc") must derive distinct ports.
        assert_ne!(vhost_wire_port("ab", "c"), vhost_wire_port("a", "bc"));
        // Distinct labels / ports give distinct ports.
        assert_ne!(vhost_wire_port("blog", "80"), vhost_wire_port("ssh", "80"));
        assert_ne!(vhost_wire_port("blog", "80"), vhost_wire_port("blog", "443"));
    }

    #[test]
    fn vhost_wire_port_apex_distinct() {
        // The apex label "@" is just another label; its derivation differs from
        // any other label and is publicly computable (correct — apex is public).
        assert_ne!(vhost_wire_port("@", "443"), vhost_wire_port("blog", "443"));
        assert_eq!(vhost_wire_port("@", "443"), vhost_wire_port("@", "443"));
    }

    #[test]
    fn validate_records_vhost_sole_non_supplemental() {
        let vsid = ServiceId::from_signing_pubkey(&[0x05; 32]);
        let id_sid = ServiceId::from_signing_pubkey(&[0x06; 32]);

        // VHost alone — ok.
        assert!(validate_records(&[TnsRecord::VHost(vsid)]).is_ok());

        // VHost + Text (supplemental) — ok.
        assert!(validate_records(&[
            TnsRecord::VHost(vsid),
            TnsRecord::Text("desc".into()),
        ])
        .is_ok());

        // VHost + Identity — rejected (ambiguous: entity or vhost?).
        assert!(
            validate_records(&[TnsRecord::VHost(vsid), TnsRecord::Identity(id_sid)]).is_err()
        );

        // VHost + Zone — rejected.
        assert!(
            validate_records(&[TnsRecord::VHost(vsid), TnsRecord::Zone(id_sid)]).is_err()
        );
    }

    #[test]
    fn record_roundtrip_content_ref() {
        let record = TnsRecord::ContentRef([0xCC; 64]);
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn record_roundtrip_text() {
        let record = TnsRecord::Text("hello world".into());
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn record_roundtrip_service() {
        let record = TnsRecord::Service {
            port: "payment".into(),
            weight: 7,
            meta: b"llama-3.1-8b".to_vec(),
        };
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn record_roundtrip_service_empty_meta() {
        let record = TnsRecord::Service {
            port: "".into(),
            weight: 0,
            meta: Vec::new(),
        };
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn record_roundtrip_alias() {
        let record = TnsRecord::Alias("www.other".into());
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn record_set_roundtrip() {
        let records = vec![
            TnsRecord::Identity(ServiceId::from_signing_pubkey(&[1; 32])),
            TnsRecord::Text("test".into()),
            TnsRecord::Zone(ServiceId::from_signing_pubkey(&[2; 32])),
        ];
        let bytes = serialize_record_set(&records);
        let parsed = deserialize_record_set(&bytes).unwrap();
        assert_eq!(parsed, records);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let zone = ServiceId::from_signing_pubkey(&[0x42; 32]);
        let label = "www";
        let records = vec![
            TnsRecord::Identity(ServiceId::from_signing_pubkey(&[1; 32])),
            TnsRecord::Identity(ServiceId::from_signing_pubkey(&[2; 32])),
        ];
        let blob = seal(&zone, label, &serialize_record_set(&records));
        let decrypted = deserialize_record_set(&unseal(&zone, label, &blob).unwrap()).unwrap();
        assert_eq!(decrypted, records);
    }

    #[test]
    fn bundle_authenticates_owner_and_binding() {
        let owner = Keypair::generate();
        let zone = owner.identity.service_id();
        let label = "www";
        let recs = vec![TnsRecord::Text("ok".into())];
        let b = build_bundle(&owner, &zone, label, 7, &recs);

        // Valid: right owner, right (zone,label).
        let (got, seq, author) = open_bundle(&zone, label, &b, true).unwrap();
        assert_eq!(got, recs);
        assert_eq!(seq, 7);
        assert_eq!(author, zone);

        // Cross-label and cross-zone replay are rejected (signature binds both).
        assert!(open_bundle(&zone, "mail", &b, true).is_none());
        let other = ServiceId::from_signing_pubkey(&[0x99; 32]);
        assert!(open_bundle(&other, label, &b, true).is_none());

        // Tamper: flip a byte in the records region → signature fails.
        let mut tampered = b.clone();
        let n = tampered.len();
        tampered[n / 2] ^= 0xFF;
        assert!(open_bundle(&zone, label, &tampered, true).is_none());

        // A bundle signed by a NON-owner for `zone` is rejected under require_owner
        // (the forgery hole), but accepted in pool mode (any member may write).
        let attacker = Keypair::generate();
        let evil = build_bundle(&attacker, &zone, label, 8, &recs);
        assert!(open_bundle(&zone, label, &evil, true).is_none());
        assert!(open_bundle(&zone, label, &evil, false).is_some());
    }

    #[test]
    fn flood_at_zone_key_cannot_dark_a_name() {
        // Finding 1, end to end: an attacker who knows the public name derives
        // zone_key(zone) and floods it with many validly-signed (by their own
        // disposable keys) junk records. None pass the self-address gate, so the
        // legitimate zone publication is never evicted and the name keeps resolving.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone = Keypair::generate();
            let zone_id = zone.identity.service_id();
            let target = ServiceId::from_signing_pubkey(&[0x11; 32]);

            publish(&node, &zone, "www", &[TnsRecord::Identity(target)])
                .await
                .unwrap();

            // Attacker floods the descriptor location with junk. Each record
            // is a validly-signed ZoneKey from a fresh key — but its signer's
            // ServiceId does not hash to this key, so the ingest gate drops it.
            let descriptor_key = crate::dht::zone_key(&zone_id);
            for _ in 0..64 {
                let junk_kp = Keypair::generate();
                let value = publication::KEY_MARKER.to_vec();
                let seq = node.next_dht_sequence().await;
                let expires = crate::dht::expires_in(Duration::from_secs(600));
                // Build a ZoneKey at the victim's descriptor key, signed by junk_kp.
                let rec = crate::dht::DhtRecord {
                    key: descriptor_key,
                    record_type: RecordType::ZoneKey,
                    sequence: seq,
                    signer: junk_kp.peer_id(),
                    signer_algo: junk_kp.identity.signing.algo() as u8,
                    signer_pubkey: junk_kp.identity.signing.signing_pubkey_bytes(),
                    value: value.clone(),
                    expires,
                    stored_at: Instant::now(),
                    signature: junk_kp.sign(&crate::dht::record_signable(
                        descriptor_key.as_bytes(),
                        RecordType::ZoneKey,
                        seq,
                        &value,
                    )),
                };
                // The gate rejects it; if it somehow didn't, this would store junk.
                assert!(crate::dht::VerifiedRecord::verify_incoming(rec).is_err());
            }

            // The legitimate name still resolves.
            match resolve(&node, zone_id, "www").await {
                TnsResolution::Records(r) => {
                    assert_eq!(r, vec![TnsRecord::Identity(target)])
                }
                other => panic!("expected Records, got {:?}", other),
            }
        });
    }

    #[test]
    fn unpublish_replaces_label_with_tombstone() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone = Keypair::generate();
            let zone_id = zone.identity.service_id();
            let a = ServiceId::from_signing_pubkey(&[0xA1; 32]);
            let b = ServiceId::from_signing_pubkey(&[0xB2; 32]);

            // Two independently published labels in one zone must both resolve.
            publish(&node, &zone, "www", &[TnsRecord::Identity(a)])
                .await
                .unwrap();
            publish(&node, &zone, "mail", &[TnsRecord::Identity(b)])
                .await
                .unwrap();
            assert!(matches!(
                resolve(&node, zone_id, "www").await,
                TnsResolution::Records(_)
            ));
            assert!(matches!(
                resolve(&node, zone_id, "mail").await,
                TnsResolution::Records(_)
            ));

            // Remove www; mail must survive, www must become NotFound.
            unpublish(&node, &zone, "www").await.unwrap();
            node.tns_cache().lock().await.forget(&zone_id, "www");
            match resolve(&node, zone_id, "www").await {
                TnsResolution::NotFound => {}
                other => panic!("expected NotFound after unpublish, got {:?}", other),
            }
            match resolve(&node, zone_id, "mail").await {
                TnsResolution::Records(r) => assert_eq!(r, vec![TnsRecord::Identity(b)]),
                other => panic!("expected mail to survive, got {:?}", other),
            }
        });
    }

    #[test]
    fn wrong_zone_cannot_decrypt() {
        let zone = ServiceId::from_signing_pubkey(&[0x42; 32]);
        let wrong_zone = ServiceId::from_signing_pubkey(&[0x43; 32]);
        let label = "www";
        let records = vec![TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[1; 32],
        ))];
        let blob = seal(&zone, label, &serialize_record_set(&records));
        assert!(unseal(&wrong_zone, label, &blob).is_err());
    }

    #[test]
    fn wrong_label_cannot_decrypt() {
        let zone = ServiceId::from_signing_pubkey(&[0x42; 32]);
        let records = vec![TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[1; 32],
        ))];
        let blob = seal(&zone, "www", &serialize_record_set(&records));
        assert!(unseal(&zone, "mail", &blob).is_err());
    }

    #[test]
    fn dht_key_deterministic() {
        let zone = ServiceId::from_signing_pubkey(&[0x42; 32]);
        assert_eq!(tns_dht_key(&zone, "www"), tns_dht_key(&zone, "www"));
    }

    #[test]
    fn dht_key_differs_by_label() {
        let zone = ServiceId::from_signing_pubkey(&[0x42; 32]);
        assert_ne!(tns_dht_key(&zone, "www"), tns_dht_key(&zone, "mail"));
    }

    #[test]
    fn dht_key_differs_by_zone() {
        let zone1 = ServiceId::from_signing_pubkey(&[0x42; 32]);
        let zone2 = ServiceId::from_signing_pubkey(&[0x43; 32]);
        assert_ne!(tns_dht_key(&zone1, "www"), tns_dht_key(&zone2, "www"));
    }

    #[test]
    fn label_via_state_db() {
        use crate::state::StateDb;

        let path = std::env::temp_dir().join(format!(
            "tarnet-label-test-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = StateDb::open(&path).unwrap();
        let zone = ServiceId::from_signing_pubkey(&[0x42; 32]);

        // Set and get
        let zone_bytes = tns_record_to_bytes(&TnsRecord::Zone(zone));
        db.label_set("", "alice", &[zone_bytes.clone()], false)
            .unwrap();
        let result = db.label_get("", "alice").unwrap();
        assert!(result.is_some());
        let (blobs, publish) = result.unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(!publish);

        // Not found
        assert!(db.label_get("", "bob").unwrap().is_none());

        // Overwrite
        let zone2 = ServiceId::from_signing_pubkey(&[0x43; 32]);
        let zone2_bytes = tns_record_to_bytes(&TnsRecord::Zone(zone2));
        db.label_set("", "alice", &[zone2_bytes], true).unwrap();
        let (_, publish) = db.label_get("", "alice").unwrap().unwrap();
        assert!(publish);

        // List
        let zone_bytes2 = tns_record_to_bytes(&TnsRecord::Zone(zone));
        db.label_set("", "bob", &[zone_bytes2], false).unwrap();
        let list = db.label_list("").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "alice");
        assert_eq!(list[1].0, "bob");

        // Remove
        db.label_remove("", "alice").unwrap();
        assert!(db.label_get("", "alice").unwrap().is_none());
        assert_eq!(db.label_list("",).unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn publish_and_local_resolve() {
        // Test that publishing records makes them locally resolvable
        // without network (single-node, records go into local DHT store).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let zone_kp = Keypair::generate();
            let zone_id = zone_kp.identity.service_id();
            let node = Node::new(Keypair::generate());

            let records = vec![
                TnsRecord::Identity(ServiceId::from_signing_pubkey(&[0x11; 32])),
                TnsRecord::Identity(ServiceId::from_signing_pubkey(&[0x22; 32])),
            ];

            publish(&node, &zone_kp, "www", &records)
                .await
                .unwrap();

            // Should be immediately resolvable from local store.
            let result = resolve(&node, zone_id, "www").await;
            match result {
                TnsResolution::Records(resolved) => {
                    assert_eq!(resolved, records);
                }
                other => panic!("expected Records, got {:?}", other),
            }
        });
    }

    #[test]
    fn delegation_chain_local() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());

            // Zone A delegates "blog" to Zone B.
            let zone_a = Keypair::generate();
            let zone_b = Keypair::generate();

            publish(
                &node,
                &zone_a,
                "blog",
                &[TnsRecord::Zone(zone_b.identity.service_id())],
            )
            .await
            .unwrap();

            // Zone B has "www" pointing to an identity.
            let target = ServiceId::from_signing_pubkey(&[0xFF; 32]);
            publish(&node, &zone_b, "www", &[TnsRecord::Identity(target)])
                .await
                .unwrap();

            // Resolve "www.blog" in zone A.
            let result = resolve(&node, zone_a.identity.service_id(), "www.blog").await;
            match result {
                TnsResolution::Records(resolved) => {
                    assert_eq!(resolved, vec![TnsRecord::Identity(target)]);
                }
                other => panic!("expected Records, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolution_not_found() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone = Keypair::generate();

            let result = resolve(&node, zone.identity.service_id(), "nonexistent").await;
            match result {
                TnsResolution::NotFound => {}
                other => panic!("expected NotFound, got {:?}", other),
            }
        });
    }

    #[test]
    fn multiple_identity_records() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone = Keypair::generate();

            let records = vec![
                TnsRecord::Identity(ServiceId::from_signing_pubkey(&[0x11; 32])),
                TnsRecord::Identity(ServiceId::from_signing_pubkey(&[0x22; 32])),
                TnsRecord::Identity(ServiceId::from_signing_pubkey(&[0x33; 32])),
            ];
            publish(&node, &zone, "lb", &records).await.unwrap();

            let result = resolve(&node, zone.identity.service_id(), "lb").await;
            match result {
                TnsResolution::Records(resolved) => {
                    assert_eq!(resolved.len(), 3);
                    assert_eq!(resolved, records);
                }
                other => panic!("expected Records, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolve_name_single_label() {
        // "server" → look up "server" in node's own zone → Identity record
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let default_sid = node.default_service_id().await;
            let default_kp = node.keypair_for_service(&default_sid).await.unwrap();
            let target = ServiceId::from_signing_pubkey(&[0xAA; 32]);

            publish(
                &node,
                &default_kp,
                "server",
                &[TnsRecord::Identity(target)],
            )
            .await
            .unwrap();

            let result = resolve_name(&node, "server").await;
            match result {
                TnsResolution::Records(records) => {
                    assert_eq!(records, vec![TnsRecord::Identity(target)]);
                }
                other => panic!("expected Identity, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolve_name_multi_label() {
        // "www.tom" → "tom" in own zone is Zone(zone Z),
        // then "www" in zone Z → Identity record
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let default_sid = node.default_service_id().await;
            let default_kp = node.keypair_for_service(&default_sid).await.unwrap();
            let zone = Keypair::generate();
            let target = ServiceId::from_signing_pubkey(&[0xAA; 32]);

            // Publish "tom" as Zone in our own zone
            publish(
                &node,
                &default_kp,
                "tom",
                &[TnsRecord::Zone(zone.identity.service_id())],
            )
            .await
            .unwrap();

            // Publish "www" in zone Z
            publish(&node, &zone, "www", &[TnsRecord::Identity(target)])
                .await
                .unwrap();

            let result = resolve_name(&node, "www.tom").await;
            match result {
                TnsResolution::Records(records) => {
                    assert_eq!(records, vec![TnsRecord::Identity(target)]);
                }
                other => panic!("expected Identity, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolve_name_with_zone_chain() {
        // "service.app.tom" → own zone "tom" → Zone(zone A),
        // zone A "app" → Zone(zone B),
        // zone B "service" → Identity
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let default_sid = node.default_service_id().await;
            let default_kp = node.keypair_for_service(&default_sid).await.unwrap();
            let zone_a = Keypair::generate();
            let zone_b = Keypair::generate();

            // "tom" in own zone → Zone to zone A
            publish(
                &node,
                &default_kp,
                "tom",
                &[TnsRecord::Zone(zone_a.identity.service_id())],
            )
            .await
            .unwrap();

            // "app" in zone A → Zone to zone B
            publish(
                &node,
                &zone_a,
                "app",
                &[TnsRecord::Zone(zone_b.identity.service_id())],
            )
            .await
            .unwrap();

            let target = TnsRecord::Identity(ServiceId::from_signing_pubkey(&[0xBB; 32]));
            publish(&node, &zone_b, "service", &[target.clone()])
                .await
                .unwrap();

            let result = resolve_name(&node, "service.app.tom").await;
            match result {
                TnsResolution::Records(records) => {
                    assert_eq!(records, vec![target]);
                }
                other => panic!("expected Identity, got {:?}", other),
            }
        });
    }

    #[test]
    fn alias_cycle_hits_depth_limit() {
        // "a" aliases to "b", "b" aliases to "a" → should not loop forever
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let zone = Keypair::generate();
            let node = Node::new(Keypair::generate());

            // "loop" → Alias("final.loop")  (restart with same name = cycle)
            publish(
                &node,
                &zone,
                "loop",
                &[TnsRecord::Alias("final.loop".into())],
            )
            .await
            .unwrap();

            publish(
                &node,
                &zone,
                "final",
                &[TnsRecord::Identity(ServiceId::from_signing_pubkey(
                    &[0xAA; 32],
                ))],
            )
            .await
            .unwrap();

            let result = resolve(&node, zone.identity.service_id(), "final.loop").await;
            match result {
                TnsResolution::Error(msg) => {
                    assert!(
                        msg.contains("depth"),
                        "expected depth limit error, got: {}",
                        msg
                    );
                }
                other => panic!("expected Error, got {:?}", other),
            }
        });
    }

    #[test]
    fn zone_self_loop_hits_depth_limit() {
        // Zone delegates to itself → should not loop forever
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let zone = Keypair::generate();
            let node = Node::new(Keypair::generate());

            // "x" in zone delegates back to the same zone
            publish(
                &node,
                &zone,
                "x",
                &[TnsRecord::Zone(zone.identity.service_id())],
            )
            .await
            .unwrap();

            // "y" in zone is a terminal record
            publish(
                &node,
                &zone,
                "y",
                &[TnsRecord::Identity(ServiceId::from_signing_pubkey(
                    &[0xBB; 32],
                ))],
            )
            .await
            .unwrap();

            // Resolve "y.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x" — enough labels to exceed depth
            let name = format!("y{}", ".x".repeat(MAX_DELEGATION_DEPTH + 1));
            let result = resolve(&node, zone.identity.service_id(), &name).await;
            match result {
                TnsResolution::Error(msg) => {
                    assert!(
                        msg.contains("depth"),
                        "expected depth limit error, got: {}",
                        msg
                    );
                }
                other => panic!("expected Error, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolve_name_not_found() {
        // "nobody" → not published in own zone → NotFound
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());

            let result = resolve_name(&node, "nobody").await;
            assert!(matches!(result, TnsResolution::NotFound));
        });
    }

    #[test]
    fn resolve_name_not_found_is_instant() {
        // Names not in our zone should return NotFound without a DHT poll.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());

            let start = std::time::Instant::now();
            let result = resolve_name(&node, "google.com").await;
            let elapsed = start.elapsed();

            assert!(matches!(result, TnsResolution::NotFound));
            // Must be well under PER_STEP_TIMEOUT (10s).
            assert!(
                elapsed < Duration::from_secs(1),
                "resolve took {:?}, expected < 1s",
                elapsed
            );
        });
    }

    #[test]
    fn resolve_via_raw_service_id() {
        // "bob.<raw-base32-service-id>" → parse rightmost label as zone,
        // then look up "bob" in that zone.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone = Keypair::generate();
            let zone_id = zone.identity.service_id();
            let target = ServiceId::from_signing_pubkey(&[0xBB; 32]);

            // Publish "bob" in the foreign zone.
            publish(&node, &zone, "bob", &[TnsRecord::Identity(target)])
                .await
                .unwrap();

            // Resolve using the raw ServiceId as the zone label.
            let name = format!("bob.{}", zone_id);
            let result = resolve_name(&node, &name).await;
            match result {
                TnsResolution::Records(records) => {
                    assert_eq!(records, vec![TnsRecord::Identity(target)]);
                }
                other => panic!("expected Identity record, got {:?}", other),
            }
        });
    }

    #[test]
    fn try_parse_service_id_rejects_garbage() {
        assert!(try_parse_service_id("com").is_none());
        assert!(try_parse_service_id("google").is_none());
        assert!(try_parse_service_id("").is_none());
        assert!(try_parse_service_id("abc123").is_none());

        // Valid base32 but wrong length
        assert!(try_parse_service_id("ABCD").is_none());

        // Correct format should work
        let kp = Keypair::generate();
        let sid = kp.identity.service_id();
        let encoded = format!("{}", sid);
        assert!(try_parse_service_id(&encoded).is_some());
        assert_eq!(try_parse_service_id(&encoded).unwrap(), sid);
    }

    // ── Validation tests ──

    #[test]
    fn validate_alias_bare_label() {
        assert!(validate_alias_target("@").is_ok());
        assert!(validate_alias_target("www").is_ok());
        assert!(validate_alias_target("my-service").is_ok());
    }

    #[test]
    fn validate_alias_absolute() {
        let kp = Keypair::generate();
        let sid = kp.identity.service_id();
        let target = format!("blog.{}", sid);
        assert!(validate_alias_target(&target).is_ok());
    }

    #[test]
    fn validate_alias_rejects_ambiguous() {
        // Multi-label where rightmost is not a ServiceId
        assert!(validate_alias_target("foo.bar").is_err());
        assert!(validate_alias_target("a.b.c").is_err());
        assert!(validate_alias_target("www.example").is_err());
    }

    #[test]
    fn validate_alias_rejects_empty() {
        assert!(validate_alias_target("").is_err());
    }

    #[test]
    fn validate_records_gns_zone_sole_non_supplemental() {
        let zone_sid = ServiceId::from_signing_pubkey(&[0x01; 32]);
        let id_sid = ServiceId::from_signing_pubkey(&[0x02; 32]);

        // Zone alone — ok.
        assert!(validate_records(&[TnsRecord::Zone(zone_sid)]).is_ok());

        // Zone + Text (supplemental) — ok.
        assert!(validate_records(&[
            TnsRecord::Zone(zone_sid),
            TnsRecord::Text("description".into()),
        ])
        .is_ok());

        // Zone + ContentRef (supplemental) — ok.
        assert!(
            validate_records(&[TnsRecord::Zone(zone_sid), TnsRecord::ContentRef([0xAA; 64]),])
                .is_ok()
        );

        // Zone + Identity — rejected (both non-supplemental).
        assert!(
            validate_records(&[TnsRecord::Zone(zone_sid), TnsRecord::Identity(id_sid),]).is_err()
        );

        // Zone + Alias — rejected (both non-supplemental).
        assert!(
            validate_records(&[TnsRecord::Zone(zone_sid), TnsRecord::Alias("@".into()),]).is_err()
        );
    }

    #[test]
    fn validate_records_identity_and_text_ok() {
        // Multiple Identity + Text records at a label is fine.
        assert!(validate_records(&[
            TnsRecord::Identity(ServiceId::from_signing_pubkey(&[1; 32])),
            TnsRecord::Identity(ServiceId::from_signing_pubkey(&[2; 32])),
            TnsRecord::Text("load balanced".into()),
        ])
        .is_ok());
    }

    #[test]
    fn validate_records_rejects_empty() {
        assert!(validate_records(&[]).is_err());
    }

    #[test]
    fn validate_records_rejects_bad_alias_target() {
        assert!(validate_records(&[TnsRecord::Alias("foo.bar".into())]).is_err());
    }

    #[test]
    fn validate_published_alias_rejects_unpublished_target() {
        use crate::state::StateDb;

        let path = std::env::temp_dir().join(format!(
            "tarnet-alias-pub-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = StateDb::open(&path).unwrap();

        // Create an unpublished label "@"
        let at_bytes = tns_record_to_bytes(&TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[0x01; 32],
        )));
        db.label_set("", "@", &[at_bytes], false).unwrap();

        // Publishing an alias to "@" should fail — "@" is unpublished.
        let records = vec![TnsRecord::Alias("@".into())];
        assert!(validate_published_aliases(&records, &db, "").is_err());

        // Now publish "@"
        let at_bytes = tns_record_to_bytes(&TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[0x01; 32],
        )));
        db.label_set("", "@", &[at_bytes], true).unwrap();

        // Same alias should now pass.
        assert!(validate_published_aliases(&records, &db, "").is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_unpublished_alias_allows_unpublished_target() {
        // Unpublished labels skip alias validation entirely.
        // This is tested by the fact that tns_set_label only calls
        // validate_published_aliases when publish=true. The function
        // itself always checks, so calling it directly on an unpublished
        // target should fail — but the call site guards it.
        // Here we just verify the guard logic matches expectations.

        use crate::state::StateDb;

        let path = std::env::temp_dir().join(format!(
            "tarnet-alias-unpub-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = StateDb::open(&path).unwrap();

        let at_bytes = tns_record_to_bytes(&TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[0x01; 32],
        )));
        db.label_set("", "@", &[at_bytes], false).unwrap();

        // validate_published_aliases rejects this...
        let records = vec![TnsRecord::Alias("@".into())];
        assert!(validate_published_aliases(&records, &db, "").is_err());

        // ...but validate_records alone is fine (alias target "@" is a bare label).
        assert!(validate_records(&records).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_published_alias_allows_absent_target() {
        // A published alias to a label that doesn't exist in the local store
        // is allowed — the label may be published via tns_publish directly.
        use crate::state::StateDb;

        let path = std::env::temp_dir().join(format!(
            "tarnet-alias-absent-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = StateDb::open(&path).unwrap();

        let records = vec![TnsRecord::Alias("@".into())];
        assert!(validate_published_aliases(&records, &db, "").is_ok());

        let _ = std::fs::remove_file(&path);
    }

    // ── Alias resolution tests ──

    #[test]
    fn resolve_alias_relative() {
        // Zone has "@" → Identity, "blog" → Alias("@").
        // Resolving "blog" should follow the alias and return the Identity.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let zone = Keypair::generate();
            let node = Node::new(Keypair::generate());
            let target = ServiceId::from_signing_pubkey(&[0xAA; 32]);

            publish(&node, &zone, "@", &[TnsRecord::Identity(target)])
                .await
                .unwrap();
            publish(&node, &zone, "blog", &[TnsRecord::Alias("@".into())])
                .await
                .unwrap();

            let result = resolve(&node, zone.identity.service_id(), "blog").await;
            match result {
                TnsResolution::Records(records) => {
                    assert_eq!(records, vec![TnsRecord::Identity(target)]);
                }
                other => panic!("expected Identity via alias, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolve_alias_in_chain() {
        // Zone A: "friend" → Zone(B). Zone B: "site" → Alias("@"), "@" → Identity.
        // Resolving "site.friend" in zone A should follow Zone then Alias.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone_a = Keypair::generate();
            let zone_b = Keypair::generate();
            let target = ServiceId::from_signing_pubkey(&[0xBB; 32]);

            publish(
                &node,
                &zone_a,
                "friend",
                &[TnsRecord::Zone(zone_b.identity.service_id())],
            )
            .await
            .unwrap();

            publish(&node, &zone_b, "@", &[TnsRecord::Identity(target)])
                .await
                .unwrap();
            publish(&node, &zone_b, "site", &[TnsRecord::Alias("@".into())])
                .await
                .unwrap();

            let result = resolve(&node, zone_a.identity.service_id(), "site.friend").await;
            match result {
                TnsResolution::Records(records) => {
                    assert_eq!(records, vec![TnsRecord::Identity(target)]);
                }
                other => panic!("expected Identity via zone+alias, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolve_alias_absolute() {
        // Zone A has "shortcut" → Alias("www.<zone_b_sid>").
        // Zone B has "www" → Identity.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone_a = Keypair::generate();
            let zone_b = Keypair::generate();
            let zone_b_sid = zone_b.identity.service_id();
            let target = ServiceId::from_signing_pubkey(&[0xCC; 32]);

            let alias_target = format!("www.{}", zone_b_sid);
            publish(
                &node,
                &zone_a,
                "shortcut",
                &[TnsRecord::Alias(alias_target)],
            )
            .await
            .unwrap();

            publish(&node, &zone_b, "www", &[TnsRecord::Identity(target)])
                .await
                .unwrap();

            let result = resolve(&node, zone_a.identity.service_id(), "shortcut").await;
            match result {
                TnsResolution::Records(records) => {
                    assert_eq!(records, vec![TnsRecord::Identity(target)]);
                }
                other => panic!("expected Identity via absolute alias, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolve_vhost_surfaces_canonical_label() {
        // Zone has "blog" → VHost(serving). Resolving "blog" returns the serving
        // SID and canonical label "blog" regardless of approach path.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone = Keypair::generate();
            let zone_sid = zone.identity.service_id();
            let serving = ServiceId::from_signing_pubkey(&[0xEE; 32]);

            publish(&node, &zone, "blog", &[TnsRecord::VHost(serving)])
                .await
                .unwrap();

            // Direct in-zone.
            match resolve(&node, zone_sid, "blog").await {
                TnsResolution::VHost {
                    serving: s,
                    canonical_label,
                } => {
                    assert_eq!(s, serving);
                    assert_eq!(canonical_label, "blog");
                }
                other => panic!("expected VHost, got {:?}", other),
            }

            // Via raw SID suffix: "blog.<zone_sid>" — same canonical label.
            let name = format!("blog.{}", zone_sid);
            match resolve_name(&node, &name).await {
                TnsResolution::VHost {
                    serving: s,
                    canonical_label,
                } => {
                    assert_eq!(s, serving);
                    assert_eq!(canonical_label, "blog");
                }
                other => panic!("expected VHost via raw SID, got {:?}", other),
            }
        });
    }

    #[test]
    fn resolve_vhost_via_absolute_alias() {
        // Zone A: "alice-blog" → Alias("blog.<ALICE_SID>"). Alice zone: "blog" →
        // VHost. Canonical label must be "blog" (final position), not the alias.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone_a = Keypair::generate();
            let alice = Keypair::generate();
            let alice_sid = alice.identity.service_id();
            let serving = ServiceId::from_signing_pubkey(&[0xAB; 32]);

            publish(
                &node,
                &zone_a,
                "alice-blog",
                &[TnsRecord::Alias(format!("blog.{}", alice_sid))],
            )
            .await
            .unwrap();
            publish(&node, &alice, "blog", &[TnsRecord::VHost(serving)])
                .await
                .unwrap();

            match resolve(&node, zone_a.identity.service_id(), "alice-blog").await {
                TnsResolution::VHost {
                    serving: s,
                    canonical_label,
                } => {
                    assert_eq!(s, serving);
                    assert_eq!(canonical_label, "blog");
                }
                other => panic!("expected VHost via alias, got {:?}", other),
            }
        });
    }

    // ── Label store tests ──

    #[test]
    fn label_store_multiple_records() {
        use crate::state::StateDb;

        let path = std::env::temp_dir().join(format!(
            "tarnet-label-multi-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = StateDb::open(&path).unwrap();

        let rec1 = tns_record_to_bytes(&TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[1; 32],
        )));
        let rec2 = tns_record_to_bytes(&TnsRecord::Text("hello".into()));
        db.label_set("", "multi", &[rec1.clone(), rec2.clone()], true)
            .unwrap();

        let (blobs, publish) = db.label_get("", "multi").unwrap().unwrap();
        assert_eq!(blobs.len(), 2);
        assert!(publish);

        // Verify records deserialize correctly.
        let (r1, _) = tns_record_from_bytes(&blobs[0]).unwrap();
        let (r2, _) = tns_record_from_bytes(&blobs[1]).unwrap();
        assert_eq!(
            r1,
            TnsRecord::Identity(ServiceId::from_signing_pubkey(&[1; 32]))
        );
        assert_eq!(r2, TnsRecord::Text("hello".into()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn label_store_overwrite_replaces_records() {
        use crate::state::StateDb;

        let path = std::env::temp_dir().join(format!(
            "tarnet-label-overwrite-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = StateDb::open(&path).unwrap();

        let rec1 = tns_record_to_bytes(&TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[1; 32],
        )));
        let rec2 = tns_record_to_bytes(&TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[2; 32],
        )));
        db.label_set("", "x", &[rec1], false).unwrap();
        db.label_set("", "x", &[rec2.clone()], true).unwrap();

        let (blobs, publish) = db.label_get("", "x").unwrap().unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0], rec2);
        assert!(publish);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn label_store_cascade_delete() {
        use crate::state::StateDb;

        let path = std::env::temp_dir().join(format!(
            "tarnet-label-cascade-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = StateDb::open(&path).unwrap();

        let rec = tns_record_to_bytes(&TnsRecord::Identity(ServiceId::from_signing_pubkey(
            &[1; 32],
        )));
        db.label_set("", "del", &[rec.clone(), rec], false).unwrap();
        db.label_remove("", "del").unwrap();
        assert!(db.label_get("", "del").unwrap().is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn record_roundtrip_peer_ed25519() {
        let kp = Keypair::generate_ed25519();
        let peer_id = kp.peer_id();
        let record = build_peer_record(&kp, &peer_id);
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());

        // Verification should pass
        let service_id = kp.identity.service_id();
        let verified_peer = verify_peer_record(&parsed, &service_id).unwrap();
        assert_eq!(verified_peer, peer_id);
    }

    #[test]
    fn record_roundtrip_peer_falcon_ed25519() {
        let kp = Keypair::generate();
        let peer_id = kp.peer_id();
        let record = build_peer_record(&kp, &peer_id);
        let bytes = tns_record_to_bytes(&record);
        let (parsed, consumed) = tns_record_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(consumed, bytes.len());

        // Verification should pass
        let service_id = kp.identity.service_id();
        let verified_peer = verify_peer_record(&parsed, &service_id).unwrap();
        assert_eq!(verified_peer, peer_id);
    }

    #[test]
    fn peer_record_rejects_wrong_service_id() {
        let kp = Keypair::generate();
        let peer_id = kp.peer_id();
        let record = build_peer_record(&kp, &peer_id);

        // Verify against a different ServiceId — should fail
        let wrong_sid = ServiceId::from_signing_pubkey(&[0xFF; 32]);
        assert!(verify_peer_record(&record, &wrong_sid).is_err());
    }

    #[test]
    fn peer_record_rejects_tampered_peer_id() {
        let kp = Keypair::generate();
        let peer_id = kp.peer_id();
        let record = build_peer_record(&kp, &peer_id);
        let service_id = kp.identity.service_id();

        // Tamper with the peer_id
        if let TnsRecord::Peer {
            signing_algo,
            signing_pubkey,
            signature,
            ..
        } = &record
        {
            let tampered = TnsRecord::Peer {
                signing_algo: *signing_algo,
                signing_pubkey: signing_pubkey.clone(),
                peer_id: PeerId([0xDD; 32]),
                signature: signature.clone(),
            };
            assert!(verify_peer_record(&tampered, &service_id).is_err());
        } else {
            panic!("expected Peer record");
        }
    }

    #[test]
    fn tns_cache_hit_and_expiry() {
        let mut cache = TnsCache::new();
        let zone = ServiceId::from_signing_pubkey(&[0x01; 32]);
        let records = vec![TnsRecord::Text("hello".into())];

        // Insert with 1-second TTL.
        cache.insert(zone, "test".into(), records.clone(), Duration::from_secs(1));

        // Should be a cache hit.
        assert_eq!(cache.get(&zone, "test"), Some(&records));

        // After TTL expires, should be a miss.
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(cache.get(&zone, "test"), None);
    }

    #[test]
    fn tns_cache_negative() {
        let mut cache = TnsCache::new();
        let zone = ServiceId::from_signing_pubkey(&[0x02; 32]);

        cache.insert_negative(zone, "missing".into());

        // Negative cache returns empty vec.
        assert_eq!(cache.get(&zone, "missing"), Some(&Vec::new()));
    }

    #[test]
    fn tns_cache_eviction() {
        let mut cache = TnsCache::new();
        let zone = ServiceId::from_signing_pubkey(&[0x03; 32]);

        // Fill beyond max entries.
        for i in 0..TNS_CACHE_MAX_ENTRIES + 10 {
            cache.insert(
                zone,
                format!("label-{}", i),
                vec![TnsRecord::Text(format!("v{}", i))],
                Duration::from_secs(600),
            );
        }

        // Should not exceed max entries.
        assert!(cache.entries.len() <= TNS_CACHE_MAX_ENTRIES);
    }

    #[test]
    fn oversized_label_is_rolled_back_and_zone_keeps_publishing() {
        // A label that exceeds the encrypted value limit must fail
        // without poisoning the working set: later publishes and refreshes of
        // the same zone still succeed, and the label never resolves.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone_id = node.default_service_id().await;
            let kp = node.keypair_for_service(&zone_id).await.unwrap();
            publish(&node, &kp, "ok", &[TnsRecord::Text("a".into())]).await.unwrap();

            let big = vec![TnsRecord::Text("x".repeat(62_000))];
            assert!(validate_records(&big).is_ok(), "fits the wire, not the root");
            assert!(publish(&node, &kp, "big", &big).await.is_err());

            publish(&node, &kp, "small", &[TnsRecord::Text("b".into())]).await.unwrap();
            refresh_zone(&node, &kp).await.unwrap();
            assert!(matches!(resolve(&node, zone_id, "big").await, TnsResolution::NotFound));
            assert!(matches!(resolve(&node, zone_id, "small").await, TnsResolution::Records(_)));
        });
    }

    #[test]
    fn validate_records_rejects_wire_overflow() {
        // Lengths are u16 on the wire; longer must be refused, not truncated.
        assert!(validate_records(&[TnsRecord::Text("x".repeat(70_000))]).is_err());
        let many: Vec<TnsRecord> = (0..2_000).map(|_| TnsRecord::Text("y".repeat(40))).collect();
        assert!(validate_records(&many).is_err(), "set length prefix overflows");
    }

    #[test]
    fn delegated_apex_vhost_surfaces_as_vhost() {
        // `friend` delegates to a zone whose apex is a VHost: resolving
        // `friend` must yield the VHost endpoint (canonical label "@"), not a
        // raw record set the connector can't derive a wire port from.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone_id = node.default_service_id().await;
            let me = node.keypair_for_service(&zone_id).await.unwrap();
            let friend = Keypair::generate();
            let friend_id = friend.identity.service_id();
            let serving = ServiceId::from_signing_pubkey(&[0x77; 32]);

            publish(&node, &friend, "@", &[TnsRecord::VHost(serving)]).await.unwrap();
            publish(&node, &me, "friend", &[TnsRecord::Zone(friend_id)]).await.unwrap();

            match resolve_name(&node, "friend").await {
                TnsResolution::VHost { serving: s, canonical_label } => {
                    assert_eq!(s, serving);
                    assert_eq!(canonical_label, "@");
                }
                other => panic!("expected VHost, got {:?}", other),
            }
        });
    }

    #[test]
    fn unpublished_local_labels_resolve_like_any_zone() {
        // Private petnames live only in the label table. They must resolve
        // with the same rules as published names: a Zone petname follows to
        // its apex, an alias is followed, and a name below a non-Zone label
        // is an error rather than that label's records.
        use crate::state::{StateDb, StorageLimits};
        let path = std::env::temp_dir().join(format!(
            "tarnet-local-resolve-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = std::sync::Arc::new(StateDb::open(&path).unwrap());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::with_db(Keypair::generate(), db.clone(), StorageLimits::default());
            let friend = Keypair::generate();
            let friend_id = friend.identity.service_id();
            let target = ServiceId::from_signing_pubkey(&[0x55; 32]);
            publish(&node, &friend, "@", &[TnsRecord::Identity(target)]).await.unwrap();

            let set = |label: &str, rec: TnsRecord| {
                db.label_set("", label, &[tns_record_to_bytes(&rec)], false).unwrap()
            };
            set("pal", TnsRecord::Zone(friend_id));
            set("buddy", TnsRecord::Alias("pal".into()));
            set("server", TnsRecord::Identity(target));

            for name in ["pal", "buddy"] {
                match resolve_name(&node, name).await {
                    TnsResolution::Records(r) => assert_eq!(r, vec![TnsRecord::Identity(target)], "{name}"),
                    other => panic!("{name}: expected apex Identity, got {:?}", other),
                }
            }
            assert!(matches!(
                resolve_name(&node, "www.server").await,
                TnsResolution::Error(_)
            ));
        });
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn label_sequence_beats_held_key_descriptor() {
        // A zone key moved to a node whose counter is lower (or a lost db):
        // the old, higher-sequence root is held here. Re-signing must climb
        // above it, or the local store refuses the new root and publish fails.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone_id = node.default_service_id().await;
            let kp = node.keypair_for_service(&zone_id).await.unwrap();
            let old = crate::dht::VerifiedRecord::new_zone_key(
                &kp,
                1_000_000,
                Duration::from_secs(ZONE_ROOT_TTL as u64),
            );
            node.dht_store_insert_local_for_test(old.into_inner()).await;

            publish(&node, &kp, "www", &[TnsRecord::Text("new".into())]).await.unwrap();
            let records = held_label(&node, &kp, "www").await;
            assert_eq!(records, vec![TnsRecord::Text("new".into())]);
            assert!(node.next_dht_sequence().await > 1_000_000);
        });
    }

    #[test]
    fn failed_intro_registration_keeps_other_labels_and_drops_intro() {
        // No relays: intro registration fails. The stale intro points must
        // stop being signed, and the zone's other labels must stay in the root.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let node = Node::new(Keypair::generate());
            let zone_id = node.default_service_id().await;
            let kp = node.keypair_for_service(&zone_id).await.unwrap();
            let stale_intro = TnsRecord::IntroductionPoint {
                relay_peer_id: PeerId([0x33; 32]),
                kem_algo: 0,
                kem_pubkey: vec![1, 2, 3],
            };
            publish(&node, &kp, "intro", &[stale_intro]).await.unwrap();
            publish(&node, &kp, "blog", &[TnsRecord::Text("kept".into())]).await.unwrap();

            assert!(node.publish_hidden_service(zone_id, 3).await.is_err());

            assert!(held_label(&node, &kp, "intro").await.is_empty());
            assert_eq!(
                held_label(&node, &kp, "blog").await,
                vec![TnsRecord::Text("kept".into())]
            );
        });
    }
}
