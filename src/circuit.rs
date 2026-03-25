//! Circuit-based forwarding: replaces origin/destination headers with opaque circuit IDs.
//!
//! A circuit is a path through the network where each relay only knows
//! the previous hop and next hop. Relays see `circuit_id || blob` — nothing else.
//!
//! Circuit setup is telescoping: the initiator extends the circuit one hop at a time,
//! encrypting each setup message to the target hop's public key.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use rand::RngCore;

use crate::crypto::{kdf, mac_16};
use crate::types::{Error, PeerId, Result};

/// Per-hop Poly1305 tag size.
const HOP_MAC_SIZE: usize = 16;
/// Explicit nonce size in the cell trailer.
const CELL_NONCE_SIZE: usize = 8;
/// Size of the encrypted body within a cell (before nonce + hop MAC).
pub const CELL_BODY_SIZE: usize = 1400;
/// Full cell size on the wire: encrypted body + nonce + per-hop MAC.
pub const CELL_SIZE: usize = CELL_BODY_SIZE + CELL_NONCE_SIZE + HOP_MAC_SIZE;
/// Header: command(1) + stream_id(2) + length(2).
const CELL_HEADER_SIZE: usize = 5;
/// BLAKE2b-128 digest for integrity at the endpoint.
const DIGEST_SIZE: usize = 16;
/// Maximum payload bytes in a single relay cell.
pub const CELL_PAYLOAD_MAX: usize = CELL_BODY_SIZE - CELL_HEADER_SIZE - DIGEST_SIZE;

// --- Flow control constants ---
/// Initial congestion window. Must be > SENDME_INC so the sender can push
/// enough cells to trigger the first SENDME from the receiver.
pub const CWND_INIT: u32 = SENDME_INC * 2;
pub const CWND_MIN: u32 = SENDME_INC + 1;
pub const CWND_MAX: u32 = 2048;
pub const SENDME_INC: u32 = 32;
pub const SS_MAX: u32 = 512;
/// How long a sender waits while window-blocked before assuming the SENDME was lost.
pub const SENDME_STALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Receiver-side window: how many DATA cells we accept before a SENDME is acked.
/// Set larger than CWND_MAX so legitimate senders never hit it, but misbehaving
/// senders that ignore SENDMEs get dropped.
pub const RECV_WINDOW_INIT: u32 = 1024;
/// Maximum cells we'll tolerate beyond what we've SENDME'd for.
/// If the sender overshoots by more than this, we drop the cell.
pub const RECV_WINDOW_OVERSHOOT: u32 = SENDME_INC * 2;

/// A circuit ID: 4-byte identifier, unique per-link.
pub type CircuitId = u32;

/// Direction-aware circuit table key: (circuit_id, from_peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitKey {
    pub circuit_id: CircuitId,
    pub from_peer: PeerId,
}

/// Crypto operation applied by a relay when processing a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOp {
    /// Decrypt one onion layer (forward direction: initiator → endpoint).
    Decrypt,
    /// Encrypt one onion layer (backward direction: endpoint → initiator).
    Encrypt,
}

/// Per-hop crypto state stored in a circuit forwarding entry.
/// Relays use this to peel/add one onion layer as cells pass through.
///
/// The nonce is carried explicitly in the cell trailer (8 bytes) rather than
/// tracked as an implicit counter. This allows the scheme to survive
/// unreliable (UDP-like) transports where cells may be dropped or reordered.
/// A sliding-window bitmap rejects replayed cells.
#[derive(Debug, Clone)]
pub struct HopCrypto {
    pub key: [u8; 32],
    /// Digest key for relay cell integrity at endpoints.
    pub digest_key: [u8; 32],
    /// Per-circuit nonce prefix derived from shared secret.
    /// Ensures nonce uniqueness even if keys are accidentally reused.
    pub nonce_prefix: [u8; 16],
    pub op: CryptoOp,
    /// Replay window for this hop (only meaningful for Decrypt).
    pub replay: ReplayWindow,
}

impl HopCrypto {
    /// Process a cell through this hop's crypto layer.
    ///
    /// The 8-byte nonce is read from `cell[CELL_BODY_SIZE..CELL_BODY_SIZE+8]`.
    ///
    /// **Decrypt** (relay peeling a forward layer / initiator peeling backward):
    ///   - Reads the nonce from the cell trailer.
    ///   - Checks the replay window; returns `false` if replayed/too old.
    ///   - Verifies the hop MAC; returns `false` if it doesn't match.
    ///   - Decrypts the body in place and zeros the nonce+MAC trailer.
    ///   - Returns `true` on success.
    ///   - Note: inner onion layers will always fail MAC because the outermost
    ///     hop's MAC overwrites theirs — callers that are not the outermost
    ///     hop should ignore the return value.
    ///
    /// **Encrypt** (relay adding a backward layer):
    ///   - Reads the nonce from the cell trailer (set by the sender/previous hop).
    ///   - Encrypts the body, then writes the hop MAC. Nonce is preserved.
    ///   - Always returns `true`.
    pub fn process_cell(&mut self, cell: &mut [u8; CELL_SIZE]) -> bool {
        let nonce_val = cell_nonce(cell);
        let nonce = build_nonce(&self.nonce_prefix, nonce_val);
        let aead = XChaCha20Poly1305::new((&self.key).into());
        match self.op {
            CryptoOp::Decrypt => {
                if !self.replay.accept(nonce_val) {
                    return false;
                }
                let mac_start = CELL_BODY_SIZE + CELL_NONCE_SIZE;
                let tag: [u8; 16] = cell[mac_start..].try_into().unwrap();
                let ok = aead
                    .decrypt_in_place_detached(
                        (&nonce).into(),
                        b"",
                        &mut cell[..CELL_BODY_SIZE],
                        (&tag).into(),
                    )
                    .is_ok();
                if !ok {
                    // Inner onion layer: tag was overwritten by outer hop.
                    // AEAD decrypt didn't modify the buffer, so apply
                    // keystream directly (ChaCha20 encrypt == decrypt).
                    let _ = aead.encrypt_in_place_detached(
                        (&nonce).into(),
                        b"",
                        &mut cell[..CELL_BODY_SIZE],
                    );
                }
                // Zero the tag but preserve the nonce — relays forward
                // the cell to the next hop which needs the same nonce.
                cell[mac_start..].fill(0);
                ok
            }
            CryptoOp::Encrypt => {
                let tag = aead
                    .encrypt_in_place_detached((&nonce).into(), b"", &mut cell[..CELL_BODY_SIZE])
                    .expect("AEAD encryption should not fail");
                // Preserve the nonce, overwrite the tag.
                let mac_start = CELL_BODY_SIZE + CELL_NONCE_SIZE;
                cell[mac_start..].copy_from_slice(&tag);
                true
            }
        }
    }
}

/// What a relay does with a circuit cell.
#[derive(Debug, Clone)]
pub enum CircuitAction {
    /// Forward to the next hop with a rewritten circuit_id.
    Forward {
        next_hop: PeerId,
        next_circuit_id: CircuitId,
        /// Onion layer crypto for this forwarding direction (None for legacy/tests).
        crypto: Option<HopCrypto>,
    },
    /// This is the circuit endpoint — deliver to the local node.
    Endpoint {
        /// The PeerId of the circuit originator (as known to us).
        /// For a multi-hop circuit, this is the previous hop, not the true origin.
        origin_hop: PeerId,
        /// Onion layer crypto for inbound cells.
        crypto: Option<HopCrypto>,
    },
}

/// Circuit forwarding table.
///
/// Maps (incoming_circuit_id, from_peer) → action.
/// Relays use this for blind forwarding. Endpoints use it to identify incoming circuits.
pub struct CircuitTable {
    /// Forwarding entries: key → action.
    entries: HashMap<CircuitKey, CircuitAction>,
}

impl CircuitTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Allocate a random circuit ID for a link where we know whether we initiated it.
    ///
    /// Link initiators get odd IDs, responders get even.  Since the remote
    /// peer uses the opposite parity on the same link, the circuit_table
    /// entry it creates (keyed by the remote's chosen circuit_id) can never
    /// collide with our outbound_circuits entry for the same peer.
    ///
    /// IDs are chosen randomly to avoid leaking circuit count or timing
    /// information to peers.
    pub fn alloc_id(
        &self,
        we_initiated_link: bool,
        is_taken: impl Fn(CircuitId) -> bool,
    ) -> CircuitId {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        loop {
            let raw: u32 = rng.gen();
            let id = if we_initiated_link { raw | 1 } else { raw & !1 };
            if id != 0 && !is_taken(id) {
                return id;
            }
        }
    }

    /// Install a forwarding entry.
    pub fn insert(&mut self, key: CircuitKey, action: CircuitAction) {
        self.entries.insert(key, action);
    }

    /// Look up what to do with an incoming circuit cell.
    pub fn lookup(&self, key: &CircuitKey) -> Option<&CircuitAction> {
        self.entries.get(key)
    }

    /// Mutable lookup — needed for updating nonce counters during onion processing.
    pub fn lookup_mut(&mut self, key: &CircuitKey) -> Option<&mut CircuitAction> {
        self.entries.get_mut(key)
    }

    /// Remove a circuit entry (teardown).
    pub fn remove(&mut self, key: &CircuitKey) -> Option<CircuitAction> {
        self.entries.remove(key)
    }

    /// Remove all entries involving a given peer (link went down).
    /// Returns the circuit IDs that were removed, paired with the from_peer
    /// that keyed each entry, so callers can clean up associated state.
    pub fn remove_peer(&mut self, peer: &PeerId) -> Vec<(u32, PeerId)> {
        let mut removed = Vec::new();
        self.entries.retain(|k, v| {
            let keep = k.from_peer != *peer
                && !matches!(v, CircuitAction::Forward { next_hop, .. } if next_hop == peer);
            if !keep {
                removed.push((k.circuit_id, k.from_peer));
            }
            keep
        });
        removed
    }

    /// Number of active circuit entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn entries_iter(&self) -> impl Iterator<Item = (&CircuitKey, &CircuitAction)> {
        self.entries.iter()
    }

    /// Count forwarding entries (we're a relay, not the endpoint).
    pub fn forward_count(&self) -> usize {
        self.entries
            .values()
            .filter(|a| matches!(a, CircuitAction::Forward { .. }))
            .count()
    }

    /// Count endpoint entries (circuit terminates at this node).
    pub fn endpoint_count(&self) -> usize {
        self.entries
            .values()
            .filter(|a| matches!(a, CircuitAction::Endpoint { .. }))
            .count()
    }

    /// Count circuit entries involving each peer (as from_peer or next_hop).
    /// Used by link eviction to score how many circuits depend on each neighbor.
    pub fn circuits_per_peer(&self) -> HashMap<PeerId, usize> {
        let mut counts = HashMap::new();
        for (key, action) in &self.entries {
            *counts.entry(key.from_peer).or_insert(0) += 1;
            if let CircuitAction::Forward { next_hop, .. } = action {
                *counts.entry(*next_hop).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Count circuit entries involving a single peer (as from_peer or next_hop).
    /// O(entries) but avoids allocating a HashMap — use on the hot message path.
    pub fn circuits_for_peer(&self, peer: &PeerId) -> usize {
        let mut count = 0;
        for (key, action) in &self.entries {
            if key.from_peer == *peer {
                count += 1;
            }
            if let CircuitAction::Forward { next_hop, .. } = action {
                if next_hop == peer {
                    count += 1;
                }
            }
        }
        count
    }
}

// ---------------------------------------------------------------------------
// Nonce construction
// ---------------------------------------------------------------------------

/// Build a 24-byte XChaCha20 nonce from a per-circuit prefix and counter.
/// Format: prefix (16) || counter_le (8)
fn build_nonce(prefix: &[u8; 16], counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Read the 8-byte explicit nonce from a cell's trailer.
fn cell_nonce(cell: &[u8; CELL_SIZE]) -> u64 {
    let bytes: [u8; 8] = cell[CELL_BODY_SIZE..CELL_BODY_SIZE + CELL_NONCE_SIZE]
        .try_into()
        .unwrap();
    u64::from_le_bytes(bytes)
}

/// Write the 8-byte explicit nonce into a cell's trailer.
fn set_cell_nonce(cell: &mut [u8; CELL_SIZE], nonce: u64) {
    cell[CELL_BODY_SIZE..CELL_BODY_SIZE + CELL_NONCE_SIZE].copy_from_slice(&nonce.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Replay window (sliding bitmap)
// ---------------------------------------------------------------------------

const REPLAY_WINDOW_SIZE: u64 = 2048;
/// Number of u64 words in the bitmap.
const REPLAY_BITMAP_WORDS: usize = (REPLAY_WINDOW_SIZE / 64) as usize;

/// Sliding-window replay protection.
///
/// Tracks the highest accepted nonce and a bitmap of the last
/// `REPLAY_WINDOW_SIZE` nonces. Rejects duplicates and nonces
/// older than the window.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest nonce accepted so far. Starts at 0 (no cells seen).
    max_seen: u64,
    /// Bitmap: bit `(nonce % REPLAY_WINDOW_SIZE)` is set if that nonce
    /// has already been accepted.
    bitmap: [u64; REPLAY_BITMAP_WORDS],
    /// Whether any nonce has been seen yet.
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            max_seen: 0,
            bitmap: [0u64; REPLAY_BITMAP_WORDS],
            initialized: false,
        }
    }

    /// Check and accept a nonce. Returns `true` if the nonce is fresh
    /// (not replayed and not too old). Returns `false` to reject.
    pub fn accept(&mut self, nonce: u64) -> bool {
        if !self.initialized {
            // First cell ever — accept and initialize.
            self.initialized = true;
            self.max_seen = nonce;
            self.set_bit(nonce);
            return true;
        }

        if nonce > self.max_seen {
            // Ahead of window — advance.
            let advance = nonce - self.max_seen;
            if advance >= REPLAY_WINDOW_SIZE {
                // Jumped far ahead — clear entire bitmap.
                self.bitmap = [0u64; REPLAY_BITMAP_WORDS];
            } else {
                // Clear bits for the positions we're skipping over.
                for i in (self.max_seen + 1)..=nonce {
                    self.clear_bit(i);
                }
            }
            self.max_seen = nonce;
            self.set_bit(nonce);
            true
        } else if self.max_seen - nonce >= REPLAY_WINDOW_SIZE {
            // Too old — outside the window.
            false
        } else if self.get_bit(nonce) {
            // Already seen — replay.
            false
        } else {
            // Within window and fresh.
            self.set_bit(nonce);
            true
        }
    }

    fn set_bit(&mut self, nonce: u64) {
        let idx = (nonce % REPLAY_WINDOW_SIZE) as usize;
        self.bitmap[idx / 64] |= 1u64 << (idx % 64);
    }

    fn clear_bit(&mut self, nonce: u64) {
        let idx = (nonce % REPLAY_WINDOW_SIZE) as usize;
        self.bitmap[idx / 64] &= !(1u64 << (idx % 64));
    }

    fn get_bit(&self, nonce: u64) -> bool {
        let idx = (nonce % REPLAY_WINDOW_SIZE) as usize;
        self.bitmap[idx / 64] & (1u64 << (idx % 64)) != 0
    }
}

// ---------------------------------------------------------------------------
// Relay cell inner format
// ---------------------------------------------------------------------------

/// Commands carried inside relay cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCellCommand {
    Data = 0x01,
    Sendme = 0x02,
    StreamBegin = 0x03,
    StreamEnd = 0x04,
    Extend = 0x05,
    Extended = 0x06,
    Introduce = 0x07,
    IntroduceAck = 0x08,
    RendezvousEstablish = 0x09,
    RendezvousJoin = 0x0A,
    RendezvousJoined = 0x0B,
    IntroRegister = 0x0C,
    IntroRegistered = 0x0D,
    StreamConnected = 0x0E,
    StreamRefused = 0x0F,
    /// Circuit keepalive: sent end-to-end, echoed back by endpoint.
    Padding = 0x10,
}

impl RelayCellCommand {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Sendme),
            0x03 => Ok(Self::StreamBegin),
            0x04 => Ok(Self::StreamEnd),
            0x05 => Ok(Self::Extend),
            0x06 => Ok(Self::Extended),
            0x07 => Ok(Self::Introduce),
            0x08 => Ok(Self::IntroduceAck),
            0x09 => Ok(Self::RendezvousEstablish),
            0x0A => Ok(Self::RendezvousJoin),
            0x0B => Ok(Self::RendezvousJoined),
            0x0C => Ok(Self::IntroRegister),
            0x0D => Ok(Self::IntroRegistered),
            0x0E => Ok(Self::StreamConnected),
            0x0F => Ok(Self::StreamRefused),
            0x10 => Ok(Self::Padding),
            _ => Err(Error::Wire(format!("unknown relay cell command: {:#x}", v))),
        }
    }
}

/// Parsed relay cell (after onion decryption at the endpoint).
///
/// Wire format (always CELL_SIZE bytes total):
///   command(1) || stream_id(2) || length(2) || digest(16) || payload(length) || padding
#[derive(Debug, Clone)]
pub struct RelayCell {
    pub command: RelayCellCommand,
    pub stream_id: u16,
    pub data: Vec<u8>,
}

/// Serialize relay cell fields directly into a fixed-size cell body with digest.
/// Avoids constructing a RelayCell struct and the Vec<u8> allocation for data.
pub fn write_cell_body(
    command: RelayCellCommand,
    stream_id: u16,
    data: &[u8],
    digest_key: &[u8; 32],
) -> [u8; CELL_BODY_SIZE] {
    assert!(
        data.len() <= CELL_PAYLOAD_MAX,
        "relay cell data ({} bytes) exceeds CELL_PAYLOAD_MAX ({} bytes) — caller must chunk",
        data.len(),
        CELL_PAYLOAD_MAX,
    );
    let mut cell = [0u8; CELL_BODY_SIZE];
    let len = data.len();
    cell[0] = command as u8;
    cell[1..3].copy_from_slice(&stream_id.to_be_bytes());
    cell[3..5].copy_from_slice(&(len as u16).to_be_bytes());

    let digest = relay_cell_digest(digest_key, &cell[..5], &data[..len]);
    cell[5..5 + DIGEST_SIZE].copy_from_slice(&digest);

    cell[5 + DIGEST_SIZE..5 + DIGEST_SIZE + len].copy_from_slice(&data[..len]);
    cell
}

impl RelayCell {
    /// Serialize into a fixed-size cell body with digest, ready for onion wrapping.
    /// `digest_key` is the endpoint's forward digest key.
    pub fn to_cell(&self, digest_key: &[u8; 32]) -> [u8; CELL_BODY_SIZE] {
        write_cell_body(self.command, self.stream_id, &self.data, digest_key)
    }

    /// Parse a fully-decrypted cell body and verify its digest.
    /// `digest_key` is the endpoint's forward digest key.
    pub fn from_cell(cell: &[u8; CELL_BODY_SIZE], digest_key: &[u8; 32]) -> Result<Self> {
        let command = RelayCellCommand::from_u8(cell[0])?;
        let stream_id = u16::from_be_bytes([cell[1], cell[2]]);
        let length = u16::from_be_bytes([cell[3], cell[4]]) as usize;

        if length > CELL_PAYLOAD_MAX {
            return Err(Error::Wire("relay cell length exceeds max".into()));
        }

        let stored_digest = &cell[5..5 + DIGEST_SIZE];
        let payload = &cell[5 + DIGEST_SIZE..5 + DIGEST_SIZE + length];

        let expected = relay_cell_digest(digest_key, &cell[..5], payload);
        if stored_digest != expected {
            return Err(Error::Crypto("relay cell digest mismatch".into()));
        }

        Ok(Self {
            command,
            stream_id,
            data: payload.to_vec(),
        })
    }
}

/// Compute a digest of DATA cell payload for SENDME authentication.
/// This allows the receiver to prove it actually received the data.
/// Uses a fixed key — not for secrecy, just for consistent hashing.
pub fn relay_cell_digest_for_sendme(payload: &[u8]) -> [u8; DIGEST_SIZE] {
    let key = b"tarnet_sendme_digest_key________"; // 32 bytes
    mac_16(key, &[payload])
}

/// 16-byte digest for relay cell integrity.
fn relay_cell_digest(digest_key: &[u8; 32], header: &[u8], payload: &[u8]) -> [u8; DIGEST_SIZE] {
    mac_16(digest_key, &[header, payload])
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// The symmetric keys derived for a circuit hop.
pub struct HopKeys {
    pub forward_key: [u8; 32],
    pub forward_digest: [u8; 32],
    pub backward_key: [u8; 32],
    pub backward_digest: [u8; 32],
    /// Per-circuit nonce prefix derived from shared secret.
    pub nonce_prefix: [u8; 16],
}

/// Derive the symmetric keys for a circuit hop from a DH shared secret.
pub fn derive_hop_keys(shared_secret: &[u8; 32]) -> HopKeys {
    let nonce_material = kdf(shared_secret, "tarnet circuit nonce");
    let mut nonce_prefix = [0u8; 16];
    nonce_prefix.copy_from_slice(&nonce_material[..16]);
    HopKeys {
        forward_key: kdf(shared_secret, "tarnet circuit hop enc"),
        forward_digest: kdf(shared_secret, "tarnet circuit hop enc digest"),
        backward_key: kdf(shared_secret, "tarnet circuit hop dec"),
        backward_digest: kdf(shared_secret, "tarnet circuit hop dec digest"),
        nonce_prefix,
    }
}

// ---------------------------------------------------------------------------
// Initiator-side circuit state
// ---------------------------------------------------------------------------

/// Per-hop symmetric keys held by the circuit initiator.
///
/// The nonce is NOT stored per-hop. Instead, a single per-cell nonce is
/// chosen by the sender (OutboundCircuit) and written into the cell trailer.
/// All hops read it from there.
#[derive(Debug, Clone)]
pub struct HopKey {
    /// Key for encrypting cells toward the endpoint (forward direction).
    pub forward_key: [u8; 32],
    /// Digest key for forward relay cell integrity.
    pub forward_digest: [u8; 32],
    /// Key for decrypting cells from the endpoint (backward direction).
    pub backward_key: [u8; 32],
    /// Digest key for backward relay cell integrity.
    pub backward_digest: [u8; 32],
    /// Per-circuit nonce prefix derived from shared secret.
    pub nonce_prefix: [u8; 16],
}

impl HopKey {
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> Self {
        let keys = derive_hop_keys(shared_secret);
        Self {
            forward_key: keys.forward_key,
            forward_digest: keys.forward_digest,
            backward_key: keys.backward_key,
            backward_digest: keys.backward_digest,
            nonce_prefix: keys.nonce_prefix,
        }
    }

    /// Like `from_shared_secret` but with forward/backward swapped.
    /// Used by the responder side of an end-to-end key exchange so that
    /// the responder's "forward" decrypts the initiator's "forward" and
    /// vice versa.
    pub fn from_shared_secret_responder(shared_secret: &[u8; 32]) -> Self {
        let keys = derive_hop_keys(shared_secret);
        Self {
            forward_key: keys.backward_key,
            forward_digest: keys.backward_digest,
            backward_key: keys.forward_key,
            backward_digest: keys.forward_digest,
            nonce_prefix: keys.nonce_prefix,
        }
    }

    /// Encrypt one onion layer (forward direction).
    /// Reads the nonce from the cell trailer, encrypts the body,
    /// then computes and writes the hop tag. Nonce is preserved.
    pub fn encrypt_forward(&self, cell: &mut [u8; CELL_SIZE]) {
        let nonce_val = cell_nonce(cell);
        let nonce = build_nonce(&self.nonce_prefix, nonce_val);
        let aead = XChaCha20Poly1305::new((&self.forward_key).into());
        let tag = aead
            .encrypt_in_place_detached((&nonce).into(), b"", &mut cell[..CELL_BODY_SIZE])
            .expect("AEAD encryption should not fail");
        let mac_start = CELL_BODY_SIZE + CELL_NONCE_SIZE;
        cell[mac_start..].copy_from_slice(&tag);
    }

    /// Decrypt one onion layer (backward direction).
    /// Reads the nonce from the cell trailer, decrypts the body.
    /// Only the outermost layer's tag survives; inner tags are overwritten.
    pub fn decrypt_backward(&self, cell: &mut [u8; CELL_SIZE]) {
        let nonce_val = cell_nonce(cell);
        let nonce = build_nonce(&self.nonce_prefix, nonce_val);
        let aead = XChaCha20Poly1305::new((&self.backward_key).into());
        // Use encrypt_in_place_detached for decryption: ChaCha20 is a
        // symmetric stream cipher (encrypt == decrypt). This avoids
        // AEAD tag verification, which would fail for inner onion layers
        // whose tags are overwritten by outer layers.
        let _ = aead.encrypt_in_place_detached((&nonce).into(), b"", &mut cell[..CELL_BODY_SIZE]);
        // Zero the tag but preserve the nonce for multi-hop decryption.
        cell[CELL_BODY_SIZE + CELL_NONCE_SIZE..].fill(0);
    }
}

/// State of a circuit being built or in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// Building: extending toward waypoints via DV routing.
    Extending { hops_built: usize },
    /// Ready for use.
    Ready,
    /// Destroyed.
    Destroyed,
}

/// A circuit we initiated (outbound).
#[derive(Debug)]
pub struct OutboundCircuit {
    /// Circuit ID on our link to the first hop.
    pub first_hop_circuit_id: CircuitId,
    /// First hop PeerId (our direct neighbor).
    pub first_hop: PeerId,
    /// Per-hop symmetric keys, in order from first to last hop.
    pub hop_keys: Vec<HopKey>,
    /// Current state of the circuit.
    pub state: CircuitState,
    /// Waypoints this circuit routes through (the originator's view, not actual hops).
    pub waypoints: Vec<PeerId>,
    /// Flow control state.
    pub congestion: CongestionWindow,
    /// Last time we received any relay cell on this circuit.
    pub last_activity: Instant,
    /// Forward nonce counter — one counter shared by all hops for a given cell.
    pub forward_nonce: u64,
}

impl OutboundCircuit {
    /// Wrap a relay cell in all onion layers for sending through the circuit.
    /// Sets the explicit nonce in the cell trailer before encrypting.
    pub fn wrap_forward(&mut self, cell: &mut [u8; CELL_SIZE]) {
        let nonce = self.forward_nonce;
        self.forward_nonce += 1;
        set_cell_nonce(cell, nonce);
        // Encrypt in reverse hop order: innermost (endpoint) first, outermost (hop 1) last.
        for hop in self.hop_keys.iter().rev() {
            hop.encrypt_forward(cell);
        }
    }

    /// Unwrap all onion layers from a cell received through the circuit (backward direction).
    /// The nonce is read from the cell trailer (set by the endpoint).
    /// Returns the plaintext cell bytes — caller should parse with `RelayCell::from_cell()`.
    pub fn unwrap_backward(&self, cell: &mut [u8; CELL_SIZE]) {
        // Decrypt in forward hop order: outermost (hop 1) first, innermost (endpoint) last.
        for hop in self.hop_keys.iter() {
            hop.decrypt_backward(cell);
        }
    }

    /// Send a relay cell through this circuit. Returns (first_hop, circuit_id, encrypted_cell).
    pub fn send_relay_cell(
        &mut self,
        relay_cell: &RelayCell,
    ) -> (PeerId, CircuitId, [u8; CELL_SIZE]) {
        let last = self.hop_keys.len() - 1;
        self.send_to_hop(relay_cell, last)
    }

    /// Send a DATA cell through this circuit without constructing a RelayCell.
    /// Avoids a Vec<u8> allocation for the data payload on the hot path.
    pub fn send_data_cell(
        &mut self,
        data: &[u8],
    ) -> (PeerId, CircuitId, [u8; CELL_SIZE]) {
        let last = self.hop_keys.len() - 1;
        let digest_key = self.hop_keys[last].forward_digest;
        let body = write_cell_body(RelayCellCommand::Data, 0, data, &digest_key);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        let nonce = self.forward_nonce;
        self.forward_nonce += 1;
        set_cell_nonce(&mut cell, nonce);
        for hop in self.hop_keys[..=last].iter().rev() {
            hop.encrypt_forward(&mut cell);
        }
        (self.first_hop, self.first_hop_circuit_id, cell)
    }

    /// Receive and decrypt a relay cell from this circuit.
    pub fn recv_relay_cell(&mut self, cell: &mut [u8; CELL_SIZE]) -> Result<RelayCell> {
        let last = self.hop_keys.len() - 1;
        self.recv_from_hop(cell, last)
    }

    /// Send a relay cell to a specific intermediate hop (for EXTEND during construction).
    /// `hop_index` is 0-based (0 = first hop, which is the current endpoint during extension).
    pub fn send_to_hop(
        &mut self,
        relay_cell: &RelayCell,
        hop_index: usize,
    ) -> (PeerId, CircuitId, [u8; CELL_SIZE]) {
        let digest_key = self.hop_keys[hop_index].forward_digest;
        let body = relay_cell.to_cell(&digest_key);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        // Set the explicit nonce and encrypt layers from hop_index down to 0.
        let nonce = self.forward_nonce;
        self.forward_nonce += 1;
        set_cell_nonce(&mut cell, nonce);
        for hop in self.hop_keys[..=hop_index].iter().rev() {
            hop.encrypt_forward(&mut cell);
        }
        (self.first_hop, self.first_hop_circuit_id, cell)
    }

    /// Receive and decrypt a relay cell from a specific intermediate hop.
    /// The nonce is read from the cell trailer.
    pub fn recv_from_hop(&self, cell: &mut [u8; CELL_SIZE], hop_index: usize) -> Result<RelayCell> {
        for hop in self.hop_keys[..=hop_index].iter() {
            hop.decrypt_backward(cell);
        }
        let digest_key = self.hop_keys[hop_index].backward_digest;
        let body: &[u8; CELL_BODY_SIZE] = cell[..CELL_BODY_SIZE].try_into().unwrap();
        RelayCell::from_cell(body, &digest_key)
    }
}

// ---------------------------------------------------------------------------
// Congestion window (AIMD)
// ---------------------------------------------------------------------------

/// AIMD congestion control state for a circuit.
///
/// Each direction of a circuit has its own `CongestionWindow`:
/// - **Sender side**: tracks `cwnd` / `inflight`, gates sends via `can_send()`.
/// - **Receiver side**: tracks `recv_allowed` (credit window), drops cells that
///   exceed the window, and signals when to send a SENDME back.
#[derive(Debug, Clone)]
pub struct CongestionWindow {
    // --- Sender side ---
    pub cwnd: u32,
    pub inflight: u32,
    pub slow_start: bool,
    // --- Receiver side ---
    /// Cells delivered since last SENDME was sent.
    pub deliver_count: u32,
    /// BLAKE2b-128 digest of the last DATA cell received (for authenticated SENDMEs).
    pub last_data_digest: [u8; DIGEST_SIZE],
    /// Remaining receive credit. When this hits 0, drop incoming DATA cells.
    /// Replenished by SENDME_INC each time we send a SENDME.
    pub recv_allowed: u32,
    // --- Stall detection ---
    /// When we last received a SENDME (or first became window-blocked).
    /// Used to detect lost SENDMEs and recover.
    pub last_sendme_at: Option<Instant>,
}

impl CongestionWindow {
    pub fn new() -> Self {
        Self {
            cwnd: CWND_INIT,
            inflight: 0,
            slow_start: true,
            deliver_count: 0,
            last_data_digest: [0u8; DIGEST_SIZE],
            recv_allowed: RECV_WINDOW_INIT,
            last_sendme_at: None,
        }
    }

    /// Check if we can send another cell.
    pub fn can_send(&self) -> bool {
        self.inflight < self.cwnd
    }

    /// Record that we sent a cell.
    pub fn on_send(&mut self) {
        self.inflight += 1;
    }

    /// Process a received SENDME acknowledgment.
    pub fn on_sendme(&mut self) {
        self.inflight = self.inflight.saturating_sub(SENDME_INC);
        self.last_sendme_at = Some(Instant::now());
        if self.slow_start {
            self.cwnd = (self.cwnd + SENDME_INC).min(CWND_MAX);
            if self.cwnd >= SS_MAX {
                self.slow_start = false;
            }
        } else {
            self.cwnd = (self.cwnd + 1).min(CWND_MAX);
        }
    }

    /// React to a timeout or loss event.
    pub fn on_loss(&mut self) {
        self.slow_start = false;
        self.cwnd = (self.cwnd / 2).max(CWND_MIN);
    }

    /// Check if the sender is stalled waiting for a lost SENDME.
    /// If blocked for longer than `SENDME_STALL_TIMEOUT`, assume the SENDME
    /// was lost: halve the window (loss event) and grant a small probe window
    /// so the sender can resume. The new data will trigger a fresh SENDME
    /// from the receiver.
    /// Returns true if a stall was detected and recovered.
    pub fn check_stall(&mut self) -> bool {
        if self.can_send() {
            return false; // not blocked
        }
        let stalled = match self.last_sendme_at {
            Some(t) => t.elapsed() >= SENDME_STALL_TIMEOUT,
            // Never received a SENDME — use a generous timeout for initial slow start.
            None => false,
        };
        if stalled {
            self.on_loss();
            // Reset inflight to open a probe window: allow SENDME_INC cells
            // so the sender can push enough data to trigger a new SENDME.
            self.inflight = self.cwnd.saturating_sub(SENDME_INC);
            self.last_sendme_at = Some(Instant::now());
            true
        } else {
            false
        }
    }

    /// Check if the receiver can accept another DATA cell.
    /// Returns false if the sender has exceeded the receive window.
    pub fn can_receive(&self) -> bool {
        self.recv_allowed > 0
    }

    /// Record delivery of a DATA cell (receiver side). Returns true if a SENDME should be sent.
    /// Caller must check `can_receive()` first — this decrements the receive credit.
    pub fn on_deliver(&mut self, cell_digest: [u8; DIGEST_SIZE]) -> bool {
        self.last_data_digest = cell_digest;
        self.recv_allowed = self.recv_allowed.saturating_sub(1);
        self.deliver_count += 1;
        if self.deliver_count >= SENDME_INC {
            self.deliver_count = 0;
            // Replenish receive credit when we send a SENDME
            self.recv_allowed += SENDME_INC;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// EXTEND / EXTENDED payload helpers
// ---------------------------------------------------------------------------

/// Build an EXTEND relay cell payload.
/// Format: kem_algo(1) || eph_pk_len(2 BE) || eph_pk(variable) || destination(32)
///
/// The destination is the waypoint target — the relay routes toward it via DV,
/// extending to its own best next_hop rather than requiring a direct link.
pub fn build_extend_payload(kem_algo: u8, eph_pk: &[u8], destination: &PeerId) -> Vec<u8> {
    let len = eph_pk.len() as u16;
    let mut payload = Vec::with_capacity(3 + eph_pk.len() + 32);
    payload.push(kem_algo);
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(eph_pk);
    payload.extend_from_slice(destination.as_bytes());
    payload
}

/// Parse an EXTEND relay cell payload.
/// Returns (kem_algo, ephemeral_pubkey, destination).
pub fn parse_extend_payload(data: &[u8]) -> Result<(u8, Vec<u8>, PeerId)> {
    if data.len() < 3 {
        return Err(Error::Wire("EXTEND payload too short".into()));
    }
    let kem_algo = data[0];
    let eph_pk_len = u16::from_be_bytes([data[1], data[2]]) as usize;
    let min_len = 3 + eph_pk_len + 32;
    if data.len() < min_len {
        return Err(Error::Wire("EXTEND payload too short".into()));
    }
    let eph_pk = data[3..3 + eph_pk_len].to_vec();
    let offset = 3 + eph_pk_len;
    let mut peer_bytes = [0u8; 32];
    peer_bytes.copy_from_slice(&data[offset..offset + 32]);
    Ok((kem_algo, eph_pk, PeerId(peer_bytes)))
}

/// Build an EXTENDED relay cell payload.
/// Format: kem_algo(1) || reply_len(2 BE) || reply(variable)
/// Flag in EXTENDED payload: the extend reached the requested destination.
pub const EXTENDED_FLAG_REACHED: u8 = 0x01;

pub fn build_extended_payload(kem_algo: u8, reply: &[u8]) -> Vec<u8> {
    let len = reply.len() as u16;
    let mut payload = Vec::with_capacity(4 + reply.len());
    payload.push(0u8); // flags — relay sets EXTENDED_FLAG_REACHED when waypoint reached
    payload.push(kem_algo);
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(reply);
    payload
}

/// Parse an EXTENDED relay cell payload.
/// Returns (reached, kem_algo, reply).
pub fn parse_extended_payload(data: &[u8]) -> Result<(bool, u8, Vec<u8>)> {
    if data.len() < 4 {
        return Err(Error::Wire("EXTENDED payload too short".into()));
    }
    let reached = (data[0] & EXTENDED_FLAG_REACHED) != 0;
    let kem_algo = data[1];
    let reply_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + reply_len {
        return Err(Error::Wire("EXTENDED payload too short".into()));
    }
    let reply = data[4..4 + reply_len].to_vec();
    Ok((reached, kem_algo, reply))
}

// ---------------------------------------------------------------------------
// STREAM_BEGIN / STREAM_END payload helpers
// ---------------------------------------------------------------------------

/// Build a STREAM_BEGIN relay cell payload.
/// Format: service_id(32) || mode(1) || port_len(2) || port(bytes)
pub fn build_stream_begin_payload(
    service_id: &tarnet_api::types::ServiceId,
    mode: tarnet_api::service::PortMode,
    port: &str,
) -> Vec<u8> {
    let port_bytes = port.as_bytes();
    let port_len = u16::try_from(port_bytes.len()).expect("port name too long");
    let mut payload = Vec::with_capacity(35 + port_bytes.len());
    payload.extend_from_slice(service_id.as_bytes());
    payload.push(mode as u8);
    payload.extend_from_slice(&port_len.to_be_bytes());
    payload.extend_from_slice(port_bytes);
    payload
}

/// Parse a STREAM_BEGIN relay cell payload.
/// Returns (service_id, mode, port).
pub fn parse_stream_begin_payload(
    data: &[u8],
) -> Result<(
    tarnet_api::types::ServiceId,
    tarnet_api::service::PortMode,
    String,
)> {
    if data.len() < 35 {
        return Err(Error::Wire("STREAM_BEGIN payload too short".into()));
    }
    let mut sid = [0u8; 32];
    sid.copy_from_slice(&data[..32]);
    let mode = match data[32] {
        0 => tarnet_api::service::PortMode::ReliableOrdered,
        1 => tarnet_api::service::PortMode::ReliableUnordered,
        2 => tarnet_api::service::PortMode::UnreliableUnordered,
        other => return Err(Error::Wire(format!("unknown port mode {}", other))),
    };
    let port_len = u16::from_be_bytes([data[33], data[34]]) as usize;
    if data.len() < 35 + port_len {
        return Err(Error::Wire("STREAM_BEGIN port truncated".into()));
    }
    let port = String::from_utf8(data[35..35 + port_len].to_vec())
        .map_err(|_| Error::Wire("STREAM_BEGIN port is not valid UTF-8".into()))?;
    Ok((tarnet_api::types::ServiceId(sid), mode, port))
}

// ---------------------------------------------------------------------------
// Rendezvous payload helpers
// ---------------------------------------------------------------------------

/// Encrypted INTRODUCE payload.
///
/// The inner plaintext is `rendezvous_peer_id(32) || cookie(32)` (64 bytes).
/// It is encrypted to the service's public key so that the introduction point
/// cannot learn which rendezvous peer / cookie belongs to which service.
///
/// Wire format: `eph_pubkey(32) || nonce(24) || ciphertext(64) || tag(16)` = 136 bytes.
///
/// Encryption uses KEM → KDF → XChaCha20-Poly1305 AEAD,
/// matching the patterns used elsewhere in tarnet.
/// Build an INTRODUCE payload encrypted to the service's KEM public key.
///
/// The client encapsulates to the service's KEM pubkey, producing a shared
/// secret and ciphertext. The shared secret encrypts the INTRODUCE body
/// and is also used later as the e2e session key.
///
/// Wire format: `ct_len(2 BE) || kem_ciphertext(variable) || nonce(24) || encrypted(64+16)`
pub fn build_introduce_payload(
    rendezvous_peer: &PeerId,
    cookie: &[u8; 32],
    mode: tarnet_api::service::PortMode,
    port: &str,
    kem_ciphertext: &[u8],
    shared_secret: &[u8; 32],
) -> Vec<u8> {
    let enc_key = kdf(shared_secret, "tarnet introduce enc");
    let port_bytes = port.as_bytes();
    let port_len = u16::try_from(port_bytes.len()).expect("port name too long");

    // Plaintext: rendezvous_peer(32) || cookie(32) || mode(1) || port_len(2) || port(bytes)
    let mut plaintext = Vec::with_capacity(67 + port_bytes.len());
    plaintext.extend_from_slice(rendezvous_peer.as_bytes());
    plaintext.extend_from_slice(cookie);
    plaintext.push(mode as u8);
    plaintext.extend_from_slice(&port_len.to_be_bytes());
    plaintext.extend_from_slice(port_bytes);

    let mut nonce = [0u8; 24];
    RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

    let aead = XChaCha20Poly1305::new((&enc_key).into());
    let ciphertext = aead
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &plaintext,
                aad: b"",
            },
        )
        .expect("AEAD encryption should not fail");

    // Wire: ct_len(2) || kem_ciphertext(variable) || nonce(24) || encrypted(plaintext+16)
    let ct_len = kem_ciphertext.len() as u16;
    let mut payload = Vec::with_capacity(2 + kem_ciphertext.len() + 24 + ciphertext.len());
    payload.extend_from_slice(&ct_len.to_be_bytes());
    payload.extend_from_slice(kem_ciphertext);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    payload
}

/// Parse and decrypt an INTRODUCE payload using the service's KEM keypair.
///
/// Returns `(rendezvous_peer_id, cookie, mode, port, shared_secret)`.
pub fn parse_introduce_payload(
    data: &[u8],
    service_kem: &crate::identity::KemKeypair,
) -> Result<(
    PeerId,
    [u8; 32],
    tarnet_api::service::PortMode,
    String,
    [u8; 32],
)> {
    if data.len() < 2 {
        return Err(Error::Wire("INTRODUCE payload too short".into()));
    }

    let ct_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let min_len = 2 + ct_len + 24 + 32 + 32 + 1 + 2 + 16;
    if data.len() < min_len {
        return Err(Error::Wire("INTRODUCE payload truncated".into()));
    }

    let kem_ct = &data[2..2 + ct_len];
    let nonce = &data[2 + ct_len..2 + ct_len + 24];
    let ciphertext_with_tag = &data[2 + ct_len + 24..];

    // Recover shared secret via KEM decapsulation
    let shared_bytes = service_kem
        .decapsulate(kem_ct)
        .map_err(|e| Error::Crypto(format!("INTRODUCE KEM decapsulate failed: {}", e)))?;

    let enc_key = kdf(&shared_bytes, "tarnet introduce enc");

    // Decrypt and verify via AEAD
    let aead = XChaCha20Poly1305::new((&enc_key).into());
    let plaintext = aead
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext_with_tag,
                aad: b"",
            },
        )
        .map_err(|_| Error::Crypto("INTRODUCE AEAD decryption failed".into()))?;

    let mut peer = [0u8; 32];
    peer.copy_from_slice(&plaintext[..32]);
    let mut cookie = [0u8; 32];
    cookie.copy_from_slice(&plaintext[32..64]);
    let mode = match plaintext[64] {
        0 => tarnet_api::service::PortMode::ReliableOrdered,
        1 => tarnet_api::service::PortMode::ReliableUnordered,
        2 => tarnet_api::service::PortMode::UnreliableUnordered,
        other => return Err(Error::Wire(format!("unknown port mode {}", other))),
    };
    let port_len = u16::from_be_bytes([plaintext[65], plaintext[66]]) as usize;
    if plaintext.len() < 67 + port_len {
        return Err(Error::Wire("INTRODUCE port truncated".into()));
    }
    let port = String::from_utf8(plaintext[67..67 + port_len].to_vec())
        .map_err(|_| Error::Wire("INTRODUCE port is not valid UTF-8".into()))?;

    Ok((PeerId(peer), cookie, mode, port, shared_bytes))
}

/// Build a rendezvous cookie payload (used by both ESTABLISH and JOIN).
/// Format: cookie(32)
pub fn build_rendezvous_cookie_payload(cookie: &[u8; 32]) -> Vec<u8> {
    cookie.to_vec()
}

/// Parse a rendezvous cookie payload (used by both ESTABLISH and JOIN).
pub fn parse_rendezvous_cookie_payload(data: &[u8], label: &str) -> Result<[u8; 32]> {
    if data.len() < 32 {
        return Err(Error::Wire(format!("{} payload too short", label)));
    }
    let mut cookie = [0u8; 32];
    cookie.copy_from_slice(&data[..32]);
    Ok(cookie)
}

/// RENDEZVOUS_ESTABLISH payload: cookie(32)
pub fn build_rendezvous_establish_payload(cookie: &[u8; 32]) -> Vec<u8> {
    build_rendezvous_cookie_payload(cookie)
}

/// Parse a RENDEZVOUS_ESTABLISH payload.
pub fn parse_rendezvous_establish_payload(data: &[u8]) -> Result<[u8; 32]> {
    parse_rendezvous_cookie_payload(data, "RENDEZVOUS_ESTABLISH")
}

/// RENDEZVOUS_JOIN payload: cookie(32)
pub fn build_rendezvous_join_payload(cookie: &[u8; 32]) -> Vec<u8> {
    build_rendezvous_cookie_payload(cookie)
}

/// Parse a RENDEZVOUS_JOIN payload.
pub fn parse_rendezvous_join_payload(data: &[u8]) -> Result<[u8; 32]> {
    parse_rendezvous_cookie_payload(data, "RENDEZVOUS_JOIN")
}

/// INTRO_REGISTER payload: service_id(52)
pub fn build_intro_register_payload(service_id: &tarnet_api::types::ServiceId) -> Vec<u8> {
    service_id.as_bytes().to_vec()
}

/// Parse an INTRO_REGISTER payload.
pub fn parse_intro_register_payload(data: &[u8]) -> Result<tarnet_api::types::ServiceId> {
    if data.len() < 32 {
        return Err(Error::Wire("INTRO_REGISTER payload too short".into()));
    }
    let mut sid = [0u8; 32];
    sid.copy_from_slice(&data[..32]);
    Ok(tarnet_api::types::ServiceId(sid))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn alloc_random_ids_respect_parity() {
        let table = CircuitTable::new();
        for _ in 0..100 {
            let odd_id = table.alloc_id(true, |_| false);
            assert_ne!(odd_id, 0);
            assert_eq!(odd_id % 2, 1, "initiator ID must be odd");

            let even_id = table.alloc_id(false, |_| false);
            assert_ne!(even_id, 0);
            assert_eq!(even_id % 2, 0, "responder ID must be even");
        }
    }

    #[test]
    fn insert_and_lookup_forward() {
        let mut table = CircuitTable::new();
        let key = CircuitKey {
            circuit_id: 42,
            from_peer: pid(1),
        };
        let action = CircuitAction::Forward {
            next_hop: pid(2),
            next_circuit_id: 73,
            crypto: None,
        };
        table.insert(key, action.clone());

        let result = table.lookup(&key).unwrap();
        match result {
            CircuitAction::Forward {
                next_hop,
                next_circuit_id,
                ..
            } => {
                assert_eq!(*next_hop, pid(2));
                assert_eq!(*next_circuit_id, 73);
            }
            _ => panic!("expected Forward"),
        }
    }

    #[test]
    fn insert_and_lookup_endpoint() {
        let mut table = CircuitTable::new();
        let key = CircuitKey {
            circuit_id: 99,
            from_peer: pid(3),
        };
        table.insert(
            key,
            CircuitAction::Endpoint {
                origin_hop: pid(3),
                crypto: None,
            },
        );

        assert!(matches!(
            table.lookup(&key),
            Some(CircuitAction::Endpoint { .. })
        ));
    }

    #[test]
    fn same_circuit_id_different_peers() {
        let mut table = CircuitTable::new();
        let key1 = CircuitKey {
            circuit_id: 10,
            from_peer: pid(1),
        };
        let key2 = CircuitKey {
            circuit_id: 10,
            from_peer: pid(2),
        };
        table.insert(
            key1,
            CircuitAction::Forward {
                next_hop: pid(3),
                next_circuit_id: 20,
                crypto: None,
            },
        );
        table.insert(
            key2,
            CircuitAction::Forward {
                next_hop: pid(4),
                next_circuit_id: 30,
                crypto: None,
            },
        );

        // Same circuit_id, different from_peer → different entries
        match table.lookup(&key1).unwrap() {
            CircuitAction::Forward { next_hop, .. } => assert_eq!(*next_hop, pid(3)),
            _ => panic!(),
        }
        match table.lookup(&key2).unwrap() {
            CircuitAction::Forward { next_hop, .. } => assert_eq!(*next_hop, pid(4)),
            _ => panic!(),
        }
    }

    #[test]
    fn remove_entry() {
        let mut table = CircuitTable::new();
        let key = CircuitKey {
            circuit_id: 5,
            from_peer: pid(1),
        };
        table.insert(
            key,
            CircuitAction::Endpoint {
                origin_hop: pid(1),
                crypto: None,
            },
        );
        assert!(table.lookup(&key).is_some());
        table.remove(&key);
        assert!(table.lookup(&key).is_none());
    }

    #[test]
    fn remove_peer_cleans_all_entries() {
        let mut table = CircuitTable::new();
        table.insert(
            CircuitKey {
                circuit_id: 1,
                from_peer: pid(2),
            },
            CircuitAction::Forward {
                next_hop: pid(3),
                next_circuit_id: 10,
                crypto: None,
            },
        );
        table.insert(
            CircuitKey {
                circuit_id: 2,
                from_peer: pid(1),
            },
            CircuitAction::Forward {
                next_hop: pid(2),
                next_circuit_id: 20,
                crypto: None,
            },
        );
        table.insert(
            CircuitKey {
                circuit_id: 3,
                from_peer: pid(1),
            },
            CircuitAction::Forward {
                next_hop: pid(3),
                next_circuit_id: 30,
                crypto: None,
            },
        );

        assert_eq!(table.len(), 3);
        table.remove_peer(&pid(2));
        assert_eq!(table.len(), 1);
    }

    // --- Onion routing tests ---

    #[test]
    fn relay_cell_roundtrip() {
        let digest_key = [42u8; 32];
        let cell = RelayCell {
            command: RelayCellCommand::Data,
            stream_id: 0,
            data: b"hello onion".to_vec(),
        };
        let serialized = cell.to_cell(&digest_key);
        assert_eq!(serialized.len(), CELL_BODY_SIZE);

        let parsed = RelayCell::from_cell(&serialized, &digest_key).unwrap();
        assert_eq!(parsed.command, RelayCellCommand::Data);
        assert_eq!(parsed.stream_id, 0);
        assert_eq!(parsed.data, b"hello onion");
    }

    #[test]
    fn relay_cell_bad_digest() {
        let digest_key = [42u8; 32];
        let cell = RelayCell {
            command: RelayCellCommand::Data,
            stream_id: 0,
            data: b"data".to_vec(),
        };
        let mut serialized = cell.to_cell(&digest_key);
        // Corrupt the digest
        serialized[5] ^= 0xff;
        assert!(RelayCell::from_cell(&serialized, &digest_key).is_err());
    }

    #[test]
    fn onion_encrypt_decrypt_three_hops() {
        let shared1 = [1u8; 32];
        let shared2 = [2u8; 32];
        let shared3 = [3u8; 32];

        // Initiator has 3 hop keys
        let hop1 = HopKey::from_shared_secret(&shared1);
        let hop2 = HopKey::from_shared_secret(&shared2);
        let hop3 = HopKey::from_shared_secret(&shared3);

        // Relays each have their own HopCrypto for decryption (forward direction)
        let keys1 = derive_hop_keys(&shared1);
        let keys2 = derive_hop_keys(&shared2);
        let keys3 = derive_hop_keys(&shared3);

        let mut relay1_fwd = HopCrypto {
            key: keys1.forward_key,
            digest_key: keys1.forward_digest,
            nonce_prefix: keys1.nonce_prefix,
            op: CryptoOp::Decrypt,
            replay: ReplayWindow::new(),
        };
        let mut relay2_fwd = HopCrypto {
            key: keys2.forward_key,
            digest_key: keys2.forward_digest,
            nonce_prefix: keys2.nonce_prefix,
            op: CryptoOp::Decrypt,
            replay: ReplayWindow::new(),
        };
        let mut relay3_fwd = HopCrypto {
            key: keys3.forward_key,
            digest_key: keys3.forward_digest,
            nonce_prefix: keys3.nonce_prefix,
            op: CryptoOp::Decrypt,
            replay: ReplayWindow::new(),
        };

        // Initiator builds and wraps a cell
        let msg = b"secret message through 3 hops";
        let relay_cell = RelayCell {
            command: RelayCellCommand::Data,
            stream_id: 0,
            data: msg.to_vec(),
        };

        // Serialize with endpoint's (hop3) forward MAC key, embed in full cell
        let body = relay_cell.to_cell(&hop3.forward_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);

        // Set the explicit nonce (initiator picks nonce 0 for this cell)
        set_cell_nonce(&mut cell, 0);

        // Wrap: encrypt with each hop in reverse (3, 2, 1)
        // All hops read the same nonce from the cell trailer.
        hop3.encrypt_forward(&mut cell);
        hop2.encrypt_forward(&mut cell);
        hop1.encrypt_forward(&mut cell);

        // Relay 1 (outermost) peels layer — MAC verification succeeds here
        assert!(relay1_fwd.process_cell(&mut cell), "relay1 MAC failed");
        // Relay 2 peels layer — inner hop MAC was overwritten, skip verification
        relay2_fwd.process_cell(&mut cell);
        // Relay 3 (endpoint) peels layer — inner hop MAC was overwritten, skip verification
        relay3_fwd.process_cell(&mut cell);

        // Endpoint verifies and parses
        let body: &[u8; CELL_BODY_SIZE] = cell[..CELL_BODY_SIZE].try_into().unwrap();
        let parsed = RelayCell::from_cell(body, &keys3.forward_digest).unwrap();
        assert_eq!(parsed.data, msg);

        // --- Backward direction ---
        let reply = RelayCell {
            command: RelayCellCommand::Data,
            stream_id: 0,
            data: b"reply from endpoint".to_vec(),
        };

        // Endpoint serializes with backward MAC
        let bkeys3 = derive_hop_keys(&shared3);
        let bkeys2 = derive_hop_keys(&shared2);
        let bkeys1 = derive_hop_keys(&shared1);

        let body = reply.to_cell(&bkeys3.backward_digest);
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_BODY_SIZE].copy_from_slice(&body);
        // Set the explicit backward nonce (endpoint picks nonce 0)
        set_cell_nonce(&mut cell, 0);

        // Endpoint (hop3) encrypts backward, then each relay adds a layer.
        // All read the same nonce from the cell trailer.
        let mut r3_bwd = HopCrypto {
            key: bkeys3.backward_key,
            digest_key: bkeys3.backward_digest,
            nonce_prefix: bkeys3.nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: ReplayWindow::new(),
        };
        let mut r2_bwd = HopCrypto {
            key: bkeys2.backward_key,
            digest_key: bkeys2.backward_digest,
            nonce_prefix: bkeys2.nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: ReplayWindow::new(),
        };
        let mut r1_bwd = HopCrypto {
            key: bkeys1.backward_key,
            digest_key: bkeys1.backward_digest,
            nonce_prefix: bkeys1.nonce_prefix,
            op: CryptoOp::Encrypt,
            replay: ReplayWindow::new(),
        };

        r3_bwd.process_cell(&mut cell);
        r2_bwd.process_cell(&mut cell);
        r1_bwd.process_cell(&mut cell);

        // Initiator unwraps all layers
        hop1.decrypt_backward(&mut cell);
        hop2.decrypt_backward(&mut cell);
        hop3.decrypt_backward(&mut cell);

        let body: &[u8; CELL_BODY_SIZE] = cell[..CELL_BODY_SIZE].try_into().unwrap();
        let parsed = RelayCell::from_cell(body, &hop3.backward_digest).unwrap();
        assert_eq!(parsed.data, b"reply from endpoint");
    }

    #[test]
    fn extend_payload_roundtrip_x25519() {
        let pubkey = [0xAA; 32];
        let dest = pid(5);
        let payload = build_extend_payload(0x00, &pubkey, &dest);
        let (algo, parsed_key, parsed_dest) = parse_extend_payload(&payload).unwrap();
        assert_eq!(algo, 0x00);
        assert_eq!(parsed_key, pubkey);
        assert_eq!(parsed_dest, dest);
    }

    #[test]
    fn extend_payload_roundtrip_mlkem() {
        // Simulate a 1216-byte MlkemX25519 public key
        let pubkey = vec![0xBB; 1216];
        let dest = pid(7);
        let payload = build_extend_payload(0x01, &pubkey, &dest);
        let (algo, parsed_key, parsed_dest) = parse_extend_payload(&payload).unwrap();
        assert_eq!(algo, 0x01);
        assert_eq!(parsed_key, pubkey);
        assert_eq!(parsed_dest, dest);
    }

    #[test]
    fn extended_payload_roundtrip_x25519() {
        let reply = [0xCC; 32];
        let payload = build_extended_payload(0x00, &reply);
        let (reached, algo, parsed_reply) = parse_extended_payload(&payload).unwrap();
        assert_eq!(algo, 0x00);
        assert_eq!(parsed_reply, reply);
        assert!(!reached); // default is not reached
    }

    #[test]
    fn extended_payload_roundtrip_mlkem() {
        // Simulate a 1120-byte MlkemX25519 ciphertext
        let reply = vec![0xDD; 1120];
        let payload = build_extended_payload(0x01, &reply);
        let (reached, algo, parsed_reply) = parse_extended_payload(&payload).unwrap();
        assert_eq!(algo, 0x01);
        assert_eq!(parsed_reply, reply);
        assert!(!reached);
    }

    #[test]
    fn extended_payload_reached_flag() {
        let reply = [0xEE; 32];
        let mut payload = build_extended_payload(0x00, &reply);
        // Simulate relay setting the reached flag
        payload[0] |= EXTENDED_FLAG_REACHED;
        let (reached, algo, parsed_reply) = parse_extended_payload(&payload).unwrap();
        assert!(reached);
        assert_eq!(algo, 0x00);
        assert_eq!(parsed_reply, reply);
    }

    #[test]
    fn congestion_window_slow_start() {
        let mut cw = CongestionWindow::new();
        assert_eq!(cw.cwnd, CWND_INIT);
        assert!(cw.slow_start);

        // Simulate sending and receiving SENDMEs
        for _ in 0..SENDME_INC {
            cw.on_send();
        }
        cw.on_sendme();
        assert_eq!(cw.cwnd, CWND_INIT + SENDME_INC);
        assert!(cw.slow_start);
    }

    #[test]
    fn congestion_window_exits_slow_start() {
        let mut cw = CongestionWindow::new();
        // Push cwnd past SS_MAX
        while cw.cwnd < SS_MAX {
            cw.on_sendme();
        }
        assert!(!cw.slow_start);
    }

    #[test]
    fn congestion_window_loss() {
        let mut cw = CongestionWindow::new();
        let start = CWND_MAX; // use a value well above CWND_MIN
        cw.cwnd = start;
        cw.slow_start = false;
        cw.on_loss();
        assert_eq!(cw.cwnd, start / 2);
        cw.on_loss();
        assert_eq!(cw.cwnd, start / 4);
        // Repeated halving eventually clamps at CWND_MIN
        while cw.cwnd > CWND_MIN {
            cw.on_loss();
        }
        assert_eq!(cw.cwnd, CWND_MIN);
        cw.on_loss();
        assert_eq!(cw.cwnd, CWND_MIN, "should not go below CWND_MIN");
    }

    #[test]
    fn congestion_window_sendme_trigger() {
        let mut cw = CongestionWindow::new();
        for i in 0..SENDME_INC - 1 {
            assert!(
                !cw.on_deliver([i as u8; DIGEST_SIZE]),
                "should not trigger at {}",
                i
            );
        }
        assert!(
            cw.on_deliver([0xFF; DIGEST_SIZE]),
            "should trigger at SENDME_INC"
        );
    }

    // --- Replay window tests ---

    #[test]
    fn replay_window_accepts_sequential() {
        let mut rw = ReplayWindow::new();
        for i in 0..100 {
            assert!(rw.accept(i), "should accept nonce {}", i);
        }
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut rw = ReplayWindow::new();
        assert!(rw.accept(5));
        assert!(!rw.accept(5), "duplicate should be rejected");
    }

    #[test]
    fn replay_window_accepts_out_of_order() {
        let mut rw = ReplayWindow::new();
        assert!(rw.accept(10));
        assert!(rw.accept(5), "older-but-unseen should be accepted");
        assert!(rw.accept(8));
        assert!(!rw.accept(5), "now it's a duplicate");
    }

    #[test]
    fn replay_window_rejects_too_old() {
        let mut rw = ReplayWindow::new();
        assert!(rw.accept(0));
        // Advance far ahead
        assert!(rw.accept(REPLAY_WINDOW_SIZE + 100));
        // Nonce 0 is now outside the window
        assert!(!rw.accept(0), "too old should be rejected");
        // But something within the window should work
        assert!(rw.accept(REPLAY_WINDOW_SIZE + 50));
    }

    #[test]
    fn replay_window_handles_large_gap() {
        let mut rw = ReplayWindow::new();
        assert!(rw.accept(0));
        assert!(rw.accept(10000));
        assert!(rw.accept(10001));
        assert!(!rw.accept(10000), "duplicate after gap");
    }
}
