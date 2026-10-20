//! Onion layer crypto for circuit cells (cell crypto version 2), see
//! `docs/spec/routing.md`, "Cell crypto".
//!
//! ```text
//! cell   = region(496) || trailer(16)
//! region = body(480) || tag(16)          encrypted by every layer
//! tag    = MAC(mac_key, inner || body)
//! ```
//!
//! Each layer has an outer and an inner trailer value, `inner = AES(prp, outer)`.
//! A cell moving inward (forward) arrives with the outer value and leaves with
//! the inner one; outward (backward) the other way. Every layer XORs a
//! XChaCha20 keystream over the region with the inner value as nonce, so
//! relays see unrelated trailers. The layer where a cell is sealed or opened
//! (the end layer) uses a different nonce space from layers it passes
//! through, and its inner value is a plain counter: 8 zero bytes then a u64.
//! End-layer keys run under the symmetric epoch ratchet (counter >> 16), so
//! a long-lived circuit forgets the keys of cells it has finished with; the
//! pass-through keys and the trailer permutation stay fixed for the circuit.

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{mac_16, Ratchet};

/// Full cell size on the wire.
pub const CELL_SIZE: usize = 512;
/// Trailer: the layer-transformed nonce value.
pub const CELL_TRAILER_SIZE: usize = 16;
/// End-to-end tag, encrypted with the body.
pub const CELL_TAG_SIZE: usize = 16;
/// Bytes every layer encrypts.
pub const CELL_REGION_SIZE: usize = CELL_SIZE - CELL_TRAILER_SIZE;
/// Relay cell body: header, payload and padding.
pub const CELL_BODY_SIZE: usize = CELL_REGION_SIZE - CELL_TAG_SIZE;

/// Cell crypto version carried in CREATE.
pub const CELL_CRYPTO_VERSION: u8 = 2;

/// Trailers a relay remembers per circuit direction to drop replays.
const RECENT_TRAILERS: usize = 2048;

/// After an end-to-end rekey, how long the old receive keys outlive the
/// first cell under the new ones: cells sealed before the switch may still
/// be in flight.
const PREV_KEEP: Duration = Duration::from_secs(120);

/// Nonce suffix of the layer where a cell is sealed or opened.
const END: u8 = 1;
/// Nonce suffix of a layer a cell passes through.
const THROUGH: u8 = 0;

/// Keys of one direction of one onion layer. Each direction has one sealer
/// and one opener, so the end ratchet advances the same way at both.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LayerKeys {
    /// Pass-through keystream.
    stream: [u8; 32],
    prp: [u8; 32],
    /// Base of the end-layer keystream and MAC keys.
    end: Ratchet,
}

/// One epoch's end-layer keys.
#[derive(Zeroize, ZeroizeOnDrop)]
struct EndKeys {
    stream: [u8; 32],
    mac: [u8; 32],
}

impl EndKeys {
    fn of(epoch_key: &[u8; 32]) -> Self {
        Self {
            stream: blake3::derive_key("tarnet onion v2 end stream", epoch_key),
            mac: blake3::derive_key("tarnet onion v2 end mac", epoch_key),
        }
    }

    fn tag(&self, inner: &[u8; 16], body: &[u8]) -> [u8; 16] {
        mac_16(&self.mac, &[inner, body])
    }
}

impl std::fmt::Debug for LayerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LayerKeys(..)")
    }
}

impl LayerKeys {
    fn derive(secret: &[u8; 32], transcript: &[u8; 32], dir: &str) -> Self {
        let mut material = Zeroizing::new([0u8; 64]);
        material[..32].copy_from_slice(secret);
        material[32..].copy_from_slice(transcript);
        let key = |what: &str| {
            blake3::derive_key(&format!("tarnet onion v2 {} {}", dir, what), &*material)
        };
        Self {
            stream: key("stream"),
            prp: key("prp"),
            end: Ratchet::new(key("end")),
        }
    }

    fn inner_of(&self, outer: &[u8; 16]) -> [u8; 16] {
        let mut block = (*outer).into();
        Aes256::new((&self.prp).into()).encrypt_block(&mut block);
        block.into()
    }

    fn outer_of(&self, inner: &[u8; 16]) -> [u8; 16] {
        let mut block = (*inner).into();
        Aes256::new((&self.prp).into()).decrypt_block(&mut block);
        block.into()
    }

    /// The pass-through keystream.
    fn xor_through(&self, inner: &[u8; 16], region: &mut [u8]) {
        xor_stream(&self.stream, inner, THROUGH, region);
    }

    /// Seal `body` at this layer with `counter`: the end layer of a cell.
    /// Counters must grow; older epochs' keys are forgotten. Returns the
    /// region and this layer's outer trailer.
    fn seal(&mut self, counter: u64, body: &[u8; CELL_BODY_SIZE]) -> ([u8; CELL_REGION_SIZE], [u8; 16]) {
        let keys = EndKeys::of(&Zeroizing::new(self.end.send_key(counter)));
        let inner = counter_trailer(counter);
        let mut region = [0u8; CELL_REGION_SIZE];
        region[..CELL_BODY_SIZE].copy_from_slice(body);
        let tag = keys.tag(&inner, body);
        region[CELL_BODY_SIZE..].copy_from_slice(&tag);
        xor_stream(&keys.stream, &inner, END, &mut region);
        (region, self.outer_of(&inner))
    }

    /// Try to open `region` as sealed at this layer under `inner`. Returns the
    /// counter and body when the tag matches; the caller commits the counter
    /// with [`Self::commit`] once it is accepted as fresh.
    fn open(&self, inner: &[u8; 16], region: &[u8]) -> Option<(u64, [u8; CELL_BODY_SIZE])> {
        let counter = trailer_counter(inner)?;
        let keys = EndKeys::of(&Zeroizing::new(self.end.recv_candidate(counter)?));
        let mut plain = Zeroizing::new([0u8; CELL_REGION_SIZE]);
        plain.copy_from_slice(region);
        xor_stream(&keys.stream, inner, END, &mut plain[..]);
        let body: [u8; CELL_BODY_SIZE] = plain[..CELL_BODY_SIZE].try_into().unwrap();
        let expected = keys.tag(inner, &body);
        bool::from(expected.ct_eq(&plain[CELL_BODY_SIZE..])).then_some((counter, body))
    }

    /// An opened cell with `counter` was accepted: ratchet to its epoch.
    fn commit(&mut self, counter: u64) {
        self.end.commit(counter);
    }
}

fn xor_stream(key: &[u8; 32], inner: &[u8; 16], suffix: u8, region: &mut [u8]) {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(inner);
    nonce[16] = suffix;
    XChaCha20::new(key.into(), (&nonce).into()).apply_keystream(region);
}

fn counter_trailer(counter: u64) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[8..].copy_from_slice(&counter.to_be_bytes());
    t
}

/// The counter in an end layer's inner value; other values are pseudorandom
/// and almost never start with 8 zero bytes.
fn trailer_counter(inner: &[u8; 16]) -> Option<u64> {
    (inner[..8] == [0; 8]).then(|| u64::from_be_bytes(inner[8..].try_into().unwrap()))
}

pub fn cell_trailer(cell: &[u8; CELL_SIZE]) -> [u8; 16] {
    cell[CELL_REGION_SIZE..].try_into().unwrap()
}

fn set_trailer(cell: &mut [u8; CELL_SIZE], t: &[u8; 16]) {
    cell[CELL_REGION_SIZE..].copy_from_slice(t);
}

/// The keys of one onion layer, in the initiator's orientation: `forward`
/// for cells moving away from the initiator, `backward` toward it.
#[derive(Clone, Debug)]
pub struct HopKey {
    pub forward: LayerKeys,
    pub backward: LayerKeys,
}

impl HopKey {
    /// Derive a layer's keys from a key-exchange secret and the hash of the
    /// handshake transcript.
    pub fn derive(secret: &[u8; 32], transcript: &[u8; 32]) -> Self {
        Self {
            forward: LayerKeys::derive(secret, transcript, "forward"),
            backward: LayerKeys::derive(secret, transcript, "backward"),
        }
    }

    /// The same layer seen from the other end (end-to-end layers).
    pub fn responder(&self) -> Self {
        Self {
            forward: self.backward.clone(),
            backward: self.forward.clone(),
        }
    }
}

/// Sliding window over 64-bit counters: rejects repeats and anything older
/// than the window.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    max_seen: u64,
    bitmap: [u64; Self::WORDS],
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    const SIZE: u64 = 2048;
    const WORDS: usize = (Self::SIZE / 64) as usize;

    pub fn new() -> Self {
        Self {
            max_seen: 0,
            bitmap: [0; Self::WORDS],
            initialized: false,
        }
    }

    pub fn accept(&mut self, n: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_seen = n;
            self.set(n);
            return true;
        }
        if n > self.max_seen {
            if n - self.max_seen >= Self::SIZE {
                self.bitmap = [0; Self::WORDS];
            } else {
                for i in self.max_seen + 1..=n {
                    self.clear(i);
                }
            }
            self.max_seen = n;
            self.set(n);
            true
        } else if self.max_seen - n >= Self::SIZE || self.get(n) {
            false
        } else {
            self.set(n);
            true
        }
    }

    fn bit(n: u64) -> (usize, u64) {
        let idx = (n % Self::SIZE) as usize;
        (idx / 64, 1 << (idx % 64))
    }
    fn set(&mut self, n: u64) {
        let (w, b) = Self::bit(n);
        self.bitmap[w] |= b;
    }
    fn clear(&mut self, n: u64) {
        let (w, b) = Self::bit(n);
        self.bitmap[w] &= !b;
    }
    fn get(&self, n: u64) -> bool {
        let (w, b) = Self::bit(n);
        self.bitmap[w] & b != 0
    }
}

/// The last trailers a relay processed in one direction. Relays see no
/// counters, so they drop recent repeats only; older replays die at the end
/// of the direction.
#[derive(Debug, Clone, Default)]
struct RecentTrailers {
    set: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
}

impl RecentTrailers {
    fn insert(&mut self, t: [u8; 16]) -> bool {
        if !self.set.insert(t) {
            return false;
        }
        self.order.push_back(t);
        if self.order.len() > RECENT_TRAILERS {
            let old = self.order.pop_front().unwrap();
            self.set.remove(&old);
        }
        true
    }
}

/// What peeling a layer found.
#[derive(Debug)]
pub enum Peeled {
    /// Seen recently or a stale counter: drop.
    Replayed,
    /// Not addressed to this layer: pass it on, peeled.
    Through,
    /// Addressed to this layer.
    Mine([u8; CELL_BODY_SIZE]),
}

/// Crypto operation of a relay entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOp {
    /// Peel a layer from a cell moving inward (forward direction).
    Decrypt,
    /// Add a layer to a cell moving outward (backward direction).
    Encrypt,
}

/// One direction of one layer at a relay.
#[derive(Debug, Clone)]
pub struct HopCrypto {
    pub keys: LayerKeys,
    pub op: CryptoOp,
    /// At a rendezvous point: after peeling our layer of one circuit, add
    /// our layer of the other.
    pub splice: Option<Box<HopCrypto>>,
    recent: RecentTrailers,
    window: ReplayWindow,
    /// Receive keys before the last end-to-end rekey (endpoints only).
    prev: Option<Box<PrevKeys>>,
    /// Keys from an end-to-end rekey, adopted on the first cell under them.
    pending: Option<Box<LayerKeys>>,
    /// Set when `pending` was adopted; see [`Self::take_promoted`].
    promoted: bool,
}

impl HopCrypto {
    pub fn new(keys: LayerKeys, op: CryptoOp) -> Self {
        Self {
            keys,
            op,
            splice: None,
            recent: RecentTrailers::default(),
            window: ReplayWindow::new(),
            prev: None,
            pending: None,
            promoted: false,
        }
    }

    /// Responder of an end-to-end rekey at a circuit endpoint: peel with
    /// `keys` once a cell sealed under them arrives.
    pub fn stage(&mut self, keys: LayerKeys) {
        self.pending = Some(Box::new(keys));
    }

    /// Whether staged keys were adopted since the last call: the endpoint
    /// then switches its sealing keys too.
    pub fn take_promoted(&mut self) -> bool {
        std::mem::take(&mut self.promoted)
    }

    /// Peel this layer, then add `wrap` (an outward layer of another circuit).
    pub fn spliced(mut self, wrap: HopCrypto) -> Self {
        self.splice = Some(Box::new(wrap));
        self
    }

    /// Peel this layer from a cell moving inward.
    pub fn peel(&mut self, cell: &mut [u8; CELL_SIZE]) -> Peeled {
        let inner = self.keys.inner_of(&cell_trailer(cell));
        if !self.recent.insert(inner) {
            return Peeled::Replayed;
        }
        if let Some((counter, body)) = self.keys.open(&inner, &cell[..CELL_REGION_SIZE]) {
            return if self.window.accept(counter) {
                self.keys.commit(counter);
                Peeled::Mine(body)
            } else {
                Peeled::Replayed
            };
        }
        if let Some(peeled) = self.peel_rekeyed(cell) {
            return peeled;
        }
        self.keys.xor_through(&inner, &mut cell[..CELL_REGION_SIZE]);
        set_trailer(cell, &inner);
        Peeled::Through
    }

    /// Try the keys around an end-to-end rekey: the previous ones for cells
    /// still in flight, then staged ones (adopting them).
    fn peel_rekeyed(&mut self, cell: &[u8; CELL_SIZE]) -> Option<Peeled> {
        let outer = cell_trailer(cell);
        let region = &cell[..CELL_REGION_SIZE];
        if self.prev.as_ref().is_some_and(|p| p.expired()) {
            self.prev = None;
        }
        if let Some(prev) = self.prev.as_mut() {
            if let Some(opened) = open_end(&mut prev.keys, &mut prev.window, &outer, region) {
                return Some(opened.map_or(Peeled::Replayed, Peeled::Mine));
            }
        }
        let pending = self.pending.as_mut()?;
        let mut window = ReplayWindow::new();
        let opened = open_end(pending, &mut window, &outer, region)?;
        let new = *self.pending.take().unwrap();
        let old = std::mem::replace(&mut self.keys, new);
        self.prev = Some(Box::new(PrevKeys {
            keys: old,
            window: std::mem::replace(&mut self.window, window),
            since: Some(Instant::now()),
        }));
        // At an endpoint the trailers it saw were plain counters, and the
        // new keys' counters start again from zero.
        self.recent = RecentTrailers::default();
        self.promoted = true;
        Some(opened.map_or(Peeled::Replayed, Peeled::Mine))
    }

    /// Add this layer to a cell moving outward. Returns false on a replay.
    pub fn wrap(&mut self, cell: &mut [u8; CELL_SIZE]) -> bool {
        let inner = cell_trailer(cell);
        if !self.recent.insert(inner) {
            return false;
        }
        self.keys.xor_through(&inner, &mut cell[..CELL_REGION_SIZE]);
        set_trailer(cell, &self.keys.outer_of(&inner));
        true
    }
}

/// Seal a cell at a layer, to move outward from there (a hop answering the
/// initiator). `counter` must grow for these keys.
pub fn seal_outward(keys: &mut LayerKeys, counter: u64, body: &[u8; CELL_BODY_SIZE]) -> [u8; CELL_SIZE] {
    let (region, outer) = keys.seal(counter, body);
    let mut cell = [0u8; CELL_SIZE];
    cell[..CELL_REGION_SIZE].copy_from_slice(&region);
    set_trailer(&mut cell, &outer);
    cell
}

/// Receive keys replaced by an end-to-end rekey.
#[derive(Debug, Clone)]
struct PrevKeys {
    keys: LayerKeys,
    window: ReplayWindow,
    /// When the other end was first seen using the new keys; the old ones
    /// expire [`PREV_KEEP`] later.
    since: Option<Instant>,
}

impl PrevKeys {
    fn expired(&self) -> bool {
        self.since.is_some_and(|t| t.elapsed() >= PREV_KEEP)
    }
}

/// Open a cell at its end layer: `None` if it isn't sealed under `keys`,
/// `Some(None)` if it is but its counter is stale.
fn open_end(
    keys: &mut LayerKeys,
    window: &mut ReplayWindow,
    outer: &[u8; 16],
    region: &[u8],
) -> Option<Option<[u8; CELL_BODY_SIZE]>> {
    let inner = keys.inner_of(outer);
    let (counter, body) = keys.open(&inner, region)?;
    if !window.accept(counter) {
        return Some(None);
    }
    keys.commit(counter);
    Some(Some(body))
}

/// The initiator's layers of one circuit, outermost first.
#[derive(Debug, Clone, Default)]
pub struct OnionLayers {
    pub hops: Vec<HopKey>,
    /// Next forward counter per hop. Per hop, not shared: each hop's end
    /// ratchet follows its own counter, and a shared one would make a rarely
    /// addressed hop see epoch jumps it refuses.
    next_counters: Vec<u64>,
    windows: Vec<ReplayWindow>,
    /// The innermost layer's receive keys before its last end-to-end rekey.
    last_prev: Option<Box<PrevKeys>>,
    /// Responder of an end-to-end rekey: the new keys, adopted when the
    /// first cell sealed under them arrives.
    last_pending: Option<Box<HopKey>>,
}

impl OnionLayers {
    pub fn new(hops: Vec<HopKey>) -> Self {
        Self {
            hops,
            next_counters: Vec::new(),
            windows: Vec::new(),
            last_prev: None,
            last_pending: None,
        }
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    pub fn push(&mut self, hop: HopKey) {
        self.hops.push(hop);
    }

    /// Initiator of an end-to-end rekey: replace the innermost layer now.
    /// Its old receive keys stay for cells the other end sealed before it
    /// switched.
    pub fn rekey_last(&mut self, new: HopKey) {
        self.last_pending = None;
        self.install_last(new, ReplayWindow::new(), None);
    }

    /// Responder of an end-to-end rekey: keep sending under the current keys
    /// until a cell under `new` arrives, which shows the initiator has them.
    pub fn stage_last(&mut self, new: HopKey) {
        self.last_pending = Some(Box::new(new));
    }

    fn install_last(&mut self, new: HopKey, window: ReplayWindow, since: Option<Instant>) {
        let last = self.hops.len() - 1;
        self.ensure_state();
        let old = std::mem::replace(&mut self.hops[last], new);
        self.last_prev = Some(Box::new(PrevKeys {
            keys: old.backward.clone(),
            window: std::mem::replace(&mut self.windows[last], window),
            since,
        }));
        self.next_counters[last] = 0;
    }

    fn ensure_state(&mut self) {
        self.windows.resize_with(self.hops.len().max(self.windows.len()), ReplayWindow::new);
        self.next_counters.resize(self.hops.len().max(self.next_counters.len()), 0);
    }

    /// Jump hop `index`'s forward counter (tests crossing epochs cheaply).
    #[cfg(test)]
    fn skip_to(&mut self, index: usize, counter: u64) {
        self.ensure_state();
        self.next_counters[index] = counter;
    }

    /// Seal `body` for hop `index` and wrap it in every layer outside it.
    pub fn seal_to(&mut self, index: usize, body: &[u8; CELL_BODY_SIZE]) -> [u8; CELL_SIZE] {
        self.ensure_state();
        let counter = self.next_counters[index];
        self.next_counters[index] += 1;
        let (mut region, mut outer) = self.hops[index].forward.seal(counter, body);
        for hop in self.hops[..index].iter().rev() {
            let inner = outer;
            hop.forward.xor_through(&inner, &mut region);
            outer = hop.forward.outer_of(&inner);
        }
        let mut cell = [0u8; CELL_SIZE];
        cell[..CELL_REGION_SIZE].copy_from_slice(&region);
        set_trailer(&mut cell, &outer);
        cell
    }

    /// Open a cell that arrived from the circuit: which hop sealed it, and its
    /// body. Fails on a bad tag or a replay.
    pub fn open(&mut self, cell: &[u8; CELL_SIZE]) -> Option<(usize, [u8; CELL_BODY_SIZE])> {
        let last = self.hops.len().checked_sub(1)?;
        self.ensure_state();
        let mut region: [u8; CELL_REGION_SIZE] = cell[..CELL_REGION_SIZE].try_into().unwrap();
        let mut outer = cell_trailer(cell);
        for i in 0..last {
            let keys = &mut self.hops[i].backward;
            if let Some(opened) = open_end(keys, &mut self.windows[i], &outer, &region) {
                return opened.map(|body| (i, body));
            }
            let inner = keys.inner_of(&outer);
            keys.xor_through(&inner, &mut region);
            outer = inner;
        }
        let current = open_end(&mut self.hops[last].backward, &mut self.windows[last], &outer, &region);
        if let Some(opened) = current {
            if let Some(prev) = self.last_prev.as_mut() {
                prev.since.get_or_insert_with(Instant::now);
            }
            return opened.map(|body| (last, body));
        }
        if self.last_prev.as_ref().is_some_and(|p| p.expired()) {
            self.last_prev = None;
        }
        if let Some(prev) = self.last_prev.as_mut() {
            if let Some(opened) = open_end(&mut prev.keys, &mut prev.window, &outer, &region) {
                return opened.map(|body| (last, body));
            }
        }
        if let Some(pending) = self.last_pending.as_mut() {
            let mut window = ReplayWindow::new();
            if let Some(opened) = open_end(&mut pending.backward, &mut window, &outer, &region) {
                let new = *self.last_pending.take().unwrap();
                self.install_last(new, window, Some(Instant::now()));
                return opened.map(|body| (last, body));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(n: u8) -> HopKey {
        HopKey::derive(&[n; 32], &[n.wrapping_add(100); 32])
    }

    fn body(text: &[u8]) -> [u8; CELL_BODY_SIZE] {
        let mut b = [0u8; CELL_BODY_SIZE];
        b[..text.len()].copy_from_slice(text);
        b
    }

    /// Relays for each hop: forward peel and backward wrap.
    fn relays(layers: &OnionLayers) -> Vec<(HopCrypto, HopCrypto)> {
        layers
            .hops
            .iter()
            .map(|h| {
                (
                    HopCrypto::new(h.forward.clone(), CryptoOp::Decrypt),
                    HopCrypto::new(h.backward.clone(), CryptoOp::Encrypt),
                )
            })
            .collect()
    }

    #[test]
    fn forward_cell_reaches_its_hop_and_no_other() {
        let mut layers = OnionLayers::new((1..=3).map(hop).collect());
        let mut relays = relays(&layers);
        for target in 0..3 {
            let mut cell = layers.seal_to(target, &body(b"hello"));
            for (i, (fwd, _)) in relays.iter_mut().enumerate() {
                match fwd.peel(&mut cell) {
                    Peeled::Mine(b) => {
                        assert_eq!(i, target);
                        assert_eq!(&b[..5], b"hello");
                        break;
                    }
                    Peeled::Through => assert!(i < target),
                    Peeled::Replayed => panic!("replay at {}", i),
                }
            }
        }
    }

    #[test]
    fn backward_cell_opens_at_the_initiator_with_its_origin() {
        let mut layers = OnionLayers::new((1..=3).map(hop).collect());
        let mut relays = relays(&layers);
        let mut cell = seal_outward(&mut relays[2].1.keys, 0, &body(b"from 3"));
        for (_, bwd) in relays[..2].iter_mut().rev() {
            assert!(bwd.wrap(&mut cell));
        }
        let (origin, b) = layers.open(&cell).unwrap();
        assert_eq!(origin, 2);
        assert_eq!(&b[..6], b"from 3");
        // Replayed: rejected.
        assert!(layers.open(&cell).is_none());
    }

    #[test]
    fn trailers_differ_at_every_layer() {
        let mut layers = OnionLayers::new((1..=4).map(hop).collect());
        let mut relays = relays(&layers);
        let mut cell = layers.seal_to(3, &body(b"x"));
        let mut seen = HashSet::new();
        for (fwd, _) in relays.iter_mut() {
            assert!(seen.insert(cell_trailer(&cell)));
            if let Peeled::Mine(_) = fwd.peel(&mut cell) {
                break;
            }
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn tampering_anywhere_kills_the_cell() {
        let mut layers = OnionLayers::new((1..=2).map(hop).collect());
        for byte in [0, CELL_BODY_SIZE - 1, CELL_BODY_SIZE + 3] {
            let mut relays = relays(&layers);
            let mut cell = layers.seal_to(1, &body(b"payload"));
            cell[byte] ^= 0x40;
            assert!(matches!(relays[0].0.peel(&mut cell), Peeled::Through));
            assert!(matches!(relays[1].0.peel(&mut cell), Peeled::Through));
        }
    }

    #[test]
    fn relays_drop_recent_replays() {
        let mut layers = OnionLayers::new((1..=2).map(hop).collect());
        let mut relays = relays(&layers);
        let cell = layers.seal_to(1, &body(b"once"));
        assert!(matches!(relays[0].0.peel(&mut cell.clone()), Peeled::Through));
        assert!(matches!(relays[0].0.peel(&mut cell.clone()), Peeled::Replayed));
    }

    const EPOCH: u64 = 1 << crate::crypto::EPOCH_BITS;

    #[test]
    fn end_layer_ratchets_across_epochs_and_forgets_old_keys() {
        let mut layers = OnionLayers::new((1..=2).map(hop).collect());
        let mut relays = relays(&layers);
        let old = layers.seal_to(1, &body(b"epoch 0"));
        // A straggler from the previous epoch arriving late still opens.
        layers.skip_to(1, EPOCH - 1);
        let straggler = layers.seal_to(1, &body(b"last of 0"));
        let next = layers.seal_to(1, &body(b"first of 1"));
        let deliver = |relays: &mut Vec<(HopCrypto, HopCrypto)>, mut cell: [u8; CELL_SIZE]| {
            assert!(matches!(relays[0].0.peel(&mut cell), Peeled::Through));
            relays[1].0.peel(&mut cell)
        };
        assert!(matches!(deliver(&mut relays, next), Peeled::Mine(b) if &b[..10] == b"first of 1"));
        assert!(matches!(deliver(&mut relays, straggler), Peeled::Mine(b) if &b[..9] == b"last of 0"));

        // Two epochs on, epoch 0's key is gone: the old cell no longer opens
        // even ignoring the replay window.
        layers.skip_to(1, 2 * EPOCH);
        let later = layers.seal_to(1, &body(b"epoch 2"));
        assert!(matches!(deliver(&mut relays, later), Peeled::Mine(_)));
        let mut cell = old;
        assert!(matches!(relays[0].0.peel(&mut cell), Peeled::Through));
        let inner = relays[1].0.keys.inner_of(&cell_trailer(&cell));
        assert!(relays[1].0.keys.open(&inner, &cell[..CELL_REGION_SIZE]).is_none());

        // A forged far-future counter is refused without ratcheting.
        layers.skip_to(1, 100 * EPOCH);
        let far = layers.seal_to(1, &body(b"far"));
        assert!(matches!(deliver(&mut relays, far), Peeled::Through));
    }

    #[test]
    fn hops_count_independently() {
        // Heavy traffic to the last hop must not push a rarely addressed hop
        // past the epochs its relay accepts.
        let mut layers = OnionLayers::new((1..=2).map(hop).collect());
        let mut relays = relays(&layers);
        layers.skip_to(1, 10 * EPOCH);
        let _ = layers.seal_to(1, &body(b"bulk"));
        let mut cell = layers.seal_to(0, &body(b"to first"));
        assert!(matches!(relays[0].0.peel(&mut cell), Peeled::Mine(b) if &b[..8] == b"to first"));
    }

    #[test]
    fn backward_ratchet_matches_at_the_initiator() {
        let mut layers = OnionLayers::new((1..=2).map(hop).collect());
        let mut relays = relays(&layers);
        let mut sealer = layers.hops[1].backward.clone();
        for counter in [0, EPOCH + 3, 3 * EPOCH] {
            let mut cell = seal_outward(&mut sealer, counter, &body(b"reply"));
            assert!(relays[0].1.wrap(&mut cell));
            assert_eq!(layers.open(&cell).map(|(i, _)| i), Some(1), "counter {}", counter);
        }
    }

    #[test]
    fn endpoint_rekey_switches_without_losing_cells_in_flight() {
        let mut layers = OnionLayers::new((1..=2).map(hop).collect());
        let mut relays = relays(&layers);
        let mut old_sealer = layers.hops[1].backward.clone();
        let in_flight_fwd = layers.seal_to(1, &body(b"old fwd"));

        let new = hop(50);
        layers.rekey_last(new.clone());
        relays[1].0.stage(new.forward.clone());

        // The endpoint hasn't switched: its replies still open.
        let mut reply = seal_outward(&mut old_sealer, 0, &body(b"old reply"));
        assert!(relays[0].1.wrap(&mut reply));
        assert_eq!(layers.open(&reply).map(|(i, _)| i), Some(1));

        // The first cell under the new keys switches the endpoint.
        let mut cell = layers.seal_to(1, &body(b"new fwd"));
        assert!(matches!(relays[0].0.peel(&mut cell), Peeled::Through));
        assert!(matches!(relays[1].0.peel(&mut cell), Peeled::Mine(b) if &b[..7] == b"new fwd"));
        assert!(relays[1].0.take_promoted());
        assert!(!relays[1].0.take_promoted());
        // Counters restart under the new keys; later cells aren't taken for
        // replays of the old keys' cells.
        let mut cell = layers.seal_to(1, &body(b"second"));
        assert!(matches!(relays[0].0.peel(&mut cell), Peeled::Through));
        assert!(matches!(relays[1].0.peel(&mut cell), Peeled::Mine(_)));
        let mut new_sealer = new.backward.clone();
        let mut reply = seal_outward(&mut new_sealer, 0, &body(b"new reply"));
        assert!(relays[0].1.wrap(&mut reply));
        assert_eq!(layers.open(&reply).map(|(i, _)| i), Some(1));

        // A cell sealed before the rekey, delivered late, still opens once.
        let mut late = in_flight_fwd;
        assert!(matches!(relays[0].0.peel(&mut late), Peeled::Through));
        assert!(matches!(relays[1].0.peel(&mut late.clone()), Peeled::Mine(b) if &b[..7] == b"old fwd"));
        assert!(!matches!(relays[1].0.peel(&mut late), Peeled::Mine(_)));
    }

    #[test]
    fn end_to_end_rekey_through_a_splice() {
        let e2e = hop(9);
        let mut client = OnionLayers::new(vec![hop(1), e2e.clone()]);
        let mut service = OnionLayers::new(vec![hop(5), e2e.responder()]);
        let mut c_relays = relays(&client);
        let mut s_relays = relays(&service);
        fn to_client(
            service: &mut OnionLayers,
            relays: (&mut HopCrypto, &mut HopCrypto),
            text: &[u8],
        ) -> [u8; CELL_SIZE] {
            let mut cell = service.seal_to(1, &body(text));
            assert!(matches!(relays.0.peel(&mut cell), Peeled::Through));
            assert!(relays.1.wrap(&mut cell));
            cell
        }

        let new = hop(60);
        client.rekey_last(new.clone());
        service.stage_last(new.responder());
        // Service still on the old keys; the client reads them.
        let cell = to_client(&mut service, (&mut s_relays[0].0, &mut c_relays[0].1), b"old");
        assert_eq!(client.open(&cell).map(|(i, _)| i), Some(1));

        // The client's first new cell switches the service.
        let mut cell = client.seal_to(1, &body(b"new"));
        assert!(matches!(c_relays[0].0.peel(&mut cell), Peeled::Through));
        let mut s_wrap = HopCrypto::new(service.hops[0].backward.clone(), CryptoOp::Encrypt);
        assert!(s_wrap.wrap(&mut cell));
        assert!(matches!(service.open(&cell), Some((1, b)) if &b[..3] == b"new"));
        let cell = to_client(&mut service, (&mut s_relays[0].0, &mut c_relays[0].1), b"after");
        assert!(matches!(client.open(&cell), Some((1, b)) if &b[..5] == b"after"));
    }

    #[test]
    fn end_to_end_layer_composes_through_a_splice() {
        // Client: [c1, rp, e2e]; service: [s1, rp_s, e2e responder]. The
        // rendezvous point peels its client layer and adds its service layer.
        let e2e = hop(9);
        let mut client = OnionLayers::new(vec![hop(1), hop(2), e2e.clone()]);
        let mut service = OnionLayers::new(vec![hop(5), hop(6), e2e.responder()]);
        let mut c_relays = relays(&client);
        let mut s_relays = relays(&service);

        let mut cell = client.seal_to(2, &body(b"to service"));
        assert!(matches!(c_relays[0].0.peel(&mut cell), Peeled::Through));
        assert!(matches!(c_relays[1].0.peel(&mut cell), Peeled::Through));
        assert!(s_relays[1].1.wrap(&mut cell));
        assert!(s_relays[0].1.wrap(&mut cell));
        let (origin, b) = service.open(&cell).unwrap();
        assert_eq!(origin, 2);
        assert_eq!(&b[..10], b"to service");

        let mut cell = service.seal_to(2, &body(b"to client"));
        assert!(matches!(s_relays[0].0.peel(&mut cell), Peeled::Through));
        assert!(matches!(s_relays[1].0.peel(&mut cell), Peeled::Through));
        assert!(c_relays[1].1.wrap(&mut cell));
        assert!(c_relays[0].1.wrap(&mut cell));
        let (origin, b) = client.open(&cell).unwrap();
        assert_eq!(origin, 2);
        assert_eq!(&b[..9], b"to client");
    }
}
