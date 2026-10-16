//! Onion layer crypto for circuit cells (cell crypto version 1), see
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

use std::collections::{HashSet, VecDeque};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::mac_16;

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
pub const CELL_CRYPTO_VERSION: u8 = 1;

/// Trailers a relay remembers per circuit direction to drop replays.
const RECENT_TRAILERS: usize = 2048;

/// Nonce suffix of the layer where a cell is sealed or opened.
const END: u8 = 1;
/// Nonce suffix of a layer a cell passes through.
const THROUGH: u8 = 0;

/// Keys of one direction of one onion layer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LayerKeys {
    stream: [u8; 32],
    prp: [u8; 32],
    mac: [u8; 32],
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
            blake3::derive_key(&format!("tarnet onion v1 {} {}", dir, what), &*material)
        };
        Self {
            stream: key("stream"),
            prp: key("prp"),
            mac: key("mac"),
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

    fn xor_stream(&self, inner: &[u8; 16], suffix: u8, region: &mut [u8]) {
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(inner);
        nonce[16] = suffix;
        XChaCha20::new((&self.stream).into(), (&nonce).into()).apply_keystream(region);
    }

    fn tag(&self, inner: &[u8; 16], body: &[u8]) -> [u8; 16] {
        mac_16(&self.mac, &[inner, body])
    }

    /// Seal `body` at this layer with `counter`: the end layer of a cell.
    /// Returns the region and this layer's outer trailer.
    fn seal(&self, counter: u64, body: &[u8; CELL_BODY_SIZE]) -> ([u8; CELL_REGION_SIZE], [u8; 16]) {
        let inner = counter_trailer(counter);
        let mut region = [0u8; CELL_REGION_SIZE];
        region[..CELL_BODY_SIZE].copy_from_slice(body);
        let tag = self.tag(&inner, body);
        region[CELL_BODY_SIZE..].copy_from_slice(&tag);
        self.xor_stream(&inner, END, &mut region);
        (region, self.outer_of(&inner))
    }

    /// Try to open `region` as sealed at this layer under `inner`. Returns the
    /// counter and body when the tag matches.
    fn open(&self, inner: &[u8; 16], region: &[u8]) -> Option<(u64, [u8; CELL_BODY_SIZE])> {
        let counter = trailer_counter(inner)?;
        let mut plain = [0u8; CELL_REGION_SIZE];
        plain.copy_from_slice(region);
        self.xor_stream(inner, END, &mut plain);
        let body: [u8; CELL_BODY_SIZE] = plain[..CELL_BODY_SIZE].try_into().unwrap();
        let expected = self.tag(inner, &body);
        bool::from(expected.ct_eq(&plain[CELL_BODY_SIZE..])).then_some((counter, body))
    }
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
}

impl HopCrypto {
    pub fn new(keys: LayerKeys, op: CryptoOp) -> Self {
        Self {
            keys,
            op,
            splice: None,
            recent: RecentTrailers::default(),
            window: ReplayWindow::new(),
        }
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
                Peeled::Mine(body)
            } else {
                Peeled::Replayed
            };
        }
        self.keys.xor_stream(&inner, THROUGH, &mut cell[..CELL_REGION_SIZE]);
        set_trailer(cell, &inner);
        Peeled::Through
    }

    /// Add this layer to a cell moving outward. Returns false on a replay.
    pub fn wrap(&mut self, cell: &mut [u8; CELL_SIZE]) -> bool {
        let inner = cell_trailer(cell);
        if !self.recent.insert(inner) {
            return false;
        }
        self.keys.xor_stream(&inner, THROUGH, &mut cell[..CELL_REGION_SIZE]);
        set_trailer(cell, &self.keys.outer_of(&inner));
        true
    }
}

/// Seal a cell at a layer, to move outward from there (a hop answering the
/// initiator). `counter` must not repeat for these keys.
pub fn seal_outward(keys: &LayerKeys, counter: u64, body: &[u8; CELL_BODY_SIZE]) -> [u8; CELL_SIZE] {
    let (region, outer) = keys.seal(counter, body);
    let mut cell = [0u8; CELL_SIZE];
    cell[..CELL_REGION_SIZE].copy_from_slice(&region);
    set_trailer(&mut cell, &outer);
    cell
}

/// The initiator's layers of one circuit, outermost first.
#[derive(Debug, Clone, Default)]
pub struct OnionLayers {
    pub hops: Vec<HopKey>,
    next_counter: u64,
    windows: Vec<ReplayWindow>,
}

impl OnionLayers {
    pub fn new(hops: Vec<HopKey>) -> Self {
        Self {
            hops,
            next_counter: 0,
            windows: Vec::new(),
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

    /// Seal `body` for hop `index` and wrap it in every layer outside it.
    pub fn seal_to(&mut self, index: usize, body: &[u8; CELL_BODY_SIZE]) -> [u8; CELL_SIZE] {
        let counter = self.next_counter;
        self.next_counter += 1;
        let (mut region, mut outer) = self.hops[index].forward.seal(counter, body);
        for hop in self.hops[..index].iter().rev() {
            let inner = outer;
            hop.forward.xor_stream(&inner, THROUGH, &mut region);
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
        let mut region: [u8; CELL_REGION_SIZE] = cell[..CELL_REGION_SIZE].try_into().unwrap();
        let mut outer = cell_trailer(cell);
        for (i, hop) in self.hops.iter().enumerate() {
            let inner = hop.backward.inner_of(&outer);
            if let Some((counter, body)) = hop.backward.open(&inner, &region) {
                if self.windows.len() <= i {
                    self.windows.resize_with(i + 1, ReplayWindow::new);
                }
                return self.windows[i].accept(counter).then_some((i, body));
            }
            hop.backward.xor_stream(&inner, THROUGH, &mut region);
            outer = inner;
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
        let mut cell = seal_outward(&layers.hops[2].backward, 0, &body(b"from 3"));
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
