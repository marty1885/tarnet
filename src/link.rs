use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use std::time::Duration;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{kdf, Ratchet};
use crate::identity::{self, peer_id_from_signing_pubkey, KemKeypair, Keypair};
use crate::transport::Transport;
use crate::types::{Error, PeerId, Result};
use crate::wire::{
    HandshakeAuth, HandshakeConfirmMsg, HandshakeHello, HandshakeResponse, MessageType, RekeyMsg,
    WireMessage,
    HEADER_SIZE,
    MAX_PAYLOAD, WIRE_VERSION_MAX, WIRE_VERSION_MIN,
};
use tarnet_api::types::{KemAlgo, SigningAlgo};

/// Outbound messages buffered per link before dropping.
/// When the drain task can't keep up (slow peer / congested link),
/// new messages are silently dropped. Reliable end-to-end Channels retain their
/// packets until acknowledged and retransmit them; links do not track delivery.
const OUTBOUND_QUEUE_SIZE: usize = 4096;

/// Frame plaintext size on fast links: one full circuit relay message
/// (`HEADER + circuit_id + CELL_SIZE`) plus its record header, so a cell never
/// fragments. Every frame a node sends on a link has the same size, so an
/// observer cannot classify messages by ciphertext length; small messages
/// share a frame instead of each being padded to it.
const FAST_FRAME_PLAIN: usize = 1452;
const _: () = assert!(FAST_FRAME_PLAIN >= HEADER_SIZE + 4 + crate::circuit::CELL_SIZE + 3);

/// Frame plaintext size on slow links: 256 bytes on the wire with seq and tag.
/// Frames sized to split a cell evenly (three of 207 B) cut an isolated
/// cell's airtime by a fifth, but lose more for bulk: with 256 B frames the
/// next cell starts in the room the last fragment leaves, about 2.25 frames
/// per cell when backlogged.
const SLOW_FRAME_PLAIN: usize = 256 - SEQ_SIZE - TAG_SIZE;
/// A circuit cell as a wire message: nearly all slow-link traffic.
const CELL_MESSAGE: usize = HEADER_SIZE + 4 + crate::circuit::CELL_SIZE;
/// Links whose transport reports less bandwidth than this (bytes/s) are slow.
const SLOW_LINK_BPS: u64 = 100_000;

/// Maximum time a deferred (non-critical) message waits before being flushed,
/// even if no high-priority message arrives to share its frame.
const DEFERRED_FLUSH_MS: u64 = 30;

const TAG_SIZE: usize = 16;
const SEQ_SIZE: usize = 8;
/// Largest plaintext wire message the link will carry: a full wire header plus
/// the maximum wire payload. The send path rejects anything larger; anything
/// larger than a frame is fragmented.
const MAX_LINK_MESSAGE: usize = HEADER_SIZE + MAX_PAYLOAD;
/// Largest frame plaintext accepted from a peer. Frame size is the sender's
/// local policy; a receiver accepts any size up to one unfragmented maximum
/// message.
const MAX_FRAME_PLAIN: usize = MAX_LINK_MESSAGE + 3;
/// Largest on-the-wire frame: seq || ciphertext || tag.
const MAX_LINK_FRAME: usize = SEQ_SIZE + MAX_FRAME_PLAIN + TAG_SIZE;
/// Partially reassembled messages kept per link.
const MAX_PARTIAL_MESSAGES: usize = 8;
/// Sender buffer of recently sent fragments, for NACK repair.
const FRAGMENT_REPAIR_BYTES: usize = 16 * 1024;
/// Sliding window size for replay detection.
const REPLAY_WINDOW: u64 = 128;
/// Re-key after this many messages sent.
pub const REKEY_INTERVAL: u64 = 65536;
/// Handshake deadline floor. A handshake fails after this long without
/// receiving anything from the peer; see [`handshake_deadline`].
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Approximate total size of a handshake, for scaling its deadline to slow links.
const HANDSHAKE_BYTES: u64 = 6 * 1024;
/// A handshake that keeps trickling bytes is still cut off after this many
/// deadlines, so a peer can't hold a handshake slot open forever.
const HANDSHAKE_HARD_CAP_FACTOR: u32 = 10;
/// Rekey after this long even on a quiet link (`docs/spec/identity.md`, "Key
/// lifetime"), measured on the local monotonic clock.
pub const REKEY_MAX_AGE: Duration = Duration::from_secs(3600);

/// Session keys for bidirectional encrypted communication. Each direction's
/// key runs under the symmetric epoch ratchet ([`Ratchet`]); rekeys replace
/// the base keys with fresh KEM-derived ones.
#[derive(Zeroize, ZeroizeOnDrop)]
struct LinkCrypto {
    send: Ratchet,
    recv: Ratchet,
    /// Previous recv key, retained across a rekey so in-flight frames the peer
    /// sent under the old key still decrypt. Held until the *next* rekey rotates
    /// it out (see [`install_rekey`]), not dropped on the first new-key frame —
    /// that earlier heuristic assumed in-order delivery, so an old-key straggler
    /// reordered *after* a new-key frame would fail to decrypt. Retaining the key
    /// for the whole epoch makes decryption independent of transport ordering
    /// (needed for datagram transports such as UDP); replay is still caught
    /// per-key by `prev_recv_window`/`prev_recv_bitmap`.
    prev_recv: Option<Ratchet>,
    #[zeroize(skip)]
    send_seq: u64,
    #[zeroize(skip)]
    recv_window: u64,
    #[zeroize(skip)]
    recv_bitmap: u128,
    #[zeroize(skip)]
    prev_recv_window: u64,
    #[zeroize(skip)]
    prev_recv_bitmap: u128,
    /// Responder side of a rekey: keys for a request we answered but the
    /// initiator has not yet confirmed. We keep sending under the current key
    /// until the first frame decrypts under `pending_recv`, so a reply lost on
    /// the way back costs nothing — the initiator retries and we resend it.
    pending_send: Option<[u8; 32]>,
    pending_recv: Option<[u8; 32]>,
    /// The chain secret those pending keys came from.
    pending_chain: Option<[u8; 32]>,
    /// Identifies the request `pending_*` answers (hash of its KEM pubkey).
    #[zeroize(skip)]
    pending_tag: Option<[u8; 32]>,
    /// Tag of the last request whose keys were confirmed and installed, so a
    /// late duplicate of that request is ignored rather than re-answered.
    #[zeroize(skip)]
    completed_tag: Option<[u8; 32]>,
    /// Number of key installs on this link (0 = handshake keys).
    #[zeroize(skip)]
    epoch: u64,
    /// Secret each rekey mixes into the next one (the session secret, then
    /// each rekey's result), so a rekey's keys depend on every earlier one.
    chain_secret: [u8; 32],
    /// Hash of the handshake transcript, bound into every rekey.
    #[zeroize(skip)]
    transcript: [u8; 32],
    /// When the current keys were installed (local monotonic clock).
    #[zeroize(skip)]
    installed_at: std::time::Instant,
}

impl LinkCrypto {
    fn directional(shared_secret: &[u8; 32], is_initiator: bool) -> ([u8; 32], [u8; 32]) {
        let i2r = kdf(shared_secret, "tarnet link i2r_enc");
        let r2i = kdf(shared_secret, "tarnet link r2i_enc");
        if is_initiator {
            (i2r, r2i)
        } else {
            (r2i, i2r)
        }
    }

    /// Derive session keys from shared secret. Initiator and responder derive
    /// complementary key pairs (initiator's send = responder's recv).
    fn derive(shared_secret: &[u8; 32], is_initiator: bool) -> Self {
        let (send, recv) = Self::directional(shared_secret, is_initiator);
        Self {
            send: Ratchet::new(send),
            recv: Ratchet::new(recv),
            prev_recv: None,
            send_seq: 0,
            recv_window: 0,
            recv_bitmap: 0,
            prev_recv_window: 0,
            prev_recv_bitmap: 0,
            pending_send: None,
            pending_recv: None,
            pending_chain: None,
            pending_tag: None,
            completed_tag: None,
            epoch: 0,
            chain_secret: *shared_secret,
            transcript: [0; 32],
            installed_at: std::time::Instant::now(),
        }
    }

    /// Record the handshake's session secret and transcript for rekeys.
    fn with_chain(mut self, session: &[u8; 32], transcript: [u8; 32]) -> Self {
        self.chain_secret = *session;
        self.transcript = transcript;
        self
    }

    /// The secret a rekey installs: the previous chain secret, the rekey's
    /// KEM secret, and a hash binding the handshake transcript, the target
    /// epoch and the exchanged key and ciphertext.
    fn rekey_secret(&self, epoch: u64, kem_ss: &[u8; 32], kem_pk: &[u8], kem_ct: &[u8]) -> Zeroizing<[u8; 32]> {
        let binding = blake3::Hasher::new_derive_key("tarnet link v2 rekey binding")
            .update(&self.transcript)
            .update(&epoch.to_be_bytes())
            .update(&(kem_pk.len() as u32).to_be_bytes())
            .update(kem_pk)
            .update(&(kem_ct.len() as u32).to_be_bytes())
            .update(kem_ct)
            .finalize();
        Zeroizing::new(
            blake3::Hasher::new_derive_key("tarnet link v2 rekey")
                .update(&self.chain_secret)
                .update(kem_ss)
                .update(binding.as_bytes())
                .finalize()
                .into(),
        )
    }

    /// Install freshly-rekeyed session keys derived from `new_shared`.
    ///
    /// The current recv key is retained as `prev_recv` so frames the peer
    /// already put on the wire under the old key keep decrypting. It is held for
    /// the whole new epoch and only rotated out here at the *next* rekey, so at
    /// most one previous epoch is ever live. The send key flips immediately; the
    /// peer tolerates the overlap symmetrically via its own retained previous key.
    fn install_rekey(&mut self, new_shared: &[u8; 32], is_initiator: bool) {
        let (send, recv) = Self::directional(new_shared, is_initiator);
        self.install_keys(send, recv, *new_shared);
    }

    fn install_keys(&mut self, send: [u8; 32], recv: [u8; 32], chain: [u8; 32]) {
        let old_recv = std::mem::replace(&mut self.recv, Ratchet::new(recv));
        self.prev_recv = Some(old_recv);
        self.prev_recv_window = self.recv_window;
        self.prev_recv_bitmap = self.recv_bitmap;

        self.send = Ratchet::new(send);
        self.chain_secret = chain;
        self.send_seq = 0;
        self.recv_window = 0;
        self.recv_bitmap = 0;
        self.epoch += 1;
        self.installed_at = std::time::Instant::now();
    }

    /// Responder: hold the keys for an answered rekey request until the
    /// initiator proves it has them (see `pending_recv`). A newer request
    /// replaces an unconfirmed older one.
    fn stage_rekey(&mut self, new_shared: &[u8; 32], is_initiator: bool, tag: [u8; 32]) {
        let (send, recv) = Self::directional(new_shared, is_initiator);
        self.clear_pending();
        self.pending_send = Some(send);
        self.pending_recv = Some(recv);
        self.pending_chain = Some(*new_shared);
        self.pending_tag = Some(tag);
    }

    fn clear_pending(&mut self) {
        for k in [&mut self.pending_send, &mut self.pending_recv, &mut self.pending_chain] {
            if let Some(mut k) = k.take() {
                k.zeroize();
            }
        }
        self.pending_tag = None;
    }

    /// True once either direction has sent/received enough messages to warrant
    /// a rekey, or the keys are an hour old. Checking `recv_window` (the
    /// highest seq seen from the peer) means a link whose heavy direction is
    /// inbound still rotates keys, even if our own send side is mostly idle.
    fn should_rekey(&self) -> bool {
        self.send_seq >= REKEY_INTERVAL
            || self.recv_window >= REKEY_INTERVAL
            || self.installed_at.elapsed() >= REKEY_MAX_AGE
    }

    /// Frame nonce: 16 zero bytes followed by the frame's `seq`. Safe because
    /// a `(key, seq)` pair never repeats: each direction has its own key, and
    /// `seq` restarts at 0 only when [`install_keys`] installs a fresh key.
    fn frame_nonce(seq: u64) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[16..].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    /// Wire: `seq(8) || ciphertext || tag(16)`, with `seq` as associated data.
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let seq = self.send_seq;
        self.send_seq += 1;
        let seq_bytes = seq.to_be_bytes();

        let key = Zeroizing::new(self.send.send_key(seq));
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let ciphertext = cipher
            .encrypt(
                (&Self::frame_nonce(seq)).into(),
                Payload {
                    msg: plaintext,
                    aad: &seq_bytes,
                },
            )
            .expect("AEAD encryption should not fail");

        let mut out = Vec::with_capacity(SEQ_SIZE + ciphertext.len());
        out.extend_from_slice(&seq_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// AEAD-open `data` with the key `ratchet` gives its seq, returning
    /// (payload, seq). Changes nothing; the caller commits on success.
    fn aead_open(ratchet: &Ratchet, data: &[u8]) -> Result<(Vec<u8>, u64)> {
        let seq_bytes: [u8; SEQ_SIZE] = data[..SEQ_SIZE].try_into().unwrap();
        let seq = u64::from_be_bytes(seq_bytes);
        let key = Zeroizing::new(
            ratchet
                .recv_candidate(seq)
                .ok_or_else(|| Error::Crypto("frame outside the key's epochs".into()))?,
        );
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plaintext = cipher
            .decrypt(
                (&Self::frame_nonce(seq)).into(),
                Payload {
                    msg: &data[SEQ_SIZE..],
                    aad: &seq_bytes,
                },
            )
            .map_err(|_| Error::Crypto("AEAD decryption failed".into()))?;
        Ok((plaintext, seq))
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < SEQ_SIZE + TAG_SIZE {
            return Err(Error::Crypto("encrypted message too short".into()));
        }

        // Try the current recv key first.
        match Self::aead_open(&self.recv, data) {
            Ok((plaintext, seq)) => {
                Self::check_replay_at(&mut self.recv_window, &mut self.recv_bitmap, seq)?;
                self.recv.commit(seq);
                // Keep the previous-epoch key until the next rekey rotates it
                // out: a straggler the peer sent under the old key may still
                // arrive *after* this new-key frame on a reordering transport.
                Ok(plaintext)
            }
            Err(current_err) => {
                // The initiator's first frame under keys we staged for its
                // rekey: that confirms it installed them, so switch over.
                if let Some(pending) = self.pending_recv {
                    let staged = Ratchet::new(pending);
                    if let Ok((plaintext, seq)) = Self::aead_open(&staged, data) {
                        let send = self.pending_send.take().expect("staged with recv");
                        let chain = self.pending_chain.take().expect("staged with recv");
                        self.pending_recv = None;
                        self.completed_tag = self.pending_tag.take();
                        self.install_keys(send, pending, chain);
                        Self::check_replay_at(&mut self.recv_window, &mut self.recv_bitmap, seq)?;
                        self.recv.commit(seq);
                        return Ok(plaintext);
                    }
                }
                // During a rekey overlap, the peer may still be sending under
                // the old key. Fall back to it before declaring failure.
                if let Some(prev) = self.prev_recv.as_mut() {
                    if let Ok((plaintext, seq)) = Self::aead_open(prev, data) {
                        Self::check_replay_at(
                            &mut self.prev_recv_window,
                            &mut self.prev_recv_bitmap,
                            seq,
                        )?;
                        prev.commit(seq);
                        return Ok(plaintext);
                    }
                }
                Err(current_err)
            }
        }
    }

    /// Sliding-window replay detection against a given (window, bitmap) pair.
    /// `window` is the highest seq accepted so far; `bitmap` bit `i` marks
    /// seq `window - i` as seen.
    fn check_replay_at(window: &mut u64, bitmap: &mut u128, seq: u64) -> Result<()> {
        if *window == 0 && *bitmap == 0 {
            // First packet
            *window = seq;
            *bitmap = 1;
            return Ok(());
        }

        if seq > *window {
            // Advance the window
            let shift = seq - *window;
            if shift < 128 {
                *bitmap <<= shift;
                *bitmap |= 1;
            } else {
                *bitmap = 1;
            }
            *window = seq;
            Ok(())
        } else {
            let diff = *window - seq;
            if diff >= REPLAY_WINDOW {
                return Err(Error::Replay("sequence number too old".into()));
            }
            let bit = 1u128 << diff;
            if *bitmap & bit != 0 {
                return Err(Error::Replay("duplicate sequence number".into()));
            }
            *bitmap |= bit;
            Ok(())
        }
    }

    /// Get current send count.
    #[cfg(test)]
    fn send_count(&self) -> u64 {
        self.send_seq
    }
}

/// What the drain task sends.
enum Outgoing {
    /// A wire message, dropped by the scheduler under queueing delay.
    Message(Vec<u8>),
    /// A wire message the scheduler never drops (circuit control).
    Critical(Vec<u8>),
    /// A wire message that waits briefly to share a frame with another.
    Deferred(Vec<u8>),
    /// An encoded record (NACK or resent fragment), sent ahead of messages.
    Repair(Vec<u8>),
}

// Observed challenge/response time, not a trusted estimate of propagation.
// Peers may batch, delay or prioritize replies. Never use this for link scoring.
const RTT_PROBE_TTL: Duration = Duration::from_secs(180);
const RTT_STALE_AFTER: Duration = Duration::from_secs(300);
const RTT_MAX_PENDING: usize = 4;

#[derive(Default)]
struct LinkRtt {
    pending: std::collections::VecDeque<([u8; 16], std::time::Instant)>,
    sample: Option<(u64, std::time::Instant)>,
    last_reply: Option<std::time::Instant>,
}

impl LinkRtt {
    fn sent(&mut self, nonce: [u8; 16], now: std::time::Instant) {
        self.pending
            .retain(|(_, at)| now.duration_since(*at) < RTT_PROBE_TTL);
        // Retransmission must not restart the clock or admit a replay sample.
        if self.pending.iter().any(|(id, _)| *id == nonce) {
            return;
        }
        if self.pending.len() == RTT_MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back((nonce, now));
    }

    fn received(&mut self, nonce: [u8; 16], now: std::time::Instant) {
        self.pending
            .retain(|(_, at)| now.duration_since(*at) < RTT_PROBE_TTL);
        let Some(i) = self.pending.iter().position(|(id, _)| *id == nonce) else {
            return;
        };
        let (_, at) = self.pending.remove(i).unwrap();
        let us = (now.duration_since(at).as_micros() as u64).max(1);
        let smoothed = match self.sample {
            Some((old, at)) if now.duration_since(at) < RTT_STALE_AFTER => (old * 3 + us) / 4,
            _ => us,
        };
        self.sample = Some((smoothed, now));
    }

    fn observed_us(&self, now: std::time::Instant) -> u64 {
        self.sample
            .filter(|(_, at)| now.duration_since(*at) < RTT_STALE_AFTER)
            .map_or(0, |(us, _)| us)
    }

    fn allow_reply(&mut self, now: std::time::Instant) -> bool {
        if self
            .last_reply
            .is_some_and(|at| now.duration_since(at) < Duration::from_secs(1))
        {
            return false;
        }
        self.last_reply = Some(now);
        true
    }
}

/// The drain task's channel and the state it shares with the receive path.
struct LinkPipes {
    rtt: Arc<std::sync::Mutex<LinkRtt>>,
    outbound_tx: tokio::sync::mpsc::Sender<Outgoing>,
    reassembler: Arc<std::sync::Mutex<crate::link_frame::Reassembler>>,
    repair_notify: Arc<tokio::sync::Notify>,
    rekey_notify: Arc<tokio::sync::Notify>,
    sent_fragments: Arc<std::sync::Mutex<crate::link_frame::SentFragments>>,
    task: tokio::task::JoinHandle<()>,
}

/// Initiator-side state of a rekey awaiting its reply.
struct PendingRekey {
    eph_kem: KemKeypair,
    /// The key epoch the request installs.
    epoch: u64,
    /// The encoded request. A retry resends exactly this, never a fresh
    /// ephemeral key: every reply in flight then decapsulates to the same
    /// secret, so a late or duplicated reply can never install the wrong keys.
    request: Vec<u8>,
    sent_at: std::time::Instant,
}

/// How long the initiator waits for a rekey reply before resending the request.
/// Rekey and its reply are ordinary link messages and may be lost.
pub const REKEY_RETRY_INTERVAL: Duration = Duration::from_secs(1);

fn rekey_tag(kem_pubkey: &[u8]) -> [u8; 32] {
    blake3::derive_key("tarnet rekey request", kem_pubkey)
}

/// Compute key confirmation hash via BLAKE3 derive_key (directional).
fn compute_confirm_hash(shared_secret: &[u8; 32], is_initiator: bool) -> [u8; 32] {
    let context = if is_initiator {
        "tarnet link confirm initiator"
    } else {
        "tarnet link confirm responder"
    };
    blake3::derive_key(context, shared_secret)
}

/// Keys and first transcript hash of a v2 link handshake (see
/// `docs/spec/identity.md`, "Link"). `th1` covers the initiator's hello and
/// the responder's version, nonce and KEM ciphertext; the two handshake keys
/// seal the identities, each used once.
struct HandshakeKeys {
    th1: [u8; 32],
    responder: Zeroizing<[u8; 32]>,
    initiator: Zeroizing<[u8; 32]>,
}

impl HandshakeKeys {
    fn new(ss: &[u8; 32], hello: &[u8], resp: &HandshakeResponse) -> Self {
        let header = resp.header_bytes();
        let th1: [u8; 32] = blake3::Hasher::new_derive_key("tarnet link v2 th1")
            .update(&(hello.len() as u32).to_be_bytes())
            .update(hello)
            .update(&(header.len() as u32).to_be_bytes())
            .update(&header)
            .finalize()
            .into();
        let key = |label: &str| {
            Zeroizing::new(
                blake3::Hasher::new_derive_key(label)
                    .update(ss)
                    .update(&th1)
                    .finalize()
                    .into(),
            )
        };
        Self {
            th1,
            responder: key("tarnet link v2 handshake responder"),
            initiator: key("tarnet link v2 handshake initiator"),
        }
    }
}

/// Next transcript hash: the previous one, then a side's bundle and signature.
fn transcript_step(label: &str, prev: &[u8; 32], bundle: &[u8], sig: &[u8]) -> [u8; 32] {
    blake3::Hasher::new_derive_key(label)
        .update(prev)
        .update(&(bundle.len() as u32).to_be_bytes())
        .update(bundle)
        .update(&(sig.len() as u32).to_be_bytes())
        .update(sig)
        .finalize()
        .into()
}

fn signed_message(label: &[u8], th: &[u8; 32], bundle: &[u8]) -> Vec<u8> {
    let mut msg = label.to_vec();
    msg.extend_from_slice(th);
    msg.extend_from_slice(blake3::hash(bundle).as_bytes());
    msg
}

fn responder_signed(th1: &[u8; 32], bundle: &[u8]) -> Vec<u8> {
    signed_message(b"tarnet link responder v2", th1, bundle)
}

fn initiator_signed(th2: &[u8; 32], bundle: &[u8]) -> Vec<u8> {
    signed_message(b"tarnet link initiator v2", th2, bundle)
}

/// The link's session secret, from the KEM secret and the whole transcript.
fn session_secret(ss: &[u8; 32], th3: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        blake3::Hasher::new_derive_key("tarnet link v2 session")
            .update(ss)
            .update(th3)
            .finalize()
            .into(),
    )
}

/// Encrypt a side's `bundle || signature` under its single-use handshake key.
fn seal_identity(key: &[u8; 32], th: &[u8; 32], bundle: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut plain = Zeroizing::new(Vec::with_capacity(4 + bundle.len() + sig.len()));
    plain.extend_from_slice(&(bundle.len() as u16).to_be_bytes());
    plain.extend_from_slice(bundle);
    plain.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    plain.extend_from_slice(sig);
    XChaCha20Poly1305::new(key.into())
        .encrypt((&[0u8; 24]).into(), Payload { msg: &plain, aad: th })
        .expect("AEAD encryption should not fail")
}

fn open_identity(key: &[u8; 32], th: &[u8; 32], sealed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let plain = XChaCha20Poly1305::new(key.into())
        .decrypt((&[0u8; 24]).into(), Payload { msg: sealed, aad: th })
        .map_err(|_| Error::Crypto("handshake identity failed to decrypt".into()))?;
    let mut r = crate::codec::Reader::new(&plain);
    let len = r.read_u16()? as usize;
    let bundle = r.read_bytes(len)?;
    let len = r.read_u16()? as usize;
    let sig = r.read_bytes(len)?;
    r.finish()?;
    Ok((bundle, sig))
}

/// A peer's handshake identity: a hybrid bundle (nodes must be hybrid)
/// whose policy signature covers the transcript. Returns its class.
fn check_peer(bundle: &[u8], sig: &[u8], signed: &[u8]) -> Result<SigningAlgo> {
    if !identity::is_hybrid(bundle) {
        return Err(Error::Crypto("peer is not a hybrid identity".into()));
    }
    // The peer is whoever holds the key (its id is derived from it).
    if !identity::verify_signed(identity::SignedBy::AnyPeer, None, bundle, signed, sig) {
        return Err(Error::Crypto("peer handshake signature invalid".into()));
    }
    Ok(SigningAlgo::FalconEd25519)
}

/// Negotiate the wire protocol version from both sides' supported ranges.
/// Returns the highest mutually supported version, or an error if incompatible.
fn negotiate_version(my_min: u8, my_max: u8, peer_min: u8, peer_max: u8) -> Result<u8> {
    let negotiated = my_max.min(peer_max);
    if negotiated < my_min || negotiated < peer_min {
        return Err(Error::Wire(format!(
            "version negotiation failed: my [{}-{}] vs peer [{}-{}]",
            my_min, my_max, peer_min, peer_max,
        )));
    }
    Ok(negotiated)
}

/// Time to send `bytes` at the transport's bandwidth hint (zero if unknown).
fn tx_time(transport: &dyn Transport, bytes: u64) -> Duration {
    match transport.bandwidth_hint() {
        Some(bps) if bps > 0 => Duration::from_secs_f64(bytes as f64 / bps as f64),
        _ => Duration::ZERO,
    }
}

/// Frame plaintext size this side uses on the link (local policy).
fn frame_plain_for(transport: &dyn Transport) -> usize {
    let policy = match transport.bandwidth_hint() {
        Some(bps) if bps < SLOW_LINK_BPS => SLOW_FRAME_PLAIN,
        _ => FAST_FRAME_PLAIN,
    };
    policy
        .min(transport.mtu().saturating_sub(SEQ_SIZE + TAG_SIZE))
        .max(crate::link_frame::MIN_FRAME_PLAIN)
}

/// Send scheduler tuning for the link (local policy). Fast links keep a few
/// milliseconds of queue; slow links about two cells' worth of airtime, and at
/// most two seconds of sending.
fn sched_config(transport: &dyn Transport, frame_plain: usize) -> crate::link_sched::SchedConfig {
    use crate::link_sched::SchedConfig;
    match transport.bandwidth_hint() {
        Some(bps) if bps < SLOW_LINK_BPS => {
            // A full relay cell spans several slow-link frames.
            let frames_per_cell = CELL_MESSAGE
                .div_ceil(frame_plain.saturating_sub(crate::link_frame::FRAGMENT_HEADER).max(1));
            let cell_time = tx_time(transport, (frames_per_cell * (frame_plain + SEQ_SIZE + TAG_SIZE)) as u64);
            let target = cell_time * 2;
            SchedConfig {
                target,
                interval: target * 5,
                byte_cap: (16 * 1024).max(2 * bps as usize),
                msg_cap: OUTBOUND_QUEUE_SIZE,
                quantum: frame_plain,
            }
        }
        _ => SchedConfig {
            target: Duration::from_millis(5),
            interval: Duration::from_millis(100),
            byte_cap: 8 * 1024 * 1024,
            msg_cap: OUTBOUND_QUEUE_SIZE,
            quantum: frame_plain,
        },
    }
}

/// How long a handshake may go without receiving anything from the peer:
/// `max(30 s, 3 · tx_time(handshake))`. A whole handshake takes ~25 s on an
/// HC-12-class link, so a fixed 30 s total would fail on any loss.
fn handshake_deadline(transport: &dyn Transport) -> Duration {
    HANDSHAKE_TIMEOUT.max(tx_time(transport, HANDSHAKE_BYTES) * 3)
}

/// When the handshake last heard from the peer.
type HandshakeProgress = Arc<std::sync::Mutex<std::time::Instant>>;

/// Run a handshake, failing on silence rather than on elapsed time: the
/// deadline restarts whenever a handshake frame arrives, up to a hard cap.
async fn with_handshake_deadline<T>(
    deadline: Duration,
    progress: HandshakeProgress,
    handshake: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let started = std::time::Instant::now();
    let hard_cap = deadline * HANDSHAKE_HARD_CAP_FACTOR;
    tokio::pin!(handshake);
    loop {
        let quiet = progress.lock().unwrap().elapsed();
        let left = deadline
            .saturating_sub(quiet)
            .min(hard_cap.saturating_sub(started.elapsed()));
        if left.is_zero() {
            return Err(Error::Wire("handshake timed out".into()));
        }
        tokio::select! {
            r = &mut handshake => return r,
            _ = tokio::time::sleep(left) => {}
        }
    }
}

/// First handshake retransmission timeout, doubling up to the max. Longer on
/// transports that claim reliability, where a resend is only ever needed if
/// something between the two ends drops after all.
const HS_RTO_LOSSY: Duration = Duration::from_millis(500);
const HS_RTO_RELIABLE: Duration = Duration::from_secs(1);
const HS_RTO_MAX: Duration = Duration::from_secs(4);
/// Handshake frames are well under this.
const HS_BUF: usize = 8192;

/// Lockstep handshake I/O that survives loss, duplication and reordering.
///
/// Every message is kept byte-for-byte as sent. The initiator resends its last
/// message when the next one doesn't arrive in time; either side answers a
/// stale handshake message from the peer (a sign our last reply was lost) by
/// resending its last message. The responder never sends unprompted. This
/// runs whatever the transport claims: one end's transport being "reliable"
/// says nothing about what happens on the path.
struct HandshakeIo<'a> {
    transport: &'a dyn Transport,
    last_sent: Vec<u8>,
    /// Raw bytes of the message `expect` last returned.
    last_received: Vec<u8>,
    is_initiator: bool,
    rto_initial: Duration,
    rto: Duration,
    progress: HandshakeProgress,
}

impl<'a> HandshakeIo<'a> {
    fn new(transport: &'a dyn Transport, is_initiator: bool, progress: HandshakeProgress) -> Self {
        // Never resend before our own message has had time to go out.
        let rto_initial = if transport.is_reliable() {
            HS_RTO_RELIABLE
        } else {
            HS_RTO_LOSSY
        }
        .max(tx_time(transport, HS_BUF as u64) * 2);
        Self {
            transport,
            last_sent: Vec::new(),
            last_received: Vec::new(),
            is_initiator,
            rto_initial,
            rto: rto_initial,
            progress,
        }
    }

    async fn send(&mut self, msg: Vec<u8>) -> Result<()> {
        self.transport.send(&msg).await?;
        self.last_sent = msg;
        self.rto = self.rto_initial;
        Ok(())
    }

    async fn resend(&mut self) -> Result<()> {
        if self.last_sent.is_empty() {
            return Ok(());
        }
        self.transport.send(&self.last_sent).await
    }

    /// Next raw frame from the peer, resending our last message on timeout.
    ///
    /// The receive is never cancelled: a transport `recv` need not be
    /// cancel-safe (TCP reads a length prefix, then the body; abandoning it in
    /// between desyncs the stream for good). The timer runs beside it.
    async fn recv_raw(&mut self) -> Result<Vec<u8>> {
        let transport = self.transport;
        let progress = self.progress.clone();
        let recv = async move {
            let mut buf = vec![0u8; HS_BUF];
            let n = transport.recv(&mut buf).await?;
            buf.truncate(n);
            *progress.lock().unwrap() = std::time::Instant::now();
            Ok::<_, Error>(buf)
        };
        tokio::pin!(recv);
        loop {
            if !self.is_initiator || self.last_sent.is_empty() {
                return recv.await;
            }
            tokio::select! {
                r = &mut recv => return r,
                _ = tokio::time::sleep(self.rto) => {
                    self.rto = (self.rto * 2).min(HS_RTO_MAX.max(self.rto_initial));
                    self.resend().await?;
                }
            }
        }
    }

    /// Wait for the next handshake message of type `want`.
    async fn expect(&mut self, want: MessageType) -> Result<WireMessage> {
        loop {
            let raw = self.recv_raw().await?;
            match WireMessage::decode(&raw) {
                Ok(w) if w.msg_type == want => {
                    self.last_received = raw;
                    return Ok(w);
                }
                Ok(w) if is_handshake_type(w.msg_type) => {
                    // A repeat of an earlier step: the peer missed our reply.
                    self.resend().await?;
                }
                _ => {} // stray or garbled frame
            }
        }
    }
}

fn is_handshake_type(t: MessageType) -> bool {
    matches!(
        t,
        MessageType::HandshakeHello | MessageType::HandshakeAuth | MessageType::HandshakeConfirm
    )
}

/// Authenticated encrypted link to a direct neighbor.
///
/// Outbound wire messages go through one bounded channel to a background
/// drain task, which queues them in the link scheduler
/// ([`crate::link_sched`]), packs them into fixed-size frames (see
/// [`crate::link_frame`]), encrypts each frame and writes it to the
/// transport. The scheduler drops what waits too long; if the channel itself
/// fills, new messages are dropped, except critical ones, which wait.
pub struct PeerLink {
    rtt: Arc<std::sync::Mutex<LinkRtt>>,
    transport: Arc<dyn Transport>,
    /// Shared with the drain task, which encrypts frames as it sends them so
    /// frame seqs go out in order.
    crypto: Arc<tokio::sync::Mutex<LinkCrypto>>,
    /// Everything sent on the link, to the drain task.
    outbound_tx: tokio::sync::mpsc::Sender<Outgoing>,
    reassembler: Arc<std::sync::Mutex<crate::link_frame::Reassembler>>,
    /// Receiving a fragment can arm repair polling on an otherwise idle link.
    repair_notify: Arc<tokio::sync::Notify>,
    /// Reused frame scratch space; large enough for any negotiated frame.
    recv_buf: tokio::sync::Mutex<Vec<u8>>,
    rekey_notify: Arc<tokio::sync::Notify>,
    /// Fragments recently sent, for NACK repair.
    sent_fragments: Arc<std::sync::Mutex<crate::link_frame::SentFragments>>,
    remote_peer: PeerId,
    remote_signing_algo: SigningAlgo,
    remote_signing_pubkey: Vec<u8>,
    is_initiator: bool,
    identity: std::sync::Arc<Keypair>,
    /// Negotiated KEM algorithm for rekey exchanges.
    rekey_kem_algo: KemAlgo,
    /// Initiator side of an in-flight rekey. `None` when idle.
    pending_rekey: tokio::sync::Mutex<Option<PendingRekey>>,
    /// Responder side: the reply we sent for the latest request, keyed by the
    /// request's tag, so a retried request gets the identical answer.
    rekey_reply: tokio::sync::Mutex<Option<([u8; 32], Vec<u8>)>>,
    /// Rekey on the next sweep regardless of message counts (tests).
    force_rekey: std::sync::atomic::AtomicBool,
    /// Negotiated wire protocol version for this link.
    negotiated_version: u8,
    _drain_task: tokio::task::JoinHandle<()>,
    /// Transport name captured at construction for status display.
    transport_name: &'static str,
    /// Wire messages decoded from frames but not yet returned by
    /// [`recv_message`]. A frame can carry several.
    inbox: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    /// Responder: (initiator's HandshakeConfirm, our HandshakeConfirm) until
    /// the initiator is known to be done. A repeat of its confirm means ours
    /// was lost; we answer it so the initiator can finish instead of leaving
    /// us holding a link the other side gave up on.
    handshake_tail: std::sync::Mutex<Option<(Vec<u8>, Vec<u8>)>>,
    /// Protocol categories sent on this link (see
    /// [`crate::firewall::category_bit`]), for the firewall's connection
    /// tracking: recorded where every outgoing message passes.
    sent_categories: std::sync::atomic::AtomicU8,
}

impl PeerLink {
    /// Perform handshake as the initiator (the side that called connect).
    ///
    /// If `expected_peer` is `Some`, verifies that the authenticated remote
    /// peer matches. This prevents a MITM from intercepting the connection
    /// and authenticating as a different (valid) peer.
    pub async fn initiator(
        transport: Box<dyn Transport>,
        identity: &Keypair,
        expected_peer: Option<PeerId>,
    ) -> Result<Self> {
        let deadline = handshake_deadline(transport.as_ref());
        let progress = HandshakeProgress::new(std::time::Instant::now().into());
        let inner = Self::initiator_inner(transport, identity, expected_peer, progress.clone());
        with_handshake_deadline(deadline, progress, inner).await
    }

    async fn initiator_inner(
        transport: Box<dyn Transport>,
        identity: &Keypair,
        expected_peer: Option<PeerId>,
        progress: HandshakeProgress,
    ) -> Result<Self> {
        let eph_kem = KemKeypair::generate_ephemeral(KemAlgo::MlkemX25519);
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let hello = HandshakeHello {
            min_version: WIRE_VERSION_MIN,
            max_version: WIRE_VERSION_MAX,
            nonce,
            eph_kem_pubkey: eph_kem.kem_pubkey_bytes(),
        };
        let hello_bytes = hello.to_bytes();
        let mut io = HandshakeIo::new(transport.as_ref(), true, progress);
        io.send(hello.to_wire().encode()).await?;

        let wire = io.expect(MessageType::HandshakeAuth).await?;
        let resp = HandshakeResponse::from_bytes(&wire.payload)?;
        let negotiated_version =
            negotiate_version(WIRE_VERSION_MIN, WIRE_VERSION_MAX, resp.min_version, resp.max_version)?;
        if resp.version != negotiated_version {
            return Err(Error::Wire("responder chose a version outside the negotiation".into()));
        }
        let ss = Zeroizing::new(
            eph_kem
                .decapsulate(&resp.kem_ciphertext)
                .map_err(|e| Error::Crypto(format!("handshake KEM decapsulate failed: {e}")))?,
        );
        let hs = HandshakeKeys::new(&ss, &hello_bytes, &resp);
        let (bundle_r, sig_r) = open_identity(&hs.responder, &hs.th1, &resp.sealed)?;
        let remote_signing_algo = check_peer(&bundle_r, &sig_r, &responder_signed(&hs.th1, &bundle_r))?;
        let remote_peer = peer_id_from_signing_pubkey(&bundle_r);
        if let Some(expected) = expected_peer {
            if remote_peer != expected {
                return Err(Error::Crypto(format!(
                    "connected to {:?} but expected {:?}",
                    remote_peer, expected,
                )));
            }
        }

        let th2 = transcript_step("tarnet link v2 th2", &hs.th1, &bundle_r, &sig_r);
        let bundle_i = identity.identity.signing.signing_pubkey_bytes();
        let sig_i = identity.sign(&initiator_signed(&th2, &bundle_i));
        let sealed = seal_identity(&hs.initiator, &th2, &bundle_i, &sig_i);
        io.send(HandshakeAuth { sealed }.to_wire().encode()).await?;
        let th3 = transcript_step("tarnet link v2 th3", &th2, &bundle_i, &sig_i);
        let session = session_secret(&ss, &th3);
        let crypto = LinkCrypto::derive(&session, true).with_chain(&session, th3);

        // Receive and verify the responder's confirm. Any frame that decrypts
        // under the session keys proves the responder holds them just as well
        // (it only sends link frames after its confirm), so it also completes
        // the handshake — the confirm may have been lost or overtaken.
        let mut crypto = crypto;
        let mut early_frames = std::collections::VecDeque::new();
        let expected_peer_confirm = compute_confirm_hash(&session, false);
        loop {
            let raw = io.recv_raw().await?;
            if raw.len() >= SEQ_SIZE + TAG_SIZE {
                if let Ok(plaintext) = crypto.decrypt(&raw) {
                    early_frames.push_back(plaintext);
                    break;
                }
            }
            match WireMessage::decode(&raw) {
                Ok(w) if w.msg_type == MessageType::HandshakeConfirm => {
                    let peer_confirm = HandshakeConfirmMsg::from_bytes(&w.payload)?;
                    if peer_confirm
                        .confirm_hash
                        .ct_eq(&expected_peer_confirm)
                        .unwrap_u8()
                        == 0
                    {
                        return Err(Error::Crypto("key confirmation failed".into()));
                    }
                    break;
                }
                Ok(w) if is_handshake_type(w.msg_type) => io.resend().await?,
                _ => {}
            }
        }

        log::info!(
            "Link established (initiator) with {:?}, wire v{}",
            remote_peer,
            negotiated_version
        );
        transport.authenticated(remote_peer);
        let transport_name = transport.name();
        let transport: Arc<dyn Transport> = Arc::from(transport);
        let crypto = Arc::new(tokio::sync::Mutex::new(crypto));
        let pipes = Self::spawn_drain(transport.clone(), crypto.clone(), remote_peer);
        let link = Self {
            transport,
            crypto,
            rtt: pipes.rtt,
            outbound_tx: pipes.outbound_tx,
            reassembler: pipes.reassembler,
            repair_notify: pipes.repair_notify,
            rekey_notify: pipes.rekey_notify,
            recv_buf: tokio::sync::Mutex::new(Vec::new()),
            sent_fragments: pipes.sent_fragments,
            remote_peer,
            remote_signing_algo,
            remote_signing_pubkey: bundle_r,
            is_initiator: true,
            rekey_kem_algo: KemAlgo::MlkemX25519,
            pending_rekey: tokio::sync::Mutex::new(None),
            rekey_reply: tokio::sync::Mutex::new(None),
            force_rekey: std::sync::atomic::AtomicBool::new(false),
            negotiated_version,
            identity: std::sync::Arc::new(identity.clone()),
            _drain_task: pipes.task,
            transport_name,
            inbox: std::sync::Mutex::new(std::collections::VecDeque::new()),
            handshake_tail: std::sync::Mutex::new(None),
            sent_categories: std::sync::atomic::AtomicU8::new(0),
        };
        for frame in early_frames {
            link.ingest_frame(&frame);
        }
        Ok(link)
    }

    /// Perform handshake as the responder (the side that called accept).
    pub async fn responder(transport: Box<dyn Transport>, identity: &Keypair) -> Result<Self> {
        let deadline = handshake_deadline(transport.as_ref());
        let progress = HandshakeProgress::new(std::time::Instant::now().into());
        let inner = Self::responder_inner(transport, identity, progress.clone());
        with_handshake_deadline(deadline, progress, inner).await
    }

    async fn responder_inner(
        transport: Box<dyn Transport>,
        identity: &Keypair,
        progress: HandshakeProgress,
    ) -> Result<Self> {
        let mut io = HandshakeIo::new(transport.as_ref(), false, progress);
        let wire = io.expect(MessageType::HandshakeHello).await?;
        let hello = HandshakeHello::from_bytes(&wire.payload)?;
        let hello_bytes = wire.payload;
        let negotiated_version =
            negotiate_version(WIRE_VERSION_MIN, WIRE_VERSION_MAX, hello.min_version, hello.max_version)?;

        let (ss, kem_ciphertext) = KemKeypair::encapsulate_to(&hello.eph_kem_pubkey, KemAlgo::MlkemX25519)
            .map_err(|e| Error::Crypto(format!("handshake KEM encapsulate failed: {e}")))?;
        let ss = Zeroizing::new(ss);
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut resp = HandshakeResponse {
            version: negotiated_version,
            min_version: WIRE_VERSION_MIN,
            max_version: WIRE_VERSION_MAX,
            nonce,
            kem_ciphertext,
            sealed: Vec::new(),
        };
        let hs = HandshakeKeys::new(&ss, &hello_bytes, &resp);
        let bundle_r = identity.identity.signing.signing_pubkey_bytes();
        let sig_r = identity.sign(&responder_signed(&hs.th1, &bundle_r));
        resp.sealed = seal_identity(&hs.responder, &hs.th1, &bundle_r, &sig_r);
        io.send(resp.to_wire().encode()).await?;

        let wire = io.expect(MessageType::HandshakeAuth).await?;
        let auth_frame = std::mem::take(&mut io.last_received);
        let auth = HandshakeAuth::from_bytes(&wire.payload)?;
        let th2 = transcript_step("tarnet link v2 th2", &hs.th1, &bundle_r, &sig_r);
        let (bundle_i, sig_i) = open_identity(&hs.initiator, &th2, &auth.sealed)?;
        let remote_signing_algo = check_peer(&bundle_i, &sig_i, &initiator_signed(&th2, &bundle_i))?;
        let remote_peer = peer_id_from_signing_pubkey(&bundle_i);
        let th3 = transcript_step("tarnet link v2 th3", &th2, &bundle_i, &sig_i);
        let session = session_secret(&ss, &th3);
        let crypto = LinkCrypto::derive(&session, false).with_chain(&session, th3);

        let our_confirm = HandshakeConfirmMsg {
            confirm_hash: compute_confirm_hash(&session, false),
        }
        .to_wire()
        .encode();
        io.send(our_confirm.clone()).await?;
        let handshake_tail = Some((auth_frame, our_confirm));

        log::info!(
            "Link established (responder) with {:?}, wire v{}",
            remote_peer,
            negotiated_version
        );
        transport.authenticated(remote_peer);
        let transport_name = transport.name();
        let transport: Arc<dyn Transport> = Arc::from(transport);
        let crypto = Arc::new(tokio::sync::Mutex::new(crypto));
        let pipes = Self::spawn_drain(transport.clone(), crypto.clone(), remote_peer);
        let link = Self {
            transport,
            crypto,
            rtt: pipes.rtt,
            outbound_tx: pipes.outbound_tx,
            reassembler: pipes.reassembler,
            repair_notify: pipes.repair_notify,
            rekey_notify: pipes.rekey_notify,
            recv_buf: tokio::sync::Mutex::new(Vec::new()),
            sent_fragments: pipes.sent_fragments,
            remote_peer,
            remote_signing_algo,
            remote_signing_pubkey: bundle_i,
            is_initiator: false,
            rekey_kem_algo: KemAlgo::MlkemX25519,
            pending_rekey: tokio::sync::Mutex::new(None),
            rekey_reply: tokio::sync::Mutex::new(None),
            force_rekey: std::sync::atomic::AtomicBool::new(false),
            negotiated_version,
            identity: std::sync::Arc::new(identity.clone()),
            _drain_task: pipes.task,
            transport_name,
            inbox: std::sync::Mutex::new(std::collections::VecDeque::new()),
            handshake_tail: std::sync::Mutex::new(handshake_tail),
            sent_categories: std::sync::atomic::AtomicU8::new(0),
        };
        Ok(link)
    }

    /// Spawn the background drain task that packs queued messages into
    /// frames, encrypts them and writes them to the transport.
    ///
    /// Messages go out at once in scheduler order, sharing their frame with
    /// whatever else is queued. A deferred message arriving at an idle link
    /// waits up to [`DEFERRED_FLUSH_MS`] (jittered) for another message to
    /// ride with, so fewer distinctly-timed frames appear on the wire. Repair
    /// records (NACKs, resent fragments) go ahead of everything.
    fn spawn_drain(
        transport: Arc<dyn Transport>,
        crypto: Arc<tokio::sync::Mutex<LinkCrypto>>,
        remote: PeerId,
    ) -> LinkPipes {
        use crate::link_frame::{encode_message_into, pack_frame_with, Reassembler, SentFragments};
        use std::collections::VecDeque;

        let frame_plain = frame_plain_for(transport.as_ref());
        let frame_time = tx_time(transport.as_ref(), (frame_plain + SEQ_SIZE + TAG_SIZE) as u64);
        // Repair runs whatever the local transport claims: a "reliable" TCP
        // socket here says nothing about the far end, and either side may sit
        // behind a lossy path. On a link that loses nothing it costs only the
        // sender's repair buffer.
        // Silence on a partial message before the receiver NACKs it. The link
        // has no RTT estimate yet, so a fixed floor stands in for SRTT.
        let stall = Duration::from_millis(200).max(frame_time * 2);
        let reassembler = Arc::new(std::sync::Mutex::new(Reassembler::new(
            MAX_PARTIAL_MESSAGES,
            Duration::from_secs(5).max(tx_time(transport.as_ref(), MAX_LINK_MESSAGE as u64) * 4),
            stall,
        )));
        let sent_fragments = Arc::new(std::sync::Mutex::new(SentFragments::new(
            FRAGMENT_REPAIR_BYTES,
            Duration::from_secs(5).max(frame_time * 16),
        )));

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Outgoing>(OUTBOUND_QUEUE_SIZE);
        let sched_cfg = sched_config(transport.as_ref(), frame_plain);

        let rtt = Arc::new(std::sync::Mutex::new(LinkRtt::default()));
        let task_rtt = rtt.clone();
        let task_reassembler = reassembler.clone();
        let repair_notify = Arc::new(tokio::sync::Notify::new());
        let task_repair_notify = repair_notify.clone();
        let rekey_notify = Arc::new(tokio::sync::Notify::new());
        let task_rekey_notify = rekey_notify.clone();
        let task_sent = sent_fragments.clone();
        let task = tokio::spawn(async move {
            use crate::link_sched::Scheduler;
            use futures_util::FutureExt;
            let mut sched = Scheduler::new(sched_cfg);
            // Records past the scheduler, packed into frames in order: at most
            // one frame's worth plus the rest of a fragmented message.
            struct ReadyRecord {
                bytes: Vec<u8>,
                control: bool,
                probe: Option<[u8; 16]>,
            }
            impl AsRef<[u8]> for ReadyRecord {
                fn as_ref(&self) -> &[u8] { &self.bytes }
            }
            let mut ready: VecDeque<ReadyRecord> = VecDeque::new();
            // The remaining fragments (a frame each) of the background
            // message being sent. Foreground messages go between them, one
            // per fragment, so a large DHT record can't hold the line.
            let mut background_rest: VecDeque<ReadyRecord> = VecDeque::new();
            // Whether a foreground message went since the last fragment.
            let mut interleaved = false;
            let mut next_msg_id: u16 = 0;
            let mut reported_drops = 0;
            let mut next_nack_poll = None;

            // Queue a wire message's records, remembering fragments for repair.
            // The next message starts in whatever room the frame being
            // filled has left.
            let mut enqueue = |ready: &mut VecDeque<ReadyRecord>, background_rest: &mut VecDeque<ReadyRecord>, data: Vec<u8>| {
                let class = crate::link_sched::classify(&data).0;
                let control = class == crate::link_sched::Class::Control;
                let used = ready.iter().map(|r| r.bytes.len()).sum::<usize>() % frame_plain;
                let room = if ready.is_empty() { frame_plain } else { frame_plain - used };
                let records = encode_message_into(&data, frame_plain, room, &mut next_msg_id);
                if records.len() > 1 {
                    task_sent.lock().unwrap().remember(&records, std::time::Instant::now());
                }
                let probe = (WireMessage::peek_type(&data) == Some(MessageType::Keepalive))
                    .then(|| WireMessage::decode(&data).ok())
                    .flatten()
                    .and_then(|msg| crate::wire::KeepaliveMsg::from_bytes(&msg.payload).ok())
                    .filter(|ka| ka.ping_id.is_some())
                    .and_then(|ka| ka.probe_nonce);
                let last = records.len().saturating_sub(1);
                let defer = class == crate::link_sched::Class::Background;
                for (i, bytes) in records.into_iter().enumerate() {
                    let rec = ReadyRecord {
                        bytes,
                        control,
                        probe: if i == last { probe } else { None },
                    };
                    if defer && i > 0 {
                        background_rest.push_back(rec);
                    } else {
                        ready.push_back(rec);
                    }
                }
            };
            // Messages go to the scheduler; repair records skip it.
            let take = |sched: &mut Scheduler, ready: &mut VecDeque<ReadyRecord>, background_rest: &VecDeque<ReadyRecord>, out: Outgoing| {
                let now = std::time::Instant::now();
                match out {
                    Outgoing::Message(data) | Outgoing::Deferred(data) => sched.push(data, false, now),
                    Outgoing::Critical(data) => sched.push(data, true, now),
                    Outgoing::Repair(rec) => {
                        // A fragment still queued goes out anyway: the peer
                        // NACKed it only because a pause looked like loss.
                        let queued = |q: &VecDeque<ReadyRecord>| q.iter().any(|r| r.bytes == rec);
                        if queued(background_rest) || queued(ready) {
                            return;
                        }
                        ready.push_front(ReadyRecord {
                            bytes: rec,
                            control: true,
                            probe: None,
                        });
                    }
                }
            };

            'drain: loop {
                // Bound admission work so continuously refilling producers
                // cannot keep us in try_recv forever without sending a frame.
                for _ in 0..OUTBOUND_QUEUE_SIZE {
                    let Ok(out) = rx.try_recv() else { break };
                    take(&mut sched, &mut ready, &background_rest, out);
                }
                // New fragments can move the next repair deadline earlier
                // or later. Cache it between notifications rather than
                // scanning partials or polling a fixed-rate timer.
                let now = std::time::Instant::now();
                if task_repair_notify.notified().now_or_never().is_some()
                    || next_nack_poll.is_some_and(|at| now >= at)
                {
                    let mut r = task_reassembler.lock().unwrap();
                    let repairs = r.poll(now);
                    next_nack_poll = r.next_poll_at();
                    ready.extend(repairs.into_iter().map(|bytes| ReadyRecord {
                        bytes,
                        control: true,
                        probe: None,
                    }));
                }

                if ready.is_empty() && sched.is_empty() && background_rest.is_empty() {
                    tokio::select! {
                        out = rx.recv() => {
                            let Some(out) = out else { break };
                            let Outgoing::Deferred(first) = out else {
                                take(&mut sched, &mut ready, &background_rest, out);
                                continue;
                            };
                            // Wait briefly for a message that isn't deferred
                            // to share the frame; it ends the wait early.
                            // Held messages reach the scheduler only after
                            // the wait, which is not queueing delay.
                            let mut held = vec![first];
                            let jitter = {
                                use rand::Rng;
                                rand::thread_rng().gen_range(0..DEFERRED_FLUSH_MS)
                            };
                            let flush = tokio::time::sleep(Duration::from_millis(DEFERRED_FLUSH_MS + jitter));
                            tokio::pin!(flush);
                            loop {
                                tokio::select! {
                                    out = rx.recv() => match out {
                                        None => break 'drain,
                                        Some(Outgoing::Deferred(data)) => held.push(data),
                                        Some(out) => {
                                            take(&mut sched, &mut ready, &background_rest, out);
                                            break;
                                        }
                                    },
                                    _ = &mut flush => break,
                                }
                            }
                            let now = std::time::Instant::now();
                            for data in held {
                                sched.push(data, false, now);
                            }
                        }
                        _ = task_repair_notify.notified() => {
                            // This select consumed the notification; force a
                            // deadline refresh at the top of the next loop.
                            next_nack_poll = Some(std::time::Instant::now());
                        }
                        _ = async {
                            match next_nack_poll {
                                Some(at) => tokio::time::sleep_until(at.into()).await,
                                None => std::future::pending::<()>().await,
                            }
                        } => {}
                    }
                    continue;
                }

                // Fill the frame from the scheduler, highest class first. While
                // a background message is part-way out, foreground messages and
                // its fragments alternate.
                while ready.iter().map(|r| r.bytes.len()).sum::<usize>() < frame_plain {
                    if !background_rest.is_empty() {
                        if !interleaved {
                            if let Some(data) = sched.pop_foreground(now) {
                                interleaved = true;
                                enqueue(&mut ready, &mut background_rest, data);
                                continue;
                            }
                        }
                        if ready.is_empty() {
                            ready.push_back(background_rest.pop_front().expect("checked non-empty"));
                            interleaved = false;
                        }
                        break;
                    }
                    let Some(data) = sched.pop(now) else { break };
                    enqueue(&mut ready, &mut background_rest, data);
                }
                if sched.dropped() > reported_drops {
                    log::trace!(
                        "link to {:?}: dropped {} queued message(s)",
                        remote,
                        sched.dropped() - reported_drops
                    );
                    reported_drops = sched.dropped();
                }

                let mut control = false;
                let mut probes = Vec::new();
                let Some(frame) = pack_frame_with(&mut ready, frame_plain, |r| {
                    control |= r.control;
                    if let Some(nonce) = r.probe {
                        probes.push(nonce);
                    }
                }) else {
                    // Everything popped was dropped by the scheduler.
                    continue;
                };
                let encrypted = {
                    let mut crypto = crypto.lock().await;
                    let was_due = crypto.should_rekey();
                    let encrypted = crypto.encrypt(&frame);
                    if !was_due && crypto.should_rekey() { task_rekey_notify.notify_one(); }
                    encrypted
                };
                if !probes.is_empty() {
                    let mut rtt = task_rtt.lock().unwrap();
                    let now = std::time::Instant::now();
                    for nonce in probes {
                        rtt.sent(nonce, now);
                    }
                }
                if let Err(e) = transport.send_frame(&encrypted, control).await {
                    log::debug!("link drain to {:?}: {}", remote, e);
                    break;
                }
            }
        });
        LinkPipes {
            rtt,
            repair_notify,
            rekey_notify,
            outbound_tx: tx,
            reassembler,
            sent_fragments,
            task,
        }
    }

    /// Locally observed response time including remote batching/delay; zero
    /// means unavailable or stale. Deliberately independent of link selection.
    pub fn observed_rtt_us(&self) -> u64 {
        self.rtt
            .lock()
            .unwrap()
            .observed_us(std::time::Instant::now())
    }

    /// Process only authenticated keepalives delivered on this exact link.
    /// Bound responses to one per second; replies never generate replies.
    pub(crate) async fn handle_keepalive(&self, ka: &crate::wire::KeepaliveMsg) {
        let now = std::time::Instant::now();
        if ka.ping_id.is_none() {
            if let Some(nonce) = ka.probe_nonce {
                self.rtt.lock().unwrap().received(nonce, now);
            }
            return;
        }
        if !self.rtt.lock().unwrap().allow_reply(now) {
            return;
        }
        use rand::Rng;
        let padding = {
            let mut rng = rand::thread_rng();
            let mut padding = vec![0; rng.gen_range(0..=256)];
            rng.fill_bytes(&mut padding);
            padding
        };
        let pong = crate::wire::KeepaliveMsg {
            ping_id: None,
            probe_nonce: ka.probe_nonce,
            padding,
        };
        let _ = self.send_deferred(&pong.to_wire().encode()).await;
    }

    /// Reject a message the link can't carry.
    fn check_size(data: &[u8], remote: PeerId) -> Result<()> {
        if data.len() > MAX_LINK_MESSAGE {
            log::warn!(
                "refusing to send {}-byte message to {:?}: exceeds max link message {}",
                data.len(),
                remote,
                MAX_LINK_MESSAGE
            );
            return Err(Error::Wire(format!(
                "message {} bytes exceeds max link message {}",
                data.len(),
                MAX_LINK_MESSAGE
            )));
        }
        Ok(())
    }

    /// What every outgoing message passes: the size limit, and the record of
    /// its protocol category.
    fn outgoing(&self, data: &[u8]) -> Result<()> {
        Self::check_size(data, self.remote_peer)?;
        if let Some(mt) = WireMessage::peek_type(data) {
            self.sent_categories
                .fetch_or(crate::firewall::category_bit(mt), std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// Whether this link has sent a message of `mt`'s protocol category.
    pub fn has_sent_category_of(&self, mt: MessageType) -> bool {
        self.sent_categories.load(std::sync::atomic::Ordering::Relaxed)
            & crate::firewall::category_bit(mt)
            != 0
    }

    /// Enqueue a message, dropping it if the queue is full.
    fn enqueue(&self, data: &[u8]) -> Result<()> {
        // Reserve before copying: congested links should not allocate and
        // copy a message only to discard it at admission.
        match self.outbound_tx.try_reserve() {
            Ok(permit) => {
                permit.send(Outgoing::Message(data.to_vec()));
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                log::trace!("outbound queue full to {:?}, dropping", self.remote_peer);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(Error::Wire("link closed".into()))
            }
        }
    }

    /// Send a message over the high-priority (data) queue.
    ///
    /// If the queue is full (peer is congested), the message is silently
    /// dropped — reliable end-to-end Channels handle recovery.
    pub async fn send_message(&self, data: &[u8]) -> Result<()> {
        self.outgoing(data)?;
        self.enqueue(data)
    }

    /// Send over the high-priority queue, awaiting capacity instead of
    /// dropping when the queue is full.
    ///
    /// Circuit-control cells (CREATE/EXTEND/EXTENDED/StreamBegin/…) are
    /// one-shot request/replies with no retransmission — a silent drop turns
    /// link congestion into a hard connect failure, so backpressure is the
    /// correct policy for them. Bulk stream data keeps using
    /// [`send_message`], where reliable Channels recover dropped packets.
    pub async fn send_message_critical(&self, data: &[u8]) -> Result<()> {
        self.outgoing(data)?;
        let permit = self.outbound_tx
            .reserve()
            .await
            .map_err(|_| Error::Wire("link closed".into()))?;
        permit.send(Outgoing::Critical(data.to_vec()));
        Ok(())
    }

    /// Send a non-critical message via the deferred queue.
    ///
    /// The drain task holds deferred messages for up to [`DEFERRED_FLUSH_MS`]
    /// and sends them in the frame of the next message that isn't deferred,
    /// reducing the number of distinctly-timed link-layer frames an observer
    /// can see.
    pub async fn send_deferred(&self, data: &[u8]) -> Result<()> {
        self.outgoing(data)?;
        let permit = self.outbound_tx
            .try_reserve()
            .map_err(|e| Error::Wire(format!("deferred queue admission failed: {}", e)))?;
        permit.send(Outgoing::Deferred(data.to_vec()));
        Ok(())
    }

    /// Unpack a decrypted frame: queue its messages, reassemble fragments,
    /// answer NACKs and send NACKs for gaps.
    fn ingest_frame(&self, frame: &[u8]) {
        use crate::link_frame::{parse_frame, Record};
        let now = std::time::Instant::now();
        let mut repairs = Vec::new();
        let mut inbox = self.inbox.lock().unwrap();
        for record in parse_frame(frame) {
            match record {
                Record::Message(data) => inbox.push_back(data.to_vec()),
                Record::Fragment {
                    msg_id,
                    index,
                    count,
                    bytes,
                } => {
                    let (done, nacks) =
                        self.reassembler
                            .lock()
                            .unwrap()
                            .insert(msg_id, index, count, bytes, now);
                    inbox.extend(done);
                    repairs.extend(nacks);
                    self.repair_notify.notify_one();
                }
                Record::Nack { msg_id, missing } => {
                    repairs.extend(self.sent_fragments.lock().unwrap().lookup(msg_id, &missing, now));
                }
            }
        }
        drop(inbox);
        for rec in repairs {
            // Best effort: a full repair queue costs only the repair.
            let _ = self.outbound_tx.try_send(Outgoing::Repair(rec));
        }
    }

    /// Receive and decrypt the next wire message from the link.
    pub async fn recv_message(&self) -> Result<Vec<u8>> {
        loop {
            if let Some(msg) = self.inbox.lock().unwrap().pop_front() {
                return Ok(msg);
            }
            let mut buf = self.recv_buf.lock().await;
            if buf.is_empty() {
                buf.resize(MAX_LINK_FRAME, 0);
            }
            let n = self.transport.recv_frame(&mut buf).await?;
            let result = {
                let mut crypto = self.crypto.lock().await;
                let was_due = crypto.should_rekey();
                let result = crypto.decrypt(&buf[..n]);
                if !was_due && crypto.should_rekey() { self.rekey_notify.notify_one(); }
                result
            };
            let tail = {
                let mut tail = self.handshake_tail.lock().unwrap();
                if result.is_ok() {
                    // The initiator only sends link frames once it has finished.
                    *tail = None;
                    None
                } else {
                    tail.as_ref()
                        .filter(|(theirs, _)| theirs.as_slice() == &buf[..n])
                        .map(|(_, ours)| ours.clone())
                }
            };
            drop(buf);
            if let Some(our_confirm) = tail {
                log::debug!("Handshake confirm from {:?} repeated, resending ours", self.remote_peer);
                self.transport.send(&our_confirm).await?;
            }
            // The decrypted result and its charge travel together. Delivery
            // owns the result, so callers cannot accidentally apply an
            // authenticated liveness pause to a rejected frame.
            struct FrameDelivery<'a> {
                transport: &'a dyn Transport,
                bytes: usize,
                plaintext: Result<Vec<u8>>,
            }
            impl FrameDelivery<'_> {
                async fn finish(self) -> Result<Vec<u8>> {
                    let authenticated = self.plaintext.is_ok();
                    if authenticated {
                        self.transport.authenticated_frame();
                    }
                    self.transport.deliver_frame(self.bytes, authenticated).await;
                    self.plaintext
                }
            }
            let frame = FrameDelivery {
                transport: self.transport.as_ref(),
                bytes: n,
                plaintext: result,
            };
            self.ingest_frame(&frame.finish().await?);
        }
    }

    pub(crate) fn receive_activity(&self) -> Option<std::time::Instant> {
        self.transport.receive_activity()
    }

    pub fn remote_peer(&self) -> PeerId {
        self.remote_peer
    }

    /// Responder link that has not yet received a single link frame from the
    /// initiator. Until it does, the initiator may
    /// have given up on the handshake (its final confirm never arrived), so
    /// this link must not be trusted as the way to reach the peer.
    pub fn awaiting_peer(&self) -> bool {
        self.handshake_tail.lock().unwrap().is_some()
    }

    #[cfg(test)]
    pub(crate) fn set_awaiting_peer(&self, awaiting: bool) {
        *self.handshake_tail.lock().unwrap() = awaiting.then(|| (Vec::new(), Vec::new()));
    }

    /// Whether this side initiated the connection (outbound = true, inbound = false).
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Remote peer's signing algorithm.
    pub fn remote_signing_algo(&self) -> SigningAlgo {
        self.remote_signing_algo
    }

    /// Remote peer's signing public key bytes.
    pub fn remote_signing_pubkey(&self) -> &[u8] {
        &self.remote_signing_pubkey
    }

    /// Time to send `bytes` over this link at its transport's bandwidth hint
    /// (zero when unknown or fast). Used to keep timers from firing while a
    /// message is still on the air.
    pub fn tx_time(&self, bytes: u64) -> Duration {
        tx_time(self.transport.as_ref(), bytes)
    }

    /// Time a wire message of `len` bytes takes on this link, counting the
    /// whole frames it occupies (zero when fast or unknown).
    pub fn message_airtime(&self, len: usize) -> Duration {
        let frame_plain = frame_plain_for(self.transport.as_ref());
        let frames = if len + 3 <= frame_plain {
            1
        } else {
            len.div_ceil(frame_plain.saturating_sub(9).max(1))
        };
        tx_time(self.transport.as_ref(), (frames * (frame_plain + SEQ_SIZE + TAG_SIZE)) as u64)
    }

    /// Whether the transport is below the slow-link threshold.
    pub fn is_slow(&self) -> bool {
        matches!(self.transport.bandwidth_hint(), Some(bps) if bps < SLOW_LINK_BPS)
    }

    /// Transport name (e.g. "tcp", "ws", "webrtc").
    pub fn transport_name(&self) -> &'static str {
        self.transport_name
    }

    /// Largest encoded wire message the link carries. Senders that build
    /// oversized payloads (e.g. route advertisements) must pre-split to this
    /// size; the send path rejects anything larger. Messages bigger than a
    /// frame are fragmented, so this doesn't depend on the transport MTU.
    pub fn max_wire_message(&self) -> usize {
        MAX_LINK_MESSAGE
    }

    /// Negotiated wire protocol version for this link.
    pub fn negotiated_version(&self) -> u8 {
        self.negotiated_version
    }

    /// Check if a re-key is warranted based on traffic in either direction,
    /// or one is still waiting for its reply.
    pub async fn needs_rekey(&self) -> bool {
        self.force_rekey.load(std::sync::atomic::Ordering::Relaxed)
            || self.pending_rekey.lock().await.is_some()
            || self.crypto.lock().await.should_rekey()
    }

    /// Wake the rekey driver even if traffic has not reached the threshold.
    /// Only meaningful on the initiator side.
    pub fn request_rekey(&self) {
        if self.is_initiator {
            self.force_rekey
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.rekey_notify.notify_one();
        }
    }

    /// Number of times this link's keys have been replaced since the handshake.
    pub async fn key_epoch(&self) -> u64 {
        self.crypto.lock().await.epoch
    }

    /// Owned by the node's link receive task, so link removal cancels both
    /// I/O and maintenance. Rekeys when traffic crosses the usage threshold,
    /// when the keys reach [`REKEY_MAX_AGE`], or on request.
    pub(crate) async fn drive_rekey(&self) {
        if !self.is_initiator { std::future::pending::<()>().await; }
        loop {
            let mut retry_at = None;
            if self.needs_rekey().await {
                if let Err(e) = self.rekey_initiate().await {
                    log::debug!("Rekey initiate to {:?} failed: {}", self.remote_peer, e);
                    retry_at = Some(std::time::Instant::now() + REKEY_RETRY_INTERVAL);
                }
            }
            if let Some(pending) = self.pending_rekey.lock().await.as_ref() {
                let at = pending.sent_at + REKEY_RETRY_INTERVAL;
                retry_at = Some(retry_at.map_or(at, |old| old.min(at)));
            }
            // Quiet links still rekey when their keys turn an hour old.
            // Once rotation is in flight (or initiation failed), its retry
            // deadline takes over: the old key's age deadline may already
            // be in the past and would otherwise make this loop spin.
            if retry_at.is_none() {
                retry_at = Some(self.crypto.lock().await.installed_at + REKEY_MAX_AGE);
            }
            tokio::select! {
                _ = self.rekey_notify.notified() => {}
                _ = async {
                    match retry_at {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {}
            }
        }
    }

    /// Begin an in-band rekey by sending our ephemeral KEM public key, or
    /// resend the outstanding request once [`REKEY_RETRY_INTERVAL`] has passed
    /// without a reply.
    ///
    /// Only the link *initiator* drives rekeys; the responder answers via
    /// [`handle_rekey_msg`]. This keeps roles unambiguous (no simultaneous
    /// two-sided initiation) and keeps the new key derivation directionally
    /// consistent with the original handshake.
    ///
    /// Unlike a blocking handshake, this does not read from the transport —
    /// the response arrives as an ordinary message and is fed to
    /// [`handle_rekey_msg`] by the node's receive loop. Safe to call while that
    /// loop is running.
    ///
    /// Loss tolerance: neither side switches its send key before the other is
    /// known to hold the new keys. The initiator switches on the reply (the
    /// responder can already decrypt the new key); the responder switches on
    /// the first frame it decrypts under the new key. A lost request or reply
    /// only delays the rotation until the next retry.
    pub async fn rekey_initiate(&self) -> Result<()> {
        if !self.is_initiator {
            return Ok(());
        }

        let mut pending = self.pending_rekey.lock().await;
        if let Some(p) = pending.as_mut() {
            if p.sent_at.elapsed() < REKEY_RETRY_INTERVAL {
                return Ok(());
            }
            p.sent_at = std::time::Instant::now();
            let request = p.request.clone();
            self.send_message(&request).await?;
            log::debug!("Rekey request to {:?} resent", self.remote_peer);
            return Ok(());
        }

        let eph_kem = KemKeypair::generate_ephemeral(self.rekey_kem_algo);
        let (epoch, transcript) = {
            let c = self.crypto.lock().await;
            (c.epoch + 1, c.transcript)
        };
        let mut rekey_msg = RekeyMsg {
            epoch,
            kem_algo: self.rekey_kem_algo as u8,
            kem_pubkey: eph_kem.kem_pubkey_bytes(),
            kem_ciphertext: Vec::new(),
            signature: Vec::new(),
        };
        rekey_msg.signature = self.identity.sign(&rekey_msg.signable_bytes(&transcript));
        let request = rekey_msg.to_wire().encode();
        *pending = Some(PendingRekey {
            eph_kem,
            epoch,
            request: request.clone(),
            sent_at: std::time::Instant::now(),
        });
        self.rekey_notify.notify_one();
        // Send while holding the pending lock so a concurrent caller can't slip
        // a second init in between.
        self.send_message(&request).await?;
        log::debug!("Rekey initiated with {:?}", self.remote_peer);
        Ok(())
    }

    /// Handle an inbound rekey message, dispatched from the node receive loop.
    ///
    /// A message carrying a KEM *pubkey* is a rekey request: we encapsulate to
    /// it, stage the new keys and reply (keeping our current send key until
    /// the initiator confirms). A repeated request gets the cached reply. A
    /// message carrying a *ciphertext* is the response to a rekey we
    /// initiated: we decapsulate and install; a duplicate is ignored.
    pub async fn handle_rekey_msg(&self, peer_rekey: &RekeyMsg) -> Result<()> {
        // Authenticate against the peer's static signing key. (The frame is
        // already link-authenticated by AEAD; this binds it to the peer's
        // long-term identity and to this link's handshake, so an attacker
        // holding only session keys can't take the rekey over.)
        let transcript = self.crypto.lock().await.transcript;
        if !identity::verify_signed(
            identity::SignedBy::BoundKey,
            Some(self.remote_signing_algo as u8),
            &self.remote_signing_pubkey,
            &peer_rekey.signable_bytes(&transcript),
            &peer_rekey.signature,
        ) {
            return Err(Error::Crypto("rekey signature invalid".into()));
        }
        KemAlgo::from_u8(peer_rekey.kem_algo)
            .map_err(|e| Error::Crypto(format!("unknown rekey KEM algo: {}", e)))?;

        if !peer_rekey.kem_pubkey.is_empty() {
            let tag = rekey_tag(&peer_rekey.kem_pubkey);
            let mut cached = self.rekey_reply.lock().await;
            if self.crypto.lock().await.completed_tag == Some(tag) {
                // Late copy of a request whose keys are already in use.
                return Ok(());
            }
            if let Some((cached_tag, reply)) = cached.as_ref() {
                if *cached_tag == tag {
                    // The initiator retried: our reply was lost or is slow.
                    let reply = reply.clone();
                    drop(cached);
                    return self.send_message_critical(&reply).await;
                }
            }
            let current = self.crypto.lock().await.epoch;
            if peer_rekey.epoch != current + 1 {
                return Err(Error::Crypto(format!(
                    "rekey for epoch {} while at {}",
                    peer_rekey.epoch, current
                )));
            }

            let (kem_ss, kem_ct) =
                KemKeypair::encapsulate_to(&peer_rekey.kem_pubkey, self.rekey_kem_algo)
                    .map_err(|e| Error::Crypto(format!("rekey KEM encapsulate failed: {}", e)))?;
            let kem_ss = Zeroizing::new(kem_ss);

            let mut reply = RekeyMsg {
                epoch: peer_rekey.epoch,
                kem_algo: self.rekey_kem_algo as u8,
                kem_pubkey: Vec::new(),
                kem_ciphertext: kem_ct,
                signature: Vec::new(),
            };
            reply.signature = self.identity.sign(&reply.signable_bytes(&transcript));
            let mut crypto = self.crypto.lock().await;
            let new_shared =
                crypto.rekey_secret(peer_rekey.epoch, &kem_ss, &peer_rekey.kem_pubkey, &reply.kem_ciphertext);
            crypto.stage_rekey(&new_shared, self.is_initiator, tag);
            drop(crypto);
            let reply = reply.to_wire().encode();
            *cached = Some((tag, reply.clone()));
            drop(cached);
            // Goes out under the current key, which stays our send key until
            // the initiator's first new-key frame arrives.
            self.send_message_critical(&reply).await?;
            log::debug!("Answered rekey request from {:?}", self.remote_peer);
            Ok(())
        } else if !peer_rekey.kem_ciphertext.is_empty() {
            // Response to a rekey we initiated.
            let mut pending_slot = self.pending_rekey.lock().await;
            let Some(pending) = pending_slot.as_ref() else {
                // A duplicate reply to a retried request we already completed.
                log::trace!("Ignoring duplicate rekey reply from {:?}", self.remote_peer);
                return Ok(());
            };
            if peer_rekey.epoch != pending.epoch {
                return Err(Error::Crypto("rekey reply for another epoch".into()));
            }
            let pending = pending_slot.take().expect("checked above");
            // Keep initiation blocked until the new epoch and force flag are
            // committed. Otherwise the driver can start a fresh request for
            // the same epoch while we are still installing this reply.
            let kem_ss = pending
                .eph_kem
                .decapsulate(&peer_rekey.kem_ciphertext)
                .map_err(|e| Error::Crypto(format!("rekey KEM decapsulate failed: {}", e)))?;
            let kem_ss = Zeroizing::new(kem_ss);
            let mut crypto = self.crypto.lock().await;
            let new_shared = crypto.rekey_secret(
                pending.epoch,
                &kem_ss,
                &pending.eph_kem.kem_pubkey_bytes(),
                &peer_rekey.kem_ciphertext,
            );
            crypto.install_rekey(&new_shared, self.is_initiator);
            drop(crypto);
            self.force_rekey
                .store(false, std::sync::atomic::Ordering::Relaxed);
            drop(pending_slot);
            self.rekey_notify.notify_one();
            log::debug!("Re-keyed link with {:?} (initiated)", self.remote_peer);
            Ok(())
        } else {
            Err(Error::Crypto("empty rekey message".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_rejects_unknown_replays_and_expired_challenges() {
        let now = std::time::Instant::now();
        let mut rtt = LinkRtt::default();
        rtt.received([1; 16], now);
        assert_eq!(rtt.observed_us(now), 0);
        rtt.sent([1; 16], now);
        rtt.received([2; 16], now + Duration::from_millis(5));
        assert_eq!(rtt.observed_us(now), 0);
        rtt.received([1; 16], now + Duration::from_millis(20));
        assert_eq!(rtt.observed_us(now + Duration::from_millis(20)), 20_000);
        rtt.received([1; 16], now + Duration::from_millis(100));
        assert_eq!(rtt.sample.unwrap().0, 20_000);
        rtt.sent([3; 16], now);
        rtt.received([3; 16], now + RTT_PROBE_TTL);
        assert_eq!(rtt.sample.unwrap().0, 20_000);
        assert_eq!(
            rtt.observed_us(now + RTT_STALE_AFTER + Duration::from_secs(1)),
            0
        );
    }

    #[test]
    fn rtt_bounds_state_smooths_and_resets_stale_samples() {
        let now = std::time::Instant::now();
        let mut rtt = LinkRtt::default();
        for n in 0..10 {
            rtt.sent([n; 16], now);
        }
        assert_eq!(rtt.pending.len(), RTT_MAX_PENDING);
        rtt.received([0; 16], now + Duration::from_millis(10));
        assert!(rtt.sample.is_none());
        rtt.received([9; 16], now + Duration::from_millis(20));
        rtt.received([8; 16], now + Duration::from_millis(60));
        assert_eq!(rtt.sample.unwrap().0, 30_000);
        let later = now + RTT_STALE_AFTER + Duration::from_secs(1);
        rtt.sent([10; 16], later);
        rtt.received([10; 16], later + Duration::from_millis(100));
        assert_eq!(rtt.sample.unwrap().0, 100_000);
        assert!(rtt.allow_reply(now));
        assert!(!rtt.allow_reply(now));
        assert!(rtt.allow_reply(now + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn rtt_echo_stays_on_its_link_and_accepts_only_matching_replies() {
        use crate::wire::KeepaliveMsg;
        let (ia, ib) = (Keypair::generate(), Keypair::generate());
        let mut links = Vec::new();
        for _ in 0..2 {
            let (a, b) = lossy_pair(&[], &[]);
            let (la, lb) = tokio::join!(
                PeerLink::initiator(Box::new(a), &ia, None),
                PeerLink::responder(Box::new(b), &ib)
            );
            links.push((Arc::new(la.unwrap()), Arc::new(lb.unwrap())));
        }
        let (a, b) = &links[0];
        let (other_a, other_b) = &links[1];
        let mut table = crate::peer_transport::LinkTable::new();
        let peer = a.remote_peer();
        table.insert(peer, other_a.clone());
        let (measured_id, _) = table.insert(peer, a.clone());
        let active_before = table.get(&peer).unwrap().clone();
        let request = KeepaliveMsg {
            ping_id: Some(42),
            probe_nonce: Some([7; 16]),
            padding: vec![0; 256],
        };
        let crypto_guard = a.crypto.lock().await;
        a.send_deferred(&request.to_wire().encode()).await.unwrap();
        // Queue admission cannot start a measurement before encryption/send.
        assert!(a.rtt.lock().unwrap().pending.is_empty());
        drop(crypto_guard);
        let wire = WireMessage::decode(&recv_good(b).await).unwrap();
        let received = KeepaliveMsg::from_bytes(&wire.payload).unwrap();
        assert_eq!(received.probe_nonce, request.probe_nonce);
        // Sending is timestamped by the frame worker, not queue admission.
        assert_eq!(a.rtt.lock().unwrap().pending.len(), 1);
        b.handle_keepalive(&received).await;
        let wire = WireMessage::decode(&recv_good(a).await).unwrap();
        let reply = KeepaliveMsg::from_bytes(&wire.payload).unwrap();
        assert!(reply.ping_id.is_none());
        assert_eq!(reply.probe_nonce, request.probe_nonce);
        other_a.handle_keepalive(&reply).await;
        assert_eq!(other_a.observed_rtt_us(), 0);
        a.handle_keepalive(&KeepaliveMsg {
            ping_id: None,
            probe_nonce: None,
            padding: vec![],
        })
        .await;
        assert_eq!(a.observed_rtt_us(), 0); // legacy pong cannot produce a sample
        a.handle_keepalive(&reply).await;
        assert!(a.observed_rtt_us() > 0);
        let snapshot = table.peer_info_snapshot();
        let measured = snapshot[0]
            .links
            .iter()
            .find(|l| l.link_id == measured_id)
            .unwrap();
        assert_eq!(measured.rtt_us, a.observed_rtt_us());
        assert!(Arc::ptr_eq(table.get(&peer).unwrap(), &active_before));
        assert!(a.rtt.lock().unwrap().pending.is_empty());
        let sample = a.rtt.lock().unwrap().sample;
        a.handle_keepalive(&reply).await;
        assert_eq!(a.rtt.lock().unwrap().sample, sample);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), other_b.recv_message())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), b.recv_message())
                .await
                .is_err()
        );
    }

    #[test]
    fn crypto_roundtrip() {
        let shared = [42u8; 32];
        let mut initiator = LinkCrypto::derive(&shared, true);
        let mut responder = LinkCrypto::derive(&shared, false);

        let plaintext = b"hello tarnet link layer";
        let encrypted = initiator.encrypt(plaintext);
        let decrypted = responder.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        let encrypted2 = responder.encrypt(b"response");
        let decrypted2 = initiator.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted2, b"response");
    }

    #[test]
    fn crypto_tamper_detected() {
        let shared = [42u8; 32];
        let mut initiator = LinkCrypto::derive(&shared, true);
        let mut responder = LinkCrypto::derive(&shared, false);

        let mut encrypted = initiator.encrypt(b"data");
        // Flip a ciphertext byte (after seq)
        encrypted[SEQ_SIZE] ^= 0xff;
        assert!(responder.decrypt(&encrypted).is_err());
    }

    #[test]
    fn replay_detection() {
        let shared = [42u8; 32];
        let mut initiator = LinkCrypto::derive(&shared, true);
        let mut responder = LinkCrypto::derive(&shared, false);

        let enc1 = initiator.encrypt(b"msg1");
        let enc2 = initiator.encrypt(b"msg2");

        // Normal order works
        let _ = responder.decrypt(&enc1).unwrap();
        let _ = responder.decrypt(&enc2).unwrap();

        // Replay of enc1 should fail
        assert!(responder.decrypt(&enc1).is_err());
    }

    #[test]
    fn out_of_order_within_window() {
        let shared = [42u8; 32];
        let mut initiator = LinkCrypto::derive(&shared, true);
        let mut responder = LinkCrypto::derive(&shared, false);

        let enc0 = initiator.encrypt(b"msg0");
        let enc1 = initiator.encrypt(b"msg1");
        let enc2 = initiator.encrypt(b"msg2");

        // Deliver out of order: 2, 0, 1
        let _ = responder.decrypt(&enc2).unwrap();
        let _ = responder.decrypt(&enc0).unwrap();
        let _ = responder.decrypt(&enc1).unwrap();
    }

    #[test]
    fn sequence_counter_increments() {
        let shared = [42u8; 32];
        let mut crypto = LinkCrypto::derive(&shared, true);
        assert_eq!(crypto.send_count(), 0);
        crypto.encrypt(b"msg1");
        assert_eq!(crypto.send_count(), 1);
        crypto.encrypt(b"msg2");
        assert_eq!(crypto.send_count(), 2);
    }

    #[test]
    fn rekey_basic_roundtrip() {
        let shared = [42u8; 32];
        let mut init = LinkCrypto::derive(&shared, true);
        let mut resp = LinkCrypto::derive(&shared, false);

        let d = init.encrypt(b"pre-rekey");
        assert_eq!(resp.decrypt(&d).unwrap(), b"pre-rekey");

        let new_shared = [99u8; 32];
        resp.install_rekey(&new_shared, false);
        init.install_rekey(&new_shared, true);

        // Both directions work under the new keys, seq counters reset.
        let a = init.encrypt(b"post-i2r");
        assert_eq!(resp.decrypt(&a).unwrap(), b"post-i2r");
        let b = resp.encrypt(b"post-r2i");
        assert_eq!(init.decrypt(&b).unwrap(), b"post-r2i");
    }

    #[test]
    fn rekey_transition_overlap_is_lossless() {
        // Models the real switchover: the responder installs new keys when it
        // receives the rekey request, but the initiator keeps sending under the
        // old key until it gets the response. Those in-flight frames must still
        // decrypt via the responder's retained previous key.
        let shared = [7u8; 32];
        let mut init = LinkCrypto::derive(&shared, true);
        let mut resp = LinkCrypto::derive(&shared, false);

        let d = init.encrypt(b"old-i2r");
        assert_eq!(resp.decrypt(&d).unwrap(), b"old-i2r");

        let new_shared = [9u8; 32];

        // Responder switches first.
        resp.install_rekey(&new_shared, false);

        // Initiator still on old send key — straggler must survive.
        let straggler = init.encrypt(b"straggler");
        assert_eq!(resp.decrypt(&straggler).unwrap(), b"straggler");

        // Initiator switches; subsequent frames use the new key.
        init.install_rekey(&new_shared, true);
        let fresh = init.encrypt(b"new-i2r");
        assert_eq!(resp.decrypt(&fresh).unwrap(), b"new-i2r");

        // Reverse direction works too.
        let r = resp.encrypt(b"new-r2i");
        assert_eq!(init.decrypt(&r).unwrap(), b"new-r2i");
    }

    #[test]
    fn rekey_retains_previous_key_until_next_rekey() {
        // The previous-epoch key is retained for the whole new epoch (so a
        // reordered straggler that arrives *after* a new-key frame still
        // decrypts), and is only rotated out at the next rekey — no indefinite
        // acceptance window across more than one epoch.
        let shared = [3u8; 32];
        let mut init = LinkCrypto::derive(&shared, true);
        let mut resp = LinkCrypto::derive(&shared, false);

        let old_frame = init.encrypt(b"under-old"); // epoch 0, OLD key
        let new_shared = [5u8; 32];
        resp.install_rekey(&new_shared, false);
        init.install_rekey(&new_shared, true);

        // A new-key frame decrypts under the current key...
        let new_frame = init.encrypt(b"under-new"); // epoch 1, seq 0
        assert_eq!(resp.decrypt(&new_frame).unwrap(), b"under-new");

        // ...and a straggler from epoch 0, arriving *after* it (as reordering
        // would produce), still decrypts via the retained previous key.
        assert_eq!(resp.decrypt(&old_frame).unwrap(), b"under-old");

        // After a second rekey the epoch-0 key is rotated out (bounded
        // retention: at most one previous epoch). A fresh frame under the
        // original epoch-0 key no longer decrypts.
        let newer_shared = [7u8; 32];
        resp.install_rekey(&newer_shared, false);
        init.install_rekey(&newer_shared, true);
        let mut epoch0 = LinkCrypto::derive(&shared, true);
        let epoch0_frame = epoch0.encrypt(b"ancient");
        assert!(resp.decrypt(&epoch0_frame).is_err());
    }

    #[test]
    fn staged_rekey_switches_on_first_new_key_frame() {
        let shared = [11u8; 32];
        let mut init = LinkCrypto::derive(&shared, true);
        let mut resp = LinkCrypto::derive(&shared, false);
        let new_shared = [12u8; 32];

        // Responder answers and stages; it keeps sending under the old key,
        // which the initiator can read whether or not it got the reply.
        resp.stage_rekey(&new_shared, false, [1u8; 32]);
        let r_old = resp.encrypt(b"still-old");
        assert_eq!(init.decrypt(&r_old).unwrap(), b"still-old");
        assert_eq!(resp.epoch, 0);

        // Initiator gets the reply and installs. Old-key frames from the
        // responder still decrypt via the retained previous key.
        init.install_rekey(&new_shared, true);
        let r_old2 = resp.encrypt(b"old-after-install");
        assert_eq!(init.decrypt(&r_old2).unwrap(), b"old-after-install");

        // First new-key frame from the initiator promotes the staged keys.
        let i_new = init.encrypt(b"confirm");
        assert_eq!(resp.decrypt(&i_new).unwrap(), b"confirm");
        assert_eq!(resp.epoch, 1);
        assert_eq!(resp.completed_tag, Some([1u8; 32]));
        assert!(resp.pending_recv.is_none());
        let r_new = resp.encrypt(b"new");
        assert_eq!(init.decrypt(&r_new).unwrap(), b"new");
    }

    #[test]
    fn restaged_rekey_replaces_unconfirmed_one() {
        let shared = [13u8; 32];
        let mut init = LinkCrypto::derive(&shared, true);
        let mut resp = LinkCrypto::derive(&shared, false);
        resp.stage_rekey(&[14u8; 32], false, [1u8; 32]);
        resp.stage_rekey(&[15u8; 32], false, [2u8; 32]);
        init.install_rekey(&[15u8; 32], true);
        let f = init.encrypt(b"x");
        assert_eq!(resp.decrypt(&f).unwrap(), b"x");
        assert_eq!(resp.completed_tag, Some([2u8; 32]));
    }

    /// In-memory datagram transport that drops the sends whose index (per
    /// side, counting from 0) is listed.
    struct LossyMem {
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
        /// Indices of sent frames to drop. Shared so a test can add drops
        /// after the handshake.
        drop: Arc<std::sync::Mutex<Vec<usize>>>,
        sent: Arc<std::sync::atomic::AtomicUsize>,
        /// Sizes of the frames sent, dropped or not.
        sizes: Arc<std::sync::Mutex<Vec<usize>>>,
        bps: Option<u64>,
    }

    fn lossy_pair(drop_a: &[usize], drop_b: &[usize]) -> (LossyMem, LossyMem) {
        let (tx_a, rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, rx_b) = tokio::sync::mpsc::unbounded_channel();
        let mk = |tx, rx, drop: &[usize]| LossyMem {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            drop: Arc::new(std::sync::Mutex::new(drop.to_vec())),
            sent: Default::default(),
            sizes: Default::default(),
            bps: None,
        };
        (mk(tx_a, rx_b, drop_a), mk(tx_b, rx_a, drop_b))
    }

    #[async_trait::async_trait]
    impl Transport for LossyMem {
        async fn send(&self, data: &[u8]) -> Result<()> {
            let i = self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.sizes.lock().unwrap().push(data.len());
            if !self.drop.lock().unwrap().contains(&i) {
                let _ = self.tx.send(data.to_vec());
            }
            Ok(())
        }
        async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
            let data = self.rx.lock().await.recv().await.ok_or(Error::NotFound)?;
            buf[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        }
        fn mtu(&self) -> usize {
            65536
        }
        fn is_reliable(&self) -> bool {
            false
        }
        fn name(&self) -> &'static str {
            "lossy-mem"
        }
        fn bandwidth_hint(&self) -> Option<u64> {
            self.bps
        }
    }

    /// Handle on one side's sent frames that outlives moving the transport
    /// into a link.
    struct SentLog {
        drop: Arc<std::sync::Mutex<Vec<usize>>>,
        sent: Arc<std::sync::atomic::AtomicUsize>,
        sizes: Arc<std::sync::Mutex<Vec<usize>>>,
    }

    impl SentLog {
        fn of(t: &LossyMem) -> Self {
            Self {
                drop: t.drop.clone(),
                sent: t.sent.clone(),
                sizes: t.sizes.clone(),
            }
        }
        fn count(&self) -> usize {
            self.sent.load(std::sync::atomic::Ordering::SeqCst)
        }
        /// Drop the frames that will be the `nth` (0-based) sent from now.
        fn drop_upcoming(&self, nth: &[usize]) {
            let base = self.count();
            self.drop.lock().unwrap().extend(nth.iter().map(|n| base + n));
        }
    }

    /// Keep a link's receive path running so it answers NACKs.
    fn pump(l: Arc<PeerLink>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { while l.recv_message().await.is_ok() || true {} })
    }

    #[test]
    fn frame_seq_is_authenticated() {
        let shared = [42u8; 32];
        let mut initiator = LinkCrypto::derive(&shared, true);
        let mut responder = LinkCrypto::derive(&shared, false);
        initiator.encrypt(b"first");
        let mut frame = initiator.encrypt(b"second");
        assert_eq!(&frame[..SEQ_SIZE], &1u64.to_be_bytes(), "seq travels in clear");
        frame[SEQ_SIZE - 1] = 5; // claim another seq
        assert!(responder.decrypt(&frame).is_err());
    }

    #[tokio::test]
    async fn slow_link_uses_small_frames_and_fragments_large_messages() {
        let (mut a, mut b) = lossy_pair(&[], &[]);
        a.bps = Some(1000);
        b.bps = Some(1000);
        let log = SentLog::of(&a);
        let (la, lb) = handshake_over(a, b).await;
        let before = log.count();
        let big: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        la.send_message(&big).await.unwrap();
        la.send_message(&ping()).await.unwrap();
        // The keepalive is control class and may overtake the bulk message.
        let mut got = vec![recv_good(&lb).await, recv_good(&lb).await];
        got.sort_by_key(|m| m.len());
        assert_eq!(got, vec![ping(), big]);
        let sizes = log.sizes.lock().unwrap()[before..].to_vec();
        assert!(sizes.len() >= 3000 / SLOW_FRAME_PLAIN);
        assert!(sizes.iter().all(|&n| n == 256), "every slow-link frame is 256 B: {:?}", sizes);
    }

    #[tokio::test]
    async fn deferred_send_reports_admission_failure_under_congestion() {
        let (a, b) = lossy_pair(&[], &[]);
        let (link, _remote) = handshake_over(a, b).await;
        // Reservations deterministically fill admission capacity, independently
        // of drain-task scheduling or transport speed.
        let _capacity = link.outbound_tx.reserve_many(link.outbound_tx.max_capacity()).await.unwrap();
        assert!(link.send_deferred(&ping()).await.is_err());
        drop(_capacity);
        assert!(link.send_deferred(&ping()).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tickless_rekey_driver_quiesces_after_repeated_rotations() {
        use std::{future::Future, pin::Pin, task::{Context, Poll}};
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counted<F> { future: Pin<Box<F>>, polls: Arc<AtomicUsize> }
        impl<F: Future> Future for Counted<F> {
            type Output = F::Output;
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.get_mut();
                this.polls.fetch_add(1, Ordering::Relaxed);
                this.future.as_mut().poll(cx)
            }
        }
        let (a, b) = lossy_pair(&[], &[]);
        let (a, b) = handshake_over(a, b).await;
        // An aged key with an unanswered request must wait for the retry,
        // rather than repeatedly waking on the expired key-age deadline.
        a.crypto.lock().await.installed_at = std::time::Instant::now() - REKEY_MAX_AGE;
        let polls = Arc::new(AtomicUsize::new(0));
        let driven = a.clone();
        let task = tokio::spawn(Counted {
            future: Box::pin(async move { driven.drive_rekey().await }),
            polls: polls.clone(),
        });
        let first = WireMessage::decode(&recv_good(&b).await).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let before = polls.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let idle_polls = polls.load(Ordering::Relaxed) - before;
        task.abort();
        assert!(idle_polls <= 2, "aged keys caused {idle_polls} driver polls while awaiting a reply");
        task.await.ok();
        b.handle_rekey_msg(&RekeyMsg::from_bytes(&first.payload).unwrap()).await.unwrap();
        let reply = WireMessage::decode(&recv_good(&a).await).unwrap();
        a.handle_rekey_msg(&RekeyMsg::from_bytes(&reply.payload).unwrap()).await.unwrap();
        a.send_message(&ping()).await.unwrap();
        assert_eq!(recv_good(&b).await, ping());
        let driven = a.clone();
        let task = tokio::spawn(Counted {
            future: Box::pin(async move { driven.drive_rekey().await }),
            polls: polls.clone(),
        });
        for epoch in 2..=33 {
            a.request_rekey();
            let request = WireMessage::decode(&recv_good(&b).await).unwrap();
            b.handle_rekey_msg(&RekeyMsg::from_bytes(&request.payload).unwrap()).await.unwrap();
            let reply = WireMessage::decode(&recv_good(&a).await).unwrap();
            a.handle_rekey_msg(&RekeyMsg::from_bytes(&reply.payload).unwrap()).await.unwrap();
            assert_eq!(a.key_epoch().await, epoch);
            a.send_message(&ping()).await.unwrap();
            assert_eq!(recv_good(&b).await, ping());
            assert_eq!(b.key_epoch().await, epoch);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let before = polls.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1250)).await;
        assert_eq!(polls.load(Ordering::Relaxed), before, "completed rekeys left a polling timer");
        eprintln!("tickless rekey: 32 rotations, {before} driver polls, 0 idle polls in 1250 ms");
        task.abort();
    }

    #[tokio::test]
    async fn rekey_reply_blocks_new_initiation_until_epoch_is_installed() {
        let (a, b) = lossy_pair(&[], &[]);
        let (a, b) = handshake_over(a, b).await;
        a.request_rekey();
        a.rekey_initiate().await.unwrap();
        let request = WireMessage::decode(&recv_good(&b).await).unwrap();
        b.handle_rekey_msg(&RekeyMsg::from_bytes(&request.payload).unwrap()).await.unwrap();
        let reply = WireMessage::decode(&recv_good(&a).await).unwrap();
        let reply = RekeyMsg::from_bytes(&reply.payload).unwrap();

        // Let signature verification finish, then hold key installation up
        // while a concurrent driver attempts to initiate another rotation.
        let pending = a.pending_rekey.lock().await;
        let handler_link = a.clone();
        let handler = tokio::spawn(async move { handler_link.handle_rekey_msg(&reply).await });
        tokio::task::yield_now().await;
        let crypto = a.crypto.lock().await;
        drop(pending);
        tokio::task::yield_now().await;
        assert!(a.pending_rekey.try_lock().is_err(), "reply released pending state before installation");
        let driver_link = a.clone();
        let driver = tokio::spawn(async move { driver_link.rekey_initiate().await });
        tokio::task::yield_now().await;
        drop(crypto);
        handler.await.unwrap().unwrap();
        driver.await.unwrap().unwrap();
        // A concurrent explicit initiation is allowed, but must target epoch 2.
        assert_eq!(a.key_epoch().await, 1);
        assert_eq!(a.pending_rekey.lock().await.as_ref().unwrap().epoch, 2);
        let request = WireMessage::decode(&recv_good(&b).await).unwrap();
        let request = RekeyMsg::from_bytes(&request.payload).unwrap();
        assert_eq!(request.epoch, 2);
        b.handle_rekey_msg(&request).await.unwrap();
    }

    #[tokio::test]
    async fn rekey_driver_wakes_for_force_traffic_and_age() {
        for trigger in 0..4 {
            let (a, b) = lossy_pair(&[], &[]);
            let (a, b) = handshake_over(a, b).await;
            if trigger == 3 {
                a.crypto.lock().await.installed_at = std::time::Instant::now() - REKEY_MAX_AGE;
            }
            let driver_link = a.clone();
            let driver = tokio::spawn(async move { driver_link.drive_rekey().await; });
            match trigger {
                0 => a.request_rekey(),
                1 => {
                    a.crypto.lock().await.send_seq = REKEY_INTERVAL - 1;
                    a.send_message(&ping()).await.unwrap();
                    assert_eq!(recv_good(&b).await, ping());
                }
                2 => {
                    b.crypto.lock().await.send_seq = REKEY_INTERVAL;
                    b.send_message(&ping()).await.unwrap();
                    assert_eq!(recv_good(&a).await, ping());
                }
                _ => {} // The age deadline itself starts the rotation.
            }
            let request = recv_good(&b).await;
            let decoded = WireMessage::decode(&request).unwrap();
            assert_eq!(decoded.msg_type, MessageType::Rekey);
            // Ignore a request, then ignore its first reply: the driver must
            // retry on its one-shot deadline with no periodic node sweep.
            assert_eq!(recv_good(&b).await, request);
            let request = RekeyMsg::from_bytes(&decoded.payload).unwrap();
            b.handle_rekey_msg(&request).await.unwrap();
            let _lost_reply = recv_good(&a).await;
            let retry = WireMessage::decode(&recv_good(&b).await).unwrap();
            b.handle_rekey_msg(&RekeyMsg::from_bytes(&retry.payload).unwrap()).await.unwrap();
            let reply = WireMessage::decode(&recv_good(&a).await).unwrap();
            a.handle_rekey_msg(&RekeyMsg::from_bytes(&reply.payload).unwrap()).await.unwrap();
            assert_eq!(a.key_epoch().await, 1);
            assert!(!a.needs_rekey().await);
            a.send_message(&ping()).await.unwrap();
            assert_eq!(recv_good(&b).await, ping());
            assert_eq!(b.key_epoch().await, 1);
            driver.abort();
        }
    }

    #[tokio::test]
    async fn small_messages_share_a_frame() {
        let (a, b) = lossy_pair(&[], &[]);
        let log = SentLog::of(&a);
        let (la, lb) = handshake_over(a, b).await;
        let before = log.count();
        for _ in 0..10 {
            la.send_deferred(&ping()).await.unwrap();
        }
        for _ in 0..10 {
            assert_eq!(recv_good(&lb).await, ping());
        }
        let frames = log.count() - before;
        assert!(frames < 10, "10 keepalives took {} frames", frames);
        let sizes = log.sizes.lock().unwrap()[before..].to_vec();
        assert!(sizes.iter().all(|&n| n == FAST_FRAME_PLAIN + SEQ_SIZE + TAG_SIZE));
    }

    #[tokio::test]
    async fn lost_middle_fragment_is_repaired_by_nack() {
        let (a, b) = lossy_pair(&[], &[]);
        let log = SentLog::of(&a);
        let (la, lb) = handshake_over(a, b).await;
        let _pump = pump(la.clone());
        let big = vec![7u8; 6000]; // 5 fragments of a fast frame
        log.drop_upcoming(&[2]);
        la.send_message(&big).await.unwrap();
        assert_eq!(recv_good(&lb).await, big);
    }

    #[tokio::test]
    async fn lost_last_fragment_is_repaired_after_stall() {
        let (a, b) = lossy_pair(&[], &[]);
        let log = SentLog::of(&a);
        let (la, lb) = handshake_over(a, b).await;
        let _pump = pump(la.clone());
        let big = vec![3u8; 6000];
        let frags = 6000usize.div_ceil(FAST_FRAME_PLAIN - 9);
        log.drop_upcoming(&[frags - 1]);
        la.send_message(&big).await.unwrap();
        assert_eq!(recv_good(&lb).await, big);
    }

    #[tokio::test]
    async fn handshake_deadline_restarts_on_progress() {
        let progress = HandshakeProgress::new(std::time::Instant::now().into());
        let ticker = progress.clone();
        let keep_alive = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                *ticker.lock().unwrap() = std::time::Instant::now();
            }
        });
        let slow = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(())
        };
        with_handshake_deadline(Duration::from_millis(100), progress.clone(), slow)
            .await
            .expect("progress keeps a slow handshake alive");

        // Still trickling, but past the hard cap.
        let never = std::future::pending::<Result<()>>();
        let t0 = std::time::Instant::now();
        assert!(with_handshake_deadline(Duration::from_millis(30), progress.clone(), never)
            .await
            .is_err());
        assert!(t0.elapsed() >= Duration::from_millis(30) * HANDSHAKE_HARD_CAP_FACTOR);
        keep_alive.abort();

        // Silence fails after one deadline.
        let quiet = HandshakeProgress::new(std::time::Instant::now().into());
        let t0 = std::time::Instant::now();
        let never = std::future::pending::<Result<()>>();
        assert!(with_handshake_deadline(Duration::from_millis(50), quiet, never)
            .await
            .is_err());
        assert!(t0.elapsed() < Duration::from_millis(50) * HANDSHAKE_HARD_CAP_FACTOR);
    }

    #[test]
    fn slow_link_handshake_deadline_covers_airtime() {
        let (mut a, _b) = lossy_pair(&[], &[]);
        assert_eq!(handshake_deadline(&a), HANDSHAKE_TIMEOUT);
        a.bps = Some(500);
        // ~6 KB at 500 B/s, three times over.
        assert!(handshake_deadline(&a) >= Duration::from_secs(36));
    }

    async fn handshake_over(a: LossyMem, b: LossyMem) -> (Arc<PeerLink>, Arc<PeerLink>) {
        let (ia, ib) = (Keypair::generate(), Keypair::generate());
        let (la, lb) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(
                PeerLink::initiator(Box::new(a), &ia, None),
                PeerLink::responder(Box::new(b), &ib)
            )
        })
        .await
        .expect("handshake hung");
        (Arc::new(la.unwrap()), Arc::new(lb.unwrap()))
    }

    /// A hybrid KEM key or ciphertext whose X25519 half is a low-order point.
    fn low_order(mut bytes: Vec<u8>, first_byte: u8) -> Vec<u8> {
        bytes[..32].fill(0);
        bytes[0] = first_byte;
        bytes
    }

    #[tokio::test]
    async fn handshake_rejects_low_order_x25519_in_both_roles() {
        for first_byte in [0, 1] {
            // Responder: the initiator's ephemeral KEM key.
            let (a, b) = lossy_pair(&[], &[]);
            let identity = Keypair::generate();
            let eph = KemKeypair::generate_ephemeral(KemAlgo::MlkemX25519);
            let hello = HandshakeHello {
                min_version: WIRE_VERSION_MIN,
                max_version: WIRE_VERSION_MAX,
                nonce: [42; 32],
                eph_kem_pubkey: low_order(eph.kem_pubkey_bytes(), first_byte),
            };
            b.send(&hello.to_wire().encode()).await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(2), PeerLink::responder(Box::new(a), &identity))
                .await
                .expect("invalid KEM key must fail at once");
            assert!(matches!(result, Err(Error::Crypto(ref e)) if e.contains("non-contributory")));

            // Initiator: the responder's ciphertext.
            let (a, b) = lossy_pair(&[], &[]);
            let (_, ct) = KemKeypair::encapsulate_to(&eph.kem_pubkey_bytes(), KemAlgo::MlkemX25519).unwrap();
            let resp = HandshakeResponse {
                version: WIRE_VERSION_MAX,
                min_version: WIRE_VERSION_MIN,
                max_version: WIRE_VERSION_MAX,
                nonce: [7; 32],
                kem_ciphertext: low_order(ct, first_byte),
                sealed: vec![0; 64],
            };
            b.send(&resp.to_wire().encode()).await.unwrap();
            let result =
                tokio::time::timeout(Duration::from_secs(2), PeerLink::initiator(Box::new(a), &identity, None))
                    .await
                    .expect("invalid ciphertext must fail at once");
            assert!(matches!(result, Err(Error::Crypto(ref e)) if e.contains("non-contributory")));
        }
    }

    /// Nodes must be hybrid: either side refuses an Ed25519-only peer.
    #[tokio::test]
    async fn handshake_refuses_ecc_peers_in_both_roles() {
        for ecc_initiates in [true, false] {
            let (a, b) = lossy_pair(&[], &[]);
            let (hybrid, ecc) = (Keypair::generate(), Keypair::generate_ed25519());
            let (ia, ib) = if ecc_initiates { (&ecc, &hybrid) } else { (&hybrid, &ecc) };
            let (la, lb) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::select! {
                    r = PeerLink::initiator(Box::new(a), ia, None) => (Some(r), None),
                    r = PeerLink::responder(Box::new(b), ib) => (None, Some(r)),
                }
            })
            .await
            .expect("handshake hung");
            // The hybrid side is the one that notices and refuses.
            let refused = if ecc_initiates { lb } else { la };
            assert!(
                matches!(refused, Some(Err(Error::Crypto(ref e))) if e.contains("not a hybrid identity")),
                "ecc_initiates={ecc_initiates}"
            );
        }
    }

    #[tokio::test]
    async fn initiator_pins_the_expected_peer() {
        let (a, b) = lossy_pair(&[], &[]);
        let (ia, ib) = (Keypair::generate(), Keypair::generate());
        let wrong = Keypair::generate().peer_id();
        let (la, _lb) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                PeerLink::initiator(Box::new(a), &ia, Some(wrong)),
                async {
                    let _ = tokio::time::timeout(Duration::from_secs(2), PeerLink::responder(Box::new(b), &ib)).await;
                }
            )
        })
        .await
        .unwrap();
        assert!(matches!(la, Err(Error::Crypto(ref e)) if e.contains("expected")));
    }

    fn ping() -> Vec<u8> {
        crate::wire::KeepaliveMsg {
            ping_id: None,
            probe_nonce: None,
            padding: Vec::new(),
        }
        .to_wire()
        .encode()
    }

    /// Next frame that decrypts, skipping bad ones as the node's receive loop
    /// does (e.g. a late duplicate handshake message).
    async fn recv_good(l: &PeerLink) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(m) = l.recv_message().await {
                    return m;
                }
            }
        })
        .await
        .expect("recv hung")
    }

    async fn assert_both_ways(a: &PeerLink, b: &PeerLink) {
        a.send_message(&ping()).await.unwrap();
        recv_good(b).await;
        b.send_message(&ping()).await.unwrap();
        recv_good(a).await;
    }

    #[test]
    fn rekey_is_due_by_age_and_chains_secrets() {
        let mut c = LinkCrypto::derive(&[1; 32], true).with_chain(&[1; 32], [2; 32]);
        assert!(!c.should_rekey());
        c.installed_at = std::time::Instant::now() - REKEY_MAX_AGE;
        assert!(c.should_rekey());
        // The new secret depends on the old chain secret, the epoch and the
        // exchanged values, not only on the KEM secret.
        let a = *c.rekey_secret(1, &[9; 32], b"pk", b"ct");
        assert_ne!(a, *c.rekey_secret(2, &[9; 32], b"pk", b"ct"));
        assert_ne!(a, *c.rekey_secret(1, &[9; 32], b"pk", b"cu"));
        let other = LinkCrypto::derive(&[3; 32], true).with_chain(&[3; 32], [2; 32]);
        assert_ne!(a, *other.rekey_secret(1, &[9; 32], b"pk", b"ct"));
        c.install_rekey(&a, true);
        assert!(!c.should_rekey());
        assert_eq!(c.chain_secret, a);
    }

    /// Losing any single handshake message (and a few combinations) on a
    /// lossy transport only delays the handshake.
    #[tokio::test]
    async fn handshake_survives_lost_messages() {
        // Sends per side (then retransmits): initiator 0 = Hello, 1 = Auth;
        // responder 0 = its Auth (the response), 1 = Confirm.
        // Losing the responder's final Confirm needs its receive loop running
        // (see `lost_final_confirm_is_answered_by_established_responder`).
        let cases: &[(&[usize], &[usize])] = &[
            (&[0], &[]),
            (&[1], &[]),
            (&[], &[0]),
            (&[0, 1, 2], &[]),
            (&[], &[0, 1]),
            (&[0], &[0]),
            (&[1], &[0]),
        ];
        for (drop_a, drop_b) in cases {
            let (ta, tb) = lossy_pair(drop_a, drop_b);
            let (a, b) = handshake_over(ta, tb).await;
            assert_both_ways(&a, &b).await;
        }
    }

    /// The responder's final confirm is lost while it is idle: the
    /// initiator's repeated confirm reaches the established responder, which
    /// answers it, so the initiator completes instead of leaving the
    /// responder with a link nobody is on.
    #[tokio::test]
    async fn lost_final_confirm_is_answered_by_established_responder() {
        let (ta, tb) = lossy_pair(&[], &[1]);
        let (ia, ib) = (Keypair::generate(), Keypair::generate());
        let responder = tokio::spawn(async move {
            let b = Arc::new(PeerLink::responder(Box::new(tb), &ib).await.unwrap());
            // The node's receive loop: bad frames are dropped, not fatal.
            let reader = b.clone();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                loop {
                    if let Ok(m) = reader.recv_message().await {
                        let _ = tx.send(m);
                    }
                }
            });
            (b, async move { rx.recv().await })
        });
        let a = tokio::time::timeout(
            Duration::from_secs(20),
            PeerLink::initiator(Box::new(ta), &ia, None),
        )
        .await
        .expect("initiator hung")
        .unwrap();
        let (b, b_next) = responder.await.unwrap();
        a.send_message(&ping()).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), b_next)
            .await
            .unwrap()
            .is_some());
        b.send_message(&ping()).await.unwrap();
        recv_good(&a).await;
    }

    /// The responder's confirm is lost but it starts sending right away: its
    /// first link frame completes the initiator's handshake and is delivered.
    #[tokio::test]
    async fn link_frame_before_confirm_completes_initiator() {
        let (ta, tb) = lossy_pair(&[], &[1]);
        let (ia, ib) = (Keypair::generate(), Keypair::generate());
        let responder = tokio::spawn(async move {
            let b = PeerLink::responder(Box::new(tb), &ib).await.unwrap();
            b.send_message(&ping()).await.unwrap();
            b
        });
        let a = tokio::time::timeout(
            Duration::from_secs(20),
            PeerLink::initiator(Box::new(ta), &ia, None),
        )
        .await
        .expect("initiator hung")
        .unwrap();
        let first = WireMessage::decode(&recv_good(&a).await).unwrap();
        assert_eq!(first.msg_type, MessageType::Keepalive);
        let b = responder.await.unwrap();
        assert_both_ways(&a, &b).await;
    }

    /// Like TCP: `recv` takes a message, then spends a while "reading the
    /// body". Cancelling it in between desyncs the stream for good.
    struct SlowBody {
        inner: LossyMem,
        body_delay: Duration,
        desynced: Arc<std::sync::atomic::AtomicBool>,
    }

    struct DesyncOnDrop(Option<Arc<std::sync::atomic::AtomicBool>>);
    impl Drop for DesyncOnDrop {
        fn drop(&mut self) {
            if let Some(flag) = self.0.take() {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    #[async_trait::async_trait]
    impl Transport for SlowBody {
        async fn send(&self, d: &[u8]) -> Result<()> {
            self.inner.send(d).await
        }
        async fn recv(&self, b: &mut [u8]) -> Result<usize> {
            if self.desynced.load(std::sync::atomic::Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let n = self.inner.recv(b).await?;
            let mut guard = DesyncOnDrop(Some(self.desynced.clone()));
            tokio::time::sleep(self.body_delay).await;
            guard.0 = None;
            Ok(n)
        }
        fn mtu(&self) -> usize {
            65536
        }
        fn is_reliable(&self) -> bool {
            true
        }
        fn name(&self) -> &'static str {
            "slow-body"
        }
    }

    /// The initiator's retransmit timer must not cancel a receive in
    /// progress: with a slow "body" longer than the retransmit timeout, the
    /// handshake still completes and the stream stays in sync afterwards.
    #[tokio::test]
    async fn handshake_timer_never_cancels_a_receive() {
        let (ta, tb) = lossy_pair(&[], &[]);
        let desynced = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let slow = |t| SlowBody {
            inner: t,
            body_delay: HS_RTO_RELIABLE + Duration::from_millis(300),
            desynced: desynced.clone(),
        };
        let (ia, ib) = (Keypair::generate(), Keypair::generate());
        let (a, b) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(
                PeerLink::initiator(Box::new(slow(ta)), &ia, None),
                PeerLink::responder(Box::new(slow(tb)), &ib)
            )
        })
        .await
        .expect("handshake hung");
        let (a, b) = (a.unwrap(), b.unwrap());
        assert!(!desynced.load(std::sync::atomic::Ordering::SeqCst));
        assert_both_ways(&a, &b).await;
    }

    #[test]
    fn confirm_hash_deterministic_and_directional() {
        let secret = [99u8; 32];
        let h_init = compute_confirm_hash(&secret, true);
        let h_init2 = compute_confirm_hash(&secret, true);
        assert_eq!(h_init, h_init2);

        let h_resp = compute_confirm_hash(&secret, false);
        // Initiator and responder confirm hashes must differ
        assert_ne!(h_init, h_resp);

        let h3 = compute_confirm_hash(&[0u8; 32], true);
        assert_ne!(h_init, h3);
    }
}
