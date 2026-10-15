use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use std::time::Duration;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::kdf;
use crate::identity::{self, peer_id_from_signing_pubkey, KemKeypair, Keypair};
use crate::transport::Transport;
use crate::types::{Error, PeerId, Result};
use crate::wire::{
    HandshakeAuth, HandshakeConfirmMsg, HandshakeHello, MessageType, RekeyMsg, WireMessage,
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
const SLOW_FRAME_PLAIN: usize = 256 - SEQ_SIZE - TAG_SIZE;
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
const HANDSHAKE_BYTES: u64 = 12 * 1024;
/// A handshake that keeps trickling bytes is still cut off after this many
/// deadlines, so a peer can't hold a handshake slot open forever.
const HANDSHAKE_HARD_CAP_FACTOR: u32 = 10;
/// Hard ceiling on a single recv: if the transport produces nothing within
/// this window, treat it as a dead link. Slightly longer than the node-level
/// `KEEPALIVE_DEAD_TIMEOUT` (180s) so the app-level path has first crack at
/// declaring it dead, but a zombie socket (e.g. after suspend/resume) still
/// unblocks.
const RECV_STALL_TIMEOUT: Duration = Duration::from_secs(210);

/// Session keys for bidirectional encrypted communication.
#[derive(Zeroize, ZeroizeOnDrop)]
struct LinkCrypto {
    send_enc_key: [u8; 32],
    recv_enc_key: [u8; 32],
    /// Previous recv key, retained across a rekey so in-flight frames the peer
    /// sent under the old key still decrypt. Held until the *next* rekey rotates
    /// it out (see [`install_rekey`]), not dropped on the first new-key frame —
    /// that earlier heuristic assumed in-order delivery, so an old-key straggler
    /// reordered *after* a new-key frame would fail to decrypt. Retaining the key
    /// for the whole epoch makes decryption independent of transport ordering
    /// (needed for datagram transports such as UDP); replay is still caught
    /// per-key by `prev_recv_window`/`prev_recv_bitmap`.
    prev_recv_key: Option<[u8; 32]>,
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
}

impl LinkCrypto {
    /// Derive session keys from shared secret. Initiator and responder derive
    /// complementary key pairs (initiator's send = responder's recv).
    fn derive(shared_secret: &[u8; 32], is_initiator: bool) -> Self {
        let mut send_enc = kdf(shared_secret, "tarnet link i2r_enc");
        let mut recv_enc = kdf(shared_secret, "tarnet link r2i_enc");

        if !is_initiator {
            std::mem::swap(&mut send_enc, &mut recv_enc);
        }

        Self {
            send_enc_key: send_enc,
            recv_enc_key: recv_enc,
            prev_recv_key: None,
            send_seq: 0,
            recv_window: 0,
            recv_bitmap: 0,
            prev_recv_window: 0,
            prev_recv_bitmap: 0,
            pending_send: None,
            pending_recv: None,
            pending_tag: None,
            completed_tag: None,
            epoch: 0,
        }
    }

    /// Install freshly-rekeyed session keys derived from `new_shared`.
    ///
    /// The current recv key is retained as `prev_recv_key` so frames the peer
    /// already put on the wire under the old key keep decrypting. It is held for
    /// the whole new epoch and only rotated out here at the *next* rekey (the
    /// `prev_recv_key.take()` below zeroizes the key from two epochs ago), so at
    /// most one previous epoch is ever live. The send key flips immediately; the
    /// peer tolerates the overlap symmetrically via its own retained previous key.
    fn install_rekey(&mut self, new_shared: &[u8; 32], is_initiator: bool) {
        let fresh = Self::derive(new_shared, is_initiator);
        self.install_keys(fresh.send_enc_key, fresh.recv_enc_key);
        // `fresh` drops here; ZeroizeOnDrop wipes its own key copies.
    }

    fn install_keys(&mut self, send: [u8; 32], recv: [u8; 32]) {
        if let Some(mut old) = self.prev_recv_key.take() {
            old.zeroize();
        }
        self.prev_recv_key = Some(self.recv_enc_key);
        self.prev_recv_window = self.recv_window;
        self.prev_recv_bitmap = self.recv_bitmap;

        self.send_enc_key = send;
        self.recv_enc_key = recv;
        self.send_seq = 0;
        self.recv_window = 0;
        self.recv_bitmap = 0;
        self.epoch += 1;
    }

    /// Responder: hold the keys for an answered rekey request until the
    /// initiator proves it has them (see `pending_recv`). A newer request
    /// replaces an unconfirmed older one.
    fn stage_rekey(&mut self, new_shared: &[u8; 32], is_initiator: bool, tag: [u8; 32]) {
        let fresh = Self::derive(new_shared, is_initiator);
        self.clear_pending();
        self.pending_send = Some(fresh.send_enc_key);
        self.pending_recv = Some(fresh.recv_enc_key);
        self.pending_tag = Some(tag);
    }

    fn clear_pending(&mut self) {
        if let Some(mut k) = self.pending_send.take() {
            k.zeroize();
        }
        if let Some(mut k) = self.pending_recv.take() {
            k.zeroize();
        }
        self.pending_tag = None;
    }

    /// True once either direction has sent/received enough messages to warrant
    /// a rekey. Checking `recv_window` (the highest seq seen from the peer)
    /// means a link whose heavy direction is inbound still rotates keys, even
    /// if our own send side is mostly idle.
    fn should_rekey(&self) -> bool {
        self.send_seq >= REKEY_INTERVAL || self.recv_window >= REKEY_INTERVAL
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

        let cipher = XChaCha20Poly1305::new((&self.send_enc_key).into());
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

    /// AEAD-open `data` under `key`, returning (payload, seq).
    /// Does not run replay detection — the caller picks the matching window.
    fn aead_open(key: &[u8; 32], data: &[u8]) -> Result<(Vec<u8>, u64)> {
        let seq_bytes: [u8; SEQ_SIZE] = data[..SEQ_SIZE].try_into().unwrap();
        let seq = u64::from_be_bytes(seq_bytes);
        let cipher = XChaCha20Poly1305::new(key.into());
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
        match Self::aead_open(&self.recv_enc_key, data) {
            Ok((plaintext, seq)) => {
                Self::check_replay_at(&mut self.recv_window, &mut self.recv_bitmap, seq)?;
                // Keep the previous-epoch key until the next rekey rotates it
                // out: a straggler the peer sent under the old key may still
                // arrive *after* this new-key frame on a reordering transport.
                Ok(plaintext)
            }
            Err(current_err) => {
                // The initiator's first frame under keys we staged for its
                // rekey: that confirms it installed them, so switch over.
                if let Some(pending) = self.pending_recv {
                    if let Ok((plaintext, seq)) = Self::aead_open(&pending, data) {
                        let send = self.pending_send.take().expect("staged with recv");
                        self.pending_recv = None;
                        self.completed_tag = self.pending_tag.take();
                        self.install_keys(send, pending);
                        Self::check_replay_at(&mut self.recv_window, &mut self.recv_bitmap, seq)?;
                        return Ok(plaintext);
                    }
                }
                // During a rekey overlap, the peer may still be sending under
                // the old key. Fall back to it before declaring failure.
                if let Some(prev) = self.prev_recv_key {
                    if let Ok((plaintext, seq)) = Self::aead_open(&prev, data) {
                        Self::check_replay_at(
                            &mut self.prev_recv_window,
                            &mut self.prev_recv_bitmap,
                            seq,
                        )?;
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

/// The drain task's channel and the state it shares with the receive path.
struct LinkPipes {
    outbound_tx: tokio::sync::mpsc::Sender<Outgoing>,
    reassembler: Arc<std::sync::Mutex<crate::link_frame::Reassembler>>,
    sent_fragments: Arc<std::sync::Mutex<crate::link_frame::SentFragments>>,
    task: tokio::task::JoinHandle<()>,
}

/// Initiator-side state of a rekey awaiting its reply.
struct PendingRekey {
    eph_kem: KemKeypair,
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
            let cell_msg = HEADER_SIZE + 4 + crate::circuit::CELL_SIZE + 3;
            let frames_per_cell = cell_msg.div_ceil(frame_plain.saturating_sub(9).max(1));
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
    transport: Arc<dyn Transport>,
    /// Shared with the drain task, which encrypts frames as it sends them so
    /// frame seqs go out in order.
    crypto: Arc<tokio::sync::Mutex<LinkCrypto>>,
    /// Everything sent on the link, to the drain task.
    outbound_tx: tokio::sync::mpsc::Sender<Outgoing>,
    reassembler: Arc<std::sync::Mutex<crate::link_frame::Reassembler>>,
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
        let mut rng = rand::rngs::OsRng;
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let eph_public = X25519Public::from(&eph_secret);

        // Generate ephemeral KEM keypair for PQ forward secrecy
        let my_kem_algo = identity.identity.kem.algo();
        let eph_kem = KemKeypair::generate_ephemeral(my_kem_algo);

        let mut challenge = [0u8; 32];
        rng.fill_bytes(&mut challenge);

        // Send our hello
        let my_hello = HandshakeHello {
            ephemeral_pubkey: eph_public.to_bytes(),
            signing_algo: identity.identity.signing.algo() as u8,
            signing_pubkey: identity.identity.signing.signing_pubkey_bytes(),
            kem_algo: my_kem_algo as u8,
            kem_pubkey: identity.identity.kem.kem_pubkey_bytes(),
            challenge,
            eph_kem_pubkey: eph_kem.kem_pubkey_bytes(),
            min_version: WIRE_VERSION_MIN,
            max_version: WIRE_VERSION_MAX,
        };
        let mut io = HandshakeIo::new(transport.as_ref(), true, progress);
        io.send(my_hello.to_wire().encode()).await?;

        // Receive peer hello
        let wire = io.expect(MessageType::HandshakeHello).await?;
        let peer_hello = HandshakeHello::from_bytes(&wire.payload)?;

        // Negotiate wire protocol version
        let negotiated_version = negotiate_version(
            WIRE_VERSION_MIN,
            WIRE_VERSION_MAX,
            peer_hello.min_version,
            peer_hello.max_version,
        )?;


        // Compute X25519 ephemeral shared secret
        let peer_eph = X25519Public::from(peer_hello.ephemeral_pubkey);
        let x25519_shared = eph_secret.diffie_hellman(&peer_eph);

        // KEM encapsulate to responder's static KEM pubkey (identity binding)
        let remote_kem_algo = KemAlgo::from_u8(peer_hello.kem_algo)
            .map_err(|e| Error::Crypto(format!("unknown KEM algo: {}", e)))?;
        let (static_kem_ss, static_kem_ct) =
            KemKeypair::encapsulate_to(&peer_hello.kem_pubkey, remote_kem_algo)
                .map_err(|e| Error::Crypto(format!("KEM encapsulate (static) failed: {}", e)))?;

        // KEM encapsulate to responder's ephemeral KEM pubkey (PQ forward secrecy)
        let (eph_kem_ss, eph_kem_ct) =
            KemKeypair::encapsulate_to(&peer_hello.eph_kem_pubkey, remote_kem_algo)
                .map_err(|e| Error::Crypto(format!("KEM encapsulate (ephemeral) failed: {}", e)))?;

        // Combine: ss = BLAKE3("tarnet link", x25519_ss || static_kem_ss || eph_kem_ss)
        let shared_bytes = {
            let mut combined = Vec::with_capacity(96);
            combined.extend_from_slice(&x25519_shared.to_bytes());
            combined.extend_from_slice(&static_kem_ss);
            combined.extend_from_slice(&eph_kem_ss);
            blake3::derive_key("tarnet link", &combined)
        };

        // Derive session keys
        let crypto = LinkCrypto::derive(&shared_bytes, true);

        // Sign transcript (includes both KEM ciphertexts and version ranges)
        let my_ver = (WIRE_VERSION_MIN, WIRE_VERSION_MAX);
        let peer_ver = (peer_hello.min_version, peer_hello.max_version);
        let transcript = Self::compute_transcript(
            &my_hello.ephemeral_pubkey,
            &peer_hello.ephemeral_pubkey,
            &shared_bytes,
            true,
            &my_hello.challenge,
            &peer_hello.challenge,
            &static_kem_ct,
            &eph_kem_ct,
            my_ver,
            peer_ver,
        );
        let sig = identity.sign(&transcript);
        let auth = HandshakeAuth {
            signature: sig,
            kem_ciphertext: static_kem_ct,
            eph_kem_ciphertext: eph_kem_ct,
        };
        io.send(auth.to_wire().encode()).await?;

        // Receive and verify peer auth
        let wire = io.expect(MessageType::HandshakeAuth).await?;
        let peer_auth = HandshakeAuth::from_bytes(&wire.payload)?;

        let peer_transcript = Self::compute_transcript(
            &peer_hello.ephemeral_pubkey,
            &my_hello.ephemeral_pubkey,
            &shared_bytes,
            false,
            &peer_hello.challenge,
            &my_hello.challenge,
            &[], // responder's auth has no KEM ciphertext
            &[], // responder's auth has no ephemeral KEM ciphertext
            peer_ver,
            my_ver,
        );
        let remote_signing_algo = SigningAlgo::from_u8(peer_hello.signing_algo)
            .map_err(|e| Error::Crypto(format!("unknown signing algo: {}", e)))?;
        let remote_peer = peer_id_from_signing_pubkey(&peer_hello.signing_pubkey);
        // The peer is whoever holds the key (its id is derived from it).
        if !identity::verify_signed(
            identity::SignedBy::AnyPeer,
            Some(remote_signing_algo as u8),
            &peer_hello.signing_pubkey,
            &peer_transcript,
            &peer_auth.signature,
        ) {
            return Err(Error::Crypto("peer auth signature invalid".into()));
        }

        // Verify we connected to the peer we intended
        if let Some(expected) = expected_peer {
            if remote_peer != expected {
                return Err(Error::Crypto(format!(
                    "connected to {:?} but expected {:?}",
                    remote_peer, expected,
                )));
            }
        }

        // Key confirmation: send initiator confirm hash
        let confirm_hash = compute_confirm_hash(&shared_bytes, true);
        let confirm = HandshakeConfirmMsg { confirm_hash };
        io.send(confirm.to_wire().encode()).await?;

        // Receive and verify the responder's confirm. Any frame that decrypts
        // under the session keys proves the responder holds them just as well
        // (it only sends link frames after its confirm), so it also completes
        // the handshake — the confirm may have been lost or overtaken.
        let mut crypto = crypto;
        let mut early_frames = std::collections::VecDeque::new();
        let expected_peer_confirm = compute_confirm_hash(&shared_bytes, false);
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
        let transport_name = transport.name();
        let transport: Arc<dyn Transport> = Arc::from(transport);
        let crypto = Arc::new(tokio::sync::Mutex::new(crypto));
        let pipes = Self::spawn_drain(transport.clone(), crypto.clone(), remote_peer);
        let link = Self {
            transport,
            crypto,
            outbound_tx: pipes.outbound_tx,
            reassembler: pipes.reassembler,
            sent_fragments: pipes.sent_fragments,
            remote_peer,
            remote_signing_algo,
            remote_signing_pubkey: peer_hello.signing_pubkey,
            is_initiator: true,
            rekey_kem_algo: KemAlgo::negotiate_rekey(my_kem_algo, remote_kem_algo),
            pending_rekey: tokio::sync::Mutex::new(None),
            rekey_reply: tokio::sync::Mutex::new(None),
            force_rekey: std::sync::atomic::AtomicBool::new(false),
            negotiated_version,
            identity: std::sync::Arc::new(
                Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap(),
            ),
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
        let mut rng = rand::rngs::OsRng;
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let eph_public = X25519Public::from(&eph_secret);

        // Generate ephemeral KEM keypair for PQ forward secrecy
        let my_kem_algo = identity.identity.kem.algo();
        let eph_kem = KemKeypair::generate_ephemeral(my_kem_algo);

        // Receive peer hello
        let mut io = HandshakeIo::new(transport.as_ref(), false, progress);
        let wire = io.expect(MessageType::HandshakeHello).await?;
        let peer_hello = HandshakeHello::from_bytes(&wire.payload)?;

        // Negotiate wire protocol version
        let negotiated_version = negotiate_version(
            WIRE_VERSION_MIN,
            WIRE_VERSION_MAX,
            peer_hello.min_version,
            peer_hello.max_version,
        )?;


        let mut challenge = [0u8; 32];
        rng.fill_bytes(&mut challenge);

        // Send our hello
        let my_hello = HandshakeHello {
            ephemeral_pubkey: eph_public.to_bytes(),
            signing_algo: identity.identity.signing.algo() as u8,
            signing_pubkey: identity.identity.signing.signing_pubkey_bytes(),
            kem_algo: my_kem_algo as u8,
            kem_pubkey: identity.identity.kem.kem_pubkey_bytes(),
            challenge,
            eph_kem_pubkey: eph_kem.kem_pubkey_bytes(),
            min_version: WIRE_VERSION_MIN,
            max_version: WIRE_VERSION_MAX,
        };
        io.send(my_hello.to_wire().encode()).await?;

        // Compute X25519 ephemeral shared secret
        let peer_eph = X25519Public::from(peer_hello.ephemeral_pubkey);
        let x25519_shared = eph_secret.diffie_hellman(&peer_eph);

        // Receive peer auth (contains both static + ephemeral KEM ciphertexts)
        let wire = io.expect(MessageType::HandshakeAuth).await?;
        let peer_auth = HandshakeAuth::from_bytes(&wire.payload)?;

        // KEM decapsulate static: recover shared secret from initiator's ciphertext
        let static_kem_ss = identity
            .identity
            .kem
            .decapsulate(&peer_auth.kem_ciphertext)
            .map_err(|e| Error::Crypto(format!("KEM decapsulate (static) failed: {}", e)))?;

        // KEM decapsulate ephemeral: recover shared secret using our ephemeral KEM key
        let eph_kem_ss = eph_kem
            .decapsulate(&peer_auth.eph_kem_ciphertext)
            .map_err(|e| Error::Crypto(format!("KEM decapsulate (ephemeral) failed: {}", e)))?;

        // Combine: ss = BLAKE3("tarnet link", x25519_ss || static_kem_ss || eph_kem_ss)
        let shared_bytes = {
            let mut combined = Vec::with_capacity(96);
            combined.extend_from_slice(&x25519_shared.to_bytes());
            combined.extend_from_slice(&static_kem_ss);
            combined.extend_from_slice(&eph_kem_ss);
            blake3::derive_key("tarnet link", &combined)
        };

        // Derive session keys
        let crypto = LinkCrypto::derive(&shared_bytes, false);

        // Verify peer auth signature (transcript includes KEM ciphertexts + version ranges)
        let peer_ver = (peer_hello.min_version, peer_hello.max_version);
        let my_ver = (WIRE_VERSION_MIN, WIRE_VERSION_MAX);
        let peer_transcript = Self::compute_transcript(
            &peer_hello.ephemeral_pubkey,
            &my_hello.ephemeral_pubkey,
            &shared_bytes,
            true,
            &peer_hello.challenge,
            &my_hello.challenge,
            &peer_auth.kem_ciphertext,
            &peer_auth.eph_kem_ciphertext,
            peer_ver,
            my_ver,
        );
        let remote_signing_algo = SigningAlgo::from_u8(peer_hello.signing_algo)
            .map_err(|e| Error::Crypto(format!("unknown signing algo: {}", e)))?;
        let remote_kem_algo = KemAlgo::from_u8(peer_hello.kem_algo)
            .map_err(|e| Error::Crypto(format!("unknown KEM algo: {}", e)))?;
        let remote_peer = peer_id_from_signing_pubkey(&peer_hello.signing_pubkey);
        // The peer is whoever holds the key (its id is derived from it).
        if !identity::verify_signed(
            identity::SignedBy::AnyPeer,
            Some(remote_signing_algo as u8),
            &peer_hello.signing_pubkey,
            &peer_transcript,
            &peer_auth.signature,
        ) {
            return Err(Error::Crypto("peer auth signature invalid".into()));
        }

        // Sign transcript and send auth (no KEM ciphertext from responder)
        let transcript = Self::compute_transcript(
            &my_hello.ephemeral_pubkey,
            &peer_hello.ephemeral_pubkey,
            &shared_bytes,
            false,
            &my_hello.challenge,
            &peer_hello.challenge,
            &[], // responder's auth has no KEM ciphertext
            &[], // responder's auth has no ephemeral KEM ciphertext
            my_ver,
            peer_ver,
        );
        let sig = identity.sign(&transcript);
        let auth = HandshakeAuth {
            signature: sig,
            kem_ciphertext: Vec::new(),
            eph_kem_ciphertext: Vec::new(),
        };
        io.send(auth.to_wire().encode()).await?;

        // Key confirmation: receive and verify peer's (initiator) confirm
        let wire = io.expect(MessageType::HandshakeConfirm).await?;
        let peer_confirm_frame = std::mem::take(&mut io.last_received);
        let peer_confirm = HandshakeConfirmMsg::from_bytes(&wire.payload)?;

        let expected_peer_confirm = compute_confirm_hash(&shared_bytes, true);
        if peer_confirm
            .confirm_hash
            .ct_eq(&expected_peer_confirm)
            .unwrap_u8()
            == 0
        {
            return Err(Error::Crypto("key confirmation failed".into()));
        }

        // Send our (responder) confirm
        let confirm_hash = compute_confirm_hash(&shared_bytes, false);
        let confirm = HandshakeConfirmMsg { confirm_hash };
        let our_confirm = confirm.to_wire().encode();
        io.send(our_confirm.clone()).await?;
        let handshake_tail = Some((peer_confirm_frame, our_confirm));

        log::info!(
            "Link established (responder) with {:?}, wire v{}",
            remote_peer,
            negotiated_version
        );
        let transport_name = transport.name();
        let transport: Arc<dyn Transport> = Arc::from(transport);
        let crypto = Arc::new(tokio::sync::Mutex::new(crypto));
        let pipes = Self::spawn_drain(transport.clone(), crypto.clone(), remote_peer);
        let link = Self {
            transport,
            crypto,
            outbound_tx: pipes.outbound_tx,
            reassembler: pipes.reassembler,
            sent_fragments: pipes.sent_fragments,
            remote_peer,
            remote_signing_algo,
            remote_signing_pubkey: peer_hello.signing_pubkey,
            is_initiator: false,
            rekey_kem_algo: KemAlgo::negotiate_rekey(my_kem_algo, remote_kem_algo),
            pending_rekey: tokio::sync::Mutex::new(None),
            rekey_reply: tokio::sync::Mutex::new(None),
            force_rekey: std::sync::atomic::AtomicBool::new(false),
            negotiated_version,
            identity: std::sync::Arc::new(
                Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap(),
            ),
            _drain_task: pipes.task,
            transport_name,
            inbox: std::sync::Mutex::new(std::collections::VecDeque::new()),
            handshake_tail: std::sync::Mutex::new(handshake_tail),
            sent_categories: std::sync::atomic::AtomicU8::new(0),
        };
        Ok(link)
    }

    /// Compute handshake transcript for signing.
    ///
    /// Includes both static and ephemeral KEM ciphertexts to bind the PQ key
    /// exchanges to the authenticated transcript, preventing stripping/downgrade.
    fn compute_transcript(
        my_eph: &[u8; 32],
        peer_eph: &[u8; 32],
        shared_secret: &[u8; 32],
        is_initiator: bool,
        my_challenge: &[u8; 32],
        peer_challenge: &[u8; 32],
        kem_ciphertext: &[u8],
        eph_kem_ciphertext: &[u8],
        my_ver_range: (u8, u8),
        peer_ver_range: (u8, u8),
    ) -> Vec<u8> {
        let label = if is_initiator {
            b"tarnet-handshake-initiator"
        } else {
            b"tarnet-handshake-responder"
        };
        let hash = blake3::Hasher::new()
            .update(label.as_slice())
            .update(my_eph)
            .update(peer_eph)
            .update(shared_secret)
            .update(my_challenge)
            .update(peer_challenge)
            .update(kem_ciphertext)
            .update(eph_kem_ciphertext)
            .update(&[my_ver_range.0, my_ver_range.1])
            .update(&[peer_ver_range.0, peer_ver_range.1])
            .finalize();
        hash.as_bytes().to_vec()
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
        use crate::link_frame::{encode_message_into, pack_frame, Reassembler, SentFragments};
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

        let task_reassembler = reassembler.clone();
        let task_sent = sent_fragments.clone();
        let task = tokio::spawn(async move {
            use crate::link_sched::Scheduler;
            let mut sched = Scheduler::new(sched_cfg);
            // Records past the scheduler, packed into frames in order: at most
            // one frame's worth plus the rest of a fragmented message.
            let mut ready: VecDeque<Vec<u8>> = VecDeque::new();
            let mut next_msg_id: u16 = 0;
            let mut reported_drops = 0;
            let mut next_nack_poll = std::time::Instant::now();

            // Queue a wire message's records, remembering fragments for repair.
            // The next message starts in whatever room the frame being
            // filled has left.
            let mut enqueue = |ready: &mut VecDeque<Vec<u8>>, data: Vec<u8>| {
                let used = ready.iter().map(Vec::len).sum::<usize>() % frame_plain;
                let room = if ready.is_empty() { frame_plain } else { frame_plain - used };
                let records = encode_message_into(&data, frame_plain, room, &mut next_msg_id);
                if records.len() > 1 {
                    task_sent.lock().unwrap().remember(&records, std::time::Instant::now());
                }
                ready.extend(records);
            };
            // Messages go to the scheduler; repair records skip it.
            let take = |sched: &mut Scheduler, ready: &mut VecDeque<Vec<u8>>, out: Outgoing| {
                let now = std::time::Instant::now();
                match out {
                    Outgoing::Message(data) | Outgoing::Deferred(data) => sched.push(data, false, now),
                    Outgoing::Critical(data) => sched.push(data, true, now),
                    Outgoing::Repair(rec) => ready.push_front(rec),
                }
            };

            'drain: loop {
                // Take in everything already waiting.
                while let Ok(out) = rx.try_recv() {
                    take(&mut sched, &mut ready, out);
                }
                // NACK stalled partial messages, idle or busy.
                let now = std::time::Instant::now();
                if now >= next_nack_poll {
                    next_nack_poll = now + stall / 2;
                    let mut r = task_reassembler.lock().unwrap();
                    if !r.is_empty() {
                        ready.extend(r.poll(now));
                    }
                }

                if ready.is_empty() && sched.is_empty() {
                    tokio::select! {
                        out = rx.recv() => {
                            let Some(out) = out else { break };
                            let Outgoing::Deferred(first) = out else {
                                take(&mut sched, &mut ready, out);
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
                                            take(&mut sched, &mut ready, out);
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
                        _ = tokio::time::sleep_until(next_nack_poll.into()) => {}
                    }
                    continue;
                }

                // Fill the frame from the scheduler, highest class first.
                while ready.iter().map(Vec::len).sum::<usize>() < frame_plain {
                    let Some(data) = sched.pop(now) else { break };
                    enqueue(&mut ready, data);
                }
                if sched.dropped() > reported_drops {
                    log::trace!(
                        "link to {:?}: dropped {} queued message(s)",
                        remote,
                        sched.dropped() - reported_drops
                    );
                    reported_drops = sched.dropped();
                }

                let Some(frame) = pack_frame(&mut ready, frame_plain) else {
                    // Everything popped was dropped by the scheduler.
                    continue;
                };
                let encrypted = crypto.lock().await.encrypt(&frame);
                if let Err(e) = transport.send(&encrypted).await {
                    log::debug!("link drain to {:?}: {}", remote, e);
                    break;
                }
            }
        });
        LinkPipes {
            outbound_tx: tx,
            reassembler,
            sent_fragments,
            task,
        }
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
    fn enqueue(&self, out: Outgoing) -> Result<()> {
        match self.outbound_tx.try_send(out) {
            Ok(()) => Ok(()),
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
        self.enqueue(Outgoing::Message(data.to_vec()))
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
        self.outbound_tx
            .send(Outgoing::Critical(data.to_vec()))
            .await
            .map_err(|_| Error::Wire("link closed".into()))
    }

    /// Send a non-critical message via the deferred queue.
    ///
    /// The drain task holds deferred messages for up to [`DEFERRED_FLUSH_MS`]
    /// and sends them in the frame of the next message that isn't deferred,
    /// reducing the number of distinctly-timed link-layer frames an observer
    /// can see.
    pub async fn send_deferred(&self, data: &[u8]) -> Result<()> {
        self.outgoing(data)?;
        self.outbound_tx
            .try_send(Outgoing::Deferred(data.to_vec()))
            .map_err(|e| Error::Wire(format!("deferred queue admission failed: {}", e)))
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
            let mut buf = vec![0u8; MAX_LINK_FRAME];
            let n = tokio::time::timeout(RECV_STALL_TIMEOUT, self.transport.recv(&mut buf))
                .await
                .map_err(|_| Error::Wire("link recv stalled".into()))??;
            let result = self.crypto.lock().await.decrypt(&buf[..n]);
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
            if let Some(our_confirm) = tail {
                log::debug!("Handshake confirm from {:?} repeated, resending ours", self.remote_peer);
                self.transport.send(&our_confirm).await?;
            }
            self.ingest_frame(&result?);
        }
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

    /// Ask for a rekey on the next sweep even if the message counts don't
    /// call for one yet. Only meaningful on the initiator side.
    pub fn request_rekey(&self) {
        if self.is_initiator {
            self.force_rekey
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Number of times this link's keys have been replaced since the handshake.
    pub async fn key_epoch(&self) -> u64 {
        self.crypto.lock().await.epoch
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
        let mut rekey_msg = RekeyMsg {
            kem_algo: self.rekey_kem_algo as u8,
            kem_pubkey: eph_kem.kem_pubkey_bytes(),
            kem_ciphertext: Vec::new(),
            signature: Vec::new(),
        };
        rekey_msg.signature = self.identity.sign(&rekey_msg.signable_bytes());
        let request = rekey_msg.to_wire().encode();
        *pending = Some(PendingRekey {
            eph_kem,
            request: request.clone(),
            sent_at: std::time::Instant::now(),
        });
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
        // long-term identity, matching the handshake.)
        if !identity::verify_signed(
            identity::SignedBy::BoundKey,
            Some(self.remote_signing_algo as u8),
            &self.remote_signing_pubkey,
            &peer_rekey.signable_bytes(),
            &peer_rekey.signature,
        ) {
            return Err(Error::Crypto("rekey signature invalid".into()));
        }

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

            let peer_kem_algo = KemAlgo::from_u8(peer_rekey.kem_algo)
                .map_err(|e| Error::Crypto(format!("unknown rekey KEM algo: {}", e)))?;
            let (kem_ss, kem_ct) =
                KemKeypair::encapsulate_to(&peer_rekey.kem_pubkey, peer_kem_algo)
                    .map_err(|e| Error::Crypto(format!("rekey KEM encapsulate failed: {}", e)))?;

            let mut reply = RekeyMsg {
                kem_algo: self.rekey_kem_algo as u8,
                kem_pubkey: Vec::new(),
                kem_ciphertext: kem_ct,
                signature: Vec::new(),
            };
            reply.signature = self.identity.sign(&reply.signable_bytes());
            let reply = reply.to_wire().encode();

            let new_shared = blake3::derive_key("tarnet rekey", &kem_ss);
            self.crypto
                .lock()
                .await
                .stage_rekey(&new_shared, self.is_initiator, tag);
            *cached = Some((tag, reply.clone()));
            drop(cached);
            // Goes out under the current key, which stays our send key until
            // the initiator's first new-key frame arrives.
            self.send_message_critical(&reply).await?;
            log::debug!("Answered rekey request from {:?}", self.remote_peer);
            Ok(())
        } else if !peer_rekey.kem_ciphertext.is_empty() {
            // Response to a rekey we initiated.
            let Some(pending) = self.pending_rekey.lock().await.take() else {
                // A duplicate reply to a retried request we already completed.
                log::trace!("Ignoring duplicate rekey reply from {:?}", self.remote_peer);
                return Ok(());
            };
            let kem_ss = pending
                .eph_kem
                .decapsulate(&peer_rekey.kem_ciphertext)
                .map_err(|e| Error::Crypto(format!("rekey KEM decapsulate failed: {}", e)))?;
            let new_shared = blake3::derive_key("tarnet rekey", &kem_ss);
            self.crypto
                .lock()
                .await
                .install_rekey(&new_shared, self.is_initiator);
            self.force_rekey
                .store(false, std::sync::atomic::Ordering::Relaxed);
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
        assert!(handshake_deadline(&a) >= Duration::from_secs(70));
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

    fn ping() -> Vec<u8> {
        crate::wire::KeepaliveMsg {
            ping_id: None,
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

    /// Losing any single handshake message (and a few combinations) on a
    /// lossy transport only delays the handshake.
    #[tokio::test]
    async fn handshake_survives_lost_messages() {
        // Sends per side: 0 = Hello, 1 = Auth, 2 = Confirm (then retransmits).
        let cases: &[(&[usize], &[usize])] = &[
            (&[0], &[]),
            (&[1], &[]),
            (&[2], &[]),
            (&[], &[0]),
            (&[], &[1]),
            (&[0, 1, 2], &[]),
            (&[], &[0, 1]),
            (&[1], &[1]),
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
        let (ta, tb) = lossy_pair(&[], &[2]);
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
        let (ta, tb) = lossy_pair(&[], &[2]);
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
