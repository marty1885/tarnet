use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

/// Outbound cells buffered per link before dropping.
/// When the drain task can't keep up (slow peer / congested link),
/// new cells are silently dropped. Reliable end-to-end Channels retain their
/// packets until acknowledged and retransmit them; links do not track delivery.
const OUTBOUND_QUEUE_SIZE: usize = 4096;

/// Minimum size for all link-layer frames after padding.
/// Matches a CircuitRelay message: HEADER + circuit_id + CELL_SIZE.
/// All smaller messages are padded to this size before encryption so an observer
/// cannot classify messages by ciphertext length.
const LINK_PAD_SIZE: usize = HEADER_SIZE + 4 + crate::circuit::CELL_SIZE;

/// Maximum time a deferred (non-critical) message waits before being flushed,
/// even if no high-priority message arrives to piggyback on.
const DEFERRED_FLUSH_MS: u64 = 30;

const TAG_SIZE: usize = 16;
const SEQ_SIZE: usize = 8;
/// XChaCha20 nonce length, prepended to every frame.
const NONCE_SIZE: usize = 24;
/// Largest plaintext wire message the link will encrypt or accept: a full wire
/// header plus the maximum wire payload. This is the single frame-size contract
/// both ends agree on — the send path rejects anything larger (so a too-big
/// message can never reach the wire and corrupt the receiver), and the recv
/// buffer below is sized to hold exactly this much.
const MAX_LINK_MESSAGE: usize = HEADER_SIZE + MAX_PAYLOAD;
/// Largest on-the-wire frame: nonce || seq || MAX_LINK_MESSAGE || tag. The recv
/// buffer must be at least this big or a maximum-size message is rejected as
/// "exceeds buffer" and the link is torn down.
const MAX_LINK_FRAME: usize = NONCE_SIZE + SEQ_SIZE + MAX_LINK_MESSAGE + TAG_SIZE;
/// Sliding window size for replay detection.
const REPLAY_WINDOW: u64 = 128;
/// Re-key after this many messages sent.
pub const REKEY_INTERVAL: u64 = 65536;
/// Maximum allowed timestamp drift in seconds.
const MAX_TIMESTAMP_DRIFT: u64 = 300;
/// Maximum time allowed for the entire handshake (hello + auth + confirm).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
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

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let seq = self.send_seq;
        self.send_seq += 1;

        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        // Build plaintext: seq(8) || payload
        let mut msg = Vec::with_capacity(SEQ_SIZE + plaintext.len());
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(plaintext);

        let cipher = XChaCha20Poly1305::new((&self.send_enc_key).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &msg,
                    aad: b"",
                },
            )
            .expect("AEAD encryption should not fail");

        // Wire: nonce(24) || ciphertext+tag
        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// AEAD-open `data` under `key`, returning (payload_without_seq, seq).
    /// Does not run replay detection — the caller picks the matching window.
    fn aead_open(key: &[u8; 32], data: &[u8]) -> Result<(Vec<u8>, u64)> {
        let nonce = &data[..24];
        let ciphertext_with_tag = &data[24..];
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut plaintext = cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext_with_tag,
                    aad: b"",
                },
            )
            .map_err(|_| Error::Crypto("AEAD decryption failed".into()))?;
        if plaintext.len() < SEQ_SIZE {
            return Err(Error::Crypto("decrypted payload too short for seq".into()));
        }
        let seq = u64::from_be_bytes(plaintext[..SEQ_SIZE].try_into().unwrap());
        plaintext.drain(..SEQ_SIZE);
        Ok((plaintext, seq))
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 24 + SEQ_SIZE + TAG_SIZE {
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

/// Get current unix timestamp in seconds.
fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
}

impl<'a> HandshakeIo<'a> {
    fn new(transport: &'a dyn Transport, is_initiator: bool) -> Self {
        let rto_initial = if transport.is_reliable() {
            HS_RTO_RELIABLE
        } else {
            HS_RTO_LOSSY
        };
        Self {
            transport,
            last_sent: Vec::new(),
            last_received: Vec::new(),
            is_initiator,
            rto_initial,
            rto: rto_initial,
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
        let recv = async move {
            let mut buf = vec![0u8; HS_BUF];
            let n = transport.recv(&mut buf).await?;
            buf.truncate(n);
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
                    self.rto = (self.rto * 2).min(HS_RTO_MAX);
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
/// Outbound messages are encrypted and placed into a bounded channel.
/// A background drain task writes them to the transport. When the peer
/// is slower than the sender, the channel fills and new cells are
/// silently dropped — TCP/WS backpressure propagates naturally from
/// the slow peer through the drain task into the bounded channel.
pub struct PeerLink {
    transport: Arc<dyn Transport>,
    crypto: tokio::sync::Mutex<LinkCrypto>,
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Non-critical messages coalesced with the next high-priority send.
    deferred_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
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
    /// Initiator: link frames that arrived before the responder's
    /// HandshakeConfirm (reordered, or the confirm was lost). Delivered first.
    early_frames: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    /// Responder: (initiator's HandshakeConfirm, our HandshakeConfirm) until
    /// the initiator is known to be done. A repeat of its confirm means ours
    /// was lost; we answer it so the initiator can finish instead of leaving
    /// us holding a link the other side gave up on.
    handshake_tail: std::sync::Mutex<Option<(Vec<u8>, Vec<u8>)>>,
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
        tokio::time::timeout(HANDSHAKE_TIMEOUT, Self::initiator_inner(transport, identity, expected_peer))
            .await
            .map_err(|_| Error::Wire("handshake timed out".into()))?
    }

    async fn initiator_inner(
        transport: Box<dyn Transport>,
        identity: &Keypair,
        expected_peer: Option<PeerId>,
    ) -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let eph_public = X25519Public::from(&eph_secret);

        // Generate ephemeral KEM keypair for PQ forward secrecy
        let my_kem_algo = identity.identity.kem.algo();
        let eph_kem = KemKeypair::generate_ephemeral(my_kem_algo);

        let timestamp = unix_timestamp();
        let mut challenge = [0u8; 32];
        rng.fill_bytes(&mut challenge);

        // Send our hello
        let my_hello = HandshakeHello {
            ephemeral_pubkey: eph_public.to_bytes(),
            signing_algo: identity.identity.signing.algo() as u8,
            signing_pubkey: identity.identity.signing.signing_pubkey_bytes(),
            kem_algo: my_kem_algo as u8,
            kem_pubkey: identity.identity.kem.kem_pubkey_bytes(),
            timestamp,
            challenge,
            eph_kem_pubkey: eph_kem.kem_pubkey_bytes(),
            min_version: WIRE_VERSION_MIN,
            max_version: WIRE_VERSION_MAX,
        };
        let mut io = HandshakeIo::new(transport.as_ref(), true);
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

        // Validate timestamp
        let now = unix_timestamp();
        let drift = if peer_hello.timestamp > now {
            peer_hello.timestamp - now
        } else {
            now - peer_hello.timestamp
        };
        if drift > MAX_TIMESTAMP_DRIFT {
            return Err(Error::Crypto(format!(
                "handshake timestamp drift {}s exceeds maximum {}s",
                drift, MAX_TIMESTAMP_DRIFT
            )));
        }

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
            my_hello.timestamp,
            peer_hello.timestamp,
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
            peer_hello.timestamp,
            my_hello.timestamp,
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
        if !identity::verify(
            remote_signing_algo,
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
            if raw.len() >= NONCE_SIZE + SEQ_SIZE + TAG_SIZE {
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
        let (outbound_tx, deferred_tx, _drain_task) = Self::spawn_drain(transport.clone(), remote_peer);
        Ok(Self {
            transport,
            crypto: tokio::sync::Mutex::new(crypto),
            outbound_tx,
            deferred_tx,
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
            _drain_task,
            transport_name,
            early_frames: std::sync::Mutex::new(early_frames),
            handshake_tail: std::sync::Mutex::new(None),
        })
    }

    /// Perform handshake as the responder (the side that called accept).
    pub async fn responder(transport: Box<dyn Transport>, identity: &Keypair) -> Result<Self> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, Self::responder_inner(transport, identity))
            .await
            .map_err(|_| Error::Wire("handshake timed out".into()))?
    }

    async fn responder_inner(transport: Box<dyn Transport>, identity: &Keypair) -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let eph_public = X25519Public::from(&eph_secret);

        // Generate ephemeral KEM keypair for PQ forward secrecy
        let my_kem_algo = identity.identity.kem.algo();
        let eph_kem = KemKeypair::generate_ephemeral(my_kem_algo);

        // Receive peer hello
        let mut io = HandshakeIo::new(transport.as_ref(), false);
        let wire = io.expect(MessageType::HandshakeHello).await?;
        let peer_hello = HandshakeHello::from_bytes(&wire.payload)?;

        // Negotiate wire protocol version
        let negotiated_version = negotiate_version(
            WIRE_VERSION_MIN,
            WIRE_VERSION_MAX,
            peer_hello.min_version,
            peer_hello.max_version,
        )?;

        // Validate timestamp
        let now = unix_timestamp();
        let drift = if peer_hello.timestamp > now {
            peer_hello.timestamp - now
        } else {
            now - peer_hello.timestamp
        };
        if drift > MAX_TIMESTAMP_DRIFT {
            return Err(Error::Crypto(format!(
                "handshake timestamp drift {}s exceeds maximum {}s",
                drift, MAX_TIMESTAMP_DRIFT
            )));
        }

        let timestamp = unix_timestamp();
        let mut challenge = [0u8; 32];
        rng.fill_bytes(&mut challenge);

        // Send our hello
        let my_hello = HandshakeHello {
            ephemeral_pubkey: eph_public.to_bytes(),
            signing_algo: identity.identity.signing.algo() as u8,
            signing_pubkey: identity.identity.signing.signing_pubkey_bytes(),
            kem_algo: my_kem_algo as u8,
            kem_pubkey: identity.identity.kem.kem_pubkey_bytes(),
            timestamp,
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
            peer_hello.timestamp,
            my_hello.timestamp,
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
        if !identity::verify(
            remote_signing_algo,
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
            my_hello.timestamp,
            peer_hello.timestamp,
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
        let (outbound_tx, deferred_tx, _drain_task) = Self::spawn_drain(transport.clone(), remote_peer);
        Ok(Self {
            transport,
            crypto: tokio::sync::Mutex::new(crypto),
            outbound_tx,
            deferred_tx,
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
            _drain_task,
            transport_name,
            early_frames: std::sync::Mutex::new(std::collections::VecDeque::new()),
            handshake_tail: std::sync::Mutex::new(handshake_tail),
        })
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
        my_timestamp: u64,
        peer_timestamp: u64,
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
            .update(&my_timestamp.to_be_bytes())
            .update(&peer_timestamp.to_be_bytes())
            .update(my_challenge)
            .update(peer_challenge)
            .update(kem_ciphertext)
            .update(eph_kem_ciphertext)
            .update(&[my_ver_range.0, my_ver_range.1])
            .update(&[peer_ver_range.0, peer_ver_range.1])
            .finalize();
        hash.as_bytes().to_vec()
    }

    /// Spawn the background drain task that writes queued cells to the transport.
    ///
    /// Returns (high_priority_tx, deferred_tx, join_handle).
    /// High-priority messages are sent immediately.  Deferred messages are held
    /// for up to [`DEFERRED_FLUSH_MS`] and piggyback on the next high-priority
    /// send, reducing the number of distinctly-timed frames on the wire.
    fn spawn_drain(
        transport: Arc<dyn Transport>,
        remote: PeerId,
    ) -> (
        tokio::sync::mpsc::Sender<Vec<u8>>,
        tokio::sync::mpsc::Sender<Vec<u8>>,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE_SIZE);
        let (def_tx, mut def_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE_SIZE);

        let task = tokio::spawn(async move {
            /// Flush all pending deferred messages.
            async fn flush_deferred(
                def_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
                transport: &Arc<dyn Transport>,
                remote: PeerId,
            ) -> bool {
                while let Ok(data) = def_rx.try_recv() {
                    if let Err(e) = transport.send(&data).await {
                        log::debug!("link drain (deferred) to {:?}: {}", remote, e);
                        return false;
                    }
                }
                true
            }

            loop {
                tokio::select! {
                    biased;

                    // High-priority: send immediately, then piggyback deferred.
                    msg = rx.recv() => {
                        let Some(data) = msg else { break };
                        if let Err(e) = transport.send(&data).await {
                            log::debug!("link drain to {:?}: {}", remote, e);
                            break;
                        }
                        if !flush_deferred(&mut def_rx, &transport, remote).await {
                            break;
                        }
                    }

                    // Deferred: wait briefly for a high-priority message to coalesce with.
                    msg = def_rx.recv() => {
                        let Some(data) = msg else { break };
                        // Short sleep — if a circuit cell arrives during this window it
                        // will be handled by the biased high-priority branch above and
                        // then flush_deferred drains the rest.
                        let jitter = {
                            use rand::Rng;
                            rand::thread_rng().gen_range(0..DEFERRED_FLUSH_MS)
                        };
                        tokio::time::sleep(Duration::from_millis(
                            DEFERRED_FLUSH_MS + jitter,
                        )).await;

                        // After the wait, send the deferred message plus any others
                        // that queued up in the meantime.
                        if let Err(e) = transport.send(&data).await {
                            log::debug!("link drain (deferred) to {:?}: {}", remote, e);
                            break;
                        }
                        if !flush_deferred(&mut def_rx, &transport, remote).await {
                            break;
                        }
                    }
                }
            }
        });
        (tx, def_tx, task)
    }

    /// Pad a wire message to [`LINK_PAD_SIZE`] so all link-layer frames are
    /// the same ciphertext length, preventing message-type classification by size.
    fn pad(data: &[u8]) -> Vec<u8> {
        if data.len() >= LINK_PAD_SIZE {
            return data.to_vec();
        }
        let mut padded = Vec::with_capacity(LINK_PAD_SIZE);
        padded.extend_from_slice(data);
        padded.resize(LINK_PAD_SIZE, 0);
        padded
    }

    /// Pad and encrypt a message into a wire frame, enforcing the size contract.
    fn encrypt_frame(crypto: &mut LinkCrypto, data: &[u8], remote: PeerId) -> Result<Vec<u8>> {
        // Enforce the frame-size contract at the one send chokepoint. A message
        // larger than MAX_LINK_MESSAGE would encrypt to a frame that overflows
        // the peer's recv buffer (tearing down the link) and whose wire LEN
        // field would silently truncate. Reject it here instead of emitting a
        // frame the peer cannot receive.
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
        Ok(crypto.encrypt(&Self::pad(data)))
    }

    /// Encrypt and enqueue a message (pad → encrypt → channel).
    fn encrypt_and_enqueue(
        crypto: &mut LinkCrypto,
        tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
        data: &[u8],
        remote: PeerId,
    ) -> Result<()> {
        let encrypted = Self::encrypt_frame(crypto, data, remote)?;
        match tx.try_send(encrypted) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                log::trace!("outbound queue full to {:?}, dropping", remote);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(Error::Wire("link closed".into()))
            }
        }
    }

    /// Send an encrypted message over the high-priority (data) queue.
    ///
    /// Messages are padded to [`LINK_PAD_SIZE`] before encryption.
    /// If the queue is full (peer is congested), the cell is silently
    /// dropped — reliable end-to-end Channels handle recovery.
    pub async fn send_message(&self, data: &[u8]) -> Result<()> {
        let mut crypto = self.crypto.lock().await;
        Self::encrypt_and_enqueue(&mut crypto, &self.outbound_tx, data, self.remote_peer)
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
        // The crypto lock is held across the awaited enqueue so frames enter
        // the queue in seq order even when this send has to wait. The drain
        // task never takes this lock, so it keeps draining and the wait is
        // bounded by transport progress.
        let mut crypto = self.crypto.lock().await;
        let encrypted = Self::encrypt_frame(&mut crypto, data, self.remote_peer)?;
        self.outbound_tx
            .send(encrypted)
            .await
            .map_err(|_| Error::Wire("link closed".into()))
    }

    /// Send a non-critical message via the deferred queue.
    ///
    /// The drain task holds deferred messages for up to [`DEFERRED_FLUSH_MS`]
    /// and flushes them alongside the next high-priority message, reducing the
    /// number of distinctly-timed link-layer frames an observer can see.
    pub async fn send_deferred(&self, data: &[u8]) -> Result<()> {
        let mut crypto = self.crypto.lock().await;
        Self::encrypt_and_enqueue(&mut crypto, &self.deferred_tx, data, self.remote_peer)
    }

    /// Receive and decrypt a message from the link.
    pub async fn recv_message(&self) -> Result<Vec<u8>> {
        if let Some(early) = self.early_frames.lock().unwrap().pop_front() {
            return Ok(early);
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
        result
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

    /// Transport name (e.g. "tcp", "ws", "webrtc").
    pub fn transport_name(&self) -> &'static str {
        self.transport_name
    }

    /// Largest encoded wire message that fits this link's transport in a single
    /// frame, after link encryption overhead. Senders that build oversized
    /// payloads (e.g. route advertisements) must pre-split to this size; the
    /// send path rejects anything larger. Bounded by both the transport MTU
    /// (which carries the encrypted frame: nonce ‖ seq ‖ ciphertext ‖ tag) and
    /// the link's own plaintext ceiling. Shrinks automatically for small-MTU
    /// datagram transports (e.g. UDP).
    pub fn max_wire_message(&self) -> usize {
        const FRAME_OVERHEAD: usize = NONCE_SIZE + SEQ_SIZE + TAG_SIZE;
        self.transport
            .mtu()
            .saturating_sub(FRAME_OVERHEAD)
            .min(MAX_LINK_MESSAGE)
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
        if !identity::verify(
            self.remote_signing_algo,
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
        // Flip a ciphertext byte (after nonce)
        encrypted[24] ^= 0xff;
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
        drop: Vec<usize>,
        sent: std::sync::atomic::AtomicUsize,
    }

    fn lossy_pair(drop_a: &[usize], drop_b: &[usize]) -> (LossyMem, LossyMem) {
        let (tx_a, rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, rx_b) = tokio::sync::mpsc::unbounded_channel();
        let mk = |tx, rx, drop: &[usize]| LossyMem {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            drop: drop.to_vec(),
            sent: Default::default(),
        };
        (mk(tx_a, rx_b, drop_a), mk(tx_b, rx_a, drop_b))
    }

    #[async_trait::async_trait]
    impl Transport for LossyMem {
        async fn send(&self, data: &[u8]) -> Result<()> {
            let i = self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if !self.drop.contains(&i) {
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
            timestamp_us: None,
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
