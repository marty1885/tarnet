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
    HandshakeAuth, HandshakeConfirmMsg, HandshakeHello, RekeyMsg, WireMessage, HEADER_SIZE,
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
        if let Some(mut old) = self.prev_recv_key.take() {
            old.zeroize();
        }
        self.prev_recv_key = Some(self.recv_enc_key);
        self.prev_recv_window = self.recv_window;
        self.prev_recv_bitmap = self.recv_bitmap;

        self.send_enc_key = fresh.send_enc_key;
        self.recv_enc_key = fresh.recv_enc_key;
        self.send_seq = 0;
        self.recv_window = 0;
        self.recv_bitmap = 0;
        // `fresh` drops here; ZeroizeOnDrop wipes its own key copies.
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

    /// Get current send count (for re-key decisions).
    fn send_count(&self) -> u64 {
        self.send_seq
    }
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
    /// Initiator-side ephemeral KEM key for an in-flight rekey, paired with the
    /// `send_seq` at which it was started (a message-counter clock used to
    /// abandon a rekey that never gets a response). `None` when idle.
    pending_rekey: tokio::sync::Mutex<Option<(KemKeypair, u64)>>,
    /// Negotiated wire protocol version for this link.
    negotiated_version: u8,
    _drain_task: tokio::task::JoinHandle<()>,
    /// Transport name captured at construction for status display.
    transport_name: &'static str,
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
        let msg = my_hello.to_wire().encode();
        transport.send(&msg).await?;

        // Receive peer hello
        let mut buf = vec![0u8; 8192];
        let n = transport.recv(&mut buf).await?;
        let wire = WireMessage::decode(&buf[..n])?;
        if wire.msg_type != crate::wire::MessageType::HandshakeHello {
            return Err(Error::Wire("expected HandshakeHello".into()));
        }
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
        transport.send(&auth.to_wire().encode()).await?;

        // Receive and verify peer auth
        let n = transport.recv(&mut buf).await?;
        let wire = WireMessage::decode(&buf[..n])?;
        if wire.msg_type != crate::wire::MessageType::HandshakeAuth {
            return Err(Error::Wire("expected HandshakeAuth".into()));
        }
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
        transport.send(&confirm.to_wire().encode()).await?;

        // Receive and verify peer's (responder) confirm
        let n = transport.recv(&mut buf).await?;
        let wire = WireMessage::decode(&buf[..n])?;
        if wire.msg_type != crate::wire::MessageType::HandshakeConfirm {
            return Err(Error::Wire("expected HandshakeConfirm".into()));
        }
        let peer_confirm = HandshakeConfirmMsg::from_bytes(&wire.payload)?;
        let expected_peer_confirm = compute_confirm_hash(&shared_bytes, false);
        if peer_confirm
            .confirm_hash
            .ct_eq(&expected_peer_confirm)
            .unwrap_u8()
            == 0
        {
            return Err(Error::Crypto("key confirmation failed".into()));
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
            negotiated_version,
            identity: std::sync::Arc::new(
                Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap(),
            ),
            _drain_task,
            transport_name,
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
        let mut buf = vec![0u8; 8192];
        let n = transport.recv(&mut buf).await?;
        let wire = WireMessage::decode(&buf[..n])?;
        if wire.msg_type != crate::wire::MessageType::HandshakeHello {
            return Err(Error::Wire("expected HandshakeHello".into()));
        }
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
        transport.send(&my_hello.to_wire().encode()).await?;

        // Compute X25519 ephemeral shared secret
        let peer_eph = X25519Public::from(peer_hello.ephemeral_pubkey);
        let x25519_shared = eph_secret.diffie_hellman(&peer_eph);

        // Receive peer auth (contains both static + ephemeral KEM ciphertexts)
        let n = transport.recv(&mut buf).await?;
        let wire = WireMessage::decode(&buf[..n])?;
        if wire.msg_type != crate::wire::MessageType::HandshakeAuth {
            return Err(Error::Wire("expected HandshakeAuth".into()));
        }
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
        transport.send(&auth.to_wire().encode()).await?;

        // Key confirmation: receive and verify peer's (initiator) confirm
        let n = transport.recv(&mut buf).await?;
        let wire = WireMessage::decode(&buf[..n])?;
        if wire.msg_type != crate::wire::MessageType::HandshakeConfirm {
            return Err(Error::Wire("expected HandshakeConfirm".into()));
        }
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
        transport.send(&confirm.to_wire().encode()).await?;

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
            negotiated_version,
            identity: std::sync::Arc::new(
                Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap(),
            ),
            _drain_task,
            transport_name,
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
        let mut buf = vec![0u8; MAX_LINK_FRAME];
        let n = tokio::time::timeout(RECV_STALL_TIMEOUT, self.transport.recv(&mut buf))
            .await
            .map_err(|_| Error::Wire("link recv stalled".into()))??;
        self.crypto.lock().await.decrypt(&buf[..n])
    }

    pub fn remote_peer(&self) -> PeerId {
        self.remote_peer
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

    /// Check if a re-key is warranted based on traffic in either direction.
    pub async fn needs_rekey(&self) -> bool {
        self.crypto.lock().await.should_rekey()
    }

    /// Begin an in-band rekey by sending our ephemeral KEM public key.
    ///
    /// Only the link *initiator* drives rekeys; the responder answers via
    /// [`handle_rekey_msg`]. This keeps roles unambiguous (no simultaneous
    /// two-sided initiation) and keeps the new key derivation directionally
    /// consistent with the original handshake.
    ///
    /// Unlike a blocking handshake, this does not read from the transport —
    /// the response arrives as an ordinary message and is fed to
    /// [`handle_rekey_msg`] by the node's receive loop. Safe to call while that
    /// loop is running. No-op if a rekey is already in flight.
    pub async fn rekey_initiate(&self) -> Result<()> {
        if !self.is_initiator {
            return Ok(());
        }

        let send_seq = self.crypto.lock().await.send_count();

        let mut pending = self.pending_rekey.lock().await;
        if let Some((_, started_at)) = pending.as_ref() {
            // A rekey is already outstanding. Only abandon and retry once a full
            // interval of messages has gone by with no response (message-count
            // clock — no wall clock needed); otherwise let it complete.
            if send_seq.wrapping_sub(*started_at) < REKEY_INTERVAL {
                return Ok(());
            }
        }

        let eph_kem = KemKeypair::generate_ephemeral(self.rekey_kem_algo);
        let mut rekey_msg = RekeyMsg {
            kem_algo: self.rekey_kem_algo as u8,
            kem_pubkey: eph_kem.kem_pubkey_bytes(),
            kem_ciphertext: Vec::new(),
            signature: Vec::new(),
        };
        rekey_msg.signature = self.identity.sign(&rekey_msg.signable_bytes());
        *pending = Some((eph_kem, send_seq));
        // Send while holding the pending lock so a concurrent caller can't slip
        // a second init in between.
        self.send_message(&rekey_msg.to_wire().encode()).await?;
        log::debug!("Rekey initiated with {:?}", self.remote_peer);
        Ok(())
    }

    /// Handle an inbound rekey message, dispatched from the node receive loop.
    ///
    /// A message carrying a KEM *pubkey* is a rekey request: we encapsulate to
    /// it and reply with the ciphertext, then install the new keys. A message
    /// carrying a *ciphertext* is the response to a rekey we initiated: we
    /// decapsulate and install. The new recv key is installed alongside the old
    /// one (retained briefly) so the directional switchover has no lossy gap.
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
            // Rekey request → encapsulate, reply, then install.
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

            // The reply MUST go out under the current (old) key — the peer can
            // only decrypt it before it switches. Send first, install after.
            // Non-droppable: we install the new send key right after, so a
            // dropped reply would leave the peer unable to decrypt anything
            // we send from then on.
            self.send_message_critical(&reply.to_wire().encode()).await?;
            let new_shared = blake3::derive_key("tarnet rekey", &kem_ss);
            self.crypto
                .lock()
                .await
                .install_rekey(&new_shared, self.is_initiator);
            log::debug!("Re-keyed link with {:?} (answered request)", self.remote_peer);
            Ok(())
        } else if !peer_rekey.kem_ciphertext.is_empty() {
            // Response to a rekey we initiated.
            let eph_kem = match self.pending_rekey.lock().await.take() {
                Some((eph_kem, _)) => eph_kem,
                None => {
                    return Err(Error::Crypto(
                        "unexpected rekey response (no rekey in flight)".into(),
                    ))
                }
            };
            let kem_ss = eph_kem
                .decapsulate(&peer_rekey.kem_ciphertext)
                .map_err(|e| Error::Crypto(format!("rekey KEM decapsulate failed: {}", e)))?;
            let new_shared = blake3::derive_key("tarnet rekey", &kem_ss);
            self.crypto
                .lock()
                .await
                .install_rekey(&new_shared, self.is_initiator);
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
