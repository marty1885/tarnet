use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::kdf;
use crate::identity::{self, peer_id_from_signing_pubkey, KemKeypair, Keypair};
use crate::transport::Transport;
use crate::types::{Error, PeerId, Result};
use crate::wire::{
    HandshakeAuth, HandshakeConfirmMsg, HandshakeHello, RekeyMsg, WireMessage,
    WIRE_VERSION_MAX, WIRE_VERSION_MIN,
};
use tarnet_api::types::{KemAlgo, SigningAlgo};

/// Outbound cells buffered per link before dropping.
/// When the drain task can't keep up (slow peer / congested link),
/// new cells are silently dropped — end-to-end flow control reacts
/// via missing SENDMEs.
const OUTBOUND_QUEUE_SIZE: usize = 4096;

const TAG_SIZE: usize = 16;
const SEQ_SIZE: usize = 8;
/// Sliding window size for replay detection.
const REPLAY_WINDOW: u64 = 128;
/// Re-key after this many messages sent.
pub const REKEY_INTERVAL: u64 = 65536;
/// Maximum allowed timestamp drift in seconds.
const MAX_TIMESTAMP_DRIFT: u64 = 300;

/// Session keys for bidirectional encrypted communication.
#[derive(Zeroize, ZeroizeOnDrop)]
struct LinkCrypto {
    send_enc_key: [u8; 32],
    recv_enc_key: [u8; 32],
    #[zeroize(skip)]
    send_seq: u64,
    #[zeroize(skip)]
    recv_window: u64,
    #[zeroize(skip)]
    recv_bitmap: u128,
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
            send_seq: 0,
            recv_window: 0,
            recv_bitmap: 0,
        }
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
            .encrypt((&nonce).into(), Payload { msg: &msg, aad: b"" })
            .expect("AEAD encryption should not fail");

        // Wire: nonce(24) || ciphertext+tag
        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 24 + SEQ_SIZE + TAG_SIZE {
            return Err(Error::Crypto("encrypted message too short".into()));
        }
        let nonce = &data[..24];
        let ciphertext_with_tag = &data[24..];

        let cipher = XChaCha20Poly1305::new((&self.recv_enc_key).into());
        let mut plaintext = cipher
            .decrypt(nonce.into(), Payload { msg: ciphertext_with_tag, aad: b"" })
            .map_err(|_| Error::Crypto("AEAD decryption failed".into()))?;

        // Extract sequence number
        if plaintext.len() < SEQ_SIZE {
            return Err(Error::Crypto("decrypted payload too short for seq".into()));
        }
        let seq = u64::from_be_bytes(plaintext[..SEQ_SIZE].try_into().unwrap());

        // Anti-replay check
        self.check_replay(seq)?;

        // Strip the seq prefix in-place — no second allocation needed.
        plaintext.drain(..SEQ_SIZE);
        Ok(plaintext)
    }

    /// Sliding-window replay detection.
    fn check_replay(&mut self, seq: u64) -> Result<()> {
        if self.recv_window == 0 && self.recv_bitmap == 0 {
            // First packet
            self.recv_window = seq;
            self.recv_bitmap = 1;
            return Ok(());
        }

        if seq > self.recv_window {
            // Advance the window
            let shift = seq - self.recv_window;
            if shift < 128 {
                self.recv_bitmap <<= shift;
                self.recv_bitmap |= 1;
            } else {
                self.recv_bitmap = 1;
            }
            self.recv_window = seq;
            Ok(())
        } else {
            let diff = self.recv_window - seq;
            if diff >= REPLAY_WINDOW {
                return Err(Error::Replay("sequence number too old".into()));
            }
            let bit = 1u128 << diff;
            if self.recv_bitmap & bit != 0 {
                return Err(Error::Replay("duplicate sequence number".into()));
            }
            self.recv_bitmap |= bit;
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
    remote_peer: PeerId,
    remote_signing_algo: SigningAlgo,
    remote_signing_pubkey: Vec<u8>,
    is_initiator: bool,
    identity: std::sync::Arc<Keypair>,
    /// Negotiated KEM algorithm for rekey exchanges.
    rekey_kem_algo: KemAlgo,
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
        let peer_hello = HandshakeHello::from_bytes(&wire.payload)?;

        // Negotiate wire protocol version
        let negotiated_version = negotiate_version(
            WIRE_VERSION_MIN, WIRE_VERSION_MAX,
            peer_hello.min_version, peer_hello.max_version,
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
        let (static_kem_ss, static_kem_ct) = KemKeypair::encapsulate_to(&peer_hello.kem_pubkey, remote_kem_algo)
            .map_err(|e| Error::Crypto(format!("KEM encapsulate (static) failed: {}", e)))?;

        // KEM encapsulate to responder's ephemeral KEM pubkey (PQ forward secrecy)
        let (eph_kem_ss, eph_kem_ct) = KemKeypair::encapsulate_to(&peer_hello.eph_kem_pubkey, remote_kem_algo)
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
        if !identity::verify(remote_signing_algo, &peer_hello.signing_pubkey, &peer_transcript, &peer_auth.signature) {
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
        let peer_confirm = HandshakeConfirmMsg::from_bytes(&wire.payload)?;
        let expected_peer_confirm = compute_confirm_hash(&shared_bytes, false);
        if peer_confirm.confirm_hash != expected_peer_confirm {
            return Err(Error::Crypto("key confirmation failed".into()));
        }

        log::info!("Link established (initiator) with {:?}, wire v{}", remote_peer, negotiated_version);
        let transport_name = transport.name();
        let transport: Arc<dyn Transport> = Arc::from(transport);
        let (outbound_tx, _drain_task) = Self::spawn_drain(transport.clone(), remote_peer);
        Ok(Self {
            transport,
            crypto: tokio::sync::Mutex::new(crypto),
            outbound_tx,
            remote_peer,
            remote_signing_algo,
            remote_signing_pubkey: peer_hello.signing_pubkey,
            is_initiator: true,
            rekey_kem_algo: KemAlgo::negotiate_rekey(my_kem_algo, remote_kem_algo),
            negotiated_version,
            identity: std::sync::Arc::new(Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap()),
            _drain_task,
            transport_name,
        })
    }

    /// Perform handshake as the responder (the side that called accept).
    pub async fn responder(transport: Box<dyn Transport>, identity: &Keypair) -> Result<Self> {
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
        let peer_hello = HandshakeHello::from_bytes(&wire.payload)?;

        // Negotiate wire protocol version
        let negotiated_version = negotiate_version(
            WIRE_VERSION_MIN, WIRE_VERSION_MAX,
            peer_hello.min_version, peer_hello.max_version,
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
        let peer_auth = HandshakeAuth::from_bytes(&wire.payload)?;

        // KEM decapsulate static: recover shared secret from initiator's ciphertext
        let static_kem_ss = identity.identity.kem.decapsulate(&peer_auth.kem_ciphertext)
            .map_err(|e| Error::Crypto(format!("KEM decapsulate (static) failed: {}", e)))?;

        // KEM decapsulate ephemeral: recover shared secret using our ephemeral KEM key
        let eph_kem_ss = eph_kem.decapsulate(&peer_auth.eph_kem_ciphertext)
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
        if !identity::verify(remote_signing_algo, &peer_hello.signing_pubkey, &peer_transcript, &peer_auth.signature) {
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
        let peer_confirm = HandshakeConfirmMsg::from_bytes(&wire.payload)?;

        let expected_peer_confirm = compute_confirm_hash(&shared_bytes, true);
        if peer_confirm.confirm_hash != expected_peer_confirm {
            return Err(Error::Crypto("key confirmation failed".into()));
        }

        // Send our (responder) confirm
        let confirm_hash = compute_confirm_hash(&shared_bytes, false);
        let confirm = HandshakeConfirmMsg { confirm_hash };
        transport.send(&confirm.to_wire().encode()).await?;

        log::info!("Link established (responder) with {:?}, wire v{}", remote_peer, negotiated_version);
        let transport_name = transport.name();
        let transport: Arc<dyn Transport> = Arc::from(transport);
        let (outbound_tx, _drain_task) = Self::spawn_drain(transport.clone(), remote_peer);
        Ok(Self {
            transport,
            crypto: tokio::sync::Mutex::new(crypto),
            outbound_tx,
            remote_peer,
            remote_signing_algo,
            remote_signing_pubkey: peer_hello.signing_pubkey,
            is_initiator: false,
            rekey_kem_algo: KemAlgo::negotiate_rekey(my_kem_algo, remote_kem_algo),
            negotiated_version,
            identity: std::sync::Arc::new(Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap()),
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
    fn spawn_drain(
        transport: Arc<dyn Transport>,
        remote: PeerId,
    ) -> (tokio::sync::mpsc::Sender<Vec<u8>>, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE_SIZE);
        let task = tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if let Err(e) = transport.send(&data).await {
                    log::debug!("link drain to {:?}: {}", remote, e);
                    break;
                }
            }
        });
        (tx, task)
    }

    /// Send an encrypted message over the link.
    ///
    /// The message is encrypted and placed into a bounded outbound queue.
    /// If the queue is full (peer is congested), the cell is silently
    /// dropped — end-to-end flow control handles recovery.
    pub async fn send_message(&self, data: &[u8]) -> Result<()> {
        let encrypted = self.crypto.lock().await.encrypt(data);
        match self.outbound_tx.try_send(encrypted) {
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

    /// Receive and decrypt a message from the link.
    pub async fn recv_message(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 65536 + 24 + SEQ_SIZE + TAG_SIZE];
        let n = self.transport.recv(&mut buf).await?;
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

    /// Negotiated wire protocol version for this link.
    pub fn negotiated_version(&self) -> u8 {
        self.negotiated_version
    }

    /// Check if a re-key is needed based on messages sent.
    pub async fn needs_rekey(&self) -> bool {
        self.crypto.lock().await.send_count() >= REKEY_INTERVAL
    }

    /// Perform re-keying using the negotiated KEM algorithm.
    ///
    /// The KEM type owns the entire key exchange — no bare X25519 overlay.
    /// Initiator: generates ephemeral KEM keypair, sends pubkey, receives ciphertext.
    /// Responder: receives pubkey, encapsulates, sends ciphertext back.
    pub async fn rekey(&self) -> Result<()> {
        let kem_algo = self.rekey_kem_algo;

        if self.is_initiator {
            let eph_kem = KemKeypair::generate_ephemeral(kem_algo);

            let mut rekey_msg = RekeyMsg {
                kem_algo: kem_algo as u8,
                kem_pubkey: eph_kem.kem_pubkey_bytes(),
                kem_ciphertext: Vec::new(),
                signature: Vec::new(),
            };
            rekey_msg.signature = self.identity.sign(&rekey_msg.signable_bytes());

            self.send_message(&rekey_msg.to_wire().encode()).await?;

            // Receive responder's rekey (contains KEM ciphertext)
            let response_data = self.recv_message().await?;
            let wire = WireMessage::decode(&response_data)?;
            let peer_rekey = RekeyMsg::from_bytes(&wire.payload)?;

            if !identity::verify(
                self.remote_signing_algo,
                &self.remote_signing_pubkey,
                &peer_rekey.signable_bytes(),
                &peer_rekey.signature,
            ) {
                return Err(Error::Crypto("rekey signature invalid".into()));
            }

            let kem_ss = eph_kem.decapsulate(&peer_rekey.kem_ciphertext)
                .map_err(|e| Error::Crypto(format!("rekey KEM decapsulate failed: {}", e)))?;

            let new_shared = blake3::derive_key("tarnet rekey", &kem_ss);
            let new_crypto = LinkCrypto::derive(&new_shared, true);
            *self.crypto.lock().await = new_crypto;
        } else {
            // Responder: receive first, then send
            let response_data = self.recv_message().await?;
            let wire = WireMessage::decode(&response_data)?;
            let peer_rekey = RekeyMsg::from_bytes(&wire.payload)?;

            if !identity::verify(
                self.remote_signing_algo,
                &self.remote_signing_pubkey,
                &peer_rekey.signable_bytes(),
                &peer_rekey.signature,
            ) {
                return Err(Error::Crypto("rekey signature invalid".into()));
            }

            let peer_kem_algo = KemAlgo::from_u8(peer_rekey.kem_algo)
                .map_err(|e| Error::Crypto(format!("unknown rekey KEM algo: {}", e)))?;
            let (kem_ss, kem_ct) = KemKeypair::encapsulate_to(&peer_rekey.kem_pubkey, peer_kem_algo)
                .map_err(|e| Error::Crypto(format!("rekey KEM encapsulate failed: {}", e)))?;

            let mut rekey_msg = RekeyMsg {
                kem_algo: kem_algo as u8,
                kem_pubkey: Vec::new(),
                kem_ciphertext: kem_ct,
                signature: Vec::new(),
            };
            rekey_msg.signature = self.identity.sign(&rekey_msg.signable_bytes());

            self.send_message(&rekey_msg.to_wire().encode()).await?;

            let new_shared = blake3::derive_key("tarnet rekey", &kem_ss);
            let new_crypto = LinkCrypto::derive(&new_shared, false);
            *self.crypto.lock().await = new_crypto;
        }

        log::info!("Re-keyed link with {:?}", self.remote_peer);
        Ok(())
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
