use std::collections::{BTreeSet, HashMap};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::{kdf, Ratchet};
use crate::types::{Error, PeerId, Result};

const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const SEQ_SIZE: usize = 8;
const REPLAY_WINDOW: u64 = 1024;
const TUNNEL_DATA_CONTEXT: &[u8] = b"tarnet tunnel data v4";

/// A tunnel's receive key and replay state.
struct RecvKeys {
    dec: Ratchet,
    recv_highest: Option<u64>,
    recv_seen: BTreeSet<u64>,
}

impl RecvKeys {
    fn new(key: [u8; 32]) -> Self {
        Self {
            dec: Ratchet::new(key),
            recv_highest: None,
            recv_seen: BTreeSet::new(),
        }
    }

    fn check_replay(&self, sequence: u64) -> Result<()> {
        if self.recv_seen.contains(&sequence) {
            return Err(Error::Replay("duplicate tunnel sequence".into()));
        }
        if let Some(highest) = self.recv_highest {
            if sequence <= highest && highest - sequence >= REPLAY_WINDOW {
                return Err(Error::Replay("tunnel sequence outside replay window".into()));
            }
        }
        Ok(())
    }

    fn record_sequence(&mut self, sequence: u64) {
        let highest = self.recv_highest.map_or(sequence, |h| h.max(sequence));
        self.recv_highest = Some(highest);
        self.recv_seen.insert(sequence);
        let oldest = highest.saturating_sub(REPLAY_WINDOW - 1);
        self.recv_seen = self.recv_seen.split_off(&oldest);
    }

    fn open(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let sequence = u64::from_be_bytes(data[..SEQ_SIZE].try_into().unwrap());
        self.check_replay(sequence)?;
        let key = Zeroizing::new(
            self.dec
                .recv_candidate(sequence)
                .ok_or_else(|| Error::Crypto("tunnel message outside the key's epochs".into()))?,
        );
        let nonce = &data[SEQ_SIZE..SEQ_SIZE + NONCE_SIZE];
        let ciphertext_with_tag = &data[SEQ_SIZE + NONCE_SIZE..];
        let aad = data_aad(sequence);
        let plaintext = XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext_with_tag,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto("tunnel AEAD decryption failed".into()))?;
        // Commit replay and ratchet state only after authentication succeeds.
        // A forged packet with a high sequence number must not advance them.
        self.record_sequence(sequence);
        self.dec.commit(sequence);
        Ok(plaintext)
    }
}

fn data_aad(sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TUNNEL_DATA_CONTEXT.len() + SEQ_SIZE);
    aad.extend_from_slice(TUNNEL_DATA_CONTEXT);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

/// Hash of a tunnel key exchange: both ends, the offered key, the ciphertext
/// and both nonces. The tunnel's keys are derived from it and the KEM secret.
pub fn kex_transcript(
    initiator: &PeerId,
    responder: &PeerId,
    kem_algo: u8,
    ephemeral_pubkey: &[u8],
    ciphertext: &[u8],
    initiator_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
) -> [u8; 32] {
    blake3::Hasher::new_derive_key("tarnet tunnel v2 transcript")
        .update(initiator.as_bytes())
        .update(responder.as_bytes())
        .update(&[kem_algo])
        .update(&(ephemeral_pubkey.len() as u32).to_be_bytes())
        .update(ephemeral_pubkey)
        .update(&(ciphertext.len() as u32).to_be_bytes())
        .update(ciphertext)
        .update(initiator_nonce)
        .update(responder_nonce)
        .finalize()
        .into()
}

/// End-to-end encrypted tunnel to a remote peer.
/// Identified by the remote PeerId — one tunnel per peer.
pub struct Tunnel {
    pub remote_peer: PeerId,
    /// Forwarding hints toward `remote_peer` when we have no route to it.
    pub hints: Vec<PeerId>,
    enc: Ratchet,
    send_seq: u64,
    recv: RecvKeys,
    /// The receive keys of the tunnel this one replaced, kept until this
    /// one is replaced in turn, so messages the peer sent before switching
    /// still decrypt (rekeys lose nothing).
    prev_recv: Option<RecvKeys>,
    /// Responder side: nonces of the key exchanges that created this tunnel
    /// and replaced its predecessors, newest last, so a replay of any of them
    /// can't swap the keys while the tunnel lives.
    pub kex_nonces: Vec<[u8; 32]>,
    /// Whether we ran the key exchange (and so drive its rekeys).
    is_initiator: bool,
    /// When the keys were made (local monotonic clock).
    created_at: std::time::Instant,
    /// Last time it carried data either way, for eviction.
    last_used: std::time::Instant,
}

/// Key exchanges a tunnel remembers (see [`Tunnel::kex_nonces`]).
const KEX_NONCES_MAX: usize = 64;

impl Tunnel {
    /// Remember the key exchange that (re)created this tunnel.
    pub fn remember_kex(&mut self, nonce: [u8; 32]) {
        if self.kex_nonces.len() >= KEX_NONCES_MAX {
            self.kex_nonces.remove(0);
        }
        self.kex_nonces.push(nonce);
    }

    /// Create a new tunnel from a completed key exchange: keys come from the
    /// KEM secret and the exchange's transcript ([`kex_transcript`]).
    /// `is_initiator` determines which direction gets which keys.
    pub fn new(remote_peer: PeerId, shared_secret: &[u8; 32], transcript: &[u8; 32], is_initiator: bool) -> Self {
        let session = Zeroizing::new(
            blake3::Hasher::new_derive_key("tarnet tunnel v2 session")
                .update(shared_secret)
                .update(transcript)
                .finalize()
                .into(),
        );
        let mut enc = Zeroizing::new(kdf(&session, "tarnet tunnel i2r_enc"));
        let mut dec = Zeroizing::new(kdf(&session, "tarnet tunnel r2i_enc"));

        if !is_initiator {
            std::mem::swap(&mut enc, &mut dec);
        }

        let now = std::time::Instant::now();
        Self {
            remote_peer,
            hints: Vec::new(),
            enc: Ratchet::new(*enc),
            send_seq: 0,
            recv: RecvKeys::new(*dec),
            prev_recv: None,
            kex_nonces: Vec::new(),
            is_initiator,
            created_at: now,
            last_used: now,
        }
    }

    /// Take over from the tunnel this one replaces: its receive keys stay
    /// usable for stragglers, and its key-exchange memory carries on.
    pub fn succeed(&mut self, old: Tunnel) {
        let mut old = old;
        self.prev_recv = Some(std::mem::replace(&mut old.recv, RecvKeys::new([0; 32])));
        self.kex_nonces = std::mem::take(&mut old.kex_nonces);
    }

    /// Whether this tunnel is due for a fresh key exchange, which only the
    /// side that ran the last one starts (`docs/spec/identity.md`, "Key
    /// lifetime").
    pub fn needs_rekey(&self) -> bool {
        self.is_initiator
            && (self.send_seq >= crate::link::REKEY_INTERVAL
                || self.created_at.elapsed() >= crate::link::REKEY_MAX_AGE)
    }

    /// Encrypt data for sending through the tunnel.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sequence = self.send_seq;
        self.send_seq = self
            .send_seq
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("tunnel sequence exhausted; rekey required".into()))?;
        let mut nonce = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let aad = data_aad(sequence);
        let key = Zeroizing::new(self.enc.send_key(sequence));
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("AEAD encryption should not fail");

        let mut out = Vec::with_capacity(SEQ_SIZE + NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        self.last_used = std::time::Instant::now();
        Ok(out)
    }

    /// Decrypt data received through the tunnel: under the current keys, or
    /// the replaced tunnel's while the peer may still be using them.
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < SEQ_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(Error::Crypto("tunnel ciphertext too short".into()));
        }
        let plaintext = match self.recv.open(data) {
            Ok(p) => p,
            Err(e) => match self.prev_recv.as_mut() {
                Some(prev) => prev.open(data).map_err(|_| e)?,
                None => return Err(e),
            },
        };
        self.last_used = std::time::Instant::now();
        Ok(plaintext)
    }
}

/// Tunnel table: maps remote PeerId → Tunnel.
/// No relay state — tunnels are pure e2e encryption keyed by peer.
///
/// Bounded: past [`MAX_TUNNELS`], a new tunnel evicts the one used least
/// recently. Tunnels aren't expired by idleness, since the far end can't
/// tell its peer forgot one; under a flood of new initiators, the tunnels
/// in use survive.
pub struct TunnelTable {
    tunnels: HashMap<PeerId, Tunnel>,
}

/// Tunnels held at once.
pub const MAX_TUNNELS: usize = 4096;

impl TunnelTable {
    pub fn new() -> Self {
        Self {
            tunnels: HashMap::new(),
        }
    }

    /// Register a tunnel to a remote peer.
    pub fn add(&mut self, tunnel: Tunnel) {
        if !self.tunnels.contains_key(&tunnel.remote_peer) && self.tunnels.len() >= MAX_TUNNELS {
            if let Some(stale) = self
                .tunnels
                .iter()
                .min_by_key(|(_, t)| t.last_used)
                .map(|(p, _)| *p)
            {
                self.tunnels.remove(&stale);
            }
        }
        self.tunnels.insert(tunnel.remote_peer, tunnel);
    }

    /// Peers whose tunnel is due for a fresh key exchange we should start.
    pub fn rekey_due(&self) -> Vec<PeerId> {
        self.tunnels
            .values()
            .filter(|t| t.needs_rekey())
            .map(|t| t.remote_peer)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    /// Look up a tunnel by remote peer.
    pub fn get(&self, peer: &PeerId) -> Option<&Tunnel> {
        self.tunnels.get(peer)
    }

    pub fn get_mut(&mut self, peer: &PeerId) -> Option<&mut Tunnel> {
        self.tunnels.get_mut(peer)
    }

    /// Remove a tunnel by remote peer.
    pub fn remove(&mut self, peer: &PeerId) -> Option<Tunnel> {
        self.tunnels.remove(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_bind_the_transcript() {
        let mut a = Tunnel::new(PeerId([2; 32]), &[1; 32], &[3; 32], true);
        let mut b = Tunnel::new(PeerId([1; 32]), &[1; 32], &[4; 32], false);
        let ct = a.encrypt(b"x").unwrap();
        assert!(b.decrypt(&ct).is_err());
    }

    #[test]
    fn replacement_keeps_stragglers_readable() {
        let (ia, ib) = (PeerId([1; 32]), PeerId([2; 32]));
        let mut a = Tunnel::new(ib, &[1; 32], &[3; 32], true);
        let b = Tunnel::new(ia, &[1; 32], &[3; 32], false);
        let old_msg = a.encrypt(b"sent before the rekey").unwrap();
        // Both sides switch to a new exchange; the old message arrives late.
        let mut a2 = Tunnel::new(ib, &[9; 32], &[8; 32], true);
        let mut b2 = Tunnel::new(ia, &[9; 32], &[8; 32], false);
        a2.succeed(a);
        b2.succeed(b);
        assert_eq!(b2.decrypt(&old_msg).unwrap(), b"sent before the rekey");
        let new_msg = a2.encrypt(b"after").unwrap();
        assert_eq!(b2.decrypt(&new_msg).unwrap(), b"after");
        // Replays are still caught, under either key.
        assert!(b2.decrypt(&old_msg).is_err());
        assert!(b2.decrypt(&new_msg).is_err());
    }

    #[test]
    fn only_the_initiator_rekeys_and_only_when_due() {
        let mut a = Tunnel::new(PeerId([2; 32]), &[1; 32], &[3; 32], true);
        let b = Tunnel::new(PeerId([1; 32]), &[1; 32], &[3; 32], false);
        assert!(!a.needs_rekey());
        a.created_at -= crate::link::REKEY_MAX_AGE;
        assert!(a.needs_rekey());
        let mut b = b;
        b.created_at -= crate::link::REKEY_MAX_AGE;
        assert!(!b.needs_rekey());
    }

    #[test]
    fn the_table_is_bounded_and_keeps_tunnels_in_use() {
        let mut table = TunnelTable::new();
        for i in 0..MAX_TUNNELS as u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            table.add(Tunnel::new(PeerId(id), &[1; 32], &[0x5a; 32], false));
        }
        // The first is in use; adding one more evicts some other.
        let first = PeerId([0; 32]);
        table.get_mut(&first).unwrap().encrypt(b"x").unwrap();
        table.add(Tunnel::new(PeerId([0xFF; 32]), &[1; 32], &[0x5a; 32], false));
        assert_eq!(table.len(), MAX_TUNNELS);
        assert!(table.get(&first).is_some());
        assert!(table.get(&PeerId([0xFF; 32])).is_some());
    }

    #[test]
    fn tunnel_encrypt_decrypt() {
        let shared = [42u8; 32];
        let mut initiator = Tunnel::new(PeerId([2; 32]), &shared, &[0x5a; 32], true);
        let mut responder = Tunnel::new(PeerId([1; 32]), &shared, &[0x5a; 32], false);

        let msg = b"end-to-end encrypted data";
        let encrypted = initiator.encrypt(msg).unwrap();
        let decrypted = responder.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);

        let response = b"response through tunnel";
        let enc2 = responder.encrypt(response).unwrap();
        let dec2 = initiator.decrypt(&enc2).unwrap();
        assert_eq!(dec2, response);
    }

    #[test]
    fn tunnel_tamper_detected() {
        let shared = [42u8; 32];
        let mut initiator = Tunnel::new(PeerId([2; 32]), &shared, &[0x5a; 32], true);
        let mut responder = Tunnel::new(PeerId([1; 32]), &shared, &[0x5a; 32], false);

        let mut encrypted = initiator.encrypt(b"data").unwrap();
        encrypted[SEQ_SIZE + NONCE_SIZE] ^= 0xff;
        assert!(responder.decrypt(&encrypted).is_err());
    }

    #[test]
    fn tunnel_accepts_reordering_and_rejects_replay() {
        let shared = [7u8; 32];
        let mut sender = Tunnel::new(PeerId([2; 32]), &shared, &[0x5a; 32], true);
        let mut receiver = Tunnel::new(PeerId([1; 32]), &shared, &[0x5a; 32], false);
        let first = sender.encrypt(b"first").unwrap();
        let second = sender.encrypt(b"second").unwrap();

        assert_eq!(receiver.decrypt(&second).unwrap(), b"second");
        assert_eq!(receiver.decrypt(&first).unwrap(), b"first");
        assert!(matches!(receiver.decrypt(&first), Err(Error::Replay(_))));
    }

    #[test]
    fn unauthenticated_sequence_does_not_advance_replay_window() {
        let shared = [8u8; 32];
        let mut sender = Tunnel::new(PeerId([2; 32]), &shared, &[0x5a; 32], true);
        let mut receiver = Tunnel::new(PeerId([1; 32]), &shared, &[0x5a; 32], false);
        let valid = sender.encrypt(b"valid").unwrap();
        let mut forged = valid.clone();
        forged[..SEQ_SIZE].copy_from_slice(&u64::MAX.to_be_bytes());

        assert!(matches!(receiver.decrypt(&forged), Err(Error::Crypto(_))));
        assert_eq!(receiver.decrypt(&valid).unwrap(), b"valid");
    }

    #[test]
    fn tunnel_table_peer_keyed() {
        let mut table = TunnelTable::new();
        let shared = [42u8; 32];
        let peer_a = PeerId([1; 32]);
        let peer_b = PeerId([2; 32]);

        let tunnel_a = Tunnel::new(peer_a, &shared, &[0x5a; 32], true);
        let tunnel_b = Tunnel::new(peer_b, &shared, &[0x5a; 32], true);

        table.add(tunnel_a);
        table.add(tunnel_b);

        assert!(table.get(&peer_a).is_some());
        assert!(table.get(&peer_b).is_some());
        assert!(table.get(&PeerId([3; 32])).is_none());

        table.remove(&peer_a);
        assert!(table.get(&peer_a).is_none());
        assert!(table.get(&peer_b).is_some());
    }
}
