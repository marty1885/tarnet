use std::collections::{BTreeSet, HashMap};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;

use crate::crypto::kdf;
use crate::types::{Error, PeerId, Result};

const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const SEQ_SIZE: usize = 8;
const REPLAY_WINDOW: u64 = 1024;
const TUNNEL_DATA_CONTEXT: &[u8] = b"tarnet tunnel data v4";

/// End-to-end encrypted tunnel to a remote peer.
/// Identified by the remote PeerId — one tunnel per peer.
pub struct Tunnel {
    pub remote_peer: PeerId,
    /// Forwarding hints toward `remote_peer` when we have no route to it.
    pub hints: Vec<PeerId>,
    enc_key: [u8; 32],
    dec_key: [u8; 32],
    send_seq: u64,
    recv_highest: Option<u64>,
    recv_seen: BTreeSet<u64>,
    /// Responder side: nonces of the key exchanges that created this tunnel
    /// and replaced its predecessors, newest last, so a replay of any of them
    /// can't swap the keys while the tunnel lives.
    pub kex_nonces: Vec<[u8; 32]>,
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

    /// Create a new tunnel from a completed key exchange.
    /// `is_initiator` determines which direction gets which keys.
    pub fn new(remote_peer: PeerId, shared_secret: &[u8; 32], is_initiator: bool) -> Self {
        let mut enc = kdf(shared_secret, "tarnet tunnel i2r_enc");
        let mut dec = kdf(shared_secret, "tarnet tunnel r2i_enc");

        if !is_initiator {
            std::mem::swap(&mut enc, &mut dec);
        }

        Self {
            remote_peer,
            hints: Vec::new(),
            enc_key: enc,
            dec_key: dec,
            send_seq: 0,
            recv_highest: None,
            recv_seen: BTreeSet::new(),
            kex_nonces: Vec::new(),
            last_used: std::time::Instant::now(),
        }
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

        let mut aad = Vec::with_capacity(TUNNEL_DATA_CONTEXT.len() + SEQ_SIZE);
        aad.extend_from_slice(TUNNEL_DATA_CONTEXT);
        aad.extend_from_slice(&sequence.to_be_bytes());

        let cipher = XChaCha20Poly1305::new((&self.enc_key).into());
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

    /// Decrypt data received through the tunnel.
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < SEQ_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(Error::Crypto("tunnel ciphertext too short".into()));
        }
        let sequence = u64::from_be_bytes(data[..SEQ_SIZE].try_into().unwrap());
        self.check_replay(sequence)?;
        let nonce = &data[SEQ_SIZE..SEQ_SIZE + NONCE_SIZE];
        let ciphertext_with_tag = &data[SEQ_SIZE + NONCE_SIZE..];

        let mut aad = Vec::with_capacity(TUNNEL_DATA_CONTEXT.len() + SEQ_SIZE);
        aad.extend_from_slice(TUNNEL_DATA_CONTEXT);
        aad.extend_from_slice(&sequence.to_be_bytes());

        let cipher = XChaCha20Poly1305::new((&self.dec_key).into());
        let plaintext = cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext_with_tag,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto("tunnel AEAD decryption failed".into()))?;

        // Commit replay state only after authentication succeeds. A forged packet
        // with a high sequence number must not advance the window.
        self.record_sequence(sequence);
        self.last_used = std::time::Instant::now();
        Ok(plaintext)
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
    pub fn remove(&mut self, peer: &PeerId) {
        self.tunnels.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_table_is_bounded_and_keeps_tunnels_in_use() {
        let mut table = TunnelTable::new();
        for i in 0..MAX_TUNNELS as u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            table.add(Tunnel::new(PeerId(id), &[1; 32], false));
        }
        // The first is in use; adding one more evicts some other.
        let first = PeerId([0; 32]);
        table.get_mut(&first).unwrap().encrypt(b"x").unwrap();
        table.add(Tunnel::new(PeerId([0xFF; 32]), &[1; 32], false));
        assert_eq!(table.len(), MAX_TUNNELS);
        assert!(table.get(&first).is_some());
        assert!(table.get(&PeerId([0xFF; 32])).is_some());
    }

    use super::*;

    #[test]
    fn tunnel_encrypt_decrypt() {
        let shared = [42u8; 32];
        let mut initiator = Tunnel::new(PeerId([2; 32]), &shared, true);
        let mut responder = Tunnel::new(PeerId([1; 32]), &shared, false);

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
        let mut initiator = Tunnel::new(PeerId([2; 32]), &shared, true);
        let mut responder = Tunnel::new(PeerId([1; 32]), &shared, false);

        let mut encrypted = initiator.encrypt(b"data").unwrap();
        encrypted[SEQ_SIZE + NONCE_SIZE] ^= 0xff;
        assert!(responder.decrypt(&encrypted).is_err());
    }

    #[test]
    fn tunnel_accepts_reordering_and_rejects_replay() {
        let shared = [7u8; 32];
        let mut sender = Tunnel::new(PeerId([2; 32]), &shared, true);
        let mut receiver = Tunnel::new(PeerId([1; 32]), &shared, false);
        let first = sender.encrypt(b"first").unwrap();
        let second = sender.encrypt(b"second").unwrap();

        assert_eq!(receiver.decrypt(&second).unwrap(), b"second");
        assert_eq!(receiver.decrypt(&first).unwrap(), b"first");
        assert!(matches!(receiver.decrypt(&first), Err(Error::Replay(_))));
    }

    #[test]
    fn unauthenticated_sequence_does_not_advance_replay_window() {
        let shared = [8u8; 32];
        let mut sender = Tunnel::new(PeerId([2; 32]), &shared, true);
        let mut receiver = Tunnel::new(PeerId([1; 32]), &shared, false);
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

        let tunnel_a = Tunnel::new(peer_a, &shared, true);
        let tunnel_b = Tunnel::new(peer_b, &shared, true);

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
