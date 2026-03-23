use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;

use crate::crypto::kdf;
use crate::types::{Error, PeerId, Result};

const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;

/// End-to-end encrypted tunnel to a remote peer.
/// Identified by the remote PeerId — one tunnel per peer.
pub struct Tunnel {
    pub remote_peer: PeerId,
    enc_key: [u8; 32],
    dec_key: [u8; 32],
}

impl Tunnel {
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
            enc_key: enc,
            dec_key: dec,
        }
    }

    /// Encrypt data for sending through the tunnel.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new((&self.enc_key).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .expect("AEAD encryption should not fail");

        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt data received through the tunnel.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err(Error::Crypto("tunnel ciphertext too short".into()));
        }
        let nonce = &data[..NONCE_SIZE];
        let ciphertext_with_tag = &data[NONCE_SIZE..];

        let cipher = XChaCha20Poly1305::new((&self.dec_key).into());
        cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext_with_tag,
                    aad: b"",
                },
            )
            .map_err(|_| Error::Crypto("tunnel AEAD decryption failed".into()))
    }
}

/// Tunnel table: maps remote PeerId → Tunnel.
/// No relay state — tunnels are pure e2e encryption keyed by peer.
pub struct TunnelTable {
    pub tunnels: HashMap<PeerId, Tunnel>,
}

impl TunnelTable {
    pub fn new() -> Self {
        Self {
            tunnels: HashMap::new(),
        }
    }

    /// Register a tunnel to a remote peer.
    pub fn add(&mut self, tunnel: Tunnel) {
        self.tunnels.insert(tunnel.remote_peer, tunnel);
    }

    /// Look up a tunnel by remote peer.
    pub fn get(&self, peer: &PeerId) -> Option<&Tunnel> {
        self.tunnels.get(peer)
    }

    /// Remove a tunnel by remote peer.
    pub fn remove(&mut self, peer: &PeerId) {
        self.tunnels.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_encrypt_decrypt() {
        let shared = [42u8; 32];
        let initiator = Tunnel::new(PeerId([2; 32]), &shared, true);
        let responder = Tunnel::new(PeerId([1; 32]), &shared, false);

        let msg = b"end-to-end encrypted data";
        let encrypted = initiator.encrypt(msg);
        let decrypted = responder.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);

        let response = b"response through tunnel";
        let enc2 = responder.encrypt(response);
        let dec2 = initiator.decrypt(&enc2).unwrap();
        assert_eq!(dec2, response);
    }

    #[test]
    fn tunnel_tamper_detected() {
        let shared = [42u8; 32];
        let initiator = Tunnel::new(PeerId([2; 32]), &shared, true);
        let responder = Tunnel::new(PeerId([1; 32]), &shared, false);

        let mut encrypted = initiator.encrypt(b"data");
        encrypted[NONCE_SIZE] ^= 0xff;
        assert!(responder.decrypt(&encrypted).is_err());
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
