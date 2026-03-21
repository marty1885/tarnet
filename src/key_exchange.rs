//! Shared ephemeral KEM key exchange used by circuits, tunnels, and links.
//!
//! Provides a common pattern: the initiator generates an ephemeral KEM keypair
//! and sends the public key; the responder encapsulates to that key and sends
//! the ciphertext back; the initiator decapsulates to recover the shared secret.
//!
//! Both classical (X25519) and post-quantum hybrid (ML-KEM-768 + X25519) are
//! supported transparently — the KEM algorithm is selected at offer time and
//! carried in the payload so the responder picks the right primitive.

use crate::identity::KemKeypair;
use crate::types::{Error, Result};
use tarnet_api::types::KemAlgo;

/// Initiator side of an ephemeral KEM key exchange.
///
/// Create with [`KexOffer::new`], send [`pubkey_bytes()`] to the responder
/// (along with [`algo_byte()`] so they know which KEM to use), then call
/// [`complete()`] with the ciphertext they return.
pub struct KexOffer {
    keypair: KemKeypair,
    algo: KemAlgo,
}

impl KexOffer {
    /// Generate a fresh ephemeral KEM keypair for the given algorithm.
    pub fn new(algo: KemAlgo) -> Self {
        Self {
            keypair: KemKeypair::generate_ephemeral(algo),
            algo,
        }
    }

    /// KEM algorithm identifier byte for wire encoding.
    pub fn algo_byte(&self) -> u8 {
        self.algo as u8
    }

    /// The ephemeral public key bytes to send to the responder.
    pub fn pubkey_bytes(&self) -> Vec<u8> {
        self.keypair.kem_pubkey_bytes()
    }

    /// Complete the exchange by decapsulating the responder's ciphertext.
    /// Returns the 32-byte shared secret.
    pub fn complete(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        self.keypair
            .decapsulate(ciphertext)
            .map_err(|e| Error::Crypto(format!("KEM decapsulate failed: {}", e)))
    }
}

/// Responder side: accept a KEM offer by encapsulating to the offered public key.
///
/// Returns `(shared_secret, ciphertext)` — send the ciphertext back to the
/// initiator so they can [`KexOffer::complete()`].
pub fn kex_accept(algo: KemAlgo, pubkey: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    KemKeypair::encapsulate_to(pubkey, algo)
        .map_err(|e| Error::Crypto(format!("KEM encapsulate failed: {}", e)))
}
