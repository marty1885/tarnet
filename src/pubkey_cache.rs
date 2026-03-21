use lru::LruCache;
use std::num::NonZeroUsize;

use crate::identity::peer_id_from_signing_pubkey;
use crate::types::PeerId;
use tarnet_api::types::{KemAlgo, SigningAlgo};

/// Cached public key information for a peer.
#[derive(Debug, Clone)]
pub struct CachedPubkey {
    pub signing_algo: SigningAlgo,
    pub signing_pk: Vec<u8>,
    pub kem_algo: KemAlgo,
    pub kem_pk: Vec<u8>,
}

/// LRU cache mapping PeerId → public key material.
///
/// Populated from: link handshakes, DHT PubkeyRecord lookups.
/// On insert: verifies `derive_key("tarnet peer-id", &signing_pk) == peer_id`.
pub struct PubkeyCache {
    cache: LruCache<PeerId, CachedPubkey>,
}

impl PubkeyCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN)),
        }
    }

    /// Insert a pubkey entry, verifying the PeerId binding.
    /// Returns false if the signing pubkey doesn't derive to the claimed PeerId.
    pub fn insert(&mut self, peer_id: PeerId, entry: CachedPubkey) -> bool {
        let expected = peer_id_from_signing_pubkey(&entry.signing_pk);
        if expected != peer_id {
            log::warn!(
                "pubkey cache: signing pubkey does not derive to claimed {:?}",
                peer_id,
            );
            return false;
        }
        self.cache.put(peer_id, entry);
        true
    }

    /// Look up cached public keys for a peer.
    pub fn get(&mut self, peer_id: &PeerId) -> Option<&CachedPubkey> {
        self.cache.get(peer_id)
    }

    /// Check if we have cached keys for a peer (without promoting in LRU).
    pub fn contains(&self, peer_id: &PeerId) -> bool {
        self.cache.contains(peer_id)
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ed25519_entry() -> (PeerId, CachedPubkey) {
        let kp = crate::identity::IdentityKeypair::generate_classic();
        let peer_id = kp.peer_id();
        let entry = CachedPubkey {
            signing_algo: SigningAlgo::Ed25519,
            signing_pk: kp.signing.signing_pubkey_bytes(),
            kem_algo: KemAlgo::X25519,
            kem_pk: kp.kem.kem_pubkey_bytes(),
        };
        (peer_id, entry)
    }

    #[test]
    fn insert_and_get() {
        let mut cache = PubkeyCache::new(100);
        let (pid, entry) = make_ed25519_entry();
        assert!(cache.insert(pid, entry.clone()));
        assert!(cache.contains(&pid));
        let cached = cache.get(&pid).unwrap();
        assert_eq!(cached.signing_pk, entry.signing_pk);
    }

    #[test]
    fn rejects_wrong_peer_id() {
        let mut cache = PubkeyCache::new(100);
        let (_, entry) = make_ed25519_entry();
        let wrong_pid = PeerId([0xFF; 32]);
        assert!(!cache.insert(wrong_pid, entry));
        assert!(!cache.contains(&wrong_pid));
    }

    #[test]
    fn lru_eviction() {
        let mut cache = PubkeyCache::new(2);
        let (pid1, e1) = make_ed25519_entry();
        let (pid2, e2) = make_ed25519_entry();
        let (pid3, e3) = make_ed25519_entry();

        cache.insert(pid1, e1);
        cache.insert(pid2, e2);
        assert_eq!(cache.len(), 2);

        cache.insert(pid3, e3);
        assert_eq!(cache.len(), 2);
        // pid1 should have been evicted
        assert!(!cache.contains(&pid1));
        assert!(cache.contains(&pid2));
        assert!(cache.contains(&pid3));
    }
}
