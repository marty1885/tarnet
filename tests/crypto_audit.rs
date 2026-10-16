//! Crypto regression tests and documented protocol tradeoffs.
use std::time::{Duration, Instant};
use tarnet::api::types::{KemAlgo, SigningAlgo};
use tarnet::dht::{DhtStore, VerifiedRecord};
use tarnet::identity::{peer_id_from_signing_pubkey, verify_with_pubkey, KemKeypair, Keypair};

#[test]
fn audit_low_order_x25519_is_rejected() {
    let key = KemKeypair::generate_ephemeral(KemAlgo::X25519);
    for first_byte in [0, 1] {
        let mut low_order = [0; 32];
        low_order[0] = first_byte;
        assert!(KemKeypair::encapsulate_to(&low_order, KemAlgo::X25519).is_err());
        assert!(key.decapsulate(&low_order).is_err());
    }
}

#[test]
fn audit_hybrid_kem_rejects_low_order_classical_component() {
    let key = KemKeypair::generate_ephemeral(KemAlgo::MlkemX25519);
    let mut public = key.kem_pubkey_bytes();
    let (_, mut ciphertext) = KemKeypair::encapsulate_to(&public, KemAlgo::MlkemX25519).unwrap();
    for first_byte in [0, 1] {
        public[..32].fill(0);
        public[0] = first_byte;
        ciphertext[..32].fill(0);
        ciphertext[0] = first_byte;
        assert!(KemKeypair::encapsulate_to(&public, KemAlgo::MlkemX25519).is_err());
        assert!(key.decapsulate(&ciphertext).is_err());
    }
}

#[test]
fn audit_kem_rejects_truncated_and_extended_inputs() {
    for algo in [KemAlgo::X25519, KemAlgo::MlkemX25519] {
        let key = KemKeypair::generate_ephemeral(algo);
        let public = key.kem_pubkey_bytes();
        let (_, ciphertext) = KemKeypair::encapsulate_to(&public, algo).unwrap();
        let mut extended_public = public.clone();
        extended_public.push(0);
        let mut extended_ciphertext = ciphertext.clone();
        extended_ciphertext.push(0);
        for malformed in [&public[..public.len() - 1], &extended_public] {
            assert!(KemKeypair::encapsulate_to(malformed, algo).is_err());
        }
        for malformed in [&ciphertext[..ciphertext.len() - 1], &extended_ciphertext] {
            assert!(key.decapsulate(malformed).is_err());
        }
    }
}

#[test]
fn audit_identity_point_signature_is_rejected() {
    let mut pk = [0; 32];
    pk[0] = 1; // Edwards identity point.
    let mut sig = [0; 64];
    sig[0] = 1; // R = identity, S = 0.
    let peer = peer_id_from_signing_pubkey(&pk);
    for message in [b"first".as_slice(), b"unrelated signed assertion".as_slice()] {
        assert!(!verify_with_pubkey(SigningAlgo::Ed25519, &pk, &peer, message, &sig));
    }
}

#[test]
fn audit_expired_zone_root_can_be_replayed_to_fresh_store() {
    let owner = Keypair::generate_classic();
    let original = VerifiedRecord::new_zone_root(&owner, b"old root", 1, Duration::from_secs(1));
    let mut replay = original.into_inner();
    // The relay replaces the unsigned remaining TTL, after the original expired.
    replay.expires = Instant::now() + Duration::from_secs(24 * 3600);
    let verified = VerifiedRecord::verify_incoming(replay).unwrap();
    let mut fresh_store = DhtStore::new(&Keypair::generate_classic().peer_id());
    assert!(fresh_store.put(verified));
}

#[test]
fn audit_content_dictionary_guess_recovers_handle() {
    let (record, secret_handle) = VerifiedRecord::new_content(b"yes", Duration::from_secs(60));
    // A storage node has the blob and lookup key, but no handle.
    let observed = record.record();
    let (guess, guessed_handle) = VerifiedRecord::new_content(b"yes", Duration::from_secs(60));
    assert_eq!(observed.value, guess.record().value);
    assert_eq!(secret_handle, guessed_handle);
}

#[test]
fn audit_storage_node_can_decrypt_hello_wrapper() {
    let owner = Keypair::generate_classic();
    let record = VerifiedRecord::new_hello(&owner, b"transport addresses", 1, Duration::from_secs(60));
    let stored = record.record();
    assert_eq!(
        tarnet::dht::signed_record_decrypt(&stored.key, &stored.value).unwrap(),
        b"transport addresses"
    );
}

#[test]
fn audit_hybrid_signature_rejects_weak_ed25519_even_with_valid_falcon() {
    let owner = Keypair::generate();
    let message = b"valid Falcon is insufficient";
    let mut public = owner.identity.signing.signing_pubkey_bytes();
    let mut signature = owner.sign(message);
    public[..32].fill(0);
    public[0] = 1;
    signature[..64].fill(0);
    signature[0] = 1;
    let peer = peer_id_from_signing_pubkey(&public);
    assert!(!verify_with_pubkey(SigningAlgo::FalconEd25519, &public, &peer, message, &signature));
}
