//! Audit reproductions: these assert the observed vulnerable behavior.
use std::time::{Duration, Instant};
use tarnet::api::types::{KemAlgo, SigningAlgo};
use tarnet::dht::{DhtStore, VerifiedRecord};
use tarnet::identity::{peer_id_from_signing_pubkey, verify_with_pubkey, KemKeypair, Keypair};

#[test]
fn audit_low_order_x25519_produces_known_secret() {
    let (secret, _) = KemKeypair::encapsulate_to(&[0; 32], KemAlgo::X25519).unwrap();
    assert_eq!(secret, [0; 32]);
    let key = KemKeypair::generate_ephemeral(KemAlgo::X25519);
    assert_eq!(key.decapsulate(&[0; 32]).unwrap(), [0; 32]);
}

#[test]
fn audit_identity_point_signature_needs_no_private_key() {
    let mut pk = [0; 32];
    pk[0] = 1; // Edwards identity point.
    let mut sig = [0; 64];
    sig[0] = 1; // R = identity, S = 0.
    let peer = peer_id_from_signing_pubkey(&pk);
    for message in [b"first".as_slice(), b"unrelated signed assertion".as_slice()] {
        assert!(verify_with_pubkey(SigningAlgo::Ed25519, &pk, &peer, message, &sig));
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
