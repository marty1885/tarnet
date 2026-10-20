//! Opaque, independently addressed label candidates. The ECC envelope is an
//! admission filter; the encrypted identity signature authenticates the data.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    dht::{DhtRecord, VerifiedRecord},
    identity::Keypair,
    types::{DhtId, Error, PeerId, RecordType, Result},
};
use tarnet_api::types::{ServiceId, SigningAlgo};

pub const LANES: u8 = 4;
pub const TTL: u32 = 600;
pub const MAX_VALUE_BYTES: usize = 60 * 1024;
pub const KEY_MARKER: &[u8] = b"tarnet tns public key v2";
const VERSION: u8 = 2;
const WORK_HEADER: usize = 1 + 8;
const MIN_BLOB: usize = 24 + 16;
const WORK_BASE_BITS: u32 = 14;
const INNER_DOMAIN: &[u8] = b"tarnet tns label records v2\0";

fn name_input(pk: &[u8], label: &str, lane: u8) -> Result<Vec<u8>> {
    if lane >= LANES || label.is_empty() || label.len() > u16::MAX as usize {
        return Err(Error::Protocol("invalid TNS label or lane".into()));
    }
    if crate::identity::signing_algo_of(pk).is_none() {
        return Err(Error::Crypto("invalid TNS identity public key".into()));
    }
    let mut input = Vec::new();
    input.extend_from_slice(&(pk.len() as u16).to_be_bytes());
    input.extend_from_slice(pk);
    input.extend_from_slice(&(label.len() as u16).to_be_bytes());
    input.extend_from_slice(label.as_bytes());
    input.push(lane);
    Ok(input)
}

fn factor(pk: &[u8], label: &str, lane: u8) -> Result<Scalar> {
    let input = name_input(pk, label, lane)?;
    let mut wide = [0; 64];
    blake3::Hasher::new_derive_key("tarnet tns blinding factor v2")
        .update(&input)
        .finalize_xof()
        .fill(&mut wide);
    let h = Scalar::from_bytes_mod_order_wide(&wide);
    if h == Scalar::ZERO {
        return Err(Error::Crypto("zero TNS blinding factor".into()));
    }
    Ok(h)
}

pub fn location(blinded_pk: &[u8; 32]) -> DhtId {
    let mut q = [0; 64];
    blake3::Hasher::new_derive_key("tarnet tns label location v2")
        .update(blinded_pk)
        .finalize_xof()
        .fill(&mut q);
    DhtId(q)
}

pub fn label_key(pk: &[u8], label: &str, lane: u8) -> Result<([u8; 32], DhtId)> {
    let ed = crate::identity::bundle_ed25519(pk)
        .ok_or_else(|| Error::Crypto("invalid TNS identity key bundle".into()))?;
    let point = CompressedEdwardsY(ed)
    .decompress()
    .ok_or_else(|| Error::Crypto("invalid TNS Ed25519 point".into()))?;
    if !point.is_torsion_free() || point.is_small_order() {
        return Err(Error::Crypto("invalid TNS Ed25519 subgroup".into()));
    }
    let blinded = (factor(pk, label, lane)? * point).compress().to_bytes();
    Ok((blinded, location(&blinded)))
}

/// EDKEY-style signing with a derived scalar. The nonce construction follows
/// RFC 9498 section 5.1.2: hash the private expansion prefix with the factor,
/// then hash that derived prefix with the message. Our factor is additionally
/// domain-separated and binds the full hybrid key and lane.
fn sign_blinded(
    owner: &Keypair,
    label: &str,
    lane: u8,
    message: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    let pk = owner.identity.signing.signing_pubkey_bytes();
    let h = factor(&pk, label, lane)?;
    let seed = Zeroizing::new(owner.identity.signing.ed25519_seed());
    let mut expanded = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(&*seed)));
    let mut a_bytes = Zeroizing::new(<[u8; 32]>::try_from(&expanded[..32]).unwrap());
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let mut a = Scalar::from_bytes_mod_order(*a_bytes);
    let mut derived = h * a;
    let public = (&derived * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let mut nonce_hash = Sha256::new();
    nonce_hash.update(&expanded[32..]);
    nonce_hash.update(h.as_bytes());
    let nonce_prefix = Zeroizing::new(<[u8; 32]>::from(nonce_hash.finalize()));
    let mut r_hash = Sha512::new();
    r_hash.update(&*nonce_prefix);
    r_hash.update(message);
    let mut r_wide = Zeroizing::new(<[u8; 64]>::from(r_hash.finalize()));
    let mut r = Scalar::from_bytes_mod_order_wide(&r_wide);
    let r_point = (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let mut challenge = Sha512::new();
    challenge.update(r_point);
    challenge.update(public);
    challenge.update(message);
    let k = Scalar::from_bytes_mod_order_wide(&challenge.finalize().into());
    let mut s = r + k * derived;
    let mut signature = r_point.to_vec();
    signature.extend_from_slice(s.as_bytes());
    a.zeroize();
    derived.zeroize();
    r.zeroize();
    s.zeroize();
    expanded.zeroize();
    r_wide.zeroize();
    Ok((public, signature))
}

fn encryption_key(sid: &ServiceId, label: &str, lane: u8) -> [u8; 32] {
    let mut input = sid.as_bytes().to_vec();
    input.extend_from_slice(&(label.len() as u16).to_be_bytes());
    input.extend_from_slice(label.as_bytes());
    input.push(lane);
    blake3::derive_key("tarnet tns label encryption v2", &input)
}

fn inner_message(sid: &ServiceId, label: &str, lane: u8, sequence: u64, set: &[u8]) -> Vec<u8> {
    let mut m = INNER_DOMAIN.to_vec();
    m.extend_from_slice(sid.as_bytes());
    m.extend_from_slice(&(label.len() as u16).to_be_bytes());
    m.extend_from_slice(label.as_bytes());
    m.push(lane);
    m.extend_from_slice(&sequence.to_be_bytes());
    m.extend_from_slice(&(set.len() as u32).to_be_bytes());
    m.extend_from_slice(set);
    m
}

fn blob(value: &[u8]) -> Option<&[u8]> {
    (value.len() >= WORK_HEADER + MIN_BLOB && value[0] == VERSION).then(|| &value[WORK_HEADER..])
}

pub fn candidate_id(q: &DhtId, value: &[u8]) -> Option<PeerId> {
    let mut h = blake3::Hasher::new_derive_key("tarnet tns candidate identity v2");
    h.update(q.as_bytes()).update(blob(value)?);
    Some(PeerId(*h.finalize().as_bytes()))
}

fn work_bits(blob_len: usize) -> u32 {
    let units = blob_len.div_ceil(4096).max(1);
    WORK_BASE_BITS + (usize::BITS - (units - 1).leading_zeros())
}

fn work_prefix(q: &DhtId, encrypted: &[u8]) -> blake3::Hasher {
    let mut h = blake3::Hasher::new_derive_key("tarnet tns candidate work v2");
    h.update(q.as_bytes())
        .update(blake3::hash(encrypted).as_bytes());
    h
}

fn valid_work(prefix: &blake3::Hasher, nonce: u64, bits: u32) -> bool {
    let hash = prefix.clone().update(&nonce.to_be_bytes()).finalize();
    u64::from_be_bytes(hash.as_bytes()[..8].try_into().unwrap()).leading_zeros() >= bits
}

pub fn verify_envelope(record: &DhtRecord) -> std::result::Result<(), &'static str> {
    if record.record_type != RecordType::TnsLabel
        || record.sequence != 0
        || record.signer_algo != SigningAlgo::Ed25519 as u8
        || record.signer_pubkey.len() != 32
        || record.value.len() > MAX_VALUE_BYTES
    {
        return Err("noncanonical TNS candidate metadata");
    }
    let public: [u8; 32] = record.signer_pubkey.as_slice().try_into().unwrap();
    if location(&public) != record.key {
        return Err("TNS candidate not at its blinded key");
    }
    if candidate_id(&record.key, &record.value) != Some(record.signer) {
        return Err("invalid TNS candidate identity");
    }
    let encrypted = blob(&record.value).ok_or("invalid TNS candidate envelope")?;
    let nonce = u64::from_be_bytes(record.value[1..9].try_into().unwrap());
    if !valid_work(
        &work_prefix(&record.key, encrypted),
        nonce,
        work_bits(encrypted.len()),
    ) {
        return Err("insufficient TNS candidate work");
    }
    let vk = VerifyingKey::from_bytes(&public).map_err(|_| "invalid TNS blinded key")?;
    let sig =
        Signature::from_slice(&record.signature).map_err(|_| "invalid TNS envelope signature")?;
    vk.verify_strict(
        &crate::dht::record_signable(record.key.as_bytes(), record.record_type, 0, &record.value),
        &sig,
    )
    .map_err(|_| "invalid TNS envelope signature")
}

pub fn build(
    owner: &Keypair,
    label: &str,
    lane: u8,
    sequence: u64,
    set: &[u8],
) -> Result<VerifiedRecord> {
    let sid = owner.identity.service_id();
    let pk = owner.identity.signing.signing_pubkey_bytes();
    name_input(&pk, label, lane)?;
    let sig = owner
        .identity
        .sign(&inner_message(&sid, label, lane, sequence, set));
    let mut plaintext = vec![VERSION, owner.identity.signing_algo() as u8];
    plaintext.extend_from_slice(&(pk.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(&pk);
    plaintext.extend_from_slice(&sequence.to_be_bytes());
    plaintext.extend_from_slice(&(set.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(set);
    plaintext.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(&sig);
    seal_candidate(owner, label, lane, &plaintext)
}

fn seal_candidate(
    owner: &Keypair,
    label: &str,
    lane: u8,
    plaintext: &[u8],
) -> Result<VerifiedRecord> {
    let sid = owner.identity.service_id();
    let pk = owner.identity.signing.signing_pubkey_bytes();
    let (public, q) = label_key(&pk, label, lane)?;
    let mut nonce = [0; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&encryption_key(&sid, label, lane)).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: q.as_bytes(),
            },
        )
        .map_err(|_| Error::Crypto("TNS encryption failed".into()))?;
    let mut encrypted = nonce.to_vec();
    encrypted.extend_from_slice(&ct);
    if encrypted.len() + WORK_HEADER > MAX_VALUE_BYTES {
        return Err(Error::Protocol(
            "TNS record set exceeds the publication limit".into(),
        ));
    }
    let prefix = work_prefix(&q, &encrypted);
    let mut work = 0u64;
    while !valid_work(&prefix, work, work_bits(encrypted.len())) {
        work = work
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("TNS work exhausted".into()))?;
    }
    let mut value = vec![VERSION];
    value.extend_from_slice(&work.to_be_bytes());
    value.extend_from_slice(&encrypted);
    let message = crate::dht::record_signable(q.as_bytes(), RecordType::TnsLabel, 0, &value);
    let (signed_public, signature) = sign_blinded(owner, label, lane, &message)?;
    debug_assert_eq!(public, signed_public);
    let record = DhtRecord {
        key: q,
        record_type: RecordType::TnsLabel,
        sequence: 0,
        signer: candidate_id(&q, &value).unwrap(),
        signer_algo: SigningAlgo::Ed25519 as u8,
        signer_pubkey: public.to_vec(),
        value,
        expires: crate::dht::expires_in(std::time::Duration::from_secs(TTL as u64)),
        stored_at: std::time::Instant::now(),
        signature,
    };
    VerifiedRecord::verify_incoming(record).map_err(|e| Error::Crypto(e.into()))
}

pub fn open(
    sid: &ServiceId,
    pk: &[u8],
    label: &str,
    lane: u8,
    record: &DhtRecord,
) -> Option<(Vec<super::TnsRecord>, u64)> {
    if ServiceId::from_signing_pubkey(pk) != *sid {
        return None;
    }
    let (public, q) = label_key(pk, label, lane).ok()?;
    if record.key != q || record.signer_pubkey != public || verify_envelope(record).is_err() {
        return None;
    }
    let encrypted = blob(&record.value)?;
    let pt = XChaCha20Poly1305::new((&encryption_key(sid, label, lane)).into())
        .decrypt(
            encrypted[..24].into(),
            Payload {
                msg: &encrypted[24..],
                aad: q.as_bytes(),
            },
        )
        .ok()?;
    let mut r = crate::codec::Reader::new(&pt);
    if r.read_u8().ok()? != VERSION {
        return None;
    }
    let algo = r.read_u8().ok()?;
    let key_len = r.read_u16().ok()? as usize;
    let inner_pk = r.read_bytes(key_len).ok()?;
    if inner_pk.as_slice() != pk {
        return None;
    }
    let sequence = r.read_u64().ok()?;
    let set_len = r.read_u32().ok()? as usize;
    // Bound before Reader's pos+n arithmetic, including on 32-bit clients.
    if set_len > r.remaining() {
        return None;
    }
    let set = r.read_bytes(set_len).ok()?;
    let sig_len = r.read_u16().ok()? as usize;
    let signature = r.read_bytes(sig_len).ok()?;
    if r.remaining() != 0
        || !crate::identity::verify_signed(
            crate::identity::SignedBy::Service(sid),
            Some(algo),
            &inner_pk,
            &inner_message(sid, label, lane, sequence, &set),
            &signature,
        )
    {
        return None;
    }
    Some((super::deserialize_record_set(&set).ok()?, sequence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dht::{DhtStore, RecordSource},
        identity::SigningKeypair,
        state::StorageLimits,
    };

    fn record(owner: &Keypair, sequence: u64) -> VerifiedRecord {
        build(
            owner,
            "ssh",
            0,
            sequence,
            &super::super::serialize_record_set(&[super::super::TnsRecord::Text(
                "secret endpoint".into(),
            )]),
        )
        .unwrap()
    }

    #[test]
    fn both_identity_schemes_roundtrip_without_exposing_zone_key() {
        for owner in [Keypair::generate_ed25519(), Keypair::generate()] {
            let pk = owner.identity.signing.signing_pubkey_bytes();
            let sid = owner.identity.service_id();
            let publication = record(&owner, 17);
            let rec = publication.record();
            assert_eq!(verify_envelope(rec), Ok(()));
            assert_eq!(rec.sequence, 0);
            assert_ne!(rec.signer_pubkey, owner.identity.signing.ed25519_pubkey());
            assert_ne!(rec.signer, owner.peer_id());
            assert!(!rec.value.windows(pk.len()).any(|window| window == pk));
            let (got, sequence) = open(&sid, &pk, "ssh", 0, rec).unwrap();
            assert_eq!(
                got,
                vec![super::super::TnsRecord::Text("secret endpoint".into())]
            );
            assert_eq!(sequence, 17);
            assert!(open(&sid, &pk, "www", 0, rec).is_none());
            assert!(open(&sid, &pk, "ssh", 1, rec).is_none());
            assert!(open(&ServiceId([3; 32]), &pk, "ssh", 0, rec).is_none());
        }
    }

    #[test]
    fn independent_labels_lanes_and_complete_hybrid_identity() {
        let owner = Keypair::generate();
        let pk = owner.identity.signing.signing_pubkey_bytes();
        let keys: std::collections::HashSet<_> = (0..LANES)
            .flat_map(|lane| ["ssh", "www"].map(|label| label_key(&pk, label, lane).unwrap().1))
            .collect();
        assert_eq!(keys.len(), LANES as usize * 2);
        let mut other_pk = pk.clone();
        other_pk[100] ^= 1; // Same Ed25519 component, different full hybrid key.
        assert_ne!(
            label_key(&pk, "ssh", 0).unwrap(),
            label_key(&other_pk, "ssh", 0).unwrap()
        );
        assert!(label_key(&pk, "", 0).is_err());
        assert!(label_key(&pk, "ssh", LANES).is_err());
    }

    #[test]
    fn nonce_derivation_separates_messages_and_blinding_contexts() {
        let owner = Keypair::generate();
        let (pk, one) = sign_blinded(&owner, "ssh", 0, b"one").unwrap();
        let (_, again) = sign_blinded(&owner, "ssh", 0, b"one").unwrap();
        let (_, two) = sign_blinded(&owner, "ssh", 0, b"two").unwrap();
        let (_, other_lane) = sign_blinded(&owner, "ssh", 1, b"one").unwrap();
        assert_eq!(one, again);
        assert_ne!(&one[..32], &two[..32]);
        assert_ne!(&one[..32], &other_lane[..32]);
        assert_eq!(
            label_key(&owner.identity.signing.signing_pubkey_bytes(), "ssh", 0)
                .unwrap()
                .0,
            pk
        );
        VerifyingKey::from_bytes(&pk)
            .unwrap()
            .verify_strict(b"one", &Signature::from_slice(&one).unwrap())
            .unwrap();
    }

    #[test]
    fn admission_rejects_foreign_keys_versions_and_retargeting() {
        let owner = Keypair::generate();
        let valid = record(&owner, 1).into_inner();
        let mut bad = valid.clone();
        bad.sequence = u64::MAX;
        assert!(VerifiedRecord::verify_incoming(bad).is_err());
        let mut bad = valid.clone();
        bad.key = DhtId([7; 64]);
        assert!(VerifiedRecord::verify_incoming(bad).is_err());
        let mut bad = valid.clone();
        let attacker = SigningKeypair::generate(SigningAlgo::Ed25519);
        bad.signer_pubkey = attacker.signing_pubkey_bytes();
        bad.signature = attacker.sign(&crate::dht::record_signable(
            bad.key.as_bytes(),
            bad.record_type,
            0,
            &bad.value,
        ));
        assert!(VerifiedRecord::verify_incoming(bad).is_err());
        let mut bad = valid;
        bad.value[WORK_HEADER + 25] ^= 1;
        assert!(VerifiedRecord::verify_incoming(bad).is_err());
    }

    #[test]
    fn valid_ecc_envelope_does_not_authenticate_bad_falcon_or_huge_inner_sequence() {
        let owner = Keypair::generate();
        let pk = owner.identity.signing.signing_pubkey_bytes();
        let sid = owner.identity.service_id();
        let valid = record(&owner, 7).into_inner();
        let encrypted = blob(&valid.value).unwrap();
        let pt = XChaCha20Poly1305::new((&encryption_key(&sid, "ssh", 0)).into())
            .decrypt(
                encrypted[..24].into(),
                Payload {
                    msg: &encrypted[24..],
                    aad: valid.key.as_bytes(),
                },
            )
            .unwrap();
        for change in ["falcon", "sequence", "set_length"] {
            let mut tampered = pt.clone();
            if change == "falcon" {
                let end = tampered.len() - 1;
                tampered[end] ^= 1;
            } else if change == "sequence" {
                tampered[4 + pk.len()..4 + pk.len() + 8].copy_from_slice(&u64::MAX.to_be_bytes());
            } else {
                tampered[4 + pk.len() + 8..4 + pk.len() + 12]
                    .copy_from_slice(&u32::MAX.to_be_bytes());
            }
            // Simulate possession of the blinded ECC signing scalar: the
            // envelope and work pass, but reader authentication must fail.
            let candidate = seal_candidate(&owner, "ssh", 0, &tampered).unwrap();
            assert!(verify_envelope(candidate.record()).is_ok());
            assert!(open(&sid, &pk, "ssh", 0, candidate.record()).is_none());
        }
    }

    #[test]
    fn candidate_history_deduplication_and_local_replacement_are_bounded() {
        let owner = Keypair::generate_ed25519();
        let first = record(&owner, 1);
        let second = record(&owner, 2);
        let q = first.record().key;
        assert_ne!(first.record().signer, second.record().signer);
        let mut limits = StorageLimits::default();
        limits.max_records_per_key = 3;
        let mut store = DhtStore::with_limits(&owner.peer_id(), limits);
        let source = RecordSource::Peer(PeerId([2; 32]));
        assert!(store.put_from(first.clone(), source));
        let deadline = store.get(&q)[0].expires;
        assert!(store.put_from(first.clone(), source));
        assert_eq!(store.get(&q)[0].expires, deadline);
        assert!(store.put_from(second.clone(), source));
        assert_eq!(store.get(&q).len(), 2);
        for sequence in 3..9 {
            store.put_from(record(&owner, sequence), source);
        }
        assert_eq!(store.get(&q).len(), 3);
        assert!(store
            .get(&q)
            .iter()
            .any(|r| r.signer == first.record().signer));
        let mut local = DhtStore::with_limits(&owner.peer_id(), limits);
        assert!(local.put(first));
        assert!(local.put(second));
        assert_eq!(local.get(&q).len(), 1);
    }

    #[test]
    fn generic_signed_junk_cannot_crowd_out_opaque_candidates() {
        let owner = Keypair::generate_ed25519();
        let genuine = record(&owner, 1);
        let q = genuine.record().key;
        let mut limits = StorageLimits::default();
        limits.max_records_per_key = 2;
        let mut store = DhtStore::with_limits(&owner.peer_id(), limits);
        assert!(store.put_from(genuine.clone(), RecordSource::Peer(PeerId([1; 32]))));
        for _ in 0..8 {
            let attacker = Keypair::generate_ed25519();
            let junk = VerifiedRecord::new_signed_at_key(
                &attacker,
                q,
                b"junk",
                u64::MAX,
                std::time::Duration::from_secs(TTL as u64),
            );
            store.put_from(junk, RecordSource::Peer(PeerId([2; 32])));
        }
        assert!(store
            .get(&q)
            .iter()
            .any(|r| r.signer == genuine.record().signer));
        assert!(store.get(&q).len() <= 2);
    }

    #[test]
    fn work_is_size_weighted_and_bound_to_location_and_blob() {
        assert!(work_bits(8192) > work_bits(4096));
        let candidate = record(&Keypair::generate_ed25519(), 1).into_inner();
        let id = candidate_id(&candidate.key, &candidate.value).unwrap();
        let mut value = candidate.value.clone();
        value[1] ^= 1; // Work changes cannot create another immutable candidate.
        assert_eq!(candidate_id(&candidate.key, &value), Some(id));
        assert_ne!(candidate_id(&DhtId([4; 64]), &value), Some(id));
        value[WORK_HEADER + 1] ^= 1;
        assert_ne!(candidate_id(&candidate.key, &value), Some(id));
    }
}
