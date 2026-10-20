//! Identity v2 key bundles (see `docs/spec/identity.md`).
//!
//! An identity commits to the leaves of several public keys; a bundle
//! reveals some of them and gives only the leaf of the rest. SIDs and PeerIds
//! hash the leaves, so which keys are revealed (and which algorithms must
//! sign) is a verification policy, not part of the identity.
//!
//! This module is pure parsing and hashing. It lives here so that
//! [`crate::types::ServiceId`] can be derived without the crypto crate.

use crate::types::{PeerId, ServiceId, SigningAlgo};

/// Bundle format version.
pub const VERSION: u8 = 2;

/// Algorithm ids. Never reused.
pub mod algo {
    pub const ED25519: u8 = 0x01;
    /// Falcon-512, round-3 key encoding and signing.
    pub const FALCON512: u8 = 0x02;
    pub const MLDSA44: u8 = 0x03;
    pub const SLHDSA_SHA2_128S: u8 = 0x04;
}

/// Public key length per algorithm.
pub fn key_len(algo: u8) -> Option<usize> {
    match algo {
        algo::ED25519 => Some(32),
        algo::FALCON512 => Some(897),
        algo::MLDSA44 => Some(1312),
        algo::SLHDSA_SHA2_128S => Some(32),
        _ => None,
    }
}

const FORM_KEY: u8 = 0;
const FORM_LEAF: u8 = 1;

/// The leaf an identity commits to for one key.
pub fn leaf(algo: u8, pk: &[u8]) -> [u8; 32] {
    blake3::Hasher::new_derive_key("tarnet key leaf v2")
        .update(&[algo])
        .update(pk)
        .finalize()
        .into()
}

/// One slot of a parsed bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot<'a> {
    pub algo: u8,
    /// The public key, when the bundle reveals it.
    pub key: Option<&'a [u8]>,
    pub leaf: [u8; 32],
}

/// A bundle that parsed canonically under the current policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle<'a> {
    pub class: SigningAlgo,
    pub slots: Vec<Slot<'a>>,
}

/// The committed sets policy 1 accepts, and which slots it requires revealed.
/// Hybrid: commits to {Ed25519, Falcon-512, ML-DSA-44, SLH-DSA}, reveals
/// Ed25519 and Falcon-512. ECC (throwaways only): commits to and reveals
/// Ed25519.
const POLICY_HYBRID: [(u8, bool); 4] = [
    (algo::ED25519, true),
    (algo::FALCON512, true),
    (algo::MLDSA44, false),
    (algo::SLHDSA_SHA2_128S, false),
];
const POLICY_ECC: [(u8, bool); 1] = [(algo::ED25519, true)];

/// The slots (algorithm, revealed) a class's canonical bundle has.
pub fn policy_slots(class: SigningAlgo) -> &'static [(u8, bool)] {
    match class {
        SigningAlgo::FalconEd25519 => &POLICY_HYBRID,
        SigningAlgo::Ed25519 => &POLICY_ECC,
    }
}

impl<'a> Bundle<'a> {
    /// Parse a bundle. Only the canonical encoding of a policy-1 class is
    /// accepted: one identity has exactly one bundle encoding, so byte
    /// comparisons of keys stay meaningful.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let (&version, rest) = bytes.split_first()?;
        if version != VERSION {
            return None;
        }
        let (&count, mut rest) = rest.split_first()?;
        let class = match count {
            4 => SigningAlgo::FalconEd25519,
            1 => SigningAlgo::Ed25519,
            _ => return None,
        };
        let mut slots = Vec::with_capacity(count as usize);
        for &(want_algo, revealed) in policy_slots(class) {
            if rest.len() < 4 {
                return None;
            }
            let (algo, form) = (rest[0], rest[1]);
            let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            rest = &rest[4..];
            if algo != want_algo || rest.len() < len {
                return None;
            }
            let (data, tail) = rest.split_at(len);
            rest = tail;
            let slot = match (form, revealed) {
                (FORM_KEY, true) if Some(len) == key_len(algo) => Slot {
                    algo,
                    key: Some(data),
                    leaf: leaf(algo, data),
                },
                (FORM_LEAF, false) if len == 32 => Slot {
                    algo,
                    key: None,
                    leaf: data.try_into().unwrap(),
                },
                _ => return None,
            };
            slots.push(slot);
        }
        if !rest.is_empty() {
            return None;
        }
        Some(Self { class, slots })
    }

    /// The revealed key for `algo`, if any.
    pub fn key(&self, algo: u8) -> Option<&'a [u8]> {
        self.slots.iter().find(|s| s.algo == algo).and_then(|s| s.key)
    }

    /// The Ed25519 public key (every class reveals it).
    pub fn ed25519(&self) -> [u8; 32] {
        self.key(algo::ED25519)
            .expect("every policy-1 class reveals Ed25519")
            .try_into()
            .unwrap()
    }

    fn id(&self, domain: &str) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(domain);
        h.update(&[VERSION, self.slots.len() as u8]);
        for slot in &self.slots {
            h.update(&slot.leaf);
        }
        h.finalize().into()
    }

    pub fn service_id(&self) -> ServiceId {
        ServiceId(self.id("tarnet sid v2"))
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId(self.id("tarnet peer-id v2"))
    }
}

/// Encode a canonical bundle. `slots` must follow [`policy_slots`] for
/// `class`: the public key for revealed slots, the leaf for the others.
pub fn encode(class: SigningAlgo, slots: &[&[u8]]) -> Vec<u8> {
    let policy = policy_slots(class);
    assert_eq!(policy.len(), slots.len(), "bundle slots don't match the policy");
    let mut out = vec![VERSION, policy.len() as u8];
    for (&(algo, revealed), data) in policy.iter().zip(slots) {
        if revealed {
            assert_eq!(Some(data.len()), key_len(algo), "wrong key length in bundle");
        } else {
            assert_eq!(data.len(), 32, "a hidden slot carries its leaf");
        }
        out.push(algo);
        out.push(if revealed { FORM_KEY } else { FORM_LEAF });
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// A policy-1 signature: `count || (algo || len(u16) || sig)*`, one entry per
/// algorithm the class must sign with, in the bundle's slot order.
pub fn encode_signature(parts: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = vec![parts.len() as u8];
    for (algo, sig) in parts {
        out.push(*algo);
        out.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        out.extend_from_slice(sig);
    }
    out
}

/// Split a policy-1 signature for `class` into its parts, in order. `None`
/// unless it carries exactly the algorithms the class requires.
pub fn parse_signature(class: SigningAlgo, sig: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let required: Vec<u8> = policy_slots(class)
        .iter()
        .filter(|(_, revealed)| *revealed)
        .map(|(a, _)| *a)
        .collect();
    let (&count, mut rest) = sig.split_first()?;
    if count as usize != required.len() {
        return None;
    }
    let mut parts = Vec::with_capacity(required.len());
    for want in required {
        if rest.len() < 3 || rest[0] != want {
            return None;
        }
        let len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
        rest = &rest[3..];
        if rest.len() < len {
            return None;
        }
        let (data, tail) = rest.split_at(len);
        parts.push((want, data));
        rest = tail;
    }
    rest.is_empty().then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hybrid() -> Vec<u8> {
        let ed = [1u8; 32];
        let falcon = [2u8; 897];
        encode(
            SigningAlgo::FalconEd25519,
            &[&ed, &falcon, &leaf(algo::MLDSA44, &[3; 1312]), &leaf(algo::SLHDSA_SHA2_128S, &[4; 32])],
        )
    }

    #[test]
    fn roundtrip_and_ids() {
        let bytes = hybrid();
        let b = Bundle::parse(&bytes).unwrap();
        assert_eq!(b.class, SigningAlgo::FalconEd25519);
        assert_eq!(b.ed25519(), [1u8; 32]);
        assert_ne!(b.service_id().0, b.peer_id().0);
        assert_eq!(ServiceId::from_signing_pubkey(&bytes), b.service_id());
    }

    #[test]
    fn ecc_never_collides_with_hybrid() {
        let ed = [1u8; 32];
        let ecc = encode(SigningAlgo::Ed25519, &[&ed]);
        let e = Bundle::parse(&ecc).unwrap();
        let h_bytes = hybrid();
        let h = Bundle::parse(&h_bytes).unwrap();
        assert_eq!(e.class, SigningAlgo::Ed25519);
        assert_ne!(e.service_id(), h.service_id());
    }

    #[test]
    fn noncanonical_rejected() {
        let bytes = hybrid();
        // Trailing byte.
        let mut b = bytes.clone();
        b.push(0);
        assert!(Bundle::parse(&b).is_none());
        // Wrong version.
        let mut b = bytes.clone();
        b[0] = 1;
        assert!(Bundle::parse(&b).is_none());
        // Falcon given as a leaf instead of revealed.
        let ed = [1u8; 32];
        let l = [9u8; 32];
        let mut b = vec![VERSION, 4];
        for (algo, form, data) in [
            (algo::ED25519, FORM_KEY, &ed[..]),
            (algo::FALCON512, FORM_LEAF, &l[..]),
            (algo::MLDSA44, FORM_LEAF, &l[..]),
            (algo::SLHDSA_SHA2_128S, FORM_LEAF, &l[..]),
        ] {
            b.push(algo);
            b.push(form);
            b.extend_from_slice(&(data.len() as u16).to_be_bytes());
            b.extend_from_slice(data);
        }
        assert!(Bundle::parse(&b).is_none());
        // Truncated.
        assert!(Bundle::parse(&bytes[..bytes.len() - 1]).is_none());
        assert!(Bundle::parse(&[]).is_none());
    }

    #[test]
    fn invalid_bytes_get_an_unmatchable_sid() {
        let junk = [7u8; 32];
        let sid = ServiceId::from_signing_pubkey(&junk);
        assert_ne!(sid, ServiceId::from_signing_pubkey(&hybrid()));
    }

    #[test]
    fn signature_parts() {
        let sig = encode_signature(&[(algo::ED25519, &[1; 64]), (algo::FALCON512, &[2; 650])]);
        let parts = parse_signature(SigningAlgo::FalconEd25519, &sig).unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parse_signature(SigningAlgo::Ed25519, &sig).is_none());
        let ecc = encode_signature(&[(algo::ED25519, &[1; 64])]);
        assert!(parse_signature(SigningAlgo::Ed25519, &ecc).is_some());
        assert!(parse_signature(SigningAlgo::FalconEd25519, &ecc).is_none());
        let mut long = sig.clone();
        long.push(0);
        assert!(parse_signature(SigningAlgo::FalconEd25519, &long).is_none());
    }
}
