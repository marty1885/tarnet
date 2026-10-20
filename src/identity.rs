//! Identity v2 (see `docs/spec/identity.md`).
//!
//! An identity is a 32-byte master seed. Every key comes from it under its
//! own label, except Falcon-512, whose key generation no standard fixes, so
//! its key pair is stored. A SID or PeerId hashes the leaves of all the keys
//! the identity commits to ([`tarnet_api::bundle`]): Ed25519 and Falcon-512
//! sign today, ML-DSA-44 and SLH-DSA are committed backups. Retiring an
//! algorithm changes the verification policy, not the identity.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{
    DetachedSignature as SignDetachedTrait, PublicKey as SignPublicKeyTrait,
    SecretKey as SignSecretKeyTrait,
};
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::crypto::Wiping;
use crate::types::{DhtId, PeerId};
use tarnet_api::bundle::{self, algo, Bundle};
use tarnet_api::types::ServiceId;
use tarnet_api::types::{IdentityScheme, KemAlgo, SigningAlgo};

/// Derive a 32-byte key from the master seed under an identity v2 label.
fn seed_key(seed: &[u8; 32], label: &str) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(&format!("tarnet identity v2 {label}"), seed))
}

fn random_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *seed);
    seed
}

/// The ML-DSA-44 public key a master seed commits to (FIPS 204 KeyGen_internal).
fn mldsa44_public(seed: &[u8; 32]) -> Vec<u8> {
    tarnet_pq::mldsa44_public(&seed_key(seed, "ml-dsa-44"))
}

/// The SLH-DSA-SHA2-128s public key a master seed commits to (FIPS 205
/// slh_keygen_internal with SK.seed, SK.prf, PK.seed from the seed).
fn slhdsa_public(seed: &[u8; 32]) -> Vec<u8> {
    let k = seed_key(seed, "slh-dsa");
    let mut seeds = Zeroizing::new([0u8; 48]);
    blake3::Hasher::new_derive_key("tarnet identity v2 slh-dsa seeds")
        .update(&*k)
        .finalize_xof()
        .fill(&mut *seeds);
    tarnet_pq::slhdsa128s_public(
        seeds[..16].try_into().unwrap(),
        seeds[16..32].try_into().unwrap(),
        seeds[32..48].try_into().unwrap(),
    )
}

/// The leaves of the backup keys (ML-DSA-44, SLH-DSA) a seed commits to.
/// Derived once when an identity is created and stored with it: SLH-DSA key
/// generation is slow on small machines.
fn backup_leaves(seed: &[u8; 32]) -> [[u8; 32]; 2] {
    [
        bundle::leaf(algo::MLDSA44, &mldsa44_public(seed)),
        bundle::leaf(algo::SLHDSA_SHA2_128S, &slhdsa_public(seed)),
    ]
}

// ---------------------------------------------------------------------------
// SigningKeypair
// ---------------------------------------------------------------------------

struct Falcon {
    sk: Wiping<falcon512::SecretKey>,
    pk: falcon512::PublicKey,
    /// Leaves of the committed backup keys (ML-DSA-44, SLH-DSA).
    backups: [[u8; 32]; 2],
}

impl Clone for Falcon {
    fn clone(&self) -> Self {
        Self {
            sk: Wiping::new(*self.sk),
            pk: self.pk,
            backups: self.backups,
        }
    }
}

/// The signing half of an identity: the active keys, plus the leaves of the
/// committed backups, and the bundle that reveals them.
#[derive(Clone)]
pub struct SigningKeypair {
    class: SigningAlgo,
    ed_sk: SigningKey,
    falcon: Option<Falcon>,
    bundle: Vec<u8>,
}

impl SigningKeypair {
    fn from_parts(class: SigningAlgo, seed: &[u8; 32], falcon: Option<Falcon>) -> Self {
        let ed_sk = SigningKey::from_bytes(&seed_key(seed, "ed25519"));
        let ed_pk = ed_sk.verifying_key().to_bytes();
        let bundle = match (class, &falcon) {
            (SigningAlgo::Ed25519, None) => bundle::encode(class, &[&ed_pk]),
            (SigningAlgo::FalconEd25519, Some(f)) => {
                let [mldsa, slhdsa] = &f.backups;
                bundle::encode(class, &[&ed_pk, f.pk.as_bytes(), mldsa, slhdsa])
            }
            _ => unreachable!("a hybrid identity has a Falcon key, an ECC one doesn't"),
        };
        Self {
            class,
            ed_sk,
            falcon,
            bundle,
        }
    }

    fn generate_from_seed(class: SigningAlgo, seed: &[u8; 32]) -> Self {
        let falcon = match class {
            SigningAlgo::Ed25519 => None,
            SigningAlgo::FalconEd25519 => {
                let (pk, sk) = falcon512::keypair();
                Some(Falcon {
                    sk: Wiping::new(sk),
                    pk,
                    backups: backup_leaves(seed),
                })
            }
        };
        Self::from_parts(class, seed, falcon)
    }

    /// Generate a fresh signing keypair (its own random seed). Standalone
    /// signers (disposable record keys); identities use [`IdentityKeypair`].
    pub fn generate(class: SigningAlgo) -> Self {
        Self::generate_from_seed(class, &random_seed())
    }

    /// A hybrid signer that never needs its backups: the committed backup
    /// leaves are random, so no ML-DSA or SLH-DSA key generation is spent on
    /// it. For disposable record keys only: it can never switch to a backup.
    fn generate_disposable(seed: &[u8; 32]) -> Self {
        let (pk, sk) = falcon512::keypair();
        let mut backups = [[0u8; 32]; 2];
        for b in &mut backups {
            rand::rngs::OsRng.fill_bytes(b);
        }
        Self::from_parts(
            SigningAlgo::FalconEd25519,
            seed,
            Some(Falcon {
                sk: Wiping::new(sk),
                pk,
                backups,
            }),
        )
    }

    /// Sign under the policy for this class: Ed25519 alone, or Ed25519 and
    /// Falcon-512 (both must verify).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let ed_sig = self.ed_sk.sign(msg).to_bytes();
        match &self.falcon {
            None => bundle::encode_signature(&[(algo::ED25519, &ed_sig)]),
            Some(f) => {
                let falcon_sig = falcon512::detached_sign(msg, &f.sk);
                bundle::encode_signature(&[
                    (algo::ED25519, &ed_sig),
                    (algo::FALCON512, falcon_sig.as_bytes()),
                ])
            }
        }
    }

    /// The identity's key bundle: what travels wherever a signer's public key
    /// does, and what its SID and PeerId are hashed from.
    pub fn signing_pubkey_bytes(&self) -> Vec<u8> {
        self.bundle.clone()
    }

    /// Ed25519 public key (every class has one).
    pub fn ed25519_pubkey(&self) -> [u8; 32] {
        self.ed_sk.verifying_key().to_bytes()
    }

    /// Ed25519 secret seed (for TNS blinded signing).
    pub fn ed25519_seed(&self) -> [u8; 32] {
        self.ed_sk.to_bytes()
    }

    pub fn algo(&self) -> SigningAlgo {
        self.class
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.ed_sk.verifying_key()
    }
}

// ---------------------------------------------------------------------------
// KemKeypair: ML-KEM-768 (FIPS 203) + X25519
// ---------------------------------------------------------------------------

/// A hybrid KEM key pair. Every KEM in tarnet is this one; ephemeral keys
/// are random, an identity's static key is derived from its seed and
/// generation.
#[derive(Clone)]
pub struct KemKeypair {
    x_secret: X25519Secret,
    mlkem_dk: tarnet_pq::MlKem768Dk,
    pubkey: Vec<u8>,
}

/// `x25519_pk(32) || mlkem_ek(1184)`.
pub const KEM_PUBKEY_LEN: usize = 32 + 1184;
/// `x25519_eph_pk(32) || mlkem_ct(1088)`.
pub const KEM_CIPHERTEXT_LEN: usize = 32 + 1088;

impl KemKeypair {
    fn from_seeds(x_seed: &[u8; 32], mlkem_seed: &[u8; 64]) -> Self {
        let x_secret = X25519Secret::from(*x_seed);
        let mlkem_dk = tarnet_pq::MlKem768Dk::from_seed(mlkem_seed);
        let mut pubkey = Vec::with_capacity(KEM_PUBKEY_LEN);
        pubkey.extend_from_slice(X25519Public::from(&x_secret).as_bytes());
        pubkey.extend_from_slice(&mlkem_dk.encapsulation_key());
        Self {
            x_secret,
            mlkem_dk,
            pubkey,
        }
    }

    /// A fresh ephemeral key pair (handshakes, rekeys, circuits).
    pub fn generate_ephemeral(_algo: KemAlgo) -> Self {
        let x = random_seed();
        let mut m = Zeroizing::new([0u8; 64]);
        rand::rngs::OsRng.fill_bytes(&mut *m);
        Self::from_seeds(&x, &m)
    }

    /// An identity's static KEM key, generation `n`, derived from its seed.
    fn derive_static(seed: &[u8; 32], generation: u32) -> Self {
        let mut input = Zeroizing::new([0u8; 36]);
        input[..32].copy_from_slice(seed);
        input[32..].copy_from_slice(&generation.to_be_bytes());
        let kem_seed = Zeroizing::new(blake3::derive_key("tarnet identity v2 kem", &*input));
        let x = Zeroizing::new(blake3::derive_key("tarnet identity v2 x25519", &*kem_seed));
        let mut m = Zeroizing::new([0u8; 64]);
        blake3::Hasher::new_derive_key("tarnet identity v2 ml-kem-768")
            .update(&*kem_seed)
            .finalize_xof()
            .fill(&mut *m);
        Self::from_seeds(&x, &m)
    }

    /// KEM public key bytes: `x25519_pk(32) || mlkem_ek(1184)`.
    pub fn kem_pubkey_bytes(&self) -> Vec<u8> {
        self.pubkey.clone()
    }

    fn combine(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> [u8; 32] {
        // X-Wing structure: ML-KEM's secret already binds its ciphertext; the
        // X25519 half is bound to its ciphertext and the recipient key here.
        let mut h = blake3::Hasher::new_derive_key("tarnet kem v2");
        h.update(ss_m).update(ss_x).update(ct_x).update(pk_x);
        h.finalize().into()
    }

    /// Encapsulate to a hybrid public key. Returns `(shared_secret,
    /// ciphertext)`, the ciphertext being `x25519_eph_pk(32) || mlkem_ct(1088)`.
    pub fn encapsulate_to(remote_pk: &[u8], _algo: KemAlgo) -> Result<([u8; 32], Vec<u8>), &'static str> {
        if remote_pk.len() != KEM_PUBKEY_LEN {
            return Err("invalid hybrid KEM public key length");
        }
        let pk_x: [u8; 32] = remote_pk[..32].try_into().unwrap();
        let x_eph = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ct_x = X25519Public::from(&x_eph).to_bytes();
        let ss_x = x_eph.diffie_hellman(&X25519Public::from(pk_x));
        if !ss_x.was_contributory() {
            return Err("non-contributory X25519 input");
        }

        let mut m = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *m);
        let (ct_m, ss_m) =
            tarnet_pq::mlkem768_encapsulate(&remote_pk[32..], &m).ok_or("invalid ML-KEM public key")?;

        let ss = Self::combine(&*ss_m, ss_x.as_bytes(), &ct_x, &pk_x);
        let mut ct = Vec::with_capacity(KEM_CIPHERTEXT_LEN);
        ct.extend_from_slice(&ct_x);
        ct.extend_from_slice(&ct_m);
        Ok((ss, ct))
    }

    /// Decapsulate a ciphertext from [`encapsulate_to`](Self::encapsulate_to).
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], &'static str> {
        if ciphertext.len() != KEM_CIPHERTEXT_LEN {
            return Err("invalid hybrid KEM ciphertext length");
        }
        let ct_x: [u8; 32] = ciphertext[..32].try_into().unwrap();
        let ss_x = self.x_secret.diffie_hellman(&X25519Public::from(ct_x));
        if !ss_x.was_contributory() {
            return Err("non-contributory X25519 input");
        }
        let ss_m = self
            .mlkem_dk
            .decapsulate(&ciphertext[32..])
            .ok_or("invalid ML-KEM ciphertext length")?;
        let pk_x = X25519Public::from(&self.x_secret).to_bytes();
        Ok(Self::combine(&*ss_m, ss_x.as_bytes(), &ct_x, &pk_x))
    }

    pub fn algo(&self) -> KemAlgo {
        KemAlgo::MlkemX25519
    }
}

// ---------------------------------------------------------------------------
// IdentityKeypair = seed → signing + static KEM
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct IdentityKeypair {
    seed: Zeroizing<[u8; 32]>,
    kem_generation: u32,
    pub signing: SigningKeypair,
    pub kem: KemKeypair,
}

/// Persisted identity format version.
const STORED_VERSION: u8 = 2;

impl IdentityKeypair {
    /// Generate a new identity with the given scheme.
    pub fn generate(scheme: IdentityScheme) -> Self {
        let seed = random_seed();
        let signing = SigningKeypair::generate_from_seed(scheme.signing_algo(), &seed);
        let kem = KemKeypair::derive_static(&seed, 0);
        Self {
            seed,
            kem_generation: 0,
            signing,
            kem,
        }
    }

    /// Generate with the default (hybrid) scheme.
    pub fn generate_default() -> Self {
        Self::generate(IdentityScheme::DEFAULT)
    }

    /// Generate an ECC (Ed25519-only) identity. Throwaways only.
    pub fn generate_ed25519() -> Self {
        Self::generate(IdentityScheme::Ed25519)
    }

    pub fn peer_id(&self) -> PeerId {
        Bundle::parse(&self.signing.bundle).expect("own bundle is canonical").peer_id()
    }

    pub fn service_id(&self) -> ServiceId {
        Bundle::parse(&self.signing.bundle).expect("own bundle is canonical").service_id()
    }

    pub fn dht_id(&self) -> DhtId {
        dht_id_from_peer_id(&self.peer_id())
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing.sign(msg)
    }

    /// The static KEM key's generation (rotations bump it).
    pub fn kem_generation(&self) -> u32 {
        self.kem_generation
    }

    /// Serialize for persistence:
    ///
    /// ```text
    /// version(2) || scheme || seed(32) || kem_generation(u32) || id_check(32)
    ///   [hybrid] || falcon_sk_len(u16) || falcon_sk || falcon_pk_len(u16) || falcon_pk
    ///            || mldsa44_leaf(32) || slhdsa_leaf(32)
    /// ```
    ///
    /// `id_check` is the PeerId-domain hash of the bundle: loading re-derives
    /// every key and refuses the identity if it no longer matches (a library
    /// changed a derivation), instead of silently becoming someone else.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(STORED_VERSION);
        buf.push(self.scheme() as u8);
        buf.extend_from_slice(&*self.seed);
        buf.extend_from_slice(&self.kem_generation.to_be_bytes());
        buf.extend_from_slice(self.peer_id().as_bytes());
        if let Some(f) = &self.signing.falcon {
            for part in [f.sk.as_bytes(), f.pk.as_bytes()] {
                buf.extend_from_slice(&(part.len() as u16).to_be_bytes());
                buf.extend_from_slice(part);
            }
            buf.extend_from_slice(&f.backups[0]);
            buf.extend_from_slice(&f.backups[1]);
        }
        buf
    }

    /// Deserialize from [`to_bytes`](Self::to_bytes). Any mismatch is an
    /// error: there is no fallback to a weaker or different identity.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let mut r = crate::codec::Reader::new(data);
        let bad = |_| "identity key material truncated";
        if r.read_u8().map_err(bad)? != STORED_VERSION {
            return Err("identity is not in the v2 format (wire v10 needs new identities)");
        }
        let scheme = IdentityScheme::from_u8(r.read_u8().map_err(bad)?)?;
        let seed = Zeroizing::new(r.read_array::<32>().map_err(bad)?);
        let kem_generation = r.read_u32().map_err(bad)?;
        let id_check = r.read_array::<32>().map_err(bad)?;
        let falcon = match scheme {
            IdentityScheme::Ed25519 => None,
            IdentityScheme::FalconEd25519 => {
                let sk_len = r.read_u16().map_err(bad)? as usize;
                let sk = Zeroizing::new(r.read_bytes(sk_len).map_err(bad)?);
                let sk = falcon512::SecretKey::from_bytes(&sk).map_err(|_| "invalid Falcon secret key")?;
                let pk_len = r.read_u16().map_err(bad)? as usize;
                let pk = falcon512::PublicKey::from_bytes(&r.read_bytes(pk_len).map_err(bad)?)
                    .map_err(|_| "invalid Falcon public key")?;
                let backups = [r.read_array::<32>().map_err(bad)?, r.read_array::<32>().map_err(bad)?];
                Some(Falcon {
                    sk: Wiping::new(sk),
                    pk,
                    backups,
                })
            }
        };
        r.finish().map_err(|_| "trailing bytes after identity key material")?;
        let signing = SigningKeypair::from_parts(scheme.signing_algo(), &seed, falcon);
        let kem = KemKeypair::derive_static(&seed, kem_generation);
        let kp = Self {
            seed,
            kem_generation,
            signing,
            kem,
        };
        if kp.peer_id().0 != id_check {
            return Err("identity keys no longer derive to the stored identity");
        }
        Ok(kp)
    }

    pub fn signing_algo(&self) -> SigningAlgo {
        self.signing.algo()
    }

    pub fn kem_algo(&self) -> KemAlgo {
        KemAlgo::MlkemX25519
    }

    pub fn scheme(&self) -> IdentityScheme {
        match self.signing_algo() {
            SigningAlgo::Ed25519 => IdentityScheme::Ed25519,
            SigningAlgo::FalconEd25519 => IdentityScheme::FalconEd25519,
        }
    }
}

// ---------------------------------------------------------------------------
// Keypair wrapper
// ---------------------------------------------------------------------------

/// A node's or identity's key pair. Wraps [`IdentityKeypair`]. Cloning is
/// cheap (no key derivation).
#[derive(Clone)]
pub struct Keypair {
    pub identity: IdentityKeypair,
}

impl Keypair {
    /// Generate a hybrid key pair (the default scheme).
    pub fn generate() -> Self {
        Self {
            identity: IdentityKeypair::generate_default(),
        }
    }

    /// A disposable hybrid record key (outer signer of TNS-style records):
    /// post-quantum like any hybrid key, but without backup keys, which a key
    /// used once never needs.
    pub fn generate_disposable() -> Self {
        let seed = random_seed();
        Self {
            identity: IdentityKeypair {
                signing: SigningKeypair::generate_disposable(&seed),
                kem: KemKeypair::derive_static(&seed, 0),
                kem_generation: 0,
                seed,
            },
        }
    }

    /// Generate an ECC (Ed25519-only) key pair. Throwaway identities only:
    /// nodes and persistent identities are hybrid.
    pub fn generate_ed25519() -> Self {
        Self {
            identity: IdentityKeypair::generate_ed25519(),
        }
    }

    pub fn generate_with_scheme(scheme: IdentityScheme) -> Self {
        Self {
            identity: IdentityKeypair::generate(scheme),
        }
    }

    pub fn to_full_bytes(&self) -> Vec<u8> {
        self.identity.to_bytes()
    }

    pub fn from_full_bytes(data: &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            identity: IdentityKeypair::from_bytes(data)?,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    pub fn dht_id(&self) -> DhtId {
        self.identity.dht_id()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.identity.sign(msg)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.identity.signing.verifying_key()
    }

    pub fn scheme(&self) -> IdentityScheme {
        self.identity.scheme()
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// PeerId of a key bundle. Bytes that aren't a canonical bundle get a hash
/// under a separate domain that matches no peer.
pub fn peer_id_from_signing_pubkey(signing_pubkey: &[u8]) -> PeerId {
    match Bundle::parse(signing_pubkey) {
        Some(b) => b.peer_id(),
        None => PeerId(blake3::derive_key("tarnet invalid identity v2", signing_pubkey)),
    }
}

/// Compute DHT ID from a peer ID (64-byte XOF hash).
pub fn dht_id_from_peer_id(peer_id: &PeerId) -> DhtId {
    let mut id = [0u8; 64];
    blake3::Hasher::new()
        .update(peer_id.as_bytes())
        .finalize_xof()
        .fill(&mut id);
    DhtId(id)
}

/// The class of a key bundle, if it is a canonical one.
pub fn signing_algo_of(pubkey: &[u8]) -> Option<SigningAlgo> {
    Bundle::parse(pubkey).map(|b| b.class)
}

/// Whether a key bundle is hybrid. Nodes (PeerIds) must be.
pub fn is_hybrid(pubkey: &[u8]) -> bool {
    signing_algo_of(pubkey) == Some(SigningAlgo::FalconEd25519)
}

/// The Ed25519 public key a bundle reveals.
pub fn bundle_ed25519(pubkey: &[u8]) -> Option<[u8; 32]> {
    Bundle::parse(pubkey).map(|b| b.ed25519())
}

/// Who a signature must come from. Every signature check binds the key to
/// an identity first: there is no way to check a signature against a key
/// alone, so no object can forget the binding.
#[derive(Debug, Clone, Copy)]
pub enum SignedBy<'a> {
    /// The bundle must be this peer's (hash to its peer id).
    Peer(&'a PeerId),
    /// The bundle must be this service's (hash to its service id).
    Service(&'a ServiceId),
    /// The bundle was bound to an identity already (a link's authenticated
    /// peer key).
    BoundKey,
    /// Whoever holds the key: the caller derives the signer from it
    /// afterwards (a handshake learning who the peer is).
    AnyPeer,
}

/// The one signature check: parse the bundle, bind it as `signed_by` says,
/// check the sender's class byte against it when one is sent, and verify
/// every signature the policy requires for that class.
pub fn verify_signed(signed_by: SignedBy, algo: Option<u8>, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Some(b) = Bundle::parse(pubkey) else {
        return false;
    };
    let bound = match signed_by {
        SignedBy::Peer(p) => b.peer_id() == *p,
        SignedBy::Service(s) => b.service_id() == *s,
        SignedBy::BoundKey | SignedBy::AnyPeer => true,
    };
    if !bound {
        return false;
    }
    if let Some(byte) = algo {
        if SigningAlgo::from_u8(byte) != Ok(b.class) {
            return false;
        }
    }
    verify(&b, msg, sig)
}

/// Verify a policy-1 signature against a parsed bundle. Private: callers go
/// through [`verify_signed`], which binds the bundle first.
fn verify(b: &Bundle, msg: &[u8], sig: &[u8]) -> bool {
    let Some(parts) = bundle::parse_signature(b.class, sig) else {
        return false;
    };
    parts.iter().all(|&(a, s)| {
        let Some(pk) = b.key(a) else {
            return false;
        };
        match a {
            algo::ED25519 => {
                let (Ok(pk), Ok(s)) = (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(s)) else {
                    return false;
                };
                let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
                    return false;
                };
                vk.verify_strict(msg, &Signature::from_bytes(&s)).is_ok()
            }
            algo::FALCON512 => {
                let (Ok(pk), Ok(s)) = (
                    falcon512::PublicKey::from_bytes(pk),
                    falcon512::DetachedSignature::from_bytes(s),
                ) else {
                    return false;
                };
                falcon512::verify_detached_signature(&s, msg, &pk).is_ok()
            }
            _ => false,
        }
    })
}

/// [`verify_signed`] for a peer's signature, with the sender's class byte.
pub fn verify_with_pubkey(algo: SigningAlgo, pubkey: &[u8], peer_id: &PeerId, msg: &[u8], sig: &[u8]) -> bool {
    verify_signed(SignedBy::Peer(peer_id), Some(algo as u8), pubkey, msg, sig)
}

// ---------------------------------------------------------------------------
// TLV helpers for wire format
// ---------------------------------------------------------------------------

/// Write a TLV field: `algo(u8) || len(u16 BE) || data`.
pub fn write_tlv(buf: &mut Vec<u8>, algo: u8, data: &[u8]) {
    buf.push(algo);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Read a TLV field. Returns `(algo, data)`.
pub fn read_tlv(data: &[u8], offset: &mut usize) -> Result<(u8, Vec<u8>), &'static str> {
    if *offset + 3 > data.len() {
        return Err("TLV too short");
    }
    let algo = data[*offset];
    let len = u16::from_be_bytes([data[*offset + 1], data[*offset + 2]]) as usize;
    *offset += 3;
    if *offset + len > data.len() {
        return Err("TLV data truncated");
    }
    let val = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok((algo, val))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(kp: &IdentityKeypair, msg: &[u8], sig: &[u8]) -> bool {
        verify_signed(
            SignedBy::Peer(&kp.peer_id()),
            Some(kp.signing_algo() as u8),
            &kp.signing.signing_pubkey_bytes(),
            msg,
            sig,
        )
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let kp = IdentityKeypair::generate_default();
        let sig = kp.sign(b"post-quantum hello");
        assert!(check(&kp, b"post-quantum hello", &sig));
        assert!(!check(&kp, b"wrong", &sig));
    }

    #[test]
    fn ecc_sign_verify_roundtrip() {
        let kp = IdentityKeypair::generate_ed25519();
        let sig = kp.sign(b"hello");
        assert!(check(&kp, b"hello", &sig));
        assert!(!is_hybrid(&kp.signing.signing_pubkey_bytes()));
    }

    #[test]
    fn hybrid_requires_both_signatures() {
        let kp = IdentityKeypair::generate_default();
        let msg = b"both";
        let sig = kp.sign(msg);
        let parts = bundle::parse_signature(SigningAlgo::FalconEd25519, &sig).unwrap();
        // Ed25519 alone, in the ECC encoding, is refused for a hybrid bundle.
        let ed_only = bundle::encode_signature(&[parts[0]]);
        assert!(!check(&kp, msg, &ed_only));
        // Either half corrupted is refused.
        for flip in [5, 4 + 64 + 3 + 10] {
            let mut bad = sig.clone();
            bad[flip] ^= 0xFF;
            assert!(!check(&kp, msg, &bad), "flip at {flip}");
        }
    }

    #[test]
    fn class_byte_must_match_bundle() {
        let kp = IdentityKeypair::generate_default();
        let sig = kp.sign(b"x");
        assert!(!verify_signed(
            SignedBy::AnyPeer,
            Some(SigningAlgo::Ed25519 as u8),
            &kp.signing.signing_pubkey_bytes(),
            b"x",
            &sig
        ));
    }

    #[test]
    fn binding_is_checked() {
        let kp = IdentityKeypair::generate_default();
        let other = IdentityKeypair::generate_ed25519();
        let sig = kp.sign(b"x");
        let pk = kp.signing.signing_pubkey_bytes();
        assert!(!verify_signed(SignedBy::Peer(&other.peer_id()), None, &pk, b"x", &sig));
        assert!(!verify_signed(SignedBy::Service(&other.service_id()), None, &pk, b"x", &sig));
        assert!(verify_signed(SignedBy::Service(&kp.service_id()), None, &pk, b"x", &sig));
        // A SID and a PeerId of one identity differ (separate domains).
        assert_ne!(kp.peer_id().0, kp.service_id().0);
    }

    #[test]
    fn hybrid_kem_roundtrip() {
        let kp = IdentityKeypair::generate_default();
        let (ss, ct) = KemKeypair::encapsulate_to(&kp.kem.kem_pubkey_bytes(), KemAlgo::MlkemX25519).unwrap();
        assert_eq!(ct.len(), KEM_CIPHERTEXT_LEN);
        assert_eq!(kp.kem.decapsulate(&ct).unwrap(), ss);
        let eph = KemKeypair::generate_ephemeral(KemAlgo::MlkemX25519);
        let (ss, ct) = KemKeypair::encapsulate_to(&eph.kem_pubkey_bytes(), KemAlgo::MlkemX25519).unwrap();
        assert_eq!(eph.decapsulate(&ct).unwrap(), ss);
    }

    #[test]
    fn kem_combiner_binds_x25519_ciphertext() {
        let kp = KemKeypair::generate_ephemeral(KemAlgo::MlkemX25519);
        let (ss, mut ct) = KemKeypair::encapsulate_to(&kp.kem_pubkey_bytes(), KemAlgo::MlkemX25519).unwrap();
        ct[0] ^= 1;
        assert_ne!(kp.decapsulate(&ct).ok(), Some(ss));
        assert!(KemKeypair::encapsulate_to(&kp.kem_pubkey_bytes()[..32], KemAlgo::MlkemX25519).is_err());
    }

    #[test]
    fn identity_roundtrip_and_derivation_is_stable() {
        for kp in [IdentityKeypair::generate_default(), IdentityKeypair::generate_ed25519()] {
            let bytes = kp.to_bytes();
            let kp2 = IdentityKeypair::from_bytes(&bytes).unwrap();
            assert_eq!(kp.peer_id(), kp2.peer_id());
            assert_eq!(kp.service_id(), kp2.service_id());
            assert_eq!(kp.kem.kem_pubkey_bytes(), kp2.kem.kem_pubkey_bytes());
            assert_eq!(kp.scheme(), kp2.scheme());
        }
    }

    #[test]
    fn corrupt_identity_is_refused_not_downgraded() {
        let kp = IdentityKeypair::generate_default();
        let mut bytes = kp.to_bytes();
        bytes[5] ^= 1; // a seed byte: keys no longer match id_check
        assert!(IdentityKeypair::from_bytes(&bytes).is_err());
        let mut v1 = kp.to_bytes();
        v1[0] = 1;
        assert!(IdentityKeypair::from_bytes(&v1).is_err());
        let mut trailing = kp.to_bytes();
        trailing.push(0);
        assert!(IdentityKeypair::from_bytes(&trailing).is_err());
    }

    #[test]
    fn backup_keys_are_committed_and_deterministic() {
        let seed = [42u8; 32];
        assert_eq!(mldsa44_public(&seed), mldsa44_public(&seed));
        assert_eq!(mldsa44_public(&seed).len(), 1312);
        assert_eq!(slhdsa_public(&seed).len(), 32);
        assert_ne!(mldsa44_public(&seed), mldsa44_public(&[43u8; 32]));
        let kp = IdentityKeypair::generate_default();
        let b = Bundle::parse(&kp.signing.bundle).unwrap();
        assert_eq!(b.slots[2].leaf, bundle::leaf(algo::MLDSA44, &mldsa44_public(&kp.seed)));
        assert_eq!(
            b.slots[3].leaf,
            bundle::leaf(algo::SLHDSA_SHA2_128S, &slhdsa_public(&kp.seed))
        );
    }

    #[test]
    fn static_kem_rotates_with_generation() {
        let seed = [7u8; 32];
        let a = KemKeypair::derive_static(&seed, 0);
        let b = KemKeypair::derive_static(&seed, 1);
        assert_eq!(a.kem_pubkey_bytes(), KemKeypair::derive_static(&seed, 0).kem_pubkey_bytes());
        assert_ne!(a.kem_pubkey_bytes(), b.kem_pubkey_bytes());
    }

    #[test]
    fn dht_id_deterministic() {
        let kp = Keypair::generate();
        assert_eq!(kp.dht_id(), dht_id_from_peer_id(&kp.peer_id()));
    }

    #[test]
    fn tlv_roundtrip() {
        let mut buf = Vec::new();
        write_tlv(&mut buf, 0x02, b"hello pubkey");
        let mut offset = 0;
        let (algo, val) = read_tlv(&buf, &mut offset).unwrap();
        assert_eq!(algo, 0x02);
        assert_eq!(val, b"hello pubkey");
        assert_eq!(offset, buf.len());
    }
}
