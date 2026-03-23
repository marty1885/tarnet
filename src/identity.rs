use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
    SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait,
};
use pqcrypto_traits::sign::{
    DetachedSignature as SignDetachedTrait, PublicKey as SignPublicKeyTrait,
    SecretKey as SignSecretKeyTrait,
};
use sha2::Sha512;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::types::{DhtId, PeerId};
use tarnet_api::types::ServiceId;
use tarnet_api::types::{IdentityScheme, KemAlgo, SigningAlgo};

// ---------------------------------------------------------------------------
// SigningKeypair
// ---------------------------------------------------------------------------

enum SigningInner {
    Ed25519 {
        signing_key: SigningKey,
    },
    FalconEd25519 {
        ed_sk: SigningKey,
        falcon_sk: falcon512::SecretKey,
        falcon_pk: falcon512::PublicKey,
    },
}

pub struct SigningKeypair {
    inner: SigningInner,
}

impl SigningKeypair {
    /// Generate a new random signing keypair.
    pub fn generate(algo: SigningAlgo) -> Self {
        match algo {
            SigningAlgo::Ed25519 => {
                let mut rng = rand::rngs::OsRng;
                Self {
                    inner: SigningInner::Ed25519 {
                        signing_key: SigningKey::generate(&mut rng),
                    },
                }
            }
            SigningAlgo::FalconEd25519 => {
                let mut rng = rand::rngs::OsRng;
                let ed_sk = SigningKey::generate(&mut rng);
                let (falcon_pk, falcon_sk) = falcon512::keypair();
                Self {
                    inner: SigningInner::FalconEd25519 {
                        ed_sk,
                        falcon_sk,
                        falcon_pk,
                    },
                }
            }
        }
    }

    /// Serialize to bytes: `algo(u8) || key_material`.
    ///
    /// Ed25519: `0x01 || seed(32)` — 33 bytes.
    /// FalconEd25519: `0x02 || ed25519_seed(32) || falcon_sk_bytes || falcon_pk_bytes` —
    /// the Falcon secret and public keys are needed because Falcon has no
    /// deterministic derivation from a seed.
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.inner {
            SigningInner::Ed25519 { signing_key } => {
                let mut buf = Vec::with_capacity(33);
                buf.push(SigningAlgo::Ed25519 as u8);
                buf.extend_from_slice(&signing_key.to_bytes());
                buf
            }
            SigningInner::FalconEd25519 {
                ed_sk,
                falcon_sk,
                falcon_pk,
            } => {
                let sk_bytes = falcon_sk.as_bytes();
                let pk_bytes = falcon_pk.as_bytes();
                let mut buf = Vec::with_capacity(1 + 32 + 2 + sk_bytes.len() + 2 + pk_bytes.len());
                buf.push(SigningAlgo::FalconEd25519 as u8);
                buf.extend_from_slice(&ed_sk.to_bytes());
                buf.extend_from_slice(&(sk_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(sk_bytes);
                buf.extend_from_slice(&(pk_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(pk_bytes);
                buf
            }
        }
    }

    /// Deserialize from bytes produced by `to_bytes()`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("empty signing key data");
        }
        let algo = SigningAlgo::from_u8(data[0])?;
        match algo {
            SigningAlgo::Ed25519 => {
                if data.len() < 33 {
                    return Err("ed25519 signing key too short");
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&data[1..33]);
                Ok(Self {
                    inner: SigningInner::Ed25519 {
                        signing_key: SigningKey::from_bytes(&seed),
                    },
                })
            }
            SigningAlgo::FalconEd25519 => {
                if data.len() < 37 {
                    return Err("falcon_ed25519 signing key too short");
                }
                let mut ed_seed = [0u8; 32];
                ed_seed.copy_from_slice(&data[1..33]);
                let ed_sk = SigningKey::from_bytes(&ed_seed);

                let sk_len = u16::from_be_bytes([data[33], data[34]]) as usize;
                if data.len() < 35 + sk_len + 2 {
                    return Err("falcon_ed25519 signing key truncated");
                }
                let falcon_sk = falcon512::SecretKey::from_bytes(&data[35..35 + sk_len])
                    .map_err(|_| "invalid falcon secret key")?;

                let pk_off = 35 + sk_len;
                let pk_len = u16::from_be_bytes([data[pk_off], data[pk_off + 1]]) as usize;
                if data.len() < pk_off + 2 + pk_len {
                    return Err("falcon_ed25519 public key truncated");
                }
                let falcon_pk =
                    falcon512::PublicKey::from_bytes(&data[pk_off + 2..pk_off + 2 + pk_len])
                        .map_err(|_| "invalid falcon public key")?;

                Ok(Self {
                    inner: SigningInner::FalconEd25519 {
                        ed_sk,
                        falcon_sk,
                        falcon_pk,
                    },
                })
            }
        }
    }

    /// Sign a message. Returns a variable-length signature.
    ///
    /// Ed25519: 64 bytes.
    /// FalconEd25519: `ed25519_sig(64) || falcon_sig(variable, ~690)`.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match &self.inner {
            SigningInner::Ed25519 { signing_key } => signing_key.sign(msg).to_bytes().to_vec(),
            SigningInner::FalconEd25519 {
                ed_sk, falcon_sk, ..
            } => {
                let ed_sig = ed_sk.sign(msg).to_bytes();
                let falcon_sig = falcon512::detached_sign(msg, falcon_sk);
                let falcon_bytes = falcon_sig.as_bytes();
                let mut out = Vec::with_capacity(64 + falcon_bytes.len());
                out.extend_from_slice(&ed_sig);
                out.extend_from_slice(falcon_bytes);
                out
            }
        }
    }

    /// Full signing public key bytes.
    ///
    /// Ed25519: 32 bytes.
    /// FalconEd25519: `ed25519_pk(32) || falcon_pk(897)` = 929 bytes.
    pub fn signing_pubkey_bytes(&self) -> Vec<u8> {
        match &self.inner {
            SigningInner::Ed25519 { signing_key } => {
                signing_key.verifying_key().to_bytes().to_vec()
            }
            SigningInner::FalconEd25519 {
                ed_sk, falcon_pk, ..
            } => {
                let ed_pk = ed_sk.verifying_key().to_bytes();
                let fpk = falcon_pk.as_bytes();
                let mut out = Vec::with_capacity(32 + fpk.len());
                out.extend_from_slice(&ed_pk);
                out.extend_from_slice(fpk);
                out
            }
        }
    }

    /// Ed25519 public key — always available regardless of algo.
    pub fn ed25519_pubkey(&self) -> [u8; 32] {
        match &self.inner {
            SigningInner::Ed25519 { signing_key } => signing_key.verifying_key().to_bytes(),
            SigningInner::FalconEd25519 { ed_sk, .. } => ed_sk.verifying_key().to_bytes(),
        }
    }

    /// Ed25519 seed bytes (for X25519 derivation).
    pub fn ed25519_seed(&self) -> [u8; 32] {
        match &self.inner {
            SigningInner::Ed25519 { signing_key } => signing_key.to_bytes(),
            SigningInner::FalconEd25519 { ed_sk, .. } => ed_sk.to_bytes(),
        }
    }

    pub fn algo(&self) -> SigningAlgo {
        match &self.inner {
            SigningInner::Ed25519 { .. } => SigningAlgo::Ed25519,
            SigningInner::FalconEd25519 { .. } => SigningAlgo::FalconEd25519,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match &self.inner {
            SigningInner::Ed25519 { signing_key } => signing_key.verifying_key(),
            SigningInner::FalconEd25519 { ed_sk, .. } => ed_sk.verifying_key(),
        }
    }
}

// ---------------------------------------------------------------------------
// KemKeypair
// ---------------------------------------------------------------------------

enum KemInner {
    X25519 {
        secret: X25519Secret,
    },
    MlkemX25519 {
        x_secret: X25519Secret,
        mlkem_sk: kyber768::SecretKey,
        mlkem_pk: kyber768::PublicKey,
    },
}

pub struct KemKeypair {
    inner: KemInner,
}

impl KemKeypair {
    /// Generate an ephemeral KEM keypair (random, not derived from identity).
    /// Used for per-session PQ forward secrecy in handshakes and rekeys.
    pub fn generate_ephemeral(algo: KemAlgo) -> Self {
        match algo {
            KemAlgo::X25519 => Self {
                inner: KemInner::X25519 {
                    secret: X25519Secret::random_from_rng(rand::rngs::OsRng),
                },
            },
            KemAlgo::MlkemX25519 => {
                let x_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
                let (mlkem_pk, mlkem_sk) = kyber768::keypair();
                Self {
                    inner: KemInner::MlkemX25519 {
                        x_secret,
                        mlkem_sk,
                        mlkem_pk,
                    },
                }
            }
        }
    }

    /// Create a KEM keypair from a signing keypair.
    ///
    /// X25519: derived from Ed25519 seed (SHA-512, as existing code).
    /// MlkemX25519: X25519 derived from Ed25519 seed, ML-KEM generated independently.
    pub fn generate(algo: KemAlgo, signing: &SigningKeypair) -> Self {
        let x_secret = derive_x25519_secret(&signing.ed25519_seed());
        match algo {
            KemAlgo::X25519 => Self {
                inner: KemInner::X25519 { secret: x_secret },
            },
            KemAlgo::MlkemX25519 => {
                let (mlkem_pk, mlkem_sk) = kyber768::keypair();
                Self {
                    inner: KemInner::MlkemX25519 {
                        x_secret,
                        mlkem_sk,
                        mlkem_pk,
                    },
                }
            }
        }
    }

    /// Serialize KEM key material: `algo(u8) || extra`.
    ///
    /// X25519: `0x01` — 1 byte (secret derived from Ed25519 seed).
    /// MlkemX25519: `0x02 || mlkem_sk_len(u16) || mlkem_sk || mlkem_pk_len(u16) || mlkem_pk`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.inner {
            KemInner::X25519 { .. } => {
                vec![KemAlgo::X25519 as u8]
            }
            KemInner::MlkemX25519 {
                mlkem_sk, mlkem_pk, ..
            } => {
                let sk_bytes = mlkem_sk.as_bytes();
                let pk_bytes = mlkem_pk.as_bytes();
                let mut buf = Vec::with_capacity(1 + 2 + sk_bytes.len() + 2 + pk_bytes.len());
                buf.push(KemAlgo::MlkemX25519 as u8);
                buf.extend_from_slice(&(sk_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(sk_bytes);
                buf.extend_from_slice(&(pk_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(pk_bytes);
                buf
            }
        }
    }

    /// Deserialize from bytes. Needs the signing keypair to re-derive X25519.
    pub fn from_bytes(data: &[u8], signing: &SigningKeypair) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("empty KEM key data");
        }
        let algo = KemAlgo::from_u8(data[0])?;
        let x_secret = derive_x25519_secret(&signing.ed25519_seed());
        match algo {
            KemAlgo::X25519 => Ok(Self {
                inner: KemInner::X25519 { secret: x_secret },
            }),
            KemAlgo::MlkemX25519 => {
                if data.len() < 3 {
                    return Err("mlkem_x25519 key too short");
                }
                let sk_len = u16::from_be_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + sk_len + 2 {
                    return Err("mlkem_x25519 key truncated");
                }
                let mlkem_sk = kyber768::SecretKey::from_bytes(&data[3..3 + sk_len])
                    .map_err(|_| "invalid ML-KEM secret key")?;
                let pk_off = 3 + sk_len;
                let pk_len = u16::from_be_bytes([data[pk_off], data[pk_off + 1]]) as usize;
                if data.len() < pk_off + 2 + pk_len {
                    return Err("mlkem_x25519 public key truncated");
                }
                let mlkem_pk =
                    kyber768::PublicKey::from_bytes(&data[pk_off + 2..pk_off + 2 + pk_len])
                        .map_err(|_| "invalid ML-KEM public key")?;
                Ok(Self {
                    inner: KemInner::MlkemX25519 {
                        x_secret,
                        mlkem_sk,
                        mlkem_pk,
                    },
                })
            }
        }
    }

    /// KEM public key bytes.
    ///
    /// X25519: 32 bytes.
    /// MlkemX25519: `x25519_pk(32) || mlkem_pk(1184)` = 1216 bytes.
    pub fn kem_pubkey_bytes(&self) -> Vec<u8> {
        match &self.inner {
            KemInner::X25519 { secret } => X25519Public::from(secret).to_bytes().to_vec(),
            KemInner::MlkemX25519 {
                x_secret, mlkem_pk, ..
            } => {
                let x_pk = X25519Public::from(x_secret).to_bytes();
                let mpk = mlkem_pk.as_bytes();
                let mut out = Vec::with_capacity(32 + mpk.len());
                out.extend_from_slice(&x_pk);
                out.extend_from_slice(mpk);
                out
            }
        }
    }

    /// Encapsulate: generate a shared secret and ciphertext for the remote's public key.
    ///
    /// X25519: ephemeral DH. Returns (shared_secret, ephemeral_pubkey).
    /// MlkemX25519: `shared_secret = blake3::derive_key("tarnet kem", x25519_ss || mlkem_ss)`.
    ///   Ciphertext = `x25519_eph_pk(32) || mlkem_ct(1088)` = 1120 bytes.
    pub fn encapsulate_to(
        remote_pk: &[u8],
        algo: KemAlgo,
    ) -> Result<([u8; 32], Vec<u8>), &'static str> {
        match algo {
            KemAlgo::X25519 => {
                if remote_pk.len() < 32 {
                    return Err("X25519 pubkey too short");
                }
                let mut rpk = [0u8; 32];
                rpk.copy_from_slice(&remote_pk[..32]);
                let eph = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
                let eph_pk = X25519Public::from(&eph);
                let shared = eph.diffie_hellman(&X25519Public::from(rpk));
                Ok((shared.to_bytes(), eph_pk.to_bytes().to_vec()))
            }
            KemAlgo::MlkemX25519 => {
                if remote_pk.len() < 32 {
                    return Err("mlkem_x25519 pubkey too short");
                }
                // X25519 part
                let mut x_rpk = [0u8; 32];
                x_rpk.copy_from_slice(&remote_pk[..32]);
                let x_eph = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
                let x_eph_pk = X25519Public::from(&x_eph);
                let x_ss = x_eph.diffie_hellman(&X25519Public::from(x_rpk));

                // ML-KEM part
                let mlkem_pk = kyber768::PublicKey::from_bytes(&remote_pk[32..])
                    .map_err(|_| "invalid ML-KEM pubkey")?;
                let (mlkem_ss, mlkem_ct) = kyber768::encapsulate(&mlkem_pk);

                // Combined shared secret
                let mut combined = Vec::with_capacity(32 + mlkem_ss.as_bytes().len());
                combined.extend_from_slice(&x_ss.to_bytes());
                combined.extend_from_slice(mlkem_ss.as_bytes());
                let ss = blake3::derive_key("tarnet kem", &combined);

                // Ciphertext: x25519_eph_pk || mlkem_ct
                let ct_bytes = mlkem_ct.as_bytes();
                let mut ct = Vec::with_capacity(32 + ct_bytes.len());
                ct.extend_from_slice(&x_eph_pk.to_bytes());
                ct.extend_from_slice(ct_bytes);

                Ok((ss, ct))
            }
        }
    }

    /// Decapsulate: recover shared secret from ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], &'static str> {
        match &self.inner {
            KemInner::X25519 { secret } => {
                if ciphertext.len() < 32 {
                    return Err("X25519 ciphertext too short");
                }
                let mut eph_pk = [0u8; 32];
                eph_pk.copy_from_slice(&ciphertext[..32]);
                let shared = secret.diffie_hellman(&X25519Public::from(eph_pk));
                Ok(shared.to_bytes())
            }
            KemInner::MlkemX25519 {
                x_secret, mlkem_sk, ..
            } => {
                if ciphertext.len() < 32 {
                    return Err("mlkem_x25519 ciphertext too short");
                }
                // X25519 part
                let mut x_eph_pk = [0u8; 32];
                x_eph_pk.copy_from_slice(&ciphertext[..32]);
                let x_ss = x_secret.diffie_hellman(&X25519Public::from(x_eph_pk));

                // ML-KEM part
                let mlkem_ct = kyber768::Ciphertext::from_bytes(&ciphertext[32..])
                    .map_err(|_| "invalid ML-KEM ciphertext")?;
                let mlkem_ss = kyber768::decapsulate(&mlkem_ct, mlkem_sk);

                // Combined
                let mut combined = Vec::with_capacity(32 + mlkem_ss.as_bytes().len());
                combined.extend_from_slice(&x_ss.to_bytes());
                combined.extend_from_slice(mlkem_ss.as_bytes());
                let ss = blake3::derive_key("tarnet kem", &combined);

                Ok(ss)
            }
        }
    }

    pub fn algo(&self) -> KemAlgo {
        match &self.inner {
            KemInner::X25519 { .. } => KemAlgo::X25519,
            KemInner::MlkemX25519 { .. } => KemAlgo::MlkemX25519,
        }
    }

    /// X25519 public key — always available.
    pub fn x25519_public(&self) -> X25519Public {
        match &self.inner {
            KemInner::X25519 { secret } => X25519Public::from(secret),
            KemInner::MlkemX25519 { x_secret, .. } => X25519Public::from(x_secret),
        }
    }

    /// X25519 static secret — for INTRODUCE DH (existing protocol).
    pub fn x25519_secret_ref(&self) -> &X25519Secret {
        match &self.inner {
            KemInner::X25519 { secret } => secret,
            KemInner::MlkemX25519 { x_secret, .. } => x_secret,
        }
    }
}

// ---------------------------------------------------------------------------
// IdentityKeypair = signing + KEM
// ---------------------------------------------------------------------------

pub struct IdentityKeypair {
    pub signing: SigningKeypair,
    pub kem: KemKeypair,
}

impl IdentityKeypair {
    /// Generate a new identity keypair with the given scheme.
    pub fn generate(scheme: IdentityScheme) -> Self {
        let signing = SigningKeypair::generate(scheme.signing_algo());
        let kem = KemKeypair::generate(scheme.kem_algo(), &signing);
        Self { signing, kem }
    }

    /// Generate with the default scheme (falcon_ed25519 + mlkem_x25519).
    pub fn generate_default() -> Self {
        Self::generate(IdentityScheme::DEFAULT)
    }

    /// Generate with the Ed25519 scheme (ed25519 + x25519).
    pub fn generate_ed25519() -> Self {
        Self::generate(IdentityScheme::Ed25519)
    }

    /// Backward-compatible alias for the standalone Ed25519 scheme.
    pub fn generate_classic() -> Self {
        Self::generate_ed25519()
    }

    /// PeerId = blake3::derive_key("tarnet peer-id", &signing_pubkey_bytes)[..32].
    pub fn peer_id(&self) -> PeerId {
        peer_id_from_signing_pubkey(&self.signing.signing_pubkey_bytes())
    }

    /// ServiceId = blake3::derive_key("tarnet service-id", &signing_pubkey_bytes)[..32].
    pub fn service_id(&self) -> ServiceId {
        ServiceId::from_signing_pubkey(&self.signing.signing_pubkey_bytes())
    }

    /// DHT ID from peer ID.
    pub fn dht_id(&self) -> DhtId {
        dht_id_from_peer_id(&self.peer_id())
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing.sign(msg)
    }

    /// Serialize both keypairs for persistence.
    pub fn to_bytes(&self) -> Vec<u8> {
        let signing_bytes = self.signing.to_bytes();
        let kem_bytes = self.kem.to_bytes();
        let mut buf = Vec::with_capacity(4 + signing_bytes.len() + kem_bytes.len());
        buf.extend_from_slice(&(signing_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&signing_bytes);
        buf.extend_from_slice(&(kem_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&kem_bytes);
        buf
    }

    /// Deserialize from bytes produced by `to_bytes()`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 4 {
            return Err("identity keypair too short");
        }
        let signing_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + signing_len + 2 {
            return Err("identity keypair truncated");
        }
        let signing = SigningKeypair::from_bytes(&data[2..2 + signing_len])?;
        let kem_off = 2 + signing_len;
        let kem_len = u16::from_be_bytes([data[kem_off], data[kem_off + 1]]) as usize;
        if data.len() < kem_off + 2 + kem_len {
            return Err("identity keypair KEM truncated");
        }
        let kem = KemKeypair::from_bytes(&data[kem_off + 2..kem_off + 2 + kem_len], &signing)?;
        Ok(Self { signing, kem })
    }

    pub fn signing_algo(&self) -> SigningAlgo {
        self.signing.algo()
    }

    pub fn kem_algo(&self) -> KemAlgo {
        self.kem.algo()
    }

    pub fn scheme(&self) -> IdentityScheme {
        match (self.signing_algo(), self.kem_algo()) {
            (SigningAlgo::Ed25519, KemAlgo::X25519) => IdentityScheme::Ed25519,
            (SigningAlgo::FalconEd25519, KemAlgo::MlkemX25519) => IdentityScheme::FalconEd25519,
            (signing, kem) => panic!("unsupported identity scheme combination: {signing}/{kem}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Backward-compatible Keypair wrapper
// ---------------------------------------------------------------------------

/// Wraps IdentityKeypair for backward compatibility during migration.
/// Most existing code uses `Keypair` — this delegates to IdentityKeypair.
pub struct Keypair {
    pub identity: IdentityKeypair,
}

impl Keypair {
    /// Generate a keypair with the default scheme (falcon_ed25519 + mlkem_x25519).
    pub fn generate() -> Self {
        Self {
            identity: IdentityKeypair::generate_default(),
        }
    }

    /// Generate an Ed25519 + X25519 keypair (no PQ).
    pub fn generate_ed25519() -> Self {
        Self {
            identity: IdentityKeypair::generate_ed25519(),
        }
    }

    /// Backward-compatible alias for the standalone Ed25519 scheme.
    pub fn generate_classic() -> Self {
        Self::generate_ed25519()
    }

    /// Generate with a specific identity scheme.
    pub fn generate_with_scheme(scheme: IdentityScheme) -> Self {
        Self {
            identity: IdentityKeypair::generate(scheme),
        }
    }

    /// Backward-compatible generator for explicit low-level algorithms.
    pub fn generate_with(signing_algo: SigningAlgo, kem_algo: KemAlgo) -> Self {
        Self {
            identity: IdentityKeypair::generate(match (signing_algo, kem_algo) {
                (SigningAlgo::Ed25519, KemAlgo::X25519) => IdentityScheme::Ed25519,
                (SigningAlgo::FalconEd25519, KemAlgo::MlkemX25519) => IdentityScheme::FalconEd25519,
                _ => panic!("unsupported identity scheme combination"),
            }),
        }
    }

    /// Restore from a 32-byte Ed25519 seed. **V1 migration only** — always
    /// produces a classic `ed25519 + x25519` identity. New code must use
    /// `from_full_bytes()`.
    #[deprecated(note = "use from_full_bytes() for new code; this always produces classic ed25519")]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&bytes);
        let signing = SigningKeypair {
            inner: SigningInner::Ed25519 { signing_key },
        };
        let kem = KemKeypair::generate(KemAlgo::X25519, &signing);
        Self {
            identity: IdentityKeypair { signing, kem },
        }
    }

    /// Raw Ed25519 seed bytes. **V1 migration only** — lossy for PQ keys
    /// (discards Falcon/ML-KEM material). New code must use `to_full_bytes()`.
    #[deprecated(note = "use to_full_bytes() for new code; this loses PQ key material")]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.identity.signing.ed25519_seed()
    }

    /// Full serialization preserving all key material.
    pub fn to_full_bytes(&self) -> Vec<u8> {
        self.identity.to_bytes()
    }

    /// Restore from full serialization.
    pub fn from_full_bytes(data: &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            identity: IdentityKeypair::from_bytes(data)?,
        })
    }

    /// PeerId (hash-based).
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    pub fn dht_id(&self) -> DhtId {
        self.identity.dht_id()
    }

    /// Sign a message. Returns variable-length signature.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.identity.sign(msg)
    }

    /// Ed25519 verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.identity.signing.verifying_key()
    }

    /// Derive X25519 static secret from Ed25519 seed.
    pub fn x25519_secret(&self) -> X25519Secret {
        derive_x25519_secret(&self.identity.signing.ed25519_seed())
    }

    /// Derive X25519 public key.
    pub fn x25519_public(&self) -> X25519Public {
        self.identity.kem.x25519_public()
    }

    pub fn scheme(&self) -> IdentityScheme {
        self.identity.scheme()
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Derive PeerId from signing public key bytes.
pub fn peer_id_from_signing_pubkey(signing_pubkey: &[u8]) -> PeerId {
    PeerId(blake3::derive_key("tarnet peer-id", signing_pubkey))
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

/// Derive X25519 static secret from Ed25519 seed bytes.
fn derive_x25519_secret(ed25519_seed: &[u8; 32]) -> X25519Secret {
    let hash = <Sha512 as sha2::Digest>::digest(ed25519_seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    X25519Secret::from(scalar)
}

/// Convert an Ed25519 public key (32 bytes) to its X25519 equivalent.
pub fn ed25519_pubkey_to_x25519(ed_pubkey: &[u8; 32]) -> X25519Public {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY::from_slice(ed_pubkey).unwrap();
    let point = compressed.decompress().expect("invalid Ed25519 public key");
    X25519Public::from(point.to_montgomery().to_bytes())
}

/// Verify a signature given the signing algorithm, public key, message, and signature.
///
/// FalconEd25519: BOTH Ed25519 and Falcon signatures must pass.
pub fn verify(algo: SigningAlgo, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match algo {
        SigningAlgo::Ed25519 => {
            if pubkey.len() < 32 || sig.len() < 64 {
                return false;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pubkey[..32]);
            let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
                return false;
            };
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&sig[..64]);
            vk.verify(msg, &Signature::from_bytes(&sig_bytes)).is_ok()
        }
        SigningAlgo::FalconEd25519 => {
            if pubkey.len() < 32 || sig.len() < 64 {
                return false;
            }
            // Ed25519 verification
            let mut ed_pk = [0u8; 32];
            ed_pk.copy_from_slice(&pubkey[..32]);
            let Ok(vk) = VerifyingKey::from_bytes(&ed_pk) else {
                return false;
            };
            let mut ed_sig = [0u8; 64];
            ed_sig.copy_from_slice(&sig[..64]);
            if vk.verify(msg, &Signature::from_bytes(&ed_sig)).is_err() {
                return false;
            }

            // Falcon verification
            let Ok(falcon_pk) = falcon512::PublicKey::from_bytes(&pubkey[32..]) else {
                return false;
            };
            let Ok(falcon_sig) = falcon512::DetachedSignature::from_bytes(&sig[64..]) else {
                return false;
            };
            falcon512::verify_detached_signature(&falcon_sig, msg, &falcon_pk).is_ok()
        }
    }
}

/// Verify using a PeerId and cached public key info.
/// This is the main verification path — callers look up the pubkey from
/// the pubkey cache or inline TLV, then call this.
pub fn verify_with_pubkey(
    algo: SigningAlgo,
    pubkey: &[u8],
    peer_id: &PeerId,
    msg: &[u8],
    sig: &[u8],
) -> bool {
    // Verify that the pubkey actually corresponds to this PeerId
    let expected = peer_id_from_signing_pubkey(pubkey);
    if expected != *peer_id {
        return false;
    }
    verify(algo, pubkey, msg, sig)
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

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let kp = IdentityKeypair::generate_classic();
        let msg = b"hello tarnet";
        let sig = kp.sign(msg);
        let pubkey = kp.signing.signing_pubkey_bytes();
        assert!(verify(SigningAlgo::Ed25519, &pubkey, msg, &sig));
        assert!(!verify(SigningAlgo::Ed25519, &pubkey, b"wrong", &sig));
    }

    #[test]
    fn falcon_ed25519_sign_verify_roundtrip() {
        let kp = IdentityKeypair::generate_default();
        let msg = b"post-quantum hello";
        let sig = kp.sign(msg);
        let pubkey = kp.signing.signing_pubkey_bytes();
        assert!(verify(SigningAlgo::FalconEd25519, &pubkey, msg, &sig));
        assert!(!verify(SigningAlgo::FalconEd25519, &pubkey, b"wrong", &sig));
    }

    #[test]
    fn falcon_ed25519_requires_both_sigs() {
        let kp = IdentityKeypair::generate_default();
        let msg = b"test both sigs";
        let sig = kp.sign(msg);
        let pubkey = kp.signing.signing_pubkey_bytes();

        // Corrupt Ed25519 signature portion
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xFF;
        assert!(!verify(SigningAlgo::FalconEd25519, &pubkey, msg, &bad_sig));

        // Corrupt Falcon signature portion
        let mut bad_sig2 = sig.clone();
        bad_sig2[64] ^= 0xFF;
        assert!(!verify(SigningAlgo::FalconEd25519, &pubkey, msg, &bad_sig2));
    }

    #[test]
    fn cross_algo_rejection() {
        // Ed25519 sig should not verify as FalconEd25519
        let kp_classic = IdentityKeypair::generate_classic();
        let msg = b"algo mismatch";
        let sig = kp_classic.sign(msg);
        let pubkey = kp_classic.signing.signing_pubkey_bytes();
        assert!(!verify(SigningAlgo::FalconEd25519, &pubkey, msg, &sig));
    }

    #[test]
    fn x25519_kem_roundtrip() {
        let kp = IdentityKeypair::generate_classic();
        let remote_pk = kp.kem.kem_pubkey_bytes();
        let (ss_enc, ct) = KemKeypair::encapsulate_to(&remote_pk, KemAlgo::X25519).unwrap();
        let ss_dec = kp.kem.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn mlkem_x25519_kem_roundtrip() {
        let kp = IdentityKeypair::generate_default();
        let remote_pk = kp.kem.kem_pubkey_bytes();
        let (ss_enc, ct) = KemKeypair::encapsulate_to(&remote_pk, KemAlgo::MlkemX25519).unwrap();
        let ss_dec = kp.kem.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn peer_id_is_hash_based() {
        let kp = IdentityKeypair::generate_classic();
        let pid = kp.peer_id();
        // PeerId should NOT be the raw Ed25519 pubkey anymore
        let ed_pk = kp.signing.ed25519_pubkey();
        assert_ne!(pid.0, ed_pk);
        // It should be the BLAKE3 derive_key hash
        let expected = blake3::derive_key("tarnet peer-id", &kp.signing.signing_pubkey_bytes());
        assert_eq!(pid.0, expected);
    }

    #[test]
    fn falcon_ed25519_different_peer_id() {
        // Same Ed25519 seed but different Falcon key = different PeerId
        let kp1 = IdentityKeypair::generate_default();
        let kp2 = IdentityKeypair::generate_default();
        assert_ne!(kp1.peer_id(), kp2.peer_id());
    }

    #[test]
    fn signing_keypair_serialization() {
        let kp = SigningKeypair::generate(SigningAlgo::Ed25519);
        let bytes = kp.to_bytes();
        let kp2 = SigningKeypair::from_bytes(&bytes).unwrap();
        assert_eq!(kp.signing_pubkey_bytes(), kp2.signing_pubkey_bytes());

        let kp3 = SigningKeypair::generate(SigningAlgo::FalconEd25519);
        let bytes3 = kp3.to_bytes();
        let kp4 = SigningKeypair::from_bytes(&bytes3).unwrap();
        assert_eq!(kp3.signing_pubkey_bytes(), kp4.signing_pubkey_bytes());
    }

    #[test]
    fn identity_keypair_serialization() {
        let kp = IdentityKeypair::generate_default();
        let bytes = kp.to_bytes();
        let kp2 = IdentityKeypair::from_bytes(&bytes).unwrap();
        assert_eq!(kp.peer_id(), kp2.peer_id());
        assert_eq!(
            kp.signing.signing_pubkey_bytes(),
            kp2.signing.signing_pubkey_bytes()
        );
    }

    #[test]
    #[allow(deprecated)] // Testing the v1 migration path
    fn backward_compat_keypair() {
        // from_bytes restores classic Ed25519 from a seed
        let kp = Keypair::generate_classic();
        let seed = kp.to_bytes();
        let kp2 = Keypair::from_bytes(seed);
        assert_eq!(kp.peer_id(), kp2.peer_id());
    }

    #[test]
    fn full_bytes_roundtrip() {
        // PQ keypair survives full serialization
        let kp = Keypair::generate();
        assert_eq!(kp.identity.signing_algo(), SigningAlgo::FalconEd25519);
        let bytes = kp.to_full_bytes();
        let kp2 = Keypair::from_full_bytes(&bytes).unwrap();
        assert_eq!(kp.peer_id(), kp2.peer_id());
        assert_eq!(kp2.identity.signing_algo(), SigningAlgo::FalconEd25519);
    }

    #[test]
    fn dht_id_deterministic() {
        let kp = Keypair::generate();
        assert_eq!(kp.dht_id(), kp.dht_id());
        assert_eq!(kp.dht_id(), dht_id_from_peer_id(&kp.peer_id()));
    }

    #[test]
    fn x25519_derivation() {
        let kp = Keypair::generate();
        let secret = kp.x25519_secret();
        let public = kp.x25519_public();
        assert_eq!(X25519Public::from(&secret), public);
    }

    #[test]
    fn verify_with_pubkey_checks_peer_id() {
        let kp = IdentityKeypair::generate_classic();
        let msg = b"check peer_id binding";
        let sig = kp.sign(msg);
        let pubkey = kp.signing.signing_pubkey_bytes();
        let pid = kp.peer_id();

        assert!(verify_with_pubkey(
            SigningAlgo::Ed25519,
            &pubkey,
            &pid,
            msg,
            &sig
        ));

        // Wrong PeerId should fail
        let wrong_pid = PeerId([0xFF; 32]);
        assert!(!verify_with_pubkey(
            SigningAlgo::Ed25519,
            &pubkey,
            &wrong_pid,
            msg,
            &sig
        ));
    }

    #[test]
    fn tlv_roundtrip() {
        let mut buf = Vec::new();
        let data = b"hello pubkey";
        write_tlv(&mut buf, 0x02, data);
        let mut offset = 0;
        let (algo, val) = read_tlv(&buf, &mut offset).unwrap();
        assert_eq!(algo, 0x02);
        assert_eq!(val, data);
        assert_eq!(offset, buf.len());
    }
}
