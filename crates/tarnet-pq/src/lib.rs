//! Non-generic wrappers over ML-KEM-768, ML-DSA-44 and SLH-DSA-SHA2-128s.
//!
//! The RustCrypto implementations are generic, so their code is compiled in
//! whichever crate instantiates them. Instantiating them here, behind plain
//! functions, lets this one crate be built optimised in debug profiles too:
//! unoptimised, an SLH-DSA key generation takes about half a second.

use zeroize::Zeroizing;

pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const MLDSA44_PK_LEN: usize = 1312;
pub const SLHDSA128S_PK_LEN: usize = 32;

/// An ML-KEM-768 decapsulation key (FIPS 203).
#[derive(Clone)]
pub struct MlKem768Dk(Box<ml_kem::DecapsulationKey768>);

impl MlKem768Dk {
    /// ML-KEM.KeyGen_internal from the 64-byte seed `d || z`.
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        let seed = ml_kem::Seed::try_from(&seed[..]).expect("64-byte seed");
        Self(Box::new(ml_kem::DecapsulationKey768::from_seed(seed)))
    }

    /// The encapsulation key, encoded (1184 bytes).
    pub fn encapsulation_key(&self) -> Vec<u8> {
        use ml_kem::KeyExport as _;
        self.0.encapsulation_key().to_bytes().to_vec()
    }

    /// Decapsulate a 1088-byte ciphertext. `None` if it has the wrong length;
    /// a well-formed but wrong ciphertext gives an unrelated secret (implicit
    /// rejection), as FIPS 203 specifies.
    pub fn decapsulate(&self, ct: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        use ml_kem::Decapsulate as _;
        let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(ct).ok()?;
        Some(Zeroizing::new(self.0.decapsulate(&ct).into()))
    }
}

/// Encapsulate to an encoded ML-KEM-768 key with the 32 random bytes `m`.
/// Returns `(ciphertext, shared_secret)`, or `None` if the key fails the
/// FIPS 203 input check.
pub fn mlkem768_encapsulate(ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let ek = ml_kem::Key::<ml_kem::EncapsulationKey768>::try_from(ek).ok()?;
    let ek = ml_kem::EncapsulationKey768::new(&ek).ok()?;
    let (ct, ss) = ek.encapsulate_deterministic(&ml_kem::B32::from(*m));
    Some((ct.to_vec(), Zeroizing::new(ss.into())))
}

/// The ML-DSA-44 public key for seed `xi` (FIPS 204 KeyGen_internal).
pub fn mldsa44_public(xi: &[u8; 32]) -> Vec<u8> {
    use ml_dsa::Keypair as _;
    let xi = ml_dsa::Seed::try_from(&xi[..]).expect("32-byte seed");
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&xi);
    sk.verifying_key().encode().to_vec()
}

/// The SLH-DSA-SHA2-128s public key for (SK.seed, SK.prf, PK.seed)
/// (FIPS 205 slh_keygen_internal).
pub fn slhdsa128s_public(sk_seed: &[u8; 16], sk_prf: &[u8; 16], pk_seed: &[u8; 16]) -> Vec<u8> {
    let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
    let vk: &slh_dsa::VerifyingKey<slh_dsa::Sha2_128s> = sk.as_ref();
    vk.to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_roundtrip_and_sizes() {
        let dk = MlKem768Dk::from_seed(&[7; 64]);
        let ek = dk.encapsulation_key();
        assert_eq!(ek.len(), MLKEM768_EK_LEN);
        let (ct, ss) = mlkem768_encapsulate(&ek, &[9; 32]).unwrap();
        assert_eq!(ct.len(), MLKEM768_CT_LEN);
        assert_eq!(*dk.decapsulate(&ct).unwrap(), *ss);
        assert!(dk.decapsulate(&ct[1..]).is_none());
        assert!(mlkem768_encapsulate(&ek[1..], &[9; 32]).is_none());
    }

    #[test]
    fn backup_keys_are_deterministic() {
        assert_eq!(mldsa44_public(&[1; 32]), mldsa44_public(&[1; 32]));
        assert_eq!(mldsa44_public(&[1; 32]).len(), MLDSA44_PK_LEN);
        let a = slhdsa128s_public(&[1; 16], &[2; 16], &[3; 16]);
        assert_eq!(a.len(), SLHDSA128S_PK_LEN);
        assert_eq!(a, slhdsa128s_public(&[1; 16], &[2; 16], &[3; 16]));
    }
}
