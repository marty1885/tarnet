//! Shared cryptographic utilities used across link, tunnel, and circuit layers.

/// Key derivation: BLAKE3 derive_key mode.
///
/// Uses BLAKE3's purpose-built key derivation with a context string,
/// replacing the previous BLAKE2b-MAC(key=secret, msg=label) construction.
pub(crate) fn kdf(secret: &[u8; 32], context: &str) -> [u8; 32] {
    blake3::derive_key(context, secret)
}

/// 16-byte keyed MAC (XOF truncation) over multiple inputs.
pub(crate) fn mac_16(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 16] {
    let mut h = blake3::Hasher::new_keyed(key);
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 16];
    h.finalize_xof().fill(&mut out);
    out
}
