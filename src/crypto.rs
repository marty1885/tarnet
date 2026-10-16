//! Shared cryptographic utilities used across link, tunnel, and circuit layers.

use std::{mem::MaybeUninit, ops::Deref};
use zeroize::Zeroize;

/// Own a foreign, copyable secret whose type does not implement Zeroize.
/// In particular, pqcrypto exposes immutable byte views only. MaybeUninit lets
/// us erase the storage on drop without leaving an invalid value of T behind.
#[repr(transparent)]
pub(crate) struct Wiping<T: Copy>(MaybeUninit<T>);

impl<T: Copy> Wiping<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(MaybeUninit::new(value))
    }
}

impl<T: Copy> Deref for Wiping<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: new initializes T; storage is erased only during Drop.
        unsafe { self.0.assume_init_ref() }
    }
}

impl<T: Copy> Drop for Wiping<T> {
    fn drop(&mut self) {
        // MaybeUninit implements Zeroize without requiring mutable access to
        // T's private fields. Copy excludes a destructor we would need to run.
        self.0.zeroize();
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_secret_storage_is_erased_on_drop() {
        let mut storage = MaybeUninit::new(Wiping::new([0xabu8; 32]));
        // SAFETY: storage is initialized and is dropped exactly once. Its outer
        // MaybeUninit keeps the allocation alive for inspection after Drop;
        // repr(transparent) gives the byte-array storage the same layout.
        unsafe {
            assert_eq!(&**storage.assume_init_ref(), &[0xab; 32]);
            std::ptr::drop_in_place(storage.as_mut_ptr());
            let erased = std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), 32);
            assert_eq!(erased, &[0; 32]);
        }
    }
}
