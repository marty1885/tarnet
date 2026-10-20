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

/// Messages per symmetric-ratchet epoch (`docs/spec/identity.md`, "Key
/// lifetime"): the key for counter `c` is the base key ratcheted `c >> 16`
/// times, and older epochs' keys are deleted.
pub(crate) const EPOCH_BITS: u32 = 16;
/// A receiver advances at most this many epochs for one message. Counters
/// are authenticated only after decryption, so a forged huge counter must
/// not cost unbounded hashing.
const MAX_EPOCH_JUMP: u64 = 4;

fn ratchet_step(key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("tarnet epoch v2", key)
}

/// One direction's traffic key under the symmetric epoch ratchet. Holds the
/// current epoch's key and, for receiving, the previous epoch's (reordered
/// stragglers); nothing older survives.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct Ratchet {
    #[zeroize(skip)]
    epoch: u64,
    key: [u8; 32],
    prev: Option<[u8; 32]>,
}

impl Ratchet {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self {
            epoch: 0,
            key,
            prev: None,
        }
    }

    pub(crate) fn epoch_of(counter: u64) -> u64 {
        counter >> EPOCH_BITS
    }

    /// The key to send counter `counter` under. Advances (sending counters
    /// only grow) and forgets older keys.
    pub(crate) fn send_key(&mut self, counter: u64) -> [u8; 32] {
        let target = Self::epoch_of(counter);
        while self.epoch < target {
            self.key = ratchet_step(&self.key);
            self.epoch += 1;
        }
        self.prev = None;
        self.key
    }

    /// The key a message with counter `counter` would decrypt under, without
    /// changing anything (the message isn't authenticated yet).
    pub(crate) fn recv_candidate(&self, counter: u64) -> Option<[u8; 32]> {
        let target = Self::epoch_of(counter);
        if target == self.epoch {
            return Some(self.key);
        }
        if target + 1 == self.epoch {
            return self.prev;
        }
        if target < self.epoch || target - self.epoch > MAX_EPOCH_JUMP {
            return None;
        }
        let mut key = self.key;
        for _ in self.epoch..target {
            key = ratchet_step(&key);
        }
        Some(key)
    }

    /// A message with counter `counter` decrypted: move to its epoch if it is
    /// newer, keeping only the epoch just before.
    pub(crate) fn commit(&mut self, counter: u64) {
        let target = Self::epoch_of(counter);
        while self.epoch < target {
            let next = ratchet_step(&self.key);
            self.prev = Some(self.key);
            self.key = next;
            self.epoch += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_matches_between_ends_and_forgets_old_epochs() {
        let e = 1u64 << EPOCH_BITS;
        let mut send = Ratchet::new([1; 32]);
        let mut recv = Ratchet::new([1; 32]);
        let k0 = send.send_key(5);
        assert_eq!(recv.recv_candidate(5), Some(k0));
        let k2 = send.send_key(2 * e + 1);
        assert_ne!(k0, k2);
        // The receiver jumps ahead on an authenticated message.
        assert_eq!(recv.recv_candidate(2 * e + 1), Some(k2));
        recv.commit(2 * e + 1);
        // One epoch back is still readable (reordering)...
        assert!(recv.recv_candidate(e + 7).is_some());
        // ...two epochs back is gone.
        assert_eq!(recv.recv_candidate(3), None);
        // A forged far-future counter costs nothing and is refused.
        assert_eq!(recv.recv_candidate(1000 * e), None);
        // Candidates don't change state.
        assert_eq!(recv.recv_candidate(2 * e), Some(k2));
    }

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
