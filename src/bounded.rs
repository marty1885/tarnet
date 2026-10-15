//! Per-node state that untrusted peers make us allocate: maps whose entries
//! expire after a fixed time and whose size is capped.
//!
//! The cap is enforced here, by the one way in ([`BoundedMap::try_insert`]),
//! rather than by each caller: a caller can't forget it, can't check it in
//! one critical section and insert in another, and a full map refuses new
//! entries instead of growing.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Why an entry was not added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The key is already held (and live).
    Duplicate,
    /// The map is full of live entries.
    Full,
}

/// A map of at most `cap` entries, each forgotten `ttl` after it was added.
#[derive(Debug)]
pub struct BoundedMap<K, V> {
    entries: HashMap<K, (V, Instant)>,
    cap: usize,
    ttl: Duration,
}

impl<K: Hash + Eq, V> BoundedMap<K, V> {
    pub fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            cap,
            ttl,
        }
    }

    /// Add `key` unless it is held or the map is full of live entries.
    pub fn try_insert(&mut self, key: K, value: V) -> Result<(), Refused> {
        let now = Instant::now();
        if self.live(&key, now) {
            return Err(Refused::Duplicate);
        }
        if self.entries.len() >= self.cap {
            self.expire(now);
            if self.entries.len() >= self.cap {
                return Err(Refused::Full);
            }
        }
        self.entries.insert(key, (value, now));
        Ok(())
    }

    /// Add or replace `key`'s entry, restarting its lifetime; refused only
    /// for a new key when the map is full.
    pub fn upsert(&mut self, key: K, value: V) -> Result<(), Refused> {
        let now = Instant::now();
        if !self.entries.contains_key(&key) && self.entries.len() >= self.cap {
            self.expire(now);
            if self.entries.len() >= self.cap {
                return Err(Refused::Full);
            }
        }
        self.entries.insert(key, (value, now));
        Ok(())
    }

    /// The live entry for `key`.
    pub fn get(&self, key: &K) -> Option<&V> {
        let now = Instant::now();
        self.entries
            .get(key)
            .filter(|(_, at)| now.duration_since(*at) < self.ttl)
            .map(|(v, _)| v)
    }

    /// The live entry for `key`, to change in place (its age is kept).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let now = Instant::now();
        let ttl = self.ttl;
        self.entries
            .get_mut(key)
            .filter(|(_, at)| now.duration_since(*at) < ttl)
            .map(|(v, _)| v)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Remove `key`, returning its entry if it was live.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let now = Instant::now();
        let ttl = self.ttl;
        self.entries
            .remove(key)
            .filter(|(_, at)| now.duration_since(*at) < ttl)
            .map(|(v, _)| v)
    }

    /// Drop entries older than the ttl.
    pub fn expire(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.entries.retain(|_, (_, at)| now.duration_since(*at) < ttl);
    }

    /// Restart `key`'s lifetime (it was used); false if it isn't live.
    pub fn touch(&mut self, key: &K) -> bool {
        let now = Instant::now();
        let ttl = self.ttl;
        match self.entries.get_mut(key) {
            Some((_, at)) if now.duration_since(*at) < ttl => {
                *at = now;
                true
            }
            _ => false,
        }
    }

    /// Remove and return the expired entries, for state whose expiry has
    /// consequences (e.g. tearing down what it stood for).
    pub fn drain_expired(&mut self, now: Instant) -> Vec<(K, V)>
    where
        K: Clone,
    {
        let ttl = self.ttl;
        let dead: Vec<K> = self
            .entries
            .iter()
            .filter(|(_, (_, at))| now.duration_since(*at) >= ttl)
            .map(|(k, _)| k.clone())
            .collect();
        dead.into_iter()
            .filter_map(|k| self.entries.remove(&k).map(|(v, _)| (k, v)))
            .collect()
    }

    /// Live entries.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let now = Instant::now();
        let ttl = self.ttl;
        self.entries
            .iter()
            .filter(move |(_, (_, at))| now.duration_since(*at) < ttl)
            .map(|(k, (v, _))| (k, v))
    }

    /// Keep only the entries `keep` accepts (expired ones go too).
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.entries
            .retain(|k, (v, at)| now.duration_since(*at) < ttl && keep(k, v));
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Entries held, live or not yet expired away.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn live(&self, key: &K, now: Instant) -> bool {
        self.entries
            .get(key)
            .is_some_and(|(_, at)| now.duration_since(*at) < self.ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_holds_and_expired_entries_make_room() {
        let mut m = BoundedMap::new(2, Duration::from_millis(20));
        assert_eq!(m.try_insert(1, 'a'), Ok(()));
        assert_eq!(m.try_insert(1, 'b'), Err(Refused::Duplicate));
        assert_eq!(m.try_insert(2, 'b'), Ok(()));
        assert_eq!(m.try_insert(3, 'c'), Err(Refused::Full));
        assert_eq!(m.len(), 2);
        std::thread::sleep(Duration::from_millis(30));
        assert!(m.get(&1).is_none(), "expired entry still returned");
        assert_eq!(m.try_insert(3, 'c'), Ok(()));
        assert_eq!(m.get(&3), Some(&'c'));
        assert!(m.len() <= 2);
    }
}
