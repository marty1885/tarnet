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

    /// The live entry for `key`, to change in place. Its age is kept: to
    /// record something again, restarting its lifetime, use
    /// [`upsert`](Self::upsert).
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

/// Bounded requests whose registrations are owned by the requesting future.
/// Dropping a request (including cancellation of a race's losing futures)
/// removes its waiter synchronously, without spawning cleanup work.
pub(crate) struct Requests<K, V> {
    entries: std::sync::Arc<std::sync::Mutex<BoundedMap<K, (std::sync::Arc<()>, V)>>>,
}

pub(crate) struct Request<K: Hash + Eq + Clone, V> {
    key: K,
    generation: std::sync::Arc<()>,
    entries: std::sync::Arc<std::sync::Mutex<BoundedMap<K, (std::sync::Arc<()>, V)>>>,
}

impl<K: Hash + Eq + Clone, V> Requests<K, V> {
    pub(crate) fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            entries: std::sync::Arc::new(std::sync::Mutex::new(BoundedMap::new(cap, ttl))),
        }
    }

    pub(crate) fn register(&self, key: K, value: V) -> Option<Request<K, V>> {
        let generation = std::sync::Arc::new(());
        self.entries
            .lock()
            .unwrap()
            .try_insert(key.clone(), (generation.clone(), value))
            .ok()?;
        Some(Request {
            key,
            generation,
            entries: self.entries.clone(),
        })
    }

    pub(crate) fn contains(&self, key: &K) -> bool {
        self.entries.lock().unwrap().contains_key(key)
    }

    /// Inspect a live request without consuming it.  Response handlers use
    /// this for their validation phase, then call [`take_if`](Self::take_if)
    /// only after the complete response has been accepted.
    pub(crate) fn inspect<R>(&self, key: &K, f: impl FnOnce(&V) -> R) -> Option<R> {
        let entries = self.entries.lock().unwrap();
        entries.get(key).map(|(_, value)| f(value))
    }

    pub(crate) fn take_if(&self, key: &K, accept: impl FnOnce(&V) -> bool) -> Option<V> {
        let mut entries = self.entries.lock().unwrap();
        if !entries.get(key).is_some_and(|(_, value)| accept(value)) {
            return None;
        }
        entries.remove(key).map(|(_, value)| value)
    }
}

impl<K: Hash + Eq + Clone, V> Drop for Request<K, V> {
    fn drop(&mut self) {
        let mut entries = self.entries.lock().unwrap();
        if entries
            .get(&self.key)
            .is_some_and(|(generation, _)| std::sync::Arc::ptr_eq(generation, &self.generation))
        {
            entries.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_releases_capacity_and_invalid_answers_do_not_consume_requests() {
        let requests = Requests::new(1, Duration::from_secs(30));
        let pending = async {
            let _registration = requests.register(1, "expected").unwrap();
            assert!(requests.register(2, "other").is_none());
            assert_eq!(requests.inspect(&1, |v| *v), Some("expected"));
            assert!(requests.contains(&1));
            assert!(requests.take_if(&1, |v| *v == "wrong").is_none());
            std::future::pending::<()>().await;
        };
        assert!(tokio::time::timeout(Duration::from_millis(1), pending)
            .await
            .is_err());
        assert!(!requests.contains(&1));
        let _registration = requests.register(2, "other").unwrap();
        assert_eq!(requests.take_if(&2, |_| true), Some("other"));
    }
}
