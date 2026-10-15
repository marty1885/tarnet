//! Address directory: where address records are placed among landmarks,
//! the store a landmark keeps, and turning a record into forwarding hints.
//! See "Addresses and the directory" in `docs/spec/routing.md`. Pure state;
//! the node does the I/O.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::types::PeerId;
use crate::wire::AddressRecord;

/// An address record whose signature has been checked, or that this node
/// signed itself. The directory store and address caches take only this, so
/// no path can keep a record nobody verified (the same rule as
/// [`crate::dht::VerifiedRecord`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAddress(AddressRecord);

impl VerifiedAddress {
    /// A received record, if its signature verifies.
    pub fn verify(record: AddressRecord) -> Option<Self> {
        record.verify().then_some(Self(record))
    }

    /// A received record, if it is `peer`'s and its signature verifies.
    pub fn verify_for(record: AddressRecord, peer: &PeerId) -> Option<Self> {
        if record.peer != *peer {
            return None;
        }
        Self::verify(record)
    }

    /// A record this node just signed.
    pub fn sign(
        keypair: &crate::identity::Keypair,
        seq: u32,
        ttl_secs: u32,
        entries: Vec<crate::wire::AddressEntry>,
    ) -> Self {
        Self(AddressRecord::sign(keypair, seq, ttl_secs, entries))
    }

    #[cfg(test)]
    fn signed_here(record: AddressRecord) -> Self {
        Self(record)
    }

    pub fn record(&self) -> &AddressRecord {
        &self.0
    }

    pub fn into_inner(self) -> AddressRecord {
        self.0
    }
}

/// Directory replicas per record (`R`).
pub const REPLICAS: u8 = 3;
/// Landmarks responsible for one replica (`SPREAD`).
pub const SPREAD: usize = 2;
/// Longest a landmark keeps a record, whatever its TTL says.
pub const MAX_ADDRESS_TTL: Duration = Duration::from_secs(6 * 3600);

fn placement_key(replica: u8, peer: &PeerId) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"tarnet dir v1");
    h.update(&[replica]);
    h.update(peer.as_bytes());
    *h.finalize().as_bytes()
}

fn landmark_key(landmark: &PeerId) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"tarnet dir v1");
    h.update(landmark.as_bytes());
    *h.finalize().as_bytes()
}

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// The landmarks responsible for replica `replica` of `peer`'s record:
/// the `SPREAD` closest by XOR between placement and landmark keys. If they
/// are all reached through one first hop, the closest landmark reached
/// through another first hop is added (direction diversity).
///
/// `landmarks` lists every accepted landmark with our first hop toward it
/// (a landmark itself lists itself).
pub fn responsible(peer: &PeerId, replica: u8, landmarks: &[(PeerId, PeerId)]) -> Vec<PeerId> {
    let key = placement_key(replica, peer);
    let mut ranked: Vec<(&PeerId, &PeerId, [u8; 32])> = landmarks
        .iter()
        .map(|(l, hop)| (l, hop, xor(&key, &landmark_key(l))))
        .collect();
    ranked.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(b.0)));
    ranked.dedup_by(|a, b| a.0 == b.0);
    let mut out: Vec<PeerId> = ranked.iter().take(SPREAD).map(|(l, _, _)| **l).collect();
    if let Some((_, first, _)) = ranked.first() {
        let one_way = ranked.iter().take(SPREAD).all(|(_, hop, _)| hop == first);
        if one_way {
            if let Some((l, _, _)) = ranked.iter().skip(SPREAD).find(|(_, hop, _)| hop != first) {
                out.push(**l);
            }
        }
    }
    out
}

/// Forwarding hints for a record: the entry whose landmark (or a later
/// path node) we reach most cheaply, as `[landmark, path...]`. `cost` gives
/// our route cost to a node, `None` when we have no route. Entries naming
/// us as landmark cost nothing.
pub fn hints_from(
    record: &AddressRecord,
    me: &PeerId,
    cost: impl Fn(&PeerId) -> Option<u32>,
) -> Vec<PeerId> {
    let reach = |p: &PeerId| if p == me { Some(0) } else { cost(p) };
    record
        .entries
        .iter()
        .filter_map(|e| {
            // A packet heads for the last hint it can reach, so an entry is
            // as good as its cheapest reachable node.
            let best = std::iter::once(&e.landmark)
                .chain(e.path.iter())
                .filter_map(reach)
                .min()?;
            Some((best, e))
        })
        .min_by_key(|(c, _)| *c)
        .map(|(_, e)| {
            std::iter::once(e.landmark)
                .chain(e.path.iter().copied())
                .collect()
        })
        .unwrap_or_default()
}

/// Verified address records a landmark stores: newest `seq` per peer, kept
/// until their TTL, bounded in number.
pub struct DirStore {
    records: HashMap<PeerId, (AddressRecord, Instant)>,
    /// Records that expired here: the highest dead seq per peer, and when to
    /// forget it. The TTL is relative and nodes share no clock, so a copy
    /// arriving later (a replay) can't be told stale by its TTL; a record
    /// that died here is never stored again unless its owner signs a higher
    /// seq. Remembered for `MAX_ADDRESS_TTL`, the longest any copy could live.
    dead: crate::bounded::BoundedMap<PeerId, u32>,
    max: usize,
}

impl DirStore {
    pub fn new(max: usize) -> Self {
        Self {
            records: HashMap::new(),
            dead: crate::bounded::BoundedMap::new(max.max(1), MAX_ADDRESS_TTL),
            max: max.max(1),
        }
    }

    /// Store a record the caller has verified. A repeat of the stored
    /// record is accepted but keeps the expiry already held (only a higher
    /// seq brings a new lifetime); an older one, a different record with the
    /// same seq, or one that expired here, is refused. When full, the record
    /// expiring soonest makes room if it expires before the new one.
    pub fn put(&mut self, record: VerifiedAddress, now: Instant) -> bool {
        let record = record.into_inner();
        let expires = now + Duration::from_secs(record.ttl_secs as u64).min(MAX_ADDRESS_TTL);
        if self.records.get(&record.peer).is_some_and(|(_, t)| *t <= now) {
            self.gc(now);
        }
        if record.ttl_secs == 0 {
            return false;
        }
        if self
            .dead
            .get(&record.peer)
            .is_some_and(|seq| record.seq <= *seq)
        {
            return false;
        }
        if let Some((old, _)) = self.records.get(&record.peer) {
            if old.seq > record.seq || (old.seq == record.seq && !old.same_version(&record)) {
                return false;
            }
            if old.same_version(&record) {
                return true;
            }
        } else if self.records.len() >= self.max {
            self.gc(now);
            if self.records.len() >= self.max {
                let (victim, at) = self
                    .records
                    .iter()
                    .min_by_key(|(_, (_, t))| *t)
                    .map(|(p, (_, t))| (*p, *t))
                    .expect("full store is non-empty");
                if at >= expires {
                    return false;
                }
                self.records.remove(&victim);
            }
        }
        self.records.insert(record.peer, (record, expires));
        true
    }

    pub fn get(&self, peer: &PeerId, now: Instant) -> Option<AddressRecord> {
        self.records
            .get(peer)
            .filter(|(_, t)| *t > now)
            .and_then(|(r, expires)| {
                let mut copy = r.clone();
                copy.ttl_secs = expires
                    .saturating_duration_since(now)
                    .as_secs()
                    .min(u32::MAX as u64) as u32;
                (copy.ttl_secs > 0).then_some(copy)
            })
    }

    pub fn gc(&mut self, now: Instant) {
        let mut gone = Vec::new();
        self.records.retain(|peer, (record, t)| {
            if *t > now {
                return true;
            }
            gone.push((*peer, record.seq));
            false
        });
        // Remembered for the full cap after each death, the latest included.
        for (peer, seq) in gone {
            let seq = self.dead.get(&peer).map_or(seq, |s| (*s).max(seq));
            let _ = self.dead.upsert(peer, seq);
        }
        self.dead.expire(now);
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn clear(&mut self) {
        self.records.clear();
    }
}

/// Resolver cache using the directory's version and expiry policy. Failed
/// paths are metadata on that version, never a reason to forget its lifetime.
pub(crate) struct AddressCache {
    store: DirStore,
    failed: HashMap<PeerId, (u32, Vec<PeerId>)>,
    max_age: Duration,
}

impl AddressCache {
    pub(crate) fn new(max: usize, max_age: Duration) -> Self {
        Self {
            store: DirStore::new(max),
            failed: HashMap::new(),
            max_age,
        }
    }

    pub(crate) fn put(&mut self, mut record: VerifiedAddress, now: Instant) -> bool {
        record.0.ttl_secs = record.0.ttl_secs.min(self.max_age.as_secs() as u32);
        let peer = record.0.peer;
        let seq = record.0.seq;
        if !self.store.put(record, now) {
            return false;
        }
        if self.failed.get(&peer).is_some_and(|(old, _)| *old != seq) {
            self.failed.remove(&peer);
        }
        self.gc(now);
        true
    }

    pub(crate) fn get(&self, peer: &PeerId, now: Instant) -> Option<AddressRecord> {
        let mut record = self.store.get(peer, now)?;
        if let Some((seq, failed)) = self.failed.get(peer) {
            if *seq == record.seq {
                record.entries.retain(|e| !failed.contains(&e.landmark));
            }
        }
        (!record.entries.is_empty()).then_some(record)
    }

    /// Mark the path actually used as failed; None invalidates every path.
    /// Return the sequence when every path is exhausted. The record remains
    /// held so a refetch cannot restart its deadline or clear its failures.
    pub(crate) fn fail(
        &mut self,
        peer: &PeerId,
        landmark: Option<PeerId>,
        now: Instant,
    ) -> Option<u32> {
        let record = self.store.get(peer, now)?;
        let (_, failed) = self.failed.entry(*peer).or_insert((record.seq, Vec::new()));
        if let Some(landmark) = landmark {
            if !failed.contains(&landmark) {
                failed.push(landmark);
            }
        } else {
            *failed = record.entries.iter().map(|e| e.landmark).collect();
        }
        self.get(peer, now).is_none().then_some(record.seq)
    }

    pub(crate) fn gc(&mut self, now: Instant) {
        self.store.gc(now);
        self.failed.retain(|peer, (seq, _)| {
            self.store
                .records
                .get(peer)
                .is_some_and(|(r, _)| r.seq == *seq)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;
    use crate::wire::AddressEntry;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn placement_is_deterministic_and_spread() {
        let landmarks: Vec<(PeerId, PeerId)> = (1..=10).map(|i| (pid(i), pid(100 + i))).collect();
        let peer = pid(42);
        let mut all = std::collections::HashSet::new();
        for replica in 0..REPLICAS {
            let a = responsible(&peer, replica, &landmarks);
            // Order and first hops of the input don't matter.
            let mut shuffled = landmarks.clone();
            shuffled.reverse();
            assert_eq!(a, responsible(&peer, replica, &shuffled));
            assert_eq!(a.len(), SPREAD);
            all.extend(a);
        }
        // Replicas land on different landmarks.
        assert!(all.len() > SPREAD, "replicas all on {:?}", all);
        // Another peer is placed elsewhere.
        let others: Vec<_> = (0..REPLICAS)
            .flat_map(|r| responsible(&pid(43), r, &landmarks))
            .collect();
        assert_ne!(
            others,
            (0..REPLICAS)
                .flat_map(|r| responsible(&peer, r, &landmarks))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn placement_adds_a_landmark_in_another_direction() {
        // Every landmark but one is behind the same first hop.
        let mut landmarks: Vec<(PeerId, PeerId)> = (1..=6).map(|i| (pid(i), pid(100))).collect();
        let peer = pid(42);
        let base = responsible(&peer, 0, &landmarks);
        assert_eq!(base.len(), SPREAD);
        let elsewhere = landmarks
            .iter()
            .find(|(l, _)| !base.contains(l))
            .map(|(l, _)| *l)
            .unwrap();
        for e in landmarks.iter_mut() {
            if e.0 == elsewhere {
                e.1 = pid(200);
            }
        }
        let diverse = responsible(&peer, 0, &landmarks);
        assert_eq!(&diverse[..SPREAD], &base[..]);
        assert_eq!(diverse.get(SPREAD), Some(&elsewhere));
        // Already diverse: nothing added.
        let two_ways: Vec<(PeerId, PeerId)> = base
            .iter()
            .enumerate()
            .map(|(i, l)| (*l, pid(150 + i as u8)))
            .chain(std::iter::once((elsewhere, pid(150))))
            .collect();
        assert_eq!(responsible(&peer, 0, &two_ways).len(), SPREAD);
    }

    #[test]
    fn too_few_landmarks() {
        assert!(responsible(&pid(1), 0, &[]).is_empty());
        assert_eq!(responsible(&pid(1), 0, &[(pid(2), pid(2))]), vec![pid(2)]);
    }

    fn record(kp: &Keypair, seq: u32, ttl: u32) -> VerifiedAddress {
        VerifiedAddress::signed_here(AddressRecord::sign(
            kp,
            seq,
            ttl,
            vec![AddressEntry {
                landmark: pid(1),
                path: vec![pid(2)],
            }],
        ))
    }

    #[test]
    fn store_keeps_newest_and_expires() {
        let kp = Keypair::generate_ed25519();
        let mut store = DirStore::new(16);
        let now = Instant::now();
        assert!(store.put(record(&kp, 5, 60), now));
        assert!(!store.put(record(&kp, 4, 60), now), "older seq accepted");
        assert!(store.put(record(&kp, 5, 60), now), "republish refused");
        assert!(store.put(record(&kp, 6, 60), now));
        assert_eq!(store.get(&kp.peer_id(), now).unwrap().seq, 6);
        let later = now + Duration::from_secs(61);
        assert!(store.get(&kp.peer_id(), later).is_none());
        store.gc(later);
        assert!(store.is_empty());
    }

    #[test]
    fn a_copy_never_extends_or_revives_a_record() {
        // A replay of the signed record arrives with its full TTL: it keeps
        // the expiry held, and once the record expired here, only a higher
        // seq is stored again.
        let kp = Keypair::generate_ed25519();
        let mut store = DirStore::new(16);
        let now = Instant::now();
        let rec = record(&kp, 5, 60);
        assert!(store.put(rec.clone(), now));
        assert!(store.put(rec.clone(), now + Duration::from_secs(50)), "repeat refused");
        let later = now + Duration::from_secs(61);
        assert!(store.get(&kp.peer_id(), later).is_none(), "repeat extended the record");
        assert!(!store.put(rec, later), "expired record revived");
        assert!(store.get(&kp.peer_id(), later).is_none());
        assert!(store.put(record(&kp, 6, 60), later), "newer seq refused");
    }

    #[test]
    fn store_is_bounded() {
        let mut store = DirStore::new(2);
        let now = Instant::now();
        let kps: Vec<Keypair> = (0..3).map(|_| Keypair::generate_ed25519()).collect();
        assert!(store.put(record(&kps[0], 1, 60), now));
        assert!(store.put(record(&kps[1], 1, 600), now));
        // Longer-lived than the soonest expiring: replaces it.
        assert!(store.put(record(&kps[2], 1, 300), now));
        assert_eq!(store.len(), 2);
        assert!(store.get(&kps[0].peer_id(), now).is_none());
        // Shorter-lived than everything stored: refused.
        assert!(!store.put(record(&kps[0], 2, 10), now));
    }

    #[test]
    fn hints_pick_the_cheapest_reachable_entry() {
        let kp = Keypair::generate_ed25519();
        let rec = AddressRecord::sign(
            &kp,
            1,
            60,
            vec![
                AddressEntry {
                    landmark: pid(1),
                    path: vec![pid(2), pid(3)],
                },
                AddressEntry {
                    landmark: pid(4),
                    path: vec![pid(5)],
                },
            ],
        );
        let me = pid(99);
        let costs = |table: Vec<(u8, u32)>| move |p: &PeerId| {
            table.iter().find(|(b, _)| pid(*b) == *p).map(|(_, c)| *c)
        };
        assert_eq!(
            hints_from(&rec, &me, costs(vec![(1, 5), (4, 3)])),
            vec![pid(4), pid(5)]
        );
        // A known path node makes its entry cheaper than its landmark.
        assert_eq!(
            hints_from(&rec, &me, costs(vec![(1, 5), (4, 3), (3, 1)])),
            vec![pid(1), pid(2), pid(3)]
        );
        // We are a landmark.
        assert_eq!(
            hints_from(&rec, &pid(4), costs(vec![(1, 2)])),
            vec![pid(4), pid(5)]
        );
        assert!(hints_from(&rec, &me, costs(vec![])).is_empty());
    }
}

#[cfg(test)]
mod lifetime_regressions {
    use super::*;
    use crate::identity::Keypair;

    #[test]
    fn replies_age_without_invalidating_signatures_or_extending_duplicates() {
        let kp = Keypair::generate_ed25519();
        let now = Instant::now();
        let mut store = DirStore::new(4);
        let record = VerifiedAddress::sign(&kp, 1, 60, Vec::new());
        assert!(store.put(record.clone(), now));
        let reply = store
            .get(&kp.peer_id(), now + Duration::from_secs(50))
            .unwrap();
        assert_eq!(reply.ttl_secs, 10);
        assert!(reply.verify());
        assert!(store.put(
            VerifiedAddress::verify(reply).unwrap(),
            now + Duration::from_secs(50)
        ));
        assert!(store
            .get(&kp.peer_id(), now + Duration::from_secs(61))
            .is_none());
        assert!(!store.put(record, now + Duration::from_secs(61)));
    }
}

#[cfg(test)]
mod cache_failure_regressions {
    use super::*;

    #[test]
    fn refetching_a_failed_version_cannot_restore_its_paths_or_deadline() {
        let kp = crate::identity::Keypair::generate_ed25519();
        let peer = kp.peer_id();
        let now = Instant::now();
        let landmark = PeerId([8; 32]);
        let entries = vec![crate::wire::AddressEntry {
            landmark,
            path: Vec::new(),
        }];
        let record = VerifiedAddress::sign(&kp, 1, 60, entries.clone());
        let mut cache = AddressCache::new(4, Duration::from_secs(3600));
        assert!(cache.put(record.clone(), now));
        assert_eq!(cache.fail(&peer, Some(landmark), now), Some(1));
        assert!(cache.put(record, now + Duration::from_secs(50)));
        assert!(cache.get(&peer, now + Duration::from_secs(50)).is_none());
        assert!(cache.put(
            VerifiedAddress::sign(&kp, 2, 60, entries),
            now + Duration::from_secs(50)
        ));
        assert_eq!(
            cache.get(&peer, now + Duration::from_secs(50)).unwrap().seq,
            2
        );
    }
}
