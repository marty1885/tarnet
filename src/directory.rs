//! Address directory: where address records are placed among landmarks,
//! the store a landmark keeps, and turning a record into forwarding hints.
//! See "Addresses and the directory" in `docs/spec/routing.md`. Pure state;
//! the node does the I/O.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::types::PeerId;
use crate::wire::AddressRecord;

/// Directory replicas per record (`R`).
pub const REPLICAS: u8 = 3;
/// Landmarks responsible for one replica (`SPREAD`).
pub const SPREAD: usize = 2;
/// Longest a landmark keeps a record, whatever its TTL says.
pub const MAX_RECORD_TTL: Duration = Duration::from_secs(6 * 3600);

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
    max: usize,
}

impl DirStore {
    pub fn new(max: usize) -> Self {
        Self {
            records: HashMap::new(),
            max: max.max(1),
        }
    }

    /// Store a record the caller has verified. A repeat of the stored
    /// record refreshes its expiry; an older one, or a different record
    /// with the same seq, is refused. When full, the record expiring
    /// soonest makes room if it expires before the new one.
    pub fn put(&mut self, record: AddressRecord, now: Instant) -> bool {
        let expires = now + Duration::from_secs(record.ttl_secs as u64).min(MAX_RECORD_TTL);
        if let Some((old, _)) = self.records.get(&record.peer) {
            if old.seq > record.seq || (old.seq == record.seq && *old != record) {
                return false;
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

    pub fn get(&self, peer: &PeerId, now: Instant) -> Option<&AddressRecord> {
        self.records
            .get(peer)
            .filter(|(_, t)| *t > now)
            .map(|(r, _)| r)
    }

    pub fn gc(&mut self, now: Instant) {
        self.records.retain(|_, (_, t)| *t > now);
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

    fn record(kp: &Keypair, seq: u32, ttl: u32) -> AddressRecord {
        AddressRecord::sign(
            kp,
            seq,
            ttl,
            vec![AddressEntry {
                landmark: pid(1),
                path: vec![pid(2)],
            }],
        )
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
