//! Landmarks and the address directory: electing ourselves as a landmark,
//! publishing our address record, storing records as a landmark, origin-less
//! lookups, and turning addresses into forwarding hints. Only active once
//! the routing table outgrows its budget; see "Landmarks" and "Addresses and
//! the directory" in `docs/spec/routing.md`.

use super::*;
use crate::directory::{self as dir, DirStore};
use crate::routing::LandmarkLimits;
use crate::wire::{
    capabilities, AddressEntry, AddressRecord, DirLookupMsg, DirPublishMsg, DirResultMsg,
    PathTraceMsg, PathTraceResultMsg, ADDRESS_ENTRIES_MAX, PATH_MAX, PATH_TRACE_MAX,
};

/// How often election and address upkeep run.
const DIR_TICK: Duration = Duration::from_secs(2);
/// Address record lifetime, and how often it is republished unchanged.
const ADDRESS_TTL: Duration = Duration::from_secs(3 * 3600);
const DIR_REPUBLISH: Duration = Duration::from_secs(3600);
/// A changed address is published after a random delay in this range.
const CHANGE_DELAY_MS: std::ops::Range<u64> = 1000..5000;
/// Paths to our landmarks are traced again this often even when nothing
/// visible changed (a change beyond our next hop is invisible to us).
const RETRACE_INTERVAL: Duration = Duration::from_secs(600);
/// How long a path trace may take, and how soon a failed one is retried.
const TRACE_TIMEOUT: Duration = Duration::from_secs(20);
const TRACE_RETRY: Duration = Duration::from_secs(15);
/// A published record is looked up at each landmark this long after
/// publishing, and sent again if the landmark doesn't have it (publishes
/// are unacknowledged and lossy links lose them). Checks back off, up to
/// `PUBLISH_CHECKS` of them.
const PUBLISH_CHECK_AFTER: Duration = Duration::from_secs(5);
const PUBLISH_CHECKS: usize = 4;
/// How long one lookup attempt waits, and attempts per replica.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
const LOOKUP_ATTEMPTS: usize = 2;
/// How long relays remember a lookup's previous hop.
const TOKEN_LIFETIME: Duration = Duration::from_secs(30);
/// Lookups a relay remembers at once.
const MAX_TOKENS: usize = 8192;
/// Records a landmark stores.
const DIR_STORE_MAX: usize = 65536;
/// Resolved addresses kept at most this long (their TTL may be shorter).
const CACHE_MAX_AGE: Duration = Duration::from_secs(3600);
/// A landmark whose hello denies the role is checked again after this,
/// then ignored for `LANDMARK_REJECT_FOR`. An unanswered check is retried
/// after `LANDMARK_UNKNOWN_RETRY`.
const LANDMARK_RECHECK: Duration = Duration::from_secs(60);
const LANDMARK_REJECT_FOR: Duration = Duration::from_secs(600);
const LANDMARK_UNKNOWN_RETRY: Duration = Duration::from_secs(300);
const HELLO_FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// After every entry of an address failed, the directory is skipped for
/// that peer this long in favour of route search.
const EXHAUSTED_FOR: Duration = Duration::from_secs(60);
/// Peers whose address, landmark verdict or failure we track, at once.
const MAX_TRACKED_PEERS: usize = 4096;
/// A landmark's hello is checked again after this long.
const VERIFIED_FOR: Duration = Duration::from_secs(3600);

/// Whether this node may be a landmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandmarkMode {
    /// When it qualifies: publishes an address, relays, stores DHT records,
    /// and has a link that isn't slow.
    Auto,
    /// Never (opting out always wins).
    Never,
    /// Whenever the network needs one, even if it fails the defaults.
    Always,
}

/// Landmark election and directory settings (local policy).
#[derive(Debug, Clone)]
pub struct LandmarkConfig {
    pub mode: LandmarkMode,
    /// An uncovered node waits a random delay up to this before promoting.
    pub promote_delay_max: Duration,
    /// A landmark holds the role at least this long.
    pub min_tenure: Duration,
    /// A landmark steps down only once its reason has held this long
    /// (twice this when only hash order decides), so a brief merge doesn't
    /// reshuffle landmarks; after stepping down it doesn't promote again for
    /// this long.
    pub hysteresis: Duration,
    /// A changed address is published at most this often.
    pub publish_gap: Duration,
    pub limits: LandmarkLimits,
}

impl Default for LandmarkConfig {
    fn default() -> Self {
        Self {
            mode: LandmarkMode::Auto,
            promote_delay_max: Duration::from_secs(60),
            min_tenure: Duration::from_secs(30 * 60),
            hysteresis: Duration::from_secs(10 * 60),
            publish_gap: Duration::from_secs(30),
            limits: LandmarkLimits::default(),
        }
    }
}

#[derive(Default)]
struct Role {
    since: Option<Instant>,
    promote_at: Option<Instant>,
    demoted_at: Option<Instant>,
    /// Since when we have had a reason to step down.
    crowded_since: Option<Instant>,
}

#[derive(Default)]
struct OwnAddress {
    seq: u32,
    entries: Vec<AddressEntry>,
    record: Option<AddressRecord>,
    published_at: Option<Instant>,
    /// Nearest landmarks and our next hop to each, when last traced.
    traced: Vec<(PeerId, PeerId)>,
    traced_at: Option<Instant>,
    /// Landmarks we could place on, when last published.
    placed: Vec<PeerId>,
    change_due: Option<Instant>,
}

/// A resolved address, and the landmarks whose entries failed us.
struct CachedAddress {
    record: AddressRecord,
    expires: Instant,
    failed: Vec<PeerId>,
}

impl CachedAddress {
    /// The record without the entries that failed.
    fn usable(&self) -> AddressRecord {
        let mut rec = self.record.clone();
        rec.entries.retain(|e| !self.failed.contains(&e.landmark));
        rec
    }
}

/// What a landmark's own hello says about its flag.
#[derive(Clone, Copy)]
enum Verification {
    Checking,
    Confirmed,
    /// No hello found; try again after this.
    Unknown(Instant),
    /// Hello denies the role; ignored until this.
    Rejected(Instant),
}

/// A lookup that passed us.
struct LookupPath {
    /// Where it came from: results go back there.
    prev: PeerId,
    /// It came through in the routed phase (not walking).
    routed: bool,
    /// Where we passed it on, last: results come only from there.
    next: Option<PeerId>,
}

pub(super) struct DirectoryState {
    config: std::sync::Mutex<LandmarkConfig>,
    client_only: std::sync::atomic::AtomicBool,
    role: Mutex<Role>,
    store: Mutex<DirStore>,
    own: Mutex<OwnAddress>,
    /// Resolved addresses.
    cache: Mutex<crate::bounded::BoundedMap<PeerId, CachedAddress>>,
    traces: Mutex<HashMap<[u8; 32], oneshot::Sender<Vec<PeerId>>>>,
    /// Lookup token → previous hop, whether it was routed (not walking)
    /// through us, and when.
    reverse: Mutex<crate::bounded::BoundedMap<[u8; 32], LookupPath>>,
    /// Our own lookups in flight: the answer, and the neighbour the lookup
    /// left through (only it may answer).
    waiters: Mutex<HashMap<[u8; 32], (oneshot::Sender<Option<AddressRecord>>, PeerId)>>,
    verified: Mutex<crate::bounded::BoundedMap<PeerId, Verification>>,
    /// Peers every entry of whose address failed us: the record's seq, and
    /// when. Until a newer record turns up, attempts use route search.
    exhausted: Mutex<crate::bounded::BoundedMap<PeerId, u32>>,
}

impl DirectoryState {
    pub(super) fn new() -> Self {
        Self {
            config: std::sync::Mutex::new(LandmarkConfig::default()),
            client_only: std::sync::atomic::AtomicBool::new(false),
            role: Mutex::new(Role::default()),
            store: Mutex::new(DirStore::new(DIR_STORE_MAX)),
            own: Mutex::new(OwnAddress::default()),
            cache: Mutex::new(crate::bounded::BoundedMap::new(MAX_TRACKED_PEERS, CACHE_MAX_AGE)),
            traces: Mutex::new(HashMap::new()),
            reverse: Mutex::new(crate::bounded::BoundedMap::new(MAX_TOKENS, TOKEN_LIFETIME)),
            waiters: Mutex::new(HashMap::new()),
            // A landmark's verdict is checked again after this long.
            verified: Mutex::new(crate::bounded::BoundedMap::new(MAX_TRACKED_PEERS, VERIFIED_FOR)),
            exhausted: Mutex::new(crate::bounded::BoundedMap::new(MAX_TRACKED_PEERS, EXHAUSTED_FOR)),
        }
    }

    fn config(&self) -> LandmarkConfig {
        self.config.lock().expect("config lock").clone()
    }
}

/// Two landmarks crowd each other: how long until we, promoted at `since`,
/// step down for `other`, first seen flagged at `other_seen`; `None` if we
/// stay. If `other` was flagged before we promoted, we are the younger and
/// both sides know it: we go after `hysteresis`. Otherwise neither side may
/// know who came first (after a merge each finds the other already flagged),
/// so both fall back to the same hash order, and its loser waits twice as
/// long, letting a younger side that does know go first.
fn crowded_wait(
    me: &PeerId,
    since: Instant,
    other: &PeerId,
    other_seen: Option<Instant>,
    hysteresis: Duration,
) -> Option<Duration> {
    if other_seen.is_some_and(|seen| seen + Duration::from_secs(1) < since) {
        return Some(hysteresis);
    }
    let tie = |p: &PeerId| blake3::hash(&[b"tarnet landmark tie".as_slice(), p.as_bytes()].concat());
    (tie(other).as_bytes() < tie(me).as_bytes()).then(|| hysteresis * 2)
}

impl Node {
    // ── Configuration ──

    /// Landmark election and directory settings.
    pub async fn set_landmark_config(&self, config: LandmarkConfig) {
        let requests = self
            .routing_table
            .lock()
            .await
            .set_landmark_limits(config.limits);
        *self.directory.config.lock().expect("config lock") = config;
        self.send_seqno_requests(requests).await;
    }

    /// A client-only node publishes no address, is never a landmark, and is
    /// not offered as a relay to sample walks.
    pub fn set_client_only(&self, on: bool) {
        self.directory
            .client_only
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_client_only(&self) -> bool {
        self.directory
            .client_only
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether we are a landmark now.
    pub async fn is_landmark(&self) -> bool {
        self.routing_table.lock().await.is_landmark()
    }

    /// The landmarks we accept.
    pub async fn landmarks(&self) -> Vec<PeerId> {
        self.routing_table
            .lock()
            .await
            .landmarks()
            .into_iter()
            .map(|(l, _)| l)
            .collect()
    }

    /// Our current address record, if we publish one.
    pub async fn own_address(&self) -> Option<AddressRecord> {
        if self.is_client_only() {
            return None;
        }
        self.directory.own.lock().await.record.clone()
    }

    /// Records we store as a landmark.
    pub async fn directory_size(&self) -> usize {
        self.directory.store.lock().await.len()
    }

    // ── Landmark election ──

    /// May we be a landmark: never if opted out or client-only; by default
    /// only if we store DHT records and have a link that isn't slow.
    pub(super) async fn landmark_eligible(&self) -> bool {
        if self.is_client_only() {
            return false;
        }
        match self.directory.config().mode {
            LandmarkMode::Never => false,
            LandmarkMode::Always => true,
            LandmarkMode::Auto => {
                self.dht_stores
                    && self
                        .links
                        .lock()
                        .await
                        .iter()
                        .any(|(_, l)| !l.is_slow())
            }
        }
    }

    /// Hello capability bits for the landmark role.
    pub(super) async fn landmark_capabilities(&self) -> u32 {
        let mut caps = 0;
        if self.landmark_eligible().await {
            caps |= capabilities::LANDMARK_ELIGIBLE;
        }
        if self.routing_table.lock().await.is_landmark() {
            caps |= capabilities::LANDMARK;
        }
        caps
    }

    /// One election step: promote when uncovered in a network bigger than
    /// our budget, step down once another landmark has crowded us (within
    /// half our radius) for long enough; see `crowded_wait`.
    /// Returns whether our role changed.
    async fn landmark_tick(&self) -> bool {
        let cfg = self.directory.config();
        let eligible = self.landmark_eligible().await;
        let me = self.peer_id();
        let now = Instant::now();
        let mut role = self.directory.role.lock().await;
        let mut rt = self.routing_table.lock().await;
        if rt.is_landmark() {
            let since = *role.since.get_or_insert(now);
            if !eligible {
                rt.set_landmark(false);
                role.since = None;
                role.crowded_since = None;
                role.demoted_at = Some(now);
                log::info!("No longer eligible: stepping down as landmark");
                return true;
            }
            // How long a reason to step down must hold before we act on it,
            // if there is one.
            let wait = if now.duration_since(since) < cfg.min_tenure {
                None
            } else if rt.is_complete() {
                Some(cfg.hysteresis)
            } else {
                rt.local_radius().and_then(|radius| {
                    rt.landmarks()
                        .iter()
                        .filter(|(_, r)| r.cost.saturating_mul(2) <= radius)
                        .filter_map(|(l, _)| crowded_wait(&me, since, l, rt.landmark_since(l), cfg.hysteresis))
                        .min()
                })
            };
            let Some(wait) = wait else {
                role.crowded_since = None;
                return false;
            };
            let crowded = *role.crowded_since.get_or_insert(now);
            if now.duration_since(crowded) >= wait {
                rt.set_landmark(false);
                role.since = None;
                role.crowded_since = None;
                role.demoted_at = Some(now);
                log::info!("Stepping down as landmark");
                return true;
            }
            return false;
        }
        let cooling = role
            .demoted_at
            .is_some_and(|t| now.duration_since(t) < cfg.hysteresis);
        if !eligible || cooling || rt.is_complete() || rt.is_covered() {
            role.promote_at = None;
            return false;
        }
        match role.promote_at {
            None => {
                use rand::Rng;
                let max = cfg.promote_delay_max.as_millis() as u64;
                let wait = rand::thread_rng().gen_range(0..=max);
                role.promote_at = Some(now + Duration::from_millis(wait));
                false
            }
            Some(t) if now >= t => {
                rt.set_landmark(true);
                role.since = Some(now);
                role.promote_at = None;
                log::info!("Uncovered in a network beyond our budget: becoming a landmark");
                true
            }
            Some(_) => false,
        }
    }

    // ── Placement ──

    /// Landmarks records can be placed on, with our first hop toward each
    /// (ourselves if we are one). Landmarks whose hello denies the role are
    /// left out; the rest are checked lazily.
    async fn placeable_landmarks(&self) -> Vec<(PeerId, PeerId)> {
        let me = self.peer_id();
        let (mut out, landmark) = {
            let rt = self.routing_table.lock().await;
            let out: Vec<(PeerId, PeerId)> = rt
                .landmarks()
                .into_iter()
                .map(|(l, r)| (l, r.next_hop))
                .collect();
            (out, rt.is_landmark())
        };
        let now = Instant::now();
        let mut to_check = Vec::new();
        {
            let mut verified = self.directory.verified.lock().await;
            out.retain(|(l, _)| match verified.get(l).copied() {
                Some(Verification::Rejected(until)) if until > now => false,
                Some(Verification::Rejected(_)) | None => {
                    let _ = verified.upsert(*l, Verification::Checking);
                    to_check.push(*l);
                    true
                }
                Some(Verification::Unknown(retry)) if retry <= now => {
                    let _ = verified.upsert(*l, Verification::Checking);
                    to_check.push(*l);
                    true
                }
                _ => true,
            });
        }
        if let Some(node) = self.weak_self.get().and_then(|w| w.upgrade()) {
            for l in to_check {
                let node = node.clone();
                tokio::spawn(async move { node.verify_landmark(l).await });
            }
        }
        if landmark {
            out.push((me, me));
        }
        out
    }

    /// Check a landmark's flag against its own hello. A hello that denies
    /// the role twice, `LANDMARK_RECHECK` apart (it may just be stale),
    /// gets the landmark ignored and the neighbour that advertised the flag
    /// a strike.
    async fn verify_landmark(&self, landmark: PeerId) {
        let says = |hello: &Option<HelloRecord>| {
            hello
                .as_ref()
                .map(|h| h.capabilities & capabilities::LANDMARK != 0)
        };
        let mut verdict = says(&self.fetch_hello(&landmark).await);
        if verdict == Some(false) {
            tokio::time::sleep(LANDMARK_RECHECK).await;
            verdict = says(&self.fetch_hello(&landmark).await);
        }
        let now = Instant::now();
        let state = match verdict {
            Some(true) => Verification::Confirmed,
            None => Verification::Unknown(now + LANDMARK_UNKNOWN_RETRY),
            Some(false) => {
                let still_flagged = self
                    .routing_table
                    .lock()
                    .await
                    .lookup(&landmark)
                    .filter(|r| r.landmark);
                if let Some(r) = still_flagged {
                    log::warn!(
                        "Landmark {:?} is not one by its own hello; ignoring it",
                        landmark
                    );
                    self.strike(r.next_hop).await;
                }
                Verification::Rejected(now + LANDMARK_REJECT_FOR)
            }
        };
        let _ = self.directory.verified.lock().await.upsert(landmark, state);
    }

    /// A peer's newest hello: searched for in the DHT first, so a stale
    /// copy in our store doesn't decide.
    async fn fetch_hello(&self, peer: &PeerId) -> Option<HelloRecord> {
        self.search_hello(peer, HELLO_FETCH_TIMEOUT, true).await
    }

    async fn strike(&self, peer: PeerId) {
        self.governor.lock().await.strike(peer);
    }

    // ── Our address ──

    /// Keep our address record current: trace the paths to our nearest
    /// landmarks, and publish when they or the landmark set change, else
    /// every `DIR_REPUBLISH`.
    async fn address_tick(&self) {
        if self.is_client_only() {
            return;
        }
        let me = self.peer_id();
        let cfg = self.directory.config();
        let (nearest, landmark) = {
            let rt = self.routing_table.lock().await;
            let mut nearest: Vec<(PeerId, PeerId)> = rt
                .landmarks()
                .into_iter()
                .map(|(l, r)| (l, r.next_hop))
                .collect();
            nearest.truncate(ADDRESS_ENTRIES_MAX - rt.is_landmark() as usize);
            (nearest, rt.is_landmark())
        };
        let mut wanted = nearest.clone();
        if landmark {
            wanted.insert(0, (me, me));
        }
        if wanted.is_empty() {
            return;
        }
        let now = Instant::now();
        let retrace = {
            let own = self.directory.own.lock().await;
            own.traced != wanted
                || own
                    .traced_at
                    .map_or(true, |t| now.duration_since(t) >= RETRACE_INTERVAL)
        };
        if retrace {
            let traces = nearest.iter().map(|(l, _)| self.trace_path(*l));
            let paths = futures_util::future::join_all(traces).await;
            let mut entries = Vec::new();
            if landmark {
                entries.push(AddressEntry {
                    landmark: me,
                    path: Vec::new(),
                });
            }
            for ((l, _), path) in nearest.iter().zip(paths) {
                // A trace lists us, the relays, then the landmark. The
                // address path runs the other way and excludes both ends.
                let Some(full) = path else { continue };
                let mut relays = full[1..full.len() - 1].to_vec();
                if relays.len() > PATH_MAX {
                    log::debug!("Landmark {:?} is {} hops away; not in our address", l, full.len() - 1);
                    continue;
                }
                relays.reverse();
                entries.push(AddressEntry {
                    landmark: *l,
                    path: relays,
                });
            }
            let mut own = self.directory.own.lock().await;
            // A lost trace is tried again soon, not at the next retrace.
            let all_traced = entries.len() == wanted.len();
            own.traced = wanted;
            own.traced_at = Some(if all_traced {
                Instant::now()
            } else {
                Instant::now() - RETRACE_INTERVAL + TRACE_RETRY
            });
            if entries != own.entries {
                own.entries = entries;
                if own.change_due.is_none() {
                    use rand::Rng;
                    let delay = rand::thread_rng().gen_range(CHANGE_DELAY_MS);
                    own.change_due = Some(Instant::now() + Duration::from_millis(delay));
                }
            }
        }

        let placeable = self.placeable_landmarks().await;
        let mut placed: Vec<PeerId> = placeable.iter().map(|(l, _)| *l).collect();
        placed.sort_unstable();
        let now = Instant::now();
        let record = {
            let mut own = self.directory.own.lock().await;
            if own.entries.is_empty() {
                return;
            }
            // When the landmark set changes, records move: republish.
            if placed != own.placed && own.change_due.is_none() {
                own.change_due = Some(now);
            }
            let gap_ok = own
                .published_at
                .map_or(true, |t| now.duration_since(t) >= cfg.publish_gap);
            let changed = own.change_due.is_some_and(|t| t <= now) && gap_ok;
            let stale = own
                .published_at
                .is_some_and(|t| now.duration_since(t) >= DIR_REPUBLISH);
            if !changed && !stale {
                return;
            }
            // Monotonic across restarts without a clock: persisted with the
            // node's other sequences.
            if own.seq == 0 {
                own.seq = self
                    .db
                    .as_ref()
                    .and_then(|db| db.get_metadata("address_sequence").ok().flatten())
                    .unwrap_or(0)
                    .min(u32::MAX as u64) as u32;
            }
            own.seq = own.seq.saturating_add(1);
            self.db_set_metadata("address_sequence", own.seq as u64);
            let record = AddressRecord::sign(
                &self.identity,
                own.seq,
                ADDRESS_TTL.as_secs() as u32,
                own.entries.clone(),
            );
            own.record = Some(record.clone());
            own.published_at = Some(now);
            own.change_due = None;
            own.placed = placed;
            record
        };
        self.publish_address(record, &placeable).await;
    }

    /// Send `record` to every responsible landmark of every replica, then
    /// check in the background that each landmark has it.
    async fn publish_address(&self, record: AddressRecord, placeable: &[(PeerId, PeerId)]) {
        let me = self.peer_id();
        let mut slots = Vec::new();
        for replica in 0..dir::REPLICAS {
            for landmark in dir::responsible(&me, replica, placeable) {
                if landmark == me {
                    self.directory
                        .store
                        .lock()
                        .await
                        .put(dir::VerifiedAddress::signed_here(record.clone()), Instant::now());
                    continue;
                }
                self.send_publish(landmark, replica, &record).await;
                slots.push((landmark, replica));
            }
        }
        log::info!(
            "Published address (seq {}, {} entries) to {} landmark slots",
            record.seq,
            record.entries.len(),
            slots.len() + self.routing_table.lock().await.is_landmark() as usize
        );
        if let Some(node) = self.weak_self.get().and_then(|w| w.upgrade()) {
            tokio::spawn(async move { node.check_published(record, slots).await });
        }
    }

    async fn send_publish(&self, landmark: PeerId, replica: u8, record: &AddressRecord) {
        let msg = DirPublishMsg {
            landmark,
            replica,
            record: record.clone(),
        };
        let next = self.sender.next_hop(&landmark, &[], None).await;
        if let Some(next) = next {
            let _ = self
                .send_to_peer_deferred(&next, &msg.to_wire().encode())
                .await;
        }
    }

    /// Look our record up at each landmark we sent it to, and send it again
    /// where it is missing or older. Stops once a newer record is
    /// published.
    async fn check_published(&self, record: AddressRecord, mut slots: Vec<(PeerId, u8)>) {
        let mut wait = PUBLISH_CHECK_AFTER;
        for _ in 0..PUBLISH_CHECKS {
            tokio::time::sleep(crate::types::jittered(wait)).await;
            let current = self
                .directory
                .own
                .lock()
                .await
                .record
                .as_ref()
                .is_some_and(|r| r.seq == record.seq);
            if !current || slots.is_empty() {
                return;
            }
            let checks = slots
                .iter()
                .map(|(l, replica)| self.lookup_at(*l, record.peer, *replica));
            let found = futures_util::future::join_all(checks).await;
            let mut missing = Vec::new();
            for ((landmark, replica), found) in slots.into_iter().zip(found) {
                if found.is_some_and(|r| r.record().seq >= record.seq) {
                    continue;
                }
                log::debug!(
                    "Landmark {:?} lacks our address (replica {}); sending it again",
                    landmark,
                    replica
                );
                self.send_publish(landmark, replica, &record).await;
                missing.push((landmark, replica));
            }
            slots = missing;
            wait *= 2;
        }
    }

    /// Look `target` up at `landmark` directly, without a walk. For checking
    /// our own record, which names us anyway.
    async fn lookup_at(&self, landmark: PeerId, target: PeerId, replica: u8) -> Option<dir::VerifiedAddress> {
        let next = self.sender.next_hop(&landmark, &[], None).await?;
        let token: [u8; 32] = rand::random();
        let (tx, rx) = oneshot::channel();
        self.directory.waiters.lock().await.insert(token, (tx, next));
        let msg = DirLookupMsg {
            walking: false,
            token,
            target,
            replica,
            landmark,
        };
        let _ = self
            .send_to_peer_deferred(&next, &msg.to_wire().encode())
            .await;
        let result = tokio::time::timeout(LOOKUP_TIMEOUT, rx).await;
        self.directory.waiters.lock().await.remove(&token);
        result
            .ok()?
            .ok()?
            .and_then(|r| dir::VerifiedAddress::verify_for(r, &target))
    }

    /// The nodes from us to `target` along our routes: us first, `target`
    /// last. `None` if the trace got no answer.
    async fn trace_path(&self, target: PeerId) -> Option<Vec<PeerId>> {
        let me = self.peer_id();
        let next = self.sender.next_hop(&target, &[], None).await?;
        let token: [u8; 32] = rand::random();
        let (tx, rx) = oneshot::channel();
        self.directory.traces.lock().await.insert(token, tx);
        let msg = PathTraceMsg {
            token,
            target,
            path: vec![me],
        };
        let _ = self
            .send_to_peer_deferred(&next, &msg.to_wire().encode())
            .await;
        let result = tokio::time::timeout(TRACE_TIMEOUT, rx).await;
        self.directory.traces.lock().await.remove(&token);
        let path = result.ok()?.ok()?;
        (path.len() >= 2 && path[0] == me && path.last() == Some(&target)).then_some(path)
    }

    pub(super) async fn handle_path_trace(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut msg = PathTraceMsg::from_bytes(payload)?;
        let me = self.peer_id();
        if msg.path.last() != Some(&from) || msg.path.contains(&me) || msg.path.len() >= PATH_TRACE_MAX {
            return Ok(());
        }
        msg.path.push(me);
        if msg.target == me {
            let back = PathTraceResultMsg {
                token: msg.token,
                path: msg.path,
            };
            return self
                .send_to_peer_deferred(&from, &back.to_wire().encode())
                .await;
        }
        let next = self.sender.next_hop(&msg.target, &[], Some(&from)).await;
        match next {
            Some(next) => {
                self.send_to_peer_deferred(&next, &msg.to_wire().encode())
                    .await
            }
            None => Ok(()),
        }
    }

    pub(super) async fn handle_path_trace_result(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = PathTraceResultMsg::from_bytes(payload)?;
        let me = self.peer_id();
        let Some(i) = msg.path.iter().position(|p| *p == me) else {
            return Ok(());
        };
        // It must come from the node after us on the path.
        if msg.path.get(i + 1) != Some(&from) {
            return Ok(());
        }
        if i == 0 {
            if let Some(tx) = self.directory.traces.lock().await.remove(&msg.token) {
                let _ = tx.send(msg.path);
            }
            return Ok(());
        }
        let prev = msg.path[i - 1];
        if !self.links.lock().await.contains_key(&prev) {
            return Ok(());
        }
        self.send_to_peer_deferred(&prev, &msg.to_wire().encode())
            .await
    }

    // ── The landmark's store ──

    pub(super) async fn handle_dir_publish(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = DirPublishMsg::from_bytes(payload)?;
        let me = self.peer_id();
        if msg.landmark == me {
            if !self.routing_table.lock().await.is_landmark() {
                return Ok(());
            }
            let Some(record) = dir::VerifiedAddress::verify(msg.record) else {
                return Ok(());
            };
            self.directory.store.lock().await.put(record, Instant::now());
            return Ok(());
        }
        let next = self.sender.next_hop(&msg.landmark, &[], Some(&from)).await;
        match next {
            Some(next) => {
                self.send_to_peer_deferred(&next, &msg.to_wire().encode())
                    .await
            }
            None => Ok(()),
        }
    }

    // ── Lookups ──

    /// Remember where a lookup came from. Returns false if it already came
    /// through us in the routed phase (a loop).
    async fn remember_lookup(&self, token: [u8; 32], from: PeerId, routed: bool) -> bool {
        let mut reverse = self.directory.reverse.lock().await;
        match reverse.get_mut(&token) {
            // A walk that passes us twice returns the first way it came,
            // which erases the loop.
            Some(path) => {
                if routed {
                    if path.routed {
                        return false;
                    }
                    path.routed = true;
                }
                true
            }
            None => reverse
                .try_insert(
                    token,
                    LookupPath {
                        prev: from,
                        routed,
                        next: None,
                    },
                )
                .is_ok(),
        }
    }

    /// Pass a lookup on to `next`, remembering that its result comes from
    /// there.
    async fn pass_lookup(&self, next: PeerId, msg: &DirLookupMsg) -> Result<()> {
        if let Some(path) = self.directory.reverse.lock().await.get_mut(&msg.token) {
            path.next = Some(next);
        }
        self.send_to_peer_deferred(&next, &msg.to_wire().encode())
            .await
    }

    async fn answer_lookup(&self, to: PeerId, token: [u8; 32], record: Option<AddressRecord>) -> Result<()> {
        // A node that is the origin answers itself.
        if let Some((tx, _)) = self.directory.waiters.lock().await.remove(&token) {
            let _ = tx.send(record);
            return Ok(());
        }
        let msg = DirResultMsg { token, record };
        self.send_to_peer_deferred(&to, &msg.to_wire().encode())
            .await
    }

    pub(super) async fn handle_dir_lookup(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut msg = DirLookupMsg::from_bytes(payload)?;
        let me = self.peer_id();
        if msg.walking {
            self.remember_lookup(msg.token, from, false).await;
            use rand::seq::SliceRandom;
            use rand::Rng;
            let others: Vec<PeerId> = self
                .links
                .lock()
                .await
                .keys()
                .copied()
                .filter(|p| *p != from)
                .collect();
            let end = others.is_empty() || rand::thread_rng().gen_bool(crate::dht::WALK_END_PROBABILITY);
            if !end {
                let next = *others.choose(&mut rand::thread_rng()).expect("non-empty");
                return self.pass_lookup(next, &msg).await;
            }
            // The walk ends here: route toward a responsible landmark.
            let placeable = self.placeable_landmarks().await;
            let responsible = dir::responsible(&msg.target, msg.replica, &placeable);
            let Some(landmark) = responsible.choose(&mut rand::thread_rng()).copied() else {
                return self.answer_lookup(from, msg.token, None).await;
            };
            msg.walking = false;
            msg.landmark = landmark;
        } else if !self.remember_lookup(msg.token, from, true).await {
            return Ok(());
        }

        if msg.landmark == me {
            let record = self
                .directory
                .store
                .lock()
                .await
                .get(&msg.target, Instant::now())
                .cloned();
            let record = match record {
                Some(r) => Some(r),
                None if msg.target == me => self.own_address().await,
                None => None,
            };
            return self.answer_lookup(from, msg.token, record).await;
        }
        // Passing through the node looked up: it answers for itself.
        if msg.target == me {
            if let Some(record) = self.own_address().await {
                return self.answer_lookup(from, msg.token, Some(record)).await;
            }
        }
        let next = self.sender.next_hop(&msg.landmark, &[], Some(&from)).await;
        match next {
            Some(next) => self.pass_lookup(next, &msg).await,
            None => self.answer_lookup(from, msg.token, None).await,
        }
    }

    /// A lookup's result: taken only from where the lookup went, so a node
    /// that saw the token can't answer in its place (or end the lookup with
    /// a forged "not found").
    pub(super) async fn handle_dir_result(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let msg = DirResultMsg::from_bytes(payload)?;
        // The result comes from where we last passed the lookup: our own
        // lookup's first hop, or, if its walk came back through us and we
        // passed it on again, that later hop.
        let passed_on = self
            .directory
            .reverse
            .lock()
            .await
            .get(&msg.token)
            .map(|path| (path.prev, path.next));
        {
            let mut waiters = self.directory.waiters.lock().await;
            if let Some((_, first)) = waiters.get(&msg.token) {
                let expected = passed_on.and_then(|(_, next)| next).unwrap_or(*first);
                if expected == from {
                    if let Some((tx, _)) = waiters.remove(&msg.token) {
                        let _ = tx.send(msg.record);
                    }
                    self.directory.reverse.lock().await.remove(&msg.token);
                }
                return Ok(());
            }
        }
        let prev = match passed_on {
            Some((prev, Some(next))) if next == from => {
                self.directory.reverse.lock().await.remove(&msg.token);
                Some(prev)
            }
            _ => None,
        };
        match prev {
            Some(prev) => {
                self.send_to_peer_deferred(&prev, &msg.to_wire().encode())
                    .await
            }
            None => Ok(()),
        }
    }

    /// One lookup of one replica: a walk from a random neighbour, then
    /// routed to a responsible landmark.
    async fn lookup_once(&self, target: PeerId, replica: u8) -> Option<dir::VerifiedAddress> {
        use rand::seq::SliceRandom;
        let first = {
            let links = self.links.lock().await;
            let peers: Vec<PeerId> = links.keys().copied().collect();
            *peers.choose(&mut rand::thread_rng())?
        };
        let token: [u8; 32] = rand::random();
        let (tx, rx) = oneshot::channel();
        self.directory.waiters.lock().await.insert(token, (tx, first));
        let msg = DirLookupMsg {
            walking: true,
            token,
            target,
            replica,
            landmark: PeerId([0; 32]),
        };
        let _ = self
            .send_to_peer_deferred(&first, &msg.to_wire().encode())
            .await;
        let result = tokio::time::timeout(LOOKUP_TIMEOUT, rx).await;
        self.directory.waiters.lock().await.remove(&token);
        result
            .ok()?
            .ok()?
            .and_then(|r| dir::VerifiedAddress::verify_for(r, &target))
    }

    /// Resolve `target`'s address: from the cache, else by lookups of
    /// every replica at once (each tried up to twice). The first verified
    /// answer wins.
    pub async fn lookup_address(&self, target: &PeerId) -> Option<AddressRecord> {
        if let Some(rec) = self.cached_address(target).await {
            return Some(rec);
        }
        use futures_util::stream::{FuturesUnordered, StreamExt};
        let mut lookups: FuturesUnordered<_> = (0..dir::REPLICAS)
            .map(|replica| async move {
                for _ in 0..LOOKUP_ATTEMPTS {
                    if let Some(rec) = self.lookup_once(*target, replica).await {
                        return Some(rec);
                    }
                }
                None
            })
            .collect();
        while let Some(found) = lookups.next().await {
            if let Some(rec) = found {
                self.cache_address(rec.clone()).await;
                return Some(rec.into_inner());
            }
        }
        None
    }

    /// A cached address, without the entries that failed us.
    async fn cached_address(&self, peer: &PeerId) -> Option<AddressRecord> {
        let now = Instant::now();
        self.directory
            .cache
            .lock()
            .await
            .get(peer)
            .filter(|c| c.expires > now)
            .map(|c| c.usable())
    }

    /// Keep a verified address until it expires (at most `CACHE_MAX_AGE`).
    /// A newer seq replaces an older one; the same record again keeps the
    /// expiry held (its TTL is relative, so a copy can't extend it).
    pub(super) async fn cache_address(&self, rec: dir::VerifiedAddress) {
        let rec = rec.into_inner();
        let expires = Instant::now()
            + Duration::from_secs(rec.ttl_secs as u64).min(CACHE_MAX_AGE);
        let mut cache = self.directory.cache.lock().await;
        match cache.get_mut(&rec.peer) {
            Some(c) if c.record.seq >= rec.seq => {}
            _ => {
                let _ = cache.upsert(
                    rec.peer,
                    CachedAddress {
                        record: rec,
                        expires,
                        failed: Vec::new(),
                    },
                );
            }
        }
    }

    /// A build using `peer`'s address failed: stop using the entry we used,
    /// so the next attempt tries another. With none left, the address is
    /// dropped and the next attempt looks it up again.
    pub(super) async fn forget_address(&self, peer: &PeerId) {
        let me = self.peer_id();
        let used = {
            let cache = self.directory.cache.lock().await;
            let Some(c) = cache.get(peer) else {
                // The hints came from a route search, if any.
                drop(cache);
                self.forget_search(peer).await;
                return;
            };
            let rt = self.routing_table.lock().await;
            dir::hints_from(&c.usable(), &me, |p| rt.lookup(p).map(|r| r.cost))
                .first()
                .copied()
        };
        let mut cache = self.directory.cache.lock().await;
        let Some(c) = cache.get_mut(peer) else { return };
        if let Some(landmark) = used {
            c.failed.push(landmark);
        }
        if used.is_none() || c.usable().entries.is_empty() {
            let seq = c.record.seq;
            cache.remove(peer);
            drop(cache);
            let _ = self.directory.exhausted.lock().await.upsert(*peer, seq);
        }
    }

    /// Hints from an address we already hold, if one leads somewhere we
    /// can reach.
    pub(super) async fn cached_hints(&self, peer: &PeerId) -> Vec<PeerId> {
        let Some(rec) = self.cached_address(peer).await else {
            return Vec::new();
        };
        let me = self.peer_id();
        let rt = self.routing_table.lock().await;
        dir::hints_from(&rec, &me, |p| rt.lookup(p).map(|r| r.cost))
    }

    /// Hints toward `peer` we already hold, from its address or a route
    /// search, without asking the network.
    pub(super) async fn known_hints(&self, peer: &PeerId) -> Vec<PeerId> {
        let hints = self.cached_hints(peer).await;
        if !hints.is_empty() {
            return hints;
        }
        self.searched_hints(peer).await
    }

    /// Forwarding hints toward `peer`: none if we reach it already,
    /// else from its address (resolved if need be), else from a route
    /// search. The search runs even when our table looks complete: a node
    /// at the edge of a scoped network holds no more than its budget and
    /// can't tell its view is partial.
    pub(super) async fn address_hints(&self, peer: &PeerId) -> Vec<PeerId> {
        if *peer == self.peer_id()
            || self.links.lock().await.contains_key(peer)
            || self.routing_table.lock().await.lookup(peer).is_some()
        {
            return Vec::new();
        }
        let hints = self.cached_hints(peer).await;
        if !hints.is_empty() {
            return hints;
        }
        let hints = self.searched_hints(peer).await;
        if !hints.is_empty() {
            return hints;
        }
        // The directory first; then a route search. A record no newer than
        // one that just failed us in every entry doesn't count.
        let failed_seq = self
            .directory
            .exhausted
            .lock()
            .await
            .get(peer)
            .copied();
        // With no landmark there is no directory to ask.
        let directory = self.routing_table.lock().await.is_landmark()
            || !self.routing_table.lock().await.landmarks().is_empty();
        if directory {
            if let Some(rec) = self.lookup_address(peer).await {
                if failed_seq.is_some_and(|s| rec.seq <= s) {
                    self.directory.cache.lock().await.remove(peer);
                } else {
                    self.directory.exhausted.lock().await.remove(peer);
                    let hints = self.cached_hints(peer).await;
                    if !hints.is_empty() {
                        return hints;
                    }
                }
            }
        }
        self.route_search(peer).await.unwrap_or_default()
    }

    // ── Upkeep ──

    pub(super) fn spawn_directory_task(&self, node: Arc<Node>) {
        tokio::spawn(async move {
            let mut interval = jittered_interval(DIR_TICK);
            loop {
                interval.tick().await;
                if node.landmark_tick().await {
                    // The role is in our hello: verifiers read it there.
                    let n = node.clone();
                    tokio::spawn(async move { n.publish_hello().await });
                }
                let strikes = node.routing_table.lock().await.take_flag_strikes();
                for peer in strikes {
                    node.strike(peer).await;
                }
                node.address_tick().await;
                let now = Instant::now();
                node.directory.store.lock().await.gc(now);
                node.directory.reverse.lock().await.expire(now);
                node.directory.cache.lock().await.retain(|_, c| c.expires > now);
                node.directory.exhausted.lock().await.expire(now);
                node.directory.verified.lock().await.expire(now);
                if !node.routing_table.lock().await.is_landmark() {
                    node.directory.store.lock().await.clear();
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u8) -> PeerId {
        PeerId([n; 32])
    }

    #[test]
    fn exactly_one_of_two_crowded_landmarks_steps_down() {
        let h = Duration::from_secs(600);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(100);
        let (a, b) = (pid(1), pid(2));
        // a promoted at t0; b promoted at t1 having seen a flagged: b knows
        // it is younger and goes after h. a doesn't know (it found b flagged
        // after its own promotion): hash order, the loser waits 2h.
        assert_eq!(crowded_wait(&b, t1, &a, Some(t0), h), Some(h));
        let a_wait = crowded_wait(&a, t0, &b, Some(t1), h);
        assert!(a_wait.is_none() || a_wait == Some(2 * h));
        // After a merge each finds the other already flagged: exactly one
        // loses the hash order.
        let merge = t1 + Duration::from_secs(1000);
        let wa = crowded_wait(&a, t0, &b, Some(merge), h);
        let wb = crowded_wait(&b, t1, &a, Some(merge), h);
        assert_eq!(wa.is_some() as u8 + wb.is_some() as u8, 1);
        assert_eq!(wa.or(wb), Some(2 * h));
    }
}
