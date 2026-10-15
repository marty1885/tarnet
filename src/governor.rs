//! Resource governor: per-link-peer budgeting with load-adaptive enforcement.
//!
//! Always active but zero-cost when idle.  Budgets live as long as a
//! peer's links; strikes and blocks belong to the identity and outlive them.
//!
//! Design principles:
//!   - Key on link peers only (bounded by physical connections)
//!   - Generous by default, strict under load (GNUnet excess/scarcity)
//!   - Kill stalest circuits first under memory pressure (Tor OOM)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::types::PeerId;
use crate::wire::MessageType;

// ── Constants ───────────────────────────────────────────────────────

/// How often the governor tick runs (strike decay, window reset).
pub const GOVERNOR_TICK_INTERVAL: Duration = Duration::from_secs(10);

/// Strikes halve after this much time with no new strikes.
const STRIKE_DECAY_INTERVAL: Duration = Duration::from_secs(300);

// ── Configuration ───────────────────────────────────────────────────

/// Per-peer work a link peer can make us do, each with its own budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// A circuit leg installed here (CREATE, or EXTEND at a relay).
    CircuitCreate,
    /// DHT reverse-path state and forwarding (GET, WATCH).
    DhtQuery,
    /// DHT records to verify and maybe store (PUT, notify, GET response).
    DhtRecords,
    /// The bytes of those records.
    DhtBytes,
    /// Directory work: publishes, lookups, path traces and their answers.
    Directory,
    /// Sample walks and their results.
    Sample,
    /// Route-search floods and their answers.
    RouteSearch,
    /// Seqno requests (each allocates dedup state and may be forwarded).
    RouteRequest,
    /// Tunnel key exchanges: a signature check and a KEM each.
    TunnelKex,
}

impl Resource {
    const COUNT: usize = 9;

    fn index(self) -> usize {
        self as usize
    }
}

/// What a message costs its link peer. Every message type has one (see
/// [`message_cost`]), so a new type can't arrive unbudgeted.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cost {
    /// Link upkeep, routing state bounded by its own caps, or forwarding
    /// bounded by link bandwidth.
    Free,
    /// Charged before the handler runs.
    Charge(&'static [Resource]),
    /// DHT records: a count and their bytes.
    Records { records: u32, bytes: usize },
    /// Charged by the handler, which can tell new work from a resend: the
    /// named resource, through [`Governor::admit_circuit`].
    ByHandler(Resource),
}

/// The cost of every message type. Exhaustive on purpose: no wildcard.
pub fn message_cost(mt: MessageType, payload: &[u8]) -> Cost {
    use MessageType as M;
    use Resource as R;
    match mt {
        M::HandshakeHello | M::HandshakeAuth | M::HandshakeConfirm | M::Rekey | M::Keepalive => Cost::Free,
        // Bounded by the routing table's own caps, and rate-limited by the
        // sender's batching; dropping them would break convergence.
        M::RouteUpdate | M::RouteDigest => Cost::Free,
        M::RouteRequest => Cost::Charge(&[R::RouteRequest]),
        M::DirPublish | M::DirLookup | M::DirResult | M::PathTrace | M::PathTraceResult => {
            Cost::Charge(&[R::Directory])
        }
        M::RouteSearch | M::RouteSearchFound => Cost::Charge(&[R::RouteSearch]),
        M::SampleWalk | M::SampleResult => Cost::Charge(&[R::Sample]),
        M::DhtGet | M::DhtWatch => Cost::Charge(&[R::DhtQuery]),
        M::DhtPut | M::DhtWatchNotify => Cost::Records {
            records: 1,
            bytes: payload.len(),
        },
        M::DhtGetResponse => Cost::Records {
            records: crate::wire::DhtGetResponseMsg::record_count(payload) as u32,
            bytes: payload.len(),
        },
        M::DhtNeighbor => Cost::Free,
        M::TunnelKeyExchange | M::TunnelKeyResponse => Cost::Charge(&[R::TunnelKex]),
        // Only valid inside tunnels; dropped if they arrive on a link.
        M::ChannelOpen | M::ChannelData | M::ChannelAck | M::ChannelClose => Cost::Free,
        // Forwarding, bounded by link bandwidth. A key exchange carried
        // inside a Data message is re-evaluated as one by its handler.
        M::Data | M::EncryptedData => Cost::Free,
        M::CircuitCreate => Cost::ByHandler(R::CircuitCreate),
        M::CircuitCreated | M::CircuitRelay | M::CircuitDestroy => Cost::Free,
    }
}

/// Governor tuning knobs.
#[derive(Debug, Clone)]
pub struct GovernorConfig {
    /// Hard cap on circuits involving any single link peer.
    pub max_circuits_per_peer: usize,
    /// Refill rate (per second) and burst of each [`Resource`], per link peer.
    pub circuit_creates: (f64, f64),
    pub dht_queries: (f64, f64),
    pub dht_records: (f64, f64),
    pub dht_bytes: (f64, f64),
    pub directory: (f64, f64),
    pub sample: (f64, f64),
    pub route_search: (f64, f64),
    pub route_requests: (f64, f64),
    pub tunnel_kex: (f64, f64),
    /// Total circuit capacity of this node (for pressure calculation).
    pub max_circuits: usize,
    /// Pressure level below which no enforcement happens (0.0–1.0).
    pub pressure_threshold: f64,
    /// Strikes before transitioning to Throttled.
    pub throttle_strikes: u16,
    /// Strikes before transitioning to Blocked.
    pub block_strikes: u16,
    /// How long a Block lasts before decaying to Throttled.
    pub block_duration: Duration,
}

impl GovernorConfig {
    fn limit(&self, r: Resource) -> (f64, f64) {
        match r {
            Resource::CircuitCreate => self.circuit_creates,
            Resource::DhtQuery => self.dht_queries,
            Resource::DhtRecords => self.dht_records,
            Resource::DhtBytes => self.dht_bytes,
            Resource::Directory => self.directory,
            Resource::Sample => self.sample,
            Resource::RouteSearch => self.route_search,
            Resource::RouteRequest => self.route_requests,
            Resource::TunnelKex => self.tunnel_kex,
        }
    }
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            max_circuits_per_peer: 100,
            circuit_creates: (20.0 / 60.0, 20.0),
            dht_queries: (256.0 / 60.0, 256.0),
            dht_records: (2048.0 / 60.0, 2048.0),
            dht_bytes: (8.0 * 1024.0 * 1024.0 / 60.0, 8.0 * 1024.0 * 1024.0),
            directory: (20.0, 200.0),
            sample: (10.0, 100.0),
            route_search: (5.0, 20.0),
            route_requests: (20.0, 100.0),
            tunnel_kex: (5.0, 50.0),
            max_circuits: 10_000,
            pressure_threshold: 0.75,
            throttle_strikes: 3,
            block_strikes: 6,
            block_duration: Duration::from_secs(3600),
        }
    }
}

/// A token bucket: `burst` tokens, refilled at `rate` per second.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64) -> Self {
        Self {
            tokens: burst,
            at: Instant::now(),
        }
    }

    fn refill(&mut self, (rate, burst): (f64, f64)) {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * rate).min(burst);
        self.at = now;
    }
}

// ── Verdict ─────────────────────────────────────────────────────────

/// Result of evaluating an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Process normally.
    Allow,
    /// Drop the message (peer over budget, or not a link peer).
    Shed,
    /// The peer is blocked: drop its links.
    Blocked,
}

// ── Pressure ────────────────────────────────────────────────────────

/// Concrete resource utilization as a fraction of capacity.
#[derive(Debug, Clone, Copy)]
pub struct Pressure {
    /// 0.0 = idle, 1.0 = at capacity.
    pub level: f64,
}

impl Pressure {
    /// Recompute from current node metrics.
    pub fn compute(circuit_count: usize, circuit_capacity: usize) -> Self {
        let level = if circuit_capacity == 0 {
            0.0
        } else {
            (circuit_count as f64 / circuit_capacity as f64).min(1.0)
        };
        Self { level }
    }

    pub fn is_critical(&self) -> bool {
        self.level >= 0.95
    }
}

// ── Standing: what a peer did, kept past its links ──────────────────

/// Peers with strikes or a block remembered at once. Strikes are earned
/// over a link, so filling this takes many links' worth of misbehaviour;
/// when full, the mildest record makes room.
const MAX_STANDINGS: usize = 4096;

/// Strikes against a peer identity. Kept by identity, not by link: a
/// blocked peer that drops its link and redials is still blocked.
#[derive(Debug, Clone, Copy)]
struct Standing {
    strikes: u16,
    /// When the last strike was recorded (for decay).
    last_strike: Instant,
    blocked_until: Option<Instant>,
}

impl Standing {
    fn blocked(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|t| now < t)
    }
}

// ── Per-link-peer budget ────────────────────────────────────────────

/// Resource buckets for a single link peer.
/// Created on LinkUp, removed on (last) LinkDown.
struct PeerBudget {
    buckets: [Bucket; Resource::COUNT],
}

impl PeerBudget {
    fn new(config: &GovernorConfig) -> Self {
        let r = |r| Bucket::full(config.limit(r).1);
        use Resource::*;
        Self {
            buckets: [
                r(CircuitCreate),
                r(DhtQuery),
                r(DhtRecords),
                r(DhtBytes),
                r(Directory),
                r(Sample),
                r(RouteSearch),
                r(RouteRequest),
                r(TunnelKex),
            ],
        }
    }

    /// Take `amount` of each resource, all or none.
    fn take(&mut self, config: &GovernorConfig, charges: &[(Resource, f64)]) -> bool {
        for (r, _) in charges {
            self.buckets[r.index()].refill(config.limit(*r));
        }
        if charges.iter().any(|(r, n)| self.buckets[r.index()].tokens < *n) {
            return false;
        }
        for (r, n) in charges {
            self.buckets[r.index()].tokens -= n;
        }
        true
    }
}

// ── Governor ────────────────────────────────────────────────────────

/// Resource governor.  Non-optional, always-on core infrastructure.
pub struct Governor {
    config: GovernorConfig,
    /// One budget per link peer — bounded by transport connections. A
    /// message from a peer without one (its links are gone) is shed.
    budgets: HashMap<PeerId, PeerBudget>,
    /// Strikes and blocks, by identity, outliving links.
    standings: HashMap<PeerId, Standing>,
    /// Cached pressure level, updated each tick.
    pressure: Pressure,
}

impl Governor {
    pub fn new(config: GovernorConfig) -> Self {
        Self {
            config,
            budgets: HashMap::new(),
            standings: HashMap::new(),
            pressure: Pressure { level: 0.0 },
        }
    }

    // ── Lifecycle (tied to link peers) ──

    /// Call when a new link peer connects (first link). False if the peer
    /// is blocked: refuse the link.
    pub fn peer_connected(&mut self, peer: PeerId) -> bool {
        if self.is_blocked(&peer) {
            return false;
        }
        let config = &self.config;
        self.budgets.entry(peer).or_insert_with(|| PeerBudget::new(config));
        true
    }

    /// Call when the last link to a peer drops. Its strikes stay.
    pub fn peer_disconnected(&mut self, peer: &PeerId) {
        self.budgets.remove(peer);
    }

    /// Number of tracked peers (for diagnostics).
    pub fn peer_count(&self) -> usize {
        self.budgets.len()
    }

    pub fn is_blocked(&self, peer: &PeerId) -> bool {
        self.standings
            .get(peer)
            .is_some_and(|s| s.blocked(Instant::now()))
    }

    // ── Hot path ──

    /// Evaluate an inbound message and charge its [`message_cost`]. Called
    /// for every message in the event loop, so it must be fast. Every DHT,
    /// directory, sampling, search, seqno and key-exchange message pays here,
    /// before its handler allocates or forwards anything.
    pub fn evaluate(&mut self, from: &PeerId, msg_type: MessageType, payload: &[u8]) -> Verdict {
        let standing = self.standings.get(from).copied();
        if standing.is_some_and(|s| s.blocked(Instant::now())) {
            return Verdict::Blocked;
        }
        let config = &self.config;
        let Some(budget) = self.budgets.get_mut(from) else {
            return Verdict::Shed;
        };

        // ── Always-on budgets ──
        // Over budget is shed without a strike: a link-up sync or a busy
        // neighbour can legitimately burst.
        let paid = match message_cost(msg_type, payload) {
            Cost::Free | Cost::ByHandler(_) => true,
            Cost::Charge(resources) => {
                let charges: Vec<(Resource, f64)> = resources.iter().map(|r| (*r, 1.0)).collect();
                budget.take(config, &charges)
            }
            Cost::Records { records, bytes } => budget.take(
                config,
                &[
                    (Resource::DhtRecords, records as f64),
                    (Resource::DhtBytes, bytes as f64),
                ],
            ),
        };
        if !paid {
            return Verdict::Shed;
        }

        // ── Generous by default ──
        if self.pressure.level < config.pressure_threshold {
            return Verdict::Allow;
        }

        // ── Throttled: shed non-essential traffic ──
        let throttled = standing.is_some_and(|s| s.strikes >= config.throttle_strikes);
        if throttled && !is_essential(msg_type) {
            return Verdict::Shed;
        }

        Verdict::Allow
    }

    /// Admit a new circuit leg on `from`'s behalf (a CREATE, or an EXTEND at
    /// a relay, which installs legs on its behalf): the per-peer circuit cap
    /// and the create rate. Called by the handlers after they have told a
    /// resend from new work, so a lossy link's retransmits cost nothing.
    /// No strike: a busy honest relay forwards many clients' CREATEs.
    pub fn admit_circuit(&mut self, from: &PeerId, circuits_for_peer: usize) -> bool {
        let config = &self.config;
        let Some(budget) = self.budgets.get_mut(from) else {
            return false;
        };
        circuits_for_peer < config.max_circuits_per_peer
            && budget.take(config, &[(Resource::CircuitCreate, 1.0)])
    }

    /// Record a protocol violation by `peer`.
    pub fn strike(&mut self, peer: PeerId) {
        let now = Instant::now();
        if !self.standings.contains_key(&peer) && self.standings.len() >= MAX_STANDINGS {
            if let Some(mildest) = self
                .standings
                .iter()
                .filter(|(_, s)| !s.blocked(now))
                .min_by_key(|(_, s)| s.strikes)
                .map(|(p, _)| *p)
            {
                self.standings.remove(&mildest);
            } else {
                return;
            }
        }
        let config = &self.config;
        let s = self.standings.entry(peer).or_insert(Standing {
            strikes: 0,
            last_strike: now,
            blocked_until: None,
        });
        s.strikes = s.strikes.saturating_add(1);
        s.last_strike = now;
        if s.strikes >= config.block_strikes {
            s.blocked_until = Some(now + config.block_duration);
        }
        log::debug!("Governor: strike on {:?} (now {} strikes)", peer, s.strikes);
    }

    // ── Maintenance ──

    /// Periodic maintenance: decay strikes, update pressure.
    pub fn tick(&mut self, circuit_table_len: usize) {
        self.pressure = Pressure::compute(circuit_table_len, self.config.max_circuits);

        // Strikes halve after a quiet STRIKE_DECAY_INTERVAL; a record with
        // none left and no block running is forgotten.
        let now = Instant::now();
        self.standings.retain(|_, s| {
            if now.duration_since(s.last_strike) >= STRIKE_DECAY_INTERVAL {
                s.strikes /= 2;
                s.last_strike = now;
            }
            if !s.blocked(now) {
                s.blocked_until = None;
            }
            s.strikes > 0 || s.blocked_until.is_some()
        });
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Essential message types that should not be shed even for throttled peers.
/// These are needed to maintain link health and circuit control.
fn is_essential(mt: MessageType) -> bool {
    matches!(
        mt,
        MessageType::HandshakeHello
            | MessageType::HandshakeAuth
            | MessageType::HandshakeConfirm
            | MessageType::Keepalive
            | MessageType::Rekey
            | MessageType::CircuitDestroy
    )
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(id: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        PeerId(bytes)
    }

    #[test]
    fn circuit_admission_caps_rate_and_count_without_strikes() {
        let mut config = GovernorConfig::default();
        config.circuit_creates = (0.0, 2.0);
        config.max_circuits_per_peer = 5;
        config.block_strikes = 1;
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);
        // At the circuit cap: refused, even with tokens left.
        assert!(!gov.admit_circuit(&peer, 5));
        assert!(gov.admit_circuit(&peer, 0));
        assert!(gov.admit_circuit(&peer, 0));
        // Rate spent.
        assert!(!gov.admit_circuit(&peer, 0));
        // A CREATE itself is charged by its handler, not at the gate, and
        // refusals cost the forwarding neighbour nothing more.
        assert_eq!(gov.evaluate(&peer, MessageType::CircuitCreate, &[]), Verdict::Allow);
    }

    #[test]
    fn a_block_outlives_the_link() {
        let mut config = GovernorConfig::default();
        config.block_strikes = 2;
        config.block_duration = Duration::from_secs(3600);
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        assert!(gov.peer_connected(peer));
        gov.strike(peer);
        assert_eq!(gov.evaluate(&peer, MessageType::DhtGet, &[]), Verdict::Allow);
        gov.strike(peer);
        assert_eq!(gov.evaluate(&peer, MessageType::Keepalive, &[]), Verdict::Blocked);
        gov.peer_disconnected(&peer);
        gov.tick(0);
        // Redialling doesn't wipe it.
        assert!(!gov.peer_connected(peer));
        assert_eq!(gov.evaluate(&peer, MessageType::Keepalive, &[]), Verdict::Blocked);
    }

    #[test]
    fn throttled_allows_essential() {
        let mut config = GovernorConfig::default();
        config.pressure_threshold = 0.0;
        config.throttle_strikes = 1;
        config.block_strikes = 100;
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);
        gov.strike(peer); // → throttled
        assert_eq!(gov.evaluate(&peer, MessageType::DhtGet, &[]), Verdict::Shed);
        assert_eq!(gov.evaluate(&peer, MessageType::Keepalive, &[]), Verdict::Allow);
    }

    #[test]
    fn no_budget_without_a_link() {
        let mut gov = Governor::new(GovernorConfig::default());
        let peer = test_peer(1);
        // A message left over from a link that is gone recreates nothing.
        assert_eq!(gov.evaluate(&peer, MessageType::Keepalive, &[]), Verdict::Shed);
        assert_eq!(gov.peer_count(), 0);
        gov.peer_connected(peer);
        assert_eq!(gov.peer_count(), 1);
        gov.peer_disconnected(&peer);
        assert_eq!(gov.peer_count(), 0);
    }

    #[test]
    fn every_charged_message_type_is_bounded_without_pressure() {
        // Pressure stays zero: the budgets are always on.
        let mut config = GovernorConfig::default();
        for r in [
            &mut config.dht_queries,
            &mut config.directory,
            &mut config.sample,
            &mut config.route_search,
            &mut config.route_requests,
            &mut config.tunnel_kex,
        ] {
            *r = (0.0, 2.0);
        }
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);
        use MessageType as M;
        for (a, b) in [
            (M::DhtGet, M::DhtWatch),
            (M::DirLookup, M::DirResult),
            (M::SampleWalk, M::SampleResult),
            (M::RouteSearch, M::RouteSearchFound),
            (M::RouteRequest, M::RouteRequest),
            (M::TunnelKeyExchange, M::TunnelKeyResponse),
        ] {
            assert_eq!(gov.evaluate(&peer, a, &[]), Verdict::Allow);
            assert_eq!(gov.evaluate(&peer, b, &[]), Verdict::Allow);
            assert_eq!(gov.evaluate(&peer, a, &[]), Verdict::Shed, "{:?} unbounded", a);
        }
        // Free traffic is never charged.
        for _ in 0..100 {
            assert_eq!(gov.evaluate(&peer, M::Keepalive, &[]), Verdict::Allow);
        }
    }

    #[test]
    fn dht_records_are_charged_by_count_and_bytes() {
        let mut config = GovernorConfig::default();
        config.dht_records = (0.0, 3.0);
        config.dht_bytes = (0.0, 100.0);
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);
        assert_eq!(gov.evaluate(&peer, MessageType::DhtPut, &[0; 40]), Verdict::Allow);
        assert_eq!(gov.evaluate(&peer, MessageType::DhtPut, &[0; 70]), Verdict::Shed);
        // A refused charge takes nothing.
        assert_eq!(gov.evaluate(&peer, MessageType::DhtPut, &[0; 50]), Verdict::Allow);
        assert_eq!(gov.evaluate(&peer, MessageType::DhtWatchNotify, &[0; 5]), Verdict::Allow);
        assert_eq!(gov.evaluate(&peer, MessageType::DhtPut, &[0; 1]), Verdict::Shed);
    }

    #[test]
    fn pressure_computation() {
        let p = Pressure::compute(7500, 10_000);
        assert!((p.level - 0.75).abs() < 0.001);
        assert!(!p.is_critical());

        let p = Pressure::compute(9600, 10_000);
        assert!(p.is_critical());

        let p = Pressure::compute(0, 0);
        assert!((p.level - 0.0).abs() < 0.001);
    }
}
