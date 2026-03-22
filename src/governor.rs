//! Resource governor: per-link-peer budgeting with load-adaptive enforcement.
//!
//! Always active but zero-cost when idle.  Reads from [`StatsRegistry`]
//! (lock-free, already running) and [`CircuitTable`].  Other subsystems
//! report misbehavior via an mpsc channel.
//!
//! Design principles:
//!   - Key on link peers only (bounded by physical connections)
//!   - Generous by default, strict under load (GNUnet excess/scarcity)
//!   - Kill stalest circuits first under memory pressure (Tor OOM)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::types::PeerId;
use crate::wire::MessageType;

// ── Constants ───────────────────────────────────────────────────────

/// How often the governor tick runs (strike decay, window reset).
pub const GOVERNOR_TICK_INTERVAL: Duration = Duration::from_secs(10);

/// Strikes halve after this much time with no new strikes.
const STRIKE_DECAY_INTERVAL: Duration = Duration::from_secs(300);

/// Sliding window for circuit creation rate limiting.
const CIRCUIT_RATE_WINDOW: Duration = Duration::from_secs(60);

// ── Configuration ───────────────────────────────────────────────────

/// Governor tuning knobs.
#[derive(Debug, Clone)]
pub struct GovernorConfig {
    /// Hard cap on circuits involving any single link peer.
    pub max_circuits_per_peer: usize,
    /// Max circuit creates per peer within [`CIRCUIT_RATE_WINDOW`].
    pub circuit_creates_per_window: u32,
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

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            max_circuits_per_peer: 100,
            circuit_creates_per_window: 20,
            max_circuits: 10_000,
            pressure_threshold: 0.75,
            throttle_strikes: 3,
            block_strikes: 6,
            block_duration: Duration::from_secs(3600),
        }
    }
}

// ── Verdict ─────────────────────────────────────────────────────────

/// Result of evaluating an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Process normally.
    Allow,
    /// Drop the message (peer over budget or blocked).
    Shed,
}

// ── Reports ─────────────────────────────────────────────────────────

/// Misbehavior report from other subsystems.
#[derive(Debug)]
pub struct Report {
    /// The link peer that delivered the offending traffic.
    pub link_peer: PeerId,
    /// What went wrong.
    pub reason: ReportReason,
}

#[derive(Debug)]
pub enum ReportReason {
    /// Invalid cell, bad MAC, protocol sequence error.
    ProtocolViolation,
    /// Excessive resource consumption on a circuit.
    ResourceAbuse,
    /// Malformed data on a channel/stream.
    MalformedData,
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

// ── Per-link-peer budget ────────────────────────────────────────────

/// Enforcement standing for a link peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    Normal,
    Throttled,
    Blocked { until: Instant },
}

/// Resource budget for a single link peer.
/// Created on LinkUp, removed on (last) LinkDown.
struct PeerBudget {
    standing: Standing,
    /// Accumulated strikes.
    strikes: u16,
    /// When the last strike was recorded (for decay).
    last_strike: Option<Instant>,
    /// Circuit creation count in the current window.
    circuit_creates: u32,
    /// Start of the current rate-limit window.
    window_start: Instant,
}

impl PeerBudget {
    fn new() -> Self {
        Self {
            standing: Standing::Normal,
            strikes: 0,
            last_strike: None,
            circuit_creates: 0,
            window_start: Instant::now(),
        }
    }

    /// Reset the rate window if it has expired.
    fn maybe_reset_window(&mut self) {
        if self.window_start.elapsed() >= CIRCUIT_RATE_WINDOW {
            self.circuit_creates = 0;
            self.window_start = Instant::now();
        }
    }

    /// Try to consume a circuit-create token.  Returns false if rate exceeded.
    fn try_circuit_create(&mut self, limit: u32) -> bool {
        self.maybe_reset_window();
        if self.circuit_creates >= limit {
            return false;
        }
        self.circuit_creates += 1;
        true
    }

    /// Add a strike and update standing based on thresholds.
    fn add_strike(&mut self, throttle_at: u16, block_at: u16, block_duration: Duration) {
        self.strikes = self.strikes.saturating_add(1);
        self.last_strike = Some(Instant::now());

        if self.strikes >= block_at {
            self.standing = Standing::Blocked {
                until: Instant::now() + block_duration,
            };
        } else if self.strikes >= throttle_at {
            self.standing = Standing::Throttled;
        }
    }

    /// Decay strikes over time.  Called periodically from tick().
    fn decay_strikes(&mut self) {
        let dominated = match self.last_strike {
            Some(t) => t.elapsed() >= STRIKE_DECAY_INTERVAL,
            None => false,
        };
        if !dominated {
            return;
        }

        // Halve strikes.
        self.strikes /= 2;

        // Decay standing: Blocked → Throttled → Normal.
        match self.standing {
            Standing::Blocked { until } if Instant::now() >= until => {
                self.standing = Standing::Throttled;
            }
            Standing::Throttled if self.strikes == 0 => {
                self.standing = Standing::Normal;
            }
            _ => {}
        }

        if self.strikes > 0 {
            self.last_strike = Some(Instant::now());
        } else {
            self.last_strike = None;
        }
    }
}

// ── Governor ────────────────────────────────────────────────────────

/// Resource governor.  Non-optional, always-on core infrastructure.
pub struct Governor {
    config: GovernorConfig,
    /// One budget per link peer — bounded by transport connections.
    budgets: HashMap<PeerId, PeerBudget>,
    /// Cached pressure level, updated each tick.
    pressure: Pressure,
    /// Report channel (receiver).
    report_rx: mpsc::UnboundedReceiver<Report>,
    /// Report channel (sender), cloned out to subsystems.
    report_tx: mpsc::UnboundedSender<Report>,
}

impl Governor {
    pub fn new(config: GovernorConfig) -> Self {
        let (report_tx, report_rx) = mpsc::unbounded_channel();
        Self {
            config,
            budgets: HashMap::new(),
            pressure: Pressure { level: 0.0 },
            report_rx,
            report_tx,
        }
    }

    /// Clone the report sender for other subsystems to use.
    pub fn reporter(&self) -> mpsc::UnboundedSender<Report> {
        self.report_tx.clone()
    }

    // ── Lifecycle (tied to link peers) ──

    /// Call when a new link peer connects (first link).
    pub fn peer_connected(&mut self, peer: PeerId) {
        self.budgets.entry(peer).or_insert_with(PeerBudget::new);
    }

    /// Call when the last link to a peer drops.
    pub fn peer_disconnected(&mut self, peer: &PeerId) {
        self.budgets.remove(peer);
    }

    /// Number of tracked peers (for diagnostics).
    pub fn peer_count(&self) -> usize {
        self.budgets.len()
    }

    // ── Hot path ──

    /// Evaluate an inbound message.  Called for every message in the
    /// event loop, so it must be fast.
    ///
    /// `circuits_for_peer`: how many circuit-table entries involve this peer.
    pub fn evaluate(
        &mut self,
        from: &PeerId,
        msg_type: MessageType,
        circuits_for_peer: usize,
    ) -> Verdict {
        // ── Generous by default ──
        // Below the pressure threshold, skip all checks.
        if self.pressure.level < self.config.pressure_threshold {
            return Verdict::Allow;
        }

        let config = &self.config;

        let budget = match self.budgets.get_mut(from) {
            Some(b) => b,
            None => return Verdict::Allow,
        };

        // ── Hard block ──
        if let Standing::Blocked { until } = budget.standing {
            if Instant::now() < until {
                return Verdict::Shed;
            }
            // Block expired, decay to Throttled.
            budget.standing = Standing::Throttled;
        }

        // ── Circuit creation checks ──
        if msg_type == MessageType::CircuitCreate {
            // Per-peer circuit count cap.
            if circuits_for_peer >= config.max_circuits_per_peer {
                budget.add_strike(
                    config.throttle_strikes,
                    config.block_strikes,
                    config.block_duration,
                );
                return Verdict::Shed;
            }
            // Rate limit.
            if !budget.try_circuit_create(config.circuit_creates_per_window) {
                budget.add_strike(
                    config.throttle_strikes,
                    config.block_strikes,
                    config.block_duration,
                );
                return Verdict::Shed;
            }
        }

        // ── Throttled: shed non-essential traffic ──
        if budget.standing == Standing::Throttled && !is_essential(msg_type) {
            return Verdict::Shed;
        }

        Verdict::Allow
    }

    // ── Maintenance ──

    /// Drain pending reports from subsystems.
    pub fn drain_reports(&mut self) {
        while let Ok(report) = self.report_rx.try_recv() {
            if let Some(budget) = self.budgets.get_mut(&report.link_peer) {
                budget.add_strike(
                    self.config.throttle_strikes,
                    self.config.block_strikes,
                    self.config.block_duration,
                );
                log::debug!(
                    "Governor: strike on {:?} for {:?} (now {} strikes, {:?})",
                    report.link_peer,
                    report.reason,
                    budget.strikes,
                    budget.standing,
                );
            }
        }
    }

    /// Periodic maintenance: decay strikes, reset windows, update pressure.
    pub fn tick(&mut self, circuit_table_len: usize) {
        // Drain any pending reports first.
        self.drain_reports();

        // Update cached pressure.
        self.pressure = Pressure::compute(circuit_table_len, self.config.max_circuits);

        // Decay strikes and standing for all peers.
        for budget in self.budgets.values_mut() {
            budget.decay_strikes();
            budget.maybe_reset_window();
        }
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
    fn no_enforcement_below_threshold() {
        let mut gov = Governor::new(GovernorConfig::default());
        let peer = test_peer(1);
        gov.peer_connected(peer);
        // Pressure is 0.0 (below threshold) — everything allowed.
        assert_eq!(
            gov.evaluate(&peer, MessageType::CircuitCreate, 0),
            Verdict::Allow
        );
    }

    #[test]
    fn circuit_rate_limit_under_pressure() {
        let mut config = GovernorConfig::default();
        config.circuit_creates_per_window = 3;
        config.pressure_threshold = 0.0; // always enforce
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);

        // First 3 allowed.
        for _ in 0..3 {
            assert_eq!(
                gov.evaluate(&peer, MessageType::CircuitCreate, 0),
                Verdict::Allow,
            );
        }
        // 4th shed.
        assert_eq!(
            gov.evaluate(&peer, MessageType::CircuitCreate, 0),
            Verdict::Shed,
        );
    }

    #[test]
    fn circuit_count_cap_under_pressure() {
        let mut config = GovernorConfig::default();
        config.max_circuits_per_peer = 5;
        config.pressure_threshold = 0.0;
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);

        // At the cap → shed.
        assert_eq!(
            gov.evaluate(&peer, MessageType::CircuitCreate, 5),
            Verdict::Shed,
        );
        // Below cap → allowed.
        assert_eq!(
            gov.evaluate(&peer, MessageType::CircuitCreate, 4),
            Verdict::Allow,
        );
    }

    #[test]
    fn strikes_escalate_to_block() {
        let mut config = GovernorConfig::default();
        config.circuit_creates_per_window = 1;
        config.pressure_threshold = 0.0;
        config.throttle_strikes = 2;
        config.block_strikes = 4;
        config.block_duration = Duration::from_secs(3600);
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);

        // First create OK.
        assert_eq!(
            gov.evaluate(&peer, MessageType::CircuitCreate, 0),
            Verdict::Allow,
        );
        // Subsequent creates in the same window get shed + strike.
        for _ in 0..5 {
            assert_eq!(
                gov.evaluate(&peer, MessageType::CircuitCreate, 0),
                Verdict::Shed,
            );
        }
        // Now blocked — even non-circuit messages are shed.
        assert_eq!(
            gov.evaluate(&peer, MessageType::DhtGet, 0),
            Verdict::Shed,
        );
        // But essential messages are still shed when blocked (block is hard).
        assert_eq!(
            gov.evaluate(&peer, MessageType::Keepalive, 0),
            Verdict::Shed,
        );
    }

    #[test]
    fn throttled_allows_essential() {
        let mut config = GovernorConfig::default();
        config.circuit_creates_per_window = 1;
        config.pressure_threshold = 0.0;
        config.throttle_strikes = 1;
        config.block_strikes = 100; // won't reach block
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);

        // Use up rate limit.
        gov.evaluate(&peer, MessageType::CircuitCreate, 0);
        // Next create → strike → throttled.
        gov.evaluate(&peer, MessageType::CircuitCreate, 0);

        // Non-essential shed.
        assert_eq!(
            gov.evaluate(&peer, MessageType::DhtGet, 0),
            Verdict::Shed,
        );
        // Essential allowed.
        assert_eq!(
            gov.evaluate(&peer, MessageType::Keepalive, 0),
            Verdict::Allow,
        );
    }

    #[test]
    fn peer_disconnect_removes_budget() {
        let mut gov = Governor::new(GovernorConfig::default());
        let peer = test_peer(1);
        gov.peer_connected(peer);
        assert_eq!(gov.peer_count(), 1);
        gov.peer_disconnected(&peer);
        assert_eq!(gov.peer_count(), 0);
    }

    #[test]
    fn report_adds_strike() {
        let mut config = GovernorConfig::default();
        config.pressure_threshold = 0.0;
        config.throttle_strikes = 1;
        config.block_strikes = 100;
        let mut gov = Governor::new(config);
        let peer = test_peer(1);
        gov.peer_connected(peer);

        // Send a report.
        gov.reporter()
            .send(Report {
                link_peer: peer,
                reason: ReportReason::ProtocolViolation,
            })
            .unwrap();

        // Drain it.
        gov.drain_reports();

        // Peer should be throttled now — non-essential shed.
        assert_eq!(
            gov.evaluate(&peer, MessageType::DhtGet, 0),
            Verdict::Shed,
        );
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
