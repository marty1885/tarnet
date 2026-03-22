//! Stateful packet firewall, inspired by nftables.
//!
//! Evaluates inbound wire messages against an ordered chain of rules.
//! First matching rule wins; if none match the chain's default policy applies.
//!
//! Connection tracking groups message types into protocol categories and
//! records whether traffic has been seen in each direction.  A flow is
//! `Established` once both inbound and outbound packets have been observed
//! for the same `(PeerId, category)` pair.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::prelude::*;
use rand::rngs::StdRng;

use crate::types::PeerId;
use crate::wire::{MessageType, WireMessage};

// ── Actions & state ──────────────────────────────────────────────────

/// Verdict returned by the firewall for each message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
}

/// Connection tracking state for a `(PeerId, category)` flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// First packet of this flow; no bidirectional traffic yet.
    New,
    /// Traffic observed in both directions.
    Established,
}

// ── Match predicates ─────────────────────────────────────────────────

/// Composable predicate on an inbound message.
pub enum Match {
    /// Matches any message.
    Any,
    /// Matches a specific wire message type.
    MsgType(MessageType),
    /// Matches a specific source peer.
    Peer(PeerId),
    /// Matches connection tracking state.
    State(ConnState),
    /// Matches with a random probability in `0.0..=1.0`.
    Probability(f64),
    /// Logical NOT.
    Not(Box<Match>),
    /// Logical AND — all sub-conditions must match.
    All(Vec<Match>),
}

impl Match {
    fn eval(
        &self,
        peer: &PeerId,
        msg: &WireMessage,
        state: ConnState,
        rng: &mut StdRng,
    ) -> bool {
        match self {
            Match::Any => true,
            Match::MsgType(mt) => msg.msg_type == *mt,
            Match::Peer(p) => peer == p,
            Match::State(s) => *s == state,
            Match::Probability(p) => rng.gen::<f64>() < *p,
            Match::Not(inner) => !inner.eval(peer, msg, state, rng),
            Match::All(conds) => conds.iter().all(|c| c.eval(peer, msg, state, rng)),
        }
    }
}

// ── Rules ────────────────────────────────────────────────────────────

/// A single firewall rule: condition → action.
pub struct Rule {
    /// Unique id within this firewall, for removal.
    pub id: u64,
    /// Human-readable label (optional, for logging / debugging).
    pub label: Option<String>,
    /// Match condition.
    pub condition: Match,
    /// Verdict if the condition matches.
    pub action: Action,
}

// ── Connection tracking ──────────────────────────────────────────────

/// Protocol categories for conntrack.  Related message types are grouped
/// so that e.g. a DhtGet and its DhtGetResponse share the same flow.
///
/// Categories reflect logical conversations, not wire encoding:
///
///  - **Link**: handshake, rekey, keepalive, and WebRTC signaling — all
///    link establishment / maintenance.  WebRTC Offer/Answer/ICE are
///    overlay-routed signaling messages that negotiate a direct transport
///    link, so they belong here, not in a separate category.
///  - **Routing**: route advertisements (always between neighbors).
///  - **Dht**: put, get, response, watch — DHT queries.
///  - **Tunnel**: key exchange / response — tunnel negotiation.
///  - **Channel**: open, data, ack, close — reliable streams over tunnels.
///  - **Data**: overlay-routed payloads (`Data`, `EncryptedData`).
///    These are the envelope for tunnel key exchange, WebRTC signaling,
///    and other inner protocols, so they form their own flow.
///  - **Circuit**: create, created, relay, destroy — onion circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
enum ProtoCategory {
    Link = 0,
    Routing = 1,
    Dht = 2,
    Tunnel = 3,
    Channel = 4,
    Data = 5,
    Circuit = 6,
}

fn proto_category(mt: MessageType) -> ProtoCategory {
    match mt {
        // Link establishment & maintenance (includes WebRTC signaling —
        // Offer/Answer/ICE are overlay-routed but negotiate transport links)
        MessageType::HandshakeHello
        | MessageType::HandshakeAuth
        | MessageType::HandshakeConfirm
        | MessageType::Rekey
        | MessageType::Keepalive => ProtoCategory::Link,

        MessageType::RouteAdvertisement => ProtoCategory::Routing,

        MessageType::DhtPut
        | MessageType::DhtGet
        | MessageType::DhtGetResponse
        | MessageType::DhtWatch
        | MessageType::DhtWatchNotify
        | MessageType::DhtFindClosest
        | MessageType::DhtFindClosestResponse => ProtoCategory::Dht,

        MessageType::TunnelKeyExchange
        | MessageType::TunnelKeyResponse => ProtoCategory::Tunnel,

        MessageType::ChannelOpen
        | MessageType::ChannelData
        | MessageType::ChannelAck
        | MessageType::ChannelClose => ProtoCategory::Channel,

        MessageType::Data
        | MessageType::EncryptedData => ProtoCategory::Data,

        MessageType::CircuitCreate
        | MessageType::CircuitCreated
        | MessageType::CircuitRelay
        | MessageType::CircuitDestroy => ProtoCategory::Circuit,
    }
}

struct ConnTrackEntry {
    seen_inbound: bool,
    seen_outbound: bool,
    last_activity: Instant,
}

impl ConnTrackEntry {
    fn state(&self) -> ConnState {
        if self.seen_inbound && self.seen_outbound {
            ConnState::Established
        } else {
            ConnState::New
        }
    }
}

// ── Firewall ─────────────────────────────────────────────────────────

/// Stateful message firewall.
///
/// # Example
///
/// ```ignore
/// let mut fw = Firewall::default(); // accept-all
///
/// // Drop 50% of traffic (testing)
/// fw.add_rule(Match::Probability(0.5), Action::Drop);
///
/// // Only allow established connections (block unsolicited inbound)
/// fw.add_rule(Match::State(ConnState::Established), Action::Accept);
/// fw.set_default_policy(Action::Drop);
/// ```
pub struct Firewall {
    rules: Vec<Rule>,
    default_policy: Action,
    next_id: u64,
    conntrack: HashMap<(PeerId, u8), ConnTrackEntry>,
    rng: StdRng,
}

impl Default for Firewall {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_policy: Action::Accept,
            next_id: 1,
            conntrack: HashMap::new(),
            rng: StdRng::from_entropy(),
        }
    }
}

impl Firewall {
    /// Create a firewall with the given default policy.
    pub fn with_policy(policy: Action) -> Self {
        Self {
            default_policy: policy,
            ..Default::default()
        }
    }

    // ── Rule management ──

    /// Append a rule.  Returns its unique id.
    pub fn add_rule(&mut self, condition: Match, action: Action) -> u64 {
        self.add_rule_labeled(None, condition, action)
    }

    /// Append a labeled rule.
    pub fn add_rule_labeled(
        &mut self,
        label: Option<String>,
        condition: Match,
        action: Action,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.rules.push(Rule {
            id,
            label,
            condition,
            action,
        });
        id
    }

    /// Insert a rule at a specific position in the chain.
    pub fn insert_rule(&mut self, index: usize, condition: Match, action: Action) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let idx = index.min(self.rules.len());
        self.rules.insert(
            idx,
            Rule {
                id,
                label: None,
                condition,
                action,
            },
        );
        id
    }

    /// Remove a rule by id.  Returns true if found.
    pub fn remove_rule(&mut self, rule_id: u64) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.rules.len() < before
    }

    /// Remove all rules.
    pub fn flush_rules(&mut self) {
        self.rules.clear();
    }

    /// Set the default policy (verdict when no rule matches).
    pub fn set_default_policy(&mut self, action: Action) {
        self.default_policy = action;
    }

    /// Number of rules in the chain.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    // ── Connection tracking ──

    /// Record outbound traffic for conntrack.
    pub fn track_outbound(&mut self, peer: &PeerId, msg_type: MessageType) {
        let cat = proto_category(msg_type) as u8;
        let entry = self
            .conntrack
            .entry((*peer, cat))
            .or_insert(ConnTrackEntry {
                seen_inbound: false,
                seen_outbound: false,
                last_activity: Instant::now(),
            });
        entry.seen_outbound = true;
        entry.last_activity = Instant::now();
    }

    /// Expire conntrack entries older than `max_age`.
    pub fn gc_conntrack(&mut self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        self.conntrack.retain(|_, e| e.last_activity > cutoff);
    }

    /// Number of active conntrack entries.
    pub fn conntrack_len(&self) -> usize {
        self.conntrack.len()
    }

    // ── Evaluation ──

    /// Evaluate an inbound message.  Updates conntrack, then walks the
    /// rule chain.  First match wins; default policy if none match.
    pub fn evaluate(&mut self, peer: &PeerId, msg: &WireMessage) -> Action {
        // Update conntrack inbound
        let cat = proto_category(msg.msg_type) as u8;
        let entry = self
            .conntrack
            .entry((*peer, cat))
            .or_insert(ConnTrackEntry {
                seen_inbound: false,
                seen_outbound: false,
                last_activity: Instant::now(),
            });
        entry.seen_inbound = true;
        entry.last_activity = Instant::now();
        let state = entry.state();

        // Walk rules
        for rule in &self.rules {
            if rule.condition.eval(peer, msg, state, &mut self.rng) {
                return rule.action;
            }
        }
        self.default_policy
    }
}
