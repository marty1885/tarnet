//! Per-link send scheduler: priority classes and delay-based drops.
//!
//! A slow link should carry as much useful data as its rate allows. Queues
//! stay short and excess traffic is dropped before it is sent, instead of
//! piling up seconds deep behind it.
//!
//! Messages are classified by wire type into four classes, served highest
//! first, except that background keeps a minimum share of the link. Data is
//! fair-queued per flow (circuit, channel or origin), fq_codel style: a flow
//! that has just become active (sparse, e.g. a keystroke) is served before
//! flows that keep a backlog, and the backlogged ones share the rest round
//! robin. Data flows and background each drop from the head when queued
//! messages wait longer than the link's target delay for a whole interval
//! (CoDel). A byte cap backs this up, shedding background first, then the
//! tail of the largest flow. Control and circuit-control messages are never
//! dropped here: they are small and bounded by the protocols that send them.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::wire::{MessageType, HEADER_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Class {
    /// Keepalives, routing, rekey.
    Control = 0,
    /// Circuit and channel setup and teardown: one-shot requests whose loss
    /// costs a timeout.
    CircuitControl = 1,
    /// Circuit cells, channel and overlay data. Fair-queued per flow, sparse
    /// flows first.
    Data = 2,
    /// DHT maintenance and lookups.
    Background = 3,
}

/// Minimum share of sent bytes for background while it has data.
const LOW_CLASS_SHARE: f64 = 0.10;
/// Most credit background can bank while it has nothing queued.
const MAX_LOW_CREDIT: f64 = 4096.0;

/// Classify a wire message. Returns its base class and, for messages that
/// belong to a flow (circuit cells, channel and overlay data), a flow key.
pub(crate) fn classify(msg: &[u8]) -> (Class, Option<u64>) {
    if msg.len() < HEADER_SIZE {
        return (Class::Data, None);
    }
    let Some(msg_type) = MessageType::from_u16(u16::from_be_bytes([msg[1], msg[2]])) else {
        return (Class::Data, None);
    };
    let payload = &msg[HEADER_SIZE..];
    let flow_of = |key_bytes: usize| {
        let mut key = [0u8; 8];
        key[..2].copy_from_slice(&msg_type.as_u16().to_be_bytes());
        let n = key_bytes.min(payload.len()).min(6);
        key[2..2 + n].copy_from_slice(&payload[..n]);
        Some(u64::from_be_bytes(key))
    };
    use MessageType::*;
    match msg_type {
        HandshakeHello | HandshakeAuth | HandshakeConfirm | Rekey | Keepalive
        | RouteUpdate | RouteDigest | RouteRequest => (Class::Control, None),
        CircuitCreate | CircuitCreated | CircuitDestroy | TunnelKeyExchange
        | TunnelKeyResponse | ChannelOpen | ChannelClose => (Class::CircuitControl, None),
        // Someone is waiting on a first contact.
        DirLookup | DirResult | RouteSearch | RouteSearchFound => (Class::CircuitControl, None),
        // Keyed by circuit id.
        CircuitRelay => (Class::Data, flow_of(4)),
        // Keyed by channel id.
        ChannelData | ChannelAck => (Class::Data, flow_of(4)),
        // Keyed by the origin's first bytes.
        Data | EncryptedData => (Class::Data, flow_of(6)),
        DhtPut | DhtGet | DhtGetResponse | DhtWatch | DhtWatchNotify | DhtNeighbor
        | SampleWalk | SampleResult | DirPublish | PathTrace | PathTraceResult => {
            (Class::Background, None)
        }
    }
}

/// Scheduler tuning for one link.
#[derive(Debug, Clone)]
pub(crate) struct SchedConfig {
    /// Queueing delay above which droppable messages start being dropped.
    pub target: Duration,
    /// How long the delay must stay above target before the first drop.
    pub interval: Duration,
    /// Most bytes queued across all classes.
    pub byte_cap: usize,
    /// Most messages queued across all classes.
    pub msg_cap: usize,
    /// A queue holding no more than this after a message leaves it is not a
    /// standing queue and is never dropped from (one frame).
    pub quantum: usize,
}

struct Queued {
    data: Vec<u8>,
    at: Instant,
}

/// CoDel state for one queue.
#[derive(Default)]
struct CoDel {
    first_above: Option<Instant>,
    dropping: bool,
    drop_next: Option<Instant>,
    count: u32,
}

impl CoDel {
    fn above_for_interval(&mut self, sojourn: Duration, now: Instant, cfg: &SchedConfig) -> bool {
        if sojourn < cfg.target {
            self.first_above = None;
            return false;
        }
        match self.first_above {
            None => {
                self.first_above = Some(now + cfg.interval);
                false
            }
            Some(t) => now >= t,
        }
    }

    fn next_drop(&self, now: Instant, cfg: &SchedConfig) -> Instant {
        now + cfg.interval.div_f64((self.count.max(1) as f64).sqrt())
    }

    /// Whether to drop a message that waited `sojourn`, leaving `backlog`
    /// bytes queued behind it: CoDel's control law.
    fn should_drop(&mut self, sojourn: Duration, backlog: usize, now: Instant, cfg: &SchedConfig) -> bool {
        // A nearly empty queue isn't standing, however long its last message
        // waited (RFC 8289). Without this, one delayed message on an idle
        // link arms the timer and a later, lone message is dropped.
        if backlog <= cfg.quantum {
            self.first_above = None;
            self.dropping = false;
            return false;
        }
        let above = self.above_for_interval(sojourn, now, cfg);
        if self.dropping {
            if !above {
                self.dropping = false;
                return false;
            }
            if self.drop_next.is_some_and(|t| now >= t) {
                self.count += 1;
                self.drop_next = Some(self.next_drop(now, cfg));
                return true;
            }
            return false;
        }
        if above {
            self.dropping = true;
            // Resume near the last drop rate if dropping stopped recently.
            self.count = if self.count > 2 { self.count - 2 } else { 1 };
            self.drop_next = Some(self.next_drop(now, cfg));
            return true;
        }
        false
    }
}

/// One data flow's queue.
#[derive(Default)]
struct Flow {
    queue: VecDeque<Queued>,
    bytes: usize,
    codel: CoDel,
}

/// Which round-robin list a flow is on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowList {
    /// Became active with an empty queue: served first.
    New,
    /// Has kept a backlog: served round robin after new flows.
    Old,
}

pub(crate) struct Scheduler {
    /// Control, circuit control and background queues (FIFO).
    fifo: [VecDeque<Queued>; 4],
    fifo_bytes: [usize; 4],
    fifo_codel: CoDel,
    /// Data flows, fair-queued.
    flows: HashMap<u64, (Flow, FlowList)>,
    new_flows: VecDeque<u64>,
    old_flows: VecDeque<u64>,
    total_bytes: usize,
    total_msgs: usize,
    /// Bytes background may send ahead of higher classes: earned by
    /// higher-class bytes sent while it waited, spent when it sends.
    low_credit: f64,
    cfg: SchedConfig,
    dropped: u64,
}

/// Flow key for data without one of its own.
const ANONYMOUS_FLOW: u64 = 0;

impl Scheduler {
    pub(crate) fn new(cfg: SchedConfig) -> Self {
        Self {
            fifo: Default::default(),
            fifo_bytes: [0; 4],
            fifo_codel: CoDel::default(),
            flows: HashMap::new(),
            new_flows: VecDeque::new(),
            old_flows: VecDeque::new(),
            total_bytes: 0,
            total_msgs: 0,
            low_credit: 0.0,
            cfg,
            dropped: 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.total_msgs == 0
    }

    /// Messages dropped so far (cap or queueing delay).
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Queue a message. `critical` sends (circuit control the caller cannot
    /// afford to lose) are never below `CircuitControl`.
    pub(crate) fn push(&mut self, data: Vec<u8>, critical: bool, now: Instant) {
        let (mut class, flow) = classify(&data);
        if critical && class > Class::CircuitControl {
            class = Class::CircuitControl;
        }
        let len = data.len();
        // Make room: shed background first, then the fattest flow's tail.
        while self.total_bytes + len > self.cfg.byte_cap || self.total_msgs >= self.cfg.msg_cap {
            if !self.shed(class) {
                if class >= Class::Data {
                    self.dropped += 1;
                    return;
                }
                break; // control is never dropped
            }
        }
        self.total_bytes += len;
        self.total_msgs += 1;
        let queued = Queued { data, at: now };
        if class != Class::Data {
            self.fifo_bytes[class as usize] += len;
            self.fifo[class as usize].push_back(queued);
            return;
        }
        let key = flow.unwrap_or(ANONYMOUS_FLOW);
        let (flow, _) = self.flows.entry(key).or_insert_with(|| {
            self.new_flows.push_back(key);
            (Flow::default(), FlowList::New)
        });
        flow.bytes += len;
        flow.queue.push_back(queued);
    }

    /// Drop one message to make room for one of `incoming` class. Returns
    /// false if nothing at or below that priority can go.
    fn shed(&mut self, incoming: Class) -> bool {
        if let Some(q) = self.fifo[Class::Background as usize].pop_back() {
            self.fifo_bytes[Class::Background as usize] -= q.data.len();
            self.total_bytes -= q.data.len();
            self.total_msgs -= 1;
            self.dropped += 1;
            return true;
        }
        if incoming == Class::Background {
            return false;
        }
        let fattest = self
            .flows
            .iter()
            .max_by_key(|(_, (f, _))| f.bytes)
            .map(|(k, _)| *k);
        let Some(key) = fattest else { return false };
        let (flow, _) = self.flows.get_mut(&key).unwrap();
        let q = flow.queue.pop_back().unwrap();
        flow.bytes -= q.data.len();
        self.total_bytes -= q.data.len();
        self.total_msgs -= 1;
        self.dropped += 1;
        if flow.queue.is_empty() {
            self.remove_flow(key);
        }
        true
    }

    fn remove_flow(&mut self, key: u64) {
        if let Some((_, list)) = self.flows.remove(&key) {
            match list {
                FlowList::New => self.new_flows.retain(|&k| k != key),
                FlowList::Old => self.old_flows.retain(|&k| k != key),
            }
        }
    }

    /// Next message to send, or `None` if nothing is queued.
    pub(crate) fn pop(&mut self, now: Instant) -> Option<Vec<u8>> {
        let low_head = self.fifo[Class::Background as usize].front().map(|q| q.data.len());
        if low_head.is_some_and(|len| self.low_credit >= len as f64) {
            if let Some(data) = self.pop_fifo(Class::Background, now) {
                self.low_credit = (self.low_credit - data.len() as f64).max(0.0);
                return Some(data);
            }
        }
        let data = self
            .pop_fifo(Class::Control, now)
            .or_else(|| self.pop_fifo(Class::CircuitControl, now))
            .or_else(|| self.pop_data(now));
        if let Some(data) = data {
            if low_head.is_some() {
                self.low_credit = (self.low_credit
                    + data.len() as f64 * LOW_CLASS_SHARE / (1.0 - LOW_CLASS_SHARE))
                    .min(MAX_LOW_CREDIT);
            }
            return Some(data);
        }
        let data = self.pop_fifo(Class::Background, now)?;
        self.low_credit = (self.low_credit - data.len() as f64).max(0.0);
        Some(data)
    }

    fn pop_fifo(&mut self, class: Class, now: Instant) -> Option<Vec<u8>> {
        loop {
            let q = self.fifo[class as usize].pop_front()?;
            self.fifo_bytes[class as usize] -= q.data.len();
            self.total_bytes -= q.data.len();
            self.total_msgs -= 1;
            if class == Class::Background {
                let sojourn = now.saturating_duration_since(q.at);
                let backlog = self.fifo_bytes[class as usize];
                if self.fifo_codel.should_drop(sojourn, backlog, now, &self.cfg) {
                    self.dropped += 1;
                    continue;
                }
            }
            return Some(q.data);
        }
    }

    /// Serve data flows: flows that just became active first, then
    /// backlogged flows round robin, one message per turn.
    fn pop_data(&mut self, now: Instant) -> Option<Vec<u8>> {
        loop {
            let (key, from_new) = match self.new_flows.pop_front() {
                Some(key) => (key, true),
                None => (self.old_flows.pop_front()?, false),
            };
            let cfg = self.cfg.clone();
            let (flow, list) = self.flows.get_mut(&key).expect("listed flow exists");
            let mut out = None;
            while let Some(q) = flow.queue.pop_front() {
                flow.bytes -= q.data.len();
                self.total_bytes -= q.data.len();
                self.total_msgs -= 1;
                let sojourn = now.saturating_duration_since(q.at);
                if flow.codel.should_drop(sojourn, flow.bytes, now, &cfg) {
                    self.dropped += 1;
                    continue;
                }
                out = Some(q.data);
                break;
            }
            if flow.queue.is_empty() {
                self.flows.remove(&key);
            } else {
                // A flow that still has data after its turn is backlogged.
                *list = FlowList::Old;
                self.old_flows.push_back(key);
            }
            let _ = from_new;
            if out.is_some() {
                return out;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{encode_circuit_relay_cell, KeepaliveMsg, WireMessage};

    fn cfg() -> SchedConfig {
        SchedConfig {
            target: Duration::from_millis(100),
            interval: Duration::from_millis(500),
            byte_cap: 64 * 1024,
            msg_cap: 4096,
            quantum: 0,
        }
    }

    fn cell(circuit: u32, tag: u8) -> Vec<u8> {
        encode_circuit_relay_cell(circuit, &[tag; 100])
    }

    fn keepalive() -> Vec<u8> {
        KeepaliveMsg {
            timestamp_us: None,
            padding: Vec::new(),
        }
        .to_wire()
        .encode()
    }

    fn dht() -> Vec<u8> {
        WireMessage::new(MessageType::DhtGet, vec![0; 50]).encode()
    }

    fn create() -> Vec<u8> {
        WireMessage::new(MessageType::CircuitCreate, vec![0; 50]).encode()
    }

    #[test]
    fn lone_late_message_on_idle_queue_is_not_dropped() {
        let mut s = Scheduler::new(cfg());
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        // Each message waits past the target, but the queue never holds more
        // than the one: nothing is standing, nothing is dropped.
        for k in 0..5u32 {
            let at = t0 + ms(1000) * k;
            s.push(dht(), false, at);
            assert!(s.pop(at + ms(200)).is_some(), "message {k} dropped");
        }
        assert_eq!(s.dropped(), 0);
    }

    #[test]
    fn classes_follow_wire_type() {
        assert_eq!(classify(&keepalive()).0, Class::Control);
        assert_eq!(classify(&create()).0, Class::CircuitControl);
        assert_eq!(classify(&cell(7, 0)).0, Class::Data);
        assert_eq!(classify(&dht()).0, Class::Background);
        assert_ne!(classify(&cell(7, 0)).1, classify(&cell(8, 0)).1, "circuits are separate flows");
    }

    #[test]
    fn sparse_flow_overtakes_a_backlogged_one() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        for i in 0..4 {
            s.push(cell(1, i), false, now);
        }
        assert_eq!(s.pop(now).unwrap(), cell(1, 0));
        // A keystroke arrives while the bulk flow is still backlogged, even
        // though the bulk flow only keeps a few cells queued (window-limited).
        s.push(cell(2, 0xEE), false, now);
        s.push(create(), false, now);
        assert_eq!(s.pop(now).unwrap(), create());
        assert_eq!(s.pop(now).unwrap(), cell(2, 0xEE));
        assert_eq!(s.pop(now).unwrap(), cell(1, 1));
    }

    #[test]
    fn backlogged_flows_share_round_robin_and_keep_order() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        for i in 0..5 {
            s.push(cell(1, i), false, now);
            s.push(cell(2, i), false, now);
        }
        let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut order = Vec::new();
        while let Some(m) = s.pop(now) {
            order.push(m[8]); // low byte of the circuit id
            let n = seen.len();
            seen.entry(m).or_insert(n);
        }
        assert_eq!(order, vec![1, 2, 1, 2, 1, 2, 1, 2, 1, 2]);
        assert!(s.flows.is_empty() && s.new_flows.is_empty() && s.old_flows.is_empty());
        // Within a flow, order is kept.
        let mut s = Scheduler::new(cfg());
        for i in 0..10 {
            s.push(cell(1, i), false, now);
        }
        for i in 0..10 {
            assert_eq!(s.pop(now).unwrap(), cell(1, i));
        }
    }

    #[test]
    fn background_keeps_a_minimum_share() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        for i in 0..200 {
            s.push(keepalive(), false, now);
            s.push(cell(1, i as u8), false, now);
            s.push(dht(), false, now);
        }
        let (mut low, mut total) = (0, 0);
        for _ in 0..200 {
            let m = s.pop(now).unwrap();
            total += m.len();
            if classify(&m).0 == Class::Background {
                low += m.len();
            }
        }
        let share = low as f64 / total as f64;
        assert!(share >= 0.08, "background share {:.3}", share);
        // A keepalive is never stuck behind background.
        let mut s = Scheduler::new(cfg());
        s.push(dht(), false, now);
        s.push(keepalive(), false, now);
        assert_eq!(s.pop(now).unwrap(), keepalive());
    }

    #[test]
    fn standing_queue_is_dropped_but_control_is_not() {
        let c = cfg();
        let mut s = Scheduler::new(c.clone());
        let t0 = Instant::now();
        for i in 0..50 {
            s.push(cell(1, i), false, t0);
        }
        s.push(keepalive(), false, t0);
        // Everything waited far past target, and keeps waiting: pops spread
        // over several intervals, as on a slow line.
        let mut later = t0 + c.interval * 4;
        assert_eq!(s.pop(later).unwrap(), keepalive());
        let mut sent = 0;
        while s.pop(later).is_some() {
            sent += 1;
            later += c.interval / 4;
        }
        assert!(s.dropped() > 0);
        assert!(sent < 50);
        // Short waits are never dropped.
        let mut s = Scheduler::new(c.clone());
        for i in 0..50 {
            s.push(cell(1, i), false, t0);
        }
        let soon = t0 + c.target / 2;
        let mut sent = 0;
        while s.pop(soon).is_some() {
            sent += 1;
        }
        assert_eq!(sent, 50);
        assert_eq!(s.dropped(), 0);
    }

    #[test]
    fn byte_cap_sheds_background_then_the_fattest_flow() {
        let mut c = cfg();
        c.byte_cap = 1500;
        let mut s = Scheduler::new(c);
        let now = Instant::now();
        for _ in 0..10 {
            s.push(dht(), false, now);
        }
        s.push(cell(2, 0xEE), false, now);
        for i in 0..20 {
            s.push(cell(1, i), false, now);
        }
        for _ in 0..5 {
            s.push(create(), false, now);
        }
        assert!(s.fifo[Class::Background as usize].is_empty(), "background shed first");
        assert_eq!(s.fifo[Class::CircuitControl as usize].len(), 5, "control never dropped");
        assert_eq!(s.flows[&classify(&cell(2, 0)).1.unwrap()].0.queue.len(), 1, "the thin flow kept");
        assert!(s.total_bytes <= 1500);
    }

    #[test]
    fn critical_sends_are_circuit_control() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        for i in 0..10 {
            s.push(cell(1, i), false, now);
        }
        s.push(cell(1, 0xCC), true, now);
        assert_eq!(s.pop(now).unwrap(), cell(1, 0xCC));
    }
}
