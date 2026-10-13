use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::time::{Duration, Instant};

use rand::Rng;

use crate::wire;

/// Maximum number of selective ACK entries to include in an ACK message.
const MAX_SELECTIVE_ACKS: usize = 32;

const DEFAULT_WINDOW_SIZE: u32 = 32;

/// Maximum out-of-order packets buffered on the receive side.
/// Caps memory usage from peers sending wildly out-of-order sequences.
const MAX_RECV_BUF: usize = 128;

/// Maximum retransmit batch per call to avoid burst storms after outages.
const MAX_RETRANSMIT_BATCH: usize = 8;

/// Wrapping-safe sequence comparison: true if `a` is strictly after `b`
/// in the circular u32 sequence space (within a 2^31 window).
fn seq_after(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) as i32 > 0
}

/// Wrapping-safe: true if a is after or equal to b.
fn seq_after_eq(a: u32, b: u32) -> bool {
    a == b || seq_after(a, b)
}
/// Retransmission timeout before the first RTT sample.
const INITIAL_RTO_MS: u64 = 1000;
/// Floor on the RTT-derived retransmission timeout.
const MIN_RTO_MS: u64 = 200;
/// Ceiling on the RTT-derived retransmission timeout.
const MAX_RTO_MS: u64 = 30_000;
/// Exponential backoff stops here (or at the RTT-derived timeout, if that is
/// higher). On a lossy but live path, backing off further mostly delays the
/// one retry that would have got through; a channel only retries its few
/// outstanding packets, so frequent retries cost little.
const MAX_BACKOFF_MS: u64 = 8_000;
/// Before the first RTT sample, a hole revealed by a selective ACK is
/// retransmitted once it has been in flight this long.
const FAST_RETRANSMIT_FLOOR_MS: u64 = 50;
/// Channel is declared dead after this long without any ACK, and only once
/// `CHANNEL_DEATH_RETRIES` retransmission rounds have gone unanswered: time
/// alone would kill a live channel on a very lossy path (with half the
/// packets lost each way, a single retry only gets an ACK back 1 in 4 times).
const CHANNEL_DEATH_TIMEOUT_MS: u64 = 60_000;
const CHANNEL_DEATH_RETRIES: u32 = 24;

/// A multiplexed channel within a tunnel.
/// Independent reliable/ordered flags give four modes:
///   - raw datagram:       !reliable, !ordered  — fire-and-forget
///   - sequenced datagram: !reliable, ordered   — drop late, deliver latest in order
///   - reliable unordered: reliable,  !ordered  — ACKs + retransmit, deliver immediately
///   - reliable ordered:   reliable,  ordered   — ACKs + retransmit + reorder buffer
pub struct Channel {
    pub channel_id: u32,
    pub port: [u8; 32],
    pub reliable: bool,
    pub ordered: bool,
    state: ChannelState,
    /// Opener side: `ChannelOpen` is one message that may be lost, so it is
    /// resent until the peer shows it has the channel (sends ACK or data).
    open_retry: Option<OpenRetry>,
}

struct OpenRetry {
    next_at: Instant,
    interval: Duration,
    give_up_at: Instant,
}

/// First `ChannelOpen` resend, doubling up to the max, for at most the window.
const OPEN_RETRY_INITIAL: Duration = Duration::from_millis(500);
const OPEN_RETRY_MAX: Duration = Duration::from_secs(4);
const OPEN_RETRY_WINDOW: Duration = Duration::from_secs(30);

enum ChannelState {
    /// !reliable, !ordered — raw datagram, no state
    RawDatagram,
    /// !reliable, ordered — sequenced datagram, track recv_seq
    SequencedDatagram(SequencedState),
    /// reliable, !ordered — ACKs + retransmit, deliver immediately
    ReliableUnordered(ReliableState),
    /// reliable, ordered — ACKs + retransmit + reorder buffer
    ReliableOrdered(ReliableState),
}

/// State for sequenced (ordered, unreliable) datagrams.
struct SequencedState {
    send_seq: u32,
    recv_seq: u32,
}

impl SequencedState {
    fn new() -> Self {
        Self {
            send_seq: 0,
            recv_seq: 0,
        }
    }
}

/// Reliable delivery state: sliding window with selective ACK.
struct ReliableState {
    // Sender
    send_seq: u32,
    send_window: u32,
    send_buf: BTreeMap<u32, Vec<u8>>,
    /// Per-packet first-send timestamp for RTO calculation.
    send_times: BTreeMap<u32, Instant>,
    /// Per-packet retransmission timeout. Retrying a batch must not postpone
    /// other packets that are already due.
    send_rtos: BTreeMap<u32, u64>,
    /// Packets sent more than once: their ACKs give no RTT sample (Karn).
    retransmitted: HashSet<u32>,
    /// Holes revealed by a selective ACK, due for retransmission now.
    fast_due: BTreeSet<u32>,
    /// Smoothed RTT and its variance (RFC 6298), once sampled.
    srtt: Option<Duration>,
    rttvar: Duration,
    /// Last time we received any ACK (for death detection).
    last_ack_at: Instant,
    /// Retransmission rounds since the last ACK (for death detection).
    retries_since_ack: u32,
    /// When this channel was created (for death detection before first ACK).
    created_at: Instant,
    // Receiver — ordered mode: full reorder buffer
    recv_next: u32,
    recv_buf: BTreeMap<u32, Vec<u8>>,
    // Receiver — unordered mode: lightweight seen-set (no payload stored)
    recv_seen: HashSet<u32>,
    // Delivered data ready for the application
    recv_ready: VecDeque<Vec<u8>>,
}

impl ReliableState {
    fn with_window(window: u32) -> Self {
        let now = Instant::now();
        Self {
            send_seq: 0,
            send_window: window,
            send_buf: BTreeMap::new(),
            send_times: BTreeMap::new(),
            send_rtos: BTreeMap::new(),
            retransmitted: HashSet::new(),
            fast_due: BTreeSet::new(),
            srtt: None,
            rttvar: Duration::ZERO,
            last_ack_at: now,
            retries_since_ack: 0,
            created_at: now,
            recv_next: 0,
            recv_buf: BTreeMap::new(),
            recv_seen: HashSet::new(),
            recv_ready: VecDeque::new(),
        }
    }
}

impl ReliableState {
    /// RTO for a packet's first retry: RFC 6298 `srtt + 4·rttvar`, clamped.
    fn base_rto_ms(&self) -> u64 {
        match self.srtt {
            Some(srtt) => ((srtt + self.rttvar * 4).as_millis() as u64).clamp(MIN_RTO_MS, MAX_RTO_MS),
            None => INITIAL_RTO_MS,
        }
    }

    fn sample_rtt(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let diff = if srtt > rtt { srtt - rtt } else { rtt - srtt };
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
    }

    fn forget(&mut self, seq: u32) -> Option<Instant> {
        self.send_buf.remove(&seq)?;
        self.send_rtos.remove(&seq);
        self.fast_due.remove(&seq);
        let sent_at = self.send_times.remove(&seq);
        if self.retransmitted.remove(&seq) {
            None
        } else {
            sent_at
        }
    }
}

impl ChannelState {
    fn reliable_state(&self) -> Option<&ReliableState> {
        match self {
            ChannelState::ReliableUnordered(s) | ChannelState::ReliableOrdered(s) => Some(s),
            _ => None,
        }
    }

    fn reliable_state_mut(&mut self) -> Option<&mut ReliableState> {
        match self {
            ChannelState::ReliableUnordered(s) | ChannelState::ReliableOrdered(s) => Some(s),
            _ => None,
        }
    }
}

impl Channel {
    /// Create a new channel with independent reliable/ordered flags.
    pub fn new(channel_id: u32, port: [u8; 32], reliable: bool, ordered: bool) -> Self {
        Self::with_window(channel_id, port, reliable, ordered, DEFAULT_WINDOW_SIZE)
    }

    /// Create a channel with a custom send window size.
    pub fn with_window(channel_id: u32, port: [u8; 32], reliable: bool, ordered: bool, window: u32) -> Self {
        let state = match (reliable, ordered) {
            (false, false) => ChannelState::RawDatagram,
            (false, true) => ChannelState::SequencedDatagram(SequencedState::new()),
            (true, false) => ChannelState::ReliableUnordered(ReliableState::with_window(window)),
            (true, true) => ChannelState::ReliableOrdered(ReliableState::with_window(window)),
        };
        Self {
            channel_id,
            port,
            reliable,
            ordered,
            state,
            open_retry: None,
        }
    }

    /// We sent `ChannelOpen` for this channel: keep resending it until the
    /// peer confirms (see [`confirm_open`]).
    pub fn mark_opened_locally(&mut self) {
        let now = Instant::now();
        self.open_retry = Some(OpenRetry {
            next_at: now + OPEN_RETRY_INITIAL,
            interval: OPEN_RETRY_INITIAL,
            give_up_at: now + OPEN_RETRY_WINDOW,
        });
    }

    /// The peer sent something on this channel, so it received the open.
    pub fn confirm_open(&mut self) {
        self.open_retry = None;
    }

    /// True when `ChannelOpen` should be resent now; schedules the next one.
    pub fn open_resend_due(&mut self, now: Instant) -> bool {
        let Some(r) = self.open_retry.as_mut() else {
            return false;
        };
        if now >= r.give_up_at {
            self.open_retry = None;
            return false;
        }
        if now < r.next_at {
            return false;
        }
        r.interval = (r.interval * 2).min(OPEN_RETRY_MAX);
        r.next_at = now + r.interval;
        true
    }

    /// Earliest instant this channel needs the retransmit task: a data
    /// retransmit or a `ChannelOpen` resend.
    pub fn next_wakeup(&self) -> Option<Instant> {
        let open = self.open_retry.as_ref().map(|r| r.next_at);
        match (self.next_retransmit_at(), open) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Create a channel from a port name string.
    pub fn from_port_name(channel_id: u32, port_name: &str, reliable: bool, ordered: bool) -> Self {
        let port = wire::hash_port_name(port_name);
        Self::new(channel_id, port, reliable, ordered)
    }

    /// Prepare data for sending. Returns (sequence_number, payload) pairs.
    /// For raw datagram channels, sequence is always 0.
    pub fn prepare_send(&mut self, data: Vec<u8>) -> Vec<(u32, Vec<u8>)> {
        match &mut self.state {
            ChannelState::RawDatagram => vec![(0, data)],
            ChannelState::SequencedDatagram(state) => {
                let seq = state.send_seq;
                state.send_seq = state.send_seq.wrapping_add(1);
                vec![(seq, data)]
            }
            ChannelState::ReliableUnordered(state) | ChannelState::ReliableOrdered(state) => {
                if state.send_buf.is_empty() {
                    state.last_ack_at = Instant::now();
                    state.created_at = state.last_ack_at;
                    state.retries_since_ack = 0;
                }
                let seq = state.send_seq;
                state.send_seq = state.send_seq.wrapping_add(1);
                state.send_buf.insert(seq, data.clone());
                state.send_times.insert(seq, Instant::now());
                let rto = state.base_rto_ms();
                state.send_rtos.insert(seq, rto);
                vec![(seq, data)]
            }
        }
    }

    /// Process a received data message. Returns data ready for the application.
    pub fn receive_data(&mut self, sequence: u32, data: Vec<u8>) -> Vec<Vec<u8>> {
        match &mut self.state {
            ChannelState::RawDatagram => {
                // Immediate passthrough, no state
                vec![data]
            }
            ChannelState::SequencedDatagram(state) => {
                // Deliver only if seq >= recv_seq (drop late packets)
                if seq_after_eq(sequence, state.recv_seq) {
                    state.recv_seq = sequence.wrapping_add(1);
                    vec![data]
                } else {
                    vec![] // late packet, drop
                }
            }
            ChannelState::ReliableUnordered(state) => {
                // Deliver immediately on receipt, no reordering
                if sequence == state.recv_next {
                    // Next expected — deliver and advance
                    state.recv_ready.push_back(data);
                    state.recv_next = state.recv_next.wrapping_add(1);
                    // Advance past any seen seqs
                    while state.recv_seen.remove(&state.recv_next) {
                        state.recv_next = state.recv_next.wrapping_add(1);
                    }
                } else if seq_after(sequence, state.recv_next)
                    && !state.recv_seen.contains(&sequence)
                    && state.recv_seen.len() < MAX_RECV_BUF
                {
                    // Out-of-order, not yet seen — deliver and mark
                    state.recv_ready.push_back(data);
                    state.recv_seen.insert(sequence);
                }
                // else: duplicate, old, or recv buffer full — drop
                state.recv_ready.drain(..).collect()
            }
            ChannelState::ReliableOrdered(state) => {
                // In-order delivery with reorder buffer
                if sequence == state.recv_next {
                    state.recv_ready.push_back(data);
                    state.recv_next = state.recv_next.wrapping_add(1);
                    // Deliver any buffered consecutive packets
                    while let Some(buffered) = state.recv_buf.remove(&state.recv_next) {
                        state.recv_ready.push_back(buffered);
                        state.recv_next = state.recv_next.wrapping_add(1);
                    }
                } else if seq_after(sequence, state.recv_next)
                    && state.recv_buf.len() < MAX_RECV_BUF
                {
                    // Out-of-order: buffer it (idempotent on duplicates)
                    state.recv_buf.entry(sequence).or_insert(data);
                }
                // else: duplicate, old, or recv buffer full — drop
                state.recv_ready.drain(..).collect()
            }
        }
    }

    /// Generate an ACK message for the current receive state.
    /// Returns None for unreliable channels.
    pub fn generate_ack(&self) -> Option<(u32, Vec<u32>)> {
        match &self.state {
            ChannelState::ReliableUnordered(state) => {
                let selective: Vec<u32> = state
                    .recv_seen
                    .iter()
                    .copied()
                    .take(MAX_SELECTIVE_ACKS)
                    .collect();
                Some((state.recv_next, selective))
            }
            ChannelState::ReliableOrdered(state) => {
                let selective: Vec<u32> = state
                    .recv_buf
                    .keys()
                    .copied()
                    .take(MAX_SELECTIVE_ACKS)
                    .collect();
                Some((state.recv_next, selective))
            }
            _ => None,
        }
    }

    /// Process a received ACK. Returns sequence numbers that were acknowledged
    /// (and can be removed from send buffer).
    ///
    /// Any newly acknowledged packet proves the path works, so the remaining
    /// packets drop their exponential backoff back to the RTT-based timeout:
    /// backoff is for a silent path, not for random loss on a live one. Holes
    /// below the highest selectively acknowledged sequence are marked for
    /// immediate retransmission (see [`has_fast_retransmit`](Self::has_fast_retransmit)).
    pub fn process_ack(&mut self, ack_seq: u32, selective_acks: &[u32]) -> Vec<u32> {
        let state = match self.state.reliable_state_mut() {
            Some(s) => s,
            None => return vec![],
        };
        let mut acked = Vec::new();
        if seq_after(ack_seq, state.send_seq) {
            return acked;
        }
        let now = Instant::now();
        let mut rtt_sample: Option<Duration> = None;

        // Cumulative ACK: everything before ack_seq is acknowledged
        // (wrapping-safe: ack_seq is strictly after seq)
        let to_remove: Vec<u32> = state
            .send_buf
            .keys()
            .copied()
            .filter(|&seq| seq_after(ack_seq, seq))
            .collect();
        for seq in to_remove {
            if let Some(sent_at) = state.forget(seq) {
                rtt_sample = Some(now.duration_since(sent_at));
            }
            acked.push(seq);
        }

        // Selective ACKs
        let mut highest_sacked: Option<u32> = None;
        for &seq in selective_acks {
            if !seq_after(state.send_seq, seq) {
                continue;
            }
            if highest_sacked.map_or(true, |h| seq_after(seq, h)) {
                highest_sacked = Some(seq);
            }
            if state.send_buf.contains_key(&seq) {
                if let Some(sent_at) = state.forget(seq) {
                    rtt_sample = Some(now.duration_since(sent_at));
                }
                acked.push(seq);
            }
        }

        if acked.is_empty() {
            return acked;
        }
        state.last_ack_at = now;
        state.retries_since_ack = 0;
        if let Some(rtt) = rtt_sample {
            state.sample_rtt(rtt);
        }

        // The path is alive: clear backoff on everything still outstanding.
        let base = state.base_rto_ms();
        for rto in state.send_rtos.values_mut() {
            *rto = base;
        }

        // Fast retransmit: a packet older than the highest SACKed one that has
        // been in flight for about an RTT was lost, not delayed.
        if let Some(high) = highest_sacked {
            let in_flight_floor = state
                .srtt
                .unwrap_or(Duration::from_millis(FAST_RETRANSMIT_FLOOR_MS));
            let holes: Vec<u32> = state
                .send_buf
                .keys()
                .copied()
                .filter(|&seq| seq_after(high, seq))
                .filter(|seq| {
                    state
                        .send_times
                        .get(seq)
                        .is_some_and(|&t| now.duration_since(t) >= in_flight_floor)
                })
                .collect();
            state.fast_due.extend(holes);
        }

        acked
    }

    /// Whether a selective ACK revealed holes that should be resent now.
    pub fn has_fast_retransmit(&self) -> bool {
        self.state
            .reliable_state()
            .is_some_and(|s| !s.fast_due.is_empty())
    }

    /// Get packets that need retransmission (still in send buffer).
    pub fn pending_retransmit(&self) -> Vec<(u32, &[u8])> {
        match self.state.reliable_state() {
            Some(state) => state
                .send_buf
                .iter()
                .map(|(&seq, data)| (seq, data.as_slice()))
                .collect(),
            None => vec![],
        }
    }

    /// Check if the send window allows more data.
    pub fn can_send(&self) -> bool {
        match self.state.reliable_state() {
            Some(state) => (state.send_buf.len() as u32) < state.send_window,
            None => true,
        }
    }

    /// Get packets due for retransmission: fast-retransmit holes first, then
    /// RTO expiries. Returns (sequence, payload) pairs and applies exponential
    /// backoff to each packet sent, until an ACK shows the path is alive again.
    pub fn retransmit_due(&mut self) -> Vec<(u32, Vec<u8>)> {
        let state = match self.state.reliable_state_mut() {
            Some(s) => s,
            None => return vec![],
        };
        let now = Instant::now();
        let mut due: Vec<(u32, Vec<u8>)> = Vec::new();
        let fast: Vec<u32> = state.fast_due.iter().copied().collect();
        for seq in fast {
            if due.len() >= MAX_RETRANSMIT_BATCH {
                break;
            }
            state.fast_due.remove(&seq);
            if let Some(data) = state.send_buf.get(&seq) {
                due.push((seq, data.clone()));
            }
        }
        for (&seq, data) in &state.send_buf {
            if due.len() >= MAX_RETRANSMIT_BATCH {
                break;
            }
            if due.iter().any(|(s, _)| *s == seq) {
                continue;
            }
            if let Some(&sent_at) = state.send_times.get(&seq) {
                let rto = Duration::from_millis(state.send_rtos[&seq]);
                if now.duration_since(sent_at) >= rto {
                    due.push((seq, data.clone()));
                }
            }
        }
        if !due.is_empty() {
            state.retries_since_ack = state.retries_since_ack.saturating_add(1);
        }
        let backoff_cap = state.base_rto_ms().max(MAX_BACKOFF_MS);
        for &(seq, _) in &due {
            // Exponential backoff with jitter (±25%) to desynchronize
            // retransmits across channels/nodes that hit the same loss event.
            let base = state.send_rtos[&seq] * 2;
            let jitter_range = base / 4;
            let jittered = if jitter_range > 0 {
                let offset = rand::thread_rng().gen_range(0..=jitter_range * 2);
                base - jitter_range + offset
            } else {
                base
            };
            state.send_rtos.insert(seq, jittered.min(backoff_cap));
            state.send_times.insert(seq, now);
            state.retransmitted.insert(seq);
        }
        due
    }

    /// Check whether this channel should be declared dead.
    /// A channel is dead if it has unacked data and hasn't received any ACK
    /// within the death timeout, across enough unanswered retries.
    pub fn is_dead(&self) -> bool {
        let state = match self.state.reliable_state() {
            Some(s) => s,
            None => return false,
        };
        if state.send_buf.is_empty() {
            return false; // nothing pending, not dead
        }
        let now = Instant::now();
        let timeout = Duration::from_millis(CHANNEL_DEATH_TIMEOUT_MS);
        // Dead if we have unacked data and no ACK received within timeout.
        // Use last_ack_at if we ever got an ACK, otherwise use created_at.
        let reference = if state.last_ack_at > state.created_at {
            state.last_ack_at
        } else {
            state.created_at
        };
        now.duration_since(reference) >= timeout
            && state.retries_since_ack >= CHANNEL_DEATH_RETRIES
    }

    /// Returns the earliest instant at which a retransmit will be due,
    /// or `None` if there are no unacked packets.
    pub fn next_retransmit_at(&self) -> Option<Instant> {
        let state = self.state.reliable_state()?;
        if state.send_buf.is_empty() {
            return None;
        }
        if !state.fast_due.is_empty() {
            return Some(Instant::now());
        }
        state
            .send_times
            .iter()
            .map(|(seq, &sent_at)| sent_at + Duration::from_millis(state.send_rtos[seq]))
            .min()
    }

    /// Drain ready data (for application consumption).
    pub fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        match self.state.reliable_state_mut() {
            Some(state) => state.recv_ready.drain(..).collect(),
            None => vec![],
        }
    }
}

#[cfg(test)]
mod reliability_tests {
    use super::*;

    #[test]
    fn open_is_resent_with_backoff_until_confirmed() {
        let mut ch = Channel::new(1, [0; 32], true, true);
        assert!(!ch.open_resend_due(Instant::now())); // never opened locally
        ch.mark_opened_locally();
        let t0 = Instant::now();
        assert!(!ch.open_resend_due(t0));
        assert!(ch.next_wakeup().is_some());
        assert!(ch.open_resend_due(t0 + OPEN_RETRY_INITIAL));
        // Next one is twice as far out.
        assert!(!ch.open_resend_due(t0 + OPEN_RETRY_INITIAL * 2));
        assert!(ch.open_resend_due(t0 + OPEN_RETRY_INITIAL * 3));
        ch.confirm_open();
        assert!(!ch.open_resend_due(t0 + OPEN_RETRY_WINDOW / 2));
        assert!(ch.next_wakeup().is_none());

        // Gives up after the window.
        ch.mark_opened_locally();
        assert!(!ch.open_resend_due(Instant::now() + OPEN_RETRY_WINDOW));
        assert!(ch.next_wakeup().is_none());
    }

    #[test]
    fn lost_data_and_ack_recover_without_duplicate_delivery() {
        let mut sender = Channel::new(0, [0; 32], true, true);
        let mut receiver = Channel::new(0, [0; 32], true, true);
        let first = sender.prepare_send(b"first".to_vec()).remove(0);
        let second = sender.prepare_send(b"second".to_vec()).remove(0);
        assert!(receiver.receive_data(second.0, second.1.clone()).is_empty());
        let (ack, selective) = receiver.generate_ack().unwrap();
        sender.process_ack(ack, &selective);
        assert_eq!(sender.pending_retransmit().len(), 1);
        assert_eq!(
            receiver.receive_data(first.0, first.1.clone()),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
        // Lose that ACK: a retry is deduplicated and produces the same ACK.
        assert!(receiver.receive_data(first.0, first.1).is_empty());
        let (ack, selective) = receiver.generate_ack().unwrap();
        sender.process_ack(ack, &selective);
        assert!(sender.pending_retransmit().is_empty());
    }

    #[test]
    fn future_ack_cannot_discard_pending_data() {
        let mut channel = Channel::new(0, [0; 32], true, true);
        channel.prepare_send(vec![1]);
        assert!(channel.process_ack(100, &[0]).is_empty());
        assert_eq!(channel.pending_retransmit().len(), 1);
        channel.process_ack(0, &[100]);
        assert_eq!(channel.pending_retransmit().len(), 1);
    }

    #[test]
    fn lossy_live_channel_is_not_declared_dead_on_time_alone() {
        let mut channel = Channel::new(0, [0; 32], true, true);
        channel.prepare_send(vec![1]);
        let state = channel.state.reliable_state_mut().unwrap();
        state.last_ack_at -= Duration::from_secs(120);
        state.created_at = state.last_ack_at;
        state.retries_since_ack = CHANNEL_DEATH_RETRIES - 1;
        assert!(!channel.is_dead());
        channel.state.reliable_state_mut().unwrap().retries_since_ack = CHANNEL_DEATH_RETRIES;
        assert!(channel.is_dead());
        // Any ACK resets the count.
        channel.process_ack(1, &[]);
        assert!(!channel.is_dead());
    }

    #[test]
    fn backoff_is_capped() {
        let mut channel = Channel::new(0, [0; 32], true, true);
        let (seq, _) = channel.prepare_send(vec![1]).remove(0);
        for _ in 0..10 {
            let state = channel.state.reliable_state_mut().unwrap();
            let t = state.send_times.get_mut(&seq).unwrap();
            *t -= Duration::from_secs(60);
            assert_eq!(channel.retransmit_due().len(), 1);
        }
        let rto = channel.state.reliable_state().unwrap().send_rtos[&seq];
        assert!(rto <= MAX_BACKOFF_MS, "rto {rto}");
    }

    #[test]
    fn idle_channel_gets_a_fresh_ack_deadline() {
        let mut channel = Channel::new(0, [0; 32], true, true);
        let state = channel.state.reliable_state_mut().unwrap();
        state.last_ack_at -= Duration::from_secs(120);
        state.created_at = state.last_ack_at;
        channel.prepare_send(vec![1]);
        assert!(!channel.is_dead());
    }

    #[test]
    fn retransmission_preserves_sequence_and_payload() {
        let mut channel = Channel::new(0, [0; 32], true, true);
        let packet = channel.prepare_send(vec![7, 8]).remove(0);
        *channel
            .state
            .reliable_state_mut()
            .unwrap()
            .send_times
            .get_mut(&packet.0)
            .unwrap() -= Duration::from_secs(2);
        assert_eq!(channel.retransmit_due(), vec![packet]);
        assert!(channel.retransmit_due().is_empty());
    }

    #[test]
    fn retrying_a_batch_does_not_postpone_other_due_packets() {
        let mut channel = Channel::new(0, [0; 32], true, true);
        for _ in 0..32 {
            channel.prepare_send(vec![1]);
        }
        for sent in channel
            .state
            .reliable_state_mut()
            .unwrap()
            .send_times
            .values_mut()
        {
            *sent -= Duration::from_secs(2);
        }
        let mut retried = HashSet::new();
        for _ in 0..4 {
            let batch = channel.retransmit_due();
            assert_eq!(batch.len(), 8);
            for (seq, _) in batch {
                assert!(retried.insert(seq));
            }
        }
        assert_eq!(retried.len(), 32);
        assert!(channel.retransmit_due().is_empty());
    }

    fn age_all(channel: &mut Channel, by: Duration) {
        for sent in channel
            .state
            .reliable_state_mut()
            .unwrap()
            .send_times
            .values_mut()
        {
            *sent -= by;
        }
    }

    #[test]
    fn ack_progress_clears_backoff_on_outstanding_packets() {
        let mut channel = Channel::new(0, [0; 32], true, true);
        let first = channel.prepare_send(vec![1]).remove(0);
        let _second = channel.prepare_send(vec![2]).remove(0);
        // Both time out twice: backoff grows.
        for _ in 0..2 {
            age_all(&mut channel, Duration::from_secs(10));
            assert_eq!(channel.retransmit_due().len(), 2);
        }
        let rto_before = channel.state.reliable_state().unwrap().send_rtos[&first.0];
        assert!(rto_before >= 3 * INITIAL_RTO_MS);
        // The second arrives: the path is alive, so the first's backoff resets.
        channel.process_ack(0, &[1]);
        let state = channel.state.reliable_state().unwrap();
        assert!(state.send_rtos[&first.0] <= INITIAL_RTO_MS);
    }

    #[test]
    fn selective_ack_hole_is_fast_retransmitted() {
        let mut sender = Channel::new(0, [0; 32], true, true);
        let mut receiver = Channel::new(0, [0; 32], true, true);
        let lost = sender.prepare_send(b"lost".to_vec()).remove(0);
        let arrived = sender.prepare_send(b"arrived".to_vec()).remove(0);
        age_all(&mut sender, Duration::from_millis(FAST_RETRANSMIT_FLOOR_MS));
        assert!(receiver.receive_data(arrived.0, arrived.1).is_empty());
        let (ack, selective) = receiver.generate_ack().unwrap();
        sender.process_ack(ack, &selective);
        assert!(sender.has_fast_retransmit());
        assert!(sender.next_retransmit_at().unwrap() <= Instant::now());
        // Due immediately, long before its RTO.
        assert_eq!(sender.retransmit_due(), vec![lost]);
        assert!(!sender.has_fast_retransmit());
    }

    #[test]
    fn rtt_samples_shrink_the_timeout_and_skip_retransmitted_packets() {
        let mut channel = Channel::new(0, [0; 32], true, true);
        channel.prepare_send(vec![1]);
        channel.process_ack(1, &[]);
        let state = channel.state.reliable_state().unwrap();
        assert!(state.srtt.is_some());
        assert_eq!(state.base_rto_ms(), MIN_RTO_MS, "a fast local path hits the floor");

        // A retransmitted packet's ACK is ambiguous and gives no sample.
        let mut channel = Channel::new(0, [0; 32], true, true);
        channel.prepare_send(vec![1]);
        age_all(&mut channel, Duration::from_secs(5));
        assert_eq!(channel.retransmit_due().len(), 1);
        channel.process_ack(1, &[]);
        assert!(channel.state.reliable_state().unwrap().srtt.is_none());
    }

    /// Under 50% random loss in both directions, a burst of packets still
    /// gets through in bounded time (the e2e firewall tests' situation).
    #[test]
    fn heavy_random_loss_recovers_quickly() {
        let mut rng = rand::thread_rng();
        let mut sender = Channel::new(0, [0; 32], true, true);
        let mut receiver = Channel::new(0, [0; 32], true, true);
        let mut delivered = Vec::new();
        let mut wire: Vec<(u32, Vec<u8>)> = Vec::new();
        for i in 0..20u8 {
            wire.extend(sender.prepare_send(vec![i]));
        }
        // Simulated time in 10 ms ticks; each tick delivers the wire and its
        // ACKs with 50% loss each way.
        let tick = Duration::from_millis(10);
        let mut ticks = 0;
        while delivered.len() < 20 {
            ticks += 1;
            assert!(ticks < 3000, "only {} of 20 delivered after 30 s", delivered.len());
            for (seq, data) in wire.drain(..) {
                if rng.gen_bool(0.5) {
                    delivered.extend(receiver.receive_data(seq, data));
                    if rng.gen_bool(0.5) {
                        let (ack, sel) = receiver.generate_ack().unwrap();
                        sender.process_ack(ack, &sel);
                    }
                }
            }
            age_all(&mut sender, tick);
            loop {
                let due = sender.retransmit_due();
                if due.is_empty() {
                    break;
                }
                wire.extend(due);
            }
        }
        assert_eq!(delivered, (0..20u8).map(|i| vec![i]).collect::<Vec<_>>());
    }
}
