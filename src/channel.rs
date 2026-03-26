use std::collections::{BTreeMap, HashSet, VecDeque};
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
/// Initial retransmission timeout.
const INITIAL_RTO_MS: u64 = 1000;
/// Maximum retransmission timeout after backoff.
const MAX_RTO_MS: u64 = 30_000;
/// Channel is declared dead after this long without any ACK.
const CHANNEL_DEATH_TIMEOUT_MS: u64 = 60_000;

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
}

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
    /// Current retransmission timeout (exponential backoff).
    rto_ms: u64,
    /// Last time we received any ACK (for death detection).
    last_ack_at: Instant,
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
            rto_ms: INITIAL_RTO_MS,
            last_ack_at: now,
            created_at: now,
            recv_next: 0,
            recv_buf: BTreeMap::new(),
            recv_seen: HashSet::new(),
            recv_ready: VecDeque::new(),
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
                let seq = state.send_seq;
                state.send_seq = state.send_seq.wrapping_add(1);
                state.send_buf.insert(seq, data.clone());
                state.send_times.insert(seq, Instant::now());
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
    pub fn process_ack(&mut self, ack_seq: u32, selective_acks: &[u32]) -> Vec<u32> {
        let state = match self.state.reliable_state_mut() {
            Some(s) => s,
            None => return vec![],
        };
        let mut acked = Vec::new();

        // Cumulative ACK: everything before ack_seq is acknowledged
        // (wrapping-safe: ack_seq is strictly after seq)
        let to_remove: Vec<u32> = state
            .send_buf
            .keys()
            .copied()
            .filter(|&seq| seq_after(ack_seq, seq))
            .collect();
        for seq in to_remove {
            state.send_buf.remove(&seq);
            state.send_times.remove(&seq);
            acked.push(seq);
        }

        // Selective ACKs
        for &seq in selective_acks {
            if state.send_buf.remove(&seq).is_some() {
                state.send_times.remove(&seq);
                acked.push(seq);
            }
        }

        if !acked.is_empty() {
            state.last_ack_at = Instant::now();
            // Reset RTO on successful ACK
            state.rto_ms = INITIAL_RTO_MS;
        }

        acked
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

    /// Get packets due for retransmission based on RTO.
    /// Returns (sequence, payload) pairs and applies exponential backoff to RTO.
    pub fn retransmit_due(&mut self) -> Vec<(u32, Vec<u8>)> {
        let state = match self.state.reliable_state_mut() {
            Some(s) => s,
            None => return vec![],
        };
        let now = Instant::now();
        let rto = Duration::from_millis(state.rto_ms);
        let mut due = Vec::new();
        for (&seq, data) in &state.send_buf {
            if due.len() >= MAX_RETRANSMIT_BATCH {
                break;
            }
            if let Some(&sent_at) = state.send_times.get(&seq) {
                if now.duration_since(sent_at) >= rto {
                    due.push((seq, data.clone()));
                }
            }
        }
        if !due.is_empty() {
            // Exponential backoff with jitter (±25%) to desynchronize
            // retransmits across channels/nodes that hit the same loss event.
            let base = state.rto_ms * 2;
            let jitter_range = base / 4;
            let jittered = if jitter_range > 0 {
                let offset = rand::thread_rng().gen_range(0..=jitter_range * 2);
                base - jitter_range + offset
            } else {
                base
            };
            state.rto_ms = jittered.min(MAX_RTO_MS);
            // Reset send times for retransmitted packets
            for &(seq, _) in &due {
                state.send_times.insert(seq, now);
            }
        }
        due
    }

    /// Check whether this channel should be declared dead.
    /// A channel is dead if it has unacked data and hasn't received
    /// any ACK within the death timeout.
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
    }

    /// Returns the earliest instant at which a retransmit will be due,
    /// or `None` if there are no unacked packets.
    pub fn next_retransmit_at(&self) -> Option<Instant> {
        let state = self.state.reliable_state()?;
        if state.send_buf.is_empty() {
            return None;
        }
        let rto = Duration::from_millis(state.rto_ms);
        state
            .send_times
            .values()
            .map(|&sent_at| sent_at + rto)
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
