//! Circuit-based forwarding: replaces origin/destination headers with opaque circuit IDs.
//!
//! A circuit is a path through the network where each relay only knows
//! the previous hop and next hop. Relays see `circuit_id || blob` — nothing else.
//!
//! Circuit setup is telescoping: the initiator extends the circuit one hop at a time,
//! encrypting each setup message to the target hop's public key.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use rand::RngCore;

use crate::crypto::{kdf, mac_16};
use crate::types::{Error, PeerId, Result};

pub use crate::onion::{
    cell_trailer, seal_outward, CryptoOp, HopCrypto, HopKey, LayerKeys, OnionLayers, Peeled,
    ReplayWindow, CELL_BODY_SIZE, CELL_CRYPTO_VERSION, CELL_SIZE,
};

/// Header: command(1) + stream_id(2) + length(2).
const CELL_HEADER_SIZE: usize = 5;
/// SENDME digest size.
const DIGEST_SIZE: usize = 16;
/// Maximum payload bytes in a single relay cell.
pub const CELL_PAYLOAD_MAX: usize = CELL_BODY_SIZE - CELL_HEADER_SIZE;
/// Set in a relay cell's length field when more cells of the same relay
/// message follow.
const LENGTH_MORE: u16 = 0x8000;
/// Largest relay message carried across several cells. Bounds reassembly
/// memory; a post-quantum EXTEND is ~1.3 KB.
pub const RELAY_MESSAGE_MAX: usize = 16 * 1024;
/// Payload bytes of the first cell of a multi-cell message (after total_len).
const FIRST_PIECE_MAX: usize = CELL_PAYLOAD_MAX - 2;
/// Payload bytes of a continuation cell (after its index).
const CONTINUE_PIECE_MAX: usize = CELL_PAYLOAD_MAX - 1;

// --- Flow control constants ---
/// Initial congestion window. Must be > SENDME_INC so the sender can push
/// enough cells to trigger the first SENDME from the receiver.
pub const CWND_INIT: u32 = SENDME_INC * 2;
pub const CWND_MIN: u32 = SENDME_INC + 1;
pub const CWND_MAX: u32 = 2048;
pub const SENDME_INC: u32 = 32;
pub const SS_MAX: u32 = 512;
/// How long a sender waits while window-blocked before assuming the SENDME was lost.
pub const SENDME_STALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Receiver-side window: how many DATA cells we accept before a SENDME is acked.
/// Set larger than CWND_MAX so legitimate senders never hit it, but misbehaving
/// senders that ignore SENDMEs get dropped.
pub const RECV_WINDOW_INIT: u32 = 1024;
/// Maximum cells we'll tolerate beyond what we've SENDME'd for.
/// If the sender overshoots by more than this, we drop the cell.
pub const RECV_WINDOW_OVERSHOOT: u32 = SENDME_INC * 2;

/// A circuit ID: 4-byte identifier, unique per-link.
pub type CircuitId = u32;

/// Direction-aware circuit table key: (circuit_id, from_peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitKey {
    pub circuit_id: CircuitId,
    pub from_peer: PeerId,
}

/// What a relay does with a circuit cell.
#[derive(Debug, Clone)]
pub enum CircuitAction {
    /// Forward to the next hop with a rewritten circuit_id.
    Forward {
        next_hop: PeerId,
        next_circuit_id: CircuitId,
        /// Onion layer crypto for this forwarding direction (None for legacy/tests).
        crypto: Option<HopCrypto>,
    },
    /// This is the circuit endpoint — deliver to the local node.
    Endpoint {
        /// The PeerId of the circuit originator (as known to us).
        /// For a multi-hop circuit, this is the previous hop, not the true origin.
        origin_hop: PeerId,
        /// Onion layer crypto for inbound cells.
        crypto: Option<HopCrypto>,
        /// Multi-cell relay messages from the originator being reassembled.
        assembler: RelayAssembler,
    },
}

/// Circuit forwarding table.
///
/// Maps (incoming_circuit_id, from_peer) → action.
/// Relays use this for blind forwarding. Endpoints use it to identify incoming circuits.
pub struct CircuitTable {
    /// Forwarding entries: key → action.
    entries: HashMap<CircuitKey, CircuitAction>,
    /// When each entry last carried a cell (or was installed).
    last_used: HashMap<CircuitKey, Instant>,
}

impl CircuitTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_used: HashMap::new(),
        }
    }

    /// Allocate a random circuit ID for a link where we know whether we initiated it.
    ///
    /// Link initiators get odd IDs, responders get even.  Since the remote
    /// peer uses the opposite parity on the same link, the circuit_table
    /// entry it creates (keyed by the remote's chosen circuit_id) can never
    /// collide with our outbound_circuits entry for the same peer.
    ///
    /// IDs are chosen randomly to avoid leaking circuit count or timing
    /// information to peers.
    pub fn alloc_id(
        &self,
        we_initiated_link: bool,
        is_taken: impl Fn(CircuitId) -> bool,
    ) -> CircuitId {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        loop {
            let raw: u32 = rng.gen();
            let id = if we_initiated_link { raw | 1 } else { raw & !1 };
            if id != 0 && !self.entries.keys().any(|key| key.circuit_id == id) && !is_taken(id) {
                return id;
            }
        }
    }

    /// Install a forwarding entry.
    pub fn insert(&mut self, key: CircuitKey, action: CircuitAction) {
        self.entries.insert(key, action);
        self.last_used.insert(key, Instant::now());
    }

    /// Look up what to do with an incoming circuit cell.
    pub fn lookup(&self, key: &CircuitKey) -> Option<&CircuitAction> {
        self.entries.get(key)
    }

    /// Mutable lookup — needed for updating nonce counters during onion processing.
    /// Counts as use of the entry for idle expiry.
    pub fn lookup_mut(&mut self, key: &CircuitKey) -> Option<&mut CircuitAction> {
        let action = self.entries.get_mut(key)?;
        self.last_used.insert(*key, Instant::now());
        Some(action)
    }

    /// Remove a circuit entry (teardown).
    pub fn remove(&mut self, key: &CircuitKey) -> Option<CircuitAction> {
        self.last_used.remove(key);
        self.entries.remove(key)
    }

    /// Entries that carried no cell for `max_idle`, counting a forwarding
    /// entry as used while its reverse entry is.
    pub fn idle_entries(&self, max_idle: Duration) -> Vec<CircuitKey> {
        let now = Instant::now();
        let idle = |k: &CircuitKey| {
            self.last_used
                .get(k)
                .map_or(true, |t| now.duration_since(*t) >= max_idle)
        };
        self.entries
            .iter()
            .filter(|(k, action)| {
                idle(k)
                    && match action {
                        CircuitAction::Forward {
                            next_hop,
                            next_circuit_id,
                            ..
                        } => idle(&CircuitKey {
                            circuit_id: *next_circuit_id,
                            from_peer: *next_hop,
                        }),
                        CircuitAction::Endpoint { .. } => true,
                    }
            })
            .map(|(k, _)| *k)
            .collect()
    }

    /// Remove all entries involving a given peer (link went down).
    /// Returns the circuit IDs that were removed, paired with the from_peer
    /// that keyed each entry, so callers can clean up associated state.
    pub fn remove_peer(&mut self, peer: &PeerId) -> Vec<(u32, PeerId)> {
        let mut removed = Vec::new();
        self.entries.retain(|k, v| {
            let keep = k.from_peer != *peer
                && !matches!(v, CircuitAction::Forward { next_hop, .. } if next_hop == peer);
            if !keep {
                removed.push((k.circuit_id, k.from_peer));
            }
            keep
        });
        for (circuit_id, from_peer) in &removed {
            self.last_used.remove(&CircuitKey {
                circuit_id: *circuit_id,
                from_peer: *from_peer,
            });
        }
        removed
    }

    /// Number of active circuit entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn entries_iter(&self) -> impl Iterator<Item = (&CircuitKey, &CircuitAction)> {
        self.entries.iter()
    }

    /// Count forwarding entries (we're a relay, not the endpoint).
    pub fn forward_count(&self) -> usize {
        self.entries
            .values()
            .filter(|a| matches!(a, CircuitAction::Forward { .. }))
            .count()
    }

    /// Count endpoint entries (circuit terminates at this node).
    pub fn endpoint_count(&self) -> usize {
        self.entries
            .values()
            .filter(|a| matches!(a, CircuitAction::Endpoint { .. }))
            .count()
    }

    /// Count circuit entries involving each peer (as from_peer or next_hop).
    /// Used by link eviction to score how many circuits depend on each neighbor.
    pub fn circuits_per_peer(&self) -> HashMap<PeerId, usize> {
        let mut counts = HashMap::new();
        for (key, action) in &self.entries {
            *counts.entry(key.from_peer).or_insert(0) += 1;
            if let CircuitAction::Forward { next_hop, .. } = action {
                *counts.entry(*next_hop).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Count circuit entries involving a single peer (as from_peer or next_hop).
    /// O(entries) but avoids allocating a HashMap — use on the hot message path.
    pub fn circuits_for_peer(&self, peer: &PeerId) -> usize {
        let mut count = 0;
        for (key, action) in &self.entries {
            if key.from_peer == *peer {
                count += 1;
            }
            if let CircuitAction::Forward { next_hop, .. } = action {
                if next_hop == peer {
                    count += 1;
                }
            }
        }
        count
    }
}

// ---------------------------------------------------------------------------
// Relay cell inner format
// ---------------------------------------------------------------------------

/// Commands carried inside relay cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCellCommand {
    Data = 0x01,
    Sendme = 0x02,
    StreamBegin = 0x03,
    StreamEnd = 0x04,
    Extend = 0x05,
    Extended = 0x06,
    Introduce = 0x07,
    IntroduceAck = 0x08,
    RendezvousEstablish = 0x09,
    RendezvousJoin = 0x0A,
    RendezvousJoined = 0x0B,
    IntroRegister = 0x0C,
    IntroRegistered = 0x0D,
    StreamConnected = 0x0E,
    StreamRefused = 0x0F,
    /// Circuit keepalive: sent end-to-end, echoed back by endpoint.
    Padding = 0x10,
    StreamAck = 0x11,
    RendezvousReady = 0x12,
    /// Continuation of a relay message too large for one cell.
    Continue = 0x13,
    /// Ask the addressed hop to drop whatever it started downstream and
    /// become the circuit's endpoint again.
    Truncate = 0x14,
    /// Reply to `Truncate`.
    Truncated = 0x15,
}

impl RelayCellCommand {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Sendme),
            0x03 => Ok(Self::StreamBegin),
            0x04 => Ok(Self::StreamEnd),
            0x05 => Ok(Self::Extend),
            0x06 => Ok(Self::Extended),
            0x07 => Ok(Self::Introduce),
            0x08 => Ok(Self::IntroduceAck),
            0x09 => Ok(Self::RendezvousEstablish),
            0x0A => Ok(Self::RendezvousJoin),
            0x0B => Ok(Self::RendezvousJoined),
            0x0C => Ok(Self::IntroRegister),
            0x0D => Ok(Self::IntroRegistered),
            0x0E => Ok(Self::StreamConnected),
            0x0F => Ok(Self::StreamRefused),
            0x10 => Ok(Self::Padding),
            0x11 => Ok(Self::StreamAck),
            0x12 => Ok(Self::RendezvousReady),
            0x13 => Ok(Self::Continue),
            0x14 => Ok(Self::Truncate),
            0x15 => Ok(Self::Truncated),
            _ => Err(Error::Wire(format!("unknown relay cell command: {:#x}", v))),
        }
    }
}

/// Parsed relay cell (after onion decryption at the endpoint).
///
/// Wire format (always CELL_SIZE bytes total):
///   command(1) || stream_id(2) || length(2) || digest(16) || payload(length) || padding
#[derive(Debug, Clone)]
pub struct RelayCell {
    pub command: RelayCellCommand,
    pub stream_id: u16,
    pub data: Vec<u8>,
}

/// Serialize relay cell fields into a fixed-size cell body. Integrity comes
/// from the cell's end-to-end tag, added when the body is sealed.
pub fn write_cell_body(
    command: RelayCellCommand,
    stream_id: u16,
    data: &[u8],
) -> [u8; CELL_BODY_SIZE] {
    write_piece_body(command, stream_id, false, data)
}

fn write_piece_body(
    command: RelayCellCommand,
    stream_id: u16,
    more: bool,
    data: &[u8],
) -> [u8; CELL_BODY_SIZE] {
    assert!(
        data.len() <= CELL_PAYLOAD_MAX,
        "relay cell data ({} bytes) exceeds CELL_PAYLOAD_MAX ({} bytes) — caller must chunk",
        data.len(),
        CELL_PAYLOAD_MAX,
    );
    let mut cell = [0u8; CELL_BODY_SIZE];
    let len = data.len();
    let length_field = len as u16 | if more { LENGTH_MORE } else { 0 };
    cell[0] = command as u8;
    cell[1..3].copy_from_slice(&stream_id.to_be_bytes());
    cell[3..5].copy_from_slice(&length_field.to_be_bytes());
    cell[CELL_HEADER_SIZE..CELL_HEADER_SIZE + len].copy_from_slice(data);
    cell
}

/// One cell's worth of a relay message.
///
/// A message that fits one cell is a single piece with `more == false`. A
/// larger one is split: the first piece carries the real command, `more`,
/// and `total_len(u16) || bytes`; each following piece is a `Continue` with
/// `index(u8) || bytes`, `more` set on all but the last. Every piece has its
/// own end-to-end tag, so pieces can be lost but not forged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPiece {
    pub command: RelayCellCommand,
    pub stream_id: u16,
    pub more: bool,
    pub data: Vec<u8>,
}

impl RelayPiece {
    pub fn to_cell(&self) -> [u8; CELL_BODY_SIZE] {
        write_piece_body(self.command, self.stream_id, self.more, &self.data)
    }

    /// Parse an opened cell body (its tag already checked).
    pub fn from_cell(cell: &[u8; CELL_BODY_SIZE]) -> Result<Self> {
        let command = RelayCellCommand::from_u8(cell[0])?;
        let stream_id = u16::from_be_bytes([cell[1], cell[2]]);
        let length_field = u16::from_be_bytes([cell[3], cell[4]]);
        let more = length_field & LENGTH_MORE != 0;
        let length = (length_field & !LENGTH_MORE) as usize;

        if length > CELL_PAYLOAD_MAX {
            return Err(Error::Wire("relay cell length exceeds max".into()));
        }

        let payload = &cell[CELL_HEADER_SIZE..CELL_HEADER_SIZE + length];

        Ok(Self {
            command,
            stream_id,
            more,
            data: payload.to_vec(),
        })
    }
}

impl RelayCell {
    /// Serialize into a fixed-size cell body, ready for sealing. Panics if the
    /// data doesn't fit one cell; use [`RelayCell::pieces`] for messages that
    /// may not.
    pub fn to_cell(&self) -> [u8; CELL_BODY_SIZE] {
        write_cell_body(self.command, self.stream_id, &self.data)
    }

    /// Parse an opened single-cell message.
    /// A piece of a multi-cell message is an error here; receivers that may
    /// get one feed [`RelayPiece`]s to a [`RelayAssembler`].
    pub fn from_cell(cell: &[u8; CELL_BODY_SIZE]) -> Result<Self> {
        let piece = RelayPiece::from_cell(cell)?;
        if piece.more || piece.command == RelayCellCommand::Continue {
            return Err(Error::Wire("relay cell is part of a multi-cell message".into()));
        }
        Ok(Self {
            command: piece.command,
            stream_id: piece.stream_id,
            data: piece.data,
        })
    }

    /// Split into the cells that carry this message.
    pub fn pieces(&self) -> Result<Vec<RelayPiece>> {
        if self.data.len() <= CELL_PAYLOAD_MAX {
            return Ok(vec![RelayPiece {
                command: self.command,
                stream_id: self.stream_id,
                more: false,
                data: self.data.clone(),
            }]);
        }
        if self.data.len() > RELAY_MESSAGE_MAX {
            return Err(Error::Wire(format!(
                "relay message {} bytes exceeds {}",
                self.data.len(),
                RELAY_MESSAGE_MAX
            )));
        }
        let (first, rest) = self.data.split_at(FIRST_PIECE_MAX);
        let mut first_data = Vec::with_capacity(CELL_PAYLOAD_MAX);
        first_data.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        first_data.extend_from_slice(first);
        let mut pieces = vec![RelayPiece {
            command: self.command,
            stream_id: self.stream_id,
            more: true,
            data: first_data,
        }];
        let chunks: Vec<&[u8]> = rest.chunks(CONTINUE_PIECE_MAX).collect();
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut data = Vec::with_capacity(1 + chunk.len());
            data.push((i + 1) as u8);
            data.extend_from_slice(chunk);
            pieces.push(RelayPiece {
                command: RelayCellCommand::Continue,
                stream_id: self.stream_id,
                more: i != last,
                data,
            });
        }
        Ok(pieces)
    }
}

#[derive(Clone)]
struct PartialRelayMessage {
    command: RelayCellCommand,
    total: usize,
    buf: Vec<u8>,
    next_index: u8,
}

/// Reassembles multi-cell relay messages for one circuit direction.
///
/// Cells of a circuit arrive in order, but may be lost, and single-cell
/// messages may arrive between the pieces of a larger one. One message is
/// assembled per stream id; a piece that doesn't continue it exactly drops
/// the partial message.
#[derive(Default, Clone)]
pub struct RelayAssembler {
    partials: HashMap<u16, PartialRelayMessage>,
}

/// Streams with a message in reassembly at once, per circuit direction.
const MAX_PARTIAL_RELAY_MESSAGES: usize = 4;

impl std::fmt::Debug for RelayAssembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RelayAssembler({} partial)", self.partials.len())
    }
}

impl RelayAssembler {
    pub fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }

    /// Add a piece. Returns a complete message when this piece finishes one
    /// (or is a whole single-cell message).
    pub fn push(&mut self, piece: RelayPiece) -> Option<RelayCell> {
        let RelayPiece {
            command,
            stream_id,
            more,
            data,
        } = piece;
        if command != RelayCellCommand::Continue {
            if !more {
                return Some(RelayCell {
                    command,
                    stream_id,
                    data,
                });
            }
            if data.len() < 2 {
                self.partials.remove(&stream_id);
                return None;
            }
            let total = u16::from_be_bytes([data[0], data[1]]) as usize;
            if total > RELAY_MESSAGE_MAX || total <= data.len() - 2 {
                self.partials.remove(&stream_id);
                return None;
            }
            if self.partials.len() >= MAX_PARTIAL_RELAY_MESSAGES
                && !self.partials.contains_key(&stream_id)
            {
                return None;
            }
            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(&data[2..]);
            self.partials.insert(
                stream_id,
                PartialRelayMessage {
                    command,
                    total,
                    buf,
                    next_index: 1,
                },
            );
            return None;
        }

        let Some(partial) = self.partials.get_mut(&stream_id) else {
            return None;
        };
        let Some((&index, bytes)) = data.split_first() else {
            self.partials.remove(&stream_id);
            return None;
        };
        if index != partial.next_index || partial.buf.len() + bytes.len() > partial.total {
            self.partials.remove(&stream_id);
            return None;
        }
        partial.buf.extend_from_slice(bytes);
        partial.next_index = partial.next_index.wrapping_add(1);
        if more {
            return None;
        }
        let partial = self.partials.remove(&stream_id).unwrap();
        (partial.buf.len() == partial.total).then(|| RelayCell {
            command: partial.command,
            stream_id,
            data: partial.buf,
        })
    }
}

/// Compute a digest of DATA cell payload for SENDME authentication.
/// This allows the receiver to prove it actually received the data.
/// Uses a fixed key — not for secrecy, just for consistent hashing.
pub fn relay_cell_digest_for_sendme(payload: &[u8]) -> [u8; DIGEST_SIZE] {
    let key = b"tarnet_sendme_digest_key________"; // 32 bytes
    mac_16(key, &[payload])
}

/// State of a circuit being built or in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// Building: extending toward waypoints via DV routing.
    Extending { hops_built: usize },
    /// Ready for use.
    Ready,
    /// Destroyed.
    Destroyed,
}

/// A circuit we initiated (outbound).
#[derive(Debug)]
pub struct OutboundCircuit {
    /// Circuit ID on our link to the first hop.
    pub first_hop_circuit_id: CircuitId,
    /// First hop PeerId (our direct neighbor).
    pub first_hop: PeerId,
    /// Onion layers, outermost first.
    pub layers: OnionLayers,
    /// Hash of each waypoint's CREATE handshake, in layer order.
    pub transcripts: Vec<[u8; 32]>,
    /// Current state of the circuit.
    pub state: CircuitState,
    /// Waypoints this circuit routes through (the originator's view, not actual hops).
    pub waypoints: Vec<PeerId>,
    /// Last time we received any relay cell on this circuit.
    pub last_activity: Instant,
    /// Multi-cell messages arriving from the circuit's hops.
    pub assembler: RelayAssembler,
}

impl OutboundCircuit {
    pub fn new(
        first_hop: PeerId,
        first_hop_circuit_id: CircuitId,
        layers: OnionLayers,
        waypoints: Vec<PeerId>,
        state: CircuitState,
    ) -> Self {
        Self {
            first_hop_circuit_id,
            first_hop,
            layers,
            transcripts: Vec::new(),
            state,
            waypoints,
            last_activity: Instant::now(),
            assembler: Default::default(),
        }
    }

    fn last(&self) -> usize {
        self.layers.len() - 1
    }

    /// Send a relay cell through this circuit. Returns (first_hop, circuit_id, encrypted_cell).
    pub fn send_relay_cell(
        &mut self,
        relay_cell: &RelayCell,
    ) -> (PeerId, CircuitId, [u8; CELL_SIZE]) {
        let last = self.last();
        self.send_to_hop(relay_cell, last)
    }

    /// Send a DATA cell through this circuit without constructing a RelayCell.
    pub fn send_data_cell(&mut self, data: &[u8]) -> (PeerId, CircuitId, [u8; CELL_SIZE]) {
        let body = write_cell_body(RelayCellCommand::Data, 0, data);
        let last = self.last();
        let cell = self.layers.seal_to(last, &body);
        (self.first_hop, self.first_hop_circuit_id, cell)
    }

    /// Receive and decrypt a relay cell from this circuit's last hop.
    pub fn recv_relay_cell(&mut self, cell: &[u8; CELL_SIZE]) -> Result<RelayCell> {
        let last = self.last();
        self.recv_from_hop(cell, last)
    }

    /// Send a relay message of any size to a hop, as one cell or several.
    /// Returns (first_hop, circuit_id, encrypted cells in sending order).
    pub fn send_message_to_hop(
        &mut self,
        relay_cell: &RelayCell,
        hop_index: usize,
    ) -> Result<(PeerId, CircuitId, Vec<[u8; CELL_SIZE]>)> {
        let cells = relay_cell
            .pieces()?
            .iter()
            .map(|piece| self.layers.seal_to(hop_index, &piece.to_cell()))
            .collect();
        Ok((self.first_hop, self.first_hop_circuit_id, cells))
    }

    /// Send a relay message of any size to the circuit's last hop.
    pub fn send_relay_message(
        &mut self,
        relay_cell: &RelayCell,
    ) -> Result<(PeerId, CircuitId, Vec<[u8; CELL_SIZE]>)> {
        let last = self.last();
        self.send_message_to_hop(relay_cell, last)
    }

    /// Receive a cell from the circuit's last hop, returning a relay message
    /// once one is complete.
    pub fn recv_relay_message(&mut self, cell: &[u8; CELL_SIZE]) -> Result<Option<RelayCell>> {
        let last = self.last();
        let piece = self.recv_piece_from_hop(cell, last)?;
        Ok(self.assembler.push(piece))
    }

    /// Send a single-cell relay message to a specific hop (0 = first hop).
    pub fn send_to_hop(
        &mut self,
        relay_cell: &RelayCell,
        hop_index: usize,
    ) -> (PeerId, CircuitId, [u8; CELL_SIZE]) {
        let cell = self.layers.seal_to(hop_index, &relay_cell.to_cell());
        (self.first_hop, self.first_hop_circuit_id, cell)
    }

    /// Receive a single-cell relay message sealed by a specific hop.
    pub fn recv_from_hop(&mut self, cell: &[u8; CELL_SIZE], hop_index: usize) -> Result<RelayCell> {
        let piece = self.recv_piece_from_hop(cell, hop_index)?;
        if piece.more || piece.command == RelayCellCommand::Continue {
            return Err(Error::Wire("relay cell is part of a multi-cell message".into()));
        }
        Ok(RelayCell {
            command: piece.command,
            stream_id: piece.stream_id,
            data: piece.data,
        })
    }

    fn recv_piece_from_hop(&mut self, cell: &[u8; CELL_SIZE], hop_index: usize) -> Result<RelayPiece> {
        let (origin, body) = self
            .layers
            .open(cell)
            .ok_or_else(|| Error::Crypto("backward cell failed to open or was replayed".into()))?;
        if origin != hop_index {
            return Err(Error::Protocol(format!(
                "cell from hop {} where hop {} was expected",
                origin, hop_index
            )));
        }
        RelayPiece::from_cell(&body)
    }
}

// ---------------------------------------------------------------------------
// Congestion window (AIMD)
// ---------------------------------------------------------------------------

/// AIMD congestion control state for a circuit.
///
/// Each direction of a circuit has its own `CongestionWindow`:
/// - **Sender side**: tracks `cwnd` / `inflight`, gates sends via `can_send()`.
/// - **Receiver side**: tracks `recv_allowed` (credit window), drops cells that
///   exceed the window, and signals when to send a SENDME back.
#[derive(Debug, Clone)]
pub struct CongestionWindow {
    // --- Sender side ---
    pub cwnd: u32,
    pub inflight: u32,
    pub slow_start: bool,
    // --- Receiver side ---
    /// Cells delivered since last SENDME was sent.
    pub deliver_count: u32,
    /// BLAKE2b-128 digest of the last DATA cell received (for authenticated SENDMEs).
    pub last_data_digest: [u8; DIGEST_SIZE],
    /// Remaining receive credit. When this hits 0, drop incoming DATA cells.
    /// Replenished by SENDME_INC each time we send a SENDME.
    pub recv_allowed: u32,
    // --- Stall detection ---
    /// When we last received a SENDME (or first became window-blocked).
    /// Used to detect lost SENDMEs and recover.
    pub last_sendme_at: Option<Instant>,
}

impl CongestionWindow {
    pub fn new() -> Self {
        Self {
            cwnd: CWND_INIT,
            inflight: 0,
            slow_start: true,
            deliver_count: 0,
            last_data_digest: [0u8; DIGEST_SIZE],
            recv_allowed: RECV_WINDOW_INIT,
            last_sendme_at: None,
        }
    }

    /// Check if we can send another cell.
    pub fn can_send(&self) -> bool {
        self.inflight < self.cwnd
    }

    /// Record that we sent a cell.
    pub fn on_send(&mut self) {
        self.inflight += 1;
    }

    /// Process a received SENDME acknowledgment.
    pub fn on_sendme(&mut self) {
        self.inflight = self.inflight.saturating_sub(SENDME_INC);
        self.last_sendme_at = Some(Instant::now());
        if self.slow_start {
            self.cwnd = (self.cwnd + SENDME_INC).min(CWND_MAX);
            if self.cwnd >= SS_MAX {
                self.slow_start = false;
            }
        } else {
            self.cwnd = (self.cwnd + 1).min(CWND_MAX);
        }
    }

    /// React to a timeout or loss event.
    pub fn on_loss(&mut self) {
        self.slow_start = false;
        self.cwnd = (self.cwnd / 2).max(CWND_MIN);
    }

    /// Check if the sender is stalled waiting for a lost SENDME.
    /// If blocked for longer than `SENDME_STALL_TIMEOUT`, assume the SENDME
    /// was lost: halve the window (loss event) and grant a small probe window
    /// so the sender can resume. The new data will trigger a fresh SENDME
    /// from the receiver.
    /// Returns true if a stall was detected and recovered.
    pub fn check_stall(&mut self) -> bool {
        if self.can_send() {
            return false; // not blocked
        }
        let stalled = match self.last_sendme_at {
            Some(t) => t.elapsed() >= SENDME_STALL_TIMEOUT,
            // Never received a SENDME — use a generous timeout for initial slow start.
            None => {
                self.last_sendme_at = Some(Instant::now());
                false
            }
        };
        if stalled {
            self.on_loss();
            // Reset inflight to open a probe window: allow SENDME_INC cells
            // so the sender can push enough data to trigger a new SENDME.
            self.inflight = self.cwnd.saturating_sub(SENDME_INC);
            self.last_sendme_at = Some(Instant::now());
            true
        } else {
            false
        }
    }

    /// Check if the receiver can accept another DATA cell.
    /// Returns false if the sender has exceeded the receive window.
    pub fn can_receive(&self) -> bool {
        self.recv_allowed > 0
    }

    /// Record delivery of a DATA cell (receiver side). Returns true if a SENDME should be sent.
    /// Caller must check `can_receive()` first — this decrements the receive credit.
    pub fn on_deliver(&mut self, cell_digest: [u8; DIGEST_SIZE]) -> bool {
        self.last_data_digest = cell_digest;
        self.recv_allowed = self.recv_allowed.saturating_sub(1);
        self.deliver_count += 1;
        if self.deliver_count >= SENDME_INC {
            self.deliver_count = 0;
            // Replenish receive credit when we send a SENDME
            self.recv_allowed += SENDME_INC;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// EXTEND / EXTENDED payload helpers
// ---------------------------------------------------------------------------

/// A request to create a circuit hop at `destination`: the payload of a
/// routed CREATE, and of EXTEND.
///
/// `version(u8) || flags(u8) || kem_algo(u8) || pk_len(u16) || eph_pk ||
/// destination(32) || hint_count(u8) || hint_count × peer(32)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    pub kem_algo: u8,
    pub eph_pk: Vec<u8>,
    pub destination: PeerId,
    pub hints: Vec<PeerId>,
}

impl CreateRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(CELL_CRYPTO_VERSION);
        buf.push(0); // flags, none defined
        buf.push(self.kem_algo);
        buf.extend_from_slice(&(self.eph_pk.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.eph_pk);
        buf.extend_from_slice(self.destination.as_bytes());
        crate::codec::write_peers(&mut buf, &self.hints, crate::wire::MAX_HINTS);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = crate::codec::Reader::new(data);
        let version = r.read_u8()?;
        if version != CELL_CRYPTO_VERSION {
            return Err(Error::Wire(format!("unsupported cell crypto version {}", version)));
        }
        let flags = r.read_u8()?;
        if flags != 0 {
            return Err(Error::Wire(format!("unknown CREATE flags {:#x}", flags)));
        }
        let kem_algo = r.read_u8()?;
        let pk_len = r.read_u16()? as usize;
        let eph_pk = r.read_bytes(pk_len)?;
        let destination = PeerId(r.read_array::<32>()?);
        let hints = r.read_peers(crate::wire::MAX_HINTS, "CREATE hints")?;
        r.finish()?;
        Ok(Self {
            kem_algo,
            eph_pk,
            destination,
            hints,
        })
    }

    /// Hash of the handshake, mixed into the hop's keys and signed by the
    /// destination.
    pub fn transcript(&self, kem_ct: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("tarnet circuit create transcript v1");
        h.update(&[CELL_CRYPTO_VERSION, self.kem_algo]);
        h.update(self.destination.as_bytes());
        h.update(&(self.eph_pk.len() as u32).to_be_bytes());
        h.update(&self.eph_pk);
        h.update(&(kem_ct.len() as u32).to_be_bytes());
        h.update(kem_ct);
        *h.finalize().as_bytes()
    }
}

/// What the destination signs in CREATED.
pub fn created_signed_message(transcript: &[u8; 32]) -> Vec<u8> {
    let mut msg = b"tarnet circuit created v1".to_vec();
    msg.extend_from_slice(transcript);
    msg
}

/// The destination's answer to a CREATE: the payload of CREATED, and of
/// EXTENDED (an empty EXTENDED means the step failed).
///
/// `kem_ct_len(u16) || kem_ct || signing_pk_len(u16) || signing_pk ||
/// sig_len(u16) || sig`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedReply {
    pub kem_ct: Vec<u8>,
    pub signing_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

impl CreatedReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for field in [&self.kem_ct, &self.signing_pk, &self.sig] {
            buf.extend_from_slice(&(field.len() as u16).to_be_bytes());
            buf.extend_from_slice(field);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = crate::codec::Reader::new(data);
        let mut field = || -> Result<Vec<u8>> {
            let len = r.read_u16()? as usize;
            r.read_bytes(len)
        };
        let (kem_ct, signing_pk, sig) = (field()?, field()?, field()?);
        r.finish()?;
        Ok(Self {
            kem_ct,
            signing_pk,
            sig,
        })
    }

    /// Check that `request.destination` itself answered: its signing key
    /// hashes to the destination and signed this handshake. Returns the
    /// transcript hash for key derivation.
    pub fn verify(&self, request: &CreateRequest) -> Result<[u8; 32]> {
        let transcript = request.transcript(&self.kem_ct);
        if !crate::identity::verify_signed(
            crate::identity::SignedBy::Peer(&request.destination),
            None,
            &self.signing_pk,
            &created_signed_message(&transcript),
            &self.sig,
        ) {
            return Err(Error::Crypto("CREATED not signed by the destination".into()));
        }
        Ok(transcript)
    }
}

// ---------------------------------------------------------------------------
// STREAM_BEGIN / STREAM_END payload helpers
// ---------------------------------------------------------------------------

/// Build a STREAM_BEGIN relay cell payload.
/// Format: service_id(32) || mode(1) || port_len(2) || port(bytes)
pub fn build_stream_begin_payload(
    service_id: &tarnet_api::types::ServiceId,
    mode: tarnet_api::service::PortMode,
    port: &str,
) -> Vec<u8> {
    let port_bytes = port.as_bytes();
    let port_len = u16::try_from(port_bytes.len()).expect("port name too long");
    let mut payload = Vec::with_capacity(35 + port_bytes.len());
    payload.extend_from_slice(service_id.as_bytes());
    payload.push(mode as u8);
    payload.extend_from_slice(&port_len.to_be_bytes());
    payload.extend_from_slice(port_bytes);
    payload
}

/// Parse a STREAM_BEGIN relay cell payload.
/// Returns (service_id, mode, port).
pub fn parse_stream_begin_payload(
    data: &[u8],
) -> Result<(
    tarnet_api::types::ServiceId,
    tarnet_api::service::PortMode,
    String,
)> {
    if data.len() < 35 {
        return Err(Error::Wire("STREAM_BEGIN payload too short".into()));
    }
    let mut sid = [0u8; 32];
    sid.copy_from_slice(&data[..32]);
    let mode = match data[32] {
        0 => tarnet_api::service::PortMode::ReliableOrdered,
        1 => tarnet_api::service::PortMode::ReliableUnordered,
        2 => tarnet_api::service::PortMode::UnreliableUnordered,
        other => return Err(Error::Wire(format!("unknown port mode {}", other))),
    };
    let port_len = u16::from_be_bytes([data[33], data[34]]) as usize;
    if data.len() < 35 + port_len {
        return Err(Error::Wire("STREAM_BEGIN port truncated".into()));
    }
    let port = String::from_utf8(data[35..35 + port_len].to_vec())
        .map_err(|_| Error::Wire("STREAM_BEGIN port is not valid UTF-8".into()))?;
    Ok((tarnet_api::types::ServiceId(sid), mode, port))
}

// ---------------------------------------------------------------------------
// Rendezvous payload helpers
// ---------------------------------------------------------------------------

/// What a client tells a hidden service in INTRODUCE, sealed to the
/// service's KEM key so the intro point can't read it.
///
/// Plaintext: `rendezvous(32) || cookie(32) || mode(u8) || port_len(u16) ||
/// port || hint_count(u8) || hints || kem_algo(u8) || pk_len(u16) ||
/// client_eph_pk`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Introduction {
    pub rendezvous: PeerId,
    /// Hints toward the rendezvous point.
    pub rendezvous_hints: Vec<PeerId>,
    pub cookie: [u8; 32],
    pub mode: tarnet_api::service::PortMode,
    pub port: String,
    /// The client's ephemeral KEM key: the service answers it, which gives
    /// the end-to-end key forward secrecy.
    pub client_kem_algo: u8,
    pub client_eph_pk: Vec<u8>,
}

impl Introduction {
    fn to_plaintext(&self) -> Vec<u8> {
        let port = self.port.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(self.rendezvous.as_bytes());
        out.extend_from_slice(&self.cookie);
        out.push(self.mode as u8);
        out.extend_from_slice(&(u16::try_from(port.len()).expect("port name too long")).to_be_bytes());
        out.extend_from_slice(port);
        crate::codec::write_peers(&mut out, &self.rendezvous_hints, crate::wire::MAX_HINTS);
        out.push(self.client_kem_algo);
        out.extend_from_slice(&(self.client_eph_pk.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.client_eph_pk);
        out
    }

    fn from_plaintext(p: &[u8]) -> Result<Self> {
        let mut r = crate::codec::Reader::new(p);
        let rendezvous = PeerId(r.read_array::<32>()?);
        let cookie: [u8; 32] = r.read_array::<32>()?;
        let mode = match r.read_u8()? {
            0 => tarnet_api::service::PortMode::ReliableOrdered,
            1 => tarnet_api::service::PortMode::ReliableUnordered,
            2 => tarnet_api::service::PortMode::UnreliableUnordered,
            other => return Err(Error::Wire(format!("unknown port mode {}", other))),
        };
        let port_len = r.read_u16()? as usize;
        let port = String::from_utf8(r.read_bytes(port_len)?)
            .map_err(|_| Error::Wire("INTRODUCE port is not valid UTF-8".into()))?;
        let rendezvous_hints = r.read_peers(crate::wire::MAX_HINTS, "INTRODUCE hints")?;
        let client_kem_algo = r.read_u8()?;
        let pk_len = r.read_u16()? as usize;
        let client_eph_pk = r.read_bytes(pk_len)?;
        r.finish()?;
        Ok(Self {
            rendezvous,
            rendezvous_hints,
            cookie,
            mode,
            port,
            client_kem_algo,
            client_eph_pk,
        })
    }
}

/// Seal an [`Introduction`] to the service.
/// Wire: `ct_len(u16) || kem_ciphertext || nonce(24) || AEAD(plaintext)`.
pub fn build_introduce_payload(
    intro: &Introduction,
    kem_ciphertext: &[u8],
    shared_secret: &[u8; 32],
) -> Vec<u8> {
    let enc_key = kdf(shared_secret, "tarnet introduce enc");
    let mut nonce = [0u8; 24];
    RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let ciphertext = XChaCha20Poly1305::new((&enc_key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &intro.to_plaintext(),
                aad: b"",
            },
        )
        .expect("AEAD encryption should not fail");
    let mut payload = Vec::with_capacity(2 + kem_ciphertext.len() + 24 + ciphertext.len());
    payload.extend_from_slice(&(kem_ciphertext.len() as u16).to_be_bytes());
    payload.extend_from_slice(kem_ciphertext);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    payload
}

/// Open a sealed INTRODUCE with the service's KEM keypair. Returns the
/// introduction and the KEM secret it was sealed with.
pub fn parse_introduce_payload(
    data: &[u8],
    service_kem: &crate::identity::KemKeypair,
) -> Result<(Introduction, [u8; 32])> {
    let ct_len = data
        .get(..2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .ok_or_else(|| Error::Wire("INTRODUCE payload too short".into()))?;
    if data.len() < 2 + ct_len + 24 + 16 {
        return Err(Error::Wire("INTRODUCE payload truncated".into()));
    }
    let kem_ct = &data[2..2 + ct_len];
    let nonce = &data[2 + ct_len..2 + ct_len + 24];
    let sealed = &data[2 + ct_len + 24..];
    let shared = service_kem
        .decapsulate(kem_ct)
        .map_err(|e| Error::Crypto(format!("INTRODUCE KEM decapsulate failed: {}", e)))?;
    let enc_key = kdf(&shared, "tarnet introduce enc");
    let plaintext = XChaCha20Poly1305::new((&enc_key).into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: sealed,
                aad: b"",
            },
        )
        .map_err(|_| Error::Crypto("INTRODUCE AEAD decryption failed".into()))?;
    Ok((Introduction::from_plaintext(&plaintext)?, shared))
}

/// The INTRODUCE relay-cell payload: `service_id(32) || ext_len(u16) || ext
/// || sealed`. The intro point reads the service id to pick the service's
/// circuit; `ext` carries typed extensions (none defined yet; unknown ones
/// are ignored), so proof-of-work can be added without a break.
pub fn build_introduce_cell(
    service_id: &tarnet_api::types::ServiceId,
    ext: &[u8],
    sealed: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(34 + ext.len() + sealed.len());
    out.extend_from_slice(service_id.as_bytes());
    out.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    out.extend_from_slice(ext);
    out.extend_from_slice(sealed);
    out
}

/// Parse an INTRODUCE relay-cell payload: `(service_id, ext, sealed)`.
pub fn parse_introduce_cell(data: &[u8]) -> Result<(tarnet_api::types::ServiceId, &[u8], &[u8])> {
    let short = || Error::Wire("INTRODUCE cell too short".into());
    let sid: [u8; 32] = data.get(..32).ok_or_else(short)?.try_into().unwrap();
    let ext_len = data
        .get(32..34)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .ok_or_else(short)?;
    let ext = data.get(34..34 + ext_len).ok_or_else(short)?;
    Ok((tarnet_api::types::ServiceId(sid), ext, &data[34 + ext_len..]))
}

/// End-to-end keys of a rendezvous, in the client's orientation, and the
/// tag the service sends to prove it derived them. Mixes the INTRODUCE
/// secret (authenticates the service) with the service's answer to the
/// client's ephemeral key (forward secrecy).
pub fn rendezvous_keys(
    static_secret: &[u8; 32],
    eph_secret: &[u8; 32],
    sealed: &[u8],
    kem_ct: &[u8],
) -> (HopKey, [u8; 16]) {
    let mut h = blake3::Hasher::new_derive_key("tarnet rendezvous transcript v1");
    h.update(&(sealed.len() as u32).to_be_bytes());
    h.update(sealed);
    h.update(&(kem_ct.len() as u32).to_be_bytes());
    h.update(kem_ct);
    let transcript = *h.finalize().as_bytes();
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(static_secret);
    material.extend_from_slice(eph_secret);
    material.extend_from_slice(&transcript);
    let secret = blake3::derive_key("tarnet rendezvous secret v1", &material);
    let confirm_key = blake3::derive_key("tarnet rendezvous confirm v1", &secret);
    (HopKey::derive(&secret, &transcript), mac_16(&confirm_key, &[&transcript]))
}

/// The service's answer carried by JOIN and JOINED:
/// `kem_ct_len(u16) || kem_ct || confirm(16)`.
pub fn build_join(kem_ct: &[u8], confirm: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + kem_ct.len() + 16);
    out.extend_from_slice(&(kem_ct.len() as u16).to_be_bytes());
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(confirm);
    out
}

pub fn parse_join(data: &[u8]) -> Result<(&[u8], [u8; 16])> {
    let short = || Error::Wire("JOIN answer malformed".into());
    let len = data
        .get(..2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .ok_or_else(short)?;
    // Exactly the ciphertext and the confirm tag, nothing after.
    if data.len() != 2 + len + 16 {
        return Err(short());
    }
    Ok((&data[2..2 + len], data[2 + len..].try_into().unwrap()))
}

/// Build a rendezvous cookie payload (used by both ESTABLISH and JOIN).
/// Format: cookie(32)
pub fn build_rendezvous_cookie_payload(cookie: &[u8; 32]) -> Vec<u8> {
    cookie.to_vec()
}

/// Parse a rendezvous cookie payload (used by both ESTABLISH and JOIN).
pub fn parse_rendezvous_cookie_payload(data: &[u8], label: &str) -> Result<[u8; 32]> {
    if data.len() < 32 {
        return Err(Error::Wire(format!("{} payload too short", label)));
    }
    let mut cookie = [0u8; 32];
    cookie.copy_from_slice(&data[..32]);
    Ok(cookie)
}

/// RENDEZVOUS_ESTABLISH payload: cookie(32)
pub fn build_rendezvous_establish_payload(cookie: &[u8; 32]) -> Vec<u8> {
    build_rendezvous_cookie_payload(cookie)
}

/// Parse a RENDEZVOUS_ESTABLISH payload.
pub fn parse_rendezvous_establish_payload(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() != 32 {
        return Err(Error::Wire("RENDEZVOUS_ESTABLISH payload is not a cookie".into()));
    }
    parse_rendezvous_cookie_payload(data, "RENDEZVOUS_ESTABLISH")
}

/// RENDEZVOUS_JOIN payload: cookie(32)
pub fn build_rendezvous_join_payload(cookie: &[u8; 32], join: &[u8]) -> Vec<u8> {
    let mut out = cookie.to_vec();
    out.extend_from_slice(join);
    out
}

/// Parse a RENDEZVOUS_JOIN payload: `(cookie, join)`.
pub fn parse_rendezvous_join_payload(data: &[u8]) -> Result<([u8; 32], &[u8])> {
    let cookie = parse_rendezvous_cookie_payload(data, "RENDEZVOUS_JOIN")?;
    Ok((cookie, &data[32..]))
}

/// What a service signs to register at an intro point: bound to the intro
/// point and to the circuit's handshake with it, so the signature can't be
/// replayed elsewhere.
pub fn intro_register_message(intro_point: &PeerId, transcript: &[u8; 32]) -> Vec<u8> {
    let mut msg = b"tarnet intro register v1".to_vec();
    msg.extend_from_slice(intro_point.as_bytes());
    msg.extend_from_slice(transcript);
    msg
}

/// INTRO_REGISTER payload:
/// `service_id(32) || pk_len(u16) || signing_pk || sig_len(u16) || sig`.
pub fn build_intro_register_payload(
    service_id: &tarnet_api::types::ServiceId,
    signing_pk: &[u8],
    sig: &[u8],
) -> Vec<u8> {
    let mut out = service_id.as_bytes().to_vec();
    for field in [signing_pk, sig] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// Parse and check an INTRO_REGISTER at the intro point: the key must be the
/// service's and the signature must cover our id and our handshake with the
/// registering circuit.
pub fn verify_intro_register(
    data: &[u8],
    intro_point: &PeerId,
    transcript: &[u8; 32],
) -> Result<tarnet_api::types::ServiceId> {
    let short = || Error::Wire("INTRO_REGISTER payload too short".into());
    let sid: [u8; 32] = data.get(..32).ok_or_else(short)?.try_into().unwrap();
    let mut at = 32;
    let mut field = || -> Result<&[u8]> {
        let len = data
            .get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
            .ok_or_else(short)?;
        let bytes = data.get(at + 2..at + 2 + len).ok_or_else(short)?;
        at += 2 + len;
        Ok(bytes)
    };
    let pk = field()?;
    let sig = field()?;
    let service_id = tarnet_api::types::ServiceId(sid);
    if !crate::identity::verify_signed(
        crate::identity::SignedBy::Service(&service_id),
        None,
        pk,
        &intro_register_message(intro_point, transcript),
        sig,
    ) {
        return Err(Error::Crypto("INTRO_REGISTER not signed by the service".into()));
    }
    Ok(service_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn alloc_random_ids_respect_parity() {
        let table = CircuitTable::new();
        for _ in 0..100 {
            let odd_id = table.alloc_id(true, |_| false);
            assert_ne!(odd_id, 0);
            assert_eq!(odd_id % 2, 1, "initiator ID must be odd");

            let even_id = table.alloc_id(false, |_| false);
            assert_ne!(even_id, 0);
            assert_eq!(even_id % 2, 0, "responder ID must be even");
        }
    }

    #[test]
    fn insert_and_lookup_forward() {
        let mut table = CircuitTable::new();
        let key = CircuitKey {
            circuit_id: 42,
            from_peer: pid(1),
        };
        let action = CircuitAction::Forward {
            next_hop: pid(2),
            next_circuit_id: 73,
            crypto: None,
        };
        table.insert(key, action.clone());

        let result = table.lookup(&key).unwrap();
        match result {
            CircuitAction::Forward {
                next_hop,
                next_circuit_id,
                ..
            } => {
                assert_eq!(*next_hop, pid(2));
                assert_eq!(*next_circuit_id, 73);
            }
            _ => panic!("expected Forward"),
        }
    }

    #[test]
    fn insert_and_lookup_endpoint() {
        let mut table = CircuitTable::new();
        let key = CircuitKey {
            circuit_id: 99,
            from_peer: pid(3),
        };
        table.insert(
            key,
            CircuitAction::Endpoint {
                assembler: Default::default(),
                origin_hop: pid(3),
                crypto: None,
            },
        );

        assert!(matches!(
            table.lookup(&key),
            Some(CircuitAction::Endpoint { .. })
        ));
    }

    #[test]
    fn same_circuit_id_different_peers() {
        let mut table = CircuitTable::new();
        let key1 = CircuitKey {
            circuit_id: 10,
            from_peer: pid(1),
        };
        let key2 = CircuitKey {
            circuit_id: 10,
            from_peer: pid(2),
        };
        table.insert(
            key1,
            CircuitAction::Forward {
                next_hop: pid(3),
                next_circuit_id: 20,
                crypto: None,
            },
        );
        table.insert(
            key2,
            CircuitAction::Forward {
                next_hop: pid(4),
                next_circuit_id: 30,
                crypto: None,
            },
        );

        // Same circuit_id, different from_peer → different entries
        match table.lookup(&key1).unwrap() {
            CircuitAction::Forward { next_hop, .. } => assert_eq!(*next_hop, pid(3)),
            _ => panic!(),
        }
        match table.lookup(&key2).unwrap() {
            CircuitAction::Forward { next_hop, .. } => assert_eq!(*next_hop, pid(4)),
            _ => panic!(),
        }
    }

    #[test]
    fn remove_entry() {
        let mut table = CircuitTable::new();
        let key = CircuitKey {
            circuit_id: 5,
            from_peer: pid(1),
        };
        table.insert(
            key,
            CircuitAction::Endpoint {
                assembler: Default::default(),
                origin_hop: pid(1),
                crypto: None,
            },
        );
        assert!(table.lookup(&key).is_some());
        table.remove(&key);
        assert!(table.lookup(&key).is_none());
    }

    #[test]
    fn remove_peer_cleans_all_entries() {
        let mut table = CircuitTable::new();
        table.insert(
            CircuitKey {
                circuit_id: 1,
                from_peer: pid(2),
            },
            CircuitAction::Forward {
                next_hop: pid(3),
                next_circuit_id: 10,
                crypto: None,
            },
        );
        table.insert(
            CircuitKey {
                circuit_id: 2,
                from_peer: pid(1),
            },
            CircuitAction::Forward {
                next_hop: pid(2),
                next_circuit_id: 20,
                crypto: None,
            },
        );
        table.insert(
            CircuitKey {
                circuit_id: 3,
                from_peer: pid(1),
            },
            CircuitAction::Forward {
                next_hop: pid(3),
                next_circuit_id: 30,
                crypto: None,
            },
        );

        assert_eq!(table.len(), 3);
        table.remove_peer(&pid(2));
        assert_eq!(table.len(), 1);
    }

    // --- Onion routing tests ---

    #[test]
    fn relay_cell_roundtrip() {
        let cell = RelayCell {
            command: RelayCellCommand::Data,
            stream_id: 0,
            data: b"hello onion".to_vec(),
        };
        let serialized = cell.to_cell();
        assert_eq!(serialized.len(), CELL_BODY_SIZE);

        let parsed = RelayCell::from_cell(&serialized).unwrap();
        assert_eq!(parsed.command, RelayCellCommand::Data);
        assert_eq!(parsed.stream_id, 0);
        assert_eq!(parsed.data, b"hello onion");
    }

    fn request(dest: PeerId, hints: Vec<PeerId>) -> CreateRequest {
        CreateRequest {
            kem_algo: 0x02,
            eph_pk: vec![0xBB; 1216],
            destination: dest,
            hints,
        }
    }

    #[test]
    fn create_request_roundtrip() {
        let req = request(pid(7), vec![pid(1), pid(2), pid(3)]);
        let bytes = req.to_bytes();
        assert_eq!(CreateRequest::from_bytes(&bytes).unwrap(), req);
        assert!(CreateRequest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut other_version = bytes;
        other_version[0] = 2;
        assert!(CreateRequest::from_bytes(&other_version).is_err());
    }

    fn answer(kp: &crate::identity::Keypair, req: &CreateRequest) -> CreatedReply {
        let kem_ct = vec![0xDD; 1120];
        let sig = kp.sign(&created_signed_message(&req.transcript(&kem_ct)));
        CreatedReply {
            kem_ct,
            signing_pk: kp.identity.signing.signing_pubkey_bytes(),
            sig,
        }
    }

    #[test]
    fn created_reply_proves_the_destination() {
        let dest = crate::identity::Keypair::generate();
        let req = request(dest.peer_id(), vec![]);
        let reply = answer(&dest, &req);
        let parsed = CreatedReply::from_bytes(&reply.to_bytes()).unwrap();
        assert_eq!(parsed, reply);
        assert_eq!(parsed.verify(&req).unwrap(), req.transcript(&reply.kem_ct));

        // A relay on the way answering for the destination.
        let relay = crate::identity::Keypair::generate();
        assert!(answer(&relay, &req).verify(&req).is_err());
        // A relay swapping the ciphertext.
        let mut swapped = reply.clone();
        swapped.kem_ct[0] ^= 1;
        assert!(swapped.verify(&req).is_err());
        // A relay swapping the initiator's ephemeral key.
        let mut other = req.clone();
        other.eph_pk[0] ^= 1;
        assert!(reply.verify(&other).is_err());
    }

    fn pieces_of(len: usize, stream_id: u16) -> (RelayCell, Vec<RelayPiece>) {
        let cell = RelayCell {
            command: RelayCellCommand::Extend,
            stream_id,
            data: (0..len).map(|i| i as u8).collect(),
        };
        let pieces = cell.pieces().unwrap();
        (cell, pieces)
    }

    #[test]
    fn cells_are_512_bytes() {
        assert_eq!(CELL_SIZE, 512);
    }

    #[test]
    fn small_message_is_one_unflagged_piece() {
        let (cell, pieces) = pieces_of(CELL_PAYLOAD_MAX, 0);
        assert_eq!(pieces.len(), 1);
        assert!(!pieces[0].more);
        let mut a = RelayAssembler::default();
        assert_eq!(a.push(pieces[0].clone()).unwrap().data, cell.data);
    }

    #[test]
    fn post_quantum_extend_spans_cells_and_reassembles() {
        let (cell, pieces) = pieces_of(1216 + 32 + 1, 0);
        assert!(pieces.len() >= 3);
        assert!(pieces[..pieces.len() - 1].iter().all(|p| p.more));
        assert!(!pieces.last().unwrap().more);
        let mut a = RelayAssembler::default();
        let mut out = None;
        for p in &pieces {
            // Through the cell body format.
            let parsed = RelayPiece::from_cell(&p.to_cell()).unwrap();
            assert_eq!(&parsed, p);
            assert!(RelayCell::from_cell(&p.to_cell()).is_err());
            out = a.push(parsed);
        }
        let out = out.unwrap();
        assert_eq!(out.command, RelayCellCommand::Extend);
        assert_eq!(out.data, cell.data);
        assert!(a.is_empty());
    }

    #[test]
    fn single_cells_may_interleave_with_a_multi_cell_message() {
        let (cell, pieces) = pieces_of(1000, 0);
        let mut a = RelayAssembler::default();
        assert!(a.push(pieces[0].clone()).is_none());
        let padding = RelayPiece {
            command: RelayCellCommand::Padding,
            stream_id: 0,
            more: false,
            data: vec![],
        };
        assert_eq!(a.push(padding).unwrap().command, RelayCellCommand::Padding);
        let mut out = None;
        for p in &pieces[1..] {
            out = a.push(p.clone());
        }
        assert_eq!(out.unwrap().data, cell.data);
    }

    #[test]
    fn lost_piece_drops_the_message() {
        let (_, pieces) = pieces_of(1900, 3);
        assert!(pieces.len() >= 4);
        let mut a = RelayAssembler::default();
        for (i, p) in pieces.iter().enumerate() {
            if i == 1 {
                continue;
            }
            assert!(a.push(p.clone()).is_none());
        }
        assert!(a.is_empty());
        // A stray continuation with no message in progress is ignored.
        assert!(a.push(pieces[2].clone()).is_none());
    }

    #[test]
    fn oversized_relay_message_is_refused() {
        let cell = RelayCell {
            command: RelayCellCommand::Introduce,
            stream_id: 0,
            data: vec![0; RELAY_MESSAGE_MAX + 1],
        };
        assert!(cell.pieces().is_err());
    }

    #[test]
    fn congestion_window_slow_start() {
        let mut cw = CongestionWindow::new();
        assert_eq!(cw.cwnd, CWND_INIT);
        assert!(cw.slow_start);

        // Simulate sending and receiving SENDMEs
        for _ in 0..SENDME_INC {
            cw.on_send();
        }
        cw.on_sendme();
        assert_eq!(cw.cwnd, CWND_INIT + SENDME_INC);
        assert!(cw.slow_start);
    }

    #[test]
    fn congestion_window_exits_slow_start() {
        let mut cw = CongestionWindow::new();
        // Push cwnd past SS_MAX
        while cw.cwnd < SS_MAX {
            cw.on_sendme();
        }
        assert!(!cw.slow_start);
    }

    #[test]
    fn congestion_window_loss() {
        let mut cw = CongestionWindow::new();
        let start = CWND_MAX; // use a value well above CWND_MIN
        cw.cwnd = start;
        cw.slow_start = false;
        cw.on_loss();
        assert_eq!(cw.cwnd, start / 2);
        cw.on_loss();
        assert_eq!(cw.cwnd, start / 4);
        // Repeated halving eventually clamps at CWND_MIN
        while cw.cwnd > CWND_MIN {
            cw.on_loss();
        }
        assert_eq!(cw.cwnd, CWND_MIN);
        cw.on_loss();
        assert_eq!(cw.cwnd, CWND_MIN, "should not go below CWND_MIN");
    }

    #[test]
    fn congestion_window_sendme_trigger() {
        let mut cw = CongestionWindow::new();
        for i in 0..SENDME_INC - 1 {
            assert!(
                !cw.on_deliver([i as u8; DIGEST_SIZE]),
                "should not trigger at {}",
                i
            );
        }
        assert!(
            cw.on_deliver([0xFF; DIGEST_SIZE]),
            "should trigger at SENDME_INC"
        );
    }

    // --- Replay window tests ---

    #[test]
    fn replay_window_accepts_sequential() {
        let mut rw = ReplayWindow::new();
        for i in 0..100 {
            assert!(rw.accept(i), "should accept nonce {}", i);
        }
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut rw = ReplayWindow::new();
        assert!(rw.accept(5));
        assert!(!rw.accept(5), "duplicate should be rejected");
    }

    #[test]
    fn replay_window_accepts_out_of_order() {
        let mut rw = ReplayWindow::new();
        assert!(rw.accept(10));
        assert!(rw.accept(5), "older-but-unseen should be accepted");
        assert!(rw.accept(8));
        assert!(!rw.accept(5), "now it's a duplicate");
    }

    #[test]
    fn replay_window_rejects_too_old() {
        let mut rw = ReplayWindow::new();
        assert!(rw.accept(0));
        // Advance far ahead
        assert!(rw.accept(2048 + 100));
        // Nonce 0 is now outside the window
        assert!(!rw.accept(0), "too old should be rejected");
        // But something within the window should work
        assert!(rw.accept(2048 + 50));
    }

    #[test]
    fn replay_window_handles_large_gap() {
        let mut rw = ReplayWindow::new();
        assert!(rw.accept(0));
        assert!(rw.accept(10000));
        assert!(rw.accept(10001));
        assert!(!rw.accept(10000), "duplicate after gap");
    }
}
