//! Link frame plaintext: records packed into fixed-size frames.
//!
//! A frame's plaintext is a sequence of records followed by zero padding. A
//! zero byte is the `END` record, so padding needs no marker of its own.
//!
//! ```text
//! record:
//!   0x00 END       the rest of the frame is padding
//!   0x01 MESSAGE   len(u16) || wire_message
//!   0x02 FRAGMENT  msg_id(u16) || index(u16) || count(u16) || len(u16) || bytes
//!   0x03 NACK      msg_id(u16) || n(u8) || n × index(u16)
//! ```
//!
//! Wire messages too large for one frame are split into fragments. On lossy
//! links the receiver asks for missing fragments with `NACK` and the sender
//! resends them from a small buffer, so one lost frame doesn't cost the whole
//! message.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

const REC_END: u8 = 0x00;
const REC_MESSAGE: u8 = 0x01;
const REC_FRAGMENT: u8 = 0x02;
const REC_NACK: u8 = 0x03;

const MESSAGE_HEADER: usize = 1 + 2;
pub(crate) const FRAGMENT_HEADER: usize = 1 + 2 + 2 + 2 + 2;
/// Most indices one NACK record carries.
const NACK_MAX_INDICES: usize = 255;

/// Smallest frame plaintext a link may use: room for a fragment header and
/// some payload.
pub(crate) const MIN_FRAME_PLAIN: usize = 64;

/// A decoded record.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Record<'a> {
    Message(&'a [u8]),
    Fragment {
        msg_id: u16,
        index: u16,
        count: u16,
        bytes: &'a [u8],
    },
    Nack {
        msg_id: u16,
        missing: Vec<u16>,
    },
}

/// Parse a frame's records until `END` or the end of the frame. A malformed
/// or unknown record drops the rest of the frame.
pub(crate) fn parse_frame(mut buf: &[u8]) -> Vec<Record<'_>> {
    let mut out = Vec::new();
    while let Some((&kind, rest)) = buf.split_first() {
        match kind {
            REC_END => break,
            REC_MESSAGE => {
                if rest.len() < 2 {
                    break;
                }
                let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                let Some(body) = rest.get(2..2 + len) else { break };
                out.push(Record::Message(body));
                buf = &rest[2 + len..];
            }
            REC_FRAGMENT => {
                if rest.len() < FRAGMENT_HEADER - 1 {
                    break;
                }
                let msg_id = u16::from_be_bytes([rest[0], rest[1]]);
                let index = u16::from_be_bytes([rest[2], rest[3]]);
                let count = u16::from_be_bytes([rest[4], rest[5]]);
                let len = u16::from_be_bytes([rest[6], rest[7]]) as usize;
                let Some(bytes) = rest.get(8..8 + len) else { break };
                if count == 0 || index >= count {
                    break;
                }
                out.push(Record::Fragment {
                    msg_id,
                    index,
                    count,
                    bytes,
                });
                buf = &rest[8 + len..];
            }
            REC_NACK => {
                if rest.len() < 3 {
                    break;
                }
                let msg_id = u16::from_be_bytes([rest[0], rest[1]]);
                let n = rest[2] as usize;
                let Some(list) = rest.get(3..3 + 2 * n) else { break };
                let missing = list
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                out.push(Record::Nack { msg_id, missing });
                buf = &rest[3 + 2 * n..];
            }
            _ => break,
        }
    }
    out
}

/// Encode a wire message as the records that carry it in frames of
/// `frame_plain` bytes: one `MESSAGE` record if it fits, else fragments.
/// `next_msg_id` is advanced only when the message is fragmented.
pub(crate) fn encode_message(data: &[u8], frame_plain: usize, next_msg_id: &mut u16) -> Vec<Vec<u8>> {
    if MESSAGE_HEADER + data.len() <= frame_plain {
        let mut rec = Vec::with_capacity(MESSAGE_HEADER + data.len());
        rec.push(REC_MESSAGE);
        rec.extend_from_slice(&(data.len() as u16).to_be_bytes());
        rec.extend_from_slice(data);
        return vec![rec];
    }
    let chunk = frame_plain - FRAGMENT_HEADER;
    let count = data.len().div_ceil(chunk);
    debug_assert!(count <= u16::MAX as usize, "message too large to fragment");
    let msg_id = *next_msg_id;
    *next_msg_id = next_msg_id.wrapping_add(1);
    data.chunks(chunk)
        .enumerate()
        .map(|(index, bytes)| {
            let mut rec = Vec::with_capacity(FRAGMENT_HEADER + bytes.len());
            rec.push(REC_FRAGMENT);
            rec.extend_from_slice(&msg_id.to_be_bytes());
            rec.extend_from_slice(&(index as u16).to_be_bytes());
            rec.extend_from_slice(&(count as u16).to_be_bytes());
            rec.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            rec.extend_from_slice(bytes);
            rec
        })
        .collect()
}

/// Smallest first fragment worth starting in a partly filled frame; less
/// room than this is left as padding.
const MIN_FIRST_FRAGMENT: usize = FRAGMENT_HEADER + 32;

/// Like [`encode_message`], but the message starts in a frame that has only
/// `room` bytes left: if it doesn't fit there whole, its first fragment fills
/// that room instead of the room going to padding. On a slow link this keeps
/// cells from costing a mostly empty frame each.
pub(crate) fn encode_message_into(
    data: &[u8],
    frame_plain: usize,
    room: usize,
    next_msg_id: &mut u16,
) -> Vec<Vec<u8>> {
    if MESSAGE_HEADER + data.len() <= room || room < MIN_FIRST_FRAGMENT || room >= frame_plain {
        return encode_message(data, frame_plain, next_msg_id);
    }
    let first = room - FRAGMENT_HEADER;
    let chunk = frame_plain - FRAGMENT_HEADER;
    let count = 1 + (data.len() - first).div_ceil(chunk);
    debug_assert!(count <= u16::MAX as usize, "message too large to fragment");
    let msg_id = *next_msg_id;
    *next_msg_id = next_msg_id.wrapping_add(1);
    let (head, tail) = data.split_at(first);
    std::iter::once(head)
        .chain(tail.chunks(chunk))
        .enumerate()
        .map(|(index, bytes)| {
            let mut rec = Vec::with_capacity(FRAGMENT_HEADER + bytes.len());
            rec.push(REC_FRAGMENT);
            rec.extend_from_slice(&msg_id.to_be_bytes());
            rec.extend_from_slice(&(index as u16).to_be_bytes());
            rec.extend_from_slice(&(count as u16).to_be_bytes());
            rec.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            rec.extend_from_slice(bytes);
            rec
        })
        .collect()
}

/// Encode NACK records for `missing` fragments of `msg_id`.
pub(crate) fn encode_nack(msg_id: u16, missing: &[u16]) -> Vec<Vec<u8>> {
    missing
        .chunks(NACK_MAX_INDICES)
        .map(|part| {
            let mut rec = Vec::with_capacity(4 + 2 * part.len());
            rec.push(REC_NACK);
            rec.extend_from_slice(&msg_id.to_be_bytes());
            rec.push(part.len() as u8);
            for i in part {
                rec.extend_from_slice(&i.to_be_bytes());
            }
            rec
        })
        .collect()
}

/// The fragment `msg_id` and index of an encoded fragment record.
fn fragment_ids(rec: &[u8]) -> Option<(u16, u16)> {
    (rec.first() == Some(&REC_FRAGMENT) && rec.len() >= FRAGMENT_HEADER).then(|| {
        (
            u16::from_be_bytes([rec[1], rec[2]]),
            u16::from_be_bytes([rec[3], rec[4]]),
        )
    })
}

/// Pack records into one frame of exactly `frame_plain` bytes, taking them
/// from the front of `ready` while they fit. Returns `None` if nothing fit.
#[cfg(test)]
pub(crate) fn pack_frame(ready: &mut VecDeque<Vec<u8>>, frame_plain: usize) -> Option<Vec<u8>> {
    pack_frame_with(ready, frame_plain, |_| {})
}

/// Pack records while preserving their caller-owned metadata until consumed.
pub(crate) fn pack_frame_with<T: AsRef<[u8]>>(
    ready: &mut VecDeque<T>,
    frame_plain: usize,
    mut consume: impl FnMut(&T),
) -> Option<Vec<u8>> {
    let mut frame = Vec::with_capacity(frame_plain);
    while let Some(rec) = ready.front() {
        if frame.len() + rec.as_ref().len() > frame_plain {
            break;
        }
        frame.extend_from_slice(rec.as_ref());
        consume(rec);
        ready.pop_front();
    }
    if frame.is_empty() {
        return None;
    }
    frame.resize(frame_plain, REC_END);
    Some(frame)
}

/// The fragments of one message received so far, shared by link and stream
/// reassembly. Memory grows with what arrives, not with the count the
/// sender claims.
pub(crate) struct Fragments {
    count: u16,
    parts: BTreeMap<u16, Vec<u8>>,
    bytes: usize,
}

impl Fragments {
    pub(crate) fn new(count: u16) -> Self {
        Self {
            count,
            parts: BTreeMap::new(),
            bytes: 0,
        }
    }

    pub(crate) fn count(&self) -> u16 {
        self.count
    }

    pub(crate) fn has(&self, index: u16) -> bool {
        self.parts.contains_key(&index)
    }

    /// Bytes held.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Add fragment `index` (below `count`). Returns the bytes it added: 0
    /// for a duplicate.
    pub(crate) fn insert(&mut self, index: u16, bytes: &[u8]) -> usize {
        debug_assert!(index < self.count);
        if self.parts.contains_key(&index) {
            return 0;
        }
        self.parts.insert(index, bytes.to_vec());
        self.bytes += bytes.len();
        bytes.len()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.parts.len() == self.count as usize
    }

    /// Indices below `below` not yet received.
    pub(crate) fn missing(&self, below: u16) -> Vec<u16> {
        (0..below.min(self.count))
            .filter(|i| !self.parts.contains_key(i))
            .collect()
    }

    pub(crate) fn into_message(self) -> Vec<u8> {
        self.parts.into_values().flatten().collect()
    }
}

struct Partial {
    frags: Fragments,
    /// Indices already asked for by a gap NACK, so a later fragment doesn't
    /// ask again for the same gap.
    gap_nacked_below: u16,
    started: Instant,
    last_rx: Instant,
    /// NACKs sent since a new fragment last arrived. Only NACKs that bring
    /// nothing count against the budget: on a link that delays rather than
    /// loses, a NACK followed by the late fragment costs nothing.
    nacks: u8,
    /// Stall NACK backoff exponent: up per stall NACK, down per new fragment.
    backoff: u8,
    /// Silence after which the next stall NACK goes out: the stall time
    /// doubled per backoff step, jittered.
    nack_after: Duration,
}

/// Receiver-side reassembly of fragmented messages for one link.
pub(crate) struct Reassembler {
    partials: HashMap<u16, Partial>,
    /// Recently completed or dropped msg_ids, so a late resent fragment
    /// doesn't start a partial that can never complete.
    done: VecDeque<u16>,
    max_partials: usize,
    timeout: Duration,
    /// Silence on a partial message before the receiver NACKs it.
    stall: Duration,
}

/// Largest message reassembled: a full wire message.
const MAX_MESSAGE: usize = crate::wire::HEADER_SIZE + crate::wire::MAX_PAYLOAD;

/// Most NACKs sent for one message without a new fragment arriving in
/// between. Stall NACKs back off (stall, 2×, 4×…), so the later ones cover
/// repairs that were themselves lost or delayed. Each refill needs a
/// fragment not seen before, so a message gets at most this plus its
/// fragment count in all.
const MAX_NACKS_PER_MESSAGE: u8 = 5;
const DONE_MEMORY: usize = 64;

impl Reassembler {
    pub(crate) fn new(max_partials: usize, timeout: Duration, stall: Duration) -> Self {
        Self {
            partials: HashMap::new(),
            done: VecDeque::new(),
            max_partials,
            timeout,
            stall,
        }
    }

    fn remember_done(&mut self, msg_id: u16) {
        if self.done.len() >= DONE_MEMORY {
            self.done.pop_front();
        }
        self.done.push_back(msg_id);
    }

    /// Add a fragment. Returns the completed message, if this finished one,
    /// and NACK records for a gap this fragment revealed.
    pub(crate) fn insert(
        &mut self,
        msg_id: u16,
        index: u16,
        count: u16,
        bytes: &[u8],
        now: Instant,
    ) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
        if self.done.contains(&msg_id) {
            return (None, Vec::new());
        }
        let mut nacks = Vec::new();
        // A fragment of a newer message means earlier partials have seen
        // their last fragment go by: whatever they still miss is lost.
        for (&id, p) in self.partials.iter_mut() {
            let count = p.frags.count();
            if id != msg_id && p.nacks < MAX_NACKS_PER_MESSAGE && p.gap_nacked_below < count {
                let missing = p.frags.missing(count);
                if !missing.is_empty() && msg_id.wrapping_sub(id) < 0x8000 {
                    p.gap_nacked_below = count;
                    p.nacks += 1;
                    nacks.extend(encode_nack(id, &missing));
                }
            }
        }
        if !self.partials.contains_key(&msg_id) {
            if self.partials.len() >= self.max_partials {
                // Drop the oldest partial to make room.
                if let Some(&oldest) = self.partials.iter().min_by_key(|(_, p)| p.started).map(|(id, _)| id) {
                    self.partials.remove(&oldest);
                    self.remember_done(oldest);
                }
            }
            self.partials.insert(
                msg_id,
                Partial {
                    frags: Fragments::new(count),
                    gap_nacked_below: 0,
                    started: now,
                    last_rx: now,
                    nacks: 0,
                    backoff: 0,
                    nack_after: crate::types::jittered(self.stall),
                },
            );
        }
        let p = self.partials.get_mut(&msg_id).unwrap();
        if p.frags.count() != count || index >= count {
            return (None, nacks);
        }
        p.last_rx = now;
        if p.frags.bytes() + bytes.len() > MAX_MESSAGE {
            // More than any wire message: the sender is lying about count.
            self.partials.remove(&msg_id);
            self.remember_done(msg_id);
            return (None, nacks);
        }
        let new = !p.frags.has(index);
        p.frags.insert(index, bytes);
        if new {
            // Progress: the NACKs so far were not wasted.
            p.nacks = 0;
            p.backoff = p.backoff.saturating_sub(1);
            p.nack_after = crate::types::jittered(self.stall * (1u32 << p.backoff.min(8)));
        }
        if p.frags.is_complete() {
            let p = self.partials.remove(&msg_id).unwrap();
            self.remember_done(msg_id);
            let msg = p.frags.into_message();
            return (Some(msg), nacks);
        }
        // Fragments of one message are sent in order, so a gap below the
        // newest index means loss (or reordering; resends are idempotent).
        if p.nacks < MAX_NACKS_PER_MESSAGE && index > p.gap_nacked_below {
            let missing: Vec<u16> = p
                .frags
                .missing(index)
                .into_iter()
                .filter(|&i| i >= p.gap_nacked_below)
                .collect();
            if !missing.is_empty() {
                p.gap_nacked_below = index;
                p.nacks += 1;
                nacks.extend(encode_nack(msg_id, &missing));
            }
        }
        (None, nacks)
    }

    /// Expire timed-out partials and NACK stalled ones.
    pub(crate) fn poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let timeout = self.timeout;
        let expired: Vec<u16> = self
            .partials
            .iter()
            .filter(|(_, p)| now.duration_since(p.started) >= timeout)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            self.partials.remove(&id);
            self.remember_done(id);
        }
        let mut nacks = Vec::new();
        for (&id, p) in self.partials.iter_mut() {
            if p.nacks < MAX_NACKS_PER_MESSAGE && now.duration_since(p.last_rx) >= p.nack_after {
                let missing = p.frags.missing(p.frags.count());
                if !missing.is_empty() {
                    p.nacks += 1;
                    p.backoff = p.backoff.saturating_add(1);
                    p.nack_after = crate::types::jittered(self.stall * (1u32 << p.backoff.min(8)));
                    p.last_rx = now;
                    nacks.extend(encode_nack(id, &missing));
                }
            }
        }
        nacks
    }

    /// Next stall NACK or expiry. An empty reassembler needs no timer.
    pub(crate) fn next_poll_at(&self) -> Option<Instant> {
        self.partials.values().map(|p| {
            let expires = p.started + self.timeout;
            if p.nacks < MAX_NACKS_PER_MESSAGE {
                expires.min(p.last_rx + p.nack_after)
            } else {
                expires
            }
        }).min()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }
}

/// Sender-side buffer of recently sent fragments, for NACK repair.
pub(crate) struct SentFragments {
    by_id: HashMap<u16, (Instant, Vec<Vec<u8>>)>,
    order: VecDeque<u16>,
    bytes: usize,
    max_bytes: usize,
    max_age: Duration,
}

impl SentFragments {
    pub(crate) fn new(max_bytes: usize, max_age: Duration) -> Self {
        Self {
            by_id: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_bytes,
            max_age,
        }
    }

    fn evict_front(&mut self) {
        if let Some(id) = self.order.pop_front() {
            if let Some((_, recs)) = self.by_id.remove(&id) {
                self.bytes -= recs.iter().map(Vec::len).sum::<usize>();
            }
        }
    }

    /// Remember the fragment records of a message just queued for sending.
    pub(crate) fn remember(&mut self, records: &[Vec<u8>], now: Instant) {
        let Some((msg_id, _)) = records.first().and_then(|r| fragment_ids(r)) else {
            return;
        };
        let size: usize = records.iter().map(Vec::len).sum();
        if size > self.max_bytes {
            return;
        }
        if self.by_id.contains_key(&msg_id) {
            // msg_id wrapped while an old entry was still held.
            self.order.retain(|&id| id != msg_id);
            if let Some((_, recs)) = self.by_id.remove(&msg_id) {
                self.bytes -= recs.iter().map(Vec::len).sum::<usize>();
            }
        }
        while self.bytes + size > self.max_bytes {
            self.evict_front();
        }
        self.by_id.insert(msg_id, (now, records.to_vec()));
        self.order.push_back(msg_id);
        self.bytes += size;
    }

    /// Fragment records to resend for a NACK. Unknown or expired messages
    /// yield nothing.
    pub(crate) fn lookup(&mut self, msg_id: u16, missing: &[u16], now: Instant) -> Vec<Vec<u8>> {
        while let Some(&front) = self.order.front() {
            match self.by_id.get(&front) {
                Some((t, _)) if now.duration_since(*t) <= self.max_age => break,
                _ => self.evict_front(),
            }
        }
        let Some((_, recs)) = self.by_id.get(&msg_id) else {
            return Vec::new();
        };
        missing
            .iter()
            .filter_map(|&i| recs.get(i as usize).cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records_of(frame: &[u8]) -> Vec<Record<'_>> {
        parse_frame(frame)
    }

    #[test]
    fn small_messages_coalesce_into_one_padded_frame() {
        let mut id = 0;
        let mut ready: VecDeque<Vec<u8>> = VecDeque::new();
        ready.extend(encode_message(b"hello", 256, &mut id));
        ready.extend(encode_message(b"world!", 256, &mut id));
        let frame = pack_frame(&mut ready, 256).unwrap();
        assert_eq!(frame.len(), 256);
        assert!(ready.is_empty());
        assert_eq!(
            records_of(&frame),
            vec![Record::Message(b"hello"), Record::Message(b"world!")]
        );
        assert_eq!(id, 0, "unfragmented messages don't use msg ids");
    }

    #[test]
    fn record_that_does_not_fit_waits_for_next_frame() {
        let mut id = 0;
        let mut ready: VecDeque<Vec<u8>> = VecDeque::new();
        ready.extend(encode_message(&[1u8; 200], 256, &mut id));
        ready.extend(encode_message(&[2u8; 200], 256, &mut id));
        let first = pack_frame(&mut ready, 256).unwrap();
        assert_eq!(records_of(&first).len(), 1);
        assert_eq!(ready.len(), 1);
        let second = pack_frame(&mut ready, 256).unwrap();
        assert_eq!(records_of(&second), vec![Record::Message(&[2u8; 200][..])]);
        assert!(pack_frame(&mut ready, 256).is_none());
    }

    #[test]
    fn large_message_fragments_and_reassembles() {
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let mut id = 7;
        let mut ready: VecDeque<Vec<u8>> = encode_message(&data, 256, &mut id).into();
        assert_eq!(id, 8);
        let mut r = Reassembler::new(8, Duration::from_secs(5), Duration::from_secs(1));
        let now = Instant::now();
        let mut out = None;
        while let Some(frame) = pack_frame(&mut ready, 256) {
            for rec in parse_frame(&frame) {
                let Record::Fragment { msg_id, index, count, bytes } = rec else { panic!() };
                assert_eq!(msg_id, 7);
                let (done, nacks) = r.insert(msg_id, index, count, bytes, now);
                assert!(nacks.is_empty());
                if done.is_some() {
                    out = done;
                }
            }
        }
        assert_eq!(out.unwrap(), data);
        assert!(r.is_empty());
    }

    #[test]
    fn message_starting_in_a_partly_filled_frame_fills_it() {
        let mut id = 0;
        let mut ready: VecDeque<Vec<u8>> = VecDeque::new();
        // A cell's tail leaves 145 bytes of a 232-byte frame.
        ready.extend(encode_message(&[1u8; 84], 232, &mut id));
        let room = 232 - ready[0].len();
        let cell = vec![2u8; 524];
        ready.extend(encode_message_into(&cell, 232, room, &mut id));
        let mut frames = Vec::new();
        while let Some(f) = pack_frame(&mut ready, 232) {
            frames.push(f);
        }
        // 87 + 524 bytes plus headers need 3 frames, not 4.
        assert_eq!(frames.len(), 3);
        let mut r = Reassembler::new(8, Duration::from_secs(5), Duration::from_secs(1));
        let mut out = Vec::new();
        for f in &frames {
            for rec in parse_frame(f) {
                match rec {
                    Record::Message(m) => out.push(m.to_vec()),
                    Record::Fragment { msg_id, index, count, bytes } => {
                        out.extend(r.insert(msg_id, index, count, bytes, Instant::now()).0)
                    }
                    _ => panic!(),
                }
            }
        }
        assert_eq!(out, vec![vec![1u8; 84], cell]);
        // A message that fits the room whole stays one record.
        let mut id = 0;
        assert_eq!(encode_message_into(&[0u8; 50], 232, 100, &mut id).len(), 1);
        assert_eq!(id, 0);
    }

    #[test]
    fn max_wire_message_fits_in_slow_link_fragments() {
        let data = vec![0u8; crate::wire::HEADER_SIZE + crate::wire::MAX_PAYLOAD];
        let mut id = 0;
        let recs = encode_message(&data, 232, &mut id);
        assert!(recs.len() > 255, "needs a 16-bit fragment count");
        assert!(recs.iter().all(|r| r.len() <= 232));
    }

    fn fragments(data: &[u8], frame: usize, id: u16) -> Vec<(u16, u16, u16, Vec<u8>)> {
        let mut next = id;
        encode_message(data, frame, &mut next)
            .iter()
            .map(|rec| match parse_frame(rec).pop().unwrap() {
                Record::Fragment { msg_id, index, count, bytes } => (msg_id, index, count, bytes.to_vec()),
                _ => panic!(),
            })
            .collect()
    }

    fn nacked(recs: &[Vec<u8>]) -> Vec<(u16, Vec<u16>)> {
        recs.iter()
            .flat_map(|r| parse_frame(r))
            .map(|rec| match rec {
                Record::Nack { msg_id, missing } => (msg_id, missing),
                _ => panic!(),
            })
            .collect()
    }

    #[test]
    fn gap_triggers_nack_and_repair_completes_message() {
        let data = vec![9u8; 1000];
        let frags = fragments(&data, 128, 3);
        let now = Instant::now();
        let mut sent = SentFragments::new(16 * 1024, Duration::from_secs(10));
        let mut id = 3;
        sent.remember(&encode_message(&data, 128, &mut id), now);

        let mut r = Reassembler::new(8, Duration::from_secs(5), Duration::from_secs(1));
        let mut nacks = Vec::new();
        for (i, f) in frags.iter().enumerate() {
            if i == 2 || i == 4 {
                continue; // lost
            }
            let (done, n) = r.insert(f.0, f.1, f.2, &f.3, now);
            assert!(done.is_none());
            nacks.extend(n);
        }
        let asked = nacked(&nacks);
        let all: Vec<u16> = asked.iter().flat_map(|(_, m)| m.clone()).collect();
        assert_eq!(all, vec![2, 4]);

        let mut done = None;
        for (msg_id, missing) in asked {
            for rec in sent.lookup(msg_id, &missing, now) {
                let Record::Fragment { msg_id, index, count, bytes } = parse_frame(&rec).pop().unwrap() else {
                    panic!()
                };
                if let (Some(m), _) = r.insert(msg_id, index, count, bytes, now) {
                    done = Some(m);
                }
            }
        }
        assert_eq!(done.unwrap(), data);
    }

    #[test]
    fn repair_deadlines_cover_backoff_exhaustion_and_exact_expiry() {
        let t0 = Instant::now();
        let timeout = Duration::from_secs(60);
        let mut r = Reassembler::new(8, timeout, Duration::from_millis(200));
        assert!(r.next_poll_at().is_none());
        r.insert(7, 0, 2, b"first", t0);
        let mut last = t0;
        for _ in 0..MAX_NACKS_PER_MESSAGE {
            let at = r.next_poll_at().unwrap();
            assert!(at > last);
            assert!(!r.poll(at).is_empty(), "deadline did not produce a repair");
            last = at;
        }
        // With no NACK budget left, wait directly for expiry rather than
        // waking repeatedly on an already elapsed stall deadline.
        assert_eq!(r.next_poll_at(), Some(t0 + timeout));
        assert!(r.poll(t0 + timeout).is_empty());
        assert!(r.next_poll_at().is_none());

        let mut r = Reassembler::new(8, Duration::from_millis(10), Duration::from_secs(1));
        r.insert(9, 0, 2, b"first", t0);
        let at = r.next_poll_at().unwrap();
        assert_eq!(at, t0 + Duration::from_millis(10));
        assert!(r.poll(at).is_empty());
        assert!(r.is_empty());
        assert!(r.next_poll_at().is_none());
    }

    #[test]
    fn lost_tail_is_nacked_after_stall_and_nacks_are_capped() {
        let data = vec![1u8; 1000];
        let frags = fragments(&data, 128, 0);
        let t0 = Instant::now();
        let stall = Duration::from_millis(200);
        let mut r = Reassembler::new(8, Duration::from_secs(60), stall);
        for f in &frags[..frags.len() - 1] {
            r.insert(f.0, f.1, f.2, &f.3, t0);
        }
        assert!(r.poll(t0).is_empty());
        let mut at = Vec::new();
        for k in 1..400 {
            let now = t0 + Duration::from_millis(50 * k);
            let n = r.poll(now);
            if !n.is_empty() {
                assert_eq!(nacked(&n), vec![(0, vec![frags.len() as u16 - 1])]);
                at.push(now.duration_since(t0));
            }
        }
        assert_eq!(at.len(), MAX_NACKS_PER_MESSAGE as usize);
        // Each NACK waits about twice as long as the one before, within the
        // ±25% jitter (and the 50 ms poll step).
        let poll = Duration::from_millis(50);
        let mut prev = Duration::ZERO;
        for (k, t) in at.iter().enumerate() {
            let nominal = stall * (1u32 << k);
            let gap = *t - prev;
            assert!(gap >= nominal * 3 / 4 && gap <= nominal * 5 / 4 + poll, "{:?}", at);
            prev = *t;
        }
    }

    #[test]
    fn late_fragments_refill_the_nack_budget() {
        // A link that delays every fragment past the stall time: each NACK
        // is followed by the late fragment, so none is wasted.
        let data = vec![3u8; 2000];
        let frags = fragments(&data, 128, 0);
        assert!(frags.len() > MAX_NACKS_PER_MESSAGE as usize + 2);
        let stall = Duration::from_millis(200);
        let mut r = Reassembler::new(8, Duration::from_secs(600), stall);
        let mut now = Instant::now();
        r.insert(frags[0].0, frags[0].1, frags[0].2, &frags[0].3, now);
        let mut nacks = 0;
        let mut done = None;
        for f in &frags[1..] {
            let mut waited = 0;
            while r.poll(now).is_empty() {
                now += Duration::from_millis(50);
                waited += 1;
                assert!(waited < 2000, "no NACK after {} NACKs", nacks);
            }
            nacks += 1;
            done = r.insert(f.0, f.1, f.2, &f.3, now).0.or(done);
        }
        assert_eq!(nacks, frags.len() - 1);
        assert_eq!(done.unwrap(), data);
    }

    #[test]
    fn partial_larger_than_any_message_is_dropped() {
        let t0 = Instant::now();
        let mut r = Reassembler::new(8, Duration::from_secs(60), Duration::from_secs(60));
        let chunk = [7u8; 1000];
        for index in 0..=(MAX_MESSAGE / chunk.len()) as u16 {
            assert!(r.insert(9, index, u16::MAX, &chunk, t0).0.is_none());
        }
        assert!(r.is_empty(), "oversized partial kept");
    }

    #[test]
    fn late_duplicate_of_completed_message_is_ignored() {
        let frags = fragments(&[5u8; 300], 128, 1);
        let t0 = Instant::now();
        let mut r = Reassembler::new(8, Duration::from_secs(5), Duration::from_secs(1));
        let mut done = None;
        for f in &frags {
            done = r.insert(f.0, f.1, f.2, &f.3, t0).0.or(done);
        }
        assert!(done.is_some());
        let (again, n) = r.insert(frags[0].0, frags[0].1, frags[0].2, &frags[0].3, t0);
        assert!(again.is_none() && n.is_empty() && r.is_empty());
    }

    #[test]
    fn partials_time_out_and_are_bounded() {
        let t0 = Instant::now();
        let mut r = Reassembler::new(2, Duration::from_secs(5), Duration::from_secs(60));
        for id in 0..3u16 {
            let f = &fragments(&[1u8; 300], 128, id)[0];
            r.insert(f.0, f.1, f.2, &f.3, t0 + Duration::from_millis(id as u64));
        }
        assert_eq!(r.partials.len(), 2);
        assert!(!r.partials.contains_key(&0), "oldest partial evicted");
        r.poll(t0 + Duration::from_secs(6));
        assert!(r.is_empty());
    }

    #[test]
    fn nack_for_evicted_message_resends_nothing() {
        let t0 = Instant::now();
        let mut sent = SentFragments::new(600, Duration::from_secs(10));
        let mut id = 0;
        sent.remember(&encode_message(&[1u8; 400], 128, &mut id), t0);
        sent.remember(&encode_message(&[2u8; 400], 128, &mut id), t0);
        assert!(sent.lookup(0, &[0], t0).is_empty(), "evicted by byte cap");
        assert_eq!(sent.lookup(1, &[0, 1], t0).len(), 2);
        assert!(sent.lookup(1, &[0], t0 + Duration::from_secs(11)).is_empty(), "expired");
    }

    #[test]
    fn malformed_record_drops_rest_of_frame() {
        let mut frame = Vec::new();
        let mut id = 0;
        frame.extend(&encode_message(b"ok", 64, &mut id)[0]);
        frame.push(0x7f); // unknown kind
        frame.extend(&encode_message(b"lost", 64, &mut id)[0]);
        assert_eq!(parse_frame(&frame), vec![Record::Message(b"ok")]);
        // Truncated MESSAGE length.
        assert!(parse_frame(&[REC_MESSAGE, 0, 50, 1, 2]).is_empty());
    }
}
