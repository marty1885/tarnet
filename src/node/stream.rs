//! End-to-end sequencing, acknowledgements, retransmission, and ordered EOF.
use super::*;

pub(super) struct StreamState {
    #[cfg(test)]
    sender_passes: std::sync::atomic::AtomicUsize,
    pub app_tx: mpsc::WeakSender<Vec<u8>>,
    pub channel: Mutex<Channel>,
    pub notify: tokio::sync::Notify,
    remote_fin: std::sync::Mutex<Option<u32>>,
    remote_closed: std::sync::atomic::AtomicBool,
    /// Packet delivery runs separately from the circuit's receive/ACK lane.
    delivery_tx: mpsc::Sender<Vec<Vec<u8>>>,
    flow: std::sync::Mutex<FlowControl>,
    closed: std::sync::atomic::AtomicBool,
    delivery_cancel: tokio::sync::Notify,
    /// ACKs may move retry deadlines or reveal a fast-retransmit hole.
    retry_changed: std::sync::atomic::AtomicBool,
    /// Origin of our DATA timestamps.
    epoch: Instant,
}

/// Initial and maximum undelivered packet credit (about 464 KiB). This
/// matches the channel's existing send-window cap to retain bulk capacity.
/// Released packets extend an absolute boundary, so reordered ACKs cannot reopen a
/// stale window or spend the same credit twice.
const RECEIVE_WINDOW: u32 = 1024;
/// Long enough for an application that reads at once (an echo, a shell)
/// to return the credit within it: the receipt ACK and the window update
/// then travel as one cell instead of two. On a slow link a cell is
/// hundreds of milliseconds of airtime.
const ACK_DELAY: Duration = Duration::from_millis(25);
const ACK_EVERY: u32 = 8;
const PERSIST_INITIAL: Duration = Duration::from_secs(1);
const PERSIST_MAX: Duration = Duration::from_secs(8);

fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

struct FlowControl {
    peer_limit: u32,
    receive_limit: u32,
    ack_at: Option<tokio::time::Instant>,
    ack_events: u32,
    /// Timestamp of the last DATA packet received, for the next ACK.
    echo: Option<u16>,
}

impl Default for FlowControl {
    fn default() -> Self {
        Self {
            peer_limit: RECEIVE_WINDOW,
            receive_limit: RECEIVE_WINDOW,
            ack_at: None,
            ack_events: 0,
            echo: None,
        }
    }
}

impl FlowControl {
    fn schedule_ack(&mut self, immediate: bool) {
        let now = tokio::time::Instant::now();
        self.ack_events = self.ack_events.saturating_add(1);
        let at = if immediate || self.ack_events >= ACK_EVERY {
            now
        } else {
            now + ACK_DELAY
        };
        self.ack_at = Some(self.ack_at.map_or(at, |old| old.min(at)));
    }

    fn release(&mut self) {
        self.receive_limit = self.receive_limit.wrapping_add(1);
        self.schedule_ack(false);
    }

    fn update_peer_limit(&mut self, limit: u32) {
        if before(self.peer_limit, limit) {
            self.peer_limit = limit;
        }
    }
}

// Channel packet kinds. A packet is `kind(u8) || body`.
/// One whole application message.
const KIND_DATA: u8 = 0;
/// End of the sending direction (body empty).
const KIND_FIN: u8 = 1;
/// Part of an application message too large for one cell:
/// `msg_id(u16) || index(u16) || count(u16) || bytes`.
const KIND_FRAGMENT: u8 = 2;
/// Unsequenced persist probe. Does not occupy channel state or receive credit.
const KIND_PROBE: u8 = 3;
/// A fragment's fields after its kind byte: msg_id, index, count.
const FRAGMENT_FIELDS: usize = 6;
const FRAGMENT_HEADER: usize = 1 + FRAGMENT_FIELDS;
/// A DATA cell: `seq(u32) || timestamp(u16) || kind(u8) || body`. The
/// timestamp is the sender's own millisecond clock when it sent this copy;
/// the receiver echoes it in its next ACK.
const SEQ_LEN: usize = 4;
const HEADER_LEN: usize = SEQ_LEN + 2;
/// Channel packet bytes that fit one DATA cell after the header.
const PACKET_MAX: usize = CELL_PAYLOAD_MAX - HEADER_LEN;

/// Header of a DATA cell sent now.
fn data_header(epoch: Instant, sequence: u32) -> Vec<u8> {
    let mut data = sequence.to_be_bytes().to_vec();
    data.extend_from_slice(&stamp(epoch).to_be_bytes());
    data
}

/// Our millisecond clock, wrapping: only ever compared with itself.
fn stamp(epoch: Instant) -> u16 {
    epoch.elapsed().as_millis() as u16
}
/// Bounds on partially received application messages per stream. On a
/// reliable stream every missing fragment is still on its way (it holds a
/// channel window slot until acknowledged), so these only trip for a
/// misbehaving peer; on an unreliable stream they also shed messages whose
/// fragments were lost. The oldest partial message is dropped first.
const MAX_PARTIAL_MESSAGES: usize = 256;
const MAX_PARTIAL_BYTES: usize = 4 * 1024 * 1024;

/// Split an application message into channel packets.
fn packetize(data: &[u8], next_msg_id: &mut u16) -> Vec<Vec<u8>> {
    if 1 + data.len() <= PACKET_MAX {
        let mut packet = Vec::with_capacity(1 + data.len());
        packet.push(KIND_DATA);
        packet.extend_from_slice(data);
        return vec![packet];
    }
    let chunk = PACKET_MAX - FRAGMENT_HEADER;
    let count = data.len().div_ceil(chunk);
    // A message too large to number in 16 bits is sent as several messages.
    if count > u16::MAX as usize {
        let (head, tail) = data.split_at(chunk * u16::MAX as usize);
        let mut packets = packetize(head, next_msg_id);
        packets.extend(packetize(tail, next_msg_id));
        return packets;
    }
    let msg_id = *next_msg_id;
    *next_msg_id = next_msg_id.wrapping_add(1);
    data.chunks(chunk)
        .enumerate()
        .map(|(index, bytes)| {
            let mut packet = Vec::with_capacity(FRAGMENT_HEADER + bytes.len());
            packet.push(KIND_FRAGMENT);
            packet.extend_from_slice(&msg_id.to_be_bytes());
            packet.extend_from_slice(&(index as u16).to_be_bytes());
            packet.extend_from_slice(&(count as u16).to_be_bytes());
            packet.extend_from_slice(bytes);
            packet
        })
        .collect()
}

/// Reassembles fragmented application messages. Fragments may arrive in any
/// order (unordered streams) or never (unreliable streams).
#[derive(Default)]
struct FragmentAssembler {
    partials: HashMap<u16, PartialMessage>,
    bytes: usize,
    arrivals: u64,
}

struct PartialMessage {
    first_arrival: u64,
    frags: crate::link_frame::Fragments,
}

impl FragmentAssembler {
    fn drop_oldest(&mut self) {
        let oldest = self
            .partials
            .iter()
            .min_by_key(|(_, p)| p.first_arrival)
            .map(|(id, _)| *id);
        if let Some(p) = oldest.and_then(|id| self.partials.remove(&id)) {
            self.bytes -= p.frags.bytes();
        }
    }

    /// Add a fragment packet body; returns the message it completes.
    fn push(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        if body.len() < FRAGMENT_FIELDS {
            return None;
        }
        let msg_id = u16::from_be_bytes([body[0], body[1]]);
        let index = u16::from_be_bytes([body[2], body[3]]);
        let count = u16::from_be_bytes([body[4], body[5]]);
        let bytes = &body[FRAGMENT_FIELDS..];
        if count < 2 || index >= count {
            return None;
        }
        self.arrivals += 1;
        if !self.partials.contains_key(&msg_id) && self.partials.len() >= MAX_PARTIAL_MESSAGES {
            self.drop_oldest();
        }
        while self.bytes + bytes.len() > MAX_PARTIAL_BYTES && !self.partials.is_empty() {
            self.drop_oldest();
        }
        let arrivals = self.arrivals;
        let partial = self
            .partials
            .entry(msg_id)
            .or_insert_with(|| PartialMessage {
                first_arrival: arrivals,
                frags: crate::link_frame::Fragments::new(count),
            });
        if partial.frags.count() != count {
            let p = self.partials.remove(&msg_id)?;
            self.bytes -= p.frags.bytes();
            return None;
        }
        self.bytes += partial.frags.insert(index, bytes);
        if !partial.frags.is_complete() {
            return None;
        }
        let p = self.partials.remove(&msg_id)?;
        self.bytes -= p.frags.bytes();
        Some(p.frags.into_message())
    }
}

impl EndpointState {
    pub(super) async fn close_stream(&self, key: CircuitKey) {
        self.data_txs.lock().await.remove(&key);
        self.stream_owners.lock().await.remove(&key);
        if let Some(stream) = self.streams.lock().await.remove(&key) {
            stream.closed.store(true, Ordering::Release);
            stream.delivery_cancel.notify_waiters();
            stream.notify.notify_one();
        }
    }
}

/// Encrypt a fresh cell for every transmission, including retransmissions.
/// Sequence numbers belong to the end-to-end channel; crypto nonces never repeat.
/// The last ACK sent and when: an identical one within a round trip tells
/// the sender nothing it can have learned yet.
type LastAck = Option<((u32, u32, Vec<u32>), Instant)>;

/// The ACK we owe, encoded, clearing what it reports. Without `early` only
/// once it is due; with `early` any ACK owed at all, to ride on a DATA cell
/// going out now (it then costs a few bytes rather than a cell).
async fn take_ack(stream: &StreamState, early: bool, last_ack: &mut LastAck) -> Option<Vec<u8>> {
    let (receive_limit, echo) = {
        let mut flow = stream.flow.lock().unwrap();
        let owed = flow.ack_at?;
        if !early && owed > tokio::time::Instant::now() {
            return None;
        }
        flow.ack_at = None;
        flow.ack_events = 0;
        (flow.receive_limit, flow.echo.take())
    };
    let (ack, srtt) = {
        let channel = stream.channel.lock().await;
        (channel.generate_ack(), channel.srtt())
    };
    let (ack_seq, selective_acks) = ack?;
    let id = (ack_seq, receive_limit, selective_acks.clone());
    // A repeat of the ACK sent less than a round trip ago is redundant: the
    // sender can't have seen the first yet. On a slow link each one costs a
    // whole cell, and they queue up ahead of the data they would be
    // acknowledging. Riding on DATA it costs nothing, so it goes anyway.
    let repeat = srtt
        .zip(last_ack.as_ref())
        .is_some_and(|(rtt, (last, at))| *last == id && at.elapsed() < rtt);
    if repeat && !early {
        return None;
    }
    *last_ack = Some((id, Instant::now()));
    Some(
        StreamAckMsg {
            receive_limit,
            ack_seq,
            selective_acks,
            echo,
        }
        .to_bytes(),
    )
}

/// Send a DATA packet, carrying the ACK we owe in the same cell when both
/// fit. An interactive reply then acknowledges what it answers: on a slow
/// link that halves the cells per keystroke.
async fn send_data(
    circuits: &CircuitState,
    sender: &super::sender::Sender,
    key: CircuitKey,
    outbound: bool,
    stream: &StreamState,
    last_ack: &mut LastAck,
    data: &[u8],
) -> Result<()> {
    let ack = if data.len() + 2 + StreamAckMsg::MIN_LEN <= CELL_PAYLOAD_MAX {
        take_ack(stream, true, last_ack).await
    } else {
        None
    };
    match ack {
        Some(ack) if 2 + ack.len() + data.len() <= CELL_PAYLOAD_MAX => {
            let mut cell = (ack.len() as u16).to_be_bytes().to_vec();
            cell.extend_from_slice(&ack);
            cell.extend_from_slice(data);
            send_cell(circuits, sender, key, outbound, RelayCellCommand::StreamDataAck, &cell).await
        }
        ack => {
            if let Some(ack) = ack {
                send_cell(circuits, sender, key, outbound, RelayCellCommand::StreamAck, &ack).await?;
            }
            send_cell(circuits, sender, key, outbound, RelayCellCommand::Data, data).await
        }
    }
}

async fn send_cell(
    circuits: &CircuitState,
    sender: &super::sender::Sender,
    key: CircuitKey,
    outbound: bool,
    command: RelayCellCommand,
    data: &[u8],
) -> Result<()> {
    let encoded = if outbound {
        let mut map = circuits.outbound.lock().await;
        let circuit = map
            .get_mut(&key.circuit_id)
            .filter(|c| c.first_hop == key.from_peer)
            .ok_or_else(|| Error::Protocol("stream circuit gone".into()))?;
        let (_, cid, cell) = circuit.send_relay_cell(&RelayCell {
            command,
            stream_id: 0,
            data: data.to_vec(),
        });
        encode_circuit_relay_cell(cid, &cell)
    } else {
        let body = write_cell_body(command, 0, data);
        let mut map = circuits.hop_backward_keys.lock().await;
        let hop = map
            .get_mut(&(key.circuit_id, key.from_peer))
            .ok_or_else(|| Error::Protocol("stream backward keys gone".into()))?;
        let n = hop.counter;
        hop.counter = n
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("backward counter exhausted".into()))?;
        super::circuit::seal_backward_cell(&mut hop.keys, n, key.circuit_id, &body)
    };
    // Loss here is safe: reliable channels retain the plaintext until its ACK.
    sender
        .to_peer(&key.from_peer, &encoded, super::sender::Queue::Data)
        .await
}

impl Node {
    pub(super) async fn stream_connection(
        &self,
        sid: tarnet_api::types::ServiceId,
        mode: tarnet_api::service::PortMode,
        port: &str,
        key: CircuitKey,
        outbound: bool,
    ) -> Connection {
        use tarnet_api::service::PortMode;
        let reliable = mode != PortMode::UnreliableUnordered;
        let ordered = mode == PortMode::ReliableOrdered;
        let (app_tx, mut outgoing) = mpsc::channel::<Vec<u8>>(256);
        let (delivery_tx, mut delivery_rx) = mpsc::channel::<Vec<Vec<u8>>>(RECEIVE_WINDOW as usize);
        let stream = Arc::new(StreamState {
            #[cfg(test)]
            sender_passes: std::sync::atomic::AtomicUsize::new(0),
            app_tx: app_tx.downgrade(),
            channel: Mutex::new(Channel::from_port_name(
                key.circuit_id,
                port,
                reliable,
                ordered,
            )),
            notify: tokio::sync::Notify::new(),
            remote_fin: std::sync::Mutex::new(None),
            remote_closed: std::sync::atomic::AtomicBool::new(false),
            delivery_tx,
            flow: Default::default(),
            closed: std::sync::atomic::AtomicBool::new(false),
            delivery_cancel: tokio::sync::Notify::new(),
            retry_changed: std::sync::atomic::AtomicBool::new(false),
            epoch: Instant::now(),
        });
        // Our link on this circuit is the slowest hop we know of: size
        // retransmission timeouts so packets queued on it aren't resent early.
        let airtime = self
            .links
            .lock()
            .await
            .get(&key.from_peer)
            .map(|l| l.message_airtime(HEADER_SIZE + 4 + CELL_SIZE))
            .unwrap_or_default();
        stream.channel.lock().await.set_path_airtime(airtime);
        let (incoming_tx, app_rx) = mpsc::channel::<Vec<u8>>(256);
        self.endpoints
            .data_txs
            .lock()
            .await
            .insert(key, incoming_tx);
        self.endpoints
            .streams
            .lock()
            .await
            .insert(key, stream.clone());
        let delivery_stream = stream.clone();
        let delivery_endpoints = self.endpoints.clone();
        tokio::spawn(async move {
            let stream = delivery_stream;
            let mut fragments = FragmentAssembler::default();
            let mut fin_delivered = false;
            'delivery: loop {
                let cancelled = stream.delivery_cancel.notified();
                tokio::pin!(cancelled);
                cancelled.as_mut().enable();
                if stream.closed.load(Ordering::Acquire) {
                    break;
                }
                let batch = tokio::select! {
                    _ = &mut cancelled => break,
                    batch = delivery_rx.recv() => match batch {
                        Some(batch) => batch,
                        None => break,
                    },
                };
                for payload in batch {
                    let message = match payload[0] {
                        KIND_DATA => Some(payload[1..].to_vec()),
                        KIND_FRAGMENT => fragments.push(&payload[1..]),
                        KIND_FIN => {
                            fin_delivered = true;
                            None
                        }
                        _ => None,
                    };
                    if let Some(message) = message {
                        let tx = delivery_endpoints.data_txs.lock().await.get(&key).cloned();
                        let Some(tx) = tx else { break 'delivery };
                        if reliable {
                            tokio::select! {
                                _ = &mut cancelled => break 'delivery,
                                result = tx.send(message) => if result.is_err() { break 'delivery; },
                            }
                        } else {
                            // Best-effort delivery cannot backpressure the
                            // remote sender. Drop at the full application
                            // queue instead of accumulating another backlog
                            // of stale datagrams in the delivery worker.
                            match tx.try_send(message) {
                                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                Err(mpsc::error::TrySendError::Closed(_)) => break 'delivery,
                            }
                        }
                    }
                    if reliable {
                        stream.flow.lock().unwrap().release();
                        stream.notify.notify_one();
                    }
                }
                if !reliable {
                    continue;
                }
                // Unordered FIN must still wait for earlier sequence holes;
                // ordered delivery naturally reaches this only after them.
                let fin = *stream.remote_fin.lock().unwrap();
                let ack = stream.channel.lock().await.generate_ack();
                let receive_limit = stream.flow.lock().unwrap().receive_limit;
                if fin_delivered
                    && fin.zip(ack).is_some_and(|(fin, (ack, _))| {
                        before(fin, ack) && before(fin.wrapping_add(RECEIVE_WINDOW), receive_limit)
                    })
                {
                    delivery_endpoints.data_txs.lock().await.remove(&key);
                    stream.flow.lock().unwrap().schedule_ack(true);
                    stream.remote_closed.store(true, Ordering::Release);
                    stream.notify.notify_one();
                    break;
                }
            }
            if !stream.remote_closed.load(Ordering::Acquire) {
                delivery_endpoints.close_stream(key).await;
            }
        });
        let circuits = self.circuits.clone();
        let endpoints = self.endpoints.clone();
        let sender = self.sender.clone();
        tokio::spawn(async move {
            let mut pending = VecDeque::<Vec<u8>>::new();
            let mut next_msg_id: u16 = 0;
            let mut closing = false;
            let mut fin_sent = false;
            let mut fin_sequence = None;
            let mut retry_at: Option<Instant> = None;
            let mut persist_at = None;
            let mut persist_interval = PERSIST_INITIAL;
            let mut last_ack: LastAck = None;
            'send: loop {
                #[cfg(test)]
                stream.sender_passes.fetch_add(1, Ordering::Relaxed);
                let alive = if outbound {
                    circuits
                        .outbound
                        .lock()
                        .await
                        .get(&key.circuit_id)
                        .is_some_and(|c| c.first_hop == key.from_peer)
                } else {
                    circuits
                        .hop_backward_keys
                        .lock()
                        .await
                        .contains_key(&(key.circuit_id, key.from_peer))
                };
                if !alive {
                    break;
                }
                if !endpoints
                    .streams
                    .lock()
                    .await
                    .get(&key)
                    .is_some_and(|active| Arc::ptr_eq(active, &stream))
                {
                    break;
                }
                // A due ACK waits for a DATA packet that can go in this pass
                // with room for it, and rides on it.
                let fits = pending
                    .front()
                    .is_some_and(|p| HEADER_LEN + p.len() + 2 + StreamAckMsg::MIN_LEN <= CELL_PAYLOAD_MAX);
                let data_ready = fits && {
                    let peer_limit = stream.flow.lock().unwrap().peer_limit;
                    let channel = stream.channel.lock().await;
                    channel.can_send() && !(reliable && !before(channel.next_send_sequence(), peer_limit))
                };
                if !data_ready {
                    if let Some(data) = take_ack(&stream, false, &mut last_ack).await {
                        if send_cell(
                            &circuits,
                            &sender,
                            key,
                            outbound,
                            RelayCellCommand::StreamAck,
                            &data,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                }
                // Check retries even while new packets can be sent. Doing
                // this only in the idle select lets ACKs keep opening slots
                // for fresh data while a hole holds up ordered delivery.
                if stream.retry_changed.swap(false, Ordering::AcqRel) {
                    retry_at = stream.channel.lock().await.next_retransmit_at();
                }
                if retry_at.is_some_and(|at| at <= Instant::now()) {
                    let due = {
                        let mut channel = stream.channel.lock().await;
                        let due = channel.retransmit_due();
                        retry_at = channel.next_retransmit_at();
                        due
                    };
                    for (sequence, payload) in due {
                        log::trace!("stream {:?}: retransmit seq {}", key.circuit_id, sequence);
                        let mut data = data_header(stream.epoch, sequence);
                        data.extend_from_slice(&payload);
                        if send_data(&circuits, &sender, key, outbound, &stream, &mut last_ack, &data)
                            .await
                            .is_err()
                        {
                            break 'send;
                        }
                    }
                }
                let peer_limit = stream.flow.lock().unwrap().peer_limit;
                let (packet, credit_blocked, next_sequence, waiting_fin_delivery) = {
                    let mut channel = stream.channel.lock().await;
                    if channel.is_dead() {
                        break;
                    }
                    // Half-close: our FIN only closes our sending direction.
                    // Keep receiving (and ACKing) until the peer also reaches EOF.
                    // Receipt ACKs can precede application delivery. Do not
                    // tear down the peer's delivery worker until its credit
                    // proves it has handed off our FIN as well as our data.
                    let waiting_fin_delivery = fin_sequence.is_some_and(|seq: u32| {
                        !before(seq.wrapping_add(RECEIVE_WINDOW), peer_limit)
                    });
                    if fin_sent
                        && !waiting_fin_delivery
                        && channel.pending_retransmit().is_empty()
                        && stream
                            .remote_closed
                            .load(std::sync::atomic::Ordering::Acquire)
                    {
                        break;
                    }
                    let next_sequence = channel.next_send_sequence();
                    let credit_blocked = reliable && !before(next_sequence, peer_limit);
                    let packet = if channel.can_send() && !credit_blocked {
                        pending.pop_front().map(|payload| {
                            fin_sent |= payload[0] == KIND_FIN;
                            if payload[0] == KIND_FIN {
                                fin_sequence = Some(next_sequence);
                            }
                            let packet = channel.prepare_send(payload).remove(0);
                            if let Some(at) = channel.packet_retransmit_at(packet.0) {
                                retry_at = Some(retry_at.map_or(at, |old| old.min(at)));
                            }
                            packet
                        })
                    } else {
                        None
                    };
                    (packet, credit_blocked, next_sequence, waiting_fin_delivery)
                };
                if let Some((sequence, payload)) = packet {
                    persist_at = None;
                    persist_interval = PERSIST_INITIAL;
                    log::trace!("stream {:?}: send seq {}", key.circuit_id, sequence);
                    let mut data = data_header(stream.epoch, sequence);
                    data.extend_from_slice(&payload);
                    if send_data(&circuits, &sender, key, outbound, &stream, &mut last_ack, &data)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                if (credit_blocked && !pending.is_empty()) || waiting_fin_delivery {
                    let at = persist_at
                        .get_or_insert_with(|| tokio::time::Instant::now() + persist_interval);
                    if *at <= tokio::time::Instant::now() {
                        let mut data = data_header(stream.epoch, next_sequence);
                        data.push(KIND_PROBE);
                        if send_cell(
                            &circuits,
                            &sender,
                            key,
                            outbound,
                            RelayCellCommand::Data,
                            &data,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                        persist_interval = (persist_interval * 2).min(PERSIST_MAX);
                        *at = tokio::time::Instant::now() + persist_interval;
                    }
                } else {
                    persist_at = None;
                    persist_interval = PERSIST_INITIAL;
                }
                let ack_at = stream.flow.lock().unwrap().ack_at;
                let wake_at = ack_at
                    .into_iter()
                    .chain(persist_at)
                    .chain(retry_at.map(tokio::time::Instant::from_std))
                    .min();
                tokio::select! {
                    data = outgoing.recv(), if pending.is_empty() && !closing => {
                        match data {
                            Some(data) => {
                                pending.extend(packetize(&data, &mut next_msg_id));
                            }
                            None => {
                                closing = true;
                                if reliable { pending.push_back(vec![KIND_FIN]); }
                                else { break; }
                            }
                        }
                    }
                    _ = stream.notify.notified() => {}
                    _ = async {
                        match wake_at {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {}
                }
            }
            // Reliable FIN has been acknowledged, or the circuit is unusable.
            let _ = send_cell(
                &circuits,
                &sender,
                key,
                outbound,
                RelayCellCommand::StreamEnd,
                &[],
            )
            .await;
            endpoints.close_stream(key).await;
            if outbound {
                circuits.outbound.lock().await.remove(&key.circuit_id);
                endpoints
                    .pending_connects
                    .lock()
                    .await
                    .remove(&key.circuit_id);
            }
        });
        Connection::new(sid, mode, port.to_string(), key.circuit_id, app_tx, app_rx)
    }

    pub(super) async fn handle_stream_data(&self, key: CircuitKey, data: &[u8]) -> Result<()> {
        let kind = HEADER_LEN;
        if data.len() < HEADER_LEN + 1
            || data[kind] > KIND_PROBE
            || (matches!(data[kind], KIND_FIN | KIND_PROBE) && data.len() != HEADER_LEN + 1)
            || (data[kind] == KIND_FRAGMENT && data.len() < HEADER_LEN + FRAGMENT_HEADER)
        {
            return Err(Error::Wire("invalid stream DATA".into()));
        }
        let stream = self.endpoints.streams.lock().await.get(&key).cloned();
        let Some(stream) = stream else {
            return Ok(());
        };
        let sequence = u32::from_be_bytes(data[..SEQ_LEN].try_into().unwrap());
        let reliable = stream.channel.lock().await.reliable;
        if reliable {
            stream.flow.lock().unwrap().echo =
                Some(u16::from_be_bytes([data[SEQ_LEN], data[SEQ_LEN + 1]]));
        }
        if data[kind] == KIND_PROBE {
            if reliable {
                stream.flow.lock().unwrap().schedule_ack(true);
                stream.notify.notify_one();
            }
            return Ok(());
        }
        if reliable && !before(sequence, stream.flow.lock().unwrap().receive_limit) {
            // Ignore data outside granted credit, but repeat the current
            // window in case the sender lost a window update.
            stream.flow.lock().unwrap().schedule_ack(true);
            stream.notify.notify_one();
            return Ok(());
        }
        let (ready, immediate) = {
            let mut channel = stream.channel.lock().await;
            let expected = channel.generate_ack().map(|(seq, _)| seq);
            let ready = channel.receive_data(sequence, data[HEADER_LEN..].to_vec());
            let immediate = expected.is_some_and(|seq| seq != sequence) || data[kind] == KIND_FIN;
            (ready, immediate)
        };
        if data[kind] == KIND_FIN {
            *stream.remote_fin.lock().unwrap() = Some(sequence);
        }
        if !ready.is_empty() {
            // Granted credit bounds outstanding packets across reordering
            // and delivery. Never wait for the application in this lane:
            // reverse-direction ACKs must keep making progress.
            if stream.delivery_tx.try_send(ready).is_err() && reliable {
                self.endpoints.close_stream(key).await;
                return Err(Error::Protocol("stream delivery queue unavailable".into()));
            }
        }
        if reliable {
            stream.flow.lock().unwrap().schedule_ack(immediate);
            stream.notify.notify_one();
        }
        Ok(())
    }

    /// A cell carrying an ACK and a DATA packet: the ACK first, so the
    /// window it opens is there for whatever the packet triggers.
    pub(super) async fn handle_stream_data_ack(&self, key: CircuitKey, data: &[u8]) -> Result<()> {
        let len = data
            .get(..2)
            .map(|l| u16::from_be_bytes([l[0], l[1]]) as usize)
            .filter(|&len| data.len() >= 2 + len)
            .ok_or_else(|| Error::Wire("truncated stream DATA+ACK".into()))?;
        self.handle_stream_ack(key, &data[2..2 + len]).await?;
        self.handle_stream_data(key, &data[2 + len..]).await
    }

    pub(super) async fn handle_stream_ack(&self, key: CircuitKey, data: &[u8]) -> Result<()> {
        // The decoder bounds the selective acks.
        let ack = StreamAckMsg::from_bytes(data)?;
        let stream = self.endpoints.streams.lock().await.get(&key).cloned();
        if let Some(stream) = stream {
            log::trace!(
                "stream {:?}: ack {} sack {:?}",
                key.circuit_id,
                ack.ack_seq,
                ack.selective_acks
            );
            let echo_rtt = ack
                .echo
                .map(|sent| Duration::from_millis(stamp(stream.epoch).wrapping_sub(sent) as u64));
            stream
                .channel
                .lock()
                .await
                .process_ack_timed(ack.ack_seq, &ack.selective_acks, echo_rtt);
            stream.retry_changed.store(true, Ordering::Release);
            stream
                .flow
                .lock()
                .unwrap()
                .update_peer_limit(ack.receive_limit);
            stream.notify.notify_one();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ack_batch_deadline_is_bounded_and_gaps_are_prompt() {
        let mut flow = FlowControl::default();
        flow.schedule_ack(false);
        let first = flow.ack_at.unwrap();
        for _ in 0..ACK_EVERY - 2 {
            flow.schedule_ack(false);
        }
        assert_eq!(flow.ack_at, Some(first));
        flow.schedule_ack(false);
        assert!(flow.ack_at.unwrap() <= tokio::time::Instant::now());
        let mut flow = FlowControl::default();
        flow.schedule_ack(false);
        flow.schedule_ack(true);
        assert!(flow.ack_at.unwrap() <= tokio::time::Instant::now());
    }

    #[test]
    fn receive_credit_is_monotonic_across_wrap_and_stale_updates() {
        let mut flow = FlowControl::default();
        flow.peer_limit = u32::MAX - 2;
        flow.update_peer_limit(3);
        assert_eq!(flow.peer_limit, 3);
        flow.update_peer_limit(u32::MAX);
        assert_eq!(flow.peer_limit, 3);
        flow.receive_limit = u32::MAX;
        flow.release();
        assert_eq!(flow.receive_limit, 0);
    }

    async fn connected_pair(
        mode: tarnet_api::service::PortMode,
    ) -> (Arc<Node>, Arc<Node>, Connection, Connection) {
        use crate::transport::tcp::TcpDiscovery;
        let server = Arc::new(Node::new(Keypair::generate()));
        let client = Arc::new(Node::new(Keypair::generate()));
        let discovery = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
        let address = discovery.local_addrs()[0].to_string();
        let listener = server
            .circuit_listen(
                tarnet_api::types::ServiceId::ALL,
                mode,
                "flow",
                ListenerOptions::default(),
            )
            .await
            .unwrap();
        let node = server.clone();
        tokio::spawn(async move {
            node.run(Box::new(discovery), vec![], vec![]).await.unwrap();
        });
        let discovery = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
        let node = client.clone();
        tokio::spawn(async move {
            node.run(Box::new(discovery), vec![address], vec![])
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !client.connected_peers().await.contains(&server.peer_id()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let outgoing = client
            .circuit_connect(
                server.default_service_id().await,
                mode,
                "flow",
                Some(server.peer_id()),
                None,
            )
            .await
            .unwrap();
        let incoming = server.circuit_accept(listener.id).await.unwrap();
        (client, server, outgoing, incoming)
    }

    async fn paused_sender(node: &Node, id: u32) -> Arc<StreamState> {
        let stream = node
            .endpoints
            .streams
            .lock()
            .await
            .iter()
            .find(|(key, _)| key.circuit_id == id)
            .unwrap()
            .1
            .clone();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let limit = stream.flow.lock().unwrap().peer_limit;
                let paused = {
                    let channel = stream.channel.lock().await;
                    limit >= RECEIVE_WINDOW + 256
                        && channel.next_send_sequence() == limit
                        && channel.pending_retransmit().is_empty()
                };
                if paused {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sender did not stop cleanly at the receive window");
        stream
    }

    #[tokio::test]
    async fn unreliable_full_reader_drops_without_a_second_backlog() {
        let (_client, server, _outgoing, incoming) =
            connected_pair(tarnet_api::service::PortMode::UnreliableUnordered).await;
        let key = *server.endpoints.streams.lock().await.keys().next().unwrap();
        let stream = server.endpoints.streams.lock().await[&key].clone();
        let (_tx, mut rx) = incoming.into_split();
        // Inject a burst larger than the bounded application queue. Raw
        // datagrams have no channel sequence state, ACKs, or credit returns.
        for i in 0..400u32 {
            let mut data = vec![0; HEADER_LEN];
            data.push(KIND_DATA);
            data.extend_from_slice(&i.to_be_bytes());
            server.handle_stream_data(key, &data).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while rx.len() != 256
                || stream.delivery_tx.capacity() != stream.delivery_tx.max_capacity()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("unreliable delivery blocked behind a full reader");
        for i in 0..256u32 {
            assert_eq!(rx.recv().await.unwrap(), i.to_be_bytes());
        }
        let mut fresh = vec![0; HEADER_LEN];
        fresh.push(KIND_DATA);
        fresh.extend_from_slice(b"fresh");
        server.handle_stream_data(key, &fresh).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"fresh"
        );
        assert!(stream.flow.lock().unwrap().ack_at.is_none());
        assert_eq!(stream.flow.lock().unwrap().receive_limit, RECEIVE_WINDOW);
        assert!(stream.channel.lock().await.pending_retransmit().is_empty());
    }

    #[tokio::test]
    async fn slow_reader_preserves_reverse_acks_and_half_close() {
        let (client, server, outgoing, incoming) =
            connected_pair(tarnet_api::service::PortMode::ReliableOrdered).await;
        let id = outgoing.id;
        let (client_tx, mut client_rx) = outgoing.into_split();
        let (server_tx, mut server_rx) = incoming.into_split();
        let producer = tokio::spawn(async move {
            for i in 0..2048u32 {
                client_tx.send(i.to_be_bytes().to_vec()).await.unwrap();
            }
        });
        let stream = paused_sender(&client, id).await;
        assert_eq!(server_rx.len(), 256);
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(stream.channel.lock().await.pending_retransmit().is_empty());
        server_tx.send(b"reverse".to_vec()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"reverse"
        );
        // The reverse receipt ACK must arrive even while server_rx is full.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let stream = server
                    .endpoints
                    .streams
                    .lock()
                    .await
                    .values()
                    .next()
                    .unwrap()
                    .clone();
                if stream.channel.lock().await.pending_retransmit().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reverse ACK blocked behind the slow reader");
        drop(server_tx);
        tokio::time::timeout(Duration::from_secs(10), async {
            for i in 0..2048u32 {
                assert_eq!(server_rx.recv().await.unwrap(), i.to_be_bytes());
            }
            assert!(server_rx.recv().await.is_none());
            assert!(client_rx.recv().await.is_none());
            producer.await.unwrap();
        })
        .await
        .expect("flow-controlled data/FIN failed to drain");
    }

    #[tokio::test]
    async fn persist_probe_recovers_a_lost_window_update() {
        use crate::firewall::{Action, Firewall, Match};
        let (client, _server, outgoing, incoming) =
            connected_pair(tarnet_api::service::PortMode::ReliableOrdered).await;
        let id = outgoing.id;
        let (client_tx, _client_rx) = outgoing.into_split();
        let (_server_tx, mut server_rx) = incoming.into_split();
        let producer = tokio::spawn(async move {
            for i in 0..1792u32 {
                client_tx.send(i.to_be_bytes().to_vec()).await.unwrap();
            }
        });
        let stream = paused_sender(&client, id).await;
        let old_limit = stream.flow.lock().unwrap().peer_limit;
        let mut firewall = Firewall::default();
        firewall.add_rule(Match::MsgType(MessageType::CircuitRelay), Action::Drop);
        client.set_firewall(firewall).await;
        let drain = tokio::spawn(async move {
            for i in 0..1792u32 {
                assert_eq!(server_rx.recv().await.unwrap(), i.to_be_bytes());
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(stream.flow.lock().unwrap().peer_limit, old_limit);
        assert!(stream.channel.lock().await.pending_retransmit().is_empty());
        client.set_firewall(Firewall::default()).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            drain.await.unwrap();
            producer.await.unwrap();
        })
        .await
        .expect("lost window update left the stream stuck");
    }

    #[tokio::test]
    async fn unordered_fin_waits_for_queued_fragments() {
        let (_client, server, _outgoing, incoming) =
            connected_pair(tarnet_api::service::PortMode::ReliableUnordered).await;
        let key = *server.endpoints.streams.lock().await.keys().next().unwrap();
        let payload = vec![19; PACKET_MAX + 10];
        let packets = packetize(&payload, &mut 0);
        assert_eq!(packets.len(), 2);
        // Receipt of the last missing fragment advances the channel's ACK
        // past FIN before the separate delivery worker drains its queue.
        for (sequence, packet) in [
            (0u32, packets[0].clone()),
            (2, vec![KIND_FIN]),
            (1, packets[1].clone()),
        ] {
            let mut data = data_header(Instant::now(), sequence);
            data.extend(packet);
            server.handle_stream_data(key, &data).await.unwrap();
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), incoming.recv())
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), incoming.recv())
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn fragmented_message_larger_than_credit_makes_progress() {
        let (_client, _server, outgoing, incoming) =
            connected_pair(tarnet_api::service::PortMode::ReliableOrdered).await;
        let payload = vec![77; 3 * RECEIVE_WINDOW as usize * PACKET_MAX];
        outgoing.send(&payload).await.unwrap();
        drop(outgoing);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), incoming.recv())
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), incoming.recv())
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tickless_stream_soak_with_loss_rekeys_and_idle_recovery() {
        use crate::firewall::{Action, Firewall, Match};
        let (client, server, outgoing, incoming) =
            connected_pair(tarnet_api::service::PortMode::ReliableOrdered).await;
        let client_stream = client
            .endpoints
            .streams
            .lock()
            .await
            .values()
            .next()
            .unwrap()
            .clone();
        let server_stream = server
            .endpoints
            .streams
            .lock()
            .await
            .values()
            .next()
            .unwrap()
            .clone();
        for node in [&client, &server] {
            let mut firewall = Firewall::default();
            firewall.add_rule(
                Match::All(vec![
                    Match::MsgType(MessageType::CircuitRelay),
                    Match::Probability(0.10),
                ]),
                Action::Drop,
            );
            node.set_firewall(firewall).await;
        }
        let rekey_node = client.clone();
        let peer = server.peer_id();
        let rekeys = tokio::spawn(async move {
            for _ in 0..8 {
                let before = rekey_node.link_key_epoch(&peer).await.unwrap();
                rekey_node.request_link_rekey().await;
                tokio::time::timeout(Duration::from_secs(5), async {
                    while rekey_node.link_key_epoch(&peer).await.unwrap() == before {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("rekey stalled during bidirectional traffic");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let payload = |round: u32, index: u32, direction: u8| {
            let mut data = vec![direction; [64, 512, 2048, 8192][round as usize % 4]];
            data[..4].copy_from_slice(&round.to_be_bytes());
            data[4..8].copy_from_slice(&index.to_be_bytes());
            data
        };
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(120), async {
            for round in 0..8 {
                tokio::join!(
                    async {
                        for index in 0..64 {
                            outgoing.send(&payload(round, index, 1)).await.unwrap();
                        }
                    },
                    async {
                        for index in 0..64 {
                            incoming.send(&payload(round, index, 2)).await.unwrap();
                        }
                    },
                    async {
                        for index in 0..64 {
                            assert_eq!(incoming.recv().await.unwrap(), payload(round, index, 1));
                        }
                    },
                    async {
                        for index in 0..64 {
                            assert_eq!(outgoing.recv().await.unwrap(), payload(round, index, 2));
                        }
                    },
                );
            }
            rekeys.await.unwrap();
        })
        .await
        .expect("tickless data path stalled under loss and rekeys");
        // Clear loss and wait for the final receipts/window updates before
        // checking that the per-stream send tasks stop running altogether.
        client.clear_firewall().await;
        server.clear_firewall().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let a = client_stream
                    .channel
                    .lock()
                    .await
                    .pending_retransmit()
                    .is_empty();
                let b = server_stream
                    .channel
                    .lock()
                    .await
                    .pending_retransmit()
                    .is_empty();
                if a && b {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let a = client_stream.sender_passes.load(Ordering::Relaxed);
        let b = server_stream.sender_passes.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(650)).await;
        assert_eq!(
            client_stream.sender_passes.load(Ordering::Relaxed),
            a,
            "client retained an idle retry timer"
        );
        assert_eq!(
            server_stream.sender_passes.load(Ordering::Relaxed),
            b,
            "server retained an idle retry timer"
        );
        eprintln!("tickless stream soak: 2768896 verified bytes, 10% DATA/ACK loss each way, 8 rekeys, {:?}, 0 idle passes in 650 ms", started.elapsed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn circuit_rekeys_under_loss_keep_the_stream_intact() {
        use crate::firewall::{Action, Firewall, Match};
        let (client, server, outgoing, incoming) =
            connected_pair(tarnet_api::service::PortMode::ReliableOrdered).await;
        let circuit_id = *client.circuits.outbound.lock().await.keys().next().unwrap();
        for node in [&client, &server] {
            let mut firewall = Firewall::default();
            firewall.add_rule(
                Match::All(vec![
                    Match::MsgType(MessageType::CircuitRelay),
                    Match::Probability(0.10),
                ]),
                Action::Drop,
            );
            node.set_firewall(firewall).await;
        }
        const REKEYS: u32 = 6;
        let rekey_node = client.clone();
        let rekeys = tokio::spawn(async move {
            for _ in 0..REKEYS {
                // A failed try leaves the generation pending; retrying it
                // must keep both ends' chains in step.
                tokio::time::timeout(Duration::from_secs(30), async {
                    while rekey_node.rekey_circuit_now(circuit_id).await.is_err() {}
                })
                .await
                .expect("circuit rekey never completed");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let payload = |round: u32, index: u32, direction: u8| {
            let mut data = vec![direction; [64, 512, 2048, 8192][round as usize % 4]];
            data[..4].copy_from_slice(&round.to_be_bytes());
            data[4..8].copy_from_slice(&index.to_be_bytes());
            data
        };
        tokio::time::timeout(Duration::from_secs(120), async {
            for round in 0..8 {
                tokio::join!(
                    async {
                        for index in 0..32 {
                            outgoing.send(&payload(round, index, 1)).await.unwrap();
                        }
                    },
                    async {
                        for index in 0..32 {
                            incoming.send(&payload(round, index, 2)).await.unwrap();
                        }
                    },
                    async {
                        for index in 0..32 {
                            assert_eq!(incoming.recv().await.unwrap(), payload(round, index, 1));
                        }
                    },
                    async {
                        for index in 0..32 {
                            assert_eq!(outgoing.recv().await.unwrap(), payload(round, index, 2));
                        }
                    },
                );
            }
            rekeys.await.unwrap();
        })
        .await
        .expect("stream stalled across circuit rekeys");
        client.clear_firewall().await;
        server.clear_firewall().await;

        // Traffic after the last rekey switches the server's sending side.
        outgoing.send(b"after").await.unwrap();
        assert_eq!(incoming.recv().await.unwrap(), b"after");
        incoming.send(b"reply").await.unwrap();
        assert_eq!(outgoing.recv().await.unwrap(), b"reply");
        assert_eq!(
            client.circuits.outbound.lock().await[&circuit_id].rekey.generation,
            REKEYS
        );
        let map = server.circuits.hop_backward_keys.lock().await;
        let hop = map.values().next().unwrap();
        assert_eq!(hop.rekey.generation, REKEYS);
        assert!(hop.pending.is_none(), "server never switched to the new keys");
    }

    #[tokio::test]
    async fn burst_acks_use_fewer_frames_than_data_packets() {
        use crate::stats::StatKey;
        let (client, server, outgoing, incoming) =
            connected_pair(tarnet_api::service::PortMode::ReliableOrdered).await;
        let id = outgoing.id;
        let baseline = server.stats.read(&StatKey::PacketsUp).total;
        for _ in 0..128 {
            outgoing.send(&[1; 64]).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..128 {
                assert_eq!(incoming.recv().await.unwrap(), vec![1; 64]);
            }
            loop {
                let stream = client
                    .endpoints
                    .streams
                    .lock()
                    .await
                    .iter()
                    .find(|(key, _)| key.circuit_id == id)
                    .unwrap()
                    .1
                    .clone();
                if stream.channel.lock().await.pending_retransmit().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let frames = server.stats.read(&StatKey::PacketsUp).total - baseline;
        assert!(
            frames < 96,
            "128 DATA packets generated {frames} reverse frames"
        );
    }

    fn roundtrip(len: usize, shuffle: bool) {
        let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let mut id = 0;
        let mut packets = packetize(&data, &mut id);
        assert!(packets.iter().all(|p| p.len() <= PACKET_MAX));
        if shuffle {
            packets.reverse();
        }
        let mut asm = FragmentAssembler::default();
        let mut out = None;
        for p in packets {
            out = match p[0] {
                KIND_DATA => Some(p[1..].to_vec()),
                KIND_FRAGMENT => asm.push(&p[1..]).or(out),
                _ => panic!(),
            };
        }
        assert_eq!(out.unwrap(), data);
    }

    #[test]
    fn message_boundaries_survive_small_cells() {
        roundtrip(10, false);
        roundtrip(PACKET_MAX - 1, false);
        roundtrip(PACKET_MAX, false);
        roundtrip(1000, false);
        roundtrip(64 * 1024, false);
    }

    #[test]
    fn fragments_reassemble_in_any_order() {
        roundtrip(5000, true);
    }

    #[test]
    fn lost_fragment_drops_only_its_message() {
        let mut id = 0;
        let a = packetize(&[1u8; 1000], &mut id);
        let b = packetize(&[2u8; 1000], &mut id);
        let mut asm = FragmentAssembler::default();
        for p in &a[1..] {
            assert!(asm.push(&p[1..]).is_none());
        }
        let mut out = None;
        for p in &b {
            out = asm.push(&p[1..]).or(out);
        }
        assert_eq!(out.unwrap(), vec![2u8; 1000]);
    }

    #[test]
    fn many_messages_waiting_on_lost_fragments_all_complete() {
        // Unordered reliable delivery under loss: dozens of messages each
        // missing one fragment until retransmission fills the holes.
        let mut id = 0;
        let messages: Vec<Vec<Vec<u8>>> =
            (0..64u8).map(|i| packetize(&[i; 1000], &mut id)).collect();
        let mut asm = FragmentAssembler::default();
        for m in &messages {
            for p in &m[1..] {
                assert!(asm.push(&p[1..]).is_none());
            }
        }
        for (i, m) in messages.iter().enumerate() {
            assert_eq!(asm.push(&m[0][1..]).unwrap(), vec![i as u8; 1000]);
        }
        assert_eq!(asm.bytes, 0);
    }
}
