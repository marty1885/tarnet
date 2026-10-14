//! End-to-end sequencing, acknowledgements, retransmission, and ordered EOF.
use super::*;

pub(super) struct StreamState {
    pub app_tx: mpsc::WeakSender<Vec<u8>>,
    pub channel: Mutex<Channel>,
    pub notify: tokio::sync::Notify,
    pub outbound: bool,
    remote_fin: std::sync::Mutex<Option<u32>>,
    remote_closed: std::sync::atomic::AtomicBool,
    /// Application messages arriving in several channel packets.
    fragments: std::sync::Mutex<FragmentAssembler>,
}

// Channel packet kinds. A packet is `kind(u8) || body`.
/// One whole application message.
const KIND_DATA: u8 = 0;
/// End of the sending direction (body empty).
const KIND_FIN: u8 = 1;
/// Part of an application message too large for one cell:
/// `msg_id(u16) || index(u16) || count(u16) || bytes`.
const KIND_FRAGMENT: u8 = 2;
const FRAGMENT_HEADER: usize = 1 + 6;
/// Channel packet bytes that fit one DATA cell after the channel sequence.
const PACKET_MAX: usize = CELL_PAYLOAD_MAX - 4;
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
        if body.len() < 6 {
            return None;
        }
        let msg_id = u16::from_be_bytes([body[0], body[1]]);
        let index = u16::from_be_bytes([body[2], body[3]]);
        let count = u16::from_be_bytes([body[4], body[5]]);
        let bytes = &body[6..];
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
        let partial = self.partials.entry(msg_id).or_insert_with(|| PartialMessage {
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
            stream.notify.notify_one();
        }
    }
}

/// Encrypt a fresh cell for every transmission, including retransmissions.
/// Sequence numbers belong to the end-to-end channel; crypto nonces never repeat.
async fn send_cell(
    circuits: &CircuitState,
    links: &Arc<Mutex<crate::peer_transport::LinkTable>>,
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
        super::circuit::seal_backward_cell(&hop.keys, n, key.circuit_id, &body)
    };
    let link = links
        .lock()
        .await
        .get(&key.from_peer)
        .cloned()
        .ok_or_else(|| Error::Protocol("stream link gone".into()))?;
    // Loss here is safe: reliable channels retain the plaintext until its ACK.
    link.send_message(&encoded).await
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
        let stream = Arc::new(StreamState {
            app_tx: app_tx.downgrade(),
            channel: Mutex::new(Channel::from_port_name(
                key.circuit_id,
                port,
                reliable,
                ordered,
            )),
            notify: tokio::sync::Notify::new(),
            outbound,
            remote_fin: std::sync::Mutex::new(None),
            remote_closed: std::sync::atomic::AtomicBool::new(false),
            fragments: Default::default(),
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
        let circuits = self.circuits.clone();
        let endpoints = self.endpoints.clone();
        let links = self.links.clone();
        tokio::spawn(async move {
            let mut pending = VecDeque::<Vec<u8>>::new();
            let mut next_msg_id: u16 = 0;
            let mut closing = false;
            let mut fin_sent = false;
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            'send: loop {
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
                let packet = {
                    let mut channel = stream.channel.lock().await;
                    if channel.is_dead() {
                        break;
                    }
                    // Half-close: our FIN only closes our sending direction.
                    // Keep receiving (and ACKing) until the peer also reaches EOF.
                    if fin_sent
                        && channel.pending_retransmit().is_empty()
                        && stream
                            .remote_closed
                            .load(std::sync::atomic::Ordering::Acquire)
                    {
                        break;
                    }
                    if channel.can_send() {
                        pending.pop_front().map(|payload| {
                            fin_sent |= payload[0] == KIND_FIN;
                            channel.prepare_send(payload).remove(0)
                        })
                    } else {
                        None
                    }
                };
                if let Some((sequence, payload)) = packet {
                    log::trace!("stream {:?}: send seq {}", key.circuit_id, sequence);
                    let mut data = sequence.to_be_bytes().to_vec();
                    data.extend_from_slice(&payload);
                    if send_cell(
                        &circuits,
                        &links,
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
                    continue;
                }
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
                    _ = tick.tick() => {
                        let due = stream.channel.lock().await.retransmit_due();
                        for (sequence, payload) in due {
                            log::trace!("stream {:?}: retransmit seq {}", key.circuit_id, sequence);
                            let mut data = sequence.to_be_bytes().to_vec();
                            data.extend_from_slice(&payload);
                            if send_cell(&circuits, &links, key, outbound, RelayCellCommand::Data, &data).await.is_err() { break 'send; }
                        }
                    }
                }
            }
            // Reliable FIN has been acknowledged, or the circuit is unusable.
            let _ = send_cell(
                &circuits,
                &links,
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
        if data.len() < 5
            || data[4] > KIND_FRAGMENT
            || (data[4] == KIND_FIN && data.len() != 5)
            || (data[4] == KIND_FRAGMENT && data.len() < 4 + FRAGMENT_HEADER)
        {
            return Err(Error::Wire("invalid stream DATA".into()));
        }
        let stream = self.endpoints.streams.lock().await.get(&key).cloned();
        let Some(stream) = stream else {
            return Ok(());
        };
        let sequence = u32::from_be_bytes(data[..4].try_into().unwrap());
        let (ready, ack) = {
            let mut channel = stream.channel.lock().await;
            let ready = channel.receive_data(sequence, data[4..].to_vec());
            (ready, channel.generate_ack())
        };
        if data[4] == KIND_FIN {
            *stream.remote_fin.lock().unwrap() = Some(sequence);
        }
        let messages: Vec<Vec<u8>> = ready
            .into_iter()
            .filter_map(|payload| match payload[0] {
                KIND_DATA => Some(payload[1..].to_vec()),
                KIND_FRAGMENT => stream.fragments.lock().unwrap().push(&payload[1..]),
                _ => None,
            })
            .collect();
        // Application backpressure must not hold a node-wide map lock.
        for message in messages {
            let tx = self.endpoints.data_txs.lock().await.get(&key).cloned();
            if let Some(tx) = tx {
                let _ = tx.send(message).await;
            }
        }
        if let Some((ack_seq, selective_acks)) = ack {
            let data = ChannelAckMsg {
                channel_id: 0,
                ack_seq,
                selective_acks,
            }
            .to_bytes();
            send_cell(
                &self.circuits,
                &self.links,
                key,
                stream.outbound,
                RelayCellCommand::StreamAck,
                &data,
            )
            .await?;
            let fin = *stream.remote_fin.lock().unwrap();
            if fin.is_some_and(|seq| ack_seq.wrapping_sub(seq) as i32 > 0) {
                self.endpoints.data_txs.lock().await.remove(&key);
                stream
                    .remote_closed
                    .store(true, std::sync::atomic::Ordering::Release);
                stream.notify.notify_one();
            }
        }
        Ok(())
    }

    pub(super) async fn handle_stream_ack(&self, key: CircuitKey, data: &[u8]) -> Result<()> {
        let ack = ChannelAckMsg::from_bytes(data)?;
        if ack.selective_acks.len() > 32 {
            return Err(Error::Wire("too many stream ACKs".into()));
        }
        let stream = self.endpoints.streams.lock().await.get(&key).cloned();
        if let Some(stream) = stream {
            log::trace!(
                "stream {:?}: ack {} sack {:?}",
                key.circuit_id,
                ack.ack_seq,
                ack.selective_acks
            );
            stream
                .channel
                .lock()
                .await
                .process_ack(ack.ack_seq, &ack.selective_acks);
            stream.notify.notify_one();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
