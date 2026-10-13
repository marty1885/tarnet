//! End-to-end sequencing, acknowledgements, retransmission, and ordered EOF.
use super::*;

pub(super) struct StreamState {
    pub app_tx: mpsc::WeakSender<Vec<u8>>,
    pub channel: Mutex<Channel>,
    pub notify: tokio::sync::Notify,
    pub outbound: bool,
    remote_fin: std::sync::Mutex<Option<u32>>,
    remote_closed: std::sync::atomic::AtomicBool,
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
        let (enc, digest, domain, nonce) = {
            let mut map = circuits.hop_backward_keys.lock().await;
            let entry = map
                .get_mut(&(key.circuit_id, key.from_peer))
                .ok_or_else(|| Error::Protocol("stream backward keys gone".into()))?;
            let nonce = entry.3;
            entry.3 = entry
                .3
                .checked_add(1)
                .ok_or_else(|| Error::Crypto("backward nonce exhausted".into()))?;
            (entry.0, entry.1, entry.2, nonce)
        };
        super::circuit::encrypt_backward_cell(
            enc,
            digest,
            domain,
            nonce,
            key.circuit_id,
            command,
            data,
        )
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
        });
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
                            fin_sent |= payload[0] == 1;
                            channel.prepare_send(payload).remove(0)
                        })
                    } else {
                        None
                    }
                };
                if let Some((sequence, payload)) = packet {
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
                                for chunk in data.chunks(CELL_PAYLOAD_MAX - 5) {
                                    let mut payload = Vec::with_capacity(chunk.len() + 1);
                                    payload.push(0);
                                    payload.extend_from_slice(chunk);
                                    pending.push_back(payload);
                                }
                            }
                            None => {
                                closing = true;
                                if reliable { pending.push_back(vec![1]); }
                                else { break; }
                            }
                        }
                    }
                    _ = stream.notify.notified() => {}
                    _ = tick.tick() => {
                        let due = stream.channel.lock().await.retransmit_due();
                        for (sequence, payload) in due {
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
        if data.len() < 5 || data[4] > 1 || (data[4] == 1 && data.len() != 5) {
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
        if data[4] == 1 {
            *stream.remote_fin.lock().unwrap() = Some(sequence);
        }
        // Application backpressure must not hold a node-wide map lock.
        for payload in ready {
            if payload[0] == 0 {
                let tx = self.endpoints.data_txs.lock().await.get(&key).cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(payload[1..].to_vec()).await;
                }
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
