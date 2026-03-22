use super::*;

/// WebRTC signaling channel message tags.
const TAG_OFFER: u8 = 0x01;
const TAG_ANSWER: u8 = 0x02;
const TAG_ICE_CANDIDATE: u8 = 0x03;

/// Derive the 32-byte signaling channel port hash from a hello record's secret
/// using blake3 KDF with domain separation. No string intermediary.
fn signaling_port_hash(secret: &[u8; 16]) -> [u8; 32] {
    blake3::derive_key("tarnet webrtc signaling port", secret)
}

impl Node {
    // ── WebRTC ──────────────────────────────────────────────────

    /// Enable WebRTC transport with the given STUN servers.
    /// Must be called before `run()`.
    /// Enable mainline DHT bootstrap announcing.
    /// The node will periodically announce its TCP port on the mainline DHT
    /// so that `--bootstrap mainline:<peer-id-hex>` can find it.
    /// Must be called before `run()`. The TCP listen port must be provided.
    #[cfg(feature = "mainline-bootstrap")]
    pub fn enable_mainline(&mut self, port: u16) {
        self.mainline_enabled = true;
        let peer_id = self.peer_id();
        let addr = bootstrap::format_mainline_addr(&peer_id);
        log::info!("Mainline DHT bootstrap enabled");
        log::info!("Other nodes can bootstrap with: --bootstrap {}", addr);

        // Spawn periodic announce task
        tokio::spawn(async move {
            // Initial delay to let the network settle
            tokio::time::sleep(Duration::from_secs(5)).await;
            loop {
                match bootstrap::MainlineDht::new() {
                    Ok(dht) => {
                        if let Err(e) = dht.announce(&peer_id, port) {
                            log::warn!("Mainline DHT announce failed: {}", e);
                        } else {
                            log::debug!("Mainline DHT announce succeeded on port {}", port);
                        }
                    }
                    Err(e) => {
                        log::warn!("Mainline DHT client init failed: {}", e);
                    }
                }
                // Re-announce every 20 minutes (mainline announcements expire ~30 min)
                tokio::time::sleep(Duration::from_secs(1200)).await;
            }
        });
    }

    pub fn enable_webrtc(&mut self, stun_servers: Vec<String>) -> Result<()> {
        let connector = WebRtcConnector::new(stun_servers)?;
        self.webrtc_connector = Some(Arc::new(connector));
        Ok(())
    }

    /// Start the WebRTC signaling listener on a channel port derived from
    /// our signaling secret. Only peers who have received our hello record
    /// can compute the port name.
    pub(super) async fn start_webrtc_signaling_listener(&self) {
        let connector = match self.webrtc_connector.as_ref() {
            Some(c) => c.clone(),
            None => return,
        };

        let port_hash = signaling_port_hash(&self.signaling_secret);
        self.register_webrtc_port_listener(port_hash, connector).await;
    }

    async fn register_webrtc_port_listener(&self, port_hash: [u8; 32], connector: Arc<WebRtcConnector>) {

        let (listener_tx, mut listener_rx) = mpsc::unbounded_channel::<(PeerId, u32, mpsc::UnboundedReceiver<Vec<u8>>)>();
        self.channel_port_listeners.lock().await.insert(port_hash, listener_tx);

        let event_tx = self.event_tx.clone();
        let identity = self.identity.clone();
        let channel_data_handlers = self.channel_data_handlers.clone();
        let channels = self.channels.clone();
        let tunnel_table = self.tunnel_table.clone();
        let links = self.links.clone();
        let routing_table = self.routing_table.clone();
        let peer_id = self.peer_id();

        log::info!("WebRTC signaling listener registered");

        tokio::spawn(async move {
            while let Some((remote_peer, channel_id, mut data_rx)) = listener_rx.recv().await {
                let connector = connector.clone();
                let event_tx = event_tx.clone();
                let identity = identity.clone();
                let channel_data_handlers = channel_data_handlers.clone();
                let channels = channels.clone();
                let tunnel_table = tunnel_table.clone();
                let links = links.clone();
                let routing_table = routing_table.clone();

                log::debug!("WebRTC signaling session from {:?} on channel {}", remote_peer, channel_id);

                tokio::spawn(async move {
                    // Read messages from the channel
                    while let Some(msg) = data_rx.recv().await {
                        if msg.is_empty() {
                            continue;
                        }
                        let tag = msg[0];
                        let payload = &msg[1..];
                        let payload_str = match std::str::from_utf8(payload) {
                            Ok(s) => s,
                            Err(_) => {
                                log::warn!("WebRTC signaling: invalid UTF-8 from {:?}", remote_peer);
                                continue;
                            }
                        };

                        match tag {
                            TAG_OFFER => {
                                log::debug!("WebRTC: received offer from {:?}", remote_peer);
                                let (sdp_answer, transport_rx, mut ice_rx) = match connector.handle_offer(remote_peer, payload_str).await {
                                    Ok(v) => v,
                                    Err(e) => {
                                        log::warn!("WebRTC handle_offer failed: {}", e);
                                        break;
                                    }
                                };

                                // Send answer back on the same channel
                                let mut answer_msg = Vec::with_capacity(1 + sdp_answer.len());
                                answer_msg.push(TAG_ANSWER);
                                answer_msg.extend_from_slice(sdp_answer.as_bytes());
                                if let Err(e) = send_on_channel(
                                    &channels, &tunnel_table, &links, &routing_table,
                                    peer_id, channel_id, &answer_msg,
                                ).await {
                                    log::warn!("WebRTC: failed to send answer: {}", e);
                                    break;
                                }

                                // Spawn ICE trickle sender
                                let channels2 = channels.clone();
                                let tunnel_table2 = tunnel_table.clone();
                                let links2 = links.clone();
                                let routing_table2 = routing_table.clone();
                                tokio::spawn(async move {
                                    while let Some(candidate) = ice_rx.recv().await {
                                        let mut ice_msg = Vec::with_capacity(1 + candidate.len());
                                        ice_msg.push(TAG_ICE_CANDIDATE);
                                        ice_msg.extend_from_slice(candidate.as_bytes());
                                        if send_on_channel(
                                            &channels2, &tunnel_table2, &links2, &routing_table2,
                                            peer_id, channel_id, &ice_msg,
                                        ).await.is_err() {
                                            break;
                                        }
                                    }
                                });

                                // Wait for transport and do PeerLink handshake
                                let event_tx = event_tx.clone();
                                let identity = identity.clone();
                                let channel_data_handlers = channel_data_handlers.clone();
                                let channels3 = channels.clone();
                                tokio::spawn(async move {
                                    match transport_rx.await {
                                        Ok(transport) => {
                                            let transport: Box<dyn crate::transport::Transport> = Box::new(transport);
                                            match crate::link::PeerLink::responder(transport, &identity).await {
                                                Ok(link) => {
                                                    let link = Arc::new(link);
                                                    log::info!(
                                                        "WebRTC link established (responder) to {:?}",
                                                        link.remote_peer()
                                                    );
                                                    let _ = event_tx
                                                        .send(NodeEvent::LinkUp(link.remote_peer(), link))
                                                        .await;
                                                }
                                                Err(e) => {
                                                    log::warn!("WebRTC PeerLink handshake failed (responder): {}", e);
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            log::warn!("WebRTC connection from {:?} was cancelled", remote_peer);
                                        }
                                    }
                                    // Clean up channel handler
                                    channel_data_handlers.lock().await.remove(&channel_id);
                                    channels3.lock().await.remove(&channel_id);
                                });
                            }
                            TAG_ICE_CANDIDATE => {
                                if let Err(e) = connector.handle_ice_candidate(remote_peer, payload_str).await {
                                    log::debug!("WebRTC ICE candidate error: {}", e);
                                }
                            }
                            _ => {
                                log::debug!("WebRTC signaling: unknown tag {} from {:?}", tag, remote_peer);
                            }
                        }
                    }
                });
            }
        });
    }

    /// Compute the WebRTC signaling port hash for a peer based on their hello record.
    fn webrtc_port_hash_for_peer(hello: &HelloRecord) -> [u8; 32] {
        signaling_port_hash(&hello.signaling_secret)
    }

    /// Initiate a WebRTC connection to a remote peer via channel-based signaling.
    /// The peer must be reachable via overlay routing (tunnel) for SDP exchange.
    pub async fn connect_webrtc(&self, peer_id: PeerId) -> Result<()> {
        let connector = self
            .webrtc_connector
            .as_ref()
            .ok_or_else(|| Error::Protocol("WebRTC not enabled".into()))?;

        // Look up peer's hello record to derive the signaling port
        let hello = self.lookup_hello(&peer_id).await
            .ok_or_else(|| Error::Protocol("no hello record for WebRTC target".into()))?;
        let port_hash = Self::webrtc_port_hash_for_peer(&hello);

        // Ensure we have a tunnel to the peer
        let tunnel_rx = self.create_tunnel(peer_id).await?;
        let _ = tunnel_rx.await.map_err(|_| Error::Protocol("tunnel setup cancelled".into()))?;

        // Open a signaling channel
        let (channel_id, mut data_rx) = self.channel_open_with_handler_port(
            &peer_id, port_hash, true, true,
        ).await?;

        let (sdp_offer, transport_rx, mut ice_rx) = connector.initiate(peer_id).await?;

        // Send offer on the channel
        let mut offer_msg = Vec::with_capacity(1 + sdp_offer.len());
        offer_msg.push(TAG_OFFER);
        offer_msg.extend_from_slice(sdp_offer.as_bytes());
        self.channel_send(channel_id, &offer_msg).await?;

        // Spawn ICE trickle sender (our candidates → channel)
        let channels = self.channels.clone();
        let tunnel_table = self.tunnel_table.clone();
        let links = self.links.clone();
        let routing_table = self.routing_table.clone();
        let my_peer_id = self.peer_id();
        tokio::spawn(async move {
            while let Some(candidate) = ice_rx.recv().await {
                let mut ice_msg = Vec::with_capacity(1 + candidate.len());
                ice_msg.push(TAG_ICE_CANDIDATE);
                ice_msg.extend_from_slice(candidate.as_bytes());
                if send_on_channel(
                    &channels, &tunnel_table, &links, &routing_table,
                    my_peer_id, channel_id, &ice_msg,
                ).await.is_err() {
                    break;
                }
            }
        });

        // Spawn task to read answer and ICE candidates from the channel
        let connector = connector.clone();
        let channel_data_handlers = self.channel_data_handlers.clone();
        let channels2 = self.channels.clone();
        tokio::spawn(async move {
            while let Some(msg) = data_rx.recv().await {
                if msg.is_empty() {
                    continue;
                }
                let tag = msg[0];
                let payload = &msg[1..];
                let payload_str = match std::str::from_utf8(payload) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                match tag {
                    TAG_ANSWER => {
                        log::debug!("WebRTC: received answer from {:?}", peer_id);
                        if let Err(e) = connector.handle_answer(peer_id, payload_str).await {
                            log::warn!("WebRTC handle_answer failed: {}", e);
                            break;
                        }
                    }
                    TAG_ICE_CANDIDATE => {
                        if let Err(e) = connector.handle_ice_candidate(peer_id, payload_str).await {
                            log::debug!("WebRTC ICE candidate error: {}", e);
                        }
                    }
                    _ => {}
                }
            }
        });

        // Wait for transport and do PeerLink handshake
        let event_tx2 = self.event_tx.clone();
        let identity2 = self.identity.clone();
        tokio::spawn(async move {
            match transport_rx.await {
                Ok(transport) => {
                    let transport: Box<dyn crate::transport::Transport> = Box::new(transport);
                    match crate::link::PeerLink::initiator(transport, &identity2, Some(peer_id)).await {
                        Ok(link) => {
                            let link = Arc::new(link);
                            log::info!(
                                "WebRTC link established (initiator) to {:?}",
                                link.remote_peer()
                            );
                            let _ = event_tx2
                                .send(NodeEvent::LinkUp(link.remote_peer(), link))
                                .await;
                        }
                        Err(e) => {
                            log::warn!("WebRTC PeerLink handshake failed (initiator): {}", e);
                        }
                    }
                }
                Err(_) => {
                    log::warn!("WebRTC connection to {:?} was cancelled", peer_id);
                }
            }
            // Clean up
            channel_data_handlers.lock().await.remove(&channel_id);
            channels2.lock().await.remove(&channel_id);
        });

        Ok(())
    }
}

/// Send data on a channel using the tunnel, without holding a &Node reference.
/// Used from spawned tasks that can't borrow the node.
async fn send_on_channel(
    channels: &Arc<Mutex<HashMap<u32, (PeerId, Channel)>>>,
    tunnel_table: &Arc<Mutex<TunnelTable>>,
    links: &Arc<Mutex<LinkTable>>,
    routing_table: &Arc<Mutex<RoutingTable>>,
    our_peer_id: PeerId,
    channel_id: u32,
    data: &[u8],
) -> Result<()> {
    let (dest, sends) = {
        let mut chs = channels.lock().await;
        let (remote, ch) = chs
            .get_mut(&channel_id)
            .ok_or_else(|| Error::Protocol(format!("no channel {}", channel_id)))?;
        let dest = *remote;
        let sends = ch.prepare_send(data.to_vec());
        (dest, sends)
    };
    for (seq, payload) in sends {
        let msg = ChannelDataMsg {
            channel_id,
            sequence: seq,
            data: payload,
        };
        let inner = msg.to_wire().encode();

        // Encrypt via tunnel
        let encrypted = {
            let tt = tunnel_table.lock().await;
            let tunnel = tt
                .get(&dest)
                .ok_or_else(|| Error::Protocol(format!("no tunnel to {:?}", dest)))?;
            tunnel.encrypt(&inner)
        };

        let enc_msg = EncryptedDataMsg {
            origin: our_peer_id,
            destination: dest,
            ttl: 64,
            data: encrypted,
        };
        let encoded = enc_msg.to_wire_encrypted().encode();

        // Route
        {
            let lks = links.lock().await;
            if let Some(link) = lks.get(&dest) {
                link.send_message(&encoded).await?;
                continue;
            }
        }
        let next_hop = {
            let table = routing_table.lock().await;
            table
                .lookup(&dest)
                .map(|r| r.next_hop)
                .ok_or(Error::NotFound)?
        };
        let lks = links.lock().await;
        if let Some(link) = lks.get(&next_hop) {
            link.send_message(&encoded).await?;
        }
    }
    Ok(())
}
