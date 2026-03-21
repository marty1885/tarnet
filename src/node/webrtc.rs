use super::*;

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
        let identity = self.identity.clone();
        let links = self.links.clone();
        let routing_table = self.routing_table.clone();

        let ice_callback: crate::transport::webrtc::IceCandidateCallback =
            Arc::new(move |peer_id, candidate_str| {
                let identity = identity.clone();
                let links = links.clone();
                let routing_table = routing_table.clone();
                Box::pin(async move {
                    let msg = WebRtcIceCandidateMsg {
                        sender: identity.peer_id(),
                        payload: candidate_str,
                    };
                    let inner = msg.to_wire_ice_candidate().encode();
                    let data_msg = DataMsg {
                        origin: identity.peer_id(),
                        destination: peer_id,
                        ttl: 64,
                        data: inner,
                    };
                    let encoded = data_msg.to_wire().encode();

                    // Try direct link first, then routing table
                    let sent = {
                        let links = links.lock().await;
                        if let Some(link) = links.get(&peer_id) {
                            let _ = link.send_message(&encoded).await;
                            true
                        } else {
                            false
                        }
                    };
                    if !sent {
                        let next_hop = {
                            let table = routing_table.lock().await;
                            table.lookup(&peer_id).map(|r| r.next_hop)
                        };
                        if let Some(hop) = next_hop {
                            let links = links.lock().await;
                            if let Some(link) = links.get(&hop) {
                                let _ = link.send_message(&encoded).await;
                            }
                        }
                    }
                })
            });

        let connector = WebRtcConnector::new(stun_servers, ice_callback)?;
        self.webrtc_connector = Some(Arc::new(connector));
        Ok(())
    }

    /// Initiate a WebRTC connection to a remote peer via overlay signaling.
    /// The peer must be reachable via overlay routing for SDP exchange.
    pub async fn connect_webrtc(&self, peer_id: PeerId) -> Result<()> {
        let connector = self
            .webrtc_connector
            .as_ref()
            .ok_or_else(|| Error::Protocol("WebRTC not enabled".into()))?;

        let (sdp_offer, transport_rx) = connector.initiate(peer_id).await?;

        // Send offer via overlay routing
        let offer_msg = WebRtcOfferMsg {
            sender: self.peer_id(),
            payload: sdp_offer,
        };
        let inner = offer_msg.to_wire_offer().encode();
        let data_msg = DataMsg {
            origin: self.peer_id(),
            destination: peer_id,
            ttl: 64,
            data: inner,
        };
        self.route_message(&peer_id, &data_msg.to_wire().encode())
            .await?;

        // Wait for the data channel to open (answer will arrive via handle_webrtc_answer)
        let event_tx = self.event_tx.clone();
        let identity = self.identity.clone();
        tokio::spawn(async move {
            match transport_rx.await {
                Ok(transport) => {
                    let transport: Box<dyn crate::transport::Transport> = Box::new(transport);
                    match crate::link::PeerLink::initiator(transport, &identity, Some(peer_id)).await {
                        Ok(link) => {
                            let link = Arc::new(link);
                            log::info!(
                                "WebRTC link established (initiator) to {:?}",
                                link.remote_peer()
                            );
                            let _ = event_tx
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
        });

        Ok(())
    }

    pub(super) async fn handle_webrtc_offer(&self, _origin: PeerId, payload: &[u8]) -> Result<()> {
        let offer = WebRtcOfferMsg::from_bytes(payload)?;
        let connector = self
            .webrtc_connector
            .as_ref()
            .ok_or_else(|| Error::Protocol("WebRTC not enabled".into()))?;

        let (sdp_answer, transport_rx) = connector.handle_offer(offer.sender, &offer.payload).await?;

        // Send answer back via overlay routing
        let answer_msg = WebRtcAnswerMsg {
            sender: self.peer_id(),
            payload: sdp_answer,
        };
        let inner = answer_msg.to_wire_answer().encode();
        let data_msg = DataMsg {
            origin: self.peer_id(),
            destination: offer.sender,
            ttl: 64,
            data: inner,
        };
        self.route_message(&offer.sender, &data_msg.to_wire().encode())
            .await?;

        // Wait for the data channel to open, then do PeerLink handshake as responder
        let event_tx = self.event_tx.clone();
        let identity = self.identity.clone();
        let remote = offer.sender;
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
                    log::warn!("WebRTC connection from {:?} was cancelled", remote);
                }
            }
        });

        Ok(())
    }

    pub(super) async fn handle_webrtc_answer(&self, _origin: PeerId, payload: &[u8]) -> Result<()> {
        let answer = WebRtcAnswerMsg::from_bytes(payload)?;
        let connector = self
            .webrtc_connector
            .as_ref()
            .ok_or_else(|| Error::Protocol("WebRTC not enabled".into()))?;

        connector
            .handle_answer(answer.sender, &answer.payload)
            .await?;
        log::debug!("WebRTC answer processed from {:?}", answer.sender);
        Ok(())
    }

    pub(super) async fn handle_webrtc_ice_candidate(&self, _origin: PeerId, payload: &[u8]) -> Result<()> {
        let ice = WebRtcIceCandidateMsg::from_bytes(payload)?;
        let connector = self
            .webrtc_connector
            .as_ref()
            .ok_or_else(|| Error::Protocol("WebRTC not enabled".into()))?;

        connector
            .handle_ice_candidate(ice.sender, &ice.payload)
            .await?;
        log::debug!("WebRTC ICE candidate processed from {:?}", ice.sender);
        Ok(())
    }
}
