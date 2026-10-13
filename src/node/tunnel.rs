use super::*;

impl Node {
    /// Handle incoming TunnelKeyExchange — routed to us as destination.
    pub(super) async fn handle_tunnel_key_exchange(
        &self,
        _from: PeerId,
        payload: &[u8],
    ) -> Result<()> {
        let ke = TunnelKeyExchangeMsg::from_bytes(payload)?;

        // Authenticate the offer before doing any other work (so a forged
        // message can't even pollute the replay cache). The signature must bind
        // the ephemeral KEM key to the claimed initiator identity and to us as
        // the intended responder; otherwise an on-path relay could substitute
        // its own ephemeral key and MITM the end-to-end tunnel.
        let Ok(signer_algo) = tarnet_api::types::SigningAlgo::from_u8(ke.signer_algo) else {
            log::warn!(
                "TunnelKeyExchange from {:?}: unknown signer algo {}, rejecting",
                ke.initiator_peer_id,
                ke.signer_algo
            );
            return Ok(());
        };
        if !crate::identity::verify_with_pubkey(
            signer_algo,
            &ke.signer_pubkey,
            &ke.initiator_peer_id,
            &ke.signed_bytes(&self.peer_id()),
            &ke.signature,
        ) {
            log::warn!(
                "TunnelKeyExchange from {:?}: signature verification failed, rejecting",
                ke.initiator_peer_id
            );
            return Ok(());
        }

        // Check timestamp drift
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let drift = if now > ke.timestamp {
            now - ke.timestamp
        } else {
            ke.timestamp - now
        };
        if drift > KEY_EXCHANGE_MAX_DRIFT {
            log::warn!(
                "TunnelKeyExchange from {:?}: timestamp drift {}s, rejecting",
                ke.initiator_peer_id,
                drift
            );
            return Ok(());
        }

        // Check nonce replay
        {
            let nonces = self.seen_nonces.lock().await;
            if nonces.iter().any(|(n, _)| *n == ke.nonce) {
                log::warn!(
                    "TunnelKeyExchange from {:?}: replayed nonce, rejecting",
                    ke.initiator_peer_id
                );
                return Ok(());
            }
        }

        // Record nonce as seen
        self.seen_nonces
            .lock()
            .await
            .push_back((ke.nonce, Instant::now()));

        // Complete key exchange using KEM
        let offer_algo = tarnet_api::types::KemAlgo::from_u8(ke.kem_algo)
            .map_err(|e| Error::Wire(format!("TunnelKeyExchange unknown KEM algo: {}", e)))?;
        let (shared_bytes, reply_ciphertext) = kex_accept(offer_algo, &ke.ephemeral_pubkey)?;

        let tunnel = Tunnel::new(ke.initiator_peer_id, &shared_bytes, false);
        self.tunnel_table.lock().await.add(tunnel);

        // Generate our own nonce for the response
        let mut rng = rand::rngs::OsRng;
        let mut resp_nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut resp_nonce);

        let mut response = TunnelKeyResponseMsg {
            kem_algo: ke.kem_algo,
            ciphertext: reply_ciphertext,
            responder_peer_id: self.peer_id(),
            nonce: resp_nonce,
            initiator_nonce: ke.nonce,
            timestamp: now,
            signer_algo: self.identity.identity.signing_algo() as u8,
            signer_pubkey: self.identity.identity.signing.signing_pubkey_bytes(),
            signature: Vec::new(),
        };
        // Authenticate the response: bind the KEM ciphertext to our static
        // identity and to the initiator's *original* ephemeral key (the one we
        // received). The initiator verifies against the key it actually sent, so
        // a relay that swapped the ephemeral key is detected.
        response.signature =
            self.identity
                .sign(&response.signed_bytes(&ke.initiator_peer_id, &ke.ephemeral_pubkey));

        // Send response back via routed DataMsg (not EncryptedData since tunnel isn't established on initiator yet)
        let msg = DataMsg {
            origin: self.peer_id(),
            destination: ke.initiator_peer_id,
            ttl: 64,
            data: response.to_wire().encode(),
        };
        self.route_message(&ke.initiator_peer_id, &msg.to_wire().encode())
            .await?;

        log::info!(
            "Tunnel established (responder) with {:?}",
            ke.initiator_peer_id
        );
        let _ = self.tunnel_notify_tx.send(ke.initiator_peer_id).await;
        Ok(())
    }

    /// Handle incoming TunnelKeyResponse — completes a key exchange we initiated.
    pub(super) async fn handle_tunnel_key_response(
        &self,
        _from: PeerId,
        payload: &[u8],
    ) -> Result<()> {
        let kr = TunnelKeyResponseMsg::from_bytes(payload)?;

        // Authenticate and complete the response before consuming the pending
        // exchange.  The nonce is visible in the routed handshake envelope, so
        // an on-path peer can race a forged response; removing first would let
        // that invalid response cancel the legitimate exchange.
        let mut pending = self.pending_key_exchanges.lock().await;
        if let Some((kex, _, dest, _created)) = pending.get(&kr.initiator_nonce) {
            let dest = *dest;
            // Verify the response is from the expected peer
            if kr.responder_peer_id != dest {
                log::warn!(
                    "TunnelKeyResponse responder mismatch: expected {:?}, got {:?}",
                    dest,
                    kr.responder_peer_id
                );
                return Ok(());
            }

            // Authenticate the responder: the signature must bind the KEM
            // ciphertext to the responder's static identity (which must hash to
            // `dest`) and to the ephemeral key WE actually sent. A relay that
            // substituted a different ephemeral key signed over that key and
            // fails this check, so the MITM cannot complete the handshake.
            let Ok(signer_algo) = tarnet_api::types::SigningAlgo::from_u8(kr.signer_algo) else {
                log::warn!(
                    "TunnelKeyResponse from {:?}: unknown signer algo {}, rejecting",
                    dest,
                    kr.signer_algo
                );
                return Ok(());
            };
            if !crate::identity::verify_with_pubkey(
                signer_algo,
                &kr.signer_pubkey,
                &dest,
                &kr.signed_bytes(&self.peer_id(), &kex.pubkey_bytes()),
                &kr.signature,
            ) {
                log::warn!(
                    "TunnelKeyResponse from {:?}: signature verification failed, rejecting",
                    dest
                );
                return Ok(());
            }

            let shared_bytes = kex.complete(&kr.ciphertext)?;

            // Authentication and decapsulation both succeeded.  Only now is it
            // safe to consume the one-shot state and notifier.
            let (_, notifier, _, _) = pending
                .remove(&kr.initiator_nonce)
                .expect("pending tunnel exchange disappeared while locked");
            drop(pending);

            let tunnel = Tunnel::new(dest, &shared_bytes, true);
            self.tunnel_table.lock().await.add(tunnel);

            log::info!("Tunnel established (initiator) with {:?}", dest);
            let _ = notifier.send(dest);
        } else {
            log::debug!("TunnelKeyResponse with unknown initiator_nonce, ignoring");
        }
        Ok(())
    }

    /// Handle incoming EncryptedData — tunnel-encrypted payload routed to us.
    pub(super) async fn handle_encrypted_data(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut msg = EncryptedDataMsg::from_bytes(payload)?;

        if msg.destination == self.peer_id() {
            // We are the destination — decrypt via tunnel
            let mut tt = self.tunnel_table.lock().await;
            if let Some(tunnel) = tt.get_mut(&msg.origin) {
                let plaintext = tunnel.decrypt(&msg.data)?;
                let remote = tunnel.remote_peer;
                drop(tt);

                // Process the decrypted message (channel-level)
                match WireMessage::decode(&plaintext) {
                    Ok(inner_msg) => {
                        self.handle_channel_message(remote, inner_msg).await?;
                    }
                    Err(_) => {
                        // Raw tunnel data (no wire framing) — deliver to app
                        let _ = self.app_tx.send((remote, plaintext)).await;
                    }
                }
            } else {
                log::warn!(
                    "EncryptedData from {:?}: no tunnel for origin {:?}",
                    from,
                    msg.origin
                );
            }
            return Ok(());
        }

        // Forward to next hop (same logic as handle_data)
        if msg.ttl == 0 {
            log::debug!(
                "Dropping encrypted data with expired TTL for {:?}",
                msg.destination
            );
            return Ok(());
        }
        msg.ttl -= 1;

        let next_hop = {
            let table = self.routing_table.lock().await;
            table
                .lookup(&msg.destination)
                .map(|r| r.next_hop)
                .ok_or(Error::NotFound)?
        };
        self.send_to_peer(&next_hop, &msg.to_wire_encrypted().encode())
            .await
    }

    async fn handle_channel_message(&self, from: PeerId, msg: WireMessage) -> Result<()> {
        let mut channels = self.channel_state.channels.lock().await;
        match msg.msg_type {
            MessageType::ChannelOpen => {
                let open = ChannelOpenMsg::from_bytes(&msg.payload)?;
                if let Some((owner, _)) = channels.get(&open.channel_id) {
                    log::warn!(
                        "Rejecting channel {} from {:?}: already owned by {:?}",
                        open.channel_id,
                        from,
                        owner
                    );
                    return Ok(());
                }
                let ch = Channel::new(open.channel_id, open.port, open.reliable, open.ordered);
                channels.insert(open.channel_id, (from, ch));
                log::debug!("Channel {} opened from {:?}", open.channel_id, from);

                // Check if a port listener is registered for this port
                let listeners = self.channel_state.port_listeners.lock().await;
                if let Some(listener_tx) = listeners.get(&open.port) {
                    let (data_tx, data_rx) = mpsc::unbounded_channel();
                    self.channel_state
                        .data_handlers
                        .lock()
                        .await
                        .insert(open.channel_id, data_tx);
                    let _ = listener_tx.send((from, open.channel_id, data_rx));
                }
            }
            MessageType::ChannelData => {
                let data = ChannelDataMsg::from_bytes(&msg.payload)?;
                if let Some((owner, ch)) = channels.get_mut(&data.channel_id) {
                    if *owner != from {
                        log::warn!(
                            "Rejecting channel data for {} from non-owner {:?}",
                            data.channel_id,
                            from
                        );
                        return Ok(());
                    }
                    let delivered = ch.receive_data(data.sequence, data.data);

                    // Check if this channel has a data handler
                    let handlers = self.channel_state.data_handlers.lock().await;
                    if let Some(handler_tx) = handlers.get(&data.channel_id) {
                        for payload in delivered {
                            let _ = handler_tx.send(payload);
                        }
                        // Generate ACK, collect data, release lock, then send
                        let ack_bytes = ch.generate_ack().map(|(ack_seq, selective)| {
                            ChannelAckMsg {
                                channel_id: data.channel_id,
                                ack_seq,
                                selective_acks: selective,
                            }
                            .to_wire()
                            .encode()
                        });
                        drop(handlers);
                        drop(channels);
                        if let Some(inner) = ack_bytes {
                            let _ = self.send_tunnel_data(&from, &inner).await;
                        }
                        return Ok(());
                    }
                    drop(handlers);

                    for payload in delivered {
                        let _ = self.app_tx.send((from, payload)).await;
                    }
                    // Generate ACK, collect data, release lock, then send
                    let ack_bytes = ch.generate_ack().map(|(ack_seq, selective)| {
                        ChannelAckMsg {
                            channel_id: data.channel_id,
                            ack_seq,
                            selective_acks: selective,
                        }
                        .to_wire()
                        .encode()
                    });
                    drop(channels);
                    if let Some(inner) = ack_bytes {
                        let _ = self.send_tunnel_data(&from, &inner).await;
                    }
                    return Ok(());
                }
            }
            MessageType::ChannelAck => {
                let ack = ChannelAckMsg::from_bytes(&msg.payload)?;
                if let Some((owner, ch)) = channels.get_mut(&ack.channel_id) {
                    if *owner != from {
                        log::warn!(
                            "Rejecting channel ACK for {} from non-owner {:?}",
                            ack.channel_id,
                            from
                        );
                        return Ok(());
                    }
                    ch.process_ack(ack.ack_seq, &ack.selective_acks);
                }
            }
            MessageType::ChannelClose => {
                let close = ChannelCloseMsg::from_bytes(&msg.payload)?;
                if !channels
                    .get(&close.channel_id)
                    .is_some_and(|(owner, _)| *owner == from)
                {
                    log::warn!(
                        "Rejecting channel close for {} from non-owner {:?}",
                        close.channel_id,
                        from
                    );
                    return Ok(());
                }
                channels.remove(&close.channel_id);
                self.channel_state
                    .data_handlers
                    .lock()
                    .await
                    .remove(&close.channel_id);
                log::debug!("Channel {} closed by {:?}", close.channel_id, from);
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) async fn handle_data(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut data = DataMsg::from_bytes(payload)?;

        if data.destination == self.peer_id() {
            // Check if this carries a tunnel key exchange/response inside
            if let Ok(inner) = WireMessage::decode(&data.data) {
                match inner.msg_type {
                    MessageType::TunnelKeyExchange => {
                        return self.handle_tunnel_key_exchange(from, &inner.payload).await;
                    }
                    MessageType::TunnelKeyResponse => {
                        return self.handle_tunnel_key_response(from, &inner.payload).await;
                    }
                    _ => {}
                }
            }
            // Regular application data
            log::debug!(
                "Data arrived from {:?} ({} bytes)",
                data.origin,
                data.data.len()
            );
            let _ = self.app_tx.send((data.origin, data.data)).await;
            return Ok(());
        }

        // Forward to next hop
        if data.ttl == 0 {
            log::debug!("Dropping data with expired TTL for {:?}", data.destination);
            return Ok(());
        }
        data.ttl -= 1;

        let next_hop = {
            let table = self.routing_table.lock().await;
            table
                .lookup(&data.destination)
                .map(|r| r.next_hop)
                .ok_or(Error::NotFound)?
        };
        log::debug!(
            "Forwarding data for {:?} via {:?} (ttl={})",
            data.destination,
            next_hop,
            data.ttl
        );
        self.send_to_peer(&next_hop, &data.to_wire().encode()).await
    }

    /// Send application data to a remote peer, routed through the overlay.
    /// Per-hop encrypted by the link layer. TTL limits forwarding hops.
    pub async fn send_data(&self, dest: &PeerId, payload: &[u8]) -> Result<()> {
        let msg = DataMsg {
            origin: self.peer_id(),
            destination: *dest,
            ttl: 64,
            data: payload.to_vec(),
        };
        let encoded = msg.to_wire().encode();

        // Direct link?
        {
            let links = self.links.lock().await;
            if let Some(link) = links.get(dest) {
                return link.send_message(&encoded).await;
            }
        }

        // Route through overlay
        let next_hop = {
            let table = self.routing_table.lock().await;
            table
                .lookup(dest)
                .map(|r| r.next_hop)
                .ok_or(Error::NotFound)?
        };
        self.send_to_peer(&next_hop, &encoded).await
    }

    /// Send data to a peer through routing (finds next hop).
    pub async fn send_routed(&self, dest: &PeerId, data: &[u8]) -> Result<()> {
        self.route_message(dest, data).await
    }

    /// Route a message to a destination peer, either directly or via next hop.
    pub(super) async fn route_message(&self, dest: &PeerId, data: &[u8]) -> Result<()> {
        // Check if we have a direct link
        {
            let links = self.links.lock().await;
            if let Some(link) = links.get(dest) {
                return link.send_message(data).await;
            }
        }

        // Find next hop via routing table
        let next_hop = {
            let table = self.routing_table.lock().await;
            table
                .lookup(dest)
                .map(|r| r.next_hop)
                .ok_or(Error::NotFound)?
        };
        self.send_to_peer(&next_hop, data).await
    }

    pub async fn create_tunnel(&self, dest: PeerId) -> Result<oneshot::Receiver<PeerId>> {
        // Loopback: tunnel to self — no actual tunnel needed.
        if dest == self.peer_id() {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(dest);
            return Ok(rx);
        }

        // Wait for a route to the destination (up to 30s).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let connected = self.connected_peers().await;
            if connected.contains(&dest) {
                break;
            }
            let has_route = self.routing_table.lock().await.lookup(&dest).is_some();
            if has_route {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Protocol(format!("no route to {:?}", dest)));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let kem_algo = self.identity.identity.kem_algo();
        let kex = KexOffer::new(kem_algo);

        let mut rng = rand::rngs::OsRng;
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut ke = TunnelKeyExchangeMsg {
            kem_algo: kex.algo_byte(),
            ephemeral_pubkey: kex.pubkey_bytes(),
            initiator_peer_id: self.peer_id(),
            nonce,
            timestamp,
            signer_algo: self.identity.identity.signing_algo() as u8,
            signer_pubkey: self.identity.identity.signing.signing_pubkey_bytes(),
            signature: Vec::new(),
        };
        // Authenticate the offer: bind the ephemeral KEM key to our static
        // identity and to `dest` as the intended responder, so an on-path relay
        // cannot substitute its own ephemeral key and MITM the tunnel.
        ke.signature = self.identity.sign(&ke.signed_bytes(&dest));

        // Wrap in a DataMsg for routing
        let inner = ke.to_wire().encode();
        let msg = DataMsg {
            origin: self.peer_id(),
            destination: dest,
            ttl: 64,
            data: inner,
        };

        // Store pending state keyed by nonce
        let (tx, rx) = oneshot::channel();
        self.pending_key_exchanges
            .lock()
            .await
            .insert(nonce, (kex, tx, dest, Instant::now()));

        self.route_message(&dest, &msg.to_wire().encode()).await?;

        log::info!("Tunnel key exchange initiated to {:?}", dest);
        Ok(rx)
    }

    /// Take the application data receiver (for consuming delivered messages).
    pub async fn take_app_receiver(&self) -> Option<mpsc::Receiver<(PeerId, Vec<u8>)>> {
        self.app_rx.lock().await.take()
    }

    pub async fn send_tunnel_data(&self, dest: &PeerId, data: &[u8]) -> Result<()> {
        // Loopback: deliver to self directly.
        if *dest == self.peer_id() {
            let _ = self.app_tx.send((self.peer_id(), data.to_vec())).await;
            return Ok(());
        }

        let mut tt = self.tunnel_table.lock().await;
        let tunnel = tt
            .get_mut(dest)
            .ok_or_else(|| Error::Protocol(format!("no tunnel to {:?}", dest)))?;
        let encrypted = tunnel.encrypt(data)?;
        drop(tt);

        let msg = EncryptedDataMsg {
            origin: self.peer_id(),
            destination: *dest,
            ttl: 64,
            data: encrypted,
        };
        self.route_message(dest, &msg.to_wire_encrypted().encode())
            .await
    }

    // ── Channel-based reliable data exchange ──

    /// Open a reliable channel to a peer over an established tunnel.
    /// Returns the channel_id for use with `channel_send`.
    /// The remote side will receive data via `take_app_receiver`.
    pub async fn channel_open(
        &self,
        dest: &PeerId,
        port_name: &str,
        reliable: bool,
        ordered: bool,
    ) -> Result<u32> {
        use rand::Rng;
        let port = crate::wire::hash_port_name(port_name);
        let channel_id = {
            let mut channels = self.channel_state.channels.lock().await;
            loop {
                let candidate: u32 = rand::thread_rng().gen();
                if !channels.contains_key(&candidate) {
                    let ch = Channel::new(candidate, port, reliable, ordered);
                    channels.insert(candidate, (*dest, ch));
                    break candidate;
                }
            }
        };

        // Send ChannelOpen through the tunnel
        let open = ChannelOpenMsg {
            channel_id,
            port,
            reliable,
            ordered,
        };
        let inner = open.to_wire().encode();
        self.send_tunnel_data(dest, &inner).await?;
        Ok(channel_id)
    }

    /// Open a channel using a pre-computed 32-byte port hash.
    pub async fn channel_open_port(
        &self,
        dest: &PeerId,
        port: [u8; 32],
        reliable: bool,
        ordered: bool,
    ) -> Result<u32> {
        use rand::Rng;
        let channel_id = {
            let mut channels = self.channel_state.channels.lock().await;
            loop {
                let candidate: u32 = rand::thread_rng().gen();
                if !channels.contains_key(&candidate) {
                    let ch = Channel::new(candidate, port, reliable, ordered);
                    channels.insert(candidate, (*dest, ch));
                    break candidate;
                }
            }
        };

        let open = ChannelOpenMsg {
            channel_id,
            port,
            reliable,
            ordered,
        };
        let inner = open.to_wire().encode();
        self.send_tunnel_data(dest, &inner).await?;
        Ok(channel_id)
    }

    /// Open a reliable channel and return a receiver for incoming data on it.
    /// Used for internal protocols (e.g., WebRTC signaling) that need bidirectional
    /// communication on a channel without going through app_tx.
    pub async fn channel_open_with_handler(
        &self,
        dest: &PeerId,
        port_name: &str,
        reliable: bool,
        ordered: bool,
    ) -> Result<(u32, mpsc::UnboundedReceiver<Vec<u8>>)> {
        let channel_id = self
            .channel_open(dest, port_name, reliable, ordered)
            .await?;
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        self.channel_state
            .data_handlers
            .lock()
            .await
            .insert(channel_id, data_tx);
        Ok((channel_id, data_rx))
    }

    /// Like `channel_open_with_handler` but takes a pre-computed port hash.
    pub async fn channel_open_with_handler_port(
        &self,
        dest: &PeerId,
        port: [u8; 32],
        reliable: bool,
        ordered: bool,
    ) -> Result<(u32, mpsc::UnboundedReceiver<Vec<u8>>)> {
        let channel_id = self
            .channel_open_port(dest, port, reliable, ordered)
            .await?;
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        self.channel_state
            .data_handlers
            .lock()
            .await
            .insert(channel_id, data_tx);
        Ok((channel_id, data_rx))
    }

    /// Send data through a reliable channel.  The channel handles
    /// sequencing, ACKs, and retransmission automatically.
    pub async fn channel_send(&self, channel_id: u32, data: &[u8]) -> Result<()> {
        let (dest, sends, is_reliable) = {
            let mut channels = self.channel_state.channels.lock().await;
            let (remote, ch) = channels
                .get_mut(&channel_id)
                .ok_or_else(|| Error::Protocol(format!("no channel {}", channel_id)))?;
            let dest = *remote;
            let reliable = ch.reliable;
            let sends = ch.prepare_send(data.to_vec());
            (dest, sends, reliable)
        };
        if is_reliable {
            self.channel_state.retransmit_notify.notify_one();
        }
        for (seq, payload) in sends {
            let msg = ChannelDataMsg {
                channel_id,
                sequence: seq,
                data: payload,
            };
            let inner = msg.to_wire().encode();
            self.send_tunnel_data(&dest, &inner).await?;
        }
        Ok(())
    }

    /// Close a channel.
    pub async fn channel_close(&self, channel_id: u32) -> Result<()> {
        let dest = {
            let mut channels = self.channel_state.channels.lock().await;
            let (remote, _) = channels
                .remove(&channel_id)
                .ok_or_else(|| Error::Protocol(format!("no channel {}", channel_id)))?;
            remote
        };
        let close = ChannelCloseMsg { channel_id };
        let inner = close.to_wire().encode();
        self.send_tunnel_data(&dest, &inner).await
    }
}
