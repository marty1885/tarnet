use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, Mutex};
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::api::API;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use super::Transport;
use crate::types::{Error, PeerId, Result};

/// Maximum message size for WebRTC data channel transport.
const WEBRTC_MTU: usize = 16384;

/// WebRTC data channel transport — implements the same `Transport` trait as TCP.
/// Uses a reliable, ordered data channel so PeerLink handshake works unchanged.
pub struct WebRtcTransport {
    dc: Arc<RTCDataChannel>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    _pc: Arc<RTCPeerConnection>,
}

impl WebRtcTransport {
    /// Wrap an open data channel and its peer connection into a Transport.
    /// `rx` receives incoming messages bridged from the data channel's on_message callback.
    pub fn new(
        dc: Arc<RTCDataChannel>,
        rx: mpsc::Receiver<Vec<u8>>,
        pc: Arc<RTCPeerConnection>,
    ) -> Self {
        Self {
            dc,
            rx: Mutex::new(rx),
            _pc: pc,
        }
    }
}

#[async_trait]
impl Transport for WebRtcTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        let bytes = bytes::Bytes::copy_from_slice(data);
        self.dc
            .send(&bytes)
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut rx = self.rx.lock().await;
        let data = rx.recv().await.ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "data channel closed",
            ))
        })?;
        if data.len() > buf.len() {
            return Err(Error::Wire(format!(
                "message {} bytes exceeds buffer {}",
                data.len(),
                buf.len()
            )));
        }
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }

    fn mtu(&self) -> usize {
        WEBRTC_MTU
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "webrtc"
    }
}

/// Manages pending WebRTC connection establishments.
pub struct WebRtcConnector {
    api: API,
    config: RTCConfiguration,
    /// Pending connections: peer_id → (RTCPeerConnection, completion sender)
    pending:
        Arc<Mutex<HashMap<PeerId, (Arc<RTCPeerConnection>, oneshot::Sender<WebRtcTransport>)>>>,
}

impl WebRtcConnector {
    /// Create a new connector.
    ///
    /// `stun_servers` — list of STUN server URLs (e.g. `"stun:stun.l.google.com:19302"`).
    pub fn new(stun_servers: Vec<String>) -> Result<Self> {
        // Data-channel-only usage: no media codecs or interceptors needed.
        let media_engine = MediaEngine::default();

        // Give ICE more time — signaling goes through the overlay network,
        // so candidates arrive slower than in a direct browser-to-browser scenario.
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_ice_timeouts(
            Some(Duration::from_secs(15)), // disconnected_timeout (default 5s)
            Some(Duration::from_secs(30)), // failed_timeout (default 25s)
            Some(Duration::from_secs(5)),  // keep_alive_interval (default 2s)
        );
        setting_engine.set_host_acceptance_min_wait(Some(Duration::from_secs(3)));
        setting_engine.set_srflx_acceptance_min_wait(Some(Duration::from_secs(3)));

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(setting_engine)
            .build();

        let config = RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: stun_servers,
                ..Default::default()
            }],
            ..Default::default()
        };

        Ok(Self {
            api,
            config,
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Initiate a WebRTC connection to a remote peer.
    /// Returns the SDP offer string, a receiver that yields the transport once the
    /// data channel opens, and a receiver for trickled ICE candidates.
    pub async fn initiate(
        &self,
        peer_id: PeerId,
    ) -> Result<(
        String,
        oneshot::Receiver<WebRtcTransport>,
        mpsc::UnboundedReceiver<String>,
    )> {
        let pc = Arc::new(
            self.api
                .new_peer_connection(self.config.clone())
                .await
                .map_err(|e| Error::Protocol(format!("WebRTC new_peer_connection: {}", e)))?,
        );

        // Create a reliable, ordered data channel
        let dc = pc
            .create_data_channel(
                "tarnet",
                Some(RTCDataChannelInit {
                    ordered: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC create_data_channel: {}", e)))?;

        let (tx, rx) = oneshot::channel();

        // Set up ICE candidate trickle — send candidates to a channel
        let (ice_tx, ice_rx) = mpsc::unbounded_channel();
        pc.on_ice_candidate(Box::new(move |candidate| {
            let ice_tx = ice_tx.clone();
            Box::pin(async move {
                if let Some(c) = candidate {
                    let json = match c.to_json() {
                        Ok(j) => j,
                        Err(_) => return,
                    };
                    let candidate_str = serde_json::to_string(&json).unwrap_or_default();
                    let _ = ice_tx.send(candidate_str);
                }
            })
        }));

        // Bridge data channel messages to mpsc
        let (msg_tx, msg_rx) = mpsc::channel(256);
        dc.on_message(Box::new(move |raw| {
            let tx = msg_tx.clone();
            Box::pin(async move {
                let _ = tx.send(raw.data.to_vec()).await;
            })
        }));

        // When data channel opens, resolve the oneshot with the transport
        let dc_for_open = dc.clone();
        let pc_for_transport = pc.clone();
        let pending = self.pending.clone();
        let pid2 = peer_id;
        dc.on_open(Box::new(move || {
            let pending = pending.clone();
            let pc_for_transport = pc_for_transport.clone();
            let dc_for_open = dc_for_open.clone();
            Box::pin(async move {
                let mut p = pending.lock().await;
                if let Some((_, tx)) = p.remove(&pid2) {
                    let transport = WebRtcTransport::new(dc_for_open, msg_rx, pc_for_transport);
                    let _ = tx.send(transport);
                }
            })
        }));

        // Generate offer
        let offer = pc
            .create_offer(None)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC create_offer: {}", e)))?;
        pc.set_local_description(offer.clone())
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC set_local_description: {}", e)))?;

        let sdp = offer.sdp;
        self.pending.lock().await.insert(peer_id, (pc, tx));

        Ok((sdp, rx, ice_rx))
    }

    /// Handle an incoming SDP offer from a remote peer.
    /// Returns the SDP answer string, a receiver that yields the transport once the
    /// data channel opens, and a receiver for trickled ICE candidates.
    pub async fn handle_offer(
        &self,
        peer_id: PeerId,
        sdp_offer: &str,
    ) -> Result<(
        String,
        oneshot::Receiver<WebRtcTransport>,
        mpsc::UnboundedReceiver<String>,
    )> {
        let pc = Arc::new(
            self.api
                .new_peer_connection(self.config.clone())
                .await
                .map_err(|e| Error::Protocol(format!("WebRTC new_peer_connection: {}", e)))?,
        );

        let (tx, rx) = oneshot::channel();

        // Set up ICE candidate trickle — send candidates to a channel
        let (ice_tx, ice_rx) = mpsc::unbounded_channel();
        pc.on_ice_candidate(Box::new(move |candidate| {
            let ice_tx = ice_tx.clone();
            Box::pin(async move {
                if let Some(c) = candidate {
                    let json = match c.to_json() {
                        Ok(j) => j,
                        Err(_) => return,
                    };
                    let candidate_str = serde_json::to_string(&json).unwrap_or_default();
                    let _ = ice_tx.send(candidate_str);
                }
            })
        }));

        // Handle incoming data channel (responder side)
        let pending = self.pending.clone();
        let pid2 = peer_id;
        let pc_clone = pc.clone();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let pending = pending.clone();
            let pc_clone = pc_clone.clone();
            Box::pin(async move {
                let (msg_tx, msg_rx) = mpsc::channel(256);
                let dc_for_transport = dc.clone();

                dc.on_message(Box::new(move |raw| {
                    let tx = msg_tx.clone();
                    Box::pin(async move {
                        let _ = tx.send(raw.data.to_vec()).await;
                    })
                }));

                let dc_for_open = dc_for_transport.clone();
                dc_for_transport.on_open(Box::new(move || {
                    let pending = pending.clone();
                    let pc_clone = pc_clone.clone();
                    let dc_for_open = dc_for_open.clone();
                    Box::pin(async move {
                        let mut p = pending.lock().await;
                        if let Some((_, tx)) = p.remove(&pid2) {
                            let transport = WebRtcTransport::new(dc_for_open, msg_rx, pc_clone);
                            let _ = tx.send(transport);
                        }
                    })
                }));
            })
        }));

        // Set remote description (the offer)
        let offer = RTCSessionDescription::offer(sdp_offer.to_string())
            .map_err(|e| Error::Protocol(format!("WebRTC parse offer: {}", e)))?;
        pc.set_remote_description(offer)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC set_remote_description: {}", e)))?;

        // Create answer
        let answer = pc
            .create_answer(None)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC create_answer: {}", e)))?;
        pc.set_local_description(answer.clone())
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC set_local_description: {}", e)))?;

        let sdp = answer.sdp;
        self.pending.lock().await.insert(peer_id, (pc, tx));

        Ok((sdp, rx, ice_rx))
    }

    /// Handle an incoming SDP answer for a pending outbound connection.
    pub async fn handle_answer(&self, peer_id: PeerId, sdp_answer: &str) -> Result<()> {
        let pending = self.pending.lock().await;
        let (pc, _) = pending.get(&peer_id).ok_or_else(|| {
            Error::Protocol(format!("no pending WebRTC connection to {:?}", peer_id))
        })?;

        let answer = RTCSessionDescription::answer(sdp_answer.to_string())
            .map_err(|e| Error::Protocol(format!("WebRTC parse answer: {}", e)))?;
        pc.set_remote_description(answer)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC set_remote_description: {}", e)))?;

        Ok(())
    }

    /// Initiate a WebRTC connection with full ICE gathering (no trickle).
    /// Waits for all ICE candidates to be gathered before returning the SDP.
    /// Used for out-of-band signaling (e.g., mainline DHT) where trickle isn't possible.
    pub async fn initiate_full_ice(
        &self,
        peer_id: PeerId,
    ) -> Result<(String, oneshot::Receiver<WebRtcTransport>)> {
        let pc = Arc::new(
            self.api
                .new_peer_connection(self.config.clone())
                .await
                .map_err(|e| Error::Protocol(format!("WebRTC new_peer_connection: {}", e)))?,
        );

        let dc = pc
            .create_data_channel(
                "tarnet",
                Some(RTCDataChannelInit {
                    ordered: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC create_data_channel: {}", e)))?;

        let (tx, rx) = oneshot::channel();

        // No trickle callback — we gather everything before returning.

        let (msg_tx, msg_rx) = mpsc::channel(256);
        dc.on_message(Box::new(move |raw| {
            let tx = msg_tx.clone();
            Box::pin(async move {
                let _ = tx.send(raw.data.to_vec()).await;
            })
        }));

        let dc_for_open = dc.clone();
        let pc_for_transport = pc.clone();
        let pending = self.pending.clone();
        let pid2 = peer_id;
        dc.on_open(Box::new(move || {
            let pending = pending.clone();
            let pc_for_transport = pc_for_transport.clone();
            let dc_for_open = dc_for_open.clone();
            Box::pin(async move {
                let mut p = pending.lock().await;
                if let Some((_, tx)) = p.remove(&pid2) {
                    let transport = WebRtcTransport::new(dc_for_open, msg_rx, pc_for_transport);
                    let _ = tx.send(transport);
                }
            })
        }));

        // Create offer and wait for ICE gathering to complete
        let mut gathering_done = pc.gathering_complete_promise().await;
        let offer = pc
            .create_offer(None)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC create_offer: {}", e)))?;
        pc.set_local_description(offer)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC set_local_description: {}", e)))?;

        // Wait for gathering (with timeout)
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(10), gathering_done.recv()).await;

        // Read back the local description which now includes all candidates
        let local_desc = pc
            .local_description()
            .await
            .ok_or_else(|| Error::Protocol("no local description after gathering".into()))?;

        self.pending.lock().await.insert(peer_id, (pc, tx));
        Ok((local_desc.sdp, rx))
    }

    /// Handle an incoming SDP offer with full ICE gathering (no trickle).
    /// Used for out-of-band signaling where trickle isn't possible.
    pub async fn handle_offer_full_ice(
        &self,
        peer_id: PeerId,
        sdp_offer: &str,
    ) -> Result<(String, oneshot::Receiver<WebRtcTransport>)> {
        let pc = Arc::new(
            self.api
                .new_peer_connection(self.config.clone())
                .await
                .map_err(|e| Error::Protocol(format!("WebRTC new_peer_connection: {}", e)))?,
        );

        let (tx, rx) = oneshot::channel();

        // No trickle callback.

        let pending = self.pending.clone();
        let pid2 = peer_id;
        let pc_clone = pc.clone();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let pending = pending.clone();
            let pc_clone = pc_clone.clone();
            Box::pin(async move {
                let (msg_tx, msg_rx) = mpsc::channel(256);
                let dc_for_transport = dc.clone();

                dc.on_message(Box::new(move |raw| {
                    let tx = msg_tx.clone();
                    Box::pin(async move {
                        let _ = tx.send(raw.data.to_vec()).await;
                    })
                }));

                let dc_for_open = dc_for_transport.clone();
                dc_for_transport.on_open(Box::new(move || {
                    let pending = pending.clone();
                    let pc_clone = pc_clone.clone();
                    let dc_for_open = dc_for_open.clone();
                    Box::pin(async move {
                        let mut p = pending.lock().await;
                        if let Some((_, tx)) = p.remove(&pid2) {
                            let transport = WebRtcTransport::new(dc_for_open, msg_rx, pc_clone);
                            let _ = tx.send(transport);
                        }
                    })
                }));
            })
        }));

        let offer = RTCSessionDescription::offer(sdp_offer.to_string())
            .map_err(|e| Error::Protocol(format!("WebRTC parse offer: {}", e)))?;
        pc.set_remote_description(offer)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC set_remote_description: {}", e)))?;

        let mut gathering_done = pc.gathering_complete_promise().await;
        let answer = pc
            .create_answer(None)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC create_answer: {}", e)))?;
        pc.set_local_description(answer)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC set_local_description: {}", e)))?;

        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(10), gathering_done.recv()).await;

        let local_desc = pc
            .local_description()
            .await
            .ok_or_else(|| Error::Protocol("no local description after gathering".into()))?;

        self.pending.lock().await.insert(peer_id, (pc, tx));
        Ok((local_desc.sdp, rx))
    }

    /// Handle a trickled ICE candidate from a remote peer.
    /// Returns Ok(()) silently if there's no pending connection (benign race).
    pub async fn handle_ice_candidate(&self, peer_id: PeerId, candidate_json: &str) -> Result<()> {
        let pending = self.pending.lock().await;
        let (pc, _) = match pending.get(&peer_id) {
            Some(entry) => entry,
            None => {
                log::debug!(
                    "Ignoring stale ICE candidate from {:?} (no pending connection)",
                    peer_id
                );
                return Ok(());
            }
        };

        let candidate: RTCIceCandidateInit = serde_json::from_str(candidate_json)
            .map_err(|e| Error::Wire(format!("invalid ICE candidate JSON: {}", e)))?;
        pc.add_ice_candidate(candidate)
            .await
            .map_err(|e| Error::Protocol(format!("WebRTC add_ice_candidate: {}", e)))?;

        Ok(())
    }
}
