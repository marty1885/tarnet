//! Thin IPC client for tarnetd.
//!
//! Implements `ServiceApi` by sending requests over a Unix socket to the daemon.
//! No crypto, no routing, no DHT logic — just serialization.
//!
//! Usage:
//! ```no_run
//! use tarnet_client::IpcServiceApi;
//! use tarnet_api::ServiceApi;
//!
//! # async fn example() {
//! let client = IpcServiceApi::connect_default().await.unwrap();
//! let peer_id = client.peer_id();
//! println!("Connected to daemon: {}", peer_id);
//! # }
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, Mutex};

use tarnet_api::error::{ApiError, ApiResult};
use tarnet_api::ipc::*;
use tarnet_api::service::{
    Connection, DhtEntry, HelloInfo, NodeEvent, ServiceApi, TnsRecord, TnsResolution,
};
use tarnet_api::types::{DhtId, IdentityScheme, KemAlgo, PeerId, PrivacyLevel, ServiceId, SigningAlgo};

/// Per-connection data channel: conn_id -> sender.
type ConnDataMap = Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>;

/// Fallback for when the daemon can't return status (old daemon, connection error).
fn default_node_status() -> tarnet_api::types::NodeStatus {
    tarnet_api::types::NodeStatus {
        peer_id: PeerId([0; 32]),
        uptime_secs: 0,
        peers: Vec::new(),
        routes: Vec::new(),
        dht: tarnet_api::types::DhtStatus {
            stored_keys: 0, stored_records: 0, kbucket_peers: 0,
            local_watches: 0, remote_watches: 0, nse: 0,
        },
        circuits: tarnet_api::types::CircuitStatus {
            relay_forwards: 0, relay_endpoints: 0, outbound_circuits: 0,
            rendezvous_points: 0, intro_points: 0,
        },
        traffic: tarnet_api::types::TrafficStatus {
            bytes_up: Default::default(), bytes_down: Default::default(),
            packets_up: Default::default(), packets_down: Default::default(),
            cells_relayed: Default::default(),
        },
    }
}

/// IPC client that implements ServiceApi by talking to tarnetd over a Unix socket.
pub struct IpcServiceApi {
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    next_id: AtomicU32,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<(u8, Vec<u8>)>>>>,
    /// Cached peer ID (fetched on connect, set exactly once).
    cached_peer_id: OnceLock<PeerId>,
    /// Unified event broadcast channel.
    event_tx: tokio::sync::broadcast::Sender<NodeEvent>,
    /// Fires when the daemon connection is lost.
    disconnect_tx: tokio::sync::broadcast::Sender<()>,
    /// Per-connection data channels for circuit connections.
    conn_data: ConnDataMap,
}

impl IpcServiceApi {
    /// Connect to tarnetd at the default socket path.
    pub async fn connect_default() -> ApiResult<Arc<Self>> {
        Self::connect(&default_socket_path()).await
    }

    /// Connect to tarnetd at a specific socket path.
    pub async fn connect(path: &Path) -> ApiResult<Arc<Self>> {
        let mut stream = UnixStream::connect(path).await?;

        // Version handshake before splitting the stream
        let _negotiated = tarnet_api::ipc::handshake_client(&mut stream).await?;

        let (reader, writer) = stream.into_split();

        let pending: Arc<Mutex<HashMap<u32, oneshot::Sender<(u8, Vec<u8>)>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, _) = tokio::sync::broadcast::channel(256);
        let (disconnect_tx, _) = tokio::sync::broadcast::channel(1);
        let conn_data: ConnDataMap = Arc::new(Mutex::new(HashMap::new()));

        // Spawn reader task that dispatches responses and events
        let pending_clone = pending.clone();
        let event_tx_clone = event_tx.clone();
        let conn_data_clone = conn_data.clone();
        let disconnect_tx_clone = disconnect_tx.clone();
        tokio::spawn(async move {
            let mut reader = reader;
            loop {
                match recv_frame(&mut reader).await {
                    Ok(IpcFrame::Response {
                        request_id,
                        status,
                        payload,
                    }) => {
                        let mut pending = pending_clone.lock().await;
                        if let Some(tx) = pending.remove(&request_id) {
                            let _ = tx.send((status, payload));
                        }
                    }
                    Ok(IpcFrame::Event {
                        event_type,
                        payload,
                    }) => match event_type {
                        EVENT_DATA | EVENT_TUNNEL | EVENT_WATCH => {
                            if let Ok(event) = decode_payload::<NodeEvent>(&payload) {
                                let _ = event_tx_clone.send(event);
                            }
                        }
                        EVENT_CONN_DATA => {
                            if let Ok(evt) = decode_payload::<ConnDataEvent>(&payload) {
                                let map = conn_data_clone.lock().await;
                                if let Some(tx) = map.get(&evt.conn_id) {
                                    let _ = tx.send(evt.data).await;
                                }
                            }
                        }
                        EVENT_CONN_CLOSED => {
                            if let Ok(conn_id) = decode_payload::<u32>(&payload) {
                                conn_data_clone.lock().await.remove(&conn_id);
                            }
                        }
                        _ => {
                            log::debug!("Unknown event type: 0x{:04x}", event_type);
                        }
                    },
                    Ok(_) => {}
                    Err(_) => {
                        // Daemon disconnected — fail all pending requests and connections
                        pending_clone.lock().await.clear();
                        conn_data_clone.lock().await.clear();
                        let _ = disconnect_tx_clone.send(());
                        break;
                    }
                }
            }
        });

        let client = Arc::new(Self {
            writer: Arc::new(Mutex::new(writer)),
            next_id: AtomicU32::new(1),
            pending,
            cached_peer_id: OnceLock::new(),
            event_tx,
            disconnect_tx,
            conn_data,
        });

        // Fetch peer ID from daemon
        let (status, payload) = client.request(METHOD_GET_PEER_ID, &[]).await?;
        if status != STATUS_OK {
            return Err(ApiError::Protocol(
                "failed to get peer ID from daemon".into(),
            ));
        }
        let peer_id: PeerId = decode_payload(&payload)?;
        let _ = client.cached_peer_id.set(peer_id);

        Ok(client)
    }

    /// Send a request and wait for the response (30s timeout).
    async fn request(&self, method: u16, payload: &[u8]) -> ApiResult<(u8, Vec<u8>)> {
        self.request_with_timeout(method, payload, std::time::Duration::from_secs(30))
            .await
    }

    /// Send a request and wait for the response with a custom timeout.
    async fn request_with_timeout(
        &self,
        method: u16,
        payload: &[u8],
        timeout: std::time::Duration,
    ) -> ApiResult<(u8, Vec<u8>)> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();

        self.pending.lock().await.insert(request_id, tx);

        let frame = IpcFrame::Request {
            request_id,
            method,
            payload: payload.to_vec(),
        };
        {
            let mut writer = self.writer.lock().await;
            send_frame(&mut *writer, &frame).await?;
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(ApiError::Service("response channel dropped".into())),
            Err(_) => {
                self.pending.lock().await.remove(&request_id);
                Err(ApiError::Timeout)
            }
        }
    }

    /// Subscribe to daemon disconnect notification.
    /// The returned receiver fires once when the connection to tarnetd is lost.
    pub fn subscribe_disconnect(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.disconnect_tx.subscribe()
    }

    /// Create a Connection backed by IPC: sends go via METHOD_CONN_SEND,
    /// receives come from EVENT_CONN_DATA dispatched by the reader task.
    async fn make_ipc_connection(
        &self,
        conn_id: u32,
        remote_service_id: ServiceId,
        port: u16,
    ) -> ApiResult<Connection> {
        let (data_tx, data_rx) = mpsc::channel(256);
        self.conn_data.lock().await.insert(conn_id, data_tx);

        // Create a sender that forwards to IPC METHOD_CONN_SEND
        let (app_tx, mut app_rx) = mpsc::channel::<Vec<u8>>(256);
        let writer = self.writer.clone();
        let pending = self.pending.clone();
        let send_counter = Arc::new(AtomicU32::new(
            self.next_id.fetch_add(1_000_000, Ordering::Relaxed) + 1_000_000,
        ));
        tokio::spawn(async move {
            while let Some(data) = app_rx.recv().await {
                let payload = encode_payload(&ConnSendReq { conn_id, data });

                let request_id = send_counter.fetch_add(1, Ordering::Relaxed);
                // Register pending so the response is consumed (fire-and-forget)
                let (tx, _rx) = oneshot::channel();
                pending.lock().await.insert(request_id, tx);

                let frame = IpcFrame::Request {
                    request_id,
                    method: METHOD_CONN_SEND,
                    payload,
                };
                let mut w = writer.lock().await;
                if send_frame(&mut *w, &frame).await.is_err() {
                    break;
                }
            }
        });

        Ok(Connection::new(
            remote_service_id,
            port,
            conn_id,
            app_tx,
            data_rx,
        ))
    }

    /// Ask the daemon to reload its configuration.
    pub async fn reload(&self) -> ApiResult<()> {
        let (status, resp) = self.request(METHOD_RELOAD, &[]).await?;
        Self::check_status(status, &resp)
    }

    fn check_status(status: u8, payload: &[u8]) -> ApiResult<()> {
        match status {
            STATUS_OK => Ok(()),
            STATUS_NOT_FOUND => Err(ApiError::NotFound),
            STATUS_ERROR => {
                let msg = String::from_utf8_lossy(payload).to_string();
                Err(ApiError::Service(msg))
            }
            _ => Err(ApiError::Protocol(format!("unknown status: {}", status))),
        }
    }
}

#[async_trait]
impl ServiceApi for IpcServiceApi {
    fn peer_id(&self) -> PeerId {
        *self
            .cached_peer_id
            .get()
            .expect("peer_id called before connect completed")
    }

    async fn default_service_id(&self) -> ServiceId {
        match self.request(METHOD_DEFAULT_SERVICE_ID, &[]).await {
            Ok((STATUS_OK, payload)) => {
                decode_payload::<ServiceId>(&payload).unwrap_or(ServiceId::LOCAL)
            }
            _ => {
                log::error!("Failed to get default ServiceId from daemon");
                ServiceId::LOCAL
            }
        }
    }

    async fn resolve_identity(&self, label_or_sid: &str) -> ApiResult<ServiceId> {
        let payload = encode_payload(&label_or_sid.to_string());
        let (status, resp) = self.request(METHOD_RESOLVE_IDENTITY, &payload).await?;
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    // ── Circuit connections ──

    async fn connect(
        &self,
        service_id: ServiceId,
        port: u16,
    ) -> ApiResult<Connection> {
        let payload = encode_payload(&(service_id, port));
        let (status, resp) = self.request(METHOD_CONNECT, &payload).await?;
        Self::check_status(status, &resp)?;
        let r: ConnectResp = decode_payload(&resp)?;
        self.make_ipc_connection(r.conn_id, r.remote_service_id, port)
            .await
    }

    async fn listen(&self, service_id: ServiceId, port: u16) -> ApiResult<()> {
        let payload = encode_payload(&(service_id, port));
        let (status, resp) = self.request(METHOD_LISTEN, &payload).await?;
        Self::check_status(status, &resp)
    }

    async fn accept(&self) -> ApiResult<Connection> {
        // Accept blocks until a connection arrives — use a very long timeout
        // so we don't time out waiting for incoming connections.
        let (status, resp) = self
            .request_with_timeout(
                METHOD_ACCEPT,
                &[],
                std::time::Duration::from_secs(3600),
            )
            .await?;
        Self::check_status(status, &resp)?;
        let r: ConnectResp = decode_payload(&resp)?;
        self.make_ipc_connection(r.conn_id, r.remote_service_id, 0)
            .await
    }

    async fn listen_hidden(
        &self,
        service_id: ServiceId,
        port: u16,
        num_intro_points: usize,
    ) -> ApiResult<()> {
        let payload = encode_payload(&(service_id, port, num_intro_points as u16));
        let (status, resp) = self.request(METHOD_LISTEN_HIDDEN, &payload).await?;
        Self::check_status(status, &resp)
    }

    // ── DHT: content-addressed ──

    async fn dht_put(&self, value: &[u8]) -> DhtId {
        let payload = encode_payload(&serde_bytes::ByteBuf::from(value.to_vec()));
        let (_, resp) = self
            .request(METHOD_DHT_PUT_CONTENT, &payload)
            .await
            .unwrap();
        decode_payload(&resp).unwrap()
    }

    async fn dht_get(
        &self,
        key: &DhtId,
        timeout_secs: u32,
    ) -> Option<Vec<u8>> {
        let payload = encode_payload(&(*key, timeout_secs));
        let timeout = std::time::Duration::from_secs(timeout_secs as u64 + 5);
        let (status, resp) = self
            .request_with_timeout(METHOD_DHT_GET_CONTENT, &payload, timeout)
            .await
            .ok()?;
        if status == STATUS_NOT_FOUND || status != STATUS_OK {
            return None;
        }
        let data: serde_bytes::ByteBuf = decode_payload(&resp).ok()?;
        Some(data.into_vec())
    }

    // ── DHT: signed content ──

    async fn dht_put_signed(
        &self,
        value: &[u8],
        ttl_secs: u32,
    ) -> DhtId {
        let req = DhtPutSignedReq {
            ttl_secs,
            value: value.to_vec(),
        };
        let payload = encode_payload(&req);
        let (_, resp) = self
            .request(METHOD_DHT_PUT_SIGNED, &payload)
            .await
            .unwrap();
        decode_payload(&resp).unwrap()
    }

    async fn dht_get_signed(
        &self,
        key: &DhtId,
        timeout_secs: u32,
    ) -> Vec<DhtEntry> {
        let payload = encode_payload(&(*key, timeout_secs));
        let timeout = std::time::Duration::from_secs(timeout_secs as u64 + 5);
        let (status, resp) = match self
            .request_with_timeout(METHOD_DHT_GET_SIGNED, &payload, timeout)
            .await
        {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        if status != STATUS_OK {
            return Vec::new();
        }
        let entries: Vec<SignedContentEntry> = match decode_payload(&resp) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        entries
            .into_iter()
            .map(|e| DhtEntry { signer: e.signer, data: e.data })
            .collect()
    }

    // ── DHT: hello records ──

    async fn lookup_hello(&self, peer_id: &PeerId, timeout_secs: u32) -> Option<HelloInfo> {
        let payload = encode_payload(&(*peer_id, timeout_secs));
        let timeout = std::time::Duration::from_secs(timeout_secs as u64 + 5);
        let (status, resp) = self
            .request_with_timeout(METHOD_LOOKUP_HELLO, &payload, timeout)
            .await
            .ok()?;
        if status != STATUS_OK {
            return None;
        }
        decode_payload(&resp).ok()
    }

    // ── DHT: watches ──

    async fn dht_watch(&self, key: &DhtId, expiration_secs: u32) {
        let payload = encode_payload(&(*key, expiration_secs));
        let _ = self.request(METHOD_DHT_WATCH, &payload).await;
    }

    async fn dht_unwatch(&self, key: &DhtId) {
        let payload = encode_payload(key);
        let _ = self.request(METHOD_DHT_UNWATCH, &payload).await;
    }

    // ── Status ──

    async fn connected_peers(&self) -> Vec<PeerId> {
        let (status, resp) = match self.request(METHOD_CONNECTED_PEERS, &[]).await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        if status != STATUS_OK {
            return Vec::new();
        }
        decode_payload(&resp).unwrap_or_default()
    }

    async fn routing_entries(&self) -> Vec<(PeerId, PeerId, u32)> {
        let (status, resp) = match self.request(METHOD_ROUTING_ENTRIES, &[]).await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        if status != STATUS_OK {
            return Vec::new();
        }
        decode_payload(&resp).unwrap_or_default()
    }

    async fn node_status(&self) -> tarnet_api::types::NodeStatus {
        let (status, resp) = match self.request(METHOD_NODE_STATUS, &[]).await {
            Ok(r) => r,
            Err(_) => return default_node_status(),
        };
        if status != STATUS_OK {
            return default_node_status();
        }
        decode_payload(&resp).unwrap_or_else(|_| default_node_status())
    }

    // ── Event stream ──

    async fn subscribe_events(&self) -> ApiResult<mpsc::Receiver<NodeEvent>> {
        let mut rx = self.event_tx.subscribe();
        let (tx, out_rx) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                if tx.send(event).await.is_err() {
                    break;
                }
            }
        });
        Ok(out_rx)
    }

    // ── TNS ──

    async fn tns_publish(
        &self,
        identity: Option<&str>,
        label: &str,
        records: Vec<TnsRecord>,
        ttl_secs: u32,
    ) -> ApiResult<()> {
        let id_str: Option<String> = identity.map(|s| s.to_string());
        let payload = encode_payload(&(id_str, label.to_string(), records, ttl_secs));
        let (status, resp) = self.request(METHOD_TNS_PUBLISH, &payload).await?;
        Self::check_status(status, &resp)
    }

    async fn tns_resolve(
        &self,
        zone: ServiceId,
        name: &str,
    ) -> ApiResult<TnsResolution> {
        let payload = encode_payload(&(zone, name.to_string()));
        let (status, resp) = self.request(METHOD_TNS_RESOLVE, &payload).await?;
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    async fn tns_resolve_name(&self, name: &str) -> ApiResult<TnsResolution> {
        let payload = encode_payload(&name.to_string());
        let (status, resp) = self.request(METHOD_TNS_RESOLVE_NAME, &payload).await?;
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    async fn tns_set_label(&self, identity: Option<&str>, label: &str, records: Vec<TnsRecord>, publish: bool) -> ApiResult<()> {
        let id_str: Option<String> = identity.map(|s| s.to_string());
        let payload = encode_payload(&(id_str, label.to_string(), records, publish));
        let (status, resp) = self.request(METHOD_TNS_SET_LABEL, &payload).await?;
        Self::check_status(status, &resp)
    }

    async fn tns_get_label(&self, identity: Option<&str>, label: &str) -> ApiResult<Option<(Vec<TnsRecord>, bool)>> {
        let id_str: Option<String> = identity.map(|s| s.to_string());
        let payload = encode_payload(&(id_str, label.to_string()));
        let (status, resp) = self.request(METHOD_TNS_GET_LABEL, &payload).await?;
        if status == STATUS_NOT_FOUND {
            return Ok(None);
        }
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    async fn tns_remove_label(&self, identity: Option<&str>, label: &str) -> ApiResult<()> {
        let id_str: Option<String> = identity.map(|s| s.to_string());
        let payload = encode_payload(&(id_str, label.to_string()));
        let (status, resp) = self.request(METHOD_TNS_REMOVE_LABEL, &payload).await?;
        Self::check_status(status, &resp)
    }

    async fn tns_list_labels(&self, identity: Option<&str>) -> ApiResult<Vec<(String, Vec<TnsRecord>, bool)>> {
        let id_str: Option<String> = identity.map(|s| s.to_string());
        let payload = encode_payload(&id_str);
        let (status, resp) = self.request(METHOD_TNS_LIST_LABELS, &payload).await?;
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    // ── Identity management ──

    async fn create_identity(
        &self,
        label: &str,
        privacy: PrivacyLevel,
        outbound_hops: u8,
        scheme: IdentityScheme,
    ) -> ApiResult<ServiceId> {
        let payload = encode_payload(&(label.to_string(), privacy, outbound_hops, scheme));
        let (status, resp) = self.request(METHOD_CREATE_IDENTITY, &payload).await?;
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    async fn list_identities(
        &self,
    ) -> ApiResult<Vec<(String, ServiceId, PrivacyLevel, u8, IdentityScheme, SigningAlgo, KemAlgo)>> {
        let (status, resp) = self.request(METHOD_LIST_IDENTITIES, &[]).await?;
        Self::check_status(status, &resp)?;
        let entries: Vec<IdentityEntry> = decode_payload(&resp)?;
        Ok(entries
            .into_iter()
            .map(|e| (e.label, e.service_id, e.privacy, e.outbound_hops, e.scheme, e.signing_algo, e.kem_algo))
            .collect())
    }

    async fn delete_identity(&self, label: &str) -> ApiResult<()> {
        let payload = encode_payload(&label.to_string());
        let (status, resp) = self.request(METHOD_DELETE_IDENTITY, &payload).await?;
        Self::check_status(status, &resp)?;
        Ok(())
    }

    async fn update_identity(
        &self,
        label: &str,
        privacy: PrivacyLevel,
        outbound_hops: u8,
    ) -> ApiResult<(PrivacyLevel, u8)> {
        let payload = encode_payload(&(label.to_string(), privacy, outbound_hops));
        let (status, resp) = self.request(METHOD_UPDATE_IDENTITY, &payload).await?;
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    // ── Daemon info ──

    async fn socks_addr(&self) -> ApiResult<Vec<std::net::SocketAddr>> {
        let (status, resp) = self.request(METHOD_SOCKS_ADDR, &[]).await?;
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    // ── Unified connect ──

    async fn connect_to(&self, target: &str, port: u16) -> ApiResult<Connection> {
        let payload = encode_payload(&(target.to_string(), port));
        let (status, resp) = self.request(METHOD_CONNECT_TO, &payload).await?;
        Self::check_status(status, &resp)?;
        let r: ConnectResp = decode_payload(&resp)?;
        self.make_ipc_connection(r.conn_id, r.remote_service_id, port)
            .await
    }

    // ── Low-level overlay/tunnel ──

    async fn send_data(&self, dest: &PeerId, data: &[u8]) -> ApiResult<()> {
        let req = SendDataReq {
            dest: *dest,
            data: data.to_vec(),
        };
        let payload = encode_payload(&req);
        let (status, resp) = self.request(METHOD_SEND_DATA, &payload).await?;
        Self::check_status(status, &resp)
    }

    async fn create_tunnel(&self, dest: PeerId) -> ApiResult<PeerId> {
        let payload = encode_payload(&dest);
        let (status, resp) = self.request(METHOD_CREATE_TUNNEL, &payload).await?;
        Self::check_status(status, &resp)?;
        decode_payload(&resp)
    }

    async fn send_tunnel_data(&self, dest: &PeerId, data: &[u8]) -> ApiResult<()> {
        let req = SendDataReq {
            dest: *dest,
            data: data.to_vec(),
        };
        let payload = encode_payload(&req);
        let (status, resp) = self.request(METHOD_SEND_TUNNEL_DATA, &payload).await?;
        Self::check_status(status, &resp)
    }
}
