use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

use crate::error::{ApiError, ApiResult};
use crate::types::{DhtId, PeerId, ServiceId};

/// A single entry returned from a signed DHT get.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtEntry {
    pub signer: PeerId,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Simplified hello record for the API surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloInfo {
    pub peer_id: PeerId,
    /// Human-readable capabilities (e.g. "relay, tunnel").
    pub capabilities: String,
    /// Transport names (e.g. "TCP/IPv4", "WebRTC").
    pub transports: Vec<String>,
    /// Introducer peer IDs.
    pub introducers: Vec<PeerId>,
    /// Global addresses as connect strings (e.g. "203.0.113.5:7946").
    pub global_addresses: Vec<String>,
}

/// DHT watch notification delivered to subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEvent {
    pub key: DhtId,
    pub signer: PeerId,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// A TNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TnsRecord {
    /// Terminal: this name IS this identity (A record).
    Identity(ServiceId),
    /// Non-terminal: subnames delegated to this zone (NS record).
    Zone(ServiceId),
    /// Restart resolution with this name (CNAME).
    Alias(String),
    /// Raw content-addressed DHT reference.
    ContentRef(#[serde(with = "crate::types::serde_byte_array_64")] [u8; 64]),
    /// Arbitrary text (like TXT records).
    Text(String),
    /// Introduction point for hidden services.
    IntroductionPoint {
        relay_peer_id: PeerId,
        kem_algo: u8,
        kem_pubkey: Vec<u8>,
    },
    /// Signed peer record for public service discovery.
    /// Allows resolving ServiceId → PeerId without scanning.
    Peer {
        /// The signing algorithm used (Ed25519 or FalconEd25519).
        signing_algo: u8,
        /// Full signing public key (32 bytes for Ed25519, 929 for FalconEd25519).
        signing_pubkey: Vec<u8>,
        /// The PeerId hosting this service.
        peer_id: PeerId,
        /// Signature over `"tarnet peer record" || peer_id` using the service's signing key.
        signature: Vec<u8>,
    },
}

/// The result of a TNS name resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TnsResolution {
    /// Terminal records found.
    Records(Vec<TnsRecord>),
    /// Name not found.
    NotFound,
    /// Resolution failed with an error.
    Error(String),
}

/// Unified event stream from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeEvent {
    /// Incoming overlay data message.
    Data { peer: PeerId, #[serde(with = "serde_bytes")] payload: Vec<u8> },
    /// Incoming tunnel establishment notification.
    Tunnel { peer: PeerId },
    /// DHT watch notification.
    Watch(WatchEvent),
    /// Peer disconnected.
    PeerDisconnected(PeerId),
}

/// A bidirectional connection established via `connect()` or `accept()`.
/// Data is exchanged through an onion circuit with end-to-end tunnel encryption.
pub struct Connection {
    pub remote_service_id: ServiceId,
    pub port: u16,
    /// Unique identifier for this connection (circuit_id internally).
    pub id: u32,
    /// Send data to the remote end.
    tx: mpsc::Sender<Vec<u8>>,
    /// Receive data from the remote end.
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

/// Listener options for inbound service binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ListenerOptions {
    /// Allow overlapping listeners when all matching listeners also opt in.
    pub reuse_port: bool,
}

/// A listener handle returned from `listen()` or `listen_hidden()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    /// Opaque listener handle.
    pub id: u32,
    pub service_id: ServiceId,
    pub port: u16,
    pub options: ListenerOptions,
}

impl Connection {
    pub fn new(
        remote_service_id: ServiceId,
        port: u16,
        id: u32,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            remote_service_id,
            port,
            id,
            tx,
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    /// Send data to the remote end.
    pub async fn send(&self, data: &[u8]) -> ApiResult<()> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|_| ApiError::NotConnected)
    }

    /// Receive data from the remote end.
    pub async fn recv(&self) -> ApiResult<Vec<u8>> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or(ApiError::NotConnected)
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("remote_service_id", &self.remote_service_id)
            .field("port", &self.port)
            .field("id", &self.id)
            .finish()
    }
}

/// A bidirectional byte stream. Implemented by [`Connection`] (onion circuit)
/// and tunnel adapters (PeerId-based), allowing unified I/O handling.
#[async_trait]
pub trait DataStream: Send + Sync {
    /// Send data to the remote end.
    async fn send(&self, data: &[u8]) -> ApiResult<()>;
    /// Receive data from the remote end.
    async fn recv(&self) -> ApiResult<Vec<u8>>;
}

#[async_trait]
impl DataStream for Connection {
    async fn send(&self, data: &[u8]) -> ApiResult<()> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|_| ApiError::NotConnected)
    }

    async fn recv(&self) -> ApiResult<Vec<u8>> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(ApiError::NotConnected)
    }
}

/// The one API. Everyone uses this — daemon internals, IPC clients, tests.
///
/// Two implementations exist:
/// - `LocalServiceApi` (in tarnetd): wraps `Node` directly, zero-copy
/// - `IpcServiceApi` (in tarnet-client): serializes over Unix socket
///
/// Built-in services and external apps get the same trait.
/// No privileged access, no API divergence.
#[async_trait]
pub trait ServiceApi: Send + Sync {
    // ── Identity ──

    /// Our peer ID (Ed25519 public key).
    fn peer_id(&self) -> PeerId;

    /// Our default service ID.
    async fn default_service_id(&self) -> ServiceId;

    /// Resolve an identity label or base32 ServiceId string to a ServiceId.
    /// Returns the default ServiceId if the input is empty or "default".
    async fn resolve_identity(&self, label_or_sid: &str) -> ApiResult<ServiceId>;

    // ── Circuit connections (onion-routed, tunnel-encrypted) ──

    /// Connect to a remote service. Builds an onion circuit, establishes a tunnel,
    /// and returns a connection handle.
    async fn connect(&self, service_id: ServiceId, port: u16) -> ApiResult<Connection>;

    /// Connect as a specific source identity. Uses that identity's outbound hop
    /// count for circuit building. If `source_identity` is None, behaves like `connect()`.
    async fn connect_as(
        &self,
        service_id: ServiceId,
        port: u16,
        source_identity: Option<ServiceId>,
    ) -> ApiResult<Connection> {
        // Default implementation ignores source_identity.
        let _ = source_identity;
        self.connect(service_id, port).await
    }

    /// Listen for incoming connections on the given ServiceId and port.
    /// Use `ServiceId::ALL` to accept on any managed ServiceId.
    async fn listen(
        &self,
        service_id: ServiceId,
        port: u16,
        options: ListenerOptions,
    ) -> ApiResult<Listener>;

    /// Accept the next incoming connection for a specific listener.
    /// Blocks until one arrives.
    async fn accept(&self, listener: &Listener) -> ApiResult<Connection>;

    /// Close a listener and release its bind.
    async fn close_listener(&self, listener: &Listener) -> ApiResult<()>;

    /// Combined listen + publish hidden service. Registers the listener and
    /// publishes IntroductionPoint records in a single call.
    async fn listen_hidden(
        &self,
        service_id: ServiceId,
        port: u16,
        num_intro_points: usize,
        options: ListenerOptions,
    ) -> ApiResult<Listener>;

    // ── DHT: content-addressed (anonymous, self-authenticating) ──

    /// Store content in the DHT. Returns the inner hash (BLAKE3 of value).
    async fn dht_put(&self, value: &[u8]) -> DhtId;

    /// Retrieve content by inner hash. Checks local store first, then queries
    /// the network if `timeout_secs > 0`. Returns None if not found.
    async fn dht_get(&self, key: &DhtId, timeout_secs: u32) -> Option<Vec<u8>>;

    // ── DHT: signed content (publisher-authenticated) ──

    /// Store signed content. Returns inner hash.
    async fn dht_put_signed(&self, value: &[u8], ttl_secs: u32) -> DhtId;

    /// Retrieve signed content by inner hash. Returns entries with signer and plaintext.
    /// Checks local store first, queries network if `timeout_secs > 0`.
    async fn dht_get_signed(&self, key: &DhtId, timeout_secs: u32) -> Vec<DhtEntry>;

    // ── DHT: hello records (peer discovery) ──

    /// Look up a peer's hello record. Checks local store first, queries
    /// the network if `timeout_secs > 0`.
    async fn lookup_hello(&self, peer_id: &PeerId, timeout_secs: u32) -> Option<HelloInfo>;

    // ── DHT: watches ──

    /// Watch a DHT key for changes. Notifications arrive on the event stream.
    async fn dht_watch(&self, key: &DhtId, expiration_secs: u32);

    /// Cancel a watch on a DHT key.
    async fn dht_unwatch(&self, key: &DhtId);

    // ── Status ──

    /// List directly connected peers.
    async fn connected_peers(&self) -> Vec<PeerId>;

    /// Dump routing table: (destination, next_hop, cost).
    async fn routing_entries(&self) -> Vec<(PeerId, PeerId, u32)>;

    /// Full node status snapshot (peers, links, DHT, circuits, traffic).
    async fn node_status(&self) -> crate::types::NodeStatus;

    // ── Event stream ──

    /// Subscribe to all daemon events (data, tunnels, watches, disconnects).
    /// Each call creates a new independent subscription.
    async fn subscribe_events(&self) -> ApiResult<mpsc::Receiver<NodeEvent>>;

    // ── TNS: Tarnet Name System ──

    /// Publish a TNS record set for a label in the given identity's zone.
    /// If `identity` is None, uses the default identity.
    /// The string may be an identity label or a base32-encoded ServiceId.
    async fn tns_publish(
        &self,
        identity: Option<&str>,
        label: &str,
        records: Vec<TnsRecord>,
        ttl_secs: u32,
    ) -> ApiResult<()>;

    /// Resolve a dot-separated name starting from a zone.
    async fn tns_resolve(
        &self,
        zone: ServiceId,
        name: &str,
    ) -> ApiResult<TnsResolution>;

    /// Resolve a name relative to the local node's petnames/zone.
    async fn tns_resolve_name(&self, name: &str) -> ApiResult<TnsResolution>;

    /// Set a local label with associated records and publish flag.
    /// If `identity` is None, uses the default identity.
    async fn tns_set_label(&self, identity: Option<&str>, label: &str, records: Vec<TnsRecord>, publish: bool) -> ApiResult<()>;

    /// Get a local label's records and publish flag.
    /// If `identity` is None, uses the default identity.
    async fn tns_get_label(&self, identity: Option<&str>, label: &str) -> ApiResult<Option<(Vec<TnsRecord>, bool)>>;

    /// Remove a local label.
    /// If `identity` is None, uses the default identity.
    async fn tns_remove_label(&self, identity: Option<&str>, label: &str) -> ApiResult<()>;

    /// List all local labels with their records and publish flags.
    /// If `identity` is None, uses the default identity.
    async fn tns_list_labels(&self, identity: Option<&str>) -> ApiResult<Vec<(String, Vec<TnsRecord>, bool)>>;

    // ── Identity management ──

    /// Create a new named identity with the given privacy level, outbound hop count, and key scheme.
    async fn create_identity(
        &self,
        label: &str,
        privacy: crate::types::PrivacyLevel,
        outbound_hops: u8,
        scheme: crate::types::IdentityScheme,
    ) -> ApiResult<ServiceId>;

    /// List all identities: (label, service_id, privacy, outbound_hops, scheme, signing_algo, kem_algo).
    async fn list_identities(&self) -> ApiResult<Vec<(
        String,
        ServiceId,
        crate::types::PrivacyLevel,
        u8,
        crate::types::IdentityScheme,
        crate::types::SigningAlgo,
        crate::types::KemAlgo,
    )>>;

    /// Delete a named identity. Cannot delete the default identity.
    async fn delete_identity(&self, label: &str) -> ApiResult<()>;

    /// Update an identity's privacy level and outbound hop count.
    /// Returns the previous (privacy, outbound_hops) so callers can detect downgrades.
    async fn update_identity(
        &self,
        label: &str,
        privacy: crate::types::PrivacyLevel,
        outbound_hops: u8,
    ) -> ApiResult<(crate::types::PrivacyLevel, u8)>;

    // ── Daemon info ──

    /// Get the daemon's SOCKS proxy bind addresses.
    /// Returns empty vec if SOCKS proxy is disabled.
    async fn socks_addr(&self) -> ApiResult<Vec<std::net::SocketAddr>>;

    // ── Unified connect (string-based target resolution) ──

    /// Connect to a target identified by string. The daemon resolves the target:
    /// - ServiceId (Crockford Base32)
    /// - PeerId (hex) — derives ServiceId via from_signing_pubkey
    /// - TNS name (petname or dotted name)
    /// Then builds a circuit to the resolved ServiceId.
    async fn connect_to(&self, target: &str, port: u16) -> ApiResult<Connection>;

    // ── Low-level overlay/tunnel (advanced use only) ──

    /// Send data to a peer through the overlay network (plaintext, routed).
    async fn send_data(&self, dest: &PeerId, payload: &[u8]) -> ApiResult<()>;

    /// Create an encrypted tunnel to a remote peer. Returns peer ID on success.
    async fn create_tunnel(&self, dest: PeerId) -> ApiResult<PeerId>;

    /// Send data through an established tunnel.
    async fn send_tunnel_data(&self, dest: &PeerId, data: &[u8]) -> ApiResult<()>;
}
