use async_trait::async_trait;
use serde::{Deserialize, Serialize};
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

/// How a node participates in a pool locally. (See memory: resource pool design.)
/// Phase 1 supports `Closed` only; `Open` (Kpub + membership certs) lands in Phase 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoolKind {
    /// Private pool keyed by a shared symmetric key distributed out-of-band.
    /// Membership = possessing the key; the registry is unguessable/unlistable.
    Closed { key: [u8; 32] },
}

/// Handle returned by `pool_register`, used to withdraw the claim later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolClaim {
    pub pool: String,
    pub service: String,
    pub signer: ServiceId,
}

/// One live endpoint for a pool service (one per distinct owner/signer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolEndpoint {
    pub owner: ServiceId,
    /// Listener port-name to connect to on the owner.
    pub port: String,
    pub weight: u16,
    #[serde(with = "serde_bytes")]
    pub meta: Vec<u8>,
    /// Routing hint carried from the claim's embedded Peer record, if present.
    pub peer_id: Option<PeerId>,
}

/// Options for advertising a pool endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolRegisterOptions {
    pub weight: u16,
    #[serde(with = "serde_bytes")]
    pub meta: Vec<u8>,
    pub ttl_secs: u32,
}

impl Default for PoolRegisterOptions {
    fn default() -> Self {
        Self {
            weight: 1,
            meta: Vec::new(),
            ttl_secs: 45,
        }
    }
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
    /// Terminal, singular service endpoint. Stores the serving ServiceId to
    /// connect to. Unlike `Identity` (which asserts "this name IS this entity"
    /// and signs), a VHost names a *connectable endpoint*: the wire port is
    /// derived from the record's canonical label (its position in the home
    /// zone) so knowing the serving SID alone never yields the port. Like
    /// `Zone`, a VHost must be the sole non-supplemental record at its label.
    VHost(ServiceId),
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
    /// A pool endpoint's offer for a named service ("virtual cluster" member).
    /// Published into a pool zone alongside Identity(owner) + Peer{owner→peer_id},
    /// stored supplementally so every member that owns the service coexists.
    /// Multiplicity of Service records at a label is the load-balancing signal.
    Service {
        /// Listener port-name to connect to on the owner (the service label, by convention).
        port: String,
        /// Weight for weighted round-robin; default 1.
        weight: u16,
        /// Opaque descriptor, e.g. b"llama-3.1-8b".
        #[serde(with = "serde_bytes")]
        meta: Vec<u8>,
    },
}

/// Context for the VHost wire-port derivation key.
const VHOST_LABEL_CTX: &str = "tarnet/vhost/label/v1";

/// Derive the opaque wire port for a VHost endpoint from its canonical label
/// and the connector's supplied port.
///
/// Two-stage MAC chain, each stage consuming exactly one variable-length input,
/// so there is no concatenation boundary to alias: `("ab","c")` and `("a","bc")`
/// derive distinct ports. Stage 1 derives a per-label key; stage 2 keys a hash
/// of the supplied port. The result is a 64-char lowercase hex string used as
/// the circuit demux port — it is one-way (a connection arriving on it cannot be
/// reversed to label or port) and never surfaces to a human.
///
/// Both the connector (deriving where to dial) and the publisher (deciding which
/// derived port to listen on) call this with the same `(canonical_label,
/// supplied_port)` and arrive at the identical wire port. The apex is not
/// special: it uses canonical label `"@"`.
pub fn vhost_wire_port(canonical_label: &str, supplied_port: &str) -> String {
    let label_key = blake3::derive_key(VHOST_LABEL_CTX, canonical_label.as_bytes());
    blake3::keyed_hash(&label_key, supplied_port.as_bytes())
        .to_hex()
        .to_string()
}

/// The result of a TNS name resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TnsResolution {
    /// Terminal records found.
    Records(Vec<TnsRecord>),
    /// A VHost endpoint: the serving identity to connect to, plus the canonical
    /// label (the record's authoritative position in its home zone) from which
    /// the wire port is derived. Surfaced separately from `Records` because the
    /// canonical label is read from resolution position, not from the record.
    VHost {
        serving: ServiceId,
        canonical_label: String,
    },
    /// Name not found.
    NotFound,
    /// Resolution failed with an error.
    Error(String),
}

/// Unified event stream from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeEvent {
    /// Incoming overlay data message.
    Data {
        peer: PeerId,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
    /// Incoming tunnel establishment notification.
    Tunnel { peer: PeerId },
    /// DHT watch notification.
    Watch(WatchEvent),
    /// Peer disconnected.
    PeerDisconnected(PeerId),
}

/// Delivery semantics for a bound Tarnet port.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortMode {
    ReliableOrdered,
    ReliableUnordered,
    UnreliableUnordered,
}

/// A bidirectional connection established via `connect()` or `accept()`.
/// Data is exchanged as whole messages with mode-defined delivery guarantees.
pub struct Connection {
    pub remote_service_id: ServiceId,
    pub mode: PortMode,
    pub port: String,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    /// Opaque listener handle.
    pub id: u32,
    pub service_id: ServiceId,
    pub mode: PortMode,
    pub port: String,
    pub options: ListenerOptions,
}

impl Connection {
    pub fn new(
        remote_service_id: ServiceId,
        mode: PortMode,
        port: String,
        id: u32,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            remote_service_id,
            mode,
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
        rx.recv().await.ok_or(ApiError::NotConnected)
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("remote_service_id", &self.remote_service_id)
            .field("mode", &self.mode)
            .field("port", &self.port)
            .field("id", &self.id)
            .finish()
    }
}

/// A bidirectional message channel. Implemented by [`Connection`] (onion circuit)
/// and tunnel adapters (PeerId-based), allowing unified I/O handling.
#[async_trait]
pub trait MessageStream: Send + Sync {
    /// Send data to the remote end.
    async fn send(&self, data: &[u8]) -> ApiResult<()>;
    /// Receive one whole message from the remote end.
    async fn recv(&self) -> ApiResult<Vec<u8>>;
}

#[async_trait]
impl MessageStream for Connection {
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
    async fn connect(
        &self,
        service_id: ServiceId,
        mode: PortMode,
        port: &str,
    ) -> ApiResult<Connection>;

    /// Connect as a specific source identity. Uses that identity's outbound hop
    /// count for circuit building. If `source_identity` is None, behaves like `connect()`.
    async fn connect_as(
        &self,
        service_id: ServiceId,
        mode: PortMode,
        port: &str,
        source_identity: Option<ServiceId>,
    ) -> ApiResult<Connection> {
        // Default implementation ignores source_identity.
        let _ = source_identity;
        self.connect(service_id, mode, port).await
    }

    /// Listen for incoming connections on the given ServiceId and port.
    /// Use `ServiceId::ALL` to accept on any managed ServiceId.
    async fn listen(
        &self,
        service_id: ServiceId,
        mode: PortMode,
        port: &str,
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
        mode: PortMode,
        port: &str,
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
    async fn tns_resolve(&self, zone: ServiceId, name: &str) -> ApiResult<TnsResolution>;

    /// Resolve a name relative to the local node's petnames/zone.
    async fn tns_resolve_name(&self, name: &str) -> ApiResult<TnsResolution>;

    /// Set a local label with associated records and publish flag.
    /// If `identity` is None, uses the default identity.
    async fn tns_set_label(
        &self,
        identity: Option<&str>,
        label: &str,
        records: Vec<TnsRecord>,
        publish: bool,
    ) -> ApiResult<()>;

    /// Get a local label's records and publish flag.
    /// If `identity` is None, uses the default identity.
    async fn tns_get_label(
        &self,
        identity: Option<&str>,
        label: &str,
    ) -> ApiResult<Option<(Vec<TnsRecord>, bool)>>;

    /// Remove a local label.
    /// If `identity` is None, uses the default identity.
    async fn tns_remove_label(&self, identity: Option<&str>, label: &str) -> ApiResult<()>;

    /// List all local labels with their records and publish flags.
    /// If `identity` is None, uses the default identity.
    async fn tns_list_labels(
        &self,
        identity: Option<&str>,
    ) -> ApiResult<Vec<(String, Vec<TnsRecord>, bool)>>;

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
    async fn list_identities(
        &self,
    ) -> ApiResult<
        Vec<(
            String,
            ServiceId,
            crate::types::PrivacyLevel,
            u8,
            crate::types::IdentityScheme,
            crate::types::SigningAlgo,
            crate::types::KemAlgo,
        )>,
    >;

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
    async fn connect_to(&self, target: &str, mode: PortMode, port: &str) -> ApiResult<Connection>;

    // ── Low-level overlay/tunnel (advanced use only) ──

    /// Send data to a peer through the overlay network (plaintext, routed).
    async fn send_data(&self, dest: &PeerId, payload: &[u8]) -> ApiResult<()>;

    /// Create an encrypted tunnel to a remote peer. Returns peer ID on success.
    async fn create_tunnel(&self, dest: PeerId) -> ApiResult<PeerId>;

    /// Send data through an established tunnel.
    async fn send_tunnel_data(&self, dest: &PeerId, data: &[u8]) -> ApiResult<()>;

    /// Connect to a service, optionally using an explicit PeerId routing hint
    /// (e.g. from a pool endpoint claim) to avoid a public peer-record lookup and
    /// to reach members whose identity is not publicly resolvable.
    /// The default implementation ignores the hint and behaves like `connect_as`;
    /// implementations backed by a local node should thread the hint into routing.
    async fn connect_via(
        &self,
        service_id: ServiceId,
        mode: PortMode,
        port: &str,
        peer_hint: Option<PeerId>,
    ) -> ApiResult<Connection> {
        let _ = peer_hint;
        self.connect_as(service_id, mode, port, None).await
    }

    // ── Resource pools (virtual clusters) ──

    /// Import a pool under a local name (out-of-band key material). Returns the pool root.
    async fn pool_join(&self, name: &str, kind: PoolKind) -> ApiResult<ServiceId>;

    /// Forget a joined pool by local name.
    async fn pool_leave(&self, name: &str) -> ApiResult<()>;

    /// List joined pools: (local name, pool root).
    async fn pool_list(&self) -> ApiResult<Vec<(String, ServiceId)>>;

    /// Advertise an endpoint claim for `service` into the pool. The daemon keeps the
    /// lease refreshed until `pool_withdraw`. Returns a withdrawal handle.
    async fn pool_register(
        &self,
        pool: &str,
        service: &str,
        identity: Option<&str>,
        port: &str,
        opts: PoolRegisterOptions,
    ) -> ApiResult<PoolClaim>;

    /// Withdraw a previously registered claim (publishes a tombstone, stops refresh).
    async fn pool_withdraw(&self, claim: PoolClaim) -> ApiResult<()>;

    /// Resolve the live endpoint set for a pool service (one per member).
    async fn pool_resolve(
        &self,
        pool: &str,
        service: &str,
        timeout_secs: u32,
    ) -> ApiResult<Vec<PoolEndpoint>>;

    /// Browse the pool catalog: service names members advertise.
    async fn pool_catalog(&self, pool: &str, timeout_secs: u32) -> ApiResult<Vec<String>>;
}

pub use MessageStream as DataStream;
