use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot, Mutex};


use std::collections::HashSet;

use crate::firewall::{self as firewall, Firewall};
use crate::governor::{Governor, GovernorConfig, Verdict};

use crate::channel::Channel;
use crate::circuit::{
    CircuitAction, CircuitKey, CircuitTable, CongestionWindow, CryptoOp, HopCrypto, HopKey, ReplayWindow,
    OutboundCircuit, CircuitState, RelayCell, RelayCellCommand, CELL_SIZE, CELL_BODY_SIZE, CELL_PAYLOAD_MAX,
    build_extend_payload, parse_extend_payload, build_extended_payload, parse_extended_payload, EXTENDED_FLAG_REACHED,
    build_stream_begin_payload, parse_stream_begin_payload,
    build_introduce_payload, parse_introduce_payload,
    build_rendezvous_establish_payload, parse_rendezvous_establish_payload,
    parse_rendezvous_join_payload,
    build_intro_register_payload, parse_intro_register_payload,
    derive_hop_keys, relay_cell_digest_for_sendme, SENDME_STALL_TIMEOUT,
};
use crate::identity_store::IdentityStore;
use crate::key_exchange::{KexOffer, kex_accept};
use crate::dht::{
    probabilistic_select, random_select, is_k_closest, BloomFilter, DhtRecord, DhtQueryParams,
    DhtStore, DhtWatchTable, KBucketTable, DHT_K,
};
use crate::identity::{self, dht_id_from_peer_id, peer_id_from_signing_pubkey, Keypair};
use crate::link::PeerLink;
use crate::peer_transport::LinkTable;
use crate::pubkey_cache::PubkeyCache;
use crate::routing::dv;
use tarnet_api::types::SigningAlgo;
use crate::routing::RoutingTable;
use crate::state::{PersistedIdentity, PersistedRecord, StateDb, StorageLimits};
use crate::bootstrap;
use crate::transport::Discovery;
use crate::transport::webrtc::WebRtcConnector;
use crate::tunnel::{Tunnel, TunnelTable};
use crate::types::{DhtId, Error, LinkId, PeerId, RecordType, Result, ScopedAddress, TransportType};
use crate::wire::*;

mod circuit;
mod dht;
mod hidden_service;
mod identity_mgmt;
mod tunnel;
mod webrtc;

const ROUTE_AD_INTERVAL: Duration = Duration::from_secs(30);
const ROUTE_EXPIRY: Duration = Duration::from_secs(120);
const DHT_EXPIRY_INTERVAL: Duration = Duration::from_secs(60);
const REPLICATION_INTERVAL: Duration = Duration::from_secs(300);
/// How often to check for retransmissions and dead channels.
const RETRANSMIT_CHECK_INTERVAL: Duration = Duration::from_millis(250);
/// How long query token → previous_hop mappings live.
const QUERY_TOKEN_TTL: Duration = Duration::from_secs(30);
/// Maximum timestamp drift allowed for tunnel key exchange (seconds).
const KEY_EXCHANGE_MAX_DRIFT: u64 = 60;
/// How long seen nonces are cached for replay protection.
const NONCE_CACHE_TTL: Duration = Duration::from_secs(120);
/// How often to run the link keepalive check.
const KEEPALIVE_CHECK_INTERVAL: Duration = Duration::from_secs(15);
/// Send a keepalive if no message received on a link within this duration.
const KEEPALIVE_IDLE_THRESHOLD: Duration = Duration::from_secs(60);
/// Declare a link dead if no message received within this duration.
const KEEPALIVE_DEAD_TIMEOUT: Duration = Duration::from_secs(180);
/// How often to check circuit liveness.
const CIRCUIT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Send circuit padding if no activity within this duration.
const CIRCUIT_IDLE_THRESHOLD: Duration = Duration::from_secs(30);
/// Declare a circuit dead if no activity within this duration.
const CIRCUIT_DEAD_TIMEOUT: Duration = Duration::from_secs(90);
/// Cooldown before building a replacement backup circuit after failover.
const CIRCUIT_REBUILD_COOLDOWN: Duration = Duration::from_secs(5);

/// Info sent when an outbound circuit is dropped, so a background task can
/// handle async cleanup (destroy message, connection teardown, multipath failover).
struct CircuitDropEvent {
    circuit_id: u32,
    first_hop: PeerId,
    first_hop_circuit_id: u32,
}

/// RAII guard stored inside [`ManagedCircuit`].  When the circuit is removed
/// from the map and the `ManagedCircuit` is dropped, this guard fires a
/// cleanup event through the channel.
struct CircuitDropGuard {
    event: Option<CircuitDropEvent>,
    tx: mpsc::UnboundedSender<CircuitDropEvent>,
}

impl Drop for CircuitDropGuard {
    fn drop(&mut self) {
        if let Some(ev) = self.event.take() {
            let _ = self.tx.send(ev);
        }
    }
}

/// Wraps an [`OutboundCircuit`] with an RAII drop guard that triggers async
/// cleanup when the circuit is removed from the map.
pub struct ManagedCircuit {
    pub inner: OutboundCircuit,
    _guard: CircuitDropGuard,
}

impl std::ops::Deref for ManagedCircuit {
    type Target = OutboundCircuit;
    fn deref(&self) -> &OutboundCircuit {
        &self.inner
    }
}

impl std::ops::DerefMut for ManagedCircuit {
    fn deref_mut(&mut self) -> &mut OutboundCircuit {
        &mut self.inner
    }
}

/// Channel lifecycle events delivered to the application.
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// A reliable channel was declared dead (no ACK received within timeout).
    Dead {
        channel_id: u32,
        remote_peer: PeerId,
    },
    /// A peer's link went down — all tunnels/channels to that peer are broken.
    PeerDisconnected {
        peer_id: PeerId,
    },
}

/// Events flowing through the node's internal event loop.
pub enum NodeEvent {
    /// A new authenticated link was established.
    LinkUp(PeerId, Arc<PeerLink>),
    /// A specific link went down.
    LinkDown(PeerId, LinkId),
    /// A decrypted wire message arrived from a peer (with link_id for activity tracking).
    Message(PeerId, LinkId, WireMessage),
}

/// Configuration for a node.
pub struct NodeConfig {
    pub listen_addr: String,
    pub bootstrap_peers: Vec<String>,
    /// Maximum number of inbound (responder) links. 0 = unlimited.
    pub max_inbound: usize,
    /// Maximum number of outbound (initiator) links. 0 = unlimited.
    pub max_outbound: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".into(),
            bootstrap_peers: Vec::new(),
            max_inbound: 128,
            max_outbound: 48,
        }
    }
}

const HELLO_PUBLISH_INTERVAL: Duration = Duration::from_secs(300);
const HELLO_TTL: u32 = 600;

/// How often we check and re-publish hidden service intro points.
/// TNS TTL is 600s; we re-publish well before that.
const HIDDEN_SERVICE_MAINTAIN_INTERVAL: Duration = Duration::from_secs(240);

/// Re-publish hidden service intro points after this many seconds.
/// Must be less than the TNS TTL (600s) to avoid gaps.
const HIDDEN_SERVICE_REPUBLISH_AFTER: Duration = Duration::from_secs(480);

/// Rendezvous point state entry.
struct RendezvousEntry {
    client_circuit_id: u32,
    client_from: PeerId,
    service_circuit_id: Option<u32>,
    service_from: Option<PeerId>,
}

/// A tarnet node: manages transports, links, routing, tunnels, and channels.
pub struct Node {
    pub identity: Arc<Keypair>,
    /// Link limits. 0 = unlimited.
    max_inbound: usize,
    max_outbound: usize,
    links: Arc<Mutex<LinkTable>>,
    routing_table: Arc<Mutex<RoutingTable>>,
    dht_store: Arc<Mutex<DhtStore>>,
    tunnel_table: Arc<Mutex<TunnelTable>>,
    /// Channels: channel_id → (remote_peer, channel)
    channels: Arc<Mutex<HashMap<u32, (PeerId, Channel)>>>,
    event_tx: mpsc::Sender<NodeEvent>,
    event_rx: Mutex<Option<mpsc::Receiver<NodeEvent>>>,
    /// Channel for delivering data to the application layer.
    app_rx: Mutex<Option<mpsc::Receiver<(PeerId, Vec<u8>)>>>,
    app_tx: mpsc::Sender<(PeerId, Vec<u8>)>,
    /// Our advertised global addresses (only Global scope — published in hello).
    global_addrs: Arc<Mutex<Vec<ScopedAddress>>>,
    /// Peers that can introduce us to others (listed in hello).
    introducers: Arc<Mutex<Vec<PeerId>>>,
    /// Monotonically increasing sequence number for hello records.
    hello_sequence: Arc<Mutex<u64>>,
    /// Pending key exchanges: initiator_nonce → (KEM offer, completion notifier, destination peer)
    pending_key_exchanges:
        Arc<Mutex<HashMap<[u8; 32], (KexOffer, oneshot::Sender<PeerId>, PeerId)>>>,
    /// Notifies app when an incoming tunnel is established (peer_id)
    tunnel_notify_tx: mpsc::Sender<PeerId>,
    tunnel_notify_rx: Mutex<Option<mpsc::Receiver<PeerId>>>,
    /// Channel for delivering channel lifecycle events (e.g. channel death) to the app.
    channel_event_tx: mpsc::Sender<ChannelEvent>,
    channel_event_rx: Mutex<Option<mpsc::Receiver<ChannelEvent>>>,
    /// Seen nonces for replay protection (nonce, when_seen)
    seen_nonces: Arc<Mutex<VecDeque<([u8; 32], Instant)>>>,
    /// Remote subscriptions: who wants notifications from us when a watched key changes.
    dht_watches: Arc<Mutex<DhtWatchTable>>,
    /// Keys we are watching locally.
    local_watches: Arc<Mutex<HashSet<[u8; 64]>>>,
    /// Channel for delivering watch notifications to the application.
    dht_watch_tx: mpsc::Sender<(DhtId, DhtRecord)>,
    dht_watch_rx: Mutex<Option<mpsc::Receiver<(DhtId, DhtRecord)>>>,
    /// K-bucket table for DHT routing.
    kbucket: Arc<Mutex<KBucketTable>>,
    /// Query token routing table: maps query_token → (previous_hop, created_at).
    /// Used for anonymous hop-by-hop reply routing for DHT GETs and watch notifications.
    query_tokens: Arc<Mutex<HashMap<[u8; 32], (PeerId, Instant)>>>,
    /// Monotonically increasing sequence number for signed content records.
    signed_content_sequence: Arc<Mutex<u64>>,
    /// Circuit forwarding table.
    circuit_table: Arc<Mutex<CircuitTable>>,
    /// Outbound circuits we initiated (keyed by first_hop_circuit_id).
    /// Wrapped in [`ManagedCircuit`] so dropping triggers automatic cleanup.
    outbound_circuits: Arc<Mutex<HashMap<u32, ManagedCircuit>>>,
    /// Sender half of the circuit-drop cleanup channel.
    circuit_drop_tx: mpsc::UnboundedSender<CircuitDropEvent>,
    /// Receiver half, taken by start() to spawn the cleanup task.
    circuit_drop_rx: Mutex<Option<mpsc::UnboundedReceiver<CircuitDropEvent>>>,
    /// Pending circuit extensions: circuit_id → oneshot sender for CircuitCreated.
    /// Used to wake the telescoping build when a hop confirms.
    pending_circuit_extends: Arc<Mutex<HashMap<u32, oneshot::Sender<Vec<u8>>>>>,
    /// Pending stream connect responses: circuit_id → oneshot (true=connected, false=refused).
    pending_stream_connects: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    /// Pending relay extends: outbound_circuit_id → (inbound_from, inbound_circuit_id).
    /// When a relay sends CircuitCreate on behalf of an EXTEND, this maps the outbound
    /// circuit_id to the inbound circuit so the CircuitCreated reply can be routed back.
    relay_extend_pending: Arc<Mutex<HashMap<u32, (PeerId, u32, bool)>>>,
    /// Backward crypto keying material for circuit hops.
    /// Key: (circuit_id, from_peer) → (backward_key, backward_digest, nonce).
    /// Stored at CREATE time, used when converting Endpoint → Forward on EXTEND.
    hop_backward_keys: Arc<Mutex<HashMap<(u32, PeerId), ([u8; 32], [u8; 32], [u8; 16], u64)>>>,
    /// Active listeners: (ServiceId, port) pairs we accept connections on.
    listeners: Arc<Mutex<Vec<(tarnet_api::types::ServiceId, u16)>>>,
    /// Incoming connections queue (from accept).
    incoming_connections_tx: mpsc::Sender<tarnet_api::service::Connection>,
    incoming_connections_rx: Mutex<Option<mpsc::Receiver<tarnet_api::service::Connection>>>,
    /// Active connection state: circuit_id → (tx for sending data to the circuit).
    connection_data_txs: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    /// Endpoint-side receive congestion windows: circuit_id → CongestionWindow.
    /// Tracks receive credit for inbound DATA cells at circuit endpoints.
    endpoint_congestion: Arc<Mutex<HashMap<u32, CongestionWindow>>>,
    /// Endpoint-side send congestion windows: circuit_id → (CongestionWindow, Notify).
    /// Gates outbound DATA cells from the endpoint back to the initiator.
    /// The Notify wakes the spawned send task when a SENDME arrives.
    endpoint_send_congestion: Arc<Mutex<HashMap<u32, (CongestionWindow, Arc<tokio::sync::Notify>)>>>,
    /// Initiator-side send window notifications: circuit_id → Notify.
    /// Wakes the spawned send task when a SENDME arrives from the endpoint.
    circuit_sendme_notify: Arc<Mutex<HashMap<u32, Arc<tokio::sync::Notify>>>>,
    /// Rendezvous point state: cookie → RendezvousEntry
    rendezvous_table: Arc<Mutex<HashMap<[u8; 32], RendezvousEntry>>>,
    /// Introduction point registrations: circuit_id → registered ServiceId
    intro_registrations: Arc<Mutex<HashMap<u32, (tarnet_api::types::ServiceId, PeerId)>>>,
    /// Circuits we built TO intro points for our hidden services
    /// Maps service_id → Vec<(intro_peer_id, circuit_id)>
    hidden_service_intros: Arc<Mutex<HashMap<tarnet_api::types::ServiceId, Vec<(PeerId, u32)>>>>,
    /// Tracks when each hidden service was last successfully published.
    hidden_service_last_publish: Arc<Mutex<HashMap<tarnet_api::types::ServiceId, Instant>>>,
    /// Identity store: named keypairs with privacy levels.
    identity_store: Arc<Mutex<IdentityStore>>,
    /// Multipath circuit groups: destination → CircuitGroup.
    circuit_groups: Arc<Mutex<crate::multipath::CircuitGroupTable>>,
    /// WebRTC connection coordinator (None if WebRTC is disabled).
    webrtc_connector: Option<Arc<WebRtcConnector>>,
    /// Per-channel data handlers: channel_id → sender for data on that channel.
    /// Channels with a handler deliver data here instead of app_tx.
    channel_data_handlers: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Port listeners: port_hash → sender that receives (peer_id, channel_id, data_rx)
    /// when a new channel opens on that port.
    channel_port_listeners: Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<(PeerId, u32, mpsc::UnboundedReceiver<Vec<u8>>)>>>>,
    /// Cache of peer signing/KEM public keys (populated during link handshake).
    pubkey_cache: Arc<Mutex<PubkeyCache>>,
    /// Persistent write-through database (None for ephemeral/test nodes).
    db: Option<Arc<StateDb>>,
    /// Whether to announce on mainline DHT (set via enable_mainline).
    #[cfg(feature = "mainline-bootstrap")]
    mainline_enabled: bool,
    /// Optional stateful firewall for inbound message filtering.
    firewall: Mutex<Option<Firewall>>,
    /// Resource governor: per-link-peer budgeting, strike system, circuit rate limiting.
    /// Always-on core infrastructure (unlike the optional firewall).
    governor: Mutex<Governor>,
    /// Per-circuit relay cell queues: ensures cells on the same circuit are
    /// processed in FIFO order rather than racing in spawned tasks.
    /// Key: (circuit_id, from_peer) → sender into that circuit's processing task.
    circuit_relay_queues: Arc<Mutex<HashMap<(u32, PeerId), mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Lock-free statistics registry shared across all subsystems.
    pub stats: Arc<crate::stats::StatsRegistry>,
    /// Global bandwidth limiter shared across all links.
    bandwidth: Arc<crate::bandwidth::BandwidthLimiter>,
    /// Node start time for uptime calculation.
    started_at: std::time::Instant,
    /// TNS resolution cache: avoids repeated DHT lookups for recently resolved names.
    tns_cache: Arc<Mutex<crate::tns::TnsCache>>,
}

/// Restore a Keypair from persisted identity data.
/// Handles both v2 (full key material) and v1 (Ed25519 seed only) formats.
fn restore_keypair_from_persisted(entry: &crate::state::PersistedIdentity) -> Keypair {
    // Try full key material first (v2 format stored by IdentityKeypair::to_bytes)
    if let Ok(kp) = Keypair::from_full_bytes(&entry.signing_key_material) {
        return kp;
    }
    // Current persisted state stores signing/KEM material in separate columns.
    // Reassemble the full serialized identity before falling back to legacy v1 seeds.
    if !entry.kem_key_material.is_empty() {
        let signing_len = match u16::try_from(entry.signing_key_material.len()) {
            Ok(len) => len,
            Err(_) => panic!("persisted signing key material too large"),
        };
        let kem_len = match u16::try_from(entry.kem_key_material.len()) {
            Ok(len) => len,
            Err(_) => panic!("persisted KEM key material too large"),
        };
        let mut full = Vec::with_capacity(
            4 + entry.signing_key_material.len() + entry.kem_key_material.len(),
        );
        full.extend_from_slice(&signing_len.to_be_bytes());
        full.extend_from_slice(&entry.signing_key_material);
        full.extend_from_slice(&kem_len.to_be_bytes());
        full.extend_from_slice(&entry.kem_key_material);
        if let Ok(kp) = Keypair::from_full_bytes(&full) {
            return kp;
        }
    }
    // Fall back to extracting Ed25519 seed (v1 migration: algo byte + 32-byte seed)
    let mut seed = [0u8; 32];
    if entry.signing_key_material.len() >= 33 {
        seed.copy_from_slice(&entry.signing_key_material[1..33]);
    } else if entry.signing_key_material.len() == 32 {
        seed.copy_from_slice(&entry.signing_key_material);
    }
    #[allow(deprecated)] // Intentional: v1 migration from bare Ed25519 seed
    Keypair::from_bytes(seed)
}

impl Node {
    pub fn new(identity: Keypair) -> Self {
        Self::build(identity, Vec::new(), Vec::new(), 0, 0, StorageLimits::default(), None)
    }

    /// Create a node backed by a persistent `StateDb`.
    /// Loads identities, DHT records, and metadata from the database.
    pub fn with_db(
        identity: Keypair,
        db: Arc<StateDb>,
        storage_limits: StorageLimits,
    ) -> Self {
        let identities = db.load_identities().unwrap_or_default();
        let dht_records = db.load_dht_records().unwrap_or_default();
        let hello_seq = db.get_metadata("hello_sequence").unwrap_or(None).unwrap_or(0);
        let sc_seq = db.get_metadata("signed_content_sequence").unwrap_or(None).unwrap_or(0);

        Self::build(identity, identities, dht_records, hello_seq, sc_seq, storage_limits, Some(db))
    }

    fn build(
        identity: Keypair,
        identities: Vec<PersistedIdentity>,
        dht_records: Vec<PersistedRecord>,
        hello_seq: u64,
        sc_seq: u64,
        storage_limits: StorageLimits,
        db: Option<Arc<StateDb>>,
    ) -> Self {
        let peer_id = identity.peer_id();
        let identity_store = if identities.is_empty() {
            let default_kp = Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap();
            // Persist default identity on first run
            if let Some(ref db) = db {
                let pi = PersistedIdentity {
                    label: "default".to_string(),
                    scheme: default_kp.scheme() as u8,
                    signing_key_material: default_kp.identity.signing.to_bytes(),
                    kem_key_material: default_kp.identity.kem.to_bytes(),
                    signing_algo: default_kp.identity.signing_algo() as u8,
                    kem_algo: default_kp.identity.kem_algo() as u8,
                    privacy: tarnet_api::types::PrivacyLevel::Public,
                    outbound_hops: 1,
                    is_default: true,
                };
                let _ = db.save_identity(&pi);
            }
            IdentityStore::with_default(default_kp, tarnet_api::types::PrivacyLevel::Public, 1)
        } else {
            let default_entry = identities.iter().find(|i| i.is_default)
                .or_else(|| identities.first());
            match default_entry {
                Some(entry) => {
                    let kp = restore_keypair_from_persisted(entry);
                    let mut store = IdentityStore::with_default(kp, entry.privacy, entry.outbound_hops);
                    for id in &identities {
                        if id.is_default || id.label == "default" {
                            continue;
                        }
                        let kp = restore_keypair_from_persisted(id);
                        let full_bytes = kp.to_full_bytes();
                        let _ = store.import(&id.label, &full_bytes, id.privacy, id.outbound_hops);
                    }
                    store
                }
                None => {
                    let default_kp = Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap();
                    IdentityStore::with_default(default_kp, tarnet_api::types::PrivacyLevel::Public, 1)
                }
            }
        };
        let (event_tx, event_rx) = mpsc::channel(256);
        let (app_tx, app_rx) = mpsc::channel(256);
        let (tunnel_notify_tx, tunnel_notify_rx) = mpsc::channel(256);
        let (dht_watch_tx, dht_watch_rx) = mpsc::channel(256);
        let (channel_event_tx, channel_event_rx) = mpsc::channel(256);
        let (incoming_conn_tx, incoming_conn_rx) = mpsc::channel(64);
        let (circuit_drop_tx, circuit_drop_rx) = mpsc::unbounded_channel();
        let mut dht_store = DhtStore::with_limits(&peer_id, storage_limits);
        dht_store.import_records(dht_records);
        Self {
            identity: Arc::new(identity),
            max_inbound: 128,
            max_outbound: 48,
            links: Arc::new(Mutex::new(LinkTable::new())),
            routing_table: Arc::new(Mutex::new(RoutingTable::new(peer_id))),
            dht_store: Arc::new(Mutex::new(dht_store)),
            tunnel_table: Arc::new(Mutex::new(TunnelTable::new())),
            channels: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            app_rx: Mutex::new(Some(app_rx)),
            app_tx,
            global_addrs: Arc::new(Mutex::new(Vec::new())),
            introducers: Arc::new(Mutex::new(Vec::new())),
            hello_sequence: Arc::new(Mutex::new(hello_seq)),
            pending_key_exchanges: Arc::new(Mutex::new(HashMap::new())),
            tunnel_notify_tx,
            tunnel_notify_rx: Mutex::new(Some(tunnel_notify_rx)),
            channel_event_tx,
            channel_event_rx: Mutex::new(Some(channel_event_rx)),
            seen_nonces: Arc::new(Mutex::new(VecDeque::new())),
            dht_watches: Arc::new(Mutex::new(DhtWatchTable::new())),
            local_watches: Arc::new(Mutex::new(HashSet::new())),
            dht_watch_tx,
            dht_watch_rx: Mutex::new(Some(dht_watch_rx)),
            kbucket: Arc::new(Mutex::new(KBucketTable::new(&peer_id))),
            query_tokens: Arc::new(Mutex::new(HashMap::new())),
            signed_content_sequence: Arc::new(Mutex::new(sc_seq)),
            circuit_table: Arc::new(Mutex::new(CircuitTable::new())),
            circuit_drop_tx,
            circuit_drop_rx: Mutex::new(Some(circuit_drop_rx)),
            outbound_circuits: Arc::new(Mutex::new(HashMap::new())),
            pending_circuit_extends: Arc::new(Mutex::new(HashMap::new())),
            pending_stream_connects: Arc::new(Mutex::new(HashMap::new())),
            relay_extend_pending: Arc::new(Mutex::new(HashMap::new())),
            hop_backward_keys: Arc::new(Mutex::new(HashMap::new())),
            listeners: Arc::new(Mutex::new(Vec::new())),
            incoming_connections_tx: incoming_conn_tx,
            incoming_connections_rx: Mutex::new(Some(incoming_conn_rx)),
            connection_data_txs: Arc::new(Mutex::new(HashMap::new())),
            endpoint_congestion: Arc::new(Mutex::new(HashMap::new())),
            endpoint_send_congestion: Arc::new(Mutex::new(HashMap::new())),
            circuit_sendme_notify: Arc::new(Mutex::new(HashMap::new())),
            rendezvous_table: Arc::new(Mutex::new(HashMap::new())),
            intro_registrations: Arc::new(Mutex::new(HashMap::new())),
            hidden_service_intros: Arc::new(Mutex::new(HashMap::new())),
            hidden_service_last_publish: Arc::new(Mutex::new(HashMap::new())),
            identity_store: Arc::new(Mutex::new(identity_store)),
            circuit_groups: Arc::new(Mutex::new(crate::multipath::CircuitGroupTable::new())),
            webrtc_connector: None,
            channel_data_handlers: Arc::new(Mutex::new(HashMap::new())),
            channel_port_listeners: Arc::new(Mutex::new(HashMap::new())),
            pubkey_cache: Arc::new(Mutex::new(PubkeyCache::new(1024))),
            db,
            #[cfg(feature = "mainline-bootstrap")]
            mainline_enabled: false,
            firewall: Mutex::new(None),
            governor: Mutex::new(Governor::new(GovernorConfig::default())),
            circuit_relay_queues: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(crate::stats::StatsRegistry::new()),
            bandwidth: Arc::new(crate::bandwidth::BandwidthLimiter::new(0, 0)),
            started_at: std::time::Instant::now(),
            tns_cache: Arc::new(Mutex::new(crate::tns::TnsCache::new())),
        }
    }

    /// Persist a DHT record to the database (if present).
    fn db_upsert_dht_record(&self, record: &DhtRecord) {
        if let Some(db) = &self.db {
            if let Some(pr) = PersistedRecord::from_live(record) {
                if let Err(e) = db.upsert_dht_record(&pr) {
                    log::warn!("Failed to persist DHT record: {}", e);
                }
            }
        }
    }

    /// Persist a metadata value to the database (if present).
    fn db_set_metadata(&self, key: &str, value: u64) {
        if let Some(db) = &self.db {
            if let Err(e) = db.set_metadata(key, value) {
                log::warn!("Failed to persist metadata '{}': {}", key, e);
            }
        }
    }

    /// Return a reference to the backing StateDb (if any).
    pub fn state_db(&self) -> Option<&Arc<StateDb>> {
        self.db.as_ref()
    }

    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// Access the TNS resolution cache.
    pub fn tns_cache(&self) -> &Arc<Mutex<crate::tns::TnsCache>> {
        &self.tns_cache
    }

    /// Install a firewall.  Replaces any previously installed firewall.
    pub async fn set_firewall(&self, fw: Firewall) {
        *self.firewall.lock().await = Some(fw);
    }

    /// Remove the firewall (accept-all).
    pub async fn clear_firewall(&self) {
        *self.firewall.lock().await = None;
    }

    /// Access the firewall for live rule manipulation.
    /// Returns `None` if no firewall is installed.
    pub async fn with_firewall<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut Firewall) -> R,
    {
        self.firewall.lock().await.as_mut().map(f)
    }


    /// Wrap an [`OutboundCircuit`] with an RAII drop guard so that removing it
    /// from the map automatically triggers async cleanup.
    fn manage_circuit(&self, circuit_id: u32, circuit: OutboundCircuit) -> ManagedCircuit {
        ManagedCircuit {
            _guard: CircuitDropGuard {
                event: Some(CircuitDropEvent {
                    circuit_id,
                    first_hop: circuit.first_hop,
                    first_hop_circuit_id: circuit.first_hop_circuit_id,
                }),
                tx: self.circuit_drop_tx.clone(),
            },
            inner: circuit,
        }
    }

    /// The node's default ServiceId.
    pub async fn default_service_id(&self) -> tarnet_api::types::ServiceId {
        self.identity_store.lock().await.default_service_id()
    }

    /// Look up a keypair by ServiceId. Returns None if no matching identity exists.
    pub async fn keypair_for_service(&self, sid: &tarnet_api::types::ServiceId) -> Option<Keypair> {
        self.identity_store.lock().await.keypair_for(sid).map(|kp| Keypair::from_full_bytes(&kp.to_full_bytes()).unwrap())
    }

    /// The node's default ServiceId as raw bytes (52 bytes: pubkey + hash).
    pub async fn default_service_address(&self) -> [u8; 32] {
        self.identity_store.lock().await.default_service_id().0
    }

    /// Get a clone of the event sender for injecting LinkUp/LinkDown events from outside.
    pub fn event_sender(&self) -> mpsc::Sender<NodeEvent> {
        self.event_tx.clone()
    }

    /// Get a clone of the identity keypair.
    pub fn identity_clone(&self) -> Arc<Keypair> {
        self.identity.clone()
    }

    /// Start the node: listen for connections, connect to bootstrap peers, run event loop.
    /// `bootstrap` lists transport URIs (e.g. `tcp://host:port`, `ws://host/path`).
    /// `discovery_addrs` lists discovery URIs (e.g. `mainline:<hex>`) that resolve to transport addresses.
    pub async fn run(self: Arc<Self>, discovery: Box<dyn Discovery>, bootstrap: Vec<String>, discovery_addrs: Vec<String>) -> Result<()> {
        let discovery = Arc::new(discovery);

        // Start accepting connections
        let disc_accept = discovery.clone();
        let event_tx = self.event_tx.clone();
        let identity = self.identity.clone();
        tokio::spawn(async move {
            loop {
                match disc_accept.accept().await {
                    Ok(transport) => {
                        let tx = event_tx.clone();
                        let id = identity.clone();
                        tokio::spawn(async move {
                            match PeerLink::responder(transport, &id).await {
                                Ok(link) => {
                                    let link = Arc::new(link);
                                    let _ = tx
                                        .send(NodeEvent::LinkUp(link.remote_peer(), link.clone()))
                                        .await;
                                }
                                Err(e) => {
                                    log::warn!("Handshake failed (responder): {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        // Connect to bootstrap peers — persistent retry with backoff.
        // Each peer gets its own retry loop so one slow/offline peer doesn't
        // block connecting to others. Once connected, stop retrying that peer
        // but keep the loop alive to reconnect if the link drops later.
        if !bootstrap.is_empty() {
            let links_ref = self.links.clone();
            let disc = discovery.clone();
            let tx = self.event_tx.clone();
            let identity = self.identity.clone();
            tokio::spawn(async move {
                bootstrap_retry_loop(bootstrap, disc, tx, identity, links_ref).await;
            });
        }

        // Discovery addresses resolve via external protocols (mainline DHT, etc.)
        // then connect via the appropriate transport.
        if !discovery_addrs.is_empty() {
            let links_ref = self.links.clone();
            let disc = discovery.clone();
            let tx = self.event_tx.clone();
            let identity = self.identity.clone();
            tokio::spawn(async move {
                discovery_retry_loop(discovery_addrs, disc, tx, identity, links_ref).await;
            });
        }

        // WebRTC signaling listener: accept incoming signaling on channel ports.
        if self.webrtc_connector.is_some() {
            self.start_webrtc_signaling_listener().await;
        }

        // WebRTC auto-upgrade: periodically try to establish direct WebRTC
        // links to peers we can only reach via relay (cost > 1).
        if self.webrtc_connector.is_some() {
            let node = self.clone();
            tokio::spawn(async move {
                let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    node.try_webrtc_upgrades(&mut cooldown).await;
                }
            });
        }

        // Proactive outbound fill: if we have spare outbound slots, connect
        // to peers from the k-bucket by looking up their Hello records.
        if self.max_outbound > 0 {
            let node = self.clone();
            let disc = discovery.clone();
            tokio::spawn(async move {
                // Wait for initial bootstrap to settle
                tokio::time::sleep(Duration::from_secs(30)).await;
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    node.try_fill_outbound_links(&disc).await;
                }
            });
        }

        // Hidden service maintenance: periodically ensure all Hidden identities
        // have active intro points published.
        {
            let node = self.clone();
            tokio::spawn(async move {
                // Wait for bootstrap to settle before first publish
                tokio::time::sleep(Duration::from_secs(15)).await;
                node.maintain_hidden_services().await;
                let mut interval =
                    tokio::time::interval(HIDDEN_SERVICE_MAINTAIN_INTERVAL);
                loop {
                    interval.tick().await;
                    node.maintain_hidden_services().await;
                }
            });
        }

        // Peer record maintenance: periodically publish peer records for public identities.
        {
            let node = self.clone();
            tokio::spawn(async move {
                // Wait for bootstrap to settle before first publish
                tokio::time::sleep(Duration::from_secs(15)).await;
                node.maintain_peer_records().await;
                let mut interval =
                    tokio::time::interval(HIDDEN_SERVICE_MAINTAIN_INTERVAL);
                loop {
                    interval.tick().await;
                    node.maintain_peer_records().await;
                }
            });
        }

        // Register listeners for all identities so incoming StreamBegin is accepted
        {
            let identities = self.list_identities().await;
            for (_, sid, _, _, _, _, _) in &identities {
                let _ = self.circuit_listen(*sid, 0).await;
            }
        }

        // Run the event loop
        self.event_loop(self.clone()).await
    }

    /// Attempt WebRTC upgrades to peers reachable only via relay.
    async fn try_webrtc_upgrades(&self, cooldown: &mut HashMap<PeerId, Instant>) {
        let cooldown_duration = Duration::from_secs(300); // 5 minutes

        // Collect peers with cost > 1 (relay-only)
        let candidates: Vec<PeerId> = {
            let table = self.routing_table.lock().await;
            table
                .all_destinations()
                .filter(|(_, route)| route.cost > 1)
                .map(|(pid, _)| *pid)
                .collect()
        };

        // Filter out peers we already have direct links to
        let links = self.links.lock().await;
        let candidates: Vec<PeerId> = candidates
            .into_iter()
            .filter(|pid| !links.contains_key(pid))
            .collect();
        drop(links);

        for peer_id in candidates {
            // Respect cooldown
            if let Some(last) = cooldown.get(&peer_id) {
                if last.elapsed() < cooldown_duration {
                    continue;
                }
            }

            // Check if peer's hello record advertises WebRTC
            if let Some(hello) = self.lookup_hello(&peer_id).await {
                if hello.transports.contains(&TransportType::WebRtc) {
                    log::info!("Attempting WebRTC upgrade to {:?}", peer_id);
                    cooldown.insert(peer_id, Instant::now());
                    if let Err(e) = self.connect_webrtc(peer_id).await {
                        log::debug!("WebRTC upgrade to {:?} failed: {}", peer_id, e);
                    }
                }
            }
        }
    }

    /// Proactively fill outbound link slots by connecting to known peers.
    /// Picks candidates from the k-bucket that we don't already have a link to,
    /// looks up their Hello record for connectable addresses, and tries to connect.
    async fn try_fill_outbound_links(&self, discovery: &Arc<Box<dyn Discovery>>) {
        let outbound_count = self.links.lock().await.outbound_count();
        if self.max_outbound > 0 && outbound_count >= self.max_outbound {
            return;
        }
        let slots = if self.max_outbound > 0 {
            self.max_outbound - outbound_count
        } else {
            return; // unlimited — don't proactively fill
        };

        // Gather k-bucket peers we don't have direct links to
        let candidates: Vec<PeerId> = {
            let kb = self.kbucket.lock().await;
            let links = self.links.lock().await;
            kb.all_peers()
                .into_iter()
                .map(|(pid, _)| pid)
                .filter(|pid| !links.contains_key(pid))
                .take(slots)
                .collect()
        };

        for peer_id in candidates {
            if let Some(hello) = self.lookup_hello(&peer_id).await {
                for addr in &hello.global_addresses {
                    if let Some(addr_str) = addr.to_connect_string() {
                        match discovery.connect(&addr_str).await {
                            Ok(transport) => {
                                match PeerLink::initiator(transport, &self.identity, Some(peer_id)).await {
                                    Ok(link) => {
                                        let link = Arc::new(link);
                                        log::info!(
                                            "Proactive outbound link to {:?} via {}",
                                            link.remote_peer(), addr_str,
                                        );
                                        let _ = self
                                            .event_tx
                                            .send(NodeEvent::LinkUp(link.remote_peer(), link))
                                            .await;
                                        break; // one link per peer is enough
                                    }
                                    Err(e) => {
                                        log::debug!(
                                            "Proactive handshake to {:?} failed: {}", peer_id, e,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                log::debug!(
                                    "Proactive connect to {:?} at {} failed: {}", peer_id, addr_str, e,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Main event processing loop.
    async fn event_loop(&self, node_arc: Arc<Node>) -> Result<()> {
        let mut event_rx = self
            .event_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::Protocol("event loop already running".into()))?;

        // Periodic route advertisement timer
        let links_ref = self.links.clone();
        let routing_ref = self.routing_table.clone();
        let identity = self.identity.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(ROUTE_AD_INTERVAL);
            loop {
                interval.tick().await;

                // Collect (peer_id, link_arc, encoded_msg) under lock, then release
                // both locks before doing any I/O. Holding locks across send_message
                // (which awaits the per-link crypto lock) starves the message handler.
                let to_send: Vec<(PeerId, Arc<PeerLink>, Vec<u8>)> = {
                    let links = links_ref.lock().await;
                    let table = routing_ref.lock().await;
                    links.iter()
                        .map(|(peer_id, link)| {
                            let ad = dv::generate_advertisement(&identity, &table, peer_id);
                            (*peer_id, link.clone(), ad.to_wire().encode())
                        })
                        .collect()
                };
                for (peer_id, link, msg) in to_send {
                    if let Err(e) = link.send_message(&msg).await {
                        log::warn!("Failed to send route ad to {:?}: {}", peer_id, e);
                    }
                }

                // Also expire old routes
                routing_ref.lock().await.expire(ROUTE_EXPIRY);
            }
        });

        // Periodic link keepalive: send keepalive on idle links, kill dead links
        let ka_links = self.links.clone();
        let ka_event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(KEEPALIVE_CHECK_INTERVAL);
            loop {
                interval.tick().await;
                let links = ka_links.lock().await;

                // Check for dead links first
                let dead = links.dead_links(KEEPALIVE_DEAD_TIMEOUT);
                // Get idle links that need keepalive
                let idle = links.idle_links(KEEPALIVE_IDLE_THRESHOLD);
                drop(links);

                // Fire LinkDown for dead links
                for (peer, link_id) in dead {
                    log::info!(
                        "Link to {:?} (link_id={}) timed out (no recv for {}s), declaring dead",
                        peer, link_id, KEEPALIVE_DEAD_TIMEOUT.as_secs()
                    );
                    let _ = ka_event_tx.send(NodeEvent::LinkDown(peer, link_id)).await;
                }

                // Send keepalive on idle links (that aren't dead)
                let now_us = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64;
                let ka_msg = KeepaliveMsg { timestamp_us: Some(now_us) };
                let encoded = ka_msg.to_wire().encode();
                for (_peer, _link_id, link) in idle {
                    let _ = link.send_message(&encoded).await;
                }
            }
        });

        // Circuit drop cleanup task: handles async work triggered by the RAII
        // drop guard (CircuitDestroy message, connection teardown, multipath failover).
        let cd_links = self.links.clone();
        let cd_groups = self.circuit_groups.clone();
        let cd_conn_txs = self.connection_data_txs.clone();
        let cd_ep_cong = self.endpoint_congestion.clone();
        let cd_ep_send_cong = self.endpoint_send_congestion.clone();
        let cd_sendme_notify = self.circuit_sendme_notify.clone();
        let cd_relay_queues = self.circuit_relay_queues.clone();
        let mut circuit_drop_rx = self
            .circuit_drop_rx
            .lock()
            .await
            .take()
            .expect("circuit drop rx already taken");
        tokio::spawn(async move {
            while let Some(ev) = circuit_drop_rx.recv().await {
                // Send CircuitDestroy to first hop
                let destroy = CircuitDestroyMsg {
                    circuit_id: ev.first_hop_circuit_id,
                };
                let links = cd_links.lock().await;
                if let Some(link) = links.get(&ev.first_hop) {
                    let _ = link.send_message(&destroy.to_wire().encode()).await;
                }
                drop(links);

                // Clean up connection state
                cd_conn_txs.lock().await.remove(&ev.circuit_id);
                cd_ep_cong.lock().await.remove(&ev.circuit_id);
                cd_ep_send_cong.lock().await.remove(&ev.circuit_id);
                cd_sendme_notify.lock().await.remove(&ev.circuit_id);
                cd_relay_queues.lock().await.remove(&(ev.first_hop_circuit_id, ev.first_hop));

                // Handle multipath failover
                let mut groups = cd_groups.lock().await;
                if let Some(group) = groups.find_by_circuit_mut(ev.circuit_id) {
                    let role = group.remove_circuit(ev.circuit_id);
                    if role == Some(crate::multipath::CircuitRole::Primary) {
                        if let Some(new_primary) = group.promote_backup() {
                            log::info!(
                                "Multipath failover: circuit {} promoted to primary for {:?}",
                                new_primary,
                                group.destination,
                            );
                        } else {
                            log::warn!(
                                "Primary circuit {} died with no backup for {:?}",
                                ev.circuit_id,
                                group.destination,
                            );
                        }
                    }
                }
                groups.gc();
            }
        });

        // Periodic circuit keepalive: send padding on idle circuits, destroy dead ones.
        // Actual cleanup (destroy message, failover, connection teardown) is handled
        // automatically by the CircuitDropGuard when circuits are removed from the map.
        let ck_circuits = self.outbound_circuits.clone();
        let ck_links = self.links.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CIRCUIT_KEEPALIVE_INTERVAL);
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut dead_circuits = Vec::new();
                let mut idle_circuits = Vec::new();

                {
                    let circuits = ck_circuits.lock().await;
                    for (&cid, circuit) in circuits.iter() {
                        if circuit.state != CircuitState::Ready {
                            continue;
                        }
                        let elapsed = now.duration_since(circuit.last_activity);
                        if elapsed >= CIRCUIT_DEAD_TIMEOUT {
                            dead_circuits.push(cid);
                        } else if elapsed >= CIRCUIT_IDLE_THRESHOLD {
                            idle_circuits.push(cid);
                        }
                    }
                }

                // Remove dead circuits — the drop guard handles the rest.
                for cid in &dead_circuits {
                    log::info!(
                        "Circuit {} timed out (no activity for {}s), destroying",
                        cid,
                        CIRCUIT_DEAD_TIMEOUT.as_secs()
                    );
                    ck_circuits.lock().await.remove(cid);
                }

                // Send padding on idle circuits
                for cid in &idle_circuits {
                    let mut circuits = ck_circuits.lock().await;
                    if let Some(circuit) = circuits.get_mut(cid) {
                        let padding_cell = RelayCell {
                            command: RelayCellCommand::Padding,
                            stream_id: 0,
                            data: Vec::new(),
                        };
                        let (first_hop, relay_cid, cell) = circuit.send_relay_cell(&padding_cell);
                        drop(circuits);

                        let msg = CircuitRelayMsg {
                            circuit_id: relay_cid,
                            data: cell.to_vec(),
                        };
                        let links = ck_links.lock().await;
                        if let Some(link) = links.get(&first_hop) {
                            let _ = link.send_message(&msg.to_wire().encode()).await;
                        }
                    }
                }
            }
        });

        // Periodic governor tick: decay strikes, update pressure, drain reports.
        let gov_ref = node_arc.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(crate::governor::GOVERNOR_TICK_INTERVAL);
            loop {
                interval.tick().await;
                let ct_len = gov_ref.circuit_table.lock().await.len();
                gov_ref.governor.lock().await.tick(ct_len);
            }
        });

        // Periodic DHT expiry
        let dht_ref = self.dht_store.clone();
        let watches_ref = self.dht_watches.clone();
        let tokens_ref = self.query_tokens.clone();
        let nonces_ref = self.seen_nonces.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(DHT_EXPIRY_INTERVAL);
            loop {
                interval.tick().await;
                dht_ref.lock().await.expire();
                watches_ref.lock().await.expire();
                // Expire stale query token mappings
                let now = Instant::now();
                tokens_ref
                    .lock()
                    .await
                    .retain(|_, (_, created)| now.duration_since(*created) < QUERY_TOKEN_TTL);
                // Expire old seen nonces
                let mut nonces = nonces_ref.lock().await;
                while let Some((_, seen_at)) = nonces.front() {
                    if now.duration_since(*seen_at) >= NONCE_CACHE_TTL {
                        nonces.pop_front();
                    } else {
                        break;
                    }
                }
            }
        });

        // Periodic retransmit check and dead channel detection
        let retransmit_channels = self.channels.clone();
        let retransmit_tunnel_table = self.tunnel_table.clone();
        let retransmit_links = self.links.clone();
        let retransmit_routing = self.routing_table.clone();
        let retransmit_identity = self.identity.clone();
        let retransmit_event_tx = self.channel_event_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RETRANSMIT_CHECK_INTERVAL);
            loop {
                interval.tick().await;

                // Collect retransmit work and dead channels under the channels lock,
                // then release it before doing I/O.
                let (retransmits, dead_channels) = {
                    let mut channels = retransmit_channels.lock().await;
                    let mut retransmits: Vec<(u32, PeerId, Vec<(u32, Vec<u8>)>)> = Vec::new();
                    let mut dead: Vec<(u32, PeerId)> = Vec::new();

                    for (&channel_id, (remote_peer, ch)) in channels.iter_mut() {
                        if ch.is_dead() {
                            dead.push((channel_id, *remote_peer));
                            continue;
                        }
                        let due = ch.retransmit_due();
                        if !due.is_empty() {
                            retransmits.push((channel_id, *remote_peer, due));
                        }
                    }

                    for &(channel_id, _) in &dead {
                        channels.remove(&channel_id);
                    }

                    (retransmits, dead)
                };

                // Notify app of dead channels
                for (channel_id, remote_peer) in &dead_channels {
                    log::info!(
                        "Channel {} to {:?} declared dead (no ACK timeout)",
                        channel_id,
                        remote_peer
                    );
                    let _ = retransmit_event_tx
                        .send(ChannelEvent::Dead {
                            channel_id: *channel_id,
                            remote_peer: *remote_peer,
                        })
                        .await;
                }

                // Send retransmits — re-encrypt each via tunnel (fresh nonce)
                for (channel_id, remote, packets) in retransmits {
                    let tt = retransmit_tunnel_table.lock().await;
                    let tunnel = match tt.get(&remote) {
                        Some(t) => t,
                        None => continue,
                    };
                    let mut encoded_msgs = Vec::new();
                    for (seq, data) in &packets {
                        let channel_data = ChannelDataMsg {
                            channel_id,
                            sequence: *seq,
                            data: data.clone(),
                        };
                        let inner = channel_data.to_wire().encode();
                        let encrypted = tunnel.encrypt(&inner);
                        let msg = EncryptedDataMsg {
                            origin: retransmit_identity.peer_id(),
                            destination: remote,
                            ttl: 64,
                            data: encrypted,
                        };
                        encoded_msgs.push((*seq, msg.to_wire_encrypted().encode()));
                    }
                    drop(tt);

                    // Route each retransmit
                    for (seq, encoded) in encoded_msgs {
                        let links = retransmit_links.lock().await;
                        let result = if let Some(link) = links.get(&remote) {
                            link.send_message(&encoded).await
                        } else {
                            let table = retransmit_routing.lock().await;
                            let next_hop = table.lookup(&remote).map(|r| r.next_hop);
                            drop(table);
                            if let Some(hop) = next_hop {
                                if let Some(link) = links.get(&hop) {
                                    link.send_message(&encoded).await
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        };
                        if result.is_ok() {
                            log::trace!(
                                "Retransmitted ch {} seq {} to {:?}",
                                channel_id,
                                seq,
                                remote
                            );
                        }
                    }
                }
            }
        });

        // Periodic hello record publishing
        let hello_identity = self.identity.clone();
        let hello_global_addrs = self.global_addrs.clone();
        let hello_introducers = self.introducers.clone();
        let hello_dht = self.dht_store.clone();
        let hello_links = self.links.clone();
        let hello_seq = self.hello_sequence.clone();
        let hello_kbucket = self.kbucket.clone();
        let hello_webrtc_enabled = self.webrtc_connector.is_some();
        tokio::spawn(async move {
            // Wait a bit for initial links to establish
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut interval = tokio::time::interval(HELLO_PUBLISH_INTERVAL);
            loop {
                interval.tick().await;
                let peer_id = hello_identity.peer_id();
                let global_addrs = hello_global_addrs.lock().await.clone();
                let introducers = hello_introducers.lock().await.clone();
                let mut transports = collect_transport_types(&global_addrs);
                if hello_webrtc_enabled
                    && !transports.iter().any(|t| *t == TransportType::WebRtc)
                {
                    transports.push(TransportType::WebRtc);
                }
                let hello = HelloRecord {
                    peer_id,
                    capabilities: capabilities::RELAY | capabilities::TUNNEL,
                    transports,
                    introducers,
                    global_addresses: global_addrs,
                };

                let key = crate::dht::identity_address_key(&peer_id);
                let value = hello.to_bytes();
                let mut seq = hello_seq.lock().await;
                *seq += 1;
                let sequence = *seq;
                drop(seq);

                let signer = *peer_id.as_bytes();
                let mut bloom = BloomFilter::new();
                bloom.insert(&peer_id);
                let mut put = DhtPutMsg {
                    key: *key.as_bytes(),
                    record_type: RecordType::Hello,
                    sequence,
                    signer,
                    ttl: HELLO_TTL,
                    value: value.clone(),
                    signature: Vec::new(),
                    signer_algo: hello_identity.identity.signing.algo() as u8,
                    signer_pubkey: hello_identity.identity.signing.signing_pubkey_bytes(),
                    hop_count: 0,
                    hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
                    bloom: bloom.to_bytes(),
                };
                put.signature = hello_identity.sign(&put.signable_bytes());

                let record = crate::dht::DhtRecord {
                    key: key.clone(),
                    record_type: RecordType::Hello,
                    sequence,
                    signer,
                    signer_algo: put.signer_algo,
                    signer_pubkey: put.signer_pubkey.clone(),
                    value,
                    ttl: Duration::from_secs(HELLO_TTL as u64),
                    stored_at: std::time::Instant::now(),
                    signature: put.signature.clone(),
                };
                hello_dht.lock().await.put(record);

                // L2NSE-driven peer selection for hello propagation
                let kb = hello_kbucket.lock().await;
                let all_peers = kb.all_peers();
                let l2nse = kb.estimate_l2nse();
                drop(kb);
                let params = DhtQueryParams::from_l2nse(l2nse);
                put.hop_limit = params.hop_limit;
                let targets = probabilistic_select(&key, &all_peers, params.fan_out);

                let encoded = put.to_wire().encode();
                let links = hello_links.lock().await;
                if targets.is_empty() {
                    // Fallback: send to all neighbors
                    for (_, link) in links.iter() {
                        let _ = link.send_message(&encoded).await;
                    }
                } else {
                    for (pid, _) in &targets {
                        if let Some(link) = links.get(pid) {
                            let _ = link.send_message(&encoded).await;
                        }
                    }
                    // Also send to direct neighbors not in selected set
                    for (pid, link) in links.iter() {
                        if !targets.iter().any(|(p, _)| p == pid) {
                            let _ = link.send_message(&encoded).await;
                        }
                    }
                }
                log::debug!("Refreshed hello record");
            }
        });

        // Periodic replication maintenance
        let repl_dht = self.dht_store.clone();
        let repl_kbucket = self.kbucket.clone();
        let repl_links = self.links.clone();
        let repl_identity = self.identity.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REPLICATION_INTERVAL);
            loop {
                interval.tick().await;
                let store = repl_dht.lock().await;
                let records: Vec<DhtRecord> = store.all_records().into_iter().cloned().collect();
                let local_id = *store.local_id();
                drop(store);

                let kb = repl_kbucket.lock().await;
                let l2nse = kb.estimate_l2nse();
                let repl_params = DhtQueryParams::from_l2nse(l2nse);
                for record in &records {
                    // Check if we're among the k-closest
                    let closest = kb.closest_peers(&record.key, DHT_K);
                    let our_dist = local_id.xor_distance(&record.key);
                    let is_responsible = closest.len() < DHT_K
                        || closest
                            .iter()
                            .any(|(_, did)| record.key.xor_distance(did) >= our_dist);

                    if !is_responsible {
                        continue;
                    }

                    let mut bloom = BloomFilter::new();
                    bloom.insert(&repl_identity.peer_id());
                    let put = DhtPutMsg {
                        key: *record.key.as_bytes(),
                        record_type: record.record_type,
                        sequence: record.sequence,
                        signer: record.signer,
                        ttl: record.ttl.as_secs() as u32,
                        value: record.value.clone(),
                        signature: record.signature.clone(),
                        signer_algo: record.signer_algo,
                        signer_pubkey: record.signer_pubkey.clone(),
                        hop_count: 0,
                        hop_limit: repl_params.hop_limit,
                        bloom: bloom.to_bytes(),
                    };
                    let encoded = put.to_wire().encode();

                    let links = repl_links.lock().await;
                    for (pid, _) in &closest {
                        if let Some(link) = links.get(pid) {
                            let _ = link.send_message(&encoded).await;
                        }
                    }
                }
                drop(kb);
                log::debug!("Replication maintenance complete");
            }
        });

        // Process events
        while let Some(event) = event_rx.recv().await {
            match event {
                NodeEvent::LinkUp(peer_id, link) => {
                    self.handle_link_up(peer_id, link).await;
                }
                NodeEvent::LinkDown(peer_id, link_id) => {
                    self.handle_link_down(peer_id, link_id).await;
                }
                NodeEvent::Message(from, msg_link_id, msg) => {
                    // Stateful firewall: evaluate inbound message.
                    {
                        let mut fw_guard = self.firewall.lock().await;
                        if let Some(fw) = fw_guard.as_mut() {
                            if matches!(fw.evaluate(&from, &msg), firewall::Action::Drop) {
                                continue;
                            }
                        }
                    }
                    // Resource governor: per-link-peer budgeting.
                    {
                        let circuits_for_peer = self.circuit_table.lock().await
                            .circuits_per_peer()
                            .get(&from)
                            .copied()
                            .unwrap_or(0);
                        let mut gov = self.governor.lock().await;
                        if gov.evaluate(&from, msg.msg_type, circuits_for_peer) == Verdict::Shed {
                            continue;
                        }
                    }
                    // Update link activity timestamp for keepalive tracking
                    self.links.lock().await.touch_recv(&from, msg_link_id);

                    if msg.msg_type == MessageType::CircuitRelay && msg.payload.len() >= 4 {
                        // Route circuit relay cells through per-circuit ordered queues
                        // to guarantee FIFO processing. Without this, spawned tasks
                        // can overtake each other and deliver DATA cells out of order.
                        let circuit_id = u32::from_be_bytes([
                            msg.payload[0], msg.payload[1],
                            msg.payload[2], msg.payload[3],
                        ]);
                        let queue_key = (circuit_id, from);
                        let mut queues = self.circuit_relay_queues.lock().await;
                        let tx = queues.entry(queue_key).or_insert_with(|| {
                            let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                            let node = node_arc.clone();
                            tokio::spawn(async move {
                                while let Some(payload) = rx.recv().await {
                                    if let Err(e) = node.handle_circuit_relay(from, &payload).await {
                                        log::warn!("Error handling circuit relay from {:?}: {}", from, e);
                                    }
                                }
                            });
                            tx
                        });
                        if tx.send(msg.payload).is_err() {
                            // Receiver task exited — remove stale entry.
                            queues.remove(&queue_key);
                        }
                    } else {
                        let node = node_arc.clone();
                        tokio::spawn(async move {
                            if let Err(e) = node.handle_message(from, msg).await {
                                log::warn!("Error handling message from {:?}: {}", from, e);
                            }
                        });
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_link_up(&self, peer_id: PeerId, link: Arc<PeerLink>) {
        let is_outbound = link.is_initiator();

        // Check link limits before accepting. If at capacity, try to evict.
        {
            let links = self.links.lock().await;
            let (count, limit) = if is_outbound {
                (links.outbound_count(), self.max_outbound)
            } else {
                (links.inbound_count(), self.max_inbound)
            };

            if limit > 0 && count >= limit {
                let circuit_counts = self.circuit_table.lock().await.circuits_per_peer();
                if let Some((victim_peer, victim_link_id)) =
                    links.pick_eviction_candidate(is_outbound, &circuit_counts)
                {
                    log::info!(
                        "Link limit reached ({}/{}), evicting {:?} link_id={} to make room for {:?}",
                        count, limit, victim_peer, victim_link_id, peer_id,
                    );
                    drop(links);
                    // Graceful drain: spawn a task that waits up to 30s then force-kills.
                    // The new link is accepted immediately (temporary +1 overshoot).
                    self.evict_link(victim_peer, victim_link_id).await;
                } else {
                    // No evictable link — reject the new connection.
                    log::warn!(
                        "Link limit reached ({}/{}) and no evictable link, rejecting {:?}",
                        count, limit, peer_id,
                    );
                    return;
                }
            }
        }

        let (link_id, is_first) = self.links.lock().await.insert(peer_id, link.clone());
        log::info!("Link up: {:?} (link_id={})", peer_id, link_id);

        // Populate pubkey cache from handshake-authenticated pubkeys.
        {
            use crate::pubkey_cache::CachedPubkey;
            self.pubkey_cache.lock().await.insert(peer_id, CachedPubkey {
                signing_algo: link.remote_signing_algo(),
                signing_pk: link.remote_signing_pubkey().to_vec(),
                // KEM pubkey not yet available from link — populated from DHT later.
                kem_algo: tarnet_api::types::KemAlgo::X25519,
                kem_pk: Vec::new(),
            });
        }

        if is_first {
            self.governor.lock().await.peer_connected(peer_id);
            self.routing_table.lock().await.add_neighbor(peer_id);
            let dht_id = dht_id_from_peer_id(&peer_id);
            self.kbucket.lock().await.insert(peer_id, dht_id);
        }

        // Start recv loop for this link
        let event_tx = self.event_tx.clone();
        let remote = peer_id;
        let recv_link_id = link_id;
        let stats = self.stats.clone();
        let bandwidth = self.bandwidth.clone();
        tokio::spawn(async move {
            loop {
                match link.recv_message().await {
                    Ok(data) => {
                        bandwidth.acquire_download(data.len()).await;
                        stats.record_recv(&remote, data.len() as u64);
                        match WireMessage::decode(&data) {
                            Ok(msg) => {
                                if event_tx
                                    .send(NodeEvent::Message(remote, recv_link_id, msg))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(e) => {
                                log::warn!("Wire decode error from {:?}: {}", remote, e);
                            }
                        }
                    }
                    Err(_) => {
                        let _ = event_tx.send(NodeEvent::LinkDown(remote, recv_link_id)).await;
                        break;
                    }
                }
            }
        });

        // Send initial route advertisement to the new peer
        {
            let table = self.routing_table.lock().await;
            let ad = dv::generate_advertisement(&self.identity, &table, &peer_id);
            let link = self.links.lock().await.get(&peer_id).cloned();
            if let Some(link) = link {
                if let Err(e) = link.send_message(&ad.to_wire().encode()).await {
                    log::warn!("Failed to send initial route ad to {:?}: {}", peer_id, e);
                }
            }
        }

        // Triggered update: tell all OTHER neighbors about the new peer
        self.send_triggered_updates(&peer_id).await;

        // Send our hello record to the new peer
        {
            let hello = self.create_hello_record().await;
            let key = crate::dht::identity_address_key(&self.peer_id());
            let value = hello.to_bytes();
            let mut seq = self.hello_sequence.lock().await;
            *seq += 1;
            let sequence = *seq;
            self.db_set_metadata("hello_sequence", sequence);
            drop(seq);
            let signer = *self.peer_id().as_bytes();
            let mut put = DhtPutMsg {
                key: *key.as_bytes(),
                record_type: RecordType::Hello,
                sequence,
                signer,
                ttl: HELLO_TTL,
                value,
                signature: Vec::new(),
                signer_algo: self.identity.identity.signing.algo() as u8,
                signer_pubkey: self.identity.identity.signing.signing_pubkey_bytes(),
                hop_count: 0,
                hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
                bloom: [0u8; 256],
            };
            put.signature = self.identity.sign(&put.signable_bytes());
            if let Some(link) = self.links.lock().await.get(&peer_id) {
                let _ = link.send_message(&put.to_wire().encode()).await;
            }
        }

        // Also forward any DHT records we have to the new peer
        {
            let store = self.dht_store.lock().await;
            let link = self.links.lock().await.get(&peer_id).cloned();
            if let Some(link) = link {
                for record in store.all_records() {
                    let put = DhtPutMsg {
                        key: *record.key.as_bytes(),
                        record_type: record.record_type,
                        sequence: record.sequence,
                        signer: record.signer,
                        ttl: record.ttl.as_secs() as u32,
                        value: record.value.clone(),
                        signature: record.signature.clone(),
                        signer_algo: record.signer_algo,
                        signer_pubkey: record.signer_pubkey.clone(),
                        hop_count: 0,
                        hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
                        bloom: [0u8; 256],
                    };
                    let _ = link.send_message(&put.to_wire().encode()).await;
                }
            }
        }

        // Re-send DhtWatch for all local watches to the new peer
        {
            let watches = self.local_watches.lock().await;
            if !watches.is_empty() {
                let link = self.links.lock().await.get(&peer_id).cloned();
                if let Some(link) = link {
                    for key in watches.iter() {
                        // Generate fresh token per watch per link
                        let mut token = [0u8; 32];
                        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut token);
                        self.query_tokens
                            .lock()
                            .await
                            .insert(token, (self.peer_id(), Instant::now()));
                        let watch = DhtWatchMsg {
                            key: *key,
                            query_token: token,
                            expiration_secs: 300,
                        };
                        let _ = link.send_message(&watch.to_wire().encode()).await;
                    }
                }
            }
        }
    }

    /// Forcibly disconnect a peer by removing all links.
    /// Triggers the same cleanup as a natural link failure.
    pub async fn disconnect_peer(&self, peer_id: &PeerId) {
        loop {
            let peer_gone = {
                let mut links = self.links.lock().await;
                if !links.contains_key(peer_id) {
                    break;
                }
                // Remove link_id 0, 1, 2... until one returns peer_gone=true
                // LinkTable assigns sequential IDs, try removing from 0
                let mut gone = false;
                for id in 0..1000u64 {
                    gone = links.remove_link(peer_id, id);
                    if gone || !links.contains_key(peer_id) {
                        break;
                    }
                }
                gone
            };
            if peer_gone {
                self.routing_table.lock().await.remove_next_hop(peer_id);
                self.dht_watches.lock().await.remove_peer(peer_id);
                self.circuit_table.lock().await.remove_peer(peer_id);
                let _ = self
                    .channel_event_tx
                    .send(ChannelEvent::PeerDisconnected { peer_id: *peer_id })
                    .await;
                break;
            }
            // If not gone yet but still has links, keep trying
            if !self.links.lock().await.contains_key(peer_id) {
                break;
            }
        }
    }

    /// Gracefully evict a single link. Marks it for removal and spawns a
    /// delayed force-kill so existing circuits have time to drain.
    async fn evict_link(&self, peer_id: PeerId, link_id: LinkId) {
        // Remove the link from the table immediately so no new circuits are
        // routed through it. Existing circuits on other links to this peer
        // are unaffected. If this was the last link, full peer cleanup runs.
        let peer_gone = self.links.lock().await.remove_link(&peer_id, link_id);
        if peer_gone {
            self.governor.lock().await.peer_disconnected(&peer_id);
            self.routing_table.lock().await.remove_next_hop(&peer_id);
            self.dht_watches.lock().await.remove_peer(&peer_id);
            self.circuit_table.lock().await.remove_peer(&peer_id);
            let _ = self
                .channel_event_tx
                .send(ChannelEvent::PeerDisconnected { peer_id })
                .await;
        }
        log::info!("Evicted link {:?} link_id={}", peer_id, link_id);
    }

    async fn handle_link_down(&self, peer_id: PeerId, link_id: LinkId) {
        log::info!("Link down: {:?} (link_id={})", peer_id, link_id);
        let peer_gone = self.links.lock().await.remove_link(&peer_id, link_id);
        if peer_gone {
            self.governor.lock().await.peer_disconnected(&peer_id);
            self.routing_table.lock().await.remove_next_hop(&peer_id);
            self.dht_watches.lock().await.remove_peer(&peer_id);
            // Clean up all circuits involving this peer
            self.circuit_table.lock().await.remove_peer(&peer_id);
            // Notify application that this peer is gone
            let _ = self
                .channel_event_tx
                .send(ChannelEvent::PeerDisconnected { peer_id })
                .await;
        }
    }

    async fn handle_message(&self, from: PeerId, msg: WireMessage) -> Result<()> {
        // Update k-bucket on non-relay messages. CircuitRelay is the highest-frequency
        // message type and carries no new routing information — the peer is already known.
        if msg.msg_type != MessageType::CircuitRelay {
            let dht_id = dht_id_from_peer_id(&from);
            self.kbucket.lock().await.insert(from, dht_id);
        }

        match msg.msg_type {
            MessageType::RouteAdvertisement => {
                let ad = RouteAdvertisement::from_bytes(&msg.payload)?;
                let mut table = self.routing_table.lock().await;
                let changed = dv::process_advertisement(&mut table, &ad, &mut *self.pubkey_cache.lock().await)?;
                if changed {
                    log::debug!("Routing table updated from {:?}", from);
                    // Triggered update: re-advertise to other neighbors
                    drop(table);
                    self.send_triggered_updates(&from).await;
                }
            }
            MessageType::DhtPut => {
                let mut put = DhtPutMsg::from_bytes(&msg.payload)?;
                let key = DhtId(put.key);

                // Hop limit enforcement
                if put.hop_limit == 0 {
                    log::debug!("DHT PUT hop limit reached, not forwarding");
                    // Still process locally
                } else {
                    put.hop_limit -= 1;
                }

                // Verify signature for signed record types before storing/propagating
                if put.record_type.is_signed() {
                    log::debug!(
                        "DHT PUT verify: type={:?}, signer_algo={}, pubkey_len={}, sig_len={}, value_len={}",
                        put.record_type, put.signer_algo, put.signer_pubkey.len(),
                        put.signature.len(), put.value.len()
                    );
                    let algo = SigningAlgo::from_u8(put.signer_algo)
                        .map_err(|e| Error::Protocol(format!("unknown signer algo: {}", e)))?;
                    if !put.signer_pubkey.is_empty() {
                        // Verify that the signer pubkey matches the claimed signer PeerId
                        let expected_peer = peer_id_from_signing_pubkey(&put.signer_pubkey);
                        if expected_peer != PeerId(put.signer) {
                            log::warn!("DHT PUT from {:?}: signer pubkey does not match signer PeerId, dropping", from);
                            return Ok(());
                        }
                    }
                    if !identity::verify(algo, &put.signer_pubkey, &put.signable_bytes(), &put.signature) {
                        log::warn!("DHT PUT from {:?}: invalid signature, dropping", from);
                        return Ok(());
                    }
                }

                // Check if we already have this exact record (avoid re-flooding)
                let is_new = {
                    let store = self.dht_store.lock().await;
                    let existing = store.get(&key);
                    !existing.iter().any(|r| {
                        r.signer == put.signer
                            && r.sequence == put.sequence
                            && r.record_type == put.record_type
                    })
                };

                let record = crate::dht::DhtRecord {
                    key,
                    record_type: put.record_type,
                    sequence: put.sequence,
                    signer: put.signer,
                    signer_algo: put.signer_algo,
                    signer_pubkey: put.signer_pubkey.clone(),
                    value: put.value.clone(),
                    ttl: Duration::from_secs(put.ttl as u64),
                    stored_at: std::time::Instant::now(),
                    signature: put.signature.clone(),
                };
                self.db_upsert_dht_record(&record);
                self.dht_store.lock().await.put(record);
                log::debug!("DHT PUT from {:?} (type={:?})", from, put.record_type);

                // Forward to targeted peers if new and hop limit not exhausted
                if is_new && put.hop_limit > 0 {
                    // Bloom is advisory: skip peers in the bloom UNLESS they are
                    // among the k-closest to the key. This prevents bloom-stuffing
                    // attacks from censoring the storage nodes that matter most.
                    let bloom = BloomFilter::from_bytes(put.bloom);
                    let mut fwd_bloom = BloomFilter::new();
                    fwd_bloom.insert(&self.peer_id());
                    put.bloom = fwd_bloom.to_bytes();
                    put.hop_count = put.hop_count.saturating_add(1);

                    let kb = self.kbucket.lock().await;
                    let all_peers = kb.all_peers();
                    let l2nse = kb.estimate_l2nse();
                    drop(kb);

                    let params = DhtQueryParams::from_l2nse(l2nse);
                    // R5N-style hybrid: random walk for the first l2nse hops,
                    // then greedy convergence toward the key.
                    let targets = if put.hop_count < (l2nse.round().min(255.0) as u8) {
                        random_select(&all_peers, params.fan_out)
                    } else {
                        probabilistic_select(&key, &all_peers, params.fan_out)
                    };

                    let encoded = put.to_wire().encode();

                    let links = self.links.lock().await;
                    if targets.is_empty() {
                        for (peer_id, link) in links.iter() {
                            if *peer_id != from && !bloom.contains(peer_id) {
                                let _ = link.send_message(&encoded).await;
                            }
                        }
                    } else {
                        for (pid, _) in &targets {
                            if *pid != from
                                && (!bloom.contains(pid)
                                    || is_k_closest(pid, &key, &all_peers, DHT_K))
                            {
                                if let Some(link) = links.get(pid) {
                                    let _ = link.send_message(&encoded).await;
                                }
                            }
                        }
                    }

                    // Notify remote watchers via query token routing
                    let watchers = self.dht_watches.lock().await.get_watchers(&put.key);
                    if !watchers.is_empty() {
                        for (token, via_peer) in watchers {
                            if via_peer != from {
                                let notify = DhtWatchNotifyMsg {
                                    query_token: token,
                                    put: put.clone(),
                                };
                                let notify_encoded = notify.to_wire().encode();
                                if let Some(link) = links.get(&via_peer) {
                                    let _ = link.send_message(&notify_encoded).await;
                                }
                            }
                        }
                    }

                    // Notify local app if we're watching this key
                    if self.local_watches.lock().await.contains(&put.key) {
                        let dht_record = crate::dht::DhtRecord {
                            key,
                            record_type: put.record_type,
                            sequence: put.sequence,
                            signer: put.signer,
                            signer_algo: put.signer_algo,
                            signer_pubkey: put.signer_pubkey.clone(),
                            value: put.value.clone(),
                            ttl: Duration::from_secs(put.ttl as u64),
                            stored_at: std::time::Instant::now(),
                            signature: put.signature.clone(),
                        };
                        let _ = self.dht_watch_tx.send((key, dht_record)).await;
                    }
                }
            }
            MessageType::DhtGet => {
                let mut get = DhtGetMsg::from_bytes(&msg.payload)?;
                let key = DhtId(get.key);

                // Record query_token → previous_hop for anonymous reply routing
                self.query_tokens
                    .lock()
                    .await
                    .insert(get.query_token, (from, Instant::now()));

                // Respond with local records, routed back via query_token
                let store = self.dht_store.lock().await;
                let records = store.get(&key);
                let response_records: Vec<DhtResponseRecord> = records
                    .iter()
                    .filter_map(|r| {
                        // Send remaining TTL, not the original.
                        let elapsed = r.stored_at.elapsed();
                        let remaining = r.ttl.checked_sub(elapsed)?;
                        Some(DhtResponseRecord {
                            record_type: r.record_type,
                            sequence: r.sequence,
                            signer: r.signer,
                            ttl: remaining.as_secs() as u32,
                            value: r.value.clone(),
                            signature: r.signature.clone(),
                            signer_algo: r.signer_algo,
                            signer_pubkey: Vec::new(),
                        })
                    })
                    .collect();
                drop(store);

                if !response_records.is_empty() {
                    let response = DhtGetResponseMsg {
                        query_token: get.query_token,
                        key: get.key,
                        records: response_records,
                    };
                    // Send response back toward the requester via previous hop
                    self.send_to_peer(&from, &response.to_wire().encode())
                        .await?;
                }

                // Forward GET to other peers if hop limit allows.
                // Use query_token dedup: we just inserted (from, now) above;
                // if the token was already present with a DIFFERENT previous_hop,
                // that means we already forwarded this GET from another neighbor.
                // (The insert above overwrites, so check before inserting.)
                // Note: the insertion on line above always happens (for reply routing),
                // so we track forwarding separately via bloom membership.
                if get.hop_limit > 0 {
                    get.hop_limit -= 1;
                    // Advisory bloom: respect it for non-critical peers,
                    // override it for k-closest to resist bloom stuffing.
                    let bloom = BloomFilter::from_bytes(get.bloom);
                    let mut fwd_bloom = BloomFilter::new();
                    fwd_bloom.insert(&self.peer_id());
                    get.bloom = fwd_bloom.to_bytes();
                    get.hop_count = get.hop_count.saturating_add(1);

                    let kb = self.kbucket.lock().await;
                    let all_peers = kb.all_peers();
                    let l2nse = kb.estimate_l2nse();
                    drop(kb);

                    let params = DhtQueryParams::from_l2nse(l2nse);
                    let targets = if get.hop_count < (l2nse.round().min(255.0) as u8) {
                        random_select(&all_peers, params.fan_out)
                    } else {
                        probabilistic_select(&key, &all_peers, params.fan_out)
                    };

                    let encoded = get.to_wire().encode();

                    let links = self.links.lock().await;
                    if targets.is_empty() {
                        for (peer_id, link) in links.iter() {
                            if *peer_id != from && !bloom.contains(peer_id) {
                                let _ = link.send_message(&encoded).await;
                            }
                        }
                    } else {
                        for (pid, _) in &targets {
                            if *pid != from
                                && (!bloom.contains(pid)
                                    || is_k_closest(pid, &key, &all_peers, DHT_K))
                            {
                                if let Some(link) = links.get(pid) {
                                    let _ = link.send_message(&encoded).await;
                                }
                            }
                        }
                    }
                }
            }
            MessageType::DhtGetResponse => {
                let resp = DhtGetResponseMsg::from_bytes(&msg.payload)?;

                // Store records locally (with signature validation)
                for rec in &resp.records {
                    if rec.record_type.is_signed() {
                        let algo = match SigningAlgo::from_u8(rec.signer_algo) {
                            Ok(a) => a,
                            Err(_) => {
                                log::warn!("DhtGetResponse from {:?}: unknown signer algo", from);
                                continue;
                            }
                        };
                        let mut signable = Vec::with_capacity(64 + 1 + 8 + rec.value.len());
                        signable.extend_from_slice(&resp.key);
                        signable.push(rec.record_type.as_u8());
                        signable.extend_from_slice(&rec.sequence.to_be_bytes());
                        signable.extend_from_slice(&rec.value);
                        if !identity::verify(algo, &rec.signer_pubkey, &signable, &rec.signature) {
                            log::warn!(
                                "DhtGetResponse from {:?}: invalid signature, dropping record",
                                from
                            );
                            continue;
                        }
                    }

                    let record = crate::dht::DhtRecord {
                        key: DhtId(resp.key),
                        record_type: rec.record_type,
                        sequence: rec.sequence,
                        signer: rec.signer,
                        signer_algo: rec.signer_algo,
                        signer_pubkey: rec.signer_pubkey.clone(),
                        value: rec.value.clone(),
                        ttl: Duration::from_secs(rec.ttl as u64),
                        stored_at: std::time::Instant::now(),
                        signature: rec.signature.clone(),
                    };
                    self.db_upsert_dht_record(&record);
                    self.dht_store.lock().await.put(record);
                }

                // Route response back via query_token hop-by-hop
                let prev_hop = self
                    .query_tokens
                    .lock()
                    .await
                    .get(&resp.query_token)
                    .map(|(peer, _)| *peer);
                if let Some(prev) = prev_hop {
                    if prev == self.peer_id() {
                        // We originated this query — records already stored above
                        log::debug!("DhtGetResponse arrived for our query");
                    } else {
                        // Forward response back toward originator
                        self.send_to_peer(&prev, &resp.to_wire().encode()).await?;
                    }
                } else {
                    log::debug!("DhtGetResponse with unknown query_token, storing locally only");
                }
            }
            MessageType::DhtFindClosest => {
                let find = DhtFindClosestMsg::from_bytes(&msg.payload)?;
                let key = DhtId(find.key);
                let kb = self.kbucket.lock().await;
                let closest = kb.closest_peers(&key, DHT_K);
                drop(kb);

                let response = DhtFindClosestResponseMsg {
                    key: find.key,
                    peers: closest,
                };
                self.send_to_peer(&from, &response.to_wire().encode())
                    .await?;
            }
            MessageType::DhtFindClosestResponse => {
                let resp = DhtFindClosestResponseMsg::from_bytes(&msg.payload)?;
                // Learn about discovered peers
                let mut kb = self.kbucket.lock().await;
                for (pid, did) in &resp.peers {
                    kb.insert(*pid, *did);
                }
                drop(kb);
            }
            MessageType::TunnelKeyExchange => {
                self.handle_tunnel_key_exchange(from, &msg.payload).await?;
            }
            MessageType::TunnelKeyResponse => {
                self.handle_tunnel_key_response(from, &msg.payload).await?;
            }
            MessageType::Data => {
                self.handle_data(from, &msg.payload).await?;
            }
            MessageType::EncryptedData => {
                self.handle_encrypted_data(from, &msg.payload).await?;
            }
            MessageType::ChannelOpen
            | MessageType::ChannelData
            | MessageType::ChannelAck
            | MessageType::ChannelClose => {
                // These arrive inside tunnel data, not directly on links
                log::warn!("Received channel message outside tunnel from {:?}", from);
            }
            MessageType::HandshakeHello
            | MessageType::HandshakeAuth
            | MessageType::HandshakeConfirm => {
                log::warn!(
                    "Received handshake message on established link from {:?}",
                    from
                );
            }
            MessageType::Rekey => {
                // Re-key messages are handled at the link layer, not here
                log::debug!("Received rekey message from {:?}", from);
            }
            MessageType::Keepalive => {
                let ka = KeepaliveMsg::from_bytes(&msg.payload)?;
                if let Some(ts) = ka.timestamp_us {
                    // This is a ping — echo it back as a pong (no timestamp = pong)
                    let pong = KeepaliveMsg { timestamp_us: None };
                    if let Some(link) = self.links.lock().await.get(&from).cloned() {
                        let _ = link.send_message(&pong.to_wire().encode()).await;
                    }
                    // Also compute RTT if we have a reasonable timestamp
                    let now_us = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as u64;
                    if now_us > ts {
                        let _rtt_us = now_us - ts;
                        // Note: this is one-way latency from their clock to ours,
                        // not true RTT. RTT is measured from the pong response below.
                    }
                }
                // Pong (no timestamp) — activity is already tracked by touch_recv above.
                // RTT could be computed here if we stored the sent timestamp,
                // but the link scoring already gets RTT from the pong round-trip.
            }
            MessageType::DhtWatch => {
                let watch = DhtWatchMsg::from_bytes(&msg.payload)?;
                let mut watches = self.dht_watches.lock().await;
                watches.set_watch(watch.key, watch.query_token, from, watch.expiration_secs);
            }
            MessageType::DhtWatchNotify => {
                let notify = DhtWatchNotifyMsg::from_bytes(&msg.payload)?;
                let key = DhtId(notify.put.key);

                // Verify signature if signed type
                if notify.put.record_type.is_signed() {
                    let algo = SigningAlgo::from_u8(notify.put.signer_algo)
                        .map_err(|e| Error::Protocol(format!("unknown signer algo: {}", e)))?;
                    if !identity::verify(
                        algo,
                        &notify.put.signer_pubkey,
                        &notify.put.signable_bytes(),
                        &notify.put.signature,
                    ) {
                        log::warn!(
                            "DhtWatchNotify from {:?}: invalid signature, dropping",
                            from
                        );
                        return Ok(());
                    }
                }

                // Check if we're the destination (we originated this watch)
                if self.local_watches.lock().await.contains(&notify.put.key) {
                    // Store the record locally
                    let record = crate::dht::DhtRecord {
                        key,
                        record_type: notify.put.record_type,
                        sequence: notify.put.sequence,
                        signer: notify.put.signer,
                        signer_algo: notify.put.signer_algo,
                        signer_pubkey: notify.put.signer_pubkey.clone(),
                        value: notify.put.value.clone(),
                        ttl: Duration::from_secs(notify.put.ttl as u64),
                        stored_at: std::time::Instant::now(),
                        signature: notify.put.signature,
                    };
                    self.db_upsert_dht_record(&record);
                    self.dht_store.lock().await.put(record.clone());
                    let _ = self.dht_watch_tx.send((key, record)).await;
                } else {
                    // Route notification back via query_token hop-by-hop
                    let prev_hop = self
                        .query_tokens
                        .lock()
                        .await
                        .get(&notify.query_token)
                        .map(|(peer, _)| *peer);
                    if let Some(prev) = prev_hop {
                        self.send_to_peer(&prev, &notify.to_wire().encode()).await?;
                    } else {
                        log::debug!("DhtWatchNotify with unknown query_token, dropping");
                    }
                }
            }
            MessageType::CircuitRelay => {
                self.handle_circuit_relay(from, &msg.payload).await?;
            }
            MessageType::CircuitCreate => {
                self.handle_circuit_create(from, &msg.payload).await?;
            }
            MessageType::CircuitCreated => {
                self.handle_circuit_created(from, &msg.payload).await?;
            }
            MessageType::CircuitDestroy => {
                self.handle_circuit_destroy(from, &msg.payload).await?;
            }
            // Unknown message types are handled by the match's default
            // (from_u16 returns None, so they never reach this match)
        }
        Ok(())
    }

    /// Send triggered route updates to all neighbors except the source.
    async fn send_triggered_updates(&self, exclude: &PeerId) {
        let links = self.links.lock().await;
        let table = self.routing_table.lock().await;
        for (peer_id, link) in links.iter() {
            if peer_id == exclude {
                continue;
            }
            let ad = dv::generate_advertisement(&self.identity, &table, peer_id);
            if let Err(e) = link.send_message(&ad.to_wire().encode()).await {
                log::warn!("Failed triggered update to {:?}: {}", peer_id, e);
            }
        }
    }

    async fn send_to_peer(&self, peer: &PeerId, data: &[u8]) -> Result<()> {
        self.bandwidth.acquire_upload(data.len()).await;
        let links = self.links.lock().await;
        let link = links
            .get(peer)
            .ok_or_else(|| Error::Protocol(format!("no link to {:?}", peer)))?;
        self.stats.record_send(peer, data.len() as u64);
        link.send_message(data).await
    }

    /// Get the list of connected peers.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.links.lock().await.keys().copied().collect()
    }

    /// Get routing table entries for display.
    pub async fn routing_entries(&self) -> Vec<(PeerId, PeerId, u32)> {
        let table = self.routing_table.lock().await;
        table
            .all_destinations()
            .map(|(dest, route)| (*dest, route.next_hop, route.cost))
            .collect()
    }

    /// Snapshot the full node status for display.
    pub async fn node_status(&self) -> tarnet_api::types::NodeStatus {
        use tarnet_api::types::*;

        let peer_id = self.identity.peer_id();

        // Link/peer info
        let peer_infos = self.links.lock().await.peer_info_snapshot();
        let peers: Vec<PeerStatus> = peer_infos.into_iter().map(|pi| {
            PeerStatus {
                peer_id: pi.peer_id,
                links: pi.links.into_iter().map(|li| LinkStatus {
                    link_id: li.link_id,
                    state: li.state.to_string(),
                    direction: li.direction.to_string(),
                    rtt_us: li.rtt_us,
                    loss_rate: li.loss_rate,
                    age_secs: li.age_secs,
                    idle_secs: li.idle_secs,
                    transport: li.transport.to_string(),
                }).collect(),
            }
        }).collect();

        // Routes
        let routes = {
            let table = self.routing_table.lock().await;
            table.all_destinations()
                .map(|(dest, route)| (*dest, route.next_hop, route.cost))
                .collect()
        };

        // DHT
        let dht = {
            let store = self.dht_store.lock().await;
            let kb = self.kbucket.lock().await;
            let kbucket_peers = kb.len();
            let l2nse = kb.estimate_l2nse();
            drop(kb);
            let local_watches = self.local_watches.lock().await.len();
            let remote_watches = self.dht_watches.lock().await.watch_count();
            DhtStatus {
                stored_keys: store.key_count(),
                stored_records: store.record_count(),
                kbucket_peers,
                local_watches,
                remote_watches,
                nse: 2u64.saturating_pow(l2nse.round().min(63.0) as u32),
            }
        };

        // Circuits
        let circuits = {
            let ct = self.circuit_table.lock().await;
            let outbound = self.outbound_circuits.lock().await.len();
            let rendezvous = self.rendezvous_table.lock().await.len();
            let intro = self.intro_registrations.lock().await.len();
            CircuitStatus {
                relay_forwards: ct.forward_count(),
                relay_endpoints: ct.endpoint_count(),
                outbound_circuits: outbound,
                rendezvous_points: rendezvous,
                intro_points: intro,
            }
        };

        // Traffic
        let summary = self.stats.traffic_summary();
        let traffic = TrafficStatus {
            bytes_up: WindowedStats {
                total: summary.bytes_up.total,
                last_5min: summary.bytes_up.last_5min,
                last_1hr: summary.bytes_up.last_1hr,
                last_1day: summary.bytes_up.last_1day,
            },
            bytes_down: WindowedStats {
                total: summary.bytes_down.total,
                last_5min: summary.bytes_down.last_5min,
                last_1hr: summary.bytes_down.last_1hr,
                last_1day: summary.bytes_down.last_1day,
            },
            packets_up: WindowedStats {
                total: summary.packets_up.total,
                last_5min: summary.packets_up.last_5min,
                last_1hr: summary.packets_up.last_1hr,
                last_1day: summary.packets_up.last_1day,
            },
            packets_down: WindowedStats {
                total: summary.packets_down.total,
                last_5min: summary.packets_down.last_5min,
                last_1hr: summary.packets_down.last_1hr,
                last_1day: summary.packets_down.last_1day,
            },
            cells_relayed: WindowedStats {
                total: summary.cells_relayed.total,
                last_5min: summary.cells_relayed.last_5min,
                last_1hr: summary.cells_relayed.last_1hr,
                last_1day: summary.cells_relayed.last_1day,
            },
        };

        NodeStatus {
            peer_id,
            uptime_secs: self.started_at.elapsed().as_secs(),
            peers,
            routes,
            dht,
            circuits,
            traffic,
        }
    }

    /// Configure link limits. 0 = unlimited.
    pub fn set_link_limits(&mut self, max_inbound: usize, max_outbound: usize) {
        self.max_inbound = max_inbound;
        self.max_outbound = max_outbound;
    }

    /// Configure bandwidth limits. Rates are in bytes/sec; 0 = unlimited.
    pub fn set_bandwidth_limits(&mut self, upload_rate: u64, download_rate: u64) {
        self.bandwidth = Arc::new(crate::bandwidth::BandwidthLimiter::new(
            upload_rate,
            download_rate,
        ));
    }

    /// Update bandwidth rates on an already-running node (e.g. config reload).
    pub async fn update_bandwidth_limits(&self, upload_rate: u64, download_rate: u64) {
        self.bandwidth.update_rates(upload_rate, download_rate).await;
    }

    /// Set the global addresses this node advertises in hello records.
    /// Only Global-scoped addresses should go here — SiteLocal addresses
    /// are exchanged bilaterally over encrypted channels, never broadcast.
    pub async fn set_global_addrs(&self, addrs: Vec<ScopedAddress>) {
        *self.global_addrs.lock().await = addrs;
    }

    /// Set the introducers this node advertises in hello records.
    pub async fn set_introducers(&self, peers: Vec<PeerId>) {
        *self.introducers.lock().await = peers;
    }

    /// Take the incoming tunnel notification receiver (for listen mode).
    pub async fn take_tunnel_receiver(&self) -> Option<mpsc::Receiver<PeerId>> {
        self.tunnel_notify_rx.lock().await.take()
    }

    /// Take the channel event receiver (for channel death notifications, etc.).
    pub async fn take_channel_event_receiver(&self) -> Option<mpsc::Receiver<ChannelEvent>> {
        self.channel_event_rx.lock().await.take()
    }
}

/// Collect unique transport types from a set of scoped addresses.
fn collect_transport_types(addrs: &[ScopedAddress]) -> Vec<TransportType> {
    let mut seen = std::collections::HashSet::new();
    let mut types = Vec::new();
    for addr in addrs {
        if seen.insert(addr.transport_type.as_u16()) {
            types.push(addr.transport_type);
        }
    }
    types
}

/// Persistent discovery retry loop. Each discovery URI gets its own concurrent retry task.
/// Resolves discovery URIs (e.g. `mainline:<hex>`) to transport addresses, then connects.
async fn discovery_retry_loop(
    addrs: Vec<String>,
    discovery: Arc<Box<dyn Discovery>>,
    event_tx: mpsc::Sender<NodeEvent>,
    identity: Arc<Keypair>,
    links: Arc<Mutex<LinkTable>>,
) {
    let mut handles = Vec::new();
    for addr in addrs {
        let disc = discovery.clone();
        let tx = event_tx.clone();
        let id = identity.clone();
        let links = links.clone();
        handles.push(tokio::spawn(async move {
            discovery_single_peer(addr, disc, tx, id, links).await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

/// Retry loop for a single discovery URI. Resolves via the appropriate protocol,
/// then connects via the resolved transport address.
async fn discovery_single_peer(
    addr: String,
    discovery: Arc<Box<dyn Discovery>>,
    event_tx: mpsc::Sender<NodeEvent>,
    identity: Arc<Keypair>,
    links: Arc<Mutex<LinkTable>>,
) {
    const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);

    let mut backoff = INITIAL_BACKOFF;

    loop {
        let resolved = resolve_discovery_addr(&addr);

        if let Some(connect_addr) = resolved {
            match discovery.connect(&connect_addr).await {
                Ok(transport) => {
                    match PeerLink::initiator(transport, &identity, None).await {
                        Ok(link) => {
                            let link = Arc::new(link);
                            let remote = link.remote_peer();
                            log::info!("Discovery connected to {:?} via {} (resolved from {})", remote, connect_addr, addr);
                            let _ = event_tx
                                .send(NodeEvent::LinkUp(remote, link))
                                .await;

                            backoff = INITIAL_BACKOFF;

                            loop {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                if !links.lock().await.contains_key(&remote) {
                                    log::info!("Discovery link to {:?} lost, reconnecting...", remote);
                                    break;
                                }
                            }
                            continue;
                        }
                        Err(e) => {
                            log::debug!("Discovery handshake to {} (from {}) failed: {}", connect_addr, addr, e);
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Discovery connect to {} (from {}) failed: {}", connect_addr, addr, e);
                }
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Resolve a discovery URI to a connectable transport address.
/// Currently supports `mainline:<hex>`.
fn resolve_discovery_addr(addr: &str) -> Option<String> {
    if addr.starts_with(bootstrap::MAINLINE_PREFIX) {
        resolve_mainline_addr(addr)
    } else {
        log::warn!("Unknown discovery scheme: {}", addr);
        None
    }
}

/// Persistent bootstrap retry loop. Each peer gets its own concurrent retry task.
/// Handles `tcp://`, `ws://`, `wss://`, and bare `host:port` transport addresses.
async fn bootstrap_retry_loop(
    peers: Vec<String>,
    discovery: Arc<Box<dyn Discovery>>,
    event_tx: mpsc::Sender<NodeEvent>,
    identity: Arc<Keypair>,
    links: Arc<Mutex<LinkTable>>,
) {
    let mut handles = Vec::new();
    for addr in peers {
        let disc = discovery.clone();
        let tx = event_tx.clone();
        let id = identity.clone();
        let links = links.clone();
        handles.push(tokio::spawn(async move {
            bootstrap_single_peer(addr, disc, tx, id, links).await;
        }));
    }
    // Keep alive until all tasks finish (they run indefinitely)
    for h in handles {
        let _ = h.await;
    }
}

/// Retry loop for a single bootstrap peer. Exponential backoff, capped at 60s.
/// Reconnects if the link drops.
async fn bootstrap_single_peer(
    addr: String,
    discovery: Arc<Box<dyn Discovery>>,
    event_tx: mpsc::Sender<NodeEvent>,
    identity: Arc<Keypair>,
    links: Arc<Mutex<LinkTable>>,
) {
    const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);

    let mut backoff = INITIAL_BACKOFF;
    let mut first_attempt = true;

    loop {
        // Try TCP first (handles mainline: prefix and regular addresses)
        let tcp_result = resolve_bootstrap_addr(&addr);

        if let Some(connect_addr) = tcp_result {
            match discovery.connect(&connect_addr).await {
                Ok(transport) => {
                    match PeerLink::initiator(transport, &identity, None).await {
                        Ok(link) => {
                            let link = Arc::new(link);
                            let remote = link.remote_peer();
                            log::info!("Bootstrap connected to {:?} via {}", remote, addr);
                            let _ = event_tx
                                .send(NodeEvent::LinkUp(remote, link))
                                .await;

                            backoff = INITIAL_BACKOFF;
                            first_attempt = true;

                            // Wait until this link drops, then retry
                            loop {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                if !links.lock().await.contains_key(&remote) {
                                    log::info!("Bootstrap link to {:?} lost, reconnecting...", remote);
                                    break;
                                }
                            }
                            continue;
                        }
                        Err(e) => {
                            if first_attempt {
                                log::error!("Bootstrap handshake to {} failed: {}", addr, e);
                            } else {
                                log::debug!("Bootstrap handshake to {} failed: {}", addr, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if first_attempt {
                        log::error!("Bootstrap connect to {} failed: {}", addr, e);
                    } else {
                        log::debug!("Bootstrap connect to {} failed: {}", addr, e);
                    }
                }
            }
        }

        first_attempt = false;
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Resolve a bootstrap transport URI to a connectable string.
///
/// Supported formats:
///   - `tcp://host:port`     → strip scheme, connect via TCP
///   - `ws://host/path`      → pass through, connect via WebSocket
///   - `wss://host/path`     → pass through, connect via WebSocket
///   - `host:port`           → legacy bare address, connect via TCP
fn resolve_bootstrap_addr(addr: &str) -> Option<String> {
    if addr.starts_with("tcp://") {
        Some(addr.strip_prefix("tcp://").unwrap().to_string())
    } else if addr.starts_with("ws://") || addr.starts_with("wss://") {
        Some(addr.to_string())
    } else {
        // Bare address (hostname:port or ip:port) — return as-is,
        // DNS resolution happens inside TcpStream::connect
        Some(addr.to_string())
    }
}

/// Resolve a mainline DHT bootstrap address to a TCP connect string.
#[cfg(feature = "mainline-bootstrap")]
fn resolve_mainline_addr(addr: &str) -> Option<String> {
    let target_peer_id = match bootstrap::parse_mainline_addr(addr) {
        Ok(pid) => pid,
        Err(e) => {
            log::warn!("Invalid mainline bootstrap address '{}': {}", addr, e);
            return None;
        }
    };

    // MainlineDht::new() joins the network — this is heavyweight but only done
    // when we actually need to resolve. The DHT client is dropped after lookup.
    // TODO: share a single MainlineDht instance across the node lifetime
    let dht = match bootstrap::MainlineDht::new() {
        Ok(d) => d,
        Err(e) => {
            log::warn!("Failed to start mainline DHT client: {}", e);
            return None;
        }
    };

    let peers = dht.lookup(&target_peer_id);
    if let Some(peer) = peers.first() {
        let addr_str = format!("{}:{}", peer.ip(), peer.port());
        log::info!("Mainline DHT resolved {:?} to {}", target_peer_id, addr_str);
        Some(addr_str)
    } else {
        log::debug!("Mainline DHT: no peers found for {:?}", target_peer_id);
        None
    }
}

#[cfg(not(feature = "mainline-bootstrap"))]
fn resolve_mainline_addr(addr: &str) -> Option<String> {
    log::warn!(
        "Mainline bootstrap address '{}' requires the 'mainline-bootstrap' feature",
        addr
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarnet_api::types::{IdentityScheme, KemAlgo, SigningAlgo};

    #[tokio::test]
    async fn db_restores_pq_default_identity() {
        use crate::state::StateDb;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("tarnet-node-pq-{}.sqlite3", nanos));

        let original_identity = Keypair::generate();
        assert_eq!(original_identity.identity.signing_algo(), SigningAlgo::FalconEd25519);
        assert_eq!(original_identity.identity.kem_algo(), KemAlgo::MlkemX25519);

        let db = Arc::new(StateDb::open(&path).unwrap());
        let _original = Node::with_db(
            Keypair::from_full_bytes(&original_identity.to_full_bytes()).unwrap(),
            db.clone(),
            StorageLimits::default(),
        );

        // Re-open from the same DB with a different node identity
        let restored = Node::with_db(
            Keypair::generate(),
            db,
            StorageLimits::default(),
        );

        let identities = restored.list_identities().await;
        let default = identities
            .into_iter()
            .find(|(label, _, _, _, _, _, _)| label == "default")
            .expect("default identity should exist");
        assert_eq!(default.4, IdentityScheme::FalconEd25519);
        assert_eq!(default.5, SigningAlgo::FalconEd25519);
        assert_eq!(default.6, KemAlgo::MlkemX25519);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
