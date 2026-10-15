use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, Mutex};

use std::collections::HashSet;

use crate::firewall::{self as firewall, Firewall};
use crate::governor::{Governor, GovernorConfig, Verdict};

use crate::bootstrap;
use crate::channel::Channel;
use crate::circuit::{
    build_intro_register_payload, build_introduce_cell, build_introduce_payload,
    build_rendezvous_establish_payload, build_stream_begin_payload, created_signed_message,
    verify_intro_register, parse_introduce_cell, parse_introduce_payload,
    parse_rendezvous_establish_payload, parse_rendezvous_join_payload,
    parse_stream_begin_payload, seal_outward, write_cell_body, CircuitAction, CircuitKey, CircuitState as CircuitPhase, CircuitTable,
    CreateRequest, CreatedReply, CryptoOp, HopCrypto, HopKey, LayerKeys, OnionLayers, OutboundCircuit, Peeled,
    RelayCell, RelayCellCommand, RelayPiece, CELL_BODY_SIZE, CELL_PAYLOAD_MAX, CELL_SIZE,
};
use crate::dht::{
    DhtNeighbor, DhtRecord, DhtStore, DhtWatchTable, RecordSource, WalkStep,
};
use crate::identity::Keypair;
use crate::identity_store::IdentityStore;
use crate::key_exchange::{kex_accept, KexOffer};
use crate::link::PeerLink;
use crate::peer_transport::LinkTable;
use crate::pool::PoolStore;
use crate::pubkey_cache::PubkeyCache;
use crate::routing::RoutingTable;
use crate::state::{PersistedIdentity, StateDb, StorageLimits};
use crate::transport::webrtc::WebRtcConnector;
use crate::transport::Discovery;
use crate::tunnel::{Tunnel, TunnelTable};
use crate::types::{
    DhtId, Error, LinkId, PeerId, RecordType, Result, ScopedAddress, TransportType,
};
use crate::wire::*;
use tarnet_api::service::{Connection, Listener, ListenerOptions};

mod circuit;
mod dht;
mod directory;
mod hidden_service;
mod identity_mgmt;
mod pool;
mod route;
mod sample;
mod search;
pub(crate) mod sender;
mod stream;
mod tunnel;
mod webrtc;

pub use directory::{LandmarkConfig, LandmarkMode};

/// Create an interval that starts after a random jitter of `0..period/2`,
/// then ticks at `period`.  Desynchronizes periodic timers across nodes.
fn jittered_interval(period: Duration) -> tokio::time::Interval {
    use rand::Rng;
    let jitter = rand::thread_rng().gen_range(Duration::ZERO..period / 2);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + jitter, period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}
const DHT_EXPIRY_INTERVAL: Duration = Duration::from_secs(60);
/// How often a node republishes the (non-hello) records it published itself.
/// Owners republishing is what keeps DHT records alive.
const OWN_RECORD_REPUBLISH_INTERVAL: Duration = Duration::from_secs(1800);
/// Minimum time between link-up-triggered republishes of our own records.
const LINK_UP_REPUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(60);
/// Safety-net fallback for the retransmit task: maximum sleep when there are
/// no unacked packets or when no notify arrives.  Replaces the old 250ms poll.
const RETRANSMIT_SAFETY_INTERVAL: Duration = Duration::from_secs(5);
/// How long seen key-exchange nonces are cached (local monotonic time): long
/// enough to answer an initiator's retries; lasting replay protection is the
/// tunnel's own memory (`Tunnel::kex_nonces`).
const NONCE_CACHE_TTL: Duration = Duration::from_secs(120);
/// Most key exchanges remembered at once (see `kex_seen`).
const MAX_KEX_SEEN: usize = 4096;

/// How often the heartbeat / liveness scheduler wakes up. Fine enough that
/// the Poisson heartbeat draws aren't quantised into visible buckets, and
/// that a quiet link's liveness probes (every few seconds) go out on time.
const HEARTBEAT_TICK: Duration = Duration::from_secs(1);
/// Declare a link dead if no message received within this duration. A link
/// quiet for `peer_transport::PROBE_AFTER` is pinged every few seconds, so a
/// live link gets ~25 ping/pong chances in the remaining window: even with
/// half of all messages lost each way, a false positive is ≈ 0.75^25.
/// Note: circuits have their own faster liveness loop
/// (CIRCUIT_DEAD_TIMEOUT = 90s), so this isn't on the user-visible path.
const KEEPALIVE_DEAD_TIMEOUT: Duration = Duration::from_secs(180);
/// A responder link that hears nothing from the initiator this long after
/// the handshake is dropped: the initiator gave up
/// (its handshake times out after 30s), the link only black-holes traffic.
const UNCONFIRMED_LINK_TIMEOUT: Duration = Duration::from_secs(60);
/// How often initiator links are checked for a due (or unanswered) rekey.
const REKEY_SWEEP_TICK: Duration = Duration::from_millis(500);
/// Maximum random padding bytes added to each heartbeat. The padding size
/// is drawn uniformly from [0, this] so heartbeat packets don't form a
/// fingerprintable fixed-size class on the wire.
const HEARTBEAT_MAX_PADDING: usize = 256;
/// Maximum messages waiting for one circuit's FIFO worker.  A peer that can
/// outpace circuit processing must not be able to grow memory without bound.
const CIRCUIT_QUEUE_SIZE: usize = 256;
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
    PeerDisconnected { peer_id: PeerId },
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
            max_inbound: DEFAULT_MAX_INBOUND,
            max_outbound: DEFAULT_MAX_OUTBOUND,
        }
    }
}

const HELLO_PUBLISH_INTERVAL: Duration = Duration::from_secs(300);
const HELLO_TTL: u32 = 600;
/// How long background link upkeep searches for a peer's hello.
const HELLO_SEARCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How often we scan for Hidden identities that have no maintenance task yet.
/// Also paces the Public identities' peer-record maintenance.
const HIDDEN_SERVICE_MAINTAIN_INTERVAL: Duration = Duration::from_secs(240);

/// Default link limits (the daemon's config defaults use these too).
pub const DEFAULT_MAX_INBOUND: usize = 128;
pub const DEFAULT_MAX_OUTBOUND: usize = 48;
/// Rendezvous cookies held at once, and per client circuit.
const MAX_RENDEZVOUS: usize = 16 * 1024;
const MAX_RENDEZVOUS_PER_CIRCUIT: usize = 4;
/// A rendezvous lives this long once joined (its circuits may outlive it)...
const RENDEZVOUS_LIFETIME: Duration = Duration::from_secs(300);
/// ...and this long waiting for the service to join.
const RENDEZVOUS_JOIN_WAIT: Duration = Duration::from_secs(60);
/// INTRODUCE digests remembered at once, to drop replays.
const MAX_INTRODUCE_SEEN: usize = 16 * 1024;
/// INTRODUCEs a node's hidden services handle at once.
const MAX_CONCURRENT_INTRODUCTIONS: usize = 8;

/// How often each Hidden identity's task checks its intro circuits, drawn
/// uniformly from this range per check so identities stay unsynchronised.
const HIDDEN_SERVICE_CHECK_INTERVAL: std::ops::Range<Duration> =
    Duration::from_secs(20)..Duration::from_secs(40);

/// How often the daemon refreshes active pool-endpoint claims (leases). Must be
/// well under the claim TTL (default 45s) so a single missed refresh is tolerated
/// while a crashed node's claims still expire promptly. See `project_resource_pool`.
const POOL_CLAIM_REFRESH_INTERVAL: Duration = Duration::from_secs(15);


/// Rendezvous point state entry.
pub(crate) struct RendezvousEntry {
    client_circuit_id: u32,
    client_from: PeerId,
    service_circuit_id: Option<u32>,
    service_from: Option<PeerId>,
    created_at: Instant,
}

/// Circuit-related state grouped together.
#[derive(Clone)]
pub struct CircuitState {
    /// Circuit forwarding table.
    pub table: Arc<Mutex<CircuitTable>>,
    /// Outbound circuits we initiated (keyed by first_hop_circuit_id).
    /// Wrapped in [`ManagedCircuit`] so dropping triggers automatic cleanup.
    pub outbound: Arc<Mutex<HashMap<u32, ManagedCircuit>>>,
    /// Pending circuit extensions: circuit_id → oneshot sender for CircuitCreated.
    /// Used to wake the telescoping build when a hop confirms.
    pub pending_extends: Arc<Mutex<HashMap<u32, oneshot::Sender<Vec<u8>>>>>,
    /// Expected peer for an initial CircuitCreated response (before hop keys exist).
    pub pending_create_peers: Arc<Mutex<HashMap<u32, PeerId>>>,
    /// Pending relay extends: outbound_circuit_id → (inbound_from, inbound_circuit_id).
    /// When a relay sends CircuitCreate on behalf of an EXTEND, this maps the outbound
    /// circuit_id to the inbound circuit so the CircuitCreated reply can be routed back.
    pub relay_extend_pending: Arc<Mutex<crate::bounded::BoundedMap<CircuitKey, (PeerId, u32)>>>,
    /// Routed CREATEs we passed on, keyed by the downstream leg, until the
    /// destination's CREATED comes back.
    pub routed_pending: Arc<Mutex<crate::bounded::BoundedMap<CircuitKey, RoutedCreate>>>,
    /// Ephemeral keys of recent CREATEs (hashed) and the circuit that used
    /// each, to catch a CREATE that loops back.
    pub create_keys: Arc<Mutex<crate::bounded::BoundedMap<[u8; 32], CircuitKey>>>,
    /// CircuitCreated replies we sent, with a hash of the CREATE they answer,
    /// so a resent CREATE (the first reply was lost) gets the same reply.
    pub created_replies: Arc<Mutex<crate::bounded::BoundedMap<CircuitKey, ([u8; 32], Vec<u8>)>>>,
    /// Our backward layer keys for circuits we are a hop of, with the next
    /// counter for cells we seal ourselves.
    /// Key: (circuit_id, from_peer). Stored at CREATE time.
    pub hop_backward_keys: Arc<Mutex<HashMap<(u32, PeerId), HopBackward>>>,
    /// Per-circuit message queues: ensures control and data on the same circuit are
    /// processed in FIFO order rather than racing in spawned tasks.
    /// Key: (circuit_id, from_peer) → sender into that circuit's processing task.
    pub relay_queues: Arc<Mutex<HashMap<(u32, PeerId), mpsc::Sender<WireMessage>>>>,
    /// Multipath circuit groups: destination → CircuitGroup.
    pub groups: Arc<Mutex<crate::multipath::CircuitGroupTable>>,
    /// Initiator: circuits waiting for TRUNCATED from their last built hop.
    pub pending_truncates: Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>,
}

/// Our backward layer of a circuit we are a hop of.
pub struct HopBackward {
    pub keys: LayerKeys,
    /// Counter for cells we seal ourselves.
    pub counter: u64,
    /// Hash of the CREATE handshake that made this hop.
    pub transcript: [u8; 32],
}

/// A routed CREATE a relay passed on.
pub struct RoutedCreate {
    /// The leg the CREATE came in on.
    pub upstream: CircuitKey,
    /// Hash of its payload, to recognise resends.
    pub hash: [u8; 32],
    /// The CREATE as sent downstream, for resending.
    pub create: Vec<u8>,
}

impl CircuitState {
    fn new() -> Self {
        Self {
            table: Arc::new(Mutex::new(CircuitTable::new())),
            outbound: Arc::new(Mutex::new(HashMap::new())),
            pending_extends: Arc::new(Mutex::new(HashMap::new())),
            pending_create_peers: Arc::new(Mutex::new(HashMap::new())),
            relay_extend_pending: Arc::new(Mutex::new(crate::bounded::BoundedMap::new(
                circuit::MAX_PENDING_LEGS,
                circuit::ROUTED_CREATE_TIMEOUT,
            ))),
            routed_pending: Arc::new(Mutex::new(crate::bounded::BoundedMap::new(
                circuit::MAX_PENDING_LEGS,
                circuit::ROUTED_CREATE_TIMEOUT,
            ))),
            create_keys: Arc::new(Mutex::new(crate::bounded::BoundedMap::new(
                circuit::MAX_CREATE_KEYS,
                circuit::CREATE_KEY_TTL,
            ))),
            created_replies: Arc::new(Mutex::new(crate::bounded::BoundedMap::new(
                circuit::MAX_PENDING_LEGS,
                circuit::CREATED_REPLY_TTL,
            ))),
            hop_backward_keys: Arc::new(Mutex::new(HashMap::new())),
            relay_queues: Arc::new(Mutex::new(HashMap::new())),
            groups: Arc::new(Mutex::new(crate::multipath::CircuitGroupTable::new())),
            pending_truncates: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Endpoint (stream connection) state grouped together.
#[derive(Clone)]
pub struct EndpointState {
    /// Active connection state: circuit_id → (tx for sending data to the circuit).
    pub data_txs: Arc<Mutex<HashMap<CircuitKey, mpsc::Sender<Vec<u8>>>>>,
    streams: Arc<Mutex<HashMap<CircuitKey, Arc<stream::StreamState>>>>,
    /// Pending stream connect responses: circuit_id → oneshot (true=connected, false=refused).
    pub pending_connects: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    /// Track which link-peer owns each stream: circuit_id → peer_id.
    /// Used for per-peer stream limiting to prevent SYN flood from one peer
    /// blocking connections from others.
    pub stream_owners: Arc<Mutex<HashMap<CircuitKey, PeerId>>>,
}

/// Per-peer stream limit. Each link peer can have at most this many
/// concurrent streams to this node.
pub const MAX_STREAMS_PER_PEER: usize = 128;

/// Global stream limit. Safety net for total endpoint resource consumption.
pub const MAX_STREAMS_GLOBAL: usize = 1024;

impl EndpointState {
    fn new() -> Self {
        Self {
            data_txs: Arc::new(Mutex::new(HashMap::new())),
            streams: Arc::new(Mutex::new(HashMap::new())),
            pending_connects: Arc::new(Mutex::new(HashMap::new())),
            stream_owners: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Hidden service state grouped together.
#[derive(Clone)]
pub struct HiddenServiceState {
    /// Circuits we built TO intro points for our hidden services.
    /// Maps service_id → Vec<(intro_peer_id, circuit_id)>
    pub intros: Arc<Mutex<HashMap<tarnet_api::types::ServiceId, Vec<(PeerId, u32)>>>>,
    /// When each hidden service's zone root was last signed (with intro
    /// points, or without while none can be registered).
    pub last_publish: Arc<Mutex<HashMap<tarnet_api::types::ServiceId, Instant>>>,
    /// Hidden identities that have a running maintenance task.
    pub(super) maintained: Arc<Mutex<HashSet<tarnet_api::types::ServiceId>>>,
    /// Introduction point registrations: circuit_id → registered ServiceId
    pub intro_registrations:
        Arc<Mutex<HashMap<CircuitKey, (tarnet_api::types::ServiceId, PeerId)>>>,
    /// Rendezvous point state: cookie → RendezvousEntry
    pub(crate) rendezvous: Arc<Mutex<crate::bounded::BoundedMap<[u8; 32], RendezvousEntry>>>,
    /// Hashes of INTRODUCEs our services answered, to drop replays.
    pub(super) introduce_seen: Arc<Mutex<crate::bounded::BoundedMap<[u8; 32], ()>>>,
    /// INTRODUCEs handled at once; more are dropped.
    pub(super) introduce_slots: Arc<tokio::sync::Semaphore>,
}

impl HiddenServiceState {
    fn new() -> Self {
        Self {
            intros: Arc::new(Mutex::new(HashMap::new())),
            last_publish: Arc::new(Mutex::new(HashMap::new())),
            maintained: Arc::new(Mutex::new(HashSet::new())),
            intro_registrations: Arc::new(Mutex::new(HashMap::new())),
            rendezvous: Arc::new(Mutex::new(crate::bounded::BoundedMap::new(MAX_RENDEZVOUS, RENDEZVOUS_LIFETIME))),
            // An INTRODUCE can't be replayed once the records naming its
            // intro point have expired.
            introduce_seen: Arc::new(Mutex::new(crate::bounded::BoundedMap::new(
                MAX_INTRODUCE_SEEN,
                Duration::from_secs(2 * crate::tns::ZONE_ROOT_TTL as u64),
            ))),
            introduce_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_INTRODUCTIONS)),
        }
    }
}

/// Channel state grouped together.
#[derive(Clone)]
pub struct ChannelState {
    /// Channels by local handle (see [`crate::channel::ChannelTable`]).
    pub channels: Arc<Mutex<crate::channel::ChannelTable>>,
    /// Per-channel data handlers: channel_id → sender for data on that channel.
    /// Channels with a handler deliver data here instead of app_tx.
    pub data_handlers: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Port listeners: port_hash → sender that receives (peer_id, channel_id, data_rx)
    /// when a new channel opens on that port.
    pub port_listeners: Arc<
        Mutex<
            HashMap<
                [u8; 32],
                mpsc::UnboundedSender<(PeerId, u32, mpsc::UnboundedReceiver<Vec<u8>>)>,
            >,
        >,
    >,
    /// Wakes the retransmit task when a reliable send occurs so it can
    /// recalculate the next retransmit deadline instead of polling.
    pub retransmit_notify: Arc<tokio::sync::Notify>,
}

impl ChannelState {
    fn new() -> Self {
        Self {
            channels: Arc::new(Mutex::new(crate::channel::ChannelTable::default())),
            data_handlers: Arc::new(Mutex::new(HashMap::new())),
            port_listeners: Arc::new(Mutex::new(HashMap::new())),
            retransmit_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

struct ListenerState {
    listener: Listener,
    tx: Mutex<Option<mpsc::Sender<Connection>>>,
    rx: Mutex<mpsc::Receiver<Connection>>,
}

enum ListenerDispatch {
    NoListener,
    Enqueued,
    QueueFull,
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
    channel_state: ChannelState,
    event_tx: mpsc::Sender<NodeEvent>,
    event_rx: Mutex<Option<mpsc::Receiver<NodeEvent>>>,
    /// Lifecycle events (LinkUp/LinkDown) flow on a dedicated channel so they
    /// can't be starved behind Message backpressure on `event_tx`. The event
    /// loop drains this channel with bias over `event_rx`.
    lifecycle_tx: mpsc::Sender<NodeEvent>,
    lifecycle_rx: Mutex<Option<mpsc::Receiver<NodeEvent>>>,
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
    pending_key_exchanges: Arc<Mutex<crate::bounded::BoundedMap<[u8; 32], (KexOffer, oneshot::Sender<PeerId>, PeerId)>>>,
    /// Notifies app when an incoming tunnel is established (peer_id)
    tunnel_notify_tx: mpsc::Sender<PeerId>,
    tunnel_notify_rx: Mutex<Option<mpsc::Receiver<PeerId>>>,
    /// Channel for delivering channel lifecycle events (e.g. channel death) to the app.
    channel_event_tx: mpsc::Sender<ChannelEvent>,
    channel_event_rx: Mutex<Option<mpsc::Receiver<ChannelEvent>>>,
    /// Tunnel key exchanges answered recently, by initiator nonce: the
    /// initiator, and the response once sent, so a retry after a lost
    /// response gets the same answer (and keys) and a repeat is refused.
    kex_seen: Arc<Mutex<crate::bounded::BoundedMap<[u8; 32], (PeerId, Option<Vec<u8>>)>>>,
    /// Remote subscriptions: who wants notifications from us when a watched key changes.
    dht_watches: Arc<Mutex<DhtWatchTable>>,
    /// Keys we are watching locally.
    local_watches: Arc<Mutex<HashMap<[u8; 64], dht::LocalWatch>>>,
    /// Channel for delivering watch notifications to the application.
    dht_watch_tx: mpsc::Sender<(DhtId, DhtRecord)>,
    dht_watch_rx: Mutex<Option<mpsc::Receiver<(DhtId, DhtRecord)>>>,
    /// Query token routing table: maps query_token → (previous_hop, created_at).
    /// Used for anonymous hop-by-hop reply routing for DHT GETs and watch notifications.
    query_tokens: Arc<std::sync::Mutex<dht::QueryTokens>>,
    /// Active local DHT searches: maps query_token → a sender that the
    /// DhtGetResponse handler feeds verified records into, waking the
    /// originating [`DhtSearch`] stream. A `std::sync::Mutex` so the stream's
    /// `Drop` can deregister synchronously (RAII cancel).
    dht_searches:
        Arc<std::sync::Mutex<HashMap<[u8; 32], mpsc::Sender<crate::dht::VerifiedRecord>>>>,
    /// Launches PUT/GET/WATCH walks; shares the link, routing and token tables.
    dht_walker: dht::DhtWalker,
    /// Whether this node stores DHT records for others. Relay-only nodes
    /// (`false`) forward walks but never store, verify or cache them.
    dht_stores: bool,
    /// When our own records were last republished because a link came or
    /// went, and whether such a republish is scheduled.
    dht_link_up_republish: Mutex<(Option<Instant>, bool)>,
    /// Monotonically increasing sequence number for signed content records.
    signed_content_sequence: Arc<Mutex<u64>>,
    circuits: CircuitState,
    /// Sender half of the circuit-drop cleanup channel.
    circuit_drop_tx: mpsc::UnboundedSender<CircuitDropEvent>,
    /// Receiver half, taken by start() to spawn the cleanup task.
    circuit_drop_rx: Mutex<Option<mpsc::UnboundedReceiver<CircuitDropEvent>>>,
    endpoints: EndpointState,
    /// Active listeners keyed by listener id.
    listeners: Arc<Mutex<HashMap<u32, Arc<ListenerState>>>>,
    listener_next_id: AtomicU32,
    listener_rr: AtomicU64,
    hidden: HiddenServiceState,
    /// Relay sampling walks and the sampled relay pool.
    sampling: sample::SampleState,
    /// Landmark role, our address, the directory store and lookups.
    directory: directory::DirectoryState,
    /// Bounded route searches we run and relay.
    search: search::SearchState,
    /// This node, for spawning work from `&self` handlers. Set by `run`.
    weak_self: std::sync::OnceLock<std::sync::Weak<Node>>,
    /// Identity store: named keypairs with privacy levels.
    identity_store: Arc<Mutex<IdentityStore>>,
    /// Pool store: local name → joined virtual-cluster membership.
    pool_store: Arc<Mutex<PoolStore>>,
    /// Active pool claims this node advertises, keyed by (pool, service); refreshed by the lease timer.
    pool_claims: Arc<Mutex<HashMap<(String, String), pool::ActiveClaim>>>,
    /// WebRTC connection coordinator (None if WebRTC is disabled).
    webrtc_connector: Option<Arc<WebRtcConnector>>,
    /// Random secret embedded in hello records so only peers who have seen
    /// our hello can derive the WebRTC signaling channel port name.
    signaling_secret: [u8; 16],
    /// Cache of peer signing/KEM public keys (populated during link handshake).
    pubkey_cache: Arc<Mutex<PubkeyCache>>,
    /// Persistent write-through database (None for ephemeral/test nodes).
    db: Option<Arc<StateDb>>,
    /// Whether to announce on mainline DHT (set via enable_mainline).
    #[cfg(feature = "mainline-bootstrap")]
    mainline_enabled: bool,
    /// Optional stateful firewall for inbound message filtering.
    firewall: Mutex<Option<Firewall>>,
    /// Fast check: true when a firewall is configured.  Avoids locking the
    /// firewall mutex on every inbound message when no firewall is set.
    firewall_enabled: std::sync::atomic::AtomicBool,
    /// Resource governor: per-link-peer budgeting, strike system, circuit rate limiting.
    /// Always-on core infrastructure (unlike the optional firewall).
    governor: Mutex<Governor>,
    /// Lock-free statistics registry shared across all subsystems.
    pub stats: Arc<crate::stats::StatsRegistry>,
    /// Global bandwidth limiter shared across all links.
    bandwidth: Arc<crate::bandwidth::BandwidthLimiter>,
    /// Every send goes through this (see [`sender::Sender`]).
    sender: sender::Sender,
    /// Node start time for uptime calculation.
    started_at: std::time::Instant,
    /// TNS resolution cache: avoids repeated DHT lookups for recently resolved names.
    tns_cache: Arc<Mutex<crate::tns::TnsCache>>,
    /// In-memory working set of each owned zone's published records, keyed by
    /// zone ServiceId then label (serialized TnsRecord set). The durable source
    /// of truth a zone root is rebuilt and re-signed from on every change; the
    /// single funnel for ALL publishers (user labels, hidden-service intro/peer)
    /// so the rebuilt root always carries the whole zone. Hydrated lazily per
    /// zone from the published local labels.
    zone_published: Arc<
        Mutex<
            HashMap<tarnet_api::types::ServiceId, std::collections::BTreeMap<String, Vec<u8>>>,
        >,
    >,
    /// When we last sent each neighbour a full route dump on request.
    route_dumps_sent: Arc<Mutex<HashMap<PeerId, Instant>>>,
    /// Discovery handle for reconnection. Set by `run()`.
    discovery: Arc<Mutex<Option<Arc<Box<dyn Discovery>>>>>,
    /// Bootstrap addresses for isolation recovery. Set by `run()`.
    bootstrap_addrs: Arc<Mutex<Vec<String>>>,
    /// Guard to prevent multiple isolation recovery tasks from running.
    isolation_recovery_active: Arc<std::sync::atomic::AtomicBool>,
    /// Each link peer's inbound queues (see [`PeerLanes`]). Created with the
    /// peer's first link, dropped with its last.
    peer_lanes: std::sync::Mutex<HashMap<PeerId, PeerLanes>>,
}

/// How many of a peer's messages may wait in one of its lanes.
const PEER_LANE_SIZE: usize = 1024;

/// A link peer's inbound messages, handled one at a time and in arrival
/// order per lane: protocol state machines (routing dumps, DHT walks) see a
/// neighbour's messages in the order it sent them, never two at once. Data
/// has its own lane so control traffic doesn't wait behind an application
/// that is slow to read. Routing has its own ordered lane so throttled
/// application protocol replies cannot delay withdrawals or dump repair.
/// Circuits have their own queues (see the event loop).
struct PeerLanes {
    routing: mpsc::Sender<(LinkId, WireMessage)>,
    control: mpsc::Sender<(LinkId, WireMessage)>,
    data: mpsc::Sender<(LinkId, WireMessage)>,
    /// Cleared when the peer's last link goes: what is still queued is
    /// dropped rather than handled for a peer that is gone.
    alive: Arc<std::sync::atomic::AtomicBool>,
}

impl PeerLanes {
    fn new(node: &Arc<Node>, peer: PeerId) -> Self {
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let lane = || {
            let (tx, mut rx) = mpsc::channel::<(LinkId, WireMessage)>(PEER_LANE_SIZE);
            let node = node.clone();
            let alive = alive.clone();
            tokio::spawn(async move {
                while let Some((link_id, msg)) = rx.recv().await {
                    if !alive.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Err(e) = node.handle_message(peer, link_id, msg).await {
                        log::warn!("Error handling message from {:?}: {}", peer, e);
                    }
                }
            });
            tx
        };
        Self {
            routing: lane(),
            control: lane(),
            data: lane(),
            alive,
        }
    }

    fn lane(&self, mt: MessageType) -> &mpsc::Sender<(LinkId, WireMessage)> {
        match mt {
            MessageType::RouteUpdate | MessageType::RouteDigest | MessageType::RouteRequest => &self.routing,
            MessageType::Data
            | MessageType::EncryptedData
            | MessageType::TunnelKeyExchange
            | MessageType::TunnelKeyResponse => &self.data,
            _ => &self.control,
        }
    }
}

impl Drop for PeerLanes {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Relaxed);
    }
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
        let mut full =
            Vec::with_capacity(4 + entry.signing_key_material.len() + entry.kem_key_material.len());
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
        Self::build(
            identity,
            Vec::new(),
            0,
            0,
            StorageLimits::default(),
            None,
        )
    }

    /// Create a node backed by a persistent `StateDb`.
    /// Loads identities, DHT records, and metadata from the database.
    pub fn with_db(identity: Keypair, db: Arc<StateDb>, storage_limits: StorageLimits) -> Self {
        let identities = db.load_identities().unwrap_or_default();
        let hello_seq = db
            .get_metadata("hello_sequence")
            .unwrap_or(None)
            .unwrap_or(0);
        let sc_seq = db
            .get_metadata("signed_content_sequence")
            .unwrap_or(None)
            .unwrap_or(0);

        Self::build(
            identity,
            identities,
            hello_seq,
            sc_seq,
            storage_limits,
            Some(db),
        )
    }

    fn build(
        identity: Keypair,
        identities: Vec<PersistedIdentity>,
        hello_seq: u64,
        sc_seq: u64,
        storage_limits: StorageLimits,
        db: Option<Arc<StateDb>>,
    ) -> Self {
        let peer_id = identity.peer_id();
        let identity_store = if identities.is_empty() {
            let default_kp = Keypair::generate_with_scheme(identity.scheme());
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
            let default_entry = identities
                .iter()
                .find(|i| i.is_default)
                .or_else(|| identities.first());
            match default_entry {
                Some(entry) => {
                    let kp = restore_keypair_from_persisted(entry);
                    let mut store =
                        IdentityStore::with_default(kp, entry.privacy, entry.outbound_hops);
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
                    let default_kp = Keypair::generate_with_scheme(identity.scheme());
                    IdentityStore::with_default(
                        default_kp,
                        tarnet_api::types::PrivacyLevel::Public,
                        1,
                    )
                }
            }
        };
        // Restore joined pools (virtual-cluster memberships) from the DB.
        let mut pool_store = PoolStore::new();
        if let Some(ref db) = db {
            for (name, kind_tag, key_blob) in db.load_pools().unwrap_or_default() {
                match kind_tag {
                    0 if key_blob.len() == 32 => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&key_blob);
                        pool_store.join(&name, tarnet_api::service::PoolKind::Closed { key });
                    }
                    _ => log::warn!("Skipping unrecognized pool '{}' (kind {})", name, kind_tag),
                }
            }
        }

        let (event_tx, event_rx) = mpsc::channel(256);
        let (lifecycle_tx, lifecycle_rx) = mpsc::channel(64);
        let (app_tx, app_rx) = mpsc::channel(256);
        let (tunnel_notify_tx, tunnel_notify_rx) = mpsc::channel(256);
        let (dht_watch_tx, dht_watch_rx) = mpsc::channel(256);
        let (channel_event_tx, channel_event_rx) = mpsc::channel(256);
        let (circuit_drop_tx, circuit_drop_rx) = mpsc::unbounded_channel();
        let dht_store = match &db {
            Some(db) => DhtStore::open(&peer_id, storage_limits, db.clone()),
            None => DhtStore::with_limits(&peer_id, storage_limits),
        };
        let links = Arc::new(Mutex::new(LinkTable::new()));
        let routing_table = Arc::new(Mutex::new(RoutingTable::new(peer_id)));
        let stats = Arc::new(crate::stats::StatsRegistry::new());
        let bandwidth = Arc::new(crate::bandwidth::BandwidthLimiter::new(0, 0));
        let sender = sender::Sender::new(links.clone(), routing_table.clone());
        let query_tokens = Arc::new(std::sync::Mutex::new(dht::QueryTokens::new(
            dht::MAX_QUERY_TOKENS,
            dht::QUERY_TOKEN_TTL,
        )));
        let dht_walker = dht::DhtWalker {
            local: peer_id,
            links: links.clone(),
            routing_table: routing_table.clone(),
            neighbor_stores: Arc::new(Mutex::new(HashMap::new())),
            query_tokens: query_tokens.clone(),
            sender: sender.clone(),
        };
        Self {
            identity: Arc::new(identity),
            max_inbound: DEFAULT_MAX_INBOUND,
            max_outbound: DEFAULT_MAX_OUTBOUND,
            links,
            routing_table,
            sender,
            dht_store: Arc::new(Mutex::new(dht_store)),
            tunnel_table: Arc::new(Mutex::new(TunnelTable::new())),
            channel_state: ChannelState::new(),
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            lifecycle_tx,
            lifecycle_rx: Mutex::new(Some(lifecycle_rx)),
            app_rx: Mutex::new(Some(app_rx)),
            app_tx,
            global_addrs: Arc::new(Mutex::new(Vec::new())),
            introducers: Arc::new(Mutex::new(Vec::new())),
            hello_sequence: Arc::new(Mutex::new(hello_seq)),
            pending_key_exchanges: Arc::new(Mutex::new(crate::bounded::BoundedMap::new(
                tunnel::MAX_PENDING_KEX,
                tunnel::KEX_RETRY_WINDOW,
            ))),
            tunnel_notify_tx,
            tunnel_notify_rx: Mutex::new(Some(tunnel_notify_rx)),
            channel_event_tx,
            channel_event_rx: Mutex::new(Some(channel_event_rx)),
            kex_seen: Arc::new(Mutex::new(crate::bounded::BoundedMap::new(
                MAX_KEX_SEEN,
                NONCE_CACHE_TTL,
            ))),
            dht_watches: Arc::new(Mutex::new(DhtWatchTable::new())),
            local_watches: Arc::new(Mutex::new(HashMap::new())),
            dht_watch_tx,
            dht_watch_rx: Mutex::new(Some(dht_watch_rx)),
            query_tokens,
            dht_searches: Arc::new(std::sync::Mutex::new(HashMap::new())),
            dht_walker,
            dht_stores: true,
            dht_link_up_republish: Mutex::new((None, false)),
            signed_content_sequence: Arc::new(Mutex::new(sc_seq)),
            circuits: CircuitState::new(),
            circuit_drop_tx,
            circuit_drop_rx: Mutex::new(Some(circuit_drop_rx)),
            endpoints: EndpointState::new(),
            listeners: Arc::new(Mutex::new(HashMap::new())),
            listener_next_id: AtomicU32::new(1),
            listener_rr: AtomicU64::new(0),
            hidden: HiddenServiceState::new(),
            sampling: sample::SampleState::new(),
            directory: directory::DirectoryState::new(),
            search: search::SearchState::new(),
            weak_self: std::sync::OnceLock::new(),
            identity_store: Arc::new(Mutex::new(identity_store)),
            pool_store: Arc::new(Mutex::new(pool_store)),
            pool_claims: Arc::new(Mutex::new(HashMap::new())),
            webrtc_connector: None,
            signaling_secret: rand::random(),
            pubkey_cache: Arc::new(Mutex::new(PubkeyCache::new(1024))),
            db,
            #[cfg(feature = "mainline-bootstrap")]
            mainline_enabled: false,
            firewall: Mutex::new(None),
            firewall_enabled: std::sync::atomic::AtomicBool::new(false),
            governor: Mutex::new(Governor::new(GovernorConfig::default())),
            stats,
            bandwidth,
            started_at: std::time::Instant::now(),
            tns_cache: Arc::new(Mutex::new(crate::tns::TnsCache::new())),
            zone_published: Arc::new(Mutex::new(HashMap::new())),
            route_dumps_sent: Arc::new(Mutex::new(HashMap::new())),
            discovery: Arc::new(Mutex::new(None)),
            bootstrap_addrs: Arc::new(Mutex::new(Vec::new())),
            isolation_recovery_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            peer_lanes: std::sync::Mutex::new(HashMap::new()),
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
        self.firewall_enabled.store(true, Ordering::Relaxed);
    }

    /// Remove the firewall (accept-all).
    pub async fn clear_firewall(&self) {
        *self.firewall.lock().await = None;
        self.firewall_enabled.store(false, Ordering::Relaxed);
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

    /// Whether one of our identities is the zone `sid`.
    pub async fn owns_zone(&self, sid: &tarnet_api::types::ServiceId) -> bool {
        self.identity_store.lock().await.contains_service_id(sid)
    }

    /// Look up a keypair by ServiceId. Returns None if no matching identity exists.
    pub async fn keypair_for_service(&self, sid: &tarnet_api::types::ServiceId) -> Option<Keypair> {
        self.identity_store
            .lock()
            .await
            .keypair_for(sid)
            .map(|kp| Keypair::from_full_bytes(&kp.to_full_bytes()).unwrap())
    }

    /// The node's default ServiceId as raw bytes (52 bytes: pubkey + hash).
    pub async fn default_service_address(&self) -> [u8; 32] {
        self.identity_store.lock().await.default_service_id().0
    }

    /// Get a clone of the lifecycle sender for injecting LinkUp/LinkDown events
    /// from outside (e.g. mDNS, simulation harness). This is intentionally the
    /// lifecycle channel, not the message channel — handshake-completion must
    /// not block behind data-plane traffic.
    pub fn event_sender(&self) -> mpsc::Sender<NodeEvent> {
        self.lifecycle_tx.clone()
    }

    /// Get a clone of the identity keypair.
    pub fn identity_clone(&self) -> Arc<Keypair> {
        self.identity.clone()
    }

    /// Start the node: listen for connections, connect to bootstrap peers, run event loop.
    /// `bootstrap` lists transport URIs (e.g. `tcp://host:port`, `ws://host/path`).
    /// `discovery_addrs` lists discovery URIs (e.g. `mainline:<hex>`) that resolve to transport addresses.
    pub async fn run(
        self: Arc<Self>,
        discovery: Box<dyn Discovery>,
        bootstrap: Vec<String>,
        discovery_addrs: Vec<String>,
    ) -> Result<()> {
        let _ = self.weak_self.set(Arc::downgrade(&self));
        let discovery: Box<dyn Discovery> = Box::new(crate::transport::metered::MeteredDiscovery::new(
            discovery, self.bandwidth.clone(), self.stats.clone(),
        ));
        let discovery = Arc::new(discovery);
        *self.discovery.lock().await = Some(discovery.clone());
        *self.bootstrap_addrs.lock().await = bootstrap.clone();

        // Start accepting connections.
        //
        // Cap the number of *concurrent, not-yet-authenticated* handshakes. A
        // remote can otherwise open connections that never finish the handshake
        // and pin one task + socket + buffer each for up to the handshake
        // timeout — `max_inbound` only limits *established* links, so it does
        // not catch this. Excess connections are dropped immediately (the
        // transport closes) rather than queued, so the flood can't grow
        // unbounded. Headroom over `max_inbound` leaves room for legitimate
        // bursts where many peers connect at once.
        let max_inflight = self.max_inbound.max(64).saturating_add(64);
        let handshake_limit = Arc::new(tokio::sync::Semaphore::new(max_inflight));
        let disc_accept = discovery.clone();
        let event_tx = self.lifecycle_tx.clone();
        let identity = self.identity.clone();
        tokio::spawn(async move {
            loop {
                match disc_accept.accept().await {
                    Ok(transport) => {
                        let permit = match handshake_limit.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                log::warn!(
                                    "Inbound handshake limit ({}) reached, dropping connection",
                                    max_inflight
                                );
                                // Drop `transport` → closes the connection.
                                continue;
                            }
                        };
                        let tx = event_tx.clone();
                        let id = identity.clone();
                        tokio::spawn(async move {
                            // Hold the permit for the lifetime of the handshake;
                            // it is released when this task ends (success or fail).
                            let _permit = permit;
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
            let tx = self.lifecycle_tx.clone();
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
            let tx = self.lifecycle_tx.clone();
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
                // Peers tried recently, not tried again for this long.
                let mut cooldown = crate::bounded::BoundedMap::new(4096, Duration::from_secs(300));
                let mut interval = jittered_interval(Duration::from_secs(30));
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
                let mut interval = jittered_interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    node.try_fill_outbound_links(&disc).await;
                }
            });
        }

        // Pool claim lease refresh: re-publish active pool-endpoint claims before
        // their TTL so live endpoints persist and crashed ones expire (soft state).
        {
            let node = self.clone();
            tokio::spawn(async move {
                let mut interval = jittered_interval(POOL_CLAIM_REFRESH_INTERVAL);
                loop {
                    interval.tick().await;
                    let n = node.refresh_pool_claims().await;
                    if n > 0 {
                        log::debug!("Refreshed {} pool claim(s)", n);
                    }
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
                let mut interval = jittered_interval(HIDDEN_SERVICE_MAINTAIN_INTERVAL);
                loop {
                    interval.tick().await;
                    node.maintain_hidden_services().await;
                }
            });
        }

        // Zone maintenance for Public identities: publishing the peer record
        // re-signs the whole zone root, every published label with it, so this
        // one timer keeps names alive. (Hidden zones: `maintain_hidden_services`.)
        {
            let node = self.clone();
            tokio::spawn(async move {
                // Wait for bootstrap to settle before first publish
                tokio::time::sleep(Duration::from_secs(15)).await;
                node.maintain_peer_records().await;
                let mut interval = jittered_interval(HIDDEN_SERVICE_MAINTAIN_INTERVAL);
                loop {
                    interval.tick().await;
                    node.maintain_peer_records().await;
                }
            });
        }

        // Run the event loop
        self.event_loop(self.clone()).await
    }

    /// Attempt WebRTC upgrades to peers reachable only via relay.
    async fn try_webrtc_upgrades(&self, cooldown: &mut crate::bounded::BoundedMap<PeerId, ()>) {

        // Don't try to upgrade if we already have enough outbound links.
        if self.max_outbound > 0 {
            let outbound_count = self.links.lock().await.outbound_count();
            if outbound_count >= self.max_outbound {
                return;
            }
        }

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
            if cooldown.contains_key(&peer_id) {
                continue;
            }

            // Check if peer's hello record advertises WebRTC
            let _ = cooldown.try_insert(peer_id, ());
            let Some(hello) = self.find_hello(&peer_id, HELLO_SEARCH_TIMEOUT).await else {
                continue;
            };
            if hello.transports.contains(&TransportType::WebRtc) {
                log::info!("Attempting WebRTC upgrade to {:?}", peer_id);
                if let Err(e) = self.connect_webrtc(peer_id).await {
                    log::debug!("WebRTC upgrade to {:?} failed: {}", peer_id, e);
                }
            }
        }
    }

    /// Proactively fill outbound link slots by connecting to known peers.
    /// Candidates are peers we reach only through others, whose hellos
    /// advertise connectable addresses.
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

        // Candidates: peers we reach only through others.
        let candidates: Vec<PeerId> = {
            let table = self.routing_table.lock().await;
            let links = self.links.lock().await;
            table
                .all_destinations()
                .filter(|(pid, route)| route.cost > 1 && !links.contains_key(pid))
                .map(|(pid, _)| *pid)
                .take(slots)
                .collect()
        };

        for peer_id in candidates {
            if let Some(hello) = self.find_hello(&peer_id, HELLO_SEARCH_TIMEOUT).await {
                for addr in &hello.global_addresses {
                    if let Some(addr_str) = addr.to_connect_string() {
                        match discovery.connect(&addr_str).await {
                            Ok(transport) => {
                                match PeerLink::initiator(transport, &self.identity, Some(peer_id))
                                    .await
                                {
                                    Ok(link) => {
                                        let link = Arc::new(link);
                                        log::info!(
                                            "Proactive outbound link to {:?} via {}",
                                            link.remote_peer(),
                                            addr_str,
                                        );
                                        let _ = self
                                            .lifecycle_tx
                                            .send(NodeEvent::LinkUp(link.remote_peer(), link))
                                            .await;
                                        break; // one link per peer is enough
                                    }
                                    Err(e) => {
                                        log::debug!(
                                            "Proactive handshake to {:?} failed: {}",
                                            peer_id,
                                            e,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                log::debug!(
                                    "Proactive connect to {:?} at {} failed: {}",
                                    peer_id,
                                    addr_str,
                                    e,
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
        let mut lifecycle_rx = self
            .lifecycle_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::Protocol("event loop already running".into()))?;

        self.spawn_routing_task();
        self.spawn_sampling_task(node_arc.clone());
        self.spawn_directory_task(node_arc.clone());
        self.spawn_search_gc(node_arc.clone());

        // Per-link heartbeat / cover-traffic / liveness task. Every tick:
        //   1. Fire LinkDown for any link that hasn't received in DEAD_TIMEOUT.
        //   2. For each link whose Poisson-scheduled next-fire has elapsed,
        //      send a heartbeat with random padding (so heartbeats aren't a
        //      fixed-size class on the wire).
        let hb_links = self.links.clone();
        let hb_event_tx = self.lifecycle_tx.clone();
        tokio::spawn(async move {
            let mut interval = jittered_interval(HEARTBEAT_TICK);
            loop {
                interval.tick().await;

                let (dead, unconfirmed, due) = {
                    let mut links = hb_links.lock().await;
                    let dead = links.dead_links(KEEPALIVE_DEAD_TIMEOUT);
                    let unconfirmed = links.unconfirmed_links(UNCONFIRMED_LINK_TIMEOUT);
                    let due = links.heartbeat_due();
                    (dead, unconfirmed, due)
                };

                for (peer, link_id) in unconfirmed {
                    log::info!(
                        "Link to {:?} (link_id={}) never confirmed by the peer, dropping",
                        peer,
                        link_id
                    );
                    let _ = hb_event_tx.send(NodeEvent::LinkDown(peer, link_id)).await;
                }

                for (peer, link_id) in dead {
                    log::info!(
                        "Link to {:?} (link_id={}) timed out (no recv for {}s), declaring dead",
                        peer,
                        link_id,
                        KEEPALIVE_DEAD_TIMEOUT.as_secs()
                    );
                    let _ = hb_event_tx.send(NodeEvent::LinkDown(peer, link_id)).await;
                }

                if due.is_empty() {
                    continue;
                }

                for (_peer, _link_id, link) in due {
                    use rand::RngCore;
                    let pad_len = {
                        use rand::Rng;
                        rand::thread_rng().gen_range(0..=HEARTBEAT_MAX_PADDING)
                    };
                    let mut padding = vec![0u8; pad_len];
                    rand::thread_rng().fill_bytes(&mut padding);
                    let ka_msg = KeepaliveMsg {
                        ping_id: Some(rand::random()),
                        padding,
                    };
                    let encoded = ka_msg.to_wire().encode();
                    let _ = link.send_deferred(&encoded).await;
                }
            }
        });

        // Rekey sweep: rotate session keys on any link that has carried
        // REKEY_INTERVAL messages in either direction, giving long-lived links
        // forward secrecy against key compromise. Only the link initiator
        // drives this; the responder answers in-band. Runs on its own short
        // tick because it also resends requests whose reply was lost.
        let rk_links = self.links.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REKEY_SWEEP_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let rekey_links: Vec<Arc<PeerLink>> = {
                    let links = rk_links.lock().await;
                    links
                        .all_links()
                        .into_iter()
                        .filter(|l| l.is_initiator())
                        .collect()
                };
                for link in rekey_links {
                    if link.needs_rekey().await {
                        if let Err(e) = link.rekey_initiate().await {
                            log::debug!(
                                "Rekey initiate to {:?} failed: {}",
                                link.remote_peer(),
                                e
                            );
                        }
                    }
                }
            }
        });

        // Circuit drop cleanup task: handles async work triggered by the RAII
        // drop guard (CircuitDestroy message, connection teardown, multipath failover).
        let cd_sender = self.sender.clone();
        let cd_groups = self.circuits.groups.clone();
        let cd_endpoints = self.endpoints.clone();
        let cd_stream_owners = self.endpoints.stream_owners.clone();
        let cd_relay_queues = self.circuits.relay_queues.clone();
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
                let _ = cd_sender
                    .to_peer(
                        &ev.first_hop,
                        &destroy.to_wire().encode(),
                        sender::Queue::Critical,
                    )
                    .await;

                // Clean up connection state
                let stream_key = CircuitKey {
                    circuit_id: ev.circuit_id,
                    from_peer: ev.first_hop,
                };
                cd_endpoints.close_stream(stream_key).await;
                cd_stream_owners.lock().await.remove(&stream_key);
                cd_relay_queues
                    .lock()
                    .await
                    .remove(&(ev.first_hop_circuit_id, ev.first_hop));

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
        let ck_circuits = self.circuits.outbound.clone();
        let ck_sender = self.sender.clone();
        tokio::spawn(async move {
            let mut interval = jittered_interval(CIRCUIT_KEEPALIVE_INTERVAL);
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut dead_circuits = Vec::new();
                let mut idle_circuits = Vec::new();

                {
                    let circuits = ck_circuits.lock().await;
                    for (&cid, circuit) in circuits.iter() {
                        if circuit.state != CircuitPhase::Ready {
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

                        let encoded = encode_circuit_relay_cell(relay_cid, &cell);
                        // Cover traffic shares the same link I/O budget.
                        let _ = ck_sender
                            .to_peer(&first_hop, &encoded, sender::Queue::Data)
                            .await;
                    }
                }
            }
        });

        // Tear down routed CREATEs that were never answered.
        let half_open_ref = node_arc.clone();
        tokio::spawn(async move {
            let mut interval = jittered_interval(circuit::ROUTED_CREATE_TIMEOUT / 3);
            loop {
                interval.tick().await;
                half_open_ref.expire_routed_creates().await;
            }
        });

        // Tear down relay entries that stopped carrying cells.
        let idle_ref = node_arc.clone();
        tokio::spawn(async move {
            let mut interval = jittered_interval(circuit::RELAY_IDLE_TIMEOUT / 10);
            loop {
                interval.tick().await;
                idle_ref
                    .expire_idle_relay_entries(circuit::RELAY_IDLE_TIMEOUT)
                    .await;
            }
        });

        // Periodic governor tick: decay strikes, update pressure, drain reports.
        let gov_ref = node_arc.clone();
        tokio::spawn(async move {
            let mut interval = jittered_interval(crate::governor::GOVERNOR_TICK_INTERVAL);
            loop {
                interval.tick().await;
                let ct_len = gov_ref.circuits.table.lock().await.len();
                gov_ref.governor.lock().await.tick(ct_len);
            }
        });

        // Periodic DHT expiry and stale state cleanup
        let dht_ref = self.dht_store.clone();
        let watches_ref = self.dht_watches.clone();
        let tokens_ref = self.query_tokens.clone();
        let kex_seen_ref = self.kex_seen.clone();
        let relay_ext_ref = self.circuits.relay_extend_pending.clone();
        let pke_ref = self.pending_key_exchanges.clone();
        let rend_ref = self.hidden.rendezvous.clone();
        let intro_seen_ref = self.hidden.introduce_seen.clone();
        tokio::spawn(async move {
            let mut interval = jittered_interval(DHT_EXPIRY_INTERVAL);
            loop {
                interval.tick().await;
                dht_ref.lock().await.expire();
                watches_ref.lock().await.expire();
                let now = Instant::now();
                // Expire stale query token mappings
                tokens_ref.lock().unwrap().expire(now);
                kex_seen_ref.lock().await.expire(now);
                relay_ext_ref.lock().await.expire(now);
                pke_ref.lock().await.expire(now);
                // A completed rendezvous lives its full lifetime (circuits may
                // outlive the rendezvous); one the service never joined, less.
                rend_ref.lock().await.retain(|_, entry| {
                    entry.service_from.is_some()
                        || now.duration_since(entry.created_at) < RENDEZVOUS_JOIN_WAIT
                });
                intro_seen_ref.lock().await.expire(now);
            }
        });

        // Demand-driven retransmit and dead channel detection.
        // Instead of polling every 250ms, we sleep until the earliest retransmit
        // deadline across all channels.  A Notify wakes us when a new reliable
        // send occurs (which may set an earlier deadline).  A safety-net fallback
        // caps the sleep at RETRANSMIT_SAFETY_INTERVAL so a missed notify only
        // adds a few seconds of delay, not infinite stall.
        let retransmit_channels = self.channel_state.channels.clone();
        let retransmit_tunnel_table = self.tunnel_table.clone();
        let retransmit_sender = self.sender.clone();
        let retransmit_identity = self.identity.clone();
        let retransmit_event_tx = self.channel_event_tx.clone();
        let retransmit_notify = self.channel_state.retransmit_notify.clone();
        tokio::spawn(async move {
            loop {
                // Compute the next deadline across all channels.
                let deadline = {
                    let channels = retransmit_channels.lock().await;
                    channels.iter().filter_map(|(_, _, ch)| ch.next_wakeup()).min()
                };

                // Sleep until deadline, notify, or safety-net fallback.
                match deadline {
                    Some(at) => {
                        let delay = at.saturating_duration_since(Instant::now());
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {}
                            _ = retransmit_notify.notified() => {}
                        }
                    }
                    None => {
                        // No unacked data — wait for a send or safety fallback.
                        tokio::select! {
                            _ = tokio::time::sleep(RETRANSMIT_SAFETY_INTERVAL) => {}
                            _ = retransmit_notify.notified() => {}
                        }
                    }
                }

                // Collect retransmit work and dead channels under the channels lock,
                // then release it before doing I/O.
                let (retransmits, dead_channels, reopens) = {
                    let mut channels = retransmit_channels.lock().await;
                    let mut retransmits: Vec<(u32, PeerId, Vec<(u32, Vec<u8>)>)> = Vec::new();
                    let mut dead: Vec<(u32, PeerId)> = Vec::new();
                    let mut reopens: Vec<(PeerId, Vec<u8>)> = Vec::new();
                    let now = Instant::now();

                    for (channel_id, remote_peer, ch) in channels.iter_mut() {
                        if ch.is_dead() {
                            dead.push((channel_id, *remote_peer));
                            continue;
                        }
                        if ch.open_resend_due(now) {
                            let open = ChannelOpenMsg {
                                channel_id: ch.channel_id,
                                port: ch.port,
                                reliable: ch.reliable,
                                ordered: ch.ordered,
                            };
                            reopens.push((*remote_peer, open.to_wire().encode()));
                        }
                        let due = ch.retransmit_due();
                        if !due.is_empty() {
                            // On the wire, the channel's id, not our handle.
                            retransmits.push((ch.channel_id, *remote_peer, due));
                        }
                    }

                    for &(channel_id, _) in &dead {
                        channels.remove(channel_id);
                    }

                    (retransmits, dead, reopens)
                };

                // Resend unconfirmed ChannelOpens ahead of the data behind them.
                for (remote, inner) in reopens {
                    let (encrypted, hints) = {
                        let mut tt = retransmit_tunnel_table.lock().await;
                        let Some(t) = tt.get_mut(&remote) else { continue };
                        match t.encrypt(&inner) {
                            Ok(data) => (data, t.hints.clone()),
                            Err(_) => continue,
                        }
                    };
                    let msg = EncryptedDataMsg {
                        origin: retransmit_identity.peer_id(),
                        destination: remote,
                        ttl: crate::wire::DATA_TTL,
                        hints: hints.clone(),
                        data: encrypted,
                    };
                    let encoded = msg.to_wire_encrypted().encode();
                    let _ = retransmit_sender.routed(&remote, &hints, &encoded)
                    .await;
                }

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
                    let mut tt = retransmit_tunnel_table.lock().await;
                    let tunnel = match tt.get_mut(&remote) {
                        Some(t) => t,
                        None => continue,
                    };
                    let hints = tunnel.hints.clone();
                    let mut encoded_msgs = Vec::new();
                    for (seq, data) in &packets {
                        let channel_data = ChannelDataMsg {
                            channel_id,
                            sequence: *seq,
                            data: data.clone(),
                        };
                        let inner = channel_data.to_wire().encode();
                        let encrypted = match tunnel.encrypt(&inner) {
                            Ok(data) => data,
                            Err(e) => {
                                log::warn!("Tunnel encryption failed for {:?}: {}", remote, e);
                                continue;
                            }
                        };
                        let msg = EncryptedDataMsg {
                            origin: retransmit_identity.peer_id(),
                            destination: remote,
                            ttl: crate::wire::DATA_TTL,
                            hints: hints.clone(),
                            data: encrypted,
                        };
                        encoded_msgs.push((*seq, msg.to_wire_encrypted().encode()));
                    }
                    drop(tt);

                    // Route each retransmit
                    for (seq, encoded) in encoded_msgs {
                        let result = retransmit_sender.routed(&remote, &hints, &encoded)
                        .await;
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
        let hello_node = node_arc.clone();
        tokio::spawn(async move {
            // Wait a bit for initial links to establish
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut interval = jittered_interval(HELLO_PUBLISH_INTERVAL);
            loop {
                interval.tick().await;
                hello_node.publish_hello().await;
            }
        });

        // Owners keep their records alive: republish our own records, and keep
        // local watches' walks fresh as the topology changes.
        let republish_node = node_arc.clone();
        tokio::spawn(async move {
            let mut interval = jittered_interval(OWN_RECORD_REPUBLISH_INTERVAL);
            loop {
                interval.tick().await;
                republish_node.dht_republish_own().await;
            }
        });
        let watch_node = node_arc.clone();
        tokio::spawn(async move {
            let mut interval = jittered_interval(dht::WATCH_REFRESH_INTERVAL);
            loop {
                interval.tick().await;
                watch_node.dht_refresh_watches().await;
            }
        });

        // Process events. Lifecycle events (LinkUp/LinkDown) are polled with bias
        // over message events so handshake completion can't be starved behind a
        // data-plane backlog. If both channels close we exit.
        loop {
            let event = tokio::select! {
                biased;
                ev = lifecycle_rx.recv() => match ev {
                    Some(ev) => ev,
                    None => break,
                },
                ev = event_rx.recv() => match ev {
                    Some(ev) => ev,
                    None => break,
                },
            };
            match event {
                NodeEvent::LinkUp(peer_id, link) => {
                    self.handle_link_up(peer_id, link).await;
                    self.schedule_link_up_republish(&node_arc).await;
                }
                NodeEvent::LinkDown(peer_id, link_id) => {
                    self.remove_link(peer_id, link_id).await;
                }
                NodeEvent::Message(from, msg_link_id, msg) => {
                    // A message from a link that is already gone is stale:
                    // nothing it says applies to the peer's current state.
                    if !self.links.lock().await.touch_recv(&from, msg_link_id) {
                        continue;
                    }
                    match self.admit_message(&from, msg_link_id, &msg).await {
                        Verdict::Allow => {}
                        Verdict::Shed => continue,
                        Verdict::Blocked => {
                            self.disconnect_peer(&from).await;
                            continue;
                        }
                    }

                    if matches!(
                        msg.msg_type,
                        MessageType::CircuitRelay
                            | MessageType::CircuitCreate
                            | MessageType::CircuitCreated
                            | MessageType::CircuitDestroy
                    ) && msg.payload.len() >= 4
                    {
                        // Control messages must share DATA's FIFO: a spawned
                        // DESTROY could otherwise overtake the final DATA cells.
                        let circuit_id = u32::from_be_bytes([
                            msg.payload[0],
                            msg.payload[1],
                            msg.payload[2],
                            msg.payload[3],
                        ]);

                        // CREATE introduces circuit state, so there is no
                        // pre-existing per-circuit FIFO to attach to. Process it
                        // inline: allocating a queue first would let a peer
                        // create permanent queues with arbitrary IDs even when
                        // the CREATE is later rejected.
                        if msg.msg_type == MessageType::CircuitCreate {
                            if let Err(e) = self.handle_message(from, msg_link_id, msg).await {
                                log::warn!(
                                    "Error handling circuit create from {:?}: {}",
                                    from,
                                    e
                                );
                            }
                            continue;
                        }

                        let queue_key = (circuit_id, from);

                        // Do not let arbitrary circuit IDs allocate an
                        // unbounded FIFO and a permanent task. CREATE is the
                        // only message allowed to introduce a new ID; every
                        // other circuit message must refer to state already
                        // owned by this peer.
                        let key = CircuitKey {
                            circuit_id,
                            from_peer: from,
                        };
                        let admitted = if self.circuits.table.lock().await.lookup(&key).is_some() {
                            true
                        } else if self
                            .circuits
                            .outbound
                            .lock()
                            .await
                            .get(&circuit_id)
                            .is_some_and(|c| c.first_hop == from)
                        {
                            true
                        } else {
                            self.circuits
                                .pending_create_peers
                                .lock()
                                .await
                                .get(&circuit_id)
                                == Some(&from)
                        };
                        if !admitted {
                            log::debug!(
                                "Dropping {:?} for unknown circuit {} from {:?}",
                                msg.msg_type,
                                circuit_id,
                                from
                            );
                            continue;
                        }

                        let mut queues = self.circuits.relay_queues.lock().await;
                        let tx = queues.entry(queue_key).or_insert_with(|| {
                            let (tx, mut rx) = mpsc::channel::<WireMessage>(CIRCUIT_QUEUE_SIZE);
                            let node = node_arc.clone();
                            tokio::spawn(async move {
                                while let Some(msg) = rx.recv().await {
                                    if let Err(e) =
                                        node.handle_message(from, msg_link_id, msg).await
                                    {
                                        log::warn!(
                                            "Error handling circuit relay from {:?}: {}",
                                            from,
                                            e
                                        );
                                    }
                                }
                            });
                            tx
                        });
                        match tx.try_send(msg) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                log::warn!(
                                    "Circuit queue {} from {:?} is full; dropping message",
                                    circuit_id,
                                    from
                                );
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                // Receiver task exited — remove stale entry.
                                queues.remove(&queue_key);
                            }
                        }
                    } else {
                        let lanes = self.peer_lanes.lock().unwrap();
                        let Some(lanes) = lanes.get(&from) else { continue };
                        if lanes.lane(msg.msg_type).try_send((msg_link_id, msg)).is_err() {
                            log::debug!("Inbound queue from {:?} is full; dropping message", from);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_link_up(&self, peer_id: PeerId, link: Arc<PeerLink>) {
        let is_outbound = link.is_initiator();
        if self.governor.lock().await.is_blocked(&peer_id) {
            log::info!("Refusing link from blocked peer {:?}", peer_id);
            return;
        }

        // Check link limits before accepting. If at capacity, try to evict.
        {
            let links = self.links.lock().await;
            let (count, limit) = if is_outbound {
                (links.outbound_count(), self.max_outbound)
            } else {
                (links.inbound_count(), self.max_inbound)
            };

            if limit > 0 && count >= limit {
                let circuit_counts = self.circuits.table.lock().await.circuits_per_peer();
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
                        count,
                        limit,
                        peer_id,
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
            self.pubkey_cache.lock().await.insert(
                peer_id,
                CachedPubkey {
                    signing_algo: link.remote_signing_algo(),
                    signing_pk: link.remote_signing_pubkey().to_vec(),
                    // KEM pubkey not yet available from link — populated from DHT later.
                    kem_algo: tarnet_api::types::KemAlgo::X25519,
                    kem_pk: Vec::new(),
                },
            );
        }

        if is_first {
            self.governor.lock().await.peer_connected(peer_id);
            if let Some(node) = self.weak_self.get().and_then(|w| w.upgrade()) {
                self.peer_lanes
                    .lock()
                    .unwrap()
                    .insert(peer_id, PeerLanes::new(&node, peer_id));
            }
        }

        // Start recv loop for this link
        let event_tx = self.event_tx.clone();
        let lifecycle_tx = self.lifecycle_tx.clone();
        let remote = peer_id;
        let recv_link_id = link_id;
        let recv_task = tokio::spawn(async move {
            loop {
                match link.recv_message().await {
                    Ok(data) => {
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
                    // Frame-level failures must not kill the link. A stale frame
                    // (deferred-queue coalescing can reorder past the replay
                    // window under load) or an undecryptable frame (garbage
                    // injection) costs only that frame; tearing down the link
                    // would hand an attacker — or mere congestion — a kill
                    // switch for every circuit on it. A genuinely desynced
                    // link stops producing decryptable frames and is reaped
                    // by the keepalive dead-timeout instead.
                    Err(e @ (Error::Replay(_) | Error::Crypto(_))) => {
                        log::debug!("dropping bad frame from {:?}: {}", remote, e);
                    }
                    Err(e) => {
                        log::info!("recv_message from {:?} failed, link down: {}", remote, e);
                        let _ = lifecycle_tx
                            .send(NodeEvent::LinkDown(remote, recv_link_id))
                            .await;
                        break;
                    }
                }
            }
        });
        self.links
            .lock()
            .await
            .set_recv_task(&peer_id, link_id, recv_task.abort_handle());

        self.routing_link_up(&peer_id).await;

        // Relay-only nodes say so, so a relay-only neighbour can steer DELIVER
        // detours to a storing node. Storing is the assumed default, so a
        // storing node sends nothing.
        if !self.dht_stores {
            let msg = crate::wire::DhtNeighborMsg { flags: 0 }.to_wire().encode();
            let _ = self
                .sender
                .to_peer(&peer_id, &msg, sender::Queue::Deferred)
                .await;
        }
    }

    /// A link coming up or going down can move where walks for our keys end
    /// (and on startup it is the first chance to place anything; after a
    /// partition, an island re-places its records): republish our hello and
    /// our own records and relaunch our watches, 1–3 s after the change so it
    /// stays off a new link's handshake path and the routing table has
    /// settled. At most once per [`LINK_UP_REPUBLISH_MIN_INTERVAL`]: changes
    /// within it are folded into one republish at its end, never dropped (the
    /// links that come up right after the first carry the real network size).
    async fn schedule_link_up_republish(&self, node: &Arc<Node>) {
        let delay = {
            let mut state = self.dht_link_up_republish.lock().await;
            if state.1 {
                return; // one is already scheduled and will see this change
            }
            let jitter = {
                use rand::Rng;
                Duration::from_millis(rand::thread_rng().gen_range(1000..3000))
            };
            let wait = state
                .0
                .map_or(Duration::ZERO, |last| {
                    (last + LINK_UP_REPUBLISH_MIN_INTERVAL).saturating_duration_since(Instant::now())
                });
            state.1 = true;
            wait + jitter
        };
        let node = node.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            *node.dht_link_up_republish.lock().await = (Some(Instant::now()), false);
            node.publish_hello().await;
            node.dht_republish_own().await;
            node.dht_refresh_watches().await;
        });
    }

    /// Forcibly disconnect a peer by removing all its links.
    pub async fn disconnect_peer(&self, peer_id: &PeerId) {
        let ids = self.links.lock().await.link_ids(peer_id);
        for id in ids {
            self.remove_link(*peer_id, id).await;
        }
    }

    /// Gracefully evict a single link to make room for a new one.
    async fn evict_link(&self, peer_id: PeerId, link_id: LinkId) {
        self.remove_link(peer_id, link_id).await;
        log::info!("Evicted link {:?} link_id={}", peer_id, link_id);
    }

    /// The one way a link leaves: a failure, a timeout, an eviction or a
    /// disconnect. A link already removed (a repeated LinkDown) changes
    /// nothing.
    async fn remove_link(&self, peer_id: PeerId, link_id: LinkId) {
        let removed = self.links.lock().await.remove_link(&peer_id, link_id);
        match removed {
            crate::peer_transport::Removed::Unknown => return,
            crate::peer_transport::Removed::Link => {
                log::info!("Link down: {:?} (link_id={})", peer_id, link_id);
                self.routing_link_changed(&peer_id).await;
            }
            crate::peer_transport::Removed::Peer => {
                log::info!("Link down: {:?} (link_id={}), peer gone", peer_id, link_id);
                self.peer_gone(peer_id).await;
            }
        }
        // If we have zero links remaining, enter isolation recovery mode.
        // Try bootstrap peers + cached Hello addresses with exp backoff capped at 15min.
        if self.links.lock().await.is_empty() {
            self.spawn_isolation_recovery();
        }
    }

    /// Everything kept about a link peer goes when its last link does.
    async fn peer_gone(&self, peer_id: PeerId) {
        self.peer_lanes.lock().unwrap().remove(&peer_id);
        self.governor.lock().await.peer_disconnected(&peer_id);
        self.route_dumps_sent.lock().await.remove(&peer_id);
        self.routing_link_down(&peer_id).await;
        self.dht_watches.lock().await.remove_peer(&peer_id);
        self.dht_walker.neighbor_stores.lock().await.remove(&peer_id);
        self.cleanup_peer_circuits(peer_id).await;
        let _ = self
            .channel_event_tx
            .send(ChannelEvent::PeerDisconnected { peer_id })
            .await;
        if !self.links.lock().await.is_empty() {
            if let Some(node) = self.weak_self.get().and_then(|w| w.upgrade()) {
                self.schedule_link_up_republish(&node).await;
            }
        }
    }

    /// Close streams promptly whether a link fails, is evicted, or is explicitly
    /// disconnected. Outbound circuits are absent from the forwarding table.
    async fn cleanup_peer_circuits(&self, peer_id: PeerId) {
        let mut removed = self.circuits.table.lock().await.remove_peer(&peer_id);
        let mut outgoing = HashSet::new();
        {
            let mut outbound = self.circuits.outbound.lock().await;
            outbound.retain(|id, circuit| {
                if circuit.first_hop == peer_id {
                    removed.push((*id, peer_id));
                    outgoing.insert(*id);
                    false
                } else {
                    true
                }
            });
        }
        {
            let mut pending = self.circuits.pending_create_peers.lock().await;
            pending.retain(|id, peer| {
                if *peer == peer_id {
                    removed.push((*id, peer_id));
                    outgoing.insert(*id);
                    false
                } else {
                    true
                }
            });
        }
        for (cid, from) in &removed {
            // Tell the surviving side of a relay pair that its path is gone.
            // Do not hold circuit state locks across link backpressure.
            if *from != peer_id {
                let destroy = CircuitDestroyMsg { circuit_id: *cid }.to_wire().encode();
                let _ = self
                    .sender
                    .to_peer(from, &destroy, sender::Queue::Critical)
                    .await;
            }
            let stream_key = CircuitKey {
                circuit_id: *cid,
                from_peer: *from,
            };
            self.circuits
                .relay_queues
                .lock()
                .await
                .remove(&(*cid, *from));
            self.circuits
                .hop_backward_keys
                .lock()
                .await
                .remove(&(*cid, *from));
            self.hidden
                .intro_registrations
                .lock()
                .await
                .remove(&stream_key);
            self.endpoints.close_stream(stream_key).await;
            self.endpoints
                .stream_owners
                .lock()
                .await
                .remove(&stream_key);
            if outgoing.contains(cid) {
                self.endpoints.pending_connects.lock().await.remove(cid);
                self.circuits.pending_extends.lock().await.remove(cid);
            }
        }
        self.circuits
            .relay_extend_pending
            .lock()
            .await
            .retain(|id, (from, _)| *from != peer_id && id.from_peer != peer_id);
        self.circuits
            .routed_pending
            .lock()
            .await
            .retain(|down, p| down.from_peer != peer_id && p.upstream.from_peer != peer_id);
        self.hidden
            .rendezvous
            .lock()
            .await
            .retain(|_, entry| entry.client_from != peer_id && entry.service_from != Some(peer_id));
    }

    /// Spawn isolation recovery: when we have zero links, aggressively try to
    /// reconnect using bootstrap peers and cached Hello addresses.
    /// Exponential backoff from 5s to 15min, loops forever until a link is established.
    fn spawn_isolation_recovery(&self) {
        // Prevent multiple recovery tasks from stacking up.
        if self
            .isolation_recovery_active
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }

        log::warn!("Node isolated (zero links), starting isolation recovery");

        let discovery = self.discovery.clone();
        let links = self.links.clone();
        let identity = self.identity.clone();
        let event_tx = self.lifecycle_tx.clone();
        let bootstrap_addrs = self.bootstrap_addrs.clone();
        let dht_store = self.dht_store.clone();
        let active_flag = self.isolation_recovery_active.clone();

        tokio::spawn(async move {
            const BASE_DELAY: Duration = Duration::from_secs(5);
            const MAX_DELAY: Duration = Duration::from_secs(900); // 15 minutes

            let mut backoff = BASE_DELAY;

            // First attempt is immediate (no delay).
            let mut first = true;

            loop {
                if !first {
                    // Jitter: ±25% of backoff to avoid thundering herd
                    let jitter_range = backoff / 4;
                    let jitter = Duration::from_millis(rand::Rng::gen_range(
                        &mut rand::thread_rng(),
                        0..=jitter_range.as_millis() as u64 * 2,
                    ));
                    let delay = backoff - jitter_range + jitter;
                    tokio::time::sleep(delay).await;
                }
                first = false;

                // Check if we're still isolated.
                if !links.lock().await.is_empty() {
                    log::info!("Isolation recovery: link established, stopping");
                    active_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                    return;
                }

                let disc = match discovery.lock().await.clone() {
                    Some(d) => d,
                    None => {
                        active_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                        return;
                    }
                };

                // Gather seed addresses: bootstrap peers first, then cached Hellos.
                let mut seed_addrs: Vec<String> = Vec::new();

                // Bootstrap peers (always available, highest priority).
                for addr in bootstrap_addrs.lock().await.iter() {
                    if let Some(connect_addr) = resolve_bootstrap_addr(addr) {
                        seed_addrs.push(connect_addr);
                    }
                }

                // Addresses from the hellos we hold.
                let hellos = dht_store.lock().await.hellos();
                for hello in &hellos {
                    for addr in &hello.global_addresses {
                        if let Some(s) = addr.to_connect_string() {
                            if !seed_addrs.contains(&s) {
                                seed_addrs.push(s);
                            }
                        }
                    }
                }

                if seed_addrs.is_empty() {
                    log::warn!("Isolation recovery: no seed addresses available");
                    backoff = (backoff * 2).min(MAX_DELAY);
                    continue;
                }

                log::info!(
                    "Isolation recovery: trying {} seed addresses (backoff={}s)",
                    seed_addrs.len(),
                    backoff.as_secs(),
                );

                let mut connected = false;
                for addr_str in &seed_addrs {
                    match disc.connect(addr_str).await {
                        Ok(transport) => {
                            match PeerLink::initiator(transport, &identity, None).await {
                                Ok(link) => {
                                    let link = Arc::new(link);
                                    log::info!(
                                        "Isolation recovery: connected to {:?} via {}",
                                        link.remote_peer(),
                                        addr_str,
                                    );
                                    let _ = event_tx
                                        .send(NodeEvent::LinkUp(link.remote_peer(), link))
                                        .await;
                                    connected = true;
                                    break;
                                }
                                Err(e) => {
                                    log::debug!(
                                        "Isolation recovery: handshake to {} failed: {}",
                                        addr_str,
                                        e,
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            log::debug!(
                                "Isolation recovery: connect to {} failed: {}",
                                addr_str,
                                e,
                            );
                        }
                    }
                }

                if connected {
                    log::info!("Isolation recovery: reconnected, stopping");
                    active_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                    return;
                }

                backoff = (backoff * 2).min(MAX_DELAY);
            }
        });
    }

    /// The one gate every inbound link message passes before dispatch: the
    /// stateful firewall, then the governor, which charges the message's
    /// cost (see `governor::message_cost`).
    async fn admit_message(&self, from: &PeerId, link_id: LinkId, msg: &WireMessage) -> Verdict {
        // Skip the firewall lock entirely when none is configured.
        if self.firewall_enabled.load(Ordering::Relaxed) {
            let replied = self
                .links
                .lock()
                .await
                .get_link(from, link_id)
                .is_some_and(|l| l.has_sent_category_of(msg.msg_type));
            let mut fw_guard = self.firewall.lock().await;
            if let Some(fw) = fw_guard.as_mut() {
                if matches!(fw.evaluate(from, msg, replied), firewall::Action::Drop) {
                    return Verdict::Shed;
                }
            }
        }
        self.governor
            .lock()
            .await
            .evaluate(from, msg.msg_type, &msg.payload)
    }

    async fn handle_message(
        &self,
        from: PeerId,
        msg_link_id: LinkId,
        msg: WireMessage,
    ) -> Result<()> {
        match msg.msg_type {
            MessageType::RouteUpdate => {
                self.handle_route_update(from, &msg.payload).await?;
            }
            MessageType::RouteDigest => {
                self.handle_route_digest(from, &msg.payload).await?;
            }
            MessageType::RouteRequest => {
                self.handle_route_request(from, &msg.payload).await?;
            }
            MessageType::SampleWalk => {
                self.handle_sample_walk(from, &msg.payload).await?;
            }
            MessageType::SampleResult => {
                self.handle_sample_result(from, &msg.payload).await?;
            }
            MessageType::DirPublish => {
                self.handle_dir_publish(from, &msg.payload).await?;
            }
            MessageType::DirLookup => {
                self.handle_dir_lookup(from, &msg.payload).await?;
            }
            MessageType::DirResult => {
                self.handle_dir_result(from, &msg.payload).await?;
            }
            MessageType::PathTrace => {
                self.handle_path_trace(from, &msg.payload).await?;
            }
            MessageType::PathTraceResult => {
                self.handle_path_trace_result(from, &msg.payload).await?;
            }
            MessageType::RouteSearch => {
                self.handle_route_search(from, &msg.payload).await?;
            }
            MessageType::RouteSearchFound => {
                self.handle_route_search_found(from, &msg.payload).await?;
            }
            MessageType::DhtPut => self.handle_dht_put(from, &msg.payload).await?,
            MessageType::DhtGet => self.handle_dht_get(from, &msg.payload).await?,
            MessageType::DhtGetResponse => self.handle_dht_get_response(from, &msg.payload).await?,
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
                let rekey = RekeyMsg::from_bytes(&msg.payload)?;
                // Drive the rekey on the exact link the message arrived on —
                // not merely the active link, which may use different keys.
                let link = self.links.lock().await.get_link(&from, msg_link_id);
                if let Some(link) = link {
                    if let Err(e) = link.handle_rekey_msg(&rekey).await {
                        log::warn!("Rekey from {:?} failed: {}", from, e);
                    }
                } else {
                    log::debug!(
                        "Rekey from {:?} for unknown link_id={}, ignoring",
                        from,
                        msg_link_id
                    );
                }
            }
            MessageType::Keepalive => {
                let ka = KeepaliveMsg::from_bytes(&msg.payload)?;
                if ka.ping_id.is_some() {
                    // This is a ping — echo it back as a pong (no timestamp = pong)
                    // Pong: random padding so pongs aren't a distinguishable
                    // fixed-size response either.
                    use rand::RngCore;
                    let pad_len = {
                        use rand::Rng;
                        rand::thread_rng().gen_range(0..=HEARTBEAT_MAX_PADDING)
                    };
                    let mut padding = vec![0u8; pad_len];
                    rand::thread_rng().fill_bytes(&mut padding);
                    let pong = KeepaliveMsg {
                        ping_id: None,
                        padding,
                    };
                    let _ = self
                        .sender
                        .to_peer(&from, &pong.to_wire().encode(), sender::Queue::Deferred)
                        .await;
                }
                // Pong — activity is already tracked by touch_recv above.
            }
            MessageType::DhtWatch => self.handle_dht_watch(from, &msg.payload).await?,
            MessageType::DhtWatchNotify => self.handle_dht_watch_notify(from, &msg.payload).await?,
            MessageType::DhtNeighbor => {
                let info = crate::wire::DhtNeighborMsg::from_bytes(&msg.payload)?;
                self.dht_walker
                    .neighbor_stores
                    .lock()
                    .await
                    .insert(from, info.stores());
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
            // Unknown message types never reach this match: from_u16
            // returns None for them.
        }
        Ok(())
    }

    async fn send_to_peer(&self, peer: &PeerId, data: &[u8]) -> Result<()> {
        self.sender.to_peer(peer, data, sender::Queue::Data).await
    }

    /// Send a circuit-control message, awaiting link queue capacity instead
    /// of dropping when the peer is congested. One-shot control cells
    /// (CREATE/EXTEND/EXTENDED/StreamBegin/…) have no retransmission, so the
    /// data path's silent-drop policy would turn congestion into hard
    /// connect failures.
    ///
    /// The link Arc is cloned out of the table before the awaited send so the
    /// global links lock is never held while waiting for queue space.
    async fn send_to_peer_critical(&self, peer: &PeerId, data: &[u8]) -> Result<()> {
        self.sender.to_peer(peer, data, sender::Queue::Critical).await
    }

    /// Send a non-critical message via the deferred (coalescing) queue.
    /// The link drain task holds these briefly and flushes them alongside
    /// the next high-priority send.
    async fn send_to_peer_deferred(&self, peer: &PeerId, data: &[u8]) -> Result<()> {
        self.sender.to_peer(peer, data, sender::Queue::Deferred).await
    }

    /// Rekey every link this node initiated on the next sweep (testing).
    #[doc(hidden)]
    pub async fn request_link_rekey(&self) {
        for link in self.links.lock().await.all_links() {
            link.request_rekey();
        }
    }

    /// Key epoch of the active link to `peer` (testing).
    #[doc(hidden)]
    pub async fn link_key_epoch(&self, peer: &PeerId) -> Option<u64> {
        let link = self.links.lock().await.get(peer).cloned()?;
        Some(link.key_epoch().await)
    }

    /// Get the list of connected peers.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.links.lock().await.keys().copied().collect()
    }

    /// Cost of the best route to `dest`, if any.
    pub async fn route_cost(&self, dest: &PeerId) -> Option<u32> {
        self.routing_table.lock().await.lookup(dest).map(|r| r.cost)
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
        let peers: Vec<PeerStatus> = peer_infos
            .into_iter()
            .map(|pi| PeerStatus {
                peer_id: pi.peer_id,
                links: pi
                    .links
                    .into_iter()
                    .map(|li| LinkStatus {
                        link_id: li.link_id,
                        state: li.state.to_string(),
                        direction: li.direction.to_string(),
                        rtt_us: li.rtt_us,
                        loss_rate: li.loss_rate,
                        age_secs: li.age_secs,
                        idle_secs: li.idle_secs,
                        transport: li.transport.to_string(),
                    })
                    .collect(),
            })
            .collect();

        // Routes
        let routes = {
            let table = self.routing_table.lock().await;
            table
                .all_destinations()
                .map(|(dest, route)| (*dest, route.next_hop, route.cost))
                .collect()
        };

        // DHT
        let dht = {
            let store = self.dht_store.lock().await;
            // Network size as the DHT sizes its walks.
            let nse = self.routing_table.lock().await.network_size_estimate() as u64;
            let local_watches = self.local_watches.lock().await.len();
            let remote_watches = self.dht_watches.lock().await.watch_count();
            DhtStatus {
                stored_keys: store.key_count(),
                stored_records: store.record_count(),
                local_watches,
                remote_watches,
                nse,
            }
        };

        // Circuits
        let circuits = {
            let ct = self.circuits.table.lock().await;
            let outbound = self.circuits.outbound.lock().await.len();
            let rendezvous = self.hidden.rendezvous.lock().await.len();
            let intro = self.hidden.intro_registrations.lock().await.len();
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

    /// Choose whether this node stores DHT records for others. Relay-only nodes
    /// (`false`, e.g. low-power relays) forward DHT walks but never store or
    /// verify other nodes' records. Set before [`run`](Self::run).
    pub fn set_dht_store(&mut self, stores: bool) {
        self.dht_stores = stores;
        if !stores {
            // Relay-only: replicas reloaded from the database go too.
            if let Ok(mut store) = self.dht_store.try_lock() {
                store.drop_replicas();
            }
        }
    }

    /// Configure link limits. 0 = unlimited.
    pub fn set_link_limits(&mut self, max_inbound: usize, max_outbound: usize) {
        self.max_inbound = max_inbound;
        self.max_outbound = max_outbound;
    }

    /// Configure total link-message bandwidth, including encryption, padding,
    /// handshakes and repairs. Rates are bytes/sec; 0 = unlimited. Lower-layer
    /// transport framing (TCP/WebSocket/IP) is outside these totals.
    pub fn set_bandwidth_limits(&mut self, upload_rate: u64, download_rate: u64) {
        self.bandwidth.set_rates(upload_rate, download_rate);
    }

    /// Update bandwidth rates on an already-running node (e.g. config reload).
    pub async fn update_bandwidth_limits(&self, upload_rate: u64, download_rate: u64) {
        self.bandwidth
            .update_rates(upload_rate, download_rate)
            .await;
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
                Ok(transport) => match PeerLink::initiator(transport, &identity, None).await {
                    Ok(link) => {
                        let link = Arc::new(link);
                        let remote = link.remote_peer();
                        log::info!(
                            "Discovery connected to {:?} via {} (resolved from {})",
                            remote,
                            connect_addr,
                            addr
                        );
                        let _ = event_tx.send(NodeEvent::LinkUp(remote, link)).await;

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
                        log::debug!(
                            "Discovery handshake to {} (from {}) failed: {}",
                            connect_addr,
                            addr,
                            e
                        );
                    }
                },
                Err(e) => {
                    log::debug!(
                        "Discovery connect to {} (from {}) failed: {}",
                        connect_addr,
                        addr,
                        e
                    );
                }
            }
        }

        use rand::Rng;
        let jitter = backoff / 4;
        let jittered = backoff + rand::thread_rng().gen_range(Duration::ZERO..=jitter * 2) - jitter;
        tokio::time::sleep(jittered).await;
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
                            let _ = event_tx.send(NodeEvent::LinkUp(remote, link)).await;

                            backoff = INITIAL_BACKOFF;
                            first_attempt = true;

                            // Wait until this link drops, then retry
                            loop {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                if !links.lock().await.contains_key(&remote) {
                                    log::info!(
                                        "Bootstrap link to {:?} lost, reconnecting...",
                                        remote
                                    );
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
        use rand::Rng;
        let jitter = backoff / 4;
        let jittered = backoff + rand::thread_rng().gen_range(Duration::ZERO..=jitter * 2) - jitter;
        tokio::time::sleep(jittered).await;
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

    fn temp_db(name: &str) -> (Arc<crate::state::StateDb>, std::path::PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("tarnet-{}-{}.sqlite3", name, nanos));
        (Arc::new(crate::state::StateDb::open(&path).unwrap()), path)
    }

    fn signed(kp: &Keypair, key: DhtId, sequence: u64, value: Vec<u8>) -> crate::dht::VerifiedRecord {
        let expires = crate::dht::expires_in(Duration::from_secs(86_400));
        let signature = kp.sign(&crate::dht::record_signable(
            key.as_bytes(),
            RecordType::SignedContent,
            sequence,
            &value,
        ));
        crate::dht::VerifiedRecord::verify_incoming(DhtRecord {
            key,
            record_type: RecordType::SignedContent,
            sequence,
            signer: kp.peer_id(),
            signer_algo: kp.identity.signing.algo() as u8,
            signer_pubkey: kp.identity.signing.signing_pubkey_bytes(),
            value,
            expires,
            stored_at: Instant::now(),
            signature,
        })
        .unwrap()
    }

    /// A peer sending unique records can't grow the database past the
    /// store's limits: evicted records lose their rows, and a record evicted
    /// on arrival is never written.
    #[tokio::test]
    async fn persisted_records_stay_within_the_store_limits() {
        let (db, path) = temp_db("dht-bound");
        let limits = StorageLimits {
            max_records: 4,
            ..StorageLimits::default()
        };
        let node = Node::with_db(Keypair::generate(), db.clone(), limits);
        let attacker = Keypair::generate();
        let from = PeerId([7; 32]);
        for i in 0..50u8 {
            let rec = signed(&attacker, DhtId([i; 64]), 1, vec![i; 100]);
            node.dht_store.lock().await.put_record(rec, RecordSource::Peer(from));
        }
        let rows = db.load_dht_records().unwrap();
        assert_eq!(rows.len(), node.dht_store.lock().await.record_count());
        assert!(rows.len() <= 4, "{} rows persisted", rows.len());

        // A database already over the limits is trimmed on load.
        for i in 100..120u8 {
            let rec = signed(&attacker, DhtId([i; 64]), 1, vec![i; 100]);
            let pr = crate::state::PersistedRecord::from_stored(rec.record(), RecordSource::Peer(from)).unwrap();
            db.upsert_dht_record(&pr).unwrap();
        }
        let restored = Node::with_db(Keypair::generate(), db.clone(), limits);
        let rows = db.load_dht_records().unwrap();
        assert_eq!(rows.len(), restored.dht_store.lock().await.record_count());
        assert!(rows.len() <= 4, "{} rows after load", rows.len());
        let _ = std::fs::remove_file(&path);
    }

    /// A replayed tunnel key exchange can't swap a live tunnel's keys, even
    /// after the time-bounded nonce cache has forgotten it: the tunnel itself
    /// remembers the exchanges that made it.
    #[tokio::test]
    async fn replayed_key_exchange_cannot_replace_a_tunnel() {
        let responder = Node::new(Keypair::generate());
        let initiator = Keypair::generate();
        let offer = |nonce: [u8; 32]| {
            let kex = crate::key_exchange::KexOffer::new(initiator.identity.kem_algo());
            let mut ke = TunnelKeyExchangeMsg {
                kem_algo: kex.algo_byte(),
                ephemeral_pubkey: kex.pubkey_bytes(),
                initiator_peer_id: initiator.peer_id(),
                nonce,
                signer_algo: initiator.identity.signing_algo() as u8,
                signer_pubkey: initiator.identity.signing.signing_pubkey_bytes(),
                signature: Vec::new(),
            };
            ke.signature = initiator.sign(&ke.signed_bytes(&responder.peer_id()));
            ke.to_bytes()
        };
        let first = offer([1; 32]);
        let from = PeerId([7; 32]);
        // Sending the response fails (no route); the tunnel is made first.
        let _ = responder.handle_tunnel_key_exchange(from, &first).await;
        let _ = responder.handle_tunnel_key_exchange(from, &offer([2; 32])).await;
        let peer = initiator.peer_id();
        let nonces = || async {
            responder.tunnel_table.lock().await.get(&peer).unwrap().kex_nonces.clone()
        };
        assert_eq!(nonces().await, vec![[1; 32], [2; 32]]);

        // Long after: the nonce cache and cached responses are gone.
        responder.kex_seen.lock().await.clear();
        let _ = responder.handle_tunnel_key_exchange(from, &first).await;
        assert_eq!(nonces().await, vec![[1; 32], [2; 32]], "replay replaced the tunnel");
    }

    /// A relay verifies a PUT before telling watchers, so a forged record
    /// claiming a victim's signer and the highest sequence can't mark the
    /// victim's news as already told.
    #[tokio::test]
    async fn a_forged_put_does_not_suppress_watch_news() {
        let node = Node::new(Keypair::generate());
        let victim = Keypair::generate();
        let key = DhtId([0x31; 64]);
        node.dht_watches.lock().await.set_watch(*key.as_bytes(), [9; 32], PeerId([4; 32]), 60);
        let mut forged = signed(&victim, key, 1, b"real".to_vec()).record().to_put_msg();
        forged.sequence = u64::MAX;
        node.dht_put_seen(&forged, None, None).await;
        let news = node
            .dht_watches
            .lock()
            .await
            .watchers_needing_news(key.as_bytes(), victim.peer_id().as_bytes(), 2);
        assert_eq!(news.len(), 1, "forged PUT suppressed the victim's news");
    }

    /// A search yields the records held here first.
    #[tokio::test]
    async fn a_search_yields_what_is_held_here() {
        let node = Node::new(Keypair::generate());
        let key = DhtId([0x32; 64]);
        for _ in 0..10 {
            let rec = signed(&Keypair::generate(), key, 1, b"v".to_vec());
            node.dht_store.lock().await.put_record(rec, RecordSource::Peer(PeerId([7; 32])));
        }
        let mut search = node.dht_search(key, Instant::now()).await;
        let mut got = 0;
        while search.next().await.is_some() {
            got += 1;
        }
        assert_eq!(got, 10);
    }

    /// After a restart, a node republishes only the records it published
    /// itself; replicas peers handed it stay theirs.
    #[tokio::test]
    async fn a_restarted_node_republishes_only_its_own_records() {
        let (db, path) = temp_db("dht-origin");
        let identity = Keypair::generate();
        let node = Node::with_db(Keypair::from_full_bytes(&identity.to_full_bytes()).unwrap(), db.clone(), StorageLimits::default());
        node.dht_put_signed_content(b"mine", 600).await.unwrap();
        let replica = signed(&Keypair::generate(), DhtId([0x41; 64]), 1, b"theirs".to_vec());
        node.dht_store
            .lock()
            .await
            .put_record(replica, RecordSource::Peer(PeerId([7; 32])));
        assert_eq!(node.own_records_to_republish().await.len(), 1);

        let restarted = Node::with_db(identity, db.clone(), StorageLimits::default());
        assert_eq!(restarted.dht_store.lock().await.record_count(), 2);
        let own = restarted.own_records_to_republish().await;
        assert_eq!(own.len(), 1, "a peer's replica became ours on restart");
        assert_ne!(own[0].key, DhtId([0x41; 64]));
        let _ = std::fs::remove_file(&path);
    }

    /// Every DHT message type pays the DHT budget, WATCH included: a peer
    /// churning watch/cancel pairs runs out like one flooding GETs.
    #[tokio::test]
    async fn watch_churn_is_charged_to_the_dht_budget() {
        let node = Node::new(Keypair::generate());
        let from = PeerId([7; 32]);
        node.governor.lock().await.peer_connected(from);
        let watch = |token: u8, secs: u32| {
            crate::wire::DhtWatchMsg {
                walk: crate::wire::WalkHeader::origin(),
                key: [0x51; 64],
                query_token: [token; 32],
                expiration_secs: secs,
            }
            .to_wire()
        };
        let deliver = |msg: WireMessage| {
            let node = &node;
            async move {
                if node.admit_message(&from, 0, &msg).await == Verdict::Allow {
                    node.handle_message(from, 0, msg).await.unwrap();
                }
            }
        };
        for i in 0..200u8 {
            deliver(watch(i, 60)).await;
            deliver(watch(i, 0)).await;
        }
        deliver(watch(250, 60)).await;
        assert!(
            !node.dht_watches.lock().await.is_watched(&[0x51; 64]),
            "watch admitted past the budget"
        );
    }

    /// The reverse-path cap holds for GETs this node launches as well as
    /// GETs it relays: with the table full, a lookup launches no walks.
    #[tokio::test]
    async fn local_lookups_respect_the_reverse_path_cap() {
        let node = Node::new(Keypair::generate());
        {
            let mut qt = node.query_tokens.lock().unwrap();
            let mut i = 0u64;
            let entry = || dht::QueryToken {
                prev: PeerId([1; 32]),
                key: [0; 64],
                next: Vec::new(),
            };
            while qt.try_insert(blake3::hash(&i.to_be_bytes()).into(), entry()).is_ok() {
                i += 1;
            }
            assert_eq!(qt.len(), 65_536);
        }
        let (tx, _rx) = mpsc::channel(1);
        let launched = node
            .dht_walker
            .launch_get(&[0x71; 64], (&node.dht_searches, &tx), Instant::now() + Duration::from_secs(1))
            .await;
        assert!(launched.is_empty());
        assert_eq!(node.query_tokens.lock().unwrap().len(), 65_536);
        // A relayed GET is refused the same way.
        let from = PeerId([7; 32]);
        node.governor.lock().await.peer_connected(from);
        let get = DhtGetMsg {
            walk: crate::wire::WalkHeader::origin(),
            key: [0x72; 64],
            query_token: [0x73; 32],
        };
        node.handle_message(from, 0, get.to_wire()).await.unwrap();
        assert!(node.query_tokens.lock().unwrap().get(&[0x73; 32]).is_none());
    }

    /// A GET response is accepted only for the key its token asked for.
    #[tokio::test]
    async fn get_response_for_another_key_is_dropped() {
        let node = Node::new(Keypair::generate());
        let from = PeerId([7; 32]);
        node.governor.lock().await.peer_connected(from);
        let asked = DhtId([0x10; 64]);
        let other = DhtId([0x20; 64]);
        let token = [0x55; 32];
        node.query_tokens
            .lock().unwrap()
            .try_insert(
                token,
                dht::QueryToken {
                    prev: node.peer_id(),
                    key: *asked.as_bytes(),
                    next: vec![from],
                },
            )
            .unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        node.dht_searches.lock().unwrap().insert(token, tx);
        let signer = Keypair::generate();
        let respond = |key: DhtId| {
            let rec = signed(&signer, key, 1, b"value".to_vec());
            DhtGetResponseMsg {
                query_token: token,
                key: *key.as_bytes(),
                records: vec![rec.record().to_response_record()],
            }
            .to_wire()
        };

        node.handle_message(from, 0, respond(other)).await.unwrap();
        assert!(rx.try_recv().is_err());
        // The right key, but not from where the walk went.
        let stranger = PeerId([8; 32]);
        node.governor.lock().await.peer_connected(stranger);
        node.handle_message(stranger, 0, respond(asked)).await.unwrap();
        assert!(rx.try_recv().is_err());

        node.handle_message(from, 0, respond(asked)).await.unwrap();
        assert_eq!(rx.try_recv().unwrap().record().key, asked);
        // Delivered to the search, not stored.
        assert!(node.dht_store.lock().await.get(&asked).is_empty());
    }

    #[tokio::test]
    async fn db_restores_pq_default_identity() {
        use crate::state::StateDb;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("tarnet-node-pq-{}.sqlite3", nanos));

        let original_identity = Keypair::generate();
        assert_eq!(
            original_identity.identity.signing_algo(),
            SigningAlgo::FalconEd25519
        );
        assert_eq!(original_identity.identity.kem_algo(), KemAlgo::MlkemX25519);

        let db = Arc::new(StateDb::open(&path).unwrap());
        let _original = Node::with_db(
            Keypair::from_full_bytes(&original_identity.to_full_bytes()).unwrap(),
            db.clone(),
            StorageLimits::default(),
        );

        // Re-open from the same DB with a different node identity
        let restored = Node::with_db(Keypair::generate(), db, StorageLimits::default());

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
