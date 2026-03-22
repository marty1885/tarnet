//! LocalServiceApi: implements ServiceApi by wrapping Node directly.
//! Used by the daemon's IPC server and by in-process services.
//! Zero-copy, no serialization — just method calls.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};

use tarnet::node::Node;
use tarnet::state::StateDb;
use tarnet::tns;
use tarnet_api::error::{ApiError, ApiResult};
use tarnet_api::service::{
    Connection, DhtEntry, HelloInfo, Listener, ListenerOptions, NodeEvent, ServiceApi, TnsRecord,
    TnsResolution, WatchEvent,
};
use tarnet_api::types::{DhtId, PeerId, ServiceId};

/// How long successful TNS resolutions are cached.
const TNS_CACHE_TTL_SUCCESS: std::time::Duration = std::time::Duration::from_secs(300);
/// How long NotFound results are cached (negative caching).
const TNS_CACHE_TTL_NOT_FOUND: std::time::Duration = std::time::Duration::from_secs(60);
/// Maximum number of entries before we evict expired ones.
const TNS_CACHE_MAX_ENTRIES: usize = 1024;

struct TnsCacheEntry {
    resolution: TnsResolution,
    expires_at: Instant,
}

pub struct LocalServiceApi {
    node: Arc<Node>,
    /// Unified broadcast channel for all node events.
    event_tx: tokio::sync::broadcast::Sender<NodeEvent>,
    /// Shared persistent database for petnames (and all other state).
    db: Arc<StateDb>,
    /// SOCKS proxy bind addresses (empty if disabled).
    socks_addrs: Vec<std::net::SocketAddr>,
    /// Cache for TNS resolution results. Key is (zone_hex, name).
    tns_cache: Mutex<HashMap<String, TnsCacheEntry>>,
}

impl LocalServiceApi {
    /// Create a new LocalServiceApi wrapping the given Node.
    /// Must be called before `Node::run()` so we can take the receivers.
    pub async fn with_db(node: Arc<Node>, db: Arc<StateDb>, socks_addrs: Vec<std::net::SocketAddr>) -> Self {
        let (event_tx, _) = tokio::sync::broadcast::channel(512);

        // Take the node's receivers and merge into unified event broadcast.
        let tx = event_tx.clone();
        if let Some(mut app_rx) = node.take_app_receiver().await {
            tokio::spawn(async move {
                while let Some((peer, data)) = app_rx.recv().await {
                    let _ = tx.send(NodeEvent::Data {
                        peer,
                        payload: data,
                    });
                }
            });
        }

        let tx = event_tx.clone();
        if let Some(mut tun_rx) = node.take_tunnel_receiver().await {
            tokio::spawn(async move {
                while let Some(peer) = tun_rx.recv().await {
                    let _ = tx.send(NodeEvent::Tunnel { peer });
                }
            });
        }

        let tx = event_tx.clone();
        if let Some(mut watch_rx) = node.take_dht_watch_receiver().await {
            tokio::spawn(async move {
                while let Some((key, record)) = watch_rx.recv().await {
                    let _ = tx.send(NodeEvent::Watch(WatchEvent {
                        key,
                        signer: PeerId(record.signer),
                        value: record.value,
                    }));
                }
            });
        }

        let tx = event_tx.clone();
        if let Some(mut event_rx) = node.take_channel_event_receiver().await {
            tokio::spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    match event {
                        tarnet::node::ChannelEvent::PeerDisconnected { peer_id } => {
                            let _ = tx.send(NodeEvent::PeerDisconnected(peer_id));
                        }
                        _ => {}
                    }
                }
            });
        }

        Self {
            node,
            event_tx,
            db,
            socks_addrs,
            tns_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl LocalServiceApi {
    /// Look up a cached TNS resolution result.
    async fn tns_cache_get(&self, key: &str) -> Option<TnsResolution> {
        let cache = self.tns_cache.lock().await;
        if let Some(entry) = cache.get(key) {
            if Instant::now() < entry.expires_at {
                return Some(entry.resolution.clone());
            }
        }
        None
    }

    /// Insert a TNS resolution result into the cache.
    async fn tns_cache_put(&self, key: String, resolution: TnsResolution) {
        let ttl = match &resolution {
            TnsResolution::Records(_) => TNS_CACHE_TTL_SUCCESS,
            TnsResolution::NotFound => TNS_CACHE_TTL_NOT_FOUND,
            TnsResolution::Error(_) => return, // don't cache errors
        };
        let mut cache = self.tns_cache.lock().await;
        // Evict expired entries if we're at capacity.
        if cache.len() >= TNS_CACHE_MAX_ENTRIES {
            let now = Instant::now();
            cache.retain(|_, v| v.expires_at > now);
        }
        cache.insert(key, TnsCacheEntry {
            resolution,
            expires_at: Instant::now() + ttl,
        });
    }

    /// Invalidate all cache entries (used when local labels change).
    async fn tns_cache_clear(&self) {
        self.tns_cache.lock().await.clear();
    }

    /// Resolve an identity option to a DB key string.
    /// None or "default" → the default identity's label (or "" if unnamed).
    async fn identity_db_key(&self, identity: Option<&str>) -> ApiResult<String> {
        match identity {
            Some(id_str) if !id_str.is_empty() && id_str != "default" => Ok(id_str.to_string()),
            _ => {
                // Find the default identity's label.
                let sid = self.node.default_service_id().await;
                let identities = self.node.list_identities().await;
                for (label, s, _, _, _, _, _) in &identities {
                    if *s == sid {
                        return Ok(label.clone());
                    }
                }
                Ok(String::new())
            }
        }
    }

    /// Get the keypair for the given identity (or the default).
    async fn keypair_for_identity(&self, identity: Option<&str>) -> ApiResult<tarnet::identity::Keypair> {
        let sid = self.resolve_identity(identity.unwrap_or("")).await?;
        self.node.keypair_for_service(&sid).await.ok_or_else(|| {
            ApiError::Service(format!("no keypair found for identity '{}'", identity.unwrap_or("default")))
        })
    }

    /// Uncached TNS name resolution (called by the cached wrapper).
    fn tns_resolve_name_inner<'a>(&'a self, name: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = ApiResult<TnsResolution>> + Send + 'a>> {
        Box::pin(async move {
        // Check if the rightmost label (root of the name) is a local label.
        // Search the default identity's zone.
        let id_key = self.identity_db_key(None).await?;
        let labels: Vec<&str> = name.split('.').collect();
        if let Some(root_label) = labels.last() {
            if let Ok(Some((record_blobs, _publish))) = self.db.label_get(&id_key, root_label) {
                let records: Vec<TnsRecord> = record_blobs
                    .iter()
                    .filter_map(|b| tns::tns_record_from_bytes(b).ok().map(|(r, _)| r))
                    .collect();

                if labels.len() == 1 {
                    return Ok(TnsResolution::Records(records));
                }

                let remaining = labels[..labels.len() - 1].join(".");

                if let Some(alias_target) = records.iter().find_map(|r| match r {
                    TnsRecord::Alias(s) => Some(s.clone()),
                    _ => None,
                }) {
                    let new_name = format!("{}.{}", remaining, alias_target);
                    return self.tns_resolve_name_inner(&new_name).await;
                }

                if let Some(zone) = records.iter().find_map(|r| match r {
                    TnsRecord::Zone(sid) => Some(*sid),
                    _ => None,
                }) {
                    return Ok(tns::resolve(&self.node, zone, &remaining).await);
                }

                return Ok(TnsResolution::Records(records));
            }
        }

        Ok(tns::resolve_name(&self.node, name).await)
        })
    }
}

fn map_err(e: tarnet::types::Error) -> ApiError {
    match e {
        tarnet::types::Error::Io(e) => ApiError::Io(e),
        tarnet::types::Error::NotFound => ApiError::NotFound,
        other => ApiError::Service(other.to_string()),
    }
}

#[async_trait]
impl ServiceApi for LocalServiceApi {
    fn peer_id(&self) -> PeerId {
        self.node.peer_id()
    }

    async fn default_service_id(&self) -> ServiceId {
        self.node.default_service_id().await
    }

    async fn resolve_identity(&self, label_or_sid: &str) -> ApiResult<ServiceId> {
        if label_or_sid.is_empty() || label_or_sid == "default" {
            return Ok(self.node.default_service_id().await);
        }

        // Try matching by identity label.
        let identities = self.node.list_identities().await;
        for (label, sid, _, _, _, _, _) in &identities {
            if label == label_or_sid {
                return Ok(*sid);
            }
        }

        // Try parsing as ServiceId (base32, hex, pubkey hex).
        match ServiceId::parse(label_or_sid) {
            Ok(sid) => Ok(sid),
            Err(_) => Err(ApiError::NotFound),
        }
    }

    async fn connect(&self, service_id: ServiceId, port: u16) -> ApiResult<Connection> {
        self.node
            .circuit_connect(service_id, port, None, None)
            .await
            .map_err(map_err)
    }

    async fn connect_as(
        &self,
        service_id: ServiceId,
        port: u16,
        source_identity: Option<ServiceId>,
    ) -> ApiResult<Connection> {
        self.node
            .circuit_connect(service_id, port, None, source_identity)
            .await
            .map_err(map_err)
    }

    async fn listen(
        &self,
        service_id: ServiceId,
        port: u16,
        options: ListenerOptions,
    ) -> ApiResult<Listener> {
        self.node
            .circuit_listen(service_id, port, options)
            .await
            .map_err(map_err)
    }

    async fn accept(&self, listener: &Listener) -> ApiResult<Connection> {
        self.node.circuit_accept(listener.id).await.map_err(map_err)
    }

    async fn close_listener(&self, listener: &Listener) -> ApiResult<()> {
        self.node
            .circuit_close_listener(listener.id)
            .await
            .map_err(map_err)
    }

    async fn listen_hidden(
        &self,
        service_id: ServiceId,
        port: u16,
        num_intro_points: usize,
        options: ListenerOptions,
    ) -> ApiResult<Listener> {
        let listener = self
            .node
            .circuit_listen(service_id, port, options)
            .await
            .map_err(map_err)?;
        if let Err(e) = self
            .node
            .publish_hidden_service(service_id, num_intro_points)
            .await
        {
            let _ = self.node.circuit_close_listener(listener.id).await;
            return Err(map_err(e));
        }
        Ok(listener)
    }

    async fn send_data(&self, dest: &PeerId, payload: &[u8]) -> ApiResult<()> {
        self.node.send_data(dest, payload).await.map_err(map_err)
    }

    async fn create_tunnel(&self, dest: PeerId) -> ApiResult<PeerId> {
        let rx = self.node.create_tunnel(dest).await.map_err(map_err)?;
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(peer)) => Ok(peer),
            Ok(Err(_)) => Err(ApiError::Service("tunnel creation cancelled".into())),
            Err(_) => Err(ApiError::Timeout),
        }
    }

    async fn send_tunnel_data(&self, dest: &PeerId, data: &[u8]) -> ApiResult<()> {
        self.node
            .send_tunnel_data(dest, data)
            .await
            .map_err(map_err)
    }

    async fn dht_put(&self, value: &[u8]) -> DhtId {
        DhtId(self.node.dht_put_content(value).await)
    }

    async fn dht_get(&self, key: &DhtId, timeout_secs: u32) -> Option<Vec<u8>> {
        let inner_hash = key.as_bytes();

        // Check local store first.
        if let Some(data) = self.node.dht_get_content(inner_hash).await {
            return Some(data);
        }

        if timeout_secs == 0 {
            return None;
        }

        // Issue a network request and poll until found or timeout.
        if self.node.request_content(inner_hash).await.is_err() {
            return None;
        }

        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(timeout_secs as u64);
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if let Some(data) = self.node.dht_get_content(inner_hash).await {
                return Some(data);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
        }
    }

    async fn dht_put_signed(&self, value: &[u8], ttl_secs: u32) -> DhtId {
        DhtId(self.node.dht_put_signed_content(value, ttl_secs).await)
    }

    async fn dht_get_signed(
        &self,
        key: &DhtId,
        timeout_secs: u32,
    ) -> Vec<DhtEntry> {
        let inner_hash = key.as_bytes();

        // Check local store first.
        let results = self.node.dht_get_signed_content(inner_hash).await;
        if !results.is_empty() {
            return results.into_iter().map(|(signer, data)| DhtEntry { signer, data }).collect();
        }

        if timeout_secs == 0 {
            return Vec::new();
        }

        // Issue a network request and poll until found or timeout.
        if self.node.request_signed_content(inner_hash).await.is_err() {
            return Vec::new();
        }

        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(timeout_secs as u64);
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let results = self.node.dht_get_signed_content(inner_hash).await;
            if !results.is_empty() {
                return results.into_iter().map(|(signer, data)| DhtEntry { signer, data }).collect();
            }
            if tokio::time::Instant::now() >= deadline {
                return Vec::new();
            }
        }
    }

    async fn lookup_hello(&self, peer_id: &PeerId, timeout_secs: u32) -> Option<HelloInfo> {
        let to_hello_info = |hello: tarnet::wire::HelloRecord| HelloInfo {
            peer_id: hello.peer_id,
            capabilities: tarnet::wire::capabilities::format(hello.capabilities),
            transports: hello.transports.iter().map(|t| t.to_string()).collect(),
            introducers: hello.introducers,
            global_addresses: hello
                .global_addresses
                .iter()
                .filter_map(|a| a.to_connect_string())
                .collect(),
        };

        // Check local store first.
        if let Some(hello) = self.node.lookup_hello(peer_id).await {
            return Some(to_hello_info(hello));
        }

        if timeout_secs == 0 {
            return None;
        }

        // Issue a network request and poll until found or timeout.
        if self.node.request_hello(peer_id).await.is_err() {
            return None;
        }

        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(timeout_secs as u64);
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if let Some(hello) = self.node.lookup_hello(peer_id).await {
                return Some(to_hello_info(hello));
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
        }
    }

    async fn dht_watch(&self, key: &DhtId, expiration_secs: u32) {
        self.node.dht_watch(key, expiration_secs).await
    }

    async fn dht_unwatch(&self, key: &DhtId) {
        self.node.dht_unwatch(key).await
    }

    async fn connected_peers(&self) -> Vec<PeerId> {
        self.node.connected_peers().await
    }

    async fn routing_entries(&self) -> Vec<(PeerId, PeerId, u32)> {
        self.node.routing_entries().await
    }

    async fn node_status(&self) -> tarnet_api::types::NodeStatus {
        self.node.node_status().await
    }

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
        let id_key = self.identity_db_key(identity).await?;
        tns::validate_records(&records).map_err(map_err)?;
        tns::validate_published_aliases(&records, &self.db, &id_key).map_err(map_err)?;

        let zone_keypair = self.keypair_for_identity(identity).await?;
        tns::publish(&self.node, &zone_keypair, label, &records, ttl_secs)
            .await
            .map_err(map_err)?;
        self.tns_cache_clear().await;
        Ok(())
    }

    async fn tns_resolve(
        &self,
        zone: ServiceId,
        name: &str,
    ) -> ApiResult<TnsResolution> {
        let cache_key = format!("z:{}:{}", tarnet_api::types::encode_base32(zone.as_bytes()), name);
        if let Some(cached) = self.tns_cache_get(&cache_key).await {
            return Ok(cached);
        }
        let result = tns::resolve(&self.node, zone, name).await;
        self.tns_cache_put(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn tns_resolve_name(&self, name: &str) -> ApiResult<TnsResolution> {
        let cache_key = format!("n:{}", name);
        if let Some(cached) = self.tns_cache_get(&cache_key).await {
            return Ok(cached);
        }

        let result = self.tns_resolve_name_inner(name).await?;
        self.tns_cache_put(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn tns_set_label(&self, identity: Option<&str>, label: &str, records: Vec<TnsRecord>, publish: bool) -> ApiResult<()> {
        let id_key = self.identity_db_key(identity).await?;
        tns::validate_records(&records).map_err(map_err)?;
        if publish {
            tns::validate_published_aliases(&records, &self.db, &id_key).map_err(map_err)?;
        }
        let record_blobs: Vec<Vec<u8>> = records.iter().map(|r| tns::tns_record_to_bytes(r)).collect();
        self.db.label_set(&id_key, label, &record_blobs, publish).map_err(map_err)?;

        // Auto-publish to DHT when marked public.
        if publish {
            let zone_keypair = self.keypair_for_identity(identity).await?;
            tns::publish(&self.node, &zone_keypair, label, &records, 3600)
                .await
                .map_err(map_err)?;
        }

        self.tns_cache_clear().await;
        Ok(())
    }

    async fn tns_get_label(&self, identity: Option<&str>, label: &str) -> ApiResult<Option<(Vec<TnsRecord>, bool)>> {
        let id_key = self.identity_db_key(identity).await?;
        match self.db.label_get(&id_key, label).map_err(map_err)? {
            Some((blobs, publish)) => {
                let records = blobs
                    .iter()
                    .filter_map(|b| tns::tns_record_from_bytes(b).ok().map(|(r, _)| r))
                    .collect();
                Ok(Some((records, publish)))
            }
            None => Ok(None),
        }
    }

    async fn tns_remove_label(&self, identity: Option<&str>, label: &str) -> ApiResult<()> {
        let id_key = self.identity_db_key(identity).await?;
        self.db.label_remove(&id_key, label).map_err(map_err)?;
        self.tns_cache_clear().await;
        Ok(())
    }

    async fn tns_list_labels(&self, identity: Option<&str>) -> ApiResult<Vec<(String, Vec<TnsRecord>, bool)>> {
        let id_key = self.identity_db_key(identity).await?;
        let raw = self.db.label_list(&id_key).map_err(map_err)?;
        Ok(raw
            .into_iter()
            .map(|(label, blobs, publish)| {
                let records = blobs
                    .iter()
                    .filter_map(|b| tns::tns_record_from_bytes(b).ok().map(|(r, _)| r))
                    .collect();
                (label, records, publish)
            })
            .collect())
    }

    async fn create_identity(
        &self,
        label: &str,
        privacy: tarnet_api::types::PrivacyLevel,
        outbound_hops: u8,
        scheme: tarnet_api::types::IdentityScheme,
    ) -> ApiResult<ServiceId> {
        self.node
            .create_identity(label, privacy, outbound_hops, scheme)
            .await
            .map_err(map_err)
    }

    async fn list_identities(
        &self,
    ) -> ApiResult<Vec<(String, ServiceId, tarnet_api::types::PrivacyLevel, u8, tarnet_api::types::IdentityScheme, tarnet_api::types::SigningAlgo, tarnet_api::types::KemAlgo)>> {
        Ok(self.node.list_identities().await)
    }

    async fn delete_identity(&self, label: &str) -> ApiResult<()> {
        self.node.delete_identity(label).await.map_err(map_err)
    }

    async fn update_identity(
        &self,
        label: &str,
        privacy: tarnet_api::types::PrivacyLevel,
        outbound_hops: u8,
    ) -> ApiResult<(tarnet_api::types::PrivacyLevel, u8)> {
        self.node
            .update_identity(label, privacy, outbound_hops)
            .await
            .map_err(map_err)
    }

    async fn socks_addr(&self) -> ApiResult<Vec<std::net::SocketAddr>> {
        Ok(self.socks_addrs.clone())
    }

    async fn connect_to(&self, target: &str, port: u16) -> ApiResult<Connection> {
        // 1. Try parsing target directly as a ServiceId.
        if let Ok(sid) = ServiceId::parse(target) {
            return self.connect(sid, port).await;
        }

        // 2. Try resolving via TNS (local labels, dotted names).
        match self.tns_resolve_name(target).await? {
            TnsResolution::Records(records) => {
                // Find a connectable record (Identity).
                for rec in &records {
                    if let TnsRecord::Identity(sid) = rec {
                        return self.connect(*sid, port).await;
                    }
                }
                Err(ApiError::Service(format!(
                    "no connectable record found for '{}'",
                    target
                )))
            }
            TnsResolution::NotFound => Err(ApiError::NotFound),
            TnsResolution::Error(e) => Err(ApiError::Service(e)),
        }
    }
}
