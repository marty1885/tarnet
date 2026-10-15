//! LocalServiceApi: implements ServiceApi by wrapping Node directly.
//! Used by the daemon's IPC server and by in-process services.
//! Zero-copy, no serialization — just method calls.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;

use tarnet::node::Node;
use tarnet::state::StateDb;
use tarnet::tns;
use tarnet_api::error::{ApiError, ApiResult};
use tarnet_api::service::{
    Connection, DhtEntry, HelloInfo, Listener, ListenerOptions, NodeEvent, PoolClaim, PoolEndpoint,
    PoolKind, PoolRegisterOptions, PortMode, ServiceApi, TnsRecord, TnsResolution, WatchEvent,
};
use tarnet_api::types::{ContentHandle, DhtId, PeerId, ServiceId};


pub struct LocalServiceApi {
    node: Arc<Node>,
    /// Unified broadcast channel for all node events.
    event_tx: tokio::sync::broadcast::Sender<NodeEvent>,
    /// Shared persistent database for petnames (and all other state).
    db: Arc<StateDb>,
    /// SOCKS proxy bind addresses (empty if disabled).
    socks_addrs: Vec<std::net::SocketAddr>,
}

impl LocalServiceApi {
    /// Create a new LocalServiceApi wrapping the given Node.
    /// Must be called before `Node::run()` so we can take the receivers.
    pub async fn with_db(
        node: Arc<Node>,
        db: Arc<StateDb>,
        socks_addrs: Vec<std::net::SocketAddr>,
    ) -> Self {
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
                        signer: record.signer,
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
        }
    }
}

impl LocalServiceApi {
    /// Local labels changed: drop cached resolutions (the node's cache is
    /// the only one).
    async fn tns_cache_clear(&self) {
        self.node.tns_cache().lock().await.clear();
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
    async fn keypair_for_identity(
        &self,
        identity: Option<&str>,
    ) -> ApiResult<tarnet::identity::Keypair> {
        let sid = self.resolve_identity(identity.unwrap_or("")).await?;
        self.node.keypair_for_service(&sid).await.ok_or_else(|| {
            ApiError::Service(format!(
                "no keypair found for identity '{}'",
                identity.unwrap_or("default")
            ))
        })
    }

    /// Uncached TNS name resolution (called by the cached wrapper).
    fn tns_resolve_name_inner<'a>(
        &'a self,
        name: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ApiResult<TnsResolution>> + Send + 'a>>
    {
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
                        // A terminal VHost in our own zone: surface the serving
                        // SID + canonical label (the label itself) so connect_to
                        // can derive the wire port.
                        if let Some(serving) = records.iter().find_map(|r| match r {
                            TnsRecord::VHost(sid) => Some(*sid),
                            _ => None,
                        }) {
                            return Ok(TnsResolution::VHost {
                                serving,
                                canonical_label: root_label.to_string(),
                            });
                        }
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

    async fn connect(
        &self,
        service_id: ServiceId,
        mode: PortMode,
        port: &str,
    ) -> ApiResult<Connection> {
        self.node
            .circuit_connect(service_id, mode, port, None, None)
            .await
            .map_err(map_err)
    }

    async fn connect_as(
        &self,
        service_id: ServiceId,
        mode: PortMode,
        port: &str,
        source_identity: Option<ServiceId>,
    ) -> ApiResult<Connection> {
        self.node
            .circuit_connect(service_id, mode, port, None, source_identity)
            .await
            .map_err(map_err)
    }

    async fn connect_via(
        &self,
        service_id: ServiceId,
        mode: PortMode,
        port: &str,
        peer_hint: Option<PeerId>,
    ) -> ApiResult<Connection> {
        self.node
            .circuit_connect(service_id, mode, port, peer_hint, None)
            .await
            .map_err(map_err)
    }

    async fn listen(
        &self,
        service_id: ServiceId,
        mode: PortMode,
        port: &str,
        options: ListenerOptions,
    ) -> ApiResult<Listener> {
        self.node
            .circuit_listen(service_id, mode, port, options)
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
        mode: PortMode,
        port: &str,
        num_intro_points: usize,
        options: ListenerOptions,
    ) -> ApiResult<Listener> {
        let listener = self
            .node
            .circuit_listen(service_id, mode, port, options)
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

    async fn dht_put(&self, value: &[u8]) -> ApiResult<ContentHandle> {
        self.node
            .dht_put_content(value)
            .await
            .map_err(|e| ApiError::Service(e.to_string()))
    }

    async fn dht_get(&self, inner_hash: &ContentHandle, timeout_secs: u32) -> Option<Vec<u8>> {

        // Check local store first.
        if let Some(data) = self.node.dht_get_content(inner_hash).await {
            return Some(data);
        }

        if timeout_secs == 0 {
            return None;
        }

        // Search the network, re-reading the store as records stream back.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs as u64);
        let mut search = self.node.dht_search_content(inner_hash, deadline).await;
        loop {
            if let Some(data) = self.node.dht_get_content(inner_hash).await {
                return Some(data);
            }
            if search.next().await.is_none() {
                return None;
            }
        }
    }

    async fn dht_put_signed(&self, value: &[u8], ttl_secs: u32) -> ApiResult<ContentHandle> {
        self.node
            .dht_put_signed_content(value, ttl_secs)
            .await
            .map_err(|e| ApiError::Service(e.to_string()))
    }

    async fn dht_get_signed(&self, inner_hash: &ContentHandle, timeout_secs: u32) -> Vec<DhtEntry> {

        // Check local store first.
        let results = self.node.dht_get_signed_content(inner_hash).await;
        if !results.is_empty() {
            return results
                .into_iter()
                .map(|(signer, data)| DhtEntry { signer, data })
                .collect();
        }

        if timeout_secs == 0 {
            return Vec::new();
        }

        // Search the network, re-reading the store as records stream back.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs as u64);
        let mut search = self.node.dht_search_content(inner_hash, deadline).await;
        loop {
            let results = self.node.dht_get_signed_content(inner_hash).await;
            if !results.is_empty() {
                return results
                    .into_iter()
                    .map(|(signer, data)| DhtEntry { signer, data })
                    .collect();
            }
            if search.next().await.is_none() {
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

        // Search the network, re-reading the store as records stream back.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs as u64);
        let mut search = self.node.dht_search_hello(peer_id, deadline).await;
        loop {
            if let Some(hello) = self.node.lookup_hello(peer_id).await {
                return Some(to_hello_info(hello));
            }
            if search.next().await.is_none() {
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
    ) -> ApiResult<()> {
        let id_key = self.identity_db_key(identity).await?;
        tns::validate_records(&records).map_err(map_err)?;
        tns::validate_published_aliases(&records, &self.db, &id_key).map_err(map_err)?;

        let zone_keypair = self.keypair_for_identity(identity).await?;
        tns::publish(&self.node, &zone_keypair, label, &records)
            .await
            .map_err(map_err)?;
        self.tns_cache_clear().await;
        Ok(())
    }

    async fn tns_resolve(&self, zone: ServiceId, name: &str) -> ApiResult<TnsResolution> {
        // Each step is cached by the node's TNS cache, with its record's TTL.
        Ok(tns::resolve(&self.node, zone, name).await)
    }

    async fn tns_resolve_name(&self, name: &str) -> ApiResult<TnsResolution> {
        self.tns_resolve_name_inner(name).await
    }

    async fn tns_set_label(
        &self,
        identity: Option<&str>,
        label: &str,
        records: Vec<TnsRecord>,
        publish: bool,
    ) -> ApiResult<()> {
        let id_key = self.identity_db_key(identity).await?;
        tns::validate_records(&records).map_err(map_err)?;
        if publish {
            tns::validate_published_aliases(&records, &self.db, &id_key).map_err(map_err)?;
        }
        let record_blobs: Vec<Vec<u8>> = records
            .iter()
            .map(|r| tns::tns_record_to_bytes(r))
            .collect();
        self.db
            .label_set(&id_key, label, &record_blobs, publish)
            .map_err(map_err)?;

        // Auto-publish to DHT when marked public.
        if publish {
            let zone_keypair = self.keypair_for_identity(identity).await?;
            tns::publish(&self.node, &zone_keypair, label, &records)
                .await
                .map_err(map_err)?;
        }

        self.tns_cache_clear().await;
        Ok(())
    }

    async fn tns_get_label(
        &self,
        identity: Option<&str>,
        label: &str,
    ) -> ApiResult<Option<(Vec<TnsRecord>, bool)>> {
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
        // Drop the label from the zone root and republish it, so a removed name
        // actually stops resolving (the root holds the zone's whole label set;
        // it would otherwise persist until the root's TTL lapses).
        let zone_keypair = self.keypair_for_identity(identity).await?;
        tns::unpublish(&self.node, &zone_keypair, label)
            .await
            .map_err(map_err)?;
        self.tns_cache_clear().await;
        Ok(())
    }

    async fn tns_list_labels(
        &self,
        identity: Option<&str>,
    ) -> ApiResult<Vec<(String, Vec<TnsRecord>, bool)>> {
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
    ) -> ApiResult<
        Vec<(
            String,
            ServiceId,
            tarnet_api::types::PrivacyLevel,
            u8,
            tarnet_api::types::IdentityScheme,
            tarnet_api::types::SigningAlgo,
            tarnet_api::types::KemAlgo,
        )>,
    > {
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

    async fn connect_to(&self, target: &str, mode: PortMode, port: &str) -> ApiResult<Connection> {
        // The single connect chokepoint. The wire port is always *derived* from a
        // canonical label + the supplied port — there is no verbatim-port path.
        // `port` is the connector's supplied port (a URL u16 stringified, or a
        // native string); it is never fed to the circuit layer directly.

        // 1. Bare ServiceId: the un-petnamed apex form. Canonical label is "@".
        if let Ok(sid) = ServiceId::parse(target) {
            let wire = tns::vhost_wire_port("@", port);
            return self.connect(sid, mode, &wire).await;
        }

        // 2. Resolve via TNS (local labels, dotted names, raw-SID suffixes).
        match self.tns_resolve_name(target).await? {
            // 2a. VHost endpoint: derive from the canonical label surfaced by the
            //     resolver, connect to the serving identity.
            TnsResolution::VHost {
                serving,
                canonical_label,
            } => {
                let wire = tns::vhost_wire_port(&canonical_label, port);
                self.connect(serving, mode, &wire).await
            }
            // 2b. Plain Identity (apex / petname → @): canonical label is "@".
            TnsResolution::Records(records) => {
                for rec in &records {
                    if let TnsRecord::Identity(sid) = rec {
                        let wire = tns::vhost_wire_port("@", port);
                        return self.connect(*sid, mode, &wire).await;
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

    // ── Resource pools ──

    async fn pool_join(&self, name: &str, kind: PoolKind) -> ApiResult<ServiceId> {
        Ok(self.node.pool_join(name, kind).await)
    }

    async fn pool_leave(&self, name: &str) -> ApiResult<()> {
        if self.node.pool_leave(name).await {
            Ok(())
        } else {
            Err(ApiError::NotFound)
        }
    }

    async fn pool_list(&self) -> ApiResult<Vec<(String, ServiceId)>> {
        Ok(self.node.pool_list().await)
    }

    async fn pool_register(
        &self,
        pool: &str,
        service: &str,
        identity: Option<&str>,
        port: &str,
        opts: PoolRegisterOptions,
    ) -> ApiResult<PoolClaim> {
        self.node
            .pool_register(pool, service, identity, port, opts)
            .await
            .map_err(map_err)
    }

    async fn pool_withdraw(&self, claim: PoolClaim) -> ApiResult<()> {
        self.node.pool_withdraw(&claim).await.map_err(map_err)
    }

    async fn pool_resolve(
        &self,
        pool: &str,
        service: &str,
        timeout_secs: u32,
    ) -> ApiResult<Vec<PoolEndpoint>> {
        self.node
            .pool_resolve(pool, service, timeout_secs)
            .await
            .map_err(map_err)
    }

    async fn pool_catalog(&self, pool: &str, timeout_secs: u32) -> ApiResult<Vec<String>> {
        self.node
            .pool_catalog(pool, timeout_secs)
            .await
            .map_err(map_err)
    }
}
