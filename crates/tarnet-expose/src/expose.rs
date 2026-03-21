use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use log::{debug, error, info, warn};
use serde::Deserialize;
use tarnet_api::service::{ServiceApi, TnsRecord};
use tarnet_api::types::{PrivacyLevel, ServiceId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify};

/// Service config from a TOML file.
#[derive(Debug, Deserialize, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub local: String,
    /// Tarnet-facing port to listen on. If omitted, uses the port from `local`.
    pub port: Option<u16>,
    /// Protocol: "tcp" (default) or "udp".
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub publish: bool,
    /// Identity label to publish under. If omitted, uses the default identity.
    pub identity: Option<String>,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

/// Shared state for the expose service.
struct ExposeState<S: ServiceApi> {
    api: Arc<S>,
    /// ServiceId -> Vec<ServiceConfig> (multiple services can share an identity)
    services: Mutex<HashMap<ServiceId, Vec<ServiceConfig>>>,
    /// Per-identity ephemeral label for the Identity record.
    /// Key: identity label (None → "default"). Value: `_expose_<random>`.
    expose_labels: Mutex<HashMap<String, String>>,
    /// Session nonce for generating expose labels.
    session_nonce: u64,
}

pub fn load_services(dir: &PathBuf) -> Vec<ServiceConfig> {
    let mut services = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("Cannot read config dir {}: {}", dir.display(), e);
            return services;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().map(|e| e != "toml").unwrap_or(true) {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Cannot read {}: {}", path.display(), e);
                continue;
            }
        };

        let config: ServiceConfig = match toml::from_str(&content) {
            Ok(c) => c,
            Err(e) => {
                warn!("Cannot parse {}: {}", path.display(), e);
                continue;
            }
        };

        info!("Loaded service '{}' -> {}", config.name, config.local);
        services.push(config);
    }

    services
}

/// Look up the privacy level for an identity label.
/// Returns `(ServiceId, PrivacyLevel)` or `None` if not found.
async fn lookup_identity_privacy<S: ServiceApi>(
    api: &S,
    label: Option<&str>,
) -> Option<(ServiceId, PrivacyLevel)> {
    let identities = match api.list_identities().await {
        Ok(ids) => ids,
        Err(e) => {
            error!("Failed to list identities: {}", e);
            return None;
        }
    };
    let target = label.unwrap_or("default");
    identities
        .into_iter()
        .find(|(l, _, _, _, _, _, _)| l == target)
        .map(|(_, sid, privacy, _, _, _, _)| (sid, privacy))
}

/// Parse the port from a "host:port" local address string.
fn parse_local_port(local: &str) -> Option<u16> {
    local.rsplit(':').next().and_then(|s| s.parse().ok())
}

/// The tarnet-facing listen port: explicit `port` field, or fall back to the local port.
fn listen_port(config: &ServiceConfig) -> Option<u16> {
    config.port.or_else(|| parse_local_port(&config.local))
}

/// Build ServiceId -> Vec<ServiceConfig> map, registering listeners for each.
async fn register_services<S: ServiceApi>(
    api: &S,
    configs: &[ServiceConfig],
) -> HashMap<ServiceId, Vec<ServiceConfig>> {
    let mut map: HashMap<ServiceId, Vec<ServiceConfig>> = HashMap::new();

    for config in configs {
        let identity_label = config.identity.as_deref();
        let sid = match lookup_identity_privacy(api, identity_label).await {
            Some((sid, _)) => sid,
            None => {
                error!(
                    "Cannot register '{}': identity '{}' not found",
                    config.name,
                    identity_label.unwrap_or("default")
                );
                continue;
            }
        };

        let port = match listen_port(config) {
            Some(p) => p,
            None => {
                error!("Cannot parse port from '{}' for service '{}'", config.local, config.name);
                continue;
            }
        };

        // Register listener on this ServiceId + port.
        // The node's circuit_listen is idempotent, so duplicates are fine.
        if let Err(e) = api.listen(sid, port).await {
            error!("Failed to listen on {:?} port {} for '{}': {}", sid, port, config.name, e);
            continue;
        }

        map.entry(sid).or_default().push(config.clone());
        info!("Registered service '{}' on {:?} port {}", config.name, sid, port);
    }

    map
}

async fn publish_services<S: ServiceApi>(state: &ExposeState<S>) {
    let services = state.services.lock().await;

    // Collect unique (identity_label, ServiceId) pairs for publishing.
    for configs in services.values() {
        for config in configs {
            if !config.publish {
                continue;
            }

            let identity_label = config.identity.as_deref();
            let (self_sid, privacy) = match lookup_identity_privacy(&*state.api, identity_label).await {
                Some(v) => v,
                None => continue,
            };

            // Hidden identities: the daemon automatically publishes and maintains
            // intro points. Expose only handles TNS records for public services.
            if matches!(privacy, PrivacyLevel::Hidden { .. }) {
                info!(
                    "Skipping TNS publish for '{}' (hidden identity — daemon manages intro points)",
                    config.name,
                );
                continue;
            }

            // Get or create a per-identity expose label.
            let identity_key = identity_label.unwrap_or("default").to_string();
            let expose_label = {
                let mut labels = state.expose_labels.lock().await;
                labels
                    .entry(identity_key)
                    .or_insert_with(|| {
                        let mut hasher = std::collections::hash_map::DefaultHasher::new();
                        std::hash::Hash::hash(&state.session_nonce, &mut hasher);
                        std::hash::Hash::hash(self_sid.as_bytes(), &mut hasher);
                        format!("_expose_{:016x}", std::hash::Hasher::finish(&hasher))
                    })
                    .clone()
            };

            // Publish <expose_label> → Identity(self_sid).
            let identity_record = TnsRecord::Identity(self_sid);
            if let Err(e) = state
                .api
                .tns_publish(identity_label, &expose_label, vec![identity_record], 3600)
                .await
            {
                error!("Failed to publish '{}' for '{}': {}", expose_label, config.name, e);
                continue;
            }

            // Publish <service_name> → Alias(<expose_label>).
            let alias_record = TnsRecord::Alias(expose_label);
            match state
                .api
                .tns_publish(identity_label, &config.name, vec![alias_record], 3600)
                .await
            {
                Ok(()) => info!("Published TNS record for '{}'", config.name),
                Err(e) => error!("Failed to publish '{}': {}", config.name, e),
            }
        }
    }
}

/// Pipe a circuit connection to a local TCP backend.
async fn pipe_tcp<S: ServiceApi>(
    conn: tarnet_api::service::Connection,
    local_addr: &str,
    service_name: &str,
) {
    let tcp_stream = match TcpStream::connect(local_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Cannot connect to local {} for '{}': {}", local_addr, service_name, e);
            return;
        }
    };

    info!("Accepted connection for service '{}' -> {}", service_name, local_addr);

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
    let conn = Arc::new(conn);

    let svc = service_name.to_string();
    let conn_upload = conn.clone();
    let upload = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if conn_upload.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let svc2 = svc.clone();
    let download = tokio::spawn(async move {
        loop {
            match conn.recv().await {
                Ok(payload) => {
                    if let Err(e) = tcp_write.write_all(&payload).await {
                        debug!("TCP write error for '{}': {}", svc2, e);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let _ = tokio::join!(upload, download);
}

/// Pipe a circuit connection to a local UDP backend.
async fn pipe_udp<S: ServiceApi>(
    conn: tarnet_api::service::Connection,
    local_addr: &str,
    service_name: &str,
) {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            error!("Cannot bind UDP socket for '{}': {}", service_name, e);
            return;
        }
    };
    if let Err(e) = sock.connect(local_addr).await {
        error!("Cannot connect UDP to {} for '{}': {}", local_addr, service_name, e);
        return;
    }

    info!("Accepted UDP connection for service '{}' -> {}", service_name, local_addr);

    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 65535];

    loop {
        let sock_recv = sock.clone();
        tokio::select! {
            // Circuit -> local UDP
            data = conn.recv() => {
                match data {
                    Ok(payload) => {
                        if let Err(e) = sock.send(&payload).await {
                            debug!("UDP send error for '{}': {}", service_name, e);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Local UDP -> circuit
            n = sock_recv.recv(&mut buf) => {
                match n {
                    Ok(n) => {
                        if let Err(e) = conn.send(&buf[..n]).await {
                            debug!("Circuit send error for '{}': {}", service_name, e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("UDP recv error for '{}': {}", service_name, e);
                        break;
                    }
                }
            }
        }
    }
}

/// Assert that no TnsRecord in `records` contains a ServiceId matching `forbidden_sid`.
/// This is the core safety invariant: hidden services must never leak the node's identity.
#[cfg(test)]
fn assert_no_identity_leak(records: &[TnsRecord], forbidden_sid: &ServiceId) {
    for record in records {
        if let TnsRecord::Identity(sid) = record {
            assert_ne!(
                sid, forbidden_sid,
                "PRIVACY VIOLATION: Identity record contains node ServiceId"
            );
        }
    }
}

/// Run the expose service. Blocks until shutdown.
/// The `reload_notify` is triggered by the IPC reload command or SIGHUP.
pub async fn run_expose<S: ServiceApi + 'static>(
    api: Arc<S>,
    config_dir: PathBuf,
    reload_notify: Arc<Notify>,
) {
    info!("Expose config dir: {}", config_dir.display());

    let configs = load_services(&config_dir);
    if configs.is_empty() {
        warn!("No services configured in {}", config_dir.display());
    }

    let services = register_services(&*api, &configs).await;

    let session_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let state = Arc::new(ExposeState {
        api: api.clone(),
        services: Mutex::new(services),
        expose_labels: Mutex::new(HashMap::new()),
        session_nonce,
    });

    // Publish TNS records.
    publish_services(&state).await;

    // Reload config on SIGHUP or IPC reload notification.
    let state_reload = state.clone();
    let config_dir_reload = config_dir.clone();
    tokio::spawn(async move {
        let mut sig =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        loop {
            tokio::select! {
                _ = sig.recv() => {
                    info!("SIGHUP received, reloading expose config...");
                }
                _ = reload_notify.notified() => {
                    info!("Reload notification received, reloading expose config...");
                }
            }
            let new_configs = load_services(&config_dir_reload);
            let new_services = register_services(&*state_reload.api, &new_configs).await;
            *state_reload.services.lock().await = new_services;
            publish_services(&state_reload).await;
        }
    });

    info!("Accepting connections...");

    // Main loop: accept circuit connections and pipe to local backends.
    loop {
        let conn = match api.accept().await {
            Ok(c) => c,
            Err(e) => {
                error!("Accept error: {}", e);
                break;
            }
        };

        let sid = conn.remote_service_id;
        let port = conn.port;

        // Look up which service config handles this ServiceId + port.
        let config = {
            let services = state.services.lock().await;
            services.get(&sid).and_then(|configs| {
                configs.iter().find(|c| listen_port(c) == Some(port)).cloned()
            })
        };

        let config = match config {
            Some(c) => c,
            None => {
                warn!("No service registered for {:?} port {}", sid, port);
                continue;
            }
        };

        let service_name = config.name.clone();
        let local_addr = config.local.clone();
        let protocol = config.protocol.clone();

        tokio::spawn(async move {
            if protocol == "udp" {
                pipe_udp::<S>(conn, &local_addr, &service_name).await;
            } else {
                pipe_tcp::<S>(conn, &local_addr, &service_name).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tarnet_api::error::{ApiError, ApiResult};
    use tarnet_api::service::{Connection, HelloInfo, NodeEvent, TnsResolution};
    use tarnet_api::types::{DhtId, IdentityScheme, KemAlgo, PeerId, SigningAlgo};
    use tokio::sync::mpsc;

    /// Mock ServiceApi that records which publish paths were taken.
    struct MockApi {
        peer_id: PeerId,
        identities: Vec<(String, ServiceId, PrivacyLevel, u8, IdentityScheme, SigningAlgo, KemAlgo)>,
        /// Set to true if tns_publish is called with an Identity record containing
        /// our ServiceId for a *hidden* identity.
        hidden_identity_leaked: Arc<AtomicBool>,
        /// Set to true if listen_hidden is called.
        listen_hidden_called: Arc<AtomicBool>,
        /// Set to true if tns_publish is called at all.
        tns_publish_called: Arc<AtomicBool>,
    }

    impl MockApi {
        fn new(identities: Vec<(String, ServiceId, PrivacyLevel, u8, IdentityScheme, SigningAlgo, KemAlgo)>) -> Self {
            Self {
                peer_id: PeerId([0xAA; 32]),
                identities,
                hidden_identity_leaked: Arc::new(AtomicBool::new(false)),
                listen_hidden_called: Arc::new(AtomicBool::new(false)),
                tns_publish_called: Arc::new(AtomicBool::new(false)),
            }
        }

        fn identity_privacy(&self, label: Option<&str>) -> Option<(ServiceId, PrivacyLevel)> {
            let target = label.unwrap_or("default");
            self.identities.iter()
                .find(|(l, _, _, _, _, _, _)| l == target)
                .map(|(_, sid, p, _, _, _, _)| (*sid, *p))
        }
    }

    #[async_trait]
    impl ServiceApi for MockApi {
        fn peer_id(&self) -> PeerId { self.peer_id }
        async fn default_service_id(&self) -> ServiceId { self.identities[0].1 }
        async fn resolve_identity(&self, _: &str) -> ApiResult<ServiceId> { Ok(self.identities[0].1) }
        async fn connect(&self, _: ServiceId, _: u16) -> ApiResult<Connection> { Err(ApiError::NotConnected) }
        async fn listen(&self, _: ServiceId, _: u16) -> ApiResult<()> { Ok(()) }
        async fn accept(&self) -> ApiResult<Connection> { Err(ApiError::NotConnected) }

        async fn listen_hidden(&self, _: ServiceId, _: u16, _: usize) -> ApiResult<()> {
            self.listen_hidden_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn dht_put_content(&self, _: &[u8]) -> [u8; 64] { [0; 64] }
        async fn dht_get_content(&self, _: &[u8; 64], _: u32) -> Option<Vec<u8>> { None }
        async fn dht_put_signed_content(&self, _: &[u8], _: u32, _: bool) -> [u8; 64] { [0; 64] }
        async fn dht_get_signed_content(&self, _: &[u8; 64], _: u32) -> Vec<(PeerId, Vec<u8>)> { vec![] }
        async fn unregister_republish(&self, _: &[u8]) {}
        async fn lookup_hello(&self, _: &PeerId, _: u32) -> Option<HelloInfo> { None }
        async fn dht_watch(&self, _: &DhtId, _: u32) {}
        async fn dht_unwatch(&self, _: &DhtId) {}
        async fn connected_peers(&self) -> Vec<PeerId> { vec![] }
        async fn routing_entries(&self) -> Vec<(PeerId, PeerId, u32)> { vec![] }
        async fn node_status(&self) -> tarnet_api::types::NodeStatus {
            tarnet_api::types::NodeStatus {
                peer_id: self.peer_id, uptime_secs: 0,
                peers: vec![], routes: vec![],
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
        async fn subscribe_events(&self) -> ApiResult<mpsc::Receiver<NodeEvent>> {
            let (_tx, rx) = mpsc::channel(1);
            Ok(rx)
        }

        async fn tns_publish(
            &self,
            identity: Option<&str>,
            _label: &str,
            records: Vec<TnsRecord>,
            _ttl_secs: u32,
        ) -> ApiResult<()> {
            self.tns_publish_called.store(true, Ordering::SeqCst);
            let (hidden_sid, is_hidden) = match self.identity_privacy(identity) {
                Some((sid, PrivacyLevel::Hidden { .. })) => (Some(sid), true),
                _ => (None, false),
            };
            if is_hidden {
                if let Some(sid) = hidden_sid {
                    for record in &records {
                        if let TnsRecord::Identity(rec_sid) = record {
                            if *rec_sid == sid {
                                self.hidden_identity_leaked.store(true, Ordering::SeqCst);
                            }
                        }
                    }
                }
            }
            Ok(())
        }

        async fn tns_resolve(&self, _: ServiceId, _: &str) -> ApiResult<TnsResolution> {
            Ok(TnsResolution::NotFound)
        }
        async fn tns_resolve_name(&self, _: &str) -> ApiResult<TnsResolution> {
            Ok(TnsResolution::NotFound)
        }
        async fn tns_set_label(&self, _: &str, _: Vec<TnsRecord>, _: bool) -> ApiResult<()> { Ok(()) }
        async fn tns_get_label(&self, _: &str) -> ApiResult<Option<(Vec<TnsRecord>, bool)>> { Ok(None) }
        async fn tns_remove_label(&self, _: &str) -> ApiResult<()> { Ok(()) }
        async fn tns_list_labels(&self) -> ApiResult<Vec<(String, Vec<TnsRecord>, bool)>> { Ok(vec![]) }

        async fn create_identity(&self, _: &str, _: PrivacyLevel, _: u8, _: IdentityScheme) -> ApiResult<ServiceId> {
            Ok(self.identities[0].1)
        }
        async fn list_identities(&self) -> ApiResult<Vec<(String, ServiceId, PrivacyLevel, u8, IdentityScheme, SigningAlgo, KemAlgo)>> {
            Ok(self.identities.clone())
        }
        async fn delete_identity(&self, _: &str) -> ApiResult<()> { Ok(()) }
        async fn update_identity(&self, _: &str, _: PrivacyLevel, _: u8) -> ApiResult<(PrivacyLevel, u8)> {
            Ok((PrivacyLevel::Public, 1))
        }

        async fn socks_addr(&self) -> ApiResult<Vec<std::net::SocketAddr>> { Ok(vec![]) }
        async fn connect_to(&self, _: &str, _: u16) -> ApiResult<Connection> { Err(ApiError::NotConnected) }

        async fn send_data(&self, _: &PeerId, _: &[u8]) -> ApiResult<()> { Ok(()) }
        async fn create_tunnel(&self, _: PeerId) -> ApiResult<PeerId> { Err(ApiError::NotConnected) }
        async fn send_tunnel_data(&self, _: &PeerId, _: &[u8]) -> ApiResult<()> { Ok(()) }
    }

    fn make_service(name: &str, identity: Option<&str>) -> ServiceConfig {
        ServiceConfig {
            name: name.to_string(),
            local: "127.0.0.1:8080".to_string(),
            port: None,
            protocol: "tcp".to_string(),
            publish: true,
            identity: identity.map(|s| s.to_string()),
        }
    }

    /// Helper to build ExposeState for publish tests.
    async fn make_publish_state(
        api: Arc<MockApi>,
        configs: Vec<ServiceConfig>,
    ) -> ExposeState<MockApi> {
        let services = register_services(&*api, &configs).await;
        ExposeState {
            api,
            services: Mutex::new(services),
            expose_labels: Mutex::new(HashMap::new()),
            session_nonce: 12345,
        }
    }

    /// Hidden identity: expose must not call tns_publish or listen_hidden.
    /// The daemon manages intro points automatically.
    #[tokio::test]
    async fn hidden_identity_skipped_by_expose() {
        let hidden_sid = ServiceId::from_signing_pubkey(&[0x01; 32]);
        let api = Arc::new(MockApi::new(vec![
            ("hidden-blog".into(), hidden_sid, PrivacyLevel::Hidden { intro_points: 3 }, 2, IdentityScheme::Ed25519, SigningAlgo::Ed25519, KemAlgo::X25519),
        ]));

        let config = make_service("myblog", Some("hidden-blog"));
        let state = make_publish_state(api.clone(), vec![config]).await;
        publish_services(&state).await;

        assert!(
            !api.hidden_identity_leaked.load(Ordering::SeqCst),
            "PRIVACY BUG: ServiceId was leaked in TNS record for hidden service"
        );
        assert!(
            !api.listen_hidden_called.load(Ordering::SeqCst),
            "expose should NOT call listen_hidden (daemon handles it)"
        );
        assert!(
            !api.tns_publish_called.load(Ordering::SeqCst),
            "expose should NOT call tns_publish for hidden identities"
        );
    }

    /// Public identity should still publish Service records normally.
    #[tokio::test]
    async fn public_identity_publishes_service_record() {
        let public_sid = ServiceId::from_signing_pubkey(&[0x02; 32]);
        let api = Arc::new(MockApi::new(vec![
            ("default".into(), public_sid, PrivacyLevel::Public, 1, IdentityScheme::Ed25519, SigningAlgo::Ed25519, KemAlgo::X25519),
        ]));

        let config = make_service("mysite", None);
        let state = make_publish_state(api.clone(), vec![config]).await;
        publish_services(&state).await;

        assert!(
            api.tns_publish_called.load(Ordering::SeqCst),
            "tns_publish should be called for public identities"
        );
        assert!(
            !api.listen_hidden_called.load(Ordering::SeqCst),
            "listen_hidden should NOT be called for public identities"
        );
    }

    /// Mixed: public services get tns_publish, hidden services are skipped.
    #[tokio::test]
    async fn mixed_public_and_hidden_services() {
        let public_sid = ServiceId::from_signing_pubkey(&[0x10; 32]);
        let hidden_sid = ServiceId::from_signing_pubkey(&[0x20; 32]);
        let api = Arc::new(MockApi::new(vec![
            ("default".into(), public_sid, PrivacyLevel::Public, 1, IdentityScheme::Ed25519, SigningAlgo::Ed25519, KemAlgo::X25519),
            ("secret".into(), hidden_sid, PrivacyLevel::Hidden { intro_points: 2 }, 3, IdentityScheme::Ed25519, SigningAlgo::Ed25519, KemAlgo::X25519),
        ]));

        let configs = vec![
            make_service("public-site", None),
            make_service("secret-site", Some("secret")),
        ];
        let state = make_publish_state(api.clone(), configs).await;
        publish_services(&state).await;

        assert!(api.tns_publish_called.load(Ordering::SeqCst));
        assert!(!api.listen_hidden_called.load(Ordering::SeqCst));
        assert!(
            !api.hidden_identity_leaked.load(Ordering::SeqCst),
            "ServiceId leaked despite hidden identity"
        );
    }

    /// Services with publish=false should not trigger any publishing.
    #[tokio::test]
    async fn unpublished_service_does_nothing() {
        let sid = ServiceId::from_signing_pubkey(&[0x30; 32]);
        let api = Arc::new(MockApi::new(vec![
            ("default".into(), sid, PrivacyLevel::Public, 1, IdentityScheme::Ed25519, SigningAlgo::Ed25519, KemAlgo::X25519),
        ]));

        let mut config = make_service("nopub", None);
        config.publish = false;
        let state = make_publish_state(api.clone(), vec![config]).await;
        publish_services(&state).await;

        assert!(!api.tns_publish_called.load(Ordering::SeqCst));
        assert!(!api.listen_hidden_called.load(Ordering::SeqCst));
    }

    /// Verify the assert_no_identity_leak helper catches violations.
    #[test]
    fn assert_no_identity_leak_catches_identity_record() {
        let sid = ServiceId::from_signing_pubkey(&[0xBB; 32]);
        let safe_records = vec![
            TnsRecord::IntroductionPoint {
                relay_peer_id: PeerId([0xCC; 32]),
                kem_algo: 0x01,
                kem_pubkey: vec![0; 32],
            },
            TnsRecord::Text("hello".to_string()),
        ];
        assert_no_identity_leak(&safe_records, &sid);

        let leaky_records = vec![TnsRecord::Identity(sid)];
        let result = std::panic::catch_unwind(|| {
            assert_no_identity_leak(&leaky_records, &sid);
        });
        assert!(result.is_err(), "should panic on ServiceId leak");
    }

    /// ServiceConfig with identity field should parse from TOML.
    #[test]
    fn service_config_identity_field_parses() {
        let toml_str = r#"
            name = "myblog"
            local = "127.0.0.1:8080"
            publish = true
            identity = "hidden-id"
        "#;
        let config: ServiceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.identity.as_deref(), Some("hidden-id"));
    }

    /// ServiceConfig without identity field should default to None.
    #[test]
    fn service_config_no_identity_defaults_none() {
        let toml_str = r#"
            name = "simple"
            local = "127.0.0.1:80"
            publish = true
        "#;
        let config: ServiceConfig = toml::from_str(toml_str).unwrap();
        assert!(config.identity.is_none());
    }
}
