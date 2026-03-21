use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use log::{debug, error, info, warn};
use serde::Deserialize;
use tarnet_api::service::{ServiceApi, TnsRecord};
use tarnet_api::types::{PrivacyLevel, ServiceId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// Service config from a TOML file.
#[derive(Debug, Deserialize, Clone)]
pub struct ServiceConfig {
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
    /// Optional subdomain for TNS publication. If omitted, the service is published
    /// at the identity's zone apex (@) and reached by name + port.
    /// If set, the service is published as `<subdomain>.<identity>`.
    pub subdomain: Option<String>,
}

/// A loaded service config paired with its source filename (stem, no extension).
#[derive(Debug, Clone)]
pub struct LoadedService {
    /// Filename stem (e.g. "ssh" from "ssh.toml").
    pub filename: String,
    pub config: ServiceConfig,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

/// Shared state for the expose service.
struct ExposeState<S: ServiceApi> {
    api: Arc<S>,
    /// ServiceId -> Vec<LoadedService> (multiple services can share an identity)
    services: Mutex<HashMap<ServiceId, Vec<LoadedService>>>,
}

/// Validate a subdomain label: must be non-empty, no dots, only lowercase
/// alphanumeric plus hyphens, must not start/end with hyphen, max 63 chars.
fn validate_subdomain(label: &str) -> Result<(), String> {
    if label.is_empty() {
        return Err("subdomain must not be empty".into());
    }
    if label.len() > 63 {
        return Err(format!("subdomain '{}' exceeds 63 characters", label));
    }
    if label.contains('.') {
        return Err(format!("subdomain '{}' must not contain dots", label));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(format!("subdomain '{}' must not start or end with a hyphen", label));
    }
    if label.starts_with('_') {
        return Err(format!("subdomain '{}' must not start with underscore (reserved)", label));
    }
    for ch in label.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' {
            return Err(format!(
                "subdomain '{}' contains invalid character '{}' (only a-z, 0-9, - allowed)",
                label, ch
            ));
        }
    }
    Ok(())
}

/// Load and validate all service configs from the given directory.
/// Returns an error string describing all problems if any config is invalid.
pub fn load_services(dir: &PathBuf) -> Result<Vec<LoadedService>, String> {
    let mut services = Vec::new();
    let mut errors = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return Err(format!("cannot read config dir {}: {}", dir.display(), e));
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

        let filename = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: cannot read: {}", path.display(), e));
                continue;
            }
        };

        let config: ServiceConfig = match toml::from_str(&content) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: parse error: {}", path.display(), e));
                continue;
            }
        };

        // Validate subdomain if present.
        if let Some(ref sub) = config.subdomain {
            if let Err(e) = validate_subdomain(sub) {
                errors.push(format!("{}: {}", path.display(), e));
                continue;
            }
        }

        // Validate that we can parse a port.
        if listen_port(&config).is_none() {
            errors.push(format!("{}: cannot determine listen port from local '{}'", path.display(), config.local));
            continue;
        }

        info!("Loaded service '{}' -> {}", filename, config.local);
        services.push(LoadedService { filename, config });
    }

    if errors.is_empty() {
        Ok(services)
    } else {
        Err(errors.join("\n"))
    }
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

/// Build ServiceId -> Vec<LoadedService> map, registering listeners for each.
async fn register_services<S: ServiceApi>(
    api: &S,
    loaded: &[LoadedService],
) -> HashMap<ServiceId, Vec<LoadedService>> {
    let mut map: HashMap<ServiceId, Vec<LoadedService>> = HashMap::new();

    for svc in loaded {
        let identity_label = svc.config.identity.as_deref();
        let sid = match lookup_identity_privacy(api, identity_label).await {
            Some((sid, _)) => sid,
            None => {
                error!(
                    "Cannot register '{}': identity '{}' not found",
                    svc.filename,
                    identity_label.unwrap_or("default")
                );
                continue;
            }
        };

        let port = match listen_port(&svc.config) {
            Some(p) => p,
            None => {
                error!("Cannot parse port from '{}' for '{}'", svc.config.local, svc.filename);
                continue;
            }
        };

        // Register listener on this ServiceId + port.
        // The node's circuit_listen is idempotent, so duplicates are fine.
        if let Err(e) = api.listen(sid, port).await {
            error!("Failed to listen on {:?} port {} for '{}': {}", sid, port, svc.filename, e);
            continue;
        }

        map.entry(sid).or_default().push(svc.clone());
        info!("Registered service '{}' on {:?} port {}", svc.filename, sid, port);
    }

    map
}

async fn publish_services<S: ServiceApi>(state: &ExposeState<S>) {
    let services = state.services.lock().await;

    // Track which identities have already published their apex Identity record.
    let mut apex_published: HashMap<String, bool> = HashMap::new();

    for svcs in services.values() {
        for svc in svcs {
            if !svc.config.publish {
                continue;
            }

            let identity_label = svc.config.identity.as_deref();
            let (self_sid, privacy) = match lookup_identity_privacy(&*state.api, identity_label).await {
                Some(v) => v,
                None => continue,
            };

            // Hidden identities: the daemon automatically publishes and maintains
            // intro points. Expose only handles TNS records for public services.
            if matches!(privacy, PrivacyLevel::Hidden { .. }) {
                info!(
                    "Skipping TNS publish for '{}' (hidden identity — daemon manages intro points)",
                    svc.filename,
                );
                continue;
            }

            let identity_key = identity_label.unwrap_or("default").to_string();

            if let Some(ref subdomain) = svc.config.subdomain {
                // Subdomain mode: publish <subdomain> → Identity(self_sid).
                let identity_record = TnsRecord::Identity(self_sid);
                match state
                    .api
                    .tns_publish(identity_label, subdomain, vec![identity_record], 3600)
                    .await
                {
                    Ok(()) => info!("Published TNS record for '{}.{}'", subdomain, identity_key),
                    Err(e) => error!(
                        "{}: failed to publish subdomain '{}': {}",
                        svc.filename, subdomain, e
                    ),
                }
            } else {
                // Apex mode: publish Identity(self_sid) at "@".
                // Only need to do this once per identity.
                if *apex_published.get(&identity_key).unwrap_or(&false) {
                    continue;
                }

                // Check for @ conflict: if @ already points elsewhere, refuse.
                match state.api.tns_get_label("@").await {
                    Ok(Some((records, _))) => {
                        // @ is set. Check if it's our own Identity or something else.
                        let is_self = records.iter().any(|r| matches!(r, TnsRecord::Identity(sid) if *sid == self_sid));
                        let has_other = records.iter().any(|r| match r {
                            TnsRecord::Identity(sid) => *sid != self_sid,
                            TnsRecord::Alias(_) | TnsRecord::Zone(_) => true,
                            _ => false,
                        });
                        if has_other && !is_self {
                            error!(
                                "{}: cannot publish at apex (@): record already points elsewhere. \
                                 Set subdomain = \"{}\" in the config to publish as a subdomain instead.",
                                svc.filename, svc.filename,
                            );
                            continue;
                        }
                    }
                    Ok(None) => { /* @ is unset, good to go */ }
                    Err(e) => {
                        warn!("Failed to check @ label: {}", e);
                        // Proceed anyway — best effort.
                    }
                }

                let identity_record = TnsRecord::Identity(self_sid);
                match state
                    .api
                    .tns_publish(identity_label, "@", vec![identity_record], 3600)
                    .await
                {
                    Ok(()) => {
                        info!("Published Identity at apex (@) for identity '{}'", identity_key);
                        apex_published.insert(identity_key, true);
                    }
                    Err(e) => error!(
                        "{}: failed to publish Identity at apex: {}",
                        svc.filename, e
                    ),
                }
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

/// A reload request carrying a oneshot channel for error feedback.
pub type ReloadResult = Result<(), String>;
pub type ReloadSender = tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<ReloadResult>>;
pub type ReloadReceiver = tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<ReloadResult>>;

/// Run the expose service. Blocks until shutdown.
///
/// SIGHUP triggers a best-effort reload (no error feedback).
/// `reload_rx` receives IPC reload requests with error feedback via oneshot.
pub async fn run_expose<S: ServiceApi + 'static>(
    api: Arc<S>,
    config_dir: PathBuf,
    mut reload_rx: ReloadReceiver,
) {
    info!("Expose config dir: {}", config_dir.display());

    let loaded = match load_services(&config_dir) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to load services on startup: {}", e);
            Vec::new()
        }
    };
    if loaded.is_empty() {
        warn!("No services configured in {}", config_dir.display());
    }

    let services = register_services(&*api, &loaded).await;

    let state = Arc::new(ExposeState {
        api: api.clone(),
        services: Mutex::new(services),
    });

    // Publish TNS records.
    publish_services(&state).await;

    // Reload config on SIGHUP or IPC reload request.
    let state_reload = state.clone();
    let config_dir_reload = config_dir.clone();
    tokio::spawn(async move {
        let mut sig =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        loop {
            // Wait for either SIGHUP or an IPC reload request.
            let reply_tx: Option<tokio::sync::oneshot::Sender<ReloadResult>> = tokio::select! {
                _ = sig.recv() => {
                    info!("SIGHUP received, reloading expose config...");
                    None
                }
                Some(tx) = reload_rx.recv() => {
                    info!("Reload requested via IPC, reloading expose config...");
                    Some(tx)
                }
            };

            match load_services(&config_dir_reload) {
                Ok(new_loaded) => {
                    let new_services = register_services(&*state_reload.api, &new_loaded).await;
                    *state_reload.services.lock().await = new_services;
                    publish_services(&state_reload).await;
                    if let Some(tx) = reply_tx {
                        let _ = tx.send(Ok(()));
                    }
                }
                Err(e) => {
                    error!("Reload failed, keeping old config: {}", e);
                    if let Some(tx) = reply_tx {
                        let _ = tx.send(Err(e));
                    }
                }
            }
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
        let svc = {
            let services = state.services.lock().await;
            services.get(&sid).and_then(|svcs| {
                svcs.iter().find(|s| listen_port(&s.config) == Some(port)).cloned()
            })
        };

        let svc = match svc {
            Some(s) => s,
            None => {
                warn!("No service registered for {:?} port {}", sid, port);
                continue;
            }
        };

        let service_name = svc.filename.clone();
        let local_addr = svc.config.local.clone();
        let protocol = svc.config.protocol.clone();

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

    fn make_service(filename: &str, identity: Option<&str>, subdomain: Option<&str>) -> LoadedService {
        LoadedService {
            filename: filename.to_string(),
            config: ServiceConfig {
                local: "127.0.0.1:8080".to_string(),
                port: None,
                protocol: "tcp".to_string(),
                publish: true,
                identity: identity.map(|s| s.to_string()),
                subdomain: subdomain.map(|s| s.to_string()),
            },
        }
    }

    /// Helper to build ExposeState for publish tests.
    async fn make_publish_state(
        api: Arc<MockApi>,
        loaded: Vec<LoadedService>,
    ) -> ExposeState<MockApi> {
        let services = register_services(&*api, &loaded).await;
        ExposeState {
            api,
            services: Mutex::new(services),
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

        let svc = make_service("myblog", Some("hidden-blog"), None);
        let state = make_publish_state(api.clone(), vec![svc]).await;
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

    /// Public identity should publish Identity at apex (@).
    #[tokio::test]
    async fn public_identity_publishes_at_apex() {
        let public_sid = ServiceId::from_signing_pubkey(&[0x02; 32]);
        let api = Arc::new(MockApi::new(vec![
            ("default".into(), public_sid, PrivacyLevel::Public, 1, IdentityScheme::Ed25519, SigningAlgo::Ed25519, KemAlgo::X25519),
        ]));

        let svc = make_service("mysite", None, None);
        let state = make_publish_state(api.clone(), vec![svc]).await;
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

    /// Public identity with subdomain should publish at the subdomain label.
    #[tokio::test]
    async fn public_identity_publishes_at_subdomain() {
        let public_sid = ServiceId::from_signing_pubkey(&[0x02; 32]);
        let api = Arc::new(MockApi::new(vec![
            ("default".into(), public_sid, PrivacyLevel::Public, 1, IdentityScheme::Ed25519, SigningAlgo::Ed25519, KemAlgo::X25519),
        ]));

        let svc = make_service("blog", None, Some("blog"));
        let state = make_publish_state(api.clone(), vec![svc]).await;
        publish_services(&state).await;

        assert!(api.tns_publish_called.load(Ordering::SeqCst));
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

        let svcs = vec![
            make_service("public-site", None, None),
            make_service("secret-site", Some("secret"), None),
        ];
        let state = make_publish_state(api.clone(), svcs).await;
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

        let mut svc = make_service("nopub", None, None);
        svc.config.publish = false;
        let state = make_publish_state(api.clone(), vec![svc]).await;
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

    /// ServiceConfig with identity and subdomain fields should parse from TOML.
    #[test]
    fn service_config_identity_field_parses() {
        let toml_str = r#"
            local = "127.0.0.1:8080"
            publish = true
            identity = "hidden-id"
            subdomain = "blog"
        "#;
        let config: ServiceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.identity.as_deref(), Some("hidden-id"));
        assert_eq!(config.subdomain.as_deref(), Some("blog"));
    }

    /// ServiceConfig without optional fields should default to None.
    #[test]
    fn service_config_no_identity_defaults_none() {
        let toml_str = r#"
            local = "127.0.0.1:80"
            publish = true
        "#;
        let config: ServiceConfig = toml::from_str(toml_str).unwrap();
        assert!(config.identity.is_none());
        assert!(config.subdomain.is_none());
    }

    /// Subdomain validation tests.
    #[test]
    fn subdomain_validation() {
        assert!(validate_subdomain("ssh").is_ok());
        assert!(validate_subdomain("my-blog").is_ok());
        assert!(validate_subdomain("web0").is_ok());

        assert!(validate_subdomain("").is_err(), "empty");
        assert!(validate_subdomain("has.dot").is_err(), "dots");
        assert!(validate_subdomain("-leading").is_err(), "leading hyphen");
        assert!(validate_subdomain("trailing-").is_err(), "trailing hyphen");
        assert!(validate_subdomain("_internal").is_err(), "leading underscore");
        assert!(validate_subdomain("UPPER").is_err(), "uppercase");
        assert!(validate_subdomain("spa ce").is_err(), "space");
        let long = "a".repeat(64);
        assert!(validate_subdomain(&long).is_err(), "too long");
    }
}
