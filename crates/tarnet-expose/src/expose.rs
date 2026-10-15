use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use log::{debug, error, info, warn};
use serde::Deserialize;
use tarnet_api::service::{
    vhost_wire_port, Listener, ListenerOptions, PoolClaim, PoolRegisterOptions, PortMode,
    ServiceApi, TnsRecord,
};
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
    /// Published record type for a subdomain: "vhost" (default) or "identity".
    /// A VHost is a connectable endpoint whose wire port is derived from the
    /// subdomain label; an Identity names an entity (e.g. a delegation/petname
    /// target) and is reached via apex semantics. Ignored at the apex (always
    /// Identity — the apex *is* the entity).
    pub record: Option<String>,
    /// ServiceId (base32) the published record should point at. Defaults to this
    /// config's own identity. Set it to a *different* machine's ServiceId to
    /// publish a pointer to that machine — a publish-only entry with no local
    /// listener (that machine serves the backend).
    pub target: Option<String>,
    /// Optional pool (virtual cluster) to advertise this service into, by local name.
    /// When set, the daemon publishes this node as an endpoint for `service` in the pool
    /// and keeps the lease refreshed. Independent of `publish` (a service can be both).
    pub pool: Option<String>,
    /// Pool service label to advertise under. Defaults to the config filename stem.
    pub service: Option<String>,
    /// Weighted round-robin weight for this endpoint (default 1).
    #[serde(default)]
    pub weight: Option<u16>,
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
    services: Mutex<Vec<RegisteredService>>,
}

#[derive(Debug, Clone)]
struct RegisteredService {
    service_id: ServiceId,
    /// None for publish-only entries (the record points at another machine, so
    /// we publish a pointer but bind no local listener).
    listener: Option<Listener>,
    service: LoadedService,
    /// Set when this service was also advertised into a pool; used to withdraw on shutdown.
    pool_claim: Option<PoolClaim>,
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
        return Err(format!(
            "subdomain '{}' must not start or end with a hyphen",
            label
        ));
    }
    if label.starts_with('_') {
        return Err(format!(
            "subdomain '{}' must not start with underscore (reserved)",
            label
        ));
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
            errors.push(format!(
                "{}: cannot determine listen port from local '{}'",
                path.display(),
                config.local
            ));
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

/// Register listeners for each loaded service.
async fn register_services<S: ServiceApi>(
    api: &S,
    loaded: &[LoadedService],
) -> Vec<RegisteredService> {
    let mut services = Vec::new();

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

        // The serving SID the published record points at: an explicit `target`
        // (possibly another machine) or this config's own identity. If it isn't
        // us, this is a publish-only entry — we bind no local listener.
        let serving_sid = match svc.config.target.as_deref() {
            Some(t) => match ServiceId::parse(t) {
                Ok(s) => s,
                Err(e) => {
                    error!("Invalid target '{}' for '{}': {}", t, svc.filename, e);
                    continue;
                }
            },
            None => sid,
        };
        let we_serve = serving_sid == sid;

        let mode = if svc.config.protocol == "udp" {
            PortMode::UnreliableUnordered
        } else {
            PortMode::ReliableOrdered
        };

        // The tarnet-facing port name to bind the local listener on (only when we
        // serve the backend).
        //
        // - Pool services keep the pool service label verbatim: pool consumers
        //   dial it literally via connect_via (the pool path has no VHost
        //   derivation).
        // - A VHost endpoint binds the *derived* wire port for
        //   `(canonical_label, supplied_port)`: canonical label is the subdomain.
        // - An Identity (or the apex) is reached via apex semantics, so connect_to
        //   derives from "@" — bind the wire port for `("@", supplied_port)`.
        let is_vhost = svc.config.record.as_deref().unwrap_or("vhost") != "identity";
        let pool_service = svc
            .config
            .pool
            .as_ref()
            .map(|_| svc.config.service.clone().unwrap_or_else(|| svc.filename.clone()));

        let listener = if !we_serve {
            // Publish-only: the target machine binds the listener, not us.
            info!(
                "'{}' is a publish-only pointer to {} (no local listener)",
                svc.filename, serving_sid
            );
            None
        } else {
            let port_name = if let Some(ref service) = pool_service {
                service.clone()
            } else {
                let supplied_port = match listen_port(&svc.config) {
                    Some(p) => p.to_string(),
                    None => {
                        error!(
                            "Cannot parse port from '{}' for '{}'",
                            svc.config.local, svc.filename
                        );
                        continue;
                    }
                };
                let canonical_label = match svc.config.subdomain.as_deref() {
                    Some(sub) if is_vhost => sub,
                    _ => "@",
                };
                vhost_wire_port(canonical_label, &supplied_port)
            };

            match api
                .listen(sid, mode, &port_name, ListenerOptions::default())
                .await
            {
                Ok(listener) => Some(listener),
                Err(e) => {
                    error!(
                        "Failed to listen on {:?} port {} for '{}': {}",
                        sid, port_name, svc.filename, e
                    );
                    continue;
                }
            }
        };
        // Advertise into a pool if configured (independent of TNS publish).
        // Pool advertisement only makes sense when we serve locally.
        let pool_claim = match (svc.config.pool.as_ref(), &listener) {
            (Some(pool), Some(bound)) => {
                let service = pool_service.as_deref().unwrap_or(&svc.filename);
                let opts = PoolRegisterOptions {
                    weight: svc.config.weight.unwrap_or(1),
                    meta: Vec::new(),
                    ..Default::default()
                };
                // Pool consumers dial the listener's port verbatim via connect_via.
                match api
                    .pool_register(
                        pool,
                        service,
                        svc.config.identity.as_deref(),
                        &bound.port,
                        opts,
                    )
                    .await
                {
                    Ok(claim) => {
                        info!(
                            "Registered '{}' as endpoint '{}' in pool '{}'",
                            svc.filename, service, pool
                        );
                        Some(claim)
                    }
                    Err(e) => {
                        error!(
                            "Failed to register '{}' in pool '{}': {}",
                            svc.filename, pool, e
                        );
                        None
                    }
                }
            }
            _ => None,
        };

        if let Some(bound) = &listener {
            info!(
                "Registered service '{}' on {:?} port {}",
                svc.filename, sid, bound.port
            );
        }
        services.push(RegisteredService {
            service_id: sid,
            listener,
            service: svc.clone(),
            pool_claim,
        });
    }

    services
}

async fn close_services<S: ServiceApi>(api: &S, services: &[RegisteredService]) {
    for service in services {
        // Withdraw any pool claim first (publishes a tombstone so consumers drop it now).
        if let Some(claim) = &service.pool_claim {
            if let Err(e) = api.pool_withdraw(claim.clone()).await {
                warn!(
                    "Failed to withdraw pool claim for '{}': {}",
                    service.service.filename, e
                );
            }
        }
        if let Some(listener) = &service.listener {
            if let Err(e) = api.close_listener(listener).await {
                warn!(
                    "Failed to close listener on {:?} port {} for '{}': {}",
                    service.service_id, listener.port, service.service.filename, e
                );
            }
        }
    }
}

fn spawn_accept_tasks<S: ServiceApi + 'static>(api: Arc<S>, services: &[RegisteredService]) {
    for registered in services.iter().cloned() {
        // Publish-only entries have no listener to accept on.
        let listener = match registered.listener.clone() {
            Some(l) => l,
            None => continue,
        };
        let api = api.clone();
        tokio::spawn(async move {
            loop {
                let conn = match api.accept(&listener).await {
                    Ok(c) => c,
                    Err(e) => {
                        info!(
                            "Listener {:?} port {} for '{}' stopped accepting: {}",
                            registered.service_id,
                            listener.port,
                            registered.service.filename,
                            e
                        );
                        break;
                    }
                };

                let service_name = registered.service.filename.clone();
                let local_addr = registered.service.config.local.clone();
                let protocol = registered.service.config.protocol.clone();

                tokio::spawn(async move {
                    if protocol == "udp" {
                        pipe_udp(conn, &local_addr, &service_name).await;
                    } else {
                        pipe_tcp(conn, &local_addr, &service_name).await;
                    }
                });
            }
        });
    }
}

async fn publish_services<S: ServiceApi>(state: &ExposeState<S>) {
    let services = state.services.lock().await;

    // Track which identities have already published their apex Identity record.
    let mut apex_published: HashMap<String, bool> = HashMap::new();

    for registered in services.iter() {
        let svc = &registered.service;
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

        // The SID the published record points at: an explicit target (possibly
        // another machine) or this config's own identity.
        let serving_sid = match svc.config.target.as_deref() {
            Some(t) => match ServiceId::parse(t) {
                Ok(s) => s,
                Err(e) => {
                    error!("Invalid target '{}' for '{}': {}", t, svc.filename, e);
                    continue;
                }
            },
            None => self_sid,
        };
        let is_vhost = svc.config.record.as_deref().unwrap_or("vhost") != "identity";

        if let Some(ref subdomain) = svc.config.subdomain {
            // Subdomain mode: publish <subdomain> → VHost(serving) by default (a
            // connectable endpoint whose wire port is derived from the subdomain
            // label), or Identity(serving) when `record = "identity"` (a naming /
            // delegation target reached via apex semantics).
            let (record, kind) = if is_vhost {
                (TnsRecord::VHost(serving_sid), "VHost")
            } else {
                (TnsRecord::Identity(serving_sid), "Identity")
            };
            match state
                .api
                .tns_publish(identity_label, subdomain, vec![record])
                .await
            {
                Ok(()) => info!(
                    "Published {} record for '{}.{}' -> {}",
                    kind, subdomain, identity_key, serving_sid
                ),
                Err(e) => error!(
                    "{}: failed to publish subdomain '{}': {}",
                    svc.filename, subdomain, e
                ),
            }
        } else {
            // Apex mode: publish Identity(serving) at "@" (the apex is always an
            // Identity — it *is* the entity; `record` is ignored here).
            // Only need to do this once per identity.
            if *apex_published.get(&identity_key).unwrap_or(&false) {
                continue;
            }

            // Check for @ conflict: if @ already points elsewhere, refuse.
            match state.api.tns_get_label(identity_label, "@").await {
                Ok(Some((records, _))) => {
                    let is_self = records
                        .iter()
                        .any(|r| matches!(r, TnsRecord::Identity(sid) if *sid == serving_sid));
                    let has_other = records.iter().any(|r| match r {
                        TnsRecord::Identity(sid) => *sid != serving_sid,
                        TnsRecord::Alias(_) | TnsRecord::Zone(_) | TnsRecord::VHost(_) => true,
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
                Ok(None) => {}
                Err(e) => {
                    warn!("Failed to check @ label: {}", e);
                }
            }

            let identity_record = TnsRecord::Identity(serving_sid);
            match state
                .api
                .tns_publish(identity_label, "@", vec![identity_record])
                .await
            {
                Ok(()) => {
                    info!(
                        "Published Identity at apex (@) for identity '{}' -> {}",
                        identity_key, serving_sid
                    );
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

/// Pipe a circuit connection to a local TCP backend.
pub async fn pipe_tcp(
    conn: tarnet_api::service::Connection,
    local_addr: &str,
    service_name: &str,
) {
    let tcp_stream = match TcpStream::connect(local_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Cannot connect to local {} for '{}': {}",
                local_addr, service_name, e
            );
            return;
        }
    };

    info!(
        "Accepted connection for service '{}' -> {}",
        service_name, local_addr
    );

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
    let conn = Arc::new(conn);

    let svc = service_name.to_string();
    let conn_upload = conn.clone();
    let mut upload = tokio::spawn(async move {
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
    let mut download = tokio::spawn(async move {
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

    // Tear down as soon as either direction ends rather than waiting for both.
    // When the backend EOFs (upload ends), aborting download drops the Connection
    // promptly, which triggers a StreamEnd back to the initiator so it can reset
    // the client. Waiting on join!() here would hang until the client also closed.
    tokio::select! {
        _ = &mut upload => { download.abort(); }
        _ = &mut download => { upload.abort(); }
    }
}

/// Pipe a circuit connection to a local UDP backend.
pub async fn pipe_udp(
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
        error!(
            "Cannot connect UDP to {} for '{}': {}",
            local_addr, service_name, e
        );
        return;
    }

    info!(
        "Accepted UDP connection for service '{}' -> {}",
        service_name, local_addr
    );

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
    {
        let current = state.services.lock().await.clone();
        spawn_accept_tasks(api.clone(), &current);
    }

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
                    let old_services = state_reload.services.lock().await.clone();
                    close_services(&*state_reload.api, &old_services).await;
                    let new_services = register_services(&*state_reload.api, &new_loaded).await;
                    *state_reload.services.lock().await = new_services;
                    let current = state_reload.services.lock().await.clone();
                    spawn_accept_tasks(state_reload.api.clone(), &current);
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

    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tarnet_api::error::{ApiError, ApiResult};
    use tarnet_api::service::{Connection, DhtEntry, HelloInfo, NodeEvent, TnsResolution};
    use tarnet_api::types::{DhtId, IdentityScheme, KemAlgo, PeerId, SigningAlgo};
    use tokio::sync::mpsc;

    /// Mock ServiceApi that records which publish paths were taken.
    struct MockApi {
        peer_id: PeerId,
        identities: Vec<(
            String,
            ServiceId,
            PrivacyLevel,
            u8,
            IdentityScheme,
            SigningAlgo,
            KemAlgo,
        )>,
        /// Set to true if tns_publish is called with an Identity record containing
        /// our ServiceId for a *hidden* identity.
        hidden_identity_leaked: Arc<AtomicBool>,
        /// Set to true if listen_hidden is called.
        listen_hidden_called: Arc<AtomicBool>,
        /// Set to true if tns_publish is called at all.
        tns_publish_called: Arc<AtomicBool>,
        /// Captured (label, records) for each tns_publish call.
        published: Arc<std::sync::Mutex<Vec<(String, Vec<TnsRecord>)>>>,
    }

    impl MockApi {
        fn new(
            identities: Vec<(
                String,
                ServiceId,
                PrivacyLevel,
                u8,
                IdentityScheme,
                SigningAlgo,
                KemAlgo,
            )>,
        ) -> Self {
            Self {
                peer_id: PeerId([0xAA; 32]),
                identities,
                hidden_identity_leaked: Arc::new(AtomicBool::new(false)),
                listen_hidden_called: Arc::new(AtomicBool::new(false)),
                tns_publish_called: Arc::new(AtomicBool::new(false)),
                published: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn identity_privacy(&self, label: Option<&str>) -> Option<(ServiceId, PrivacyLevel)> {
            let target = label.unwrap_or("default");
            self.identities
                .iter()
                .find(|(l, _, _, _, _, _, _)| l == target)
                .map(|(_, sid, p, _, _, _, _)| (*sid, *p))
        }
    }

    #[async_trait]
    impl ServiceApi for MockApi {
        fn peer_id(&self) -> PeerId {
            self.peer_id
        }
        async fn default_service_id(&self) -> ServiceId {
            self.identities[0].1
        }
        async fn resolve_identity(&self, _: &str) -> ApiResult<ServiceId> {
            Ok(self.identities[0].1)
        }
        async fn connect(&self, _: ServiceId, _: PortMode, _: &str) -> ApiResult<Connection> {
            Err(ApiError::NotConnected)
        }
        async fn listen(
            &self,
            service_id: ServiceId,
            mode: PortMode,
            port: &str,
            options: ListenerOptions,
        ) -> ApiResult<Listener> {
            Ok(Listener {
                id: 1,
                service_id,
                mode,
                port: port.to_string(),
                options,
            })
        }
        async fn accept(&self, _: &Listener) -> ApiResult<Connection> {
            Err(ApiError::NotConnected)
        }
        async fn close_listener(&self, _: &Listener) -> ApiResult<()> {
            Ok(())
        }

        async fn listen_hidden(
            &self,
            service_id: ServiceId,
            mode: PortMode,
            port: &str,
            _: usize,
            options: ListenerOptions,
        ) -> ApiResult<Listener> {
            self.listen_hidden_called.store(true, Ordering::SeqCst);
            Ok(Listener {
                id: 1,
                service_id,
                mode,
                port: port.to_string(),
                options,
            })
        }

        async fn dht_put(&self, _: &[u8]) -> tarnet_api::error::ApiResult<tarnet_api::types::ContentHandle> {
            Ok(tarnet_api::types::ContentHandle([0; 64]))
        }
        async fn dht_get(&self, _: &tarnet_api::types::ContentHandle, _: u32) -> Option<Vec<u8>> {
            None
        }
        async fn dht_put_signed(&self, _: &[u8], _: u32) -> tarnet_api::error::ApiResult<tarnet_api::types::ContentHandle> {
            Ok(tarnet_api::types::ContentHandle([0; 64]))
        }
        async fn dht_get_signed(&self, _: &tarnet_api::types::ContentHandle, _: u32) -> Vec<DhtEntry> {
            vec![]
        }
        async fn lookup_hello(&self, _: &PeerId, _: u32) -> Option<HelloInfo> {
            None
        }
        async fn dht_watch(&self, _: &DhtId, _: u32) {}
        async fn dht_unwatch(&self, _: &DhtId) {}
        async fn connected_peers(&self) -> Vec<PeerId> {
            vec![]
        }
        async fn routing_entries(&self) -> Vec<(PeerId, PeerId, u32)> {
            vec![]
        }
        async fn node_status(&self) -> tarnet_api::types::NodeStatus {
            tarnet_api::types::NodeStatus {
                peer_id: self.peer_id,
                uptime_secs: 0,
                peers: vec![],
                routes: vec![],
                dht: tarnet_api::types::DhtStatus {
                    stored_keys: 0,
                    stored_records: 0,
                    kbucket_peers: 0,
                    local_watches: 0,
                    remote_watches: 0,
                    nse: 0,
                },
                circuits: tarnet_api::types::CircuitStatus {
                    relay_forwards: 0,
                    relay_endpoints: 0,
                    outbound_circuits: 0,
                    rendezvous_points: 0,
                    intro_points: 0,
                },
                traffic: tarnet_api::types::TrafficStatus {
                    bytes_up: Default::default(),
                    bytes_down: Default::default(),
                    packets_up: Default::default(),
                    packets_down: Default::default(),
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
        ) -> ApiResult<()> {
            self.tns_publish_called.store(true, Ordering::SeqCst);
            self.published
                .lock()
                .unwrap()
                .push((_label.to_string(), records.clone()));
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
        async fn tns_set_label(
            &self,
            _: Option<&str>,
            _: &str,
            _: Vec<TnsRecord>,
            _: bool,
        ) -> ApiResult<()> {
            Ok(())
        }
        async fn tns_get_label(
            &self,
            _: Option<&str>,
            _: &str,
        ) -> ApiResult<Option<(Vec<TnsRecord>, bool)>> {
            Ok(None)
        }
        async fn tns_remove_label(&self, _: Option<&str>, _: &str) -> ApiResult<()> {
            Ok(())
        }
        async fn tns_list_labels(
            &self,
            _: Option<&str>,
        ) -> ApiResult<Vec<(String, Vec<TnsRecord>, bool)>> {
            Ok(vec![])
        }

        async fn create_identity(
            &self,
            _: &str,
            _: PrivacyLevel,
            _: u8,
            _: IdentityScheme,
        ) -> ApiResult<ServiceId> {
            Ok(self.identities[0].1)
        }
        async fn list_identities(
            &self,
        ) -> ApiResult<
            Vec<(
                String,
                ServiceId,
                PrivacyLevel,
                u8,
                IdentityScheme,
                SigningAlgo,
                KemAlgo,
            )>,
        > {
            Ok(self.identities.clone())
        }
        async fn delete_identity(&self, _: &str) -> ApiResult<()> {
            Ok(())
        }
        async fn update_identity(
            &self,
            _: &str,
            _: PrivacyLevel,
            _: u8,
        ) -> ApiResult<(PrivacyLevel, u8)> {
            Ok((PrivacyLevel::Public, 1))
        }

        async fn socks_addr(&self) -> ApiResult<Vec<std::net::SocketAddr>> {
            Ok(vec![])
        }
        async fn connect_to(&self, _: &str, _: PortMode, _: &str) -> ApiResult<Connection> {
            Err(ApiError::NotConnected)
        }

        async fn send_data(&self, _: &PeerId, _: &[u8]) -> ApiResult<()> {
            Ok(())
        }
        async fn create_tunnel(&self, _: PeerId) -> ApiResult<PeerId> {
            Err(ApiError::NotConnected)
        }
        async fn send_tunnel_data(&self, _: &PeerId, _: &[u8]) -> ApiResult<()> {
            Ok(())
        }

        async fn pool_join(
            &self,
            _: &str,
            _: tarnet_api::service::PoolKind,
        ) -> ApiResult<ServiceId> {
            Err(ApiError::NotConnected)
        }
        async fn pool_leave(&self, _: &str) -> ApiResult<()> {
            Ok(())
        }
        async fn pool_list(&self) -> ApiResult<Vec<(String, ServiceId)>> {
            Ok(vec![])
        }
        async fn pool_register(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: &str,
            _: tarnet_api::service::PoolRegisterOptions,
        ) -> ApiResult<tarnet_api::service::PoolClaim> {
            Err(ApiError::NotConnected)
        }
        async fn pool_withdraw(&self, _: tarnet_api::service::PoolClaim) -> ApiResult<()> {
            Ok(())
        }
        async fn pool_resolve(
            &self,
            _: &str,
            _: &str,
            _: u32,
        ) -> ApiResult<Vec<tarnet_api::service::PoolEndpoint>> {
            Ok(vec![])
        }
        async fn pool_catalog(&self, _: &str, _: u32) -> ApiResult<Vec<String>> {
            Ok(vec![])
        }
    }

    fn make_service(
        filename: &str,
        identity: Option<&str>,
        subdomain: Option<&str>,
    ) -> LoadedService {
        LoadedService {
            filename: filename.to_string(),
            config: ServiceConfig {
                local: "127.0.0.1:8080".to_string(),
                port: None,
                protocol: "tcp".to_string(),
                publish: true,
                identity: identity.map(|s| s.to_string()),
                subdomain: subdomain.map(|s| s.to_string()),
                record: None,
                target: None,
                pool: None,
                service: None,
                weight: None,
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
        let api = Arc::new(MockApi::new(vec![(
            "hidden-blog".into(),
            hidden_sid,
            PrivacyLevel::Hidden { intro_points: 3 },
            2,
            IdentityScheme::Ed25519,
            SigningAlgo::Ed25519,
            KemAlgo::X25519,
        )]));

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
        let api = Arc::new(MockApi::new(vec![(
            "default".into(),
            public_sid,
            PrivacyLevel::Public,
            1,
            IdentityScheme::Ed25519,
            SigningAlgo::Ed25519,
            KemAlgo::X25519,
        )]));

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
        let api = Arc::new(MockApi::new(vec![(
            "default".into(),
            public_sid,
            PrivacyLevel::Public,
            1,
            IdentityScheme::Ed25519,
            SigningAlgo::Ed25519,
            KemAlgo::X25519,
        )]));

        let svc = make_service("blog", None, Some("blog"));
        let state = make_publish_state(api.clone(), vec![svc]).await;
        publish_services(&state).await;

        assert!(api.tns_publish_called.load(Ordering::SeqCst));
    }

    /// Subdomain with `record = "identity"` publishes a plain Identity, not a VHost.
    #[tokio::test]
    async fn subdomain_record_identity_publishes_identity() {
        let public_sid = ServiceId::from_signing_pubkey(&[0x07; 32]);
        let api = Arc::new(MockApi::new(vec![(
            "default".into(),
            public_sid,
            PrivacyLevel::Public,
            1,
            IdentityScheme::Ed25519,
            SigningAlgo::Ed25519,
            KemAlgo::X25519,
        )]));

        let mut svc = make_service("blog", None, Some("blog"));
        svc.config.record = Some("identity".into());
        let state = make_publish_state(api.clone(), vec![svc]).await;
        publish_services(&state).await;

        let published = api.published.lock().unwrap();
        let (label, records) = published.iter().find(|(l, _)| l == "blog").expect("published blog");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], TnsRecord::Identity(public_sid), "expected Identity, got {:?}", records[0]);
        assert!(!matches!(records[0], TnsRecord::VHost(_)));
        let _ = label;
    }

    /// Subdomain defaults to a VHost record pointing at the serving SID.
    #[tokio::test]
    async fn subdomain_defaults_to_vhost() {
        let public_sid = ServiceId::from_signing_pubkey(&[0x08; 32]);
        let api = Arc::new(MockApi::new(vec![(
            "default".into(),
            public_sid,
            PrivacyLevel::Public,
            1,
            IdentityScheme::Ed25519,
            SigningAlgo::Ed25519,
            KemAlgo::X25519,
        )]));

        let svc = make_service("blog", None, Some("blog"));
        let state = make_publish_state(api.clone(), vec![svc]).await;
        publish_services(&state).await;

        let published = api.published.lock().unwrap();
        let (_, records) = published.iter().find(|(l, _)| l == "blog").expect("published blog");
        assert_eq!(records[0], TnsRecord::VHost(public_sid));
    }

    /// A `target` pointing at another machine yields a publish-only entry (no
    /// local listener) carrying that machine's SID.
    #[tokio::test]
    async fn target_elsewhere_is_publish_only() {
        let self_sid = ServiceId::from_signing_pubkey(&[0x09; 32]);
        let other_sid = ServiceId::from_signing_pubkey(&[0x0A; 32]);
        let api = Arc::new(MockApi::new(vec![(
            "default".into(),
            self_sid,
            PrivacyLevel::Public,
            1,
            IdentityScheme::Ed25519,
            SigningAlgo::Ed25519,
            KemAlgo::X25519,
        )]));

        let mut svc = make_service("relay", None, Some("relay"));
        svc.config.target = Some(other_sid.to_string());
        let registered = register_services(&*api, &[svc.clone()]).await;
        assert_eq!(registered.len(), 1);
        assert!(
            registered[0].listener.is_none(),
            "publish-only entry must have no local listener"
        );

        let state = make_publish_state(api.clone(), vec![svc]).await;
        publish_services(&state).await;
        let published = api.published.lock().unwrap();
        let (_, records) = published.iter().find(|(l, _)| l == "relay").expect("published relay");
        assert_eq!(records[0], TnsRecord::VHost(other_sid));
    }

    /// Mixed: public services get tns_publish, hidden services are skipped.
    #[tokio::test]
    async fn mixed_public_and_hidden_services() {
        let public_sid = ServiceId::from_signing_pubkey(&[0x10; 32]);
        let hidden_sid = ServiceId::from_signing_pubkey(&[0x20; 32]);
        let api = Arc::new(MockApi::new(vec![
            (
                "default".into(),
                public_sid,
                PrivacyLevel::Public,
                1,
                IdentityScheme::Ed25519,
                SigningAlgo::Ed25519,
                KemAlgo::X25519,
            ),
            (
                "secret".into(),
                hidden_sid,
                PrivacyLevel::Hidden { intro_points: 2 },
                3,
                IdentityScheme::Ed25519,
                SigningAlgo::Ed25519,
                KemAlgo::X25519,
            ),
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
        let api = Arc::new(MockApi::new(vec![(
            "default".into(),
            sid,
            PrivacyLevel::Public,
            1,
            IdentityScheme::Ed25519,
            SigningAlgo::Ed25519,
            KemAlgo::X25519,
        )]));

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
        assert!(
            validate_subdomain("_internal").is_err(),
            "leading underscore"
        );
        assert!(validate_subdomain("UPPER").is_err(), "uppercase");
        assert!(validate_subdomain("spa ce").is_err(), "space");
        let long = "a".repeat(64);
        assert!(validate_subdomain(&long).is_err(), "too long");
    }
}
