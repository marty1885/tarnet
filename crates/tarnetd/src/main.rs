mod config;
mod ipc_server;
mod local_api;
mod mdns;
mod stun;

use std::path::PathBuf;
use std::sync::Arc;

use tarnet::identity::Keypair;
use tarnet::node::Node;
use tarnet::state::{StateDb, StorageLimits};
use tarnet::transport::tcp::TcpDiscovery;
use tarnet::transport::MultiDiscovery;
use tarnet::types::ScopedAddress;
use tarnet_api::service::ServiceApi;
use tokio::sync::{mpsc, Notify};

use config::{CliOverrides, ResolvedConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let (data_dir, config_dir, cli) = parse_cli(&args[1..]);

    let data_dir = data_dir.unwrap_or_else(tarnet_api::ipc::default_data_dir);
    let config_dir = config_dir.unwrap_or_else(tarnet_api::ipc::default_config_dir);

    // Ensure directories exist
    std::fs::create_dir_all(&data_dir).unwrap_or_else(|e| {
        eprintln!("Failed to create data dir {}: {}", data_dir.display(), e);
        std::process::exit(1);
    });
    std::fs::create_dir_all(&config_dir).unwrap_or_else(|e| {
        eprintln!("Failed to create config dir {}: {}", config_dir.display(), e);
        std::process::exit(1);
    });
    let services_dir = tarnet_api::ipc::services_dir_for(&config_dir);
    std::fs::create_dir_all(&services_dir).ok();

    // Write defaults reference file
    config::write_defaults_file(&config_dir);

    // Load config file
    let config_path = tarnet_api::ipc::config_path_for(&config_dir);
    let config_found = config_path.exists();
    let cfg = match config::load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let opts = config::resolve(&data_dir, &config_dir, cfg, cli);

    let identity = load_or_generate_identity(&opts.identity_path);
    let db = Arc::new(StateDb::open(&opts.state_path).unwrap_or_else(|e| {
        eprintln!(
            "Failed to open state DB at {}: {}",
            opts.state_path.display(),
            e
        );
        std::process::exit(1);
    }));
    let peer_id = identity.peer_id();

    #[allow(unused_mut)]
    let mut node = Node::with_db(
        identity,
        db.clone(),
        StorageLimits::default(),
    );
    node.set_link_limits(opts.max_inbound, opts.max_outbound);
    node.set_bandwidth_limits(opts.upload_limit, opts.download_limit);

    let tcp_discovery = TcpDiscovery::bind(&opts.listen_addrs)
        .await
        .expect("Failed to bind TCP");
    let local_addrs = tcp_discovery.local_addrs().to_vec();

    // Enable mainline DHT bootstrap announcing if requested
    #[cfg(feature = "mainline-bootstrap")]
    if opts.mainline {
        if let Some(first) = local_addrs.first() {
            node.enable_mainline(first.port());
        }
    }

    // Enable WebRTC if configured
    if opts.webrtc_enabled && !opts.webrtc_stun.is_empty() {
        match node.enable_webrtc(opts.webrtc_stun.clone()) {
            Ok(()) => log::info!("WebRTC enabled with {} STUN servers", opts.webrtc_stun.len()),
            Err(e) => log::warn!("Failed to enable WebRTC: {}", e),
        }
    }

    let node = Arc::new(node);

    // Create the service API BEFORE starting the node (takes receivers)
    let socks_addrs = if opts.socks_enabled { opts.socks_bind.clone() } else { Vec::new() };
    let api = Arc::new(local_api::LocalServiceApi::with_db(node.clone(), db, socks_addrs).await);

    // Build hello addresses: only advertise TCP if explicitly opted in.
    // Loopback, link-local, and private addresses never go in hello records —
    // mDNS handles LAN discovery, and the handshake verifies identity.
    let mut global_addrs = Vec::new();
    let mut public_display = "not advertised".to_string();

    if opts.tcp_advertise {
        if let Some(ref public) = opts.tcp_public_addr {
            let addr: std::net::SocketAddr = public.parse().unwrap_or_else(|e| {
                eprintln!("Invalid public_addr '{}': {}", public, e);
                std::process::exit(1);
            });
            global_addrs.push(ScopedAddress::global_from_socket_addr(addr));
            public_display = format!("{} (explicit)", public);
        } else if !opts.tcp_stun.is_empty() {
            let port = local_addrs[0].port();
            match stun::query_public_addr(&opts.tcp_stun, port).await {
                Some(public) => {
                    log::info!("STUN detected public address: {}", public);
                    global_addrs.push(ScopedAddress::global_from_socket_addr(public));
                    public_display = format!("{} (via STUN)", public);
                }
                None => {
                    log::warn!("STUN query failed, no TCP address advertised");
                    public_display = "STUN failed, not advertised".to_string();
                }
            }
        }
    }

    // Add WebSocket public URL to hello addresses if configured
    if let Some(ref ws_url) = opts.ws_public_url {
        global_addrs.push(ScopedAddress::from_ws_url(ws_url));
    }

    node.set_global_addrs(global_addrs).await;

    let address = tarnet_api::types::encode_base32(&node.default_service_address().await);

    // Startup banner
    print_banner(&opts, &address, &peer_id, &local_addrs, &config_path, config_found, &public_display);

    #[cfg(feature = "mainline-bootstrap")]
    if opts.mainline {
        let mainline_addr = tarnet::bootstrap::format_mainline_addr(&peer_id);
        eprintln!();
        eprintln!("  Bootstrap this node from anywhere with internet access:");
        eprintln!("    tarnetd --bootstrap {}", mainline_addr);
    }
    eprintln!();

    // Shared reload notifier: triggered by IPC reload command or SIGHUP.
    let reload_notify = Arc::new(Notify::new());

    // Forward SIGHUP into the reload notifier.
    {
        let notify = reload_notify.clone();
        tokio::spawn(async move {
            let mut sig =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
            loop {
                sig.recv().await;
                notify.notify_waiters();
            }
        });
    }

    // Start the IPC server
    let ipc_api = api.clone() as Arc<dyn tarnet_api::service::ServiceApi>;
    let socket_path = opts.socket_path.clone();
    let ipc_reload = reload_notify.clone();
    tokio::spawn(async move {
        if let Err(e) = ipc_server::run_ipc_server(socket_path, ipc_api, ipc_reload).await {
            log::error!("IPC server error: {}", e);
        }
    });

    // Start SOCKS5 proxy
    let _socks_shutdown = if opts.socks_enabled {
        let socks_api = api.clone();
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let bind_addrs = opts.socks_bind.clone();
        let allow_clearnet = opts.socks_allow_clearnet;
        tokio::spawn(async move {
            match tarnet_socks::proxy::run_proxy(
                socks_api, &bind_addrs, allow_clearnet, shutdown_rx,
            )
            .await
            {
                Ok(addrs) => {
                    for addr in &addrs {
                        log::info!("SOCKS5 proxy running on {}", addr);
                    }
                }
                Err(e) => log::error!("Failed to start SOCKS5 proxy: {}", e),
            }
        });
        Some(shutdown_tx)
    } else {
        None
    };

    // Start expose service
    if opts.expose_enabled {
        let expose_api = api.clone();
        let expose_dir = opts.expose_dir.clone();
        let expose_reload = reload_notify.clone();
        tokio::spawn(async move {
            tarnet_expose::expose::run_expose(expose_api, expose_dir, expose_reload).await;
        });
    }

    // Bandwidth limit reload on SIGHUP / IPC reload
    {
        let reload = reload_notify.clone();
        let config_path = opts.config_dir.join("tarnetd.toml");
        let node_ref = node.clone();
        tokio::spawn(async move {
            loop {
                reload.notified().await;
                match config::load_config(&config_path) {
                    Ok(cfg) => {
                        let ul = tarnet::bandwidth::parse_bandwidth(&cfg.core.upload_limit)
                            .unwrap_or(0);
                        let dl = tarnet::bandwidth::parse_bandwidth(&cfg.core.download_limit)
                            .unwrap_or(0);
                        node_ref.update_bandwidth_limits(ul, dl).await;
                        log::info!(
                            "Bandwidth limits reloaded: upload={} B/s, download={} B/s (0=unlimited)",
                            ul,
                            dl,
                        );
                    }
                    Err(e) => {
                        log::warn!("Failed to reload config for bandwidth limits: {}", e);
                    }
                }
            }
        });
    }

    // Start mDNS discovery
    let _mdns_handle = if opts.mdns {
        let peer_hex = format!("{}", peer_id);
        let tcp_port = local_addrs.first().map(|a| a.port()).unwrap_or(7946);
        match mdns::start(&peer_hex, tcp_port) {
            Ok((mut rx, handle)) => {
                let event_tx = node.event_sender();
                let identity_for_mdns = node.identity_clone();
                tokio::spawn(async move {
                    while let Some(addr) = rx.recv().await {
                        log::info!("mDNS: connecting to discovered peer at {}", addr);
                        let tx = event_tx.clone();
                        let id = identity_for_mdns.clone();
                        tokio::spawn(async move {
                            match tokio::net::TcpStream::connect(&addr).await {
                                Ok(stream) => {
                                    let _ = stream.set_nodelay(true);
                                    let transport: Box<dyn tarnet::transport::Transport> =
                                        Box::new(tarnet::transport::tcp::TcpTransport::new(stream));
                                    match tarnet::link::PeerLink::initiator(transport, &id, None).await {
                                        Ok(link) => {
                                            let link = Arc::new(link);
                                            log::info!("mDNS: connected to {:?}", link.remote_peer());
                                            let _ = tx.send(tarnet::node::NodeEvent::LinkUp(
                                                link.remote_peer(),
                                                link,
                                            )).await;
                                        }
                                        Err(e) => log::warn!("mDNS peer handshake failed: {}", e),
                                    }
                                }
                                Err(e) => log::debug!("mDNS: failed to connect to {}: {}", addr, e),
                            }
                        });
                    }
                });
                Some(handle)
            }
            Err(e) => {
                log::warn!("Failed to start mDNS: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Periodic status logging
    let status_api = api.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let peers = status_api.connected_peers().await;
            let routes = status_api.routing_entries().await;
            log::info!(
                "Status: {} direct peers, {} known routes",
                peers.len(),
                routes.len()
            );
        }
    });

    // Build composite discovery (TCP + optional WS listener + always WS connector)
    let discovery: Box<dyn tarnet::transport::Discovery> = if opts.ws_enabled {
        let ws_discovery = tarnet::transport::ws::WsDiscovery::bind(
            &opts.ws_listen, opts.ws_path.clone(),
        )
        .await
        .expect("Failed to bind WebSocket");
        log::info!(
            "WebSocket listening on {} (path: {})",
            ws_discovery.local_addr(),
            ws_discovery.path(),
        );
        // WS first so connect() dispatches ws:// URLs before TCP tries them
        Box::new(MultiDiscovery::new(vec![
            Box::new(ws_discovery),
            Box::new(tcp_discovery),
        ]))
    } else {
        // No WS listener, but outbound ws:// / wss:// connects still work
        Box::new(MultiDiscovery::new(vec![
            Box::new(tarnet::transport::ws::WsConnector::new()),
            Box::new(tcp_discovery),
        ]))
    };

    // Run the overlay node (blocking)
    if let Err(e) = node.run(discovery, opts.bootstrap, opts.discovery).await {
        log::error!("Node error: {}", e);
        std::process::exit(1);
    }
}

fn print_banner(
    opts: &ResolvedConfig,
    address: &str,
    peer_id: &tarnet_api::types::PeerId,
    local_addrs: &[std::net::SocketAddr],
    config_path: &std::path::Path,
    config_found: bool,
    public_display: &str,
) {
    eprintln!("=== tarnetd ===");
    eprintln!("  Address:   {}", address);
    eprintln!("  PeerId:    {}", peer_id);
    eprintln!("  Data:      {}", opts.data_dir.display());
    let config_status = if config_found { "" } else { " (not found, using defaults)" };
    eprintln!("  Config:    {}{}", config_path.display(), config_status);
    for addr in local_addrs {
        eprintln!("  TCP:       {}", addr);
    }
    eprintln!("  Public:    {}", public_display);
    if opts.webrtc_enabled {
        eprintln!("  WebRTC:    enabled ({} STUN servers)", opts.webrtc_stun.len());
    } else {
        eprintln!("  WebRTC:    disabled");
    }
    if opts.ws_enabled {
        match &opts.ws_public_url {
            Some(url) => eprintln!("  WS:        {} (path: {}, public: {})", opts.ws_listen, opts.ws_path, url),
            None => eprintln!("  WS:        {} (path: {}, not advertised)", opts.ws_listen, opts.ws_path),
        }
    }
    let inbound_str = if opts.max_inbound == 0 { "unlimited".to_string() } else { opts.max_inbound.to_string() };
    let outbound_str = if opts.max_outbound == 0 { "unlimited".to_string() } else { opts.max_outbound.to_string() };
    eprintln!("  Links:     max {} inbound, {} outbound", inbound_str, outbound_str);
    let ul_str = if opts.upload_limit == 0 { "unlimited".to_string() } else { format_bandwidth(opts.upload_limit) };
    let dl_str = if opts.download_limit == 0 { "unlimited".to_string() } else { format_bandwidth(opts.download_limit) };
    eprintln!("  Bandwidth: up {} / down {}", ul_str, dl_str);
    eprintln!("  mDNS:      {}", if opts.mdns { "enabled" } else { "disabled" });
    eprintln!("  IPC:       {}", opts.socket_path.display());
    if opts.socks_enabled {
        let addrs: Vec<String> = opts.socks_bind.iter().map(|a| a.to_string()).collect();
        eprintln!("  SOCKS5:    {}", addrs.join(", "));
    }
    if opts.expose_enabled {
        eprintln!("  Expose:    {}", opts.expose_dir.display());
    }
    if !opts.bootstrap.is_empty() {
        eprintln!("  Bootstrap: {:?}", opts.bootstrap);
    }
    if !opts.discovery.is_empty() {
        eprintln!("  Discovery: {:?}", opts.discovery);
    }
}

/// Format bytes/sec as a human-readable string.
fn format_bandwidth(bytes_per_sec: u64) -> String {
    let bits = bytes_per_sec * 8;
    if bits >= 1_000_000_000 {
        format!("{:.1} Gbps", bits as f64 / 1_000_000_000.0)
    } else if bits >= 1_000_000 {
        format!("{:.1} Mbps", bits as f64 / 1_000_000.0)
    } else if bits >= 1_000 {
        format!("{:.1} kbps", bits as f64 / 1_000.0)
    } else {
        format!("{} bps", bits)
    }
}

/// Parse CLI into (data_dir, config_dir, CliOverrides).
fn parse_cli(args: &[String]) -> (Option<PathBuf>, Option<PathBuf>, CliOverrides) {
    let mut data_dir: Option<PathBuf> = None;
    let mut config_dir: Option<PathBuf> = None;
    let mut cli = CliOverrides::default();
    let mut listen_addrs = Vec::new();
    let mut bootstrap = Vec::new();
    let mut discovery: Vec<String> = Vec::new();
    let mut stun_servers = Vec::new();

    let next_arg = |i: usize, flag: &str| -> &String {
        args.get(i).unwrap_or_else(|| {
            eprintln!("Missing value for {}", flag);
            std::process::exit(1);
        })
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                data_dir = Some(PathBuf::from(next_arg(i, "--data-dir")));
            }
            "--config-dir" => {
                i += 1;
                config_dir = Some(PathBuf::from(next_arg(i, "--config-dir")));
            }
            "--listen" => {
                i += 1;
                listen_addrs.push(next_arg(i, "--listen").clone());
            }
            "--identity" => {
                i += 1;
                cli.identity = Some(PathBuf::from(next_arg(i, "--identity")));
            }
            "--connect" | "--bootstrap" => {
                i += 1;
                bootstrap.push(next_arg(i, "--bootstrap").clone());
            }
            "--discovery" => {
                i += 1;
                discovery.push(next_arg(i, "--discovery").clone());
            }
            "--mainline" => {
                cli.mainline = Some(true);
            }
            "--stun" => {
                i += 1;
                stun_servers.push(next_arg(i, "--stun").clone());
            }
            "--public-addr" => {
                i += 1;
                cli.public_addr = Some(next_arg(i, "--public-addr").clone());
            }
            "--advertise-tcp" => {
                cli.advertise_tcp = true;
            }
            "--no-webrtc" => {
                cli.no_webrtc = true;
            }
            "--ws" => {
                cli.ws_enabled = Some(true);
            }
            "--ws-listen" => {
                i += 1;
                cli.ws_listen = Some(next_arg(i, "--ws-listen").clone());
                cli.ws_enabled = Some(true);
            }
            "--ws-path" => {
                i += 1;
                cli.ws_path = Some(next_arg(i, "--ws-path").clone());
                cli.ws_enabled = Some(true);
            }
            "--ws-public-url" => {
                i += 1;
                cli.ws_public_url = Some(next_arg(i, "--ws-public-url").clone());
                cli.ws_enabled = Some(true);
            }
            "--no-ws" => {
                cli.ws_enabled = Some(false);
            }
            "--no-mdns" => {
                cli.no_mdns = true;
            }
            "--state" => {
                i += 1;
                cli.state = Some(PathBuf::from(next_arg(i, "--state")));
            }
            "--socket" => {
                i += 1;
                cli.socket = Some(PathBuf::from(next_arg(i, "--socket")));
            }
            "--socks" => {
                i += 1;
                let val = next_arg(i, "--socks");
                let addr: std::net::SocketAddr = val.parse().unwrap_or_else(|e| {
                    eprintln!("Invalid SOCKS address '{}': {}", val, e);
                    std::process::exit(1);
                });
                cli.socks_bind = Some(vec![addr]);
            }
            "--socks-allow-clearnet" => {
                cli.socks_allow_clearnet = Some(true);
            }
            "--no-socks" => {
                cli.no_socks = true;
            }
            "--expose-dir" => {
                i += 1;
                cli.expose_dir = Some(PathBuf::from(next_arg(i, "--expose-dir")));
            }
            "--no-expose" => {
                cli.no_expose = true;
            }
            "--max-inbound-links" => {
                i += 1;
                let val = next_arg(i, "--max-inbound-links");
                cli.max_inbound = Some(val.parse().unwrap_or_else(|e| {
                    eprintln!("Invalid --max-inbound-links '{}': {}", val, e);
                    std::process::exit(1);
                }));
            }
            "--max-outbound-links" => {
                i += 1;
                let val = next_arg(i, "--max-outbound-links");
                cli.max_outbound = Some(val.parse().unwrap_or_else(|e| {
                    eprintln!("Invalid --max-outbound-links '{}': {}", val, e);
                    std::process::exit(1);
                }));
            }
            "--upload-limit" => {
                i += 1;
                cli.upload_limit = Some(next_arg(i, "--upload-limit").clone());
            }
            "--download-limit" => {
                i += 1;
                cli.download_limit = Some(next_arg(i, "--download-limit").clone());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown option: {}", other);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if !listen_addrs.is_empty() {
        cli.listen = Some(listen_addrs);
    }
    if !bootstrap.is_empty() {
        cli.bootstrap = Some(bootstrap);
    }
    if !discovery.is_empty() {
        cli.discovery = Some(discovery);
    }
    if !stun_servers.is_empty() {
        cli.stun = Some(stun_servers);
    }

    (data_dir, config_dir, cli)
}

fn print_usage() {
    eprintln!("Usage: tarnetd [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --data-dir <dir>        Data directory (default: $XDG_DATA_HOME/tarnet)");
    eprintln!("  --config-dir <dir>      Config directory (default: $XDG_CONFIG_HOME/tarnet)");
    eprintln!("  --listen <addr>         TCP listen address (repeatable; default: 0.0.0.0:7946)");
    eprintln!("  --identity <file>       Identity key file (default: <data-dir>/identity.key)");
    eprintln!("  --state <file>          Persistent SQLite state DB (default: <data-dir>/state.sqlite3)");
    eprintln!("  --bootstrap <uri>       Bootstrap peer transport URI (repeatable):");
    eprintln!("                            tcp://host:port  wss://host/path  ws://host/path");
    eprintln!("  --discovery <uri>       Discover peers via resolution protocol (repeatable):");
    eprintln!("                            mainline:<hex>");
    eprintln!("  --mainline              Announce on BitTorrent mainline DHT for remote bootstrap");
    eprintln!("  --advertise-tcp         Advertise TCP address in hello records (default: off)");
    eprintln!("  --stun <url>            Override STUN server (repeatable; applies to TCP and WebRTC)");
    eprintln!("  --public-addr <addr>    Explicit public address (implies --advertise-tcp)");
    eprintln!("  --no-webrtc             Disable WebRTC transport");
    eprintln!("  --ws                    Enable WebSocket transport");
    eprintln!("  --ws-listen <addr>      WebSocket listen address (default: 0.0.0.0:8080; implies --ws)");
    eprintln!("  --ws-path <path>        WebSocket upgrade path (default: /tarnet; implies --ws)");
    eprintln!("  --ws-public-url <url>   Advertise WS URL in hello (e.g. wss://host/path; implies --ws)");
    eprintln!("  --no-ws                 Disable WebSocket transport");
    eprintln!("  --no-mdns               Disable mDNS LAN discovery");
    eprintln!("  --socket <path>         IPC socket path (default: <data-dir>/sock)");
    eprintln!("  --socks <addr>          Override SOCKS5 bind address");
    eprintln!("  --socks-allow-clearnet  Allow SOCKS proxy to connect to non-tarnet destinations");
    eprintln!("  --no-socks              Disable SOCKS5 proxy");
    eprintln!("  --expose-dir <path>     Override service config directory");
    eprintln!("  --no-expose             Disable service exposure");
    eprintln!("  --max-inbound-links <n> Maximum inbound links (default: 128, 0 = unlimited)");
    eprintln!("  --max-outbound-links <n> Maximum outbound links (default: 48, 0 = unlimited)");
    eprintln!("  --upload-limit <rate>   Upload bandwidth limit (e.g. 10Mbps, 1MB/s; 0 = unlimited)");
    eprintln!("  --download-limit <rate> Download bandwidth limit (e.g. 50Mbps, 5MB/s; 0 = unlimited)");
}

fn load_or_generate_identity(path: &PathBuf) -> Keypair {
    ensure_parent_dir(path);
    if path.exists() {
        let bytes = std::fs::read(path).expect("Failed to read identity file");
        if bytes.is_empty() {
            eprintln!("Identity file is empty");
            std::process::exit(1);
        }
        // Try full format first (PQ keys), fall back to legacy 32-byte Ed25519 seed.
        //
        // The full format starts with an algo byte (0x01, 0x02, ...).
        // A bare 32-byte file is a v1 Ed25519 seed — but only if the first byte
        // isn't a known algo byte (otherwise it's a truncated v2 file).
        let kp = match Keypair::from_full_bytes(&bytes) {
            Ok(k) => k,
            Err(e) => {
                if bytes.len() == 32
                    && tarnet_api::types::SigningAlgo::from_u8(bytes[0]).is_err()
                {
                    // Legacy v1: bare 32-byte Ed25519 seed (first byte is random,
                    // not a valid algo discriminant)
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    #[allow(deprecated)]
                    let k = Keypair::from_bytes(key);
                    std::fs::write(path, k.to_full_bytes())
                        .expect("Failed to upgrade identity file");
                    log::info!("Upgraded v1 identity file to v2 format");
                    k
                } else {
                    eprintln!("Failed to load identity: {}", e);
                    eprintln!("If this is a v1 identity file, it may be corrupted.");
                    eprintln!("If the signing algorithm is unsupported, upgrade tarnetd.");
                    std::process::exit(1);
                }
            }
        };
        log::info!("Loaded identity from {}", path.display());
        kp
    } else {
        let kp = Keypair::generate();
        std::fs::write(path, kp.to_full_bytes()).expect("Failed to write identity file");
        tighten_permissions(path);
        log::info!("Generated new identity at {}", path.display());
        kp
    }
}

fn ensure_parent_dir(path: &PathBuf) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).expect("Failed to create parent directory");
        }
    }
}

#[cfg(unix)]
fn tighten_permissions(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let perms = std::fs::Permissions::from_mode(0o600);
    if let Err(e) = std::fs::set_permissions(path, perms) {
        log::warn!(
            "Failed to set secure permissions on {}: {}",
            path.display(),
            e
        );
    }
}

#[cfg(not(unix))]
fn tighten_permissions(_path: &PathBuf) {}
