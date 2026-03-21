use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Daemon configuration loaded from `tarnetd.toml`.
/// All fields use `#[serde(default)]` so the file can be sparse —
/// only settings the user wants to override need to be present.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub transport: TransportConfig,
    pub bootstrap: BootstrapConfig,
    pub socks: SocksConfig,
    pub core: CoreConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            transport: TransportConfig::default(),
            bootstrap: BootstrapConfig::default(),
            socks: SocksConfig::default(),
            core: CoreConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    pub tcp: TcpConfig,
    pub webrtc: WebRtcConfig,
    pub ws: WsConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tcp: TcpConfig::default(),
            webrtc: WebRtcConfig::default(),
            ws: WsConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct TcpConfig {
    pub listen: Vec<String>,
    pub stun: Vec<String>,
    pub public_addr: Option<String>,
    /// Advertise TCP addresses in hello records. When false (default),
    /// the node is reachable only via overlay routing / WebRTC / introducers.
    pub advertise: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:7946".into()],
            stun: vec!["stun:stun.l.google.com:19302".into()],
            public_addr: None,
            advertise: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct WebRtcConfig {
    pub enabled: bool,
    pub stun: Vec<String>,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stun: vec!["stun:stun.l.google.com:19302".into()],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct WsConfig {
    pub enabled: bool,
    pub listen: String,
    pub path: String,
    /// Public URL to advertise in hello records (e.g. "wss://relay.example.com/tarnet").
    /// Without this, WS accepts incoming connections but is not advertised.
    pub public_url: Option<String>,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:8080".into(),
            path: "/tarnet".into(),
            public_url: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct BootstrapConfig {
    pub peers: Vec<String>,
    /// Discovery URIs (e.g. `mainline:<hex>`, future: `nostr:<id>`, `opendht:<key>`)
    pub discovery: Vec<String>,
    pub mainline: bool,
    pub mdns: bool,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            discovery: Vec::new(),
            mainline: false,
            mdns: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct SocksConfig {
    pub enabled: bool,
    pub bind: Vec<SocketAddr>,
    pub allow_clearnet: bool,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: vec![
                "127.0.0.1:1080".parse().unwrap(),
                "[::1]:1080".parse().unwrap(),
            ],
            allow_clearnet: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    /// Maximum number of inbound (responder) links. 0 = unlimited.
    pub max_inbound: usize,
    /// Maximum number of outbound (initiator) links. 0 = unlimited.
    pub max_outbound: usize,
    /// Upload bandwidth limit (e.g. "10Mbps", "1MB/s"). Empty or "0" = unlimited.
    pub upload_limit: String,
    /// Download bandwidth limit (e.g. "50Mbps", "5MB/s"). Empty or "0" = unlimited.
    pub download_limit: String,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            max_inbound: 128,
            max_outbound: 48,
            upload_limit: String::new(),
            download_limit: String::new(),
        }
    }
}

/// Load config from a TOML file.
/// Returns `Config::default()` if the file does not exist.
/// Returns an error if the file exists but cannot be parsed.
pub fn load_config(path: &Path) -> Result<Config, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => toml::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(format!("Failed to read {}: {}", path.display(), e)),
    }
}

/// CLI flag overrides. `None` means "not specified, use config/default".
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub listen: Option<Vec<String>>,
    pub bootstrap: Option<Vec<String>>,
    pub discovery: Option<Vec<String>>,
    pub mainline: Option<bool>,
    pub no_webrtc: bool,
    pub ws_enabled: Option<bool>,
    pub ws_listen: Option<String>,
    pub ws_path: Option<String>,
    pub ws_public_url: Option<String>,
    pub stun: Option<Vec<String>>,
    pub public_addr: Option<String>,
    pub advertise_tcp: bool,
    pub no_mdns: bool,
    pub socks_bind: Option<Vec<SocketAddr>>,
    pub socks_allow_clearnet: Option<bool>,
    pub no_socks: bool,
    pub expose_dir: Option<PathBuf>,
    pub no_expose: bool,
    pub socket: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub state: Option<PathBuf>,
    pub max_inbound: Option<usize>,
    pub max_outbound: Option<usize>,
    pub upload_limit: Option<String>,
    pub download_limit: Option<String>,
}

/// Fully resolved configuration — no Option fields.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ResolvedConfig {
    pub listen_addrs: Vec<String>,
    pub bootstrap: Vec<String>,
    pub discovery: Vec<String>,
    pub mainline: bool,
    pub webrtc_enabled: bool,
    pub webrtc_stun: Vec<String>,
    pub tcp_stun: Vec<String>,
    pub tcp_public_addr: Option<String>,
    pub tcp_advertise: bool,
    pub ws_enabled: bool,
    pub ws_listen: String,
    pub ws_path: String,
    pub ws_public_url: Option<String>,
    pub mdns: bool,
    pub socks_enabled: bool,
    pub socks_bind: Vec<SocketAddr>,
    pub socks_allow_clearnet: bool,
    pub expose_enabled: bool,
    pub expose_dir: PathBuf,
    pub max_inbound: usize,
    pub max_outbound: usize,
    /// Upload bandwidth limit in bytes/sec. 0 = unlimited.
    pub upload_limit: u64,
    /// Download bandwidth limit in bytes/sec. 0 = unlimited.
    pub download_limit: u64,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub identity_path: PathBuf,
    pub state_path: PathBuf,
    pub socket_path: PathBuf,
}

const IDENTITY_FILENAME: &str = "identity.key";
const STATE_FILENAME: &str = "state.sqlite3";

/// Merge defaults, config file, and CLI overrides into a final resolved config.
pub fn resolve(
    data_dir: &Path,
    config_dir: &Path,
    config: Config,
    cli: CliOverrides,
) -> ResolvedConfig {
    let expose_dir = cli
        .expose_dir
        .unwrap_or_else(|| tarnet_api::ipc::services_dir_for(config_dir));

    // If --stun was given, override both tcp and webrtc stun lists
    let tcp_stun = cli
        .stun
        .clone()
        .unwrap_or(config.transport.tcp.stun);
    let webrtc_stun = cli
        .stun
        .unwrap_or(config.transport.webrtc.stun);

    let tcp_advertise = cli.advertise_tcp
        || cli.public_addr.is_some()
        || config.transport.tcp.public_addr.is_some()
        || config.transport.tcp.advertise;
    let tcp_public_addr = cli.public_addr.or(config.transport.tcp.public_addr);

    let ws_enabled = cli.ws_enabled.unwrap_or(config.transport.ws.enabled);
    let ws_listen = cli.ws_listen.unwrap_or(config.transport.ws.listen);
    let ws_path = cli.ws_path.unwrap_or(config.transport.ws.path);
    let ws_public_url = cli.ws_public_url.or(config.transport.ws.public_url);

    let max_inbound = cli.max_inbound.unwrap_or(config.core.max_inbound);
    let max_outbound = cli.max_outbound.unwrap_or(config.core.max_outbound);

    let upload_limit = tarnet::bandwidth::parse_bandwidth(
        cli.upload_limit.as_deref().unwrap_or(&config.core.upload_limit),
    )
    .unwrap_or_else(|e| {
        eprintln!("Invalid upload_limit: {}", e);
        std::process::exit(1);
    });
    let download_limit = tarnet::bandwidth::parse_bandwidth(
        cli.download_limit.as_deref().unwrap_or(&config.core.download_limit),
    )
    .unwrap_or_else(|e| {
        eprintln!("Invalid download_limit: {}", e);
        std::process::exit(1);
    });

    ResolvedConfig {
        listen_addrs: cli.listen.unwrap_or(config.transport.tcp.listen),
        bootstrap: cli.bootstrap.unwrap_or(config.bootstrap.peers),
        discovery: cli.discovery.unwrap_or(config.bootstrap.discovery),
        mainline: cli.mainline.unwrap_or(config.bootstrap.mainline),
        webrtc_enabled: !cli.no_webrtc && config.transport.webrtc.enabled,
        webrtc_stun,
        tcp_stun,
        tcp_advertise,
        tcp_public_addr,
        ws_enabled,
        ws_listen,
        ws_path,
        ws_public_url,
        mdns: !cli.no_mdns && config.bootstrap.mdns,
        socks_enabled: !cli.no_socks && config.socks.enabled,
        socks_bind: cli.socks_bind.unwrap_or(config.socks.bind),
        socks_allow_clearnet: cli
            .socks_allow_clearnet
            .unwrap_or(config.socks.allow_clearnet),
        expose_enabled: !cli.no_expose,
        expose_dir,
        max_inbound,
        max_outbound,
        upload_limit,
        download_limit,
        config_dir: config_dir.to_path_buf(),
        data_dir: data_dir.to_path_buf(),
        identity_path: cli
            .identity
            .unwrap_or_else(|| data_dir.join(IDENTITY_FILENAME)),
        state_path: cli.state.unwrap_or_else(|| data_dir.join(STATE_FILENAME)),
        socket_path: cli
            .socket
            .unwrap_or_else(|| tarnet_api::ipc::socket_path_for(data_dir)),
    }
}

/// Write the embedded defaults reference file to the config directory.
pub fn write_defaults_file(config_dir: &Path) {
    const DEFAULTS: &str = include_str!("tarnetd.defaults.toml");
    let path = tarnet_api::ipc::defaults_path_for(config_dir);
    if let Err(e) = std::fs::write(&path, DEFAULTS) {
        log::warn!(
            "Failed to write defaults reference to {}: {}",
            path.display(),
            e
        );
    }
}
