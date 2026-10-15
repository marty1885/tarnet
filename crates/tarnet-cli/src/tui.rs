//! Small terminal UI for inspecting the local daemon and its
//! service configuration. The daemon remains the source of truth for TNS.

use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use tarnet_api::service::{ServiceApi, TnsRecord, TnsResolution};
use tarnet_api::types::{ContentHandle, LinkStatus, NodeStatus, PeerId, ServiceId};
use tarnet_client::IpcServiceApi;
use tarnet_expose::expose::ServiceConfig;

mod layout;

use crate::{connect_daemon, Cli};

// Tab indices, in display order.
const NODE: usize = 0;
const ROUTING: usize = 1;
const SERVICES: usize = 2;
const TNS: usize = 3;
const LOOKUP: usize = 4;
const DHT: usize = 5;
const TAB_COUNT: usize = 6;

/// How often the node status (peers, routing table) is re-polled.
const STATUS_REFRESH: Duration = Duration::from_secs(2);
/// How long a DHT playground GET waits for the network.
const DHT_GET_TIMEOUT_SECS: u32 = 15;
const DHT_HISTORY: usize = 50;

type Identity = (String, ServiceId);
type Label = (String, Vec<TnsRecord>, bool);

struct ServiceFile {
    name: String,
    path: PathBuf,
    config: Result<ServiceConfig, String>,
}

struct App {
    client: Arc<IpcServiceApi>,
    services_dir: PathBuf,
    tab: usize,
    selected: usize,
    detail_scroll: u16,
    identity: usize,
    identities: Vec<Identity>,
    labels: Vec<Label>,
    services: Vec<ServiceFile>,
    status: Option<NodeStatus>,
    lookup: Option<(String, String)>,
    message: String,
    input: Option<Input>,
    last_refresh: Instant,
    dht_ops: Vec<DhtOp>,
    pending: Option<Pending>,
}

/// One entry in the DHT playground history (newest first).
struct DhtOp {
    kind: &'static str,
    /// Hex content handle; empty when a PUT failed before producing one.
    handle: String,
    data: Option<Vec<u8>>,
    ok: bool,
    note: String,
}

/// A slow daemon call, deferred so the "working" state is drawn first.
enum Pending {
    DhtPut(Vec<u8>),
    DhtGet([u8; 64]),
}

enum Input {
    Resolve(String),
    SetName(String),
    SetType {
        name: String,
        value: String,
    },
    SetValue {
        name: String,
        kind: String,
        value: String,
    },
    SetPublic {
        name: String,
        kind: String,
        value: String,
        answer: String,
    },
    Remove(String),
    DhtPut(String),
    DhtGet(String),
}

impl Input {
    fn value_mut(&mut self) -> &mut String {
        match self {
            Self::Resolve(v)
            | Self::SetName(v)
            | Self::Remove(v)
            | Self::DhtPut(v)
            | Self::DhtGet(v) => v,
            Self::SetType { value, .. } | Self::SetValue { value, .. } => value,
            Self::SetPublic { answer, .. } => answer,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Resolve(_) => "Resolve name",
            Self::SetName(_) => "Record label (@, ssh, alice)",
            Self::SetType { .. } => "Type (identity, zone, vhost, alias, text)",
            Self::SetValue { .. } => "Value (ServiceId or text)",
            Self::SetPublic { .. } => "Publish to DHT? (y/N)",
            Self::Remove(_) => "Remove selected record? (y/N)",
            Self::DhtPut(_) => "Put content (text, or @path to a file)",
            Self::DhtGet(_) => "Get content handle (128 hex chars)",
        }
    }
}

pub(super) async fn run(cli: &Cli, services_dir: Option<&Path>) {
    let client = connect_daemon(cli).await;
    let mut app = App {
        client,
        services_dir: services_dir.map(Path::to_path_buf).unwrap_or_else(|| {
            tarnet_api::ipc::services_dir_for(&tarnet_api::ipc::default_config_dir())
        }),
        tab: 0,
        selected: 0,
        detail_scroll: 0,
        identity: 0,
        identities: Vec::new(),
        labels: Vec::new(),
        services: Vec::new(),
        status: None,
        lookup: None,
        message: String::new(),
        input: None,
        last_refresh: Instant::now(),
        dht_ops: Vec::new(),
        pending: None,
    };
    app.refresh().await;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!("tarnet tui requires a terminal");
        return;
    }
    let mut terminal = match ratatui::try_init() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };
    let result = app.event_loop(&mut terminal).await;
    ratatui::restore();
    if let Err(e) = result {
        eprintln!("TUI error: {}", e);
    }
}

impl App {
    fn identity_name(&self) -> &str {
        self.identities
            .get(self.identity)
            .map(|(n, _)| n.as_str())
            .unwrap_or("default")
    }

    async fn refresh(&mut self) {
        let old_name = self.identity_name().to_string();
        match self.client.list_identities().await {
            Ok(ids) => {
                self.identities = ids.into_iter().map(|(name, sid, ..)| (name, sid)).collect();
                self.identity = self
                    .identities
                    .iter()
                    .position(|(name, _)| *name == old_name)
                    .unwrap_or(0);
            }
            Err(e) => self.message = format!("Identity lookup failed: {e}"),
        }
        self.refresh_labels().await;
        self.refresh_status().await;
        self.services = read_services(&self.services_dir);
        if !self.services_dir.is_dir() {
            self.message = format!("Service directory not found: {} (use --services-dir for a custom daemon directory)", self.services_dir.display());
        }
        self.selected = self.selected.min(self.item_count().saturating_sub(1));
    }

    /// Re-poll the daemon status. On the routing tab the selection follows
    /// its destination, so a re-sorted table doesn't move the cursor.
    async fn refresh_status(&mut self) {
        let keep = (self.tab == ROUTING)
            .then(|| self.sorted_routes().get(self.selected).map(|r| r.0))
            .flatten();
        self.status = Some(self.client.node_status().await);
        self.last_refresh = Instant::now();
        if let Some(dest) = keep {
            if let Some(i) = self.sorted_routes().iter().position(|r| r.0 == dest) {
                self.selected = i;
            }
        }
        self.selected = self.selected.min(self.item_count().saturating_sub(1));
    }

    /// Routes ordered by cost, then destination, so the table is stable
    /// between polls.
    fn sorted_routes(&self) -> Vec<&(PeerId, PeerId, u32)> {
        let mut routes: Vec<_> = self
            .status
            .as_ref()
            .map(|s| s.routes.iter().collect())
            .unwrap_or_default();
        routes.sort_by_key(|(dest, _, cost)| (*cost, *dest));
        routes
    }

    /// The link a packet to `next_hop` leaves on: its active link, or any.
    fn link_to(&self, next_hop: &PeerId) -> Option<&LinkStatus> {
        let peer = self
            .status
            .as_ref()?
            .peers
            .iter()
            .find(|p| p.peer_id == *next_hop)?;
        peer.links
            .iter()
            .find(|l| l.state == "active")
            .or_else(|| peer.links.first())
    }

    fn set_tab(&mut self, tab: usize) {
        self.tab = tab % TAB_COUNT;
        self.selected = 0;
        self.detail_scroll = 0;
    }

    async fn refresh_labels(&mut self) {
        match self
            .client
            .tns_list_labels(Some(self.identity_name()))
            .await
        {
            Ok(labels) => self.labels = labels,
            Err(e) => {
                self.labels.clear();
                self.message = format!("TNS labels: {e}");
            }
        }
    }

    fn item_count(&self) -> usize {
        match self.tab {
            NODE => self.identities.len(),
            ROUTING => self.status.as_ref().map_or(0, |s| s.routes.len()),
            SERVICES => self.services.len(),
            TNS => self.labels.len(),
            DHT => self.dht_ops.len(),
            _ => 0,
        }
    }

    async fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        loop {
            if self.last_refresh.elapsed() >= STATUS_REFRESH {
                self.refresh_status().await;
            }
            self.draw(terminal)?;
            if let Some(pending) = self.pending.take() {
                self.run_pending(pending).await;
                continue;
            }
            // Wake periodically so the node and routing views stay live.
            if !event::poll(Duration::from_millis(500))? {
                continue;
            }
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat {
                continue;
            }
            if self.input.is_some() {
                match key.code {
                    KeyCode::Esc => self.input = None,
                    KeyCode::Backspace => {
                        self.input.as_mut().unwrap().value_mut().pop();
                    }
                    KeyCode::Enter => self.submit().await,
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.input.as_mut().unwrap().value_mut().push(c)
                    }
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                KeyCode::Char(c @ '1'..='6') => self.set_tab((c as u8 - b'1') as usize),
                KeyCode::Tab | KeyCode::Right => self.set_tab(self.tab + 1),
                KeyCode::BackTab | KeyCode::Left => self.set_tab(self.tab + TAB_COUNT - 1),
                KeyCode::Char('j') | KeyCode::Down => {
                    self.selected = (self.selected + 1).min(self.item_count().saturating_sub(1));
                    self.detail_scroll = 0;
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.selected = self.selected.saturating_sub(1);
                    self.detail_scroll = 0;
                }
                KeyCode::PageDown => self.detail_scroll = self.detail_scroll.saturating_add(5),
                KeyCode::PageUp => self.detail_scroll = self.detail_scroll.saturating_sub(5),
                KeyCode::Char('r') => {
                    self.message = "Refreshed".into();
                    self.refresh().await;
                }
                KeyCode::Char('i') => {
                    if !self.identities.is_empty() {
                        self.identity = (self.identity + 1) % self.identities.len();
                        self.selected = 0;
                        self.detail_scroll = 0;
                        self.refresh_labels().await;
                    }
                }
                KeyCode::Char('/') => {
                    self.tab = LOOKUP;
                    self.detail_scroll = 0;
                    self.input = Some(Input::Resolve(String::new()));
                }
                KeyCode::Char('a') if self.tab == TNS => {
                    self.input = Some(Input::SetName(String::new()))
                }
                KeyCode::Char('d') if self.tab == TNS && self.selected < self.labels.len() => {
                    self.input = Some(Input::Remove(String::new()))
                }
                KeyCode::Char('e')
                    if self.tab == SERVICES && self.selected < self.services.len() =>
                {
                    self.edit_service(terminal).await?
                }
                KeyCode::Char('R') => match self.client.reload().await {
                    Ok(()) => {
                        self.message = "Daemon reload requested; use <r> to inspect again".into()
                    }
                    Err(e) => self.message = format!("Reload failed: {e}"),
                },
                KeyCode::Char('p') if self.tab == DHT => {
                    self.input = Some(Input::DhtPut(String::new()))
                }
                KeyCode::Char('g') if self.tab == DHT => {
                    self.input = Some(Input::DhtGet(String::new()))
                }
                KeyCode::Enter if self.tab == DHT => {
                    // Re-fetch the selected entry's handle from the network.
                    if let Some(h) = self
                        .dht_ops
                        .get(self.selected)
                        .and_then(|op| parse_handle(&op.handle).ok())
                    {
                        self.start_get(h);
                    }
                }
                KeyCode::Enter if self.tab == SERVICES => self.inspect_service().await,
                KeyCode::Enter if self.tab == TNS => self.inspect_label().await,
                _ => {}
            }
        }
        Ok(())
    }

    async fn submit(&mut self) {
        let input = self.input.take().unwrap();
        match input {
            Input::Resolve(name) if !name.trim().is_empty() => self.resolve(&name).await,
            Input::SetName(name) if !name.trim().is_empty() => {
                self.input = Some(Input::SetType {
                    name,
                    value: String::new(),
                })
            }
            Input::SetType { name, value } if !value.trim().is_empty() => {
                self.input = Some(Input::SetValue {
                    name,
                    kind: value,
                    value: String::new(),
                })
            }
            Input::SetValue { name, kind, value } if !value.trim().is_empty() => {
                self.input = Some(Input::SetPublic {
                    name,
                    kind,
                    value,
                    answer: String::new(),
                })
            }
            Input::SetPublic {
                name,
                kind,
                value,
                answer,
            } => {
                let record = match parse_record(&kind, &value) {
                    Ok(r) => r,
                    Err(e) => {
                        self.message = e;
                        return;
                    }
                };
                let public = answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes");
                match self
                    .client
                    .tns_set_label(Some(self.identity_name()), &name, vec![record], public)
                    .await
                {
                    Ok(()) => {
                        self.message = format!(
                            "Set {name} in {} ({})",
                            self.identity_name(),
                            if public { "public" } else { "private" }
                        );
                        self.refresh_labels().await;
                    }
                    Err(e) => self.message = format!("Set failed: {e}"),
                }
            }
            Input::DhtPut(text) if !text.is_empty() => {
                let data = match text.strip_prefix('@') {
                    Some(path) => match fs::read(path.trim()) {
                        Ok(d) => d,
                        Err(e) => {
                            self.message = format!("Cannot read {}: {e} (failed)", path.trim());
                            return;
                        }
                    },
                    None => text.into_bytes(),
                };
                self.message = format!("Storing {} bytes in the DHT…", data.len());
                self.pending = Some(Pending::DhtPut(data));
            }
            Input::DhtGet(handle) if !handle.trim().is_empty() => match parse_handle(&handle) {
                Ok(h) => self.start_get(h),
                Err(e) => self.message = format!("Invalid handle: {e}"),
            },
            Input::Remove(answer)
                if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") =>
            {
                if let Some((name, _, _)) = self.labels.get(self.selected) {
                    let name = name.clone();
                    match self
                        .client
                        .tns_remove_label(Some(self.identity_name()), &name)
                        .await
                    {
                        Ok(()) => {
                            self.message = format!("Removed {name}");
                            self.refresh_labels().await;
                            self.selected = self.selected.min(self.labels.len().saturating_sub(1));
                        }
                        Err(e) => self.message = format!("Remove failed: {e}"),
                    }
                }
            }
            _ => {}
        }
    }

    fn start_get(&mut self, handle: [u8; 64]) {
        self.message = format!("Fetching from the DHT (up to {DHT_GET_TIMEOUT_SECS}s)…");
        self.pending = Some(Pending::DhtGet(handle));
    }

    async fn run_pending(&mut self, pending: Pending) {
        let op = match pending {
            Pending::DhtPut(data) => match self.client.dht_put(&data).await {
                Ok(handle) => DhtOp {
                    kind: "PUT",
                    handle: hex(handle.as_bytes()),
                    note: format!("stored {} bytes", data.len()),
                    data: Some(data),
                    ok: true,
                },
                Err(e) => DhtOp {
                    kind: "PUT",
                    handle: String::new(),
                    data: None,
                    ok: false,
                    note: format!("put failed: {e}"),
                },
            },
            Pending::DhtGet(handle) => {
                match self
                    .client
                    .dht_get(&ContentHandle(handle), DHT_GET_TIMEOUT_SECS)
                    .await
                {
                    Some(data) => DhtOp {
                        kind: "GET",
                        handle: hex(&handle),
                        note: format!("retrieved {} bytes", data.len()),
                        data: Some(data),
                        ok: true,
                    },
                    None => DhtOp {
                        kind: "GET",
                        handle: hex(&handle),
                        data: None,
                        ok: false,
                        note: format!("not found within {DHT_GET_TIMEOUT_SECS}s"),
                    },
                }
            }
        };
        self.message = format!("{} {}", op.kind, op.note);
        if !op.ok {
            self.message.push_str(" (failed)");
        }
        self.dht_ops.insert(0, op);
        self.dht_ops.truncate(DHT_HISTORY);
        self.selected = 0;
        self.detail_scroll = 0;
        self.tab = DHT;
    }

    async fn resolve(&mut self, name: &str) {
        // The explicit-zone daemon API reads published records. A private label
        // in a nondefault local zone is visible through the label API instead.
        if self.identity_name() != "default" && !name.contains('.') {
            if let Some((_, records, public)) =
                self.labels.iter().find(|(label, _, _)| label == name)
            {
                self.lookup = Some((
                    name.to_string(),
                    format!(
                        "Local {} label in {}:\n{}",
                        if *public { "public" } else { "private" },
                        self.identity_name(),
                        records
                            .iter()
                            .map(short_record)
                            .collect::<Vec<_>>()
                            .join("\n")
                    ),
                ));
                self.tab = LOOKUP;
                self.detail_scroll = 0;
                return;
            }
        }
        let result = match self.identities.get(self.identity) {
            Some((zone, _)) if zone == "default" => self.client.tns_resolve_name(name).await,
            Some((_, sid)) => self.client.tns_resolve(*sid, name).await,
            None => self.client.tns_resolve_name(name).await,
        };
        let root = name.rsplit('.').next().unwrap_or(name);
        let local = self
            .labels
            .iter()
            .find(|(label, _, _)| label == root)
            .map(|(_, records, public)| {
                format!(
                    "\nLocal root label '{root}' ({}): {}{}",
                    if *public { "public" } else { "private" },
                    records
                        .iter()
                        .map(short_record)
                        .collect::<Vec<_>>()
                        .join(", "),
                    if self.identity_name() != "default" && !*public {
                        "\nNote: explicit-zone resolution cannot follow private local labels."
                    } else {
                        ""
                    }
                )
            })
            .unwrap_or_default();
        self.lookup = Some((
            name.to_string(),
            match result {
                Ok(r) => format!("{}{}", describe_resolution(&r), local),
                Err(e) => format!("Lookup failed: {e}"),
            },
        ));
        self.tab = LOOKUP;
        self.detail_scroll = 0;
    }

    async fn inspect_label(&mut self) {
        if let Some((name, _, _)) = self.labels.get(self.selected) {
            let name = name.clone();
            self.resolve(&name).await;
        }
    }

    async fn inspect_service(&mut self) {
        let Some(file) = self.services.get(self.selected) else {
            return;
        };
        let Ok(cfg) = &file.config else {
            self.message = "Fix the TOML error before resolving".into();
            return;
        };
        if !cfg.publish {
            self.message = "This service has publish = false; no TNS record is expected".into();
            return;
        }
        let name = cfg.subdomain.clone().unwrap_or_else(|| "@".into());
        let zone_name = cfg.identity.as_deref().unwrap_or("default");
        let Some((_, zone)) = self.identities.iter().find(|(n, _)| n == zone_name) else {
            self.message = format!("Identity '{zone_name}' is absent on this daemon");
            return;
        };
        let expected_sid = match cfg.target.as_deref() {
            Some(target) => match ServiceId::parse(target) {
                Ok(sid) => sid,
                Err(e) => {
                    self.message = format!("Invalid target in {}: {e}", file.name);
                    return;
                }
            },
            None => *zone,
        };
        let expected_kind = if cfg.subdomain.is_none() || cfg.record.as_deref() == Some("identity")
        {
            "IDENTITY"
        } else {
            "VHOST"
        };
        let result = if zone_name == "default" {
            self.client.tns_resolve_name(&name).await
        } else {
            self.client.tns_resolve(*zone, &name).await
        };
        let diagnosis = match result {
            Ok(ref r) => compare_resolution(r, expected_kind, expected_sid),
            Err(e) => format!("Lookup failed: {e}"),
        };
        self.lookup = Some((
            format!("{}.{} (service {})", name, zone_name, file.name),
            diagnosis,
        ));
        self.tab = LOOKUP;
        self.detail_scroll = 0;
    }

    async fn edit_service(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        let path = self.services[self.selected].path.clone();
        ratatui::restore();
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
        let result = Command::new(&editor).arg(&path).status();
        *terminal = ratatui::try_init()?;
        self.message = match result {
            Ok(s) if s.success() => {
                format!("Saved {}. Use <R> to reload the daemon", path.display())
            }
            Ok(s) => format!("Editor exited with {s}"),
            Err(e) => format!("Could not open editor: {e}"),
        };
        self.services = read_services(&self.services_dir);
        Ok(())
    }

    fn draw(&self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        terminal.draw(|frame| layout::render(frame, self))?;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a 64-byte content handle from 128 hex characters.
fn parse_handle(text: &str) -> Result<[u8; 64], String> {
    let text = text.trim();
    if text.len() != 128 || !text.is_ascii() {
        return Err(format!("expected 128 hex chars, got {}", text.len()));
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .map_err(|_| "not valid hex".to_string())?;
    }
    Ok(out)
}

fn read_services(dir: &Path) -> Vec<ServiceFile> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let config = fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|s| toml::from_str(&s).map_err(|e| e.to_string()));
            ServiceFile { name, path, config }
        })
        .collect()
}

fn short_record(record: &TnsRecord) -> String {
    match record {
        TnsRecord::Identity(s) => format!("IDENTITY {s}"),
        TnsRecord::Zone(s) => format!("ZONE {s}"),
        TnsRecord::VHost(s) => format!("VHOST {s}"),
        TnsRecord::Alias(a) => format!("ALIAS {a}"),
        TnsRecord::Text(t) => format!("TEXT {t}"),
        other => format!("{other:?}"),
    }
}

fn describe_resolution(result: &TnsResolution) -> String {
    match result {
        TnsResolution::Records(records) if records.is_empty() => "No terminal records returned".into(),
        TnsResolution::Records(records) => records.iter().map(short_record).collect::<Vec<_>>().join("\n"),
        TnsResolution::VHost { serving, canonical_label } => format!("VHOST {serving}\nCanonical label: {canonical_label}"),
        TnsResolution::NotFound => "Not found in this zone. Check the zone, delegation, publication, and daemon connectivity.".into(),
        TnsResolution::Error(e) => format!("Resolution error: {e}"),
    }
}

fn compare_resolution(result: &TnsResolution, kind: &str, sid: ServiceId) -> String {
    let actual = describe_resolution(result);
    let matches = match result {
        TnsResolution::VHost { serving, .. } => kind == "VHOST" && *serving == sid,
        TnsResolution::Records(records) => records.iter().any(|r| match r {
            TnsRecord::Identity(s) => kind == "IDENTITY" && *s == sid,
            TnsRecord::VHost(s) => kind == "VHOST" && *s == sid,
            _ => false,
        }),
        _ => false,
    };
    format!(
        "Expected: {kind} {sid}\nObserved: {actual}\n{}",
        if matches {
            "MATCH: TNS points to the configured service identity."
        } else {
            "MISMATCH: inspect target, identity, publication, and reload state."
        }
    )
}

fn parse_record(kind: &str, value: &str) -> Result<TnsRecord, String> {
    match kind.to_ascii_lowercase().as_str() {
        "identity" => ServiceId::parse(value)
            .map(TnsRecord::Identity)
            .map_err(|e| e.to_string()),
        "zone" => ServiceId::parse(value)
            .map(TnsRecord::Zone)
            .map_err(|e| e.to_string()),
        "vhost" => ServiceId::parse(value)
            .map(TnsRecord::VHost)
            .map_err(|e| e.to_string()),
        "alias" => Ok(TnsRecord::Alias(value.into())),
        "text" => Ok(TnsRecord::Text(value.into())),
        _ => Err("Type must be identity, zone, vhost, alias, or text".into()),
    }
}

fn input_text(input: &Input) -> &str {
    match input {
        Input::Resolve(s)
        | Input::SetName(s)
        | Input::Remove(s)
        | Input::DhtPut(s)
        | Input::DhtGet(s) => s,
        Input::SetType { value, .. } | Input::SetValue { value, .. } => value,
        Input::SetPublic { answer, .. } => answer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_parsing_requires_128_hex_chars() {
        assert!(parse_handle(&"ab".repeat(64)).is_ok());
        assert!(parse_handle(&format!("  {}\n", "01".repeat(64))).is_ok());
        assert!(parse_handle("abcd").is_err());
        assert!(parse_handle(&"zz".repeat(64)).is_err());
        assert!(parse_handle(&"é".repeat(64)).is_err());
    }

    #[test]
    fn deployment_diagnostic_distinguishes_target_and_record_type() {
        let wanted = ServiceId([1; 32]);
        let other = ServiceId([2; 32]);
        let answer = TnsResolution::VHost {
            serving: wanted,
            canonical_label: "ssh".into(),
        };
        assert!(compare_resolution(&answer, "VHOST", wanted).contains("MATCH:"));
        assert!(compare_resolution(&answer, "VHOST", other).contains("MISMATCH:"));
        assert!(compare_resolution(&answer, "IDENTITY", wanted).contains("MISMATCH:"));
        assert!(
            compare_resolution(&TnsResolution::NotFound, "VHOST", wanted).contains("MISMATCH:")
        );
    }
}
