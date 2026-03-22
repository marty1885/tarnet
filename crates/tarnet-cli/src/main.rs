use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tarnet_api::service::{DataStream, ServiceApi, TnsRecord, TnsResolution};
use tarnet_api::types::{PeerId, ServiceId};
use tarnet_client::IpcServiceApi;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser)]
#[command(name = "tarnet", about = "Command-line interface for the tarnet overlay network", arg_required_else_help = true)]
struct Cli {
    /// IPC socket path (default: $XDG_DATA_HOME/tarnet/sock)
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    /// Data directory
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// DHT operations (put, get, hello)
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Dht {
        #[command(subcommand)]
        command: DhtCommand,
    },
    /// Tarnet Name System (publish, resolve, label)
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Tns {
        #[command(subcommand)]
        command: TnsCommand,
    },
    /// Manage named identities
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Connect to a service (netcat-like I/O)
    #[command(arg_required_else_help = true)]
    Connect {
        /// Target: ServiceId (base32), PeerId (hex), or TNS name
        target: String,
        /// Port to connect to
        #[arg(long, default_value_t = 80)]
        port: u16,
    },
    /// Listen for incoming connections (netcat-like I/O)
    Listen {
        /// Identity to listen on (label or ServiceId; defaults to default identity)
        identity: Option<String>,
        /// Port to listen on
        #[arg(long, default_value_t = 80)]
        port: u16,
    },
    /// Run a command with traffic routed through tarnet
    #[command(arg_required_else_help = true)]
    Tarify {
        /// Identity for TNS resolution and circuit building
        #[arg(long)]
        identity: Option<String>,
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Show connected peers and routes
    Status,
    /// Reload daemon configuration
    Reload,
}

#[derive(Subcommand)]
enum DhtCommand {
    /// Store a value in the DHT (content-addressed, anonymous)
    #[command(arg_required_else_help = true)]
    Put {
        /// Value to store
        value: String,
    },
    /// Retrieve a value from the DHT by inner hash
    #[command(arg_required_else_help = true)]
    Get {
        /// Inner hash (128 hex chars)
        hash: String,
    },
    /// Store signed content in the DHT (publisher-authenticated)
    #[command(arg_required_else_help = true)]
    PutSigned {
        /// Value to store
        value: String,
        /// Time-to-live in seconds
        #[arg(long, default_value_t = 3600)]
        ttl: u32,
    },
    /// Retrieve signed content from the DHT
    #[command(arg_required_else_help = true)]
    GetSigned {
        /// Inner hash (128 hex chars)
        hash: String,
    },
    /// Look up a peer's hello record
    #[command(arg_required_else_help = true)]
    Hello {
        /// Peer ID (64 hex chars)
        peer_id: String,
    },
}

#[derive(Subcommand)]
enum TnsCommand {
    /// Set a record in your zone
    #[command(arg_required_else_help = true)]
    Set {
        /// Record name (e.g. "@", "www", "alice")
        name: String,
        /// Record type: identity, zone, text, alias, content-ref
        #[arg(name = "type")]
        record_type: String,
        /// Record value (ServiceId, text, alias target, etc.)
        value: String,
        /// Publish to the DHT (default: private/local-only)
        #[arg(long)]
        public: bool,
    },
    /// Show records for a name
    #[command(arg_required_else_help = true)]
    Get {
        /// Record name
        name: String,
    },
    /// Remove a record
    #[command(arg_required_else_help = true)]
    Rm {
        /// Record name
        name: String,
    },
    /// List all records in your zone
    List,
    /// Resolve a name (from your zone by default)
    #[command(arg_required_else_help = true)]
    Resolve {
        /// Name to resolve (e.g. "server", "www.blog", "www.alice")
        name: String,
        /// Resolve from a specific zone (ServiceId or identity label)
        #[arg(long)]
        zone: Option<String>,
    },
    /// Export all zone records to a JSON file
    Export {
        /// Output file (defaults to stdout)
        file: Option<String>,
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Import zone records from a JSON file
    #[command(arg_required_else_help = true)]
    Import {
        /// JSON file to import
        file: String,
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Remove all records from the zone
    Clear {
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Create a new identity
    #[command(arg_required_else_help = true)]
    Create {
        /// Identity label
        label: String,
        /// Privacy level: public or hidden
        #[arg(long, default_value = "public")]
        privacy: String,
        /// Number of introduction points (for hidden identities)
        #[arg(long, default_value_t = 3)]
        intro_points: u8,
        /// Number of outbound hops
        #[arg(long, default_value_t = 1)]
        outbound_hops: u8,
        /// Key scheme: falcon_ed25519 (default, post-quantum) or ed25519
        #[arg(long, default_value = "falcon_ed25519")]
        scheme: String,
    },
    /// Update an existing identity
    #[command(arg_required_else_help = true)]
    Update {
        /// Identity label
        label: String,
        /// Privacy level: public or hidden
        #[arg(long, default_value = "public")]
        privacy: String,
        /// Number of introduction points (for hidden identities)
        #[arg(long, default_value_t = 3)]
        intro_points: u8,
        /// Number of outbound hops
        #[arg(long, default_value_t = 1)]
        outbound_hops: u8,
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Delete an identity (cannot delete the default identity)
    #[command(arg_required_else_help = true)]
    Delete {
        /// Identity label
        label: String,
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// List all identities
    List,
}

fn socket_path(cli: &Cli) -> PathBuf {
    if let Some(ref s) = cli.socket {
        s.clone()
    } else if let Some(ref d) = cli.data_dir {
        tarnet_api::ipc::socket_path_for(d)
    } else {
        tarnet_api::ipc::default_socket_path()
    }
}

async fn connect_daemon(cli: &Cli) -> Arc<IpcServiceApi> {
    let socket = socket_path(cli);
    match IpcServiceApi::connect(&socket).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to tarnetd at {}: {}", socket.display(), e);
            eprintln!("Is tarnetd running?");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Command::Dht { command } => cmd_dht(&cli, command).await,
        Command::Tns { command } => cmd_tns(&cli, command).await,
        Command::Identity { command } => cmd_identity(&cli, command).await,
        Command::Connect { target, port } => cmd_connect(&cli, target, *port).await,
        Command::Listen { identity, port } => cmd_listen(&cli, identity, *port).await,
        Command::Tarify { identity, command } => cmd_tarify(&cli, identity.as_deref(), command).await,
        Command::Status => cmd_status(&cli).await,
        Command::Reload => cmd_reload(&cli).await,
    }
}

// ── Identity commands ──

async fn cmd_identity(cli: &Cli, cmd: &IdentityCommand) {
    let client = connect_daemon(cli).await;

    match cmd {
        IdentityCommand::Create { label, privacy, intro_points, outbound_hops, scheme } => {
            let privacy = parse_privacy(privacy, *intro_points);
            let scheme = parse_scheme(scheme);
            match client.create_identity(label, privacy, *outbound_hops, scheme).await {
                Ok(sid) => {
                    println!("Created identity '{}': {}", label, sid);
                    println!("  Scheme:        {}", scheme);
                    println!("  Privacy:       {:?}", privacy);
                    println!("  Outbound hops: {}", outbound_hops);
                }
                Err(e) => {
                    eprintln!("Failed to create identity: {}", e);
                    std::process::exit(1);
                }
            }
        }
        IdentityCommand::Update { label, privacy, intro_points, outbound_hops, yes } => {
            let privacy = parse_privacy(privacy, *intro_points);

            // Fetch current state to detect downgrades.
            let identities = client.list_identities().await.unwrap_or_default();
            let current = identities.iter().find(|(l, _, _, _, _, _, _)| l == label);
            if current.is_none() {
                eprintln!("Identity '{}' not found.", label);
                std::process::exit(1);
            }
            let (_, _, old_privacy, old_hops, _, _, _) = current.unwrap();

            let downgraded = match (*old_privacy, privacy) {
                (tarnet_api::types::PrivacyLevel::Hidden { .. }, tarnet_api::types::PrivacyLevel::Public) => true,
                (
                    tarnet_api::types::PrivacyLevel::Hidden { intro_points: old_n },
                    tarnet_api::types::PrivacyLevel::Hidden { intro_points: new_n },
                ) => new_n < old_n,
                _ => false,
            };
            let hops_reduced = *outbound_hops < *old_hops;

            if (downgraded || hops_reduced) && !yes {
                eprintln!("This change reduces anonymity for identity '{}':", label);
                if downgraded {
                    eprintln!("  Privacy: {:?} -> {:?}", old_privacy, privacy);
                }
                if hops_reduced {
                    eprintln!("  Outbound hops: {} -> {}", old_hops, outbound_hops);
                }
                eprint!("Proceed? [N/y] ");
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer).unwrap_or(0);
                let answer = answer.trim().to_lowercase();
                if answer != "y" && answer != "yes" {
                    eprintln!("Aborted.");
                    std::process::exit(1);
                }
            }

            match client.update_identity(label, privacy, *outbound_hops).await {
                Ok(_) => {
                    println!("Updated identity '{}':", label);
                    println!("  Privacy:       {:?}", privacy);
                    println!("  Outbound hops: {}", outbound_hops);
                }
                Err(e) => {
                    eprintln!("Failed to update identity: {}", e);
                    std::process::exit(1);
                }
            }
        }
        IdentityCommand::Delete { label, yes } => {
            if label == "default" {
                eprintln!("Cannot delete the default identity.");
                std::process::exit(1);
            }

            if !yes {
                eprint!("Delete identity '{}'? This is irreversible. [N/y] ", label);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer).unwrap_or(0);
                let answer = answer.trim().to_lowercase();
                if answer != "y" && answer != "yes" {
                    eprintln!("Aborted.");
                    std::process::exit(1);
                }
            }

            match client.delete_identity(label).await {
                Ok(()) => println!("Deleted identity '{}'.", label),
                Err(e) => {
                    eprintln!("Failed to delete identity: {}", e);
                    std::process::exit(1);
                }
            }
        }
        IdentityCommand::List => {
            match client.list_identities().await {
                Ok(identities) => {
                    if identities.is_empty() {
                        println!("No identities.");
                    } else {
                        for (label, sid, privacy, hops, scheme, signing, kem) in &identities {
                            println!("{}", label);
                            println!("  ServiceId:     {}", sid);
                            println!("  Scheme:        {}", scheme);
                            println!("  Signing:       {}", signing);
                            println!("  KEM:           {}", kem);
                            println!("  Privacy:       {:?}", privacy);
                            println!("  Outbound hops: {}", hops);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to list identities: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

// ── DHT commands ──

async fn cmd_dht(cli: &Cli, cmd: &DhtCommand) {
    let client = connect_daemon(cli).await;

    match cmd {
        DhtCommand::Put { value } => {
            let hash = client.dht_put(value.as_bytes()).await;
            println!("{}", hex_encode(hash.as_bytes()));
        }
        DhtCommand::Get { hash } => {
            let inner_hash = parse_dht_hash(hash);
            let key = tarnet_api::types::DhtId(inner_hash);

            match client.dht_get(&key, 30).await {
                Some(data) => match String::from_utf8(data.clone()) {
                    Ok(s) => println!("{}", s),
                    Err(_) => {
                        use std::io::Write;
                        std::io::stdout().write_all(&data).unwrap();
                    }
                },
                None => {
                    eprintln!("Timeout: content not found");
                    std::process::exit(1);
                }
            }
        }
        DhtCommand::PutSigned { value, ttl } => {
            let hash = client.dht_put_signed(value.as_bytes(), *ttl).await;
            println!("{}", hex_encode(hash.as_bytes()));
        }
        DhtCommand::GetSigned { hash } => {
            let inner_hash = parse_dht_hash(hash);
            let key = tarnet_api::types::DhtId(inner_hash);

            let results = client.dht_get_signed(&key, 30).await;
            if results.is_empty() {
                eprintln!("Timeout: signed content not found");
                std::process::exit(1);
            }
            for entry in &results {
                print!("[{}] ", entry.signer);
                match String::from_utf8(entry.data.clone()) {
                    Ok(s) => println!("{}", s),
                    Err(_) => {
                        use std::io::Write;
                        std::io::stdout().write_all(&entry.data).unwrap();
                        println!();
                    }
                }
            }
        }
        DhtCommand::Hello { peer_id } => {
            let target = parse_peer_id(peer_id);

            match client.lookup_hello(&target, 30).await {
                Some(hello) => {
                    println!("Peer: {}", hello.peer_id);
                    println!("Capabilities: {}", hello.capabilities);
                    if !hello.transports.is_empty() {
                        println!("Transports: {}", hello.transports.join(", "));
                    }
                    if !hello.introducers.is_empty() {
                        println!("Introducers:");
                        for intro in &hello.introducers {
                            println!("  {}", intro);
                        }
                    }
                    if !hello.global_addresses.is_empty() {
                        println!("Global addresses:");
                        for addr in &hello.global_addresses {
                            println!("  {}", addr);
                        }
                    }
                }
                None => {
                    eprintln!("Timeout: hello record not found for {}", target);
                    std::process::exit(1);
                }
            }
        }
    }
}

// ── TNS commands ──

async fn cmd_tns(cli: &Cli, cmd: &TnsCommand) {
    let client = connect_daemon(cli).await;

    match cmd {
        TnsCommand::Set { name, record_type, value, public } => {
            let record = parse_tns_record(record_type, value);
            let records = vec![record];

            match client.tns_set_label(name, records, *public).await {
                Ok(()) => {
                    let status = if *public { "[public]" } else { "[private]" };
                    println!("{} {}", name, status);
                }
                Err(e) => {
                    eprintln!("Failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        TnsCommand::Get { name } => {
            match client.tns_get_label(name).await {
                Ok(Some((records, public))) => {
                    let status = if public { "[public]" } else { "[private]" };
                    println!("{} {}:", name, status);
                    for rec in &records {
                        print_tns_record(rec);
                    }
                }
                Ok(None) => {
                    eprintln!("{}: not found", name);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        TnsCommand::Rm { name } => {
            match client.tns_remove_label(name).await {
                Ok(()) => println!("Removed '{}'", name),
                Err(e) => {
                    eprintln!("Failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        TnsCommand::List => {
            match client.tns_list_labels().await {
                Ok(entries) => {
                    if entries.is_empty() {
                        println!("No records.");
                    } else {
                        for (name, records, public) in &entries {
                            let status = if *public { "[public]" } else { "[private]" };
                            println!("{} {}:", name, status);
                            for rec in records {
                                print_tns_record(rec);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        TnsCommand::Resolve { name, zone } => {
            let result = if let Some(z) = zone {
                // Try as ServiceId first, then as identity label
                let sid = if let Ok(sid) = tarnet_api::types::ServiceId::parse(z) {
                    sid
                } else {
                    match client.resolve_identity(z).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("Unknown zone '{}': {}", z, e);
                            std::process::exit(1);
                        }
                    }
                };
                client.tns_resolve(sid, name).await
            } else {
                client.tns_resolve_name(name).await
            };
            match result {
                Ok(resolution) => print_resolution(name, &resolution),
                Err(e) => {
                    eprintln!("Resolve failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        TnsCommand::Export { file, yes } => {
            let entries = match client.tns_list_labels().await {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Failed: {}", e);
                    std::process::exit(1);
                }
            };

            if entries.is_empty() {
                eprintln!("No records to export.");
                std::process::exit(0);
            }

            let dest = file.as_deref().unwrap_or("stdout");
            if !yes {
                eprint!("Export {} record(s) to {}? [N/y] ", entries.len(), dest);
                if !confirm_stdin() {
                    eprintln!("Aborted.");
                    std::process::exit(1);
                }
            }

            let export: Vec<ZoneEntry> = entries
                .into_iter()
                .map(|(label, records, publish)| ZoneEntry { label, records, publish })
                .collect();

            let json = serde_json::to_string_pretty(&export).unwrap();

            if let Some(path) = file {
                if let Err(e) = std::fs::write(path, &json) {
                    eprintln!("Failed to write file: {}", e);
                    std::process::exit(1);
                }
                eprintln!("Exported {} record(s) to {}", export.len(), path);
            } else {
                println!("{}", json);
            }
        }
        TnsCommand::Import { file, yes } => {
            let data = match std::fs::read_to_string(file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Failed to read '{}': {}", file, e);
                    std::process::exit(1);
                }
            };

            let entries: Vec<ZoneEntry> = match serde_json::from_str(&data) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Invalid JSON: {}", e);
                    std::process::exit(1);
                }
            };

            if entries.is_empty() {
                eprintln!("No records in file.");
                std::process::exit(0);
            }

            if !yes {
                eprint!("Import {} record(s) from '{}'? [N/y] ", entries.len(), file);
                if !confirm_stdin() {
                    eprintln!("Aborted.");
                    std::process::exit(1);
                }
            }

            let mut ok = 0usize;
            for entry in &entries {
                match client.tns_set_label(&entry.label, entry.records.clone(), entry.publish).await {
                    Ok(()) => ok += 1,
                    Err(e) => eprintln!("Failed to import '{}': {}", entry.label, e),
                }
            }
            eprintln!("Imported {}/{} record(s).", ok, entries.len());
        }
        TnsCommand::Clear { yes } => {
            let entries = match client.tns_list_labels().await {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Failed: {}", e);
                    std::process::exit(1);
                }
            };

            if entries.is_empty() {
                eprintln!("No records to clear.");
                std::process::exit(0);
            }

            if !yes {
                eprint!("Remove all {} record(s) from the zone? [N/y] ", entries.len());
                if !confirm_stdin() {
                    eprintln!("Aborted.");
                    std::process::exit(1);
                }
            }

            let mut ok = 0usize;
            for (label, _, _) in &entries {
                match client.tns_remove_label(label).await {
                    Ok(()) => ok += 1,
                    Err(e) => eprintln!("Failed to remove '{}': {}", label, e),
                }
            }
            eprintln!("Removed {}/{} record(s).", ok, entries.len());
        }
    }
}

/// A single zone label entry for export/import.
#[derive(serde::Serialize, serde::Deserialize)]
struct ZoneEntry {
    label: String,
    records: Vec<TnsRecord>,
    publish: bool,
}

/// Read a y/N confirmation from stdin. Returns true only for "y" or "yes".
fn confirm_stdin() -> bool {
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).unwrap_or(0);
    let answer = answer.trim().to_lowercase();
    answer == "y" || answer == "yes"
}

fn parse_tns_record(type_str: &str, value: &str) -> TnsRecord {
    match type_str {
        "identity" => TnsRecord::Identity(parse_service_id(value)),
        "zone" => TnsRecord::Zone(parse_service_id(value)),
        "text" => TnsRecord::Text(value.to_string()),
        "alias" => TnsRecord::Alias(value.to_string()),
        "content-ref" => {
            let bytes = hex_decode(value);
            if bytes.len() != 64 {
                eprintln!("Invalid content ref: expected 128 hex chars");
                std::process::exit(1);
            }
            let mut hash = [0u8; 64];
            hash.copy_from_slice(&bytes);
            TnsRecord::ContentRef(hash)
        }
        other => {
            eprintln!("Unknown record type: {}", other);
            eprintln!("Valid types: identity, zone, text, alias, content-ref");
            std::process::exit(1);
        }
    }
}

fn print_tns_record(rec: &TnsRecord) {
    match rec {
        TnsRecord::Identity(sid) => println!("  IDENTITY    {}", sid),
        TnsRecord::Zone(sid) => println!("  ZONE        {}", sid),
        TnsRecord::Text(s) => println!("  TEXT        {}", s),
        TnsRecord::Alias(s) => println!("  ALIAS       {}", s),
        TnsRecord::ContentRef(h) => println!("  CONTENT-REF {}", hex_encode(h)),
        TnsRecord::IntroductionPoint { relay_peer_id, kem_algo, kem_pubkey } => {
            println!("  INTRO-POINT relay={} kem_algo={} kem_pk={}", relay_peer_id, kem_algo, hex_encode(kem_pubkey))
        }
        TnsRecord::Peer { signing_algo, peer_id, signing_pubkey, signature } => {
            println!("  PEER        peer={} signing_algo={} pubkey_len={} sig_len={}", peer_id, signing_algo, signing_pubkey.len(), signature.len())
        }
    }
}

fn print_resolution(name: &str, resolution: &TnsResolution) {
    match resolution {
        TnsResolution::Records(records) => {
            println!("{}:", name);
            for rec in records {
                print_tns_record(rec);
            }
        }
        TnsResolution::NotFound => {
            eprintln!("{}: not found", name);
            std::process::exit(1);
        }
        TnsResolution::Error(e) => {
            eprintln!("{}: resolution error: {}", name, e);
            std::process::exit(1);
        }
    }
}

// ── Connection commands ──

/// Bidirectional stdin/stdout bridge over any DataStream.
async fn stdio_bridge(
    stream: &dyn DataStream,
    disconnect_rx: &mut tokio::sync::broadcast::Receiver<()>,
) {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        tokio::select! {
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Err(e) = stream.send(line.as_bytes()).await {
                            eprintln!("Send error: {}", e);
                            break;
                        }
                        line.clear();
                    }
                    Err(e) => {
                        eprintln!("stdin error: {}", e);
                        break;
                    }
                }
            }
            result = stream.recv() => {
                match result {
                    Ok(data) => {
                        let _ = stdout.write_all(&data).await;
                        let _ = stdout.flush().await;
                    }
                    Err(_) => {
                        eprintln!("Connection closed.");
                        break;
                    }
                }
            }
            _ = disconnect_rx.recv() => {
                eprintln!("Daemon connection lost.");
                std::process::exit(1);
            }
        }
    }
}

async fn cmd_connect(cli: &Cli, target: &str, port: u16) {
    let client = connect_daemon(cli).await;

    eprintln!("Connecting to {} port {}...", target, port);

    let conn = match client.connect_to(target, port).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Connection failed: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("Connected to {}. Type to send, Ctrl-C to quit.", conn.remote_service_id);
    eprintln!();

    let mut disconnect_rx = client.subscribe_disconnect();
    stdio_bridge(&conn, &mut disconnect_rx).await;
}

async fn cmd_listen(cli: &Cli, identity: &Option<String>, port: u16) {
    let client = connect_daemon(cli).await;

    let id_str = identity.as_deref().unwrap_or("default");
    let service_id = match client.resolve_identity(id_str).await {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("Failed to resolve identity '{}': {}", id_str, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = client.listen(service_id, port).await {
        eprintln!("Listen failed: {}", e);
        std::process::exit(1);
    }
    eprintln!("Listening on {} port {}.", service_id, port);
    eprintln!("Waiting for connections... (Ctrl-C to quit)");

    let connections: Arc<tokio::sync::Mutex<Vec<Arc<tarnet_api::service::Connection>>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let accept_client = client.clone();
    let accept_conns = connections.clone();
    tokio::spawn(async move {
        loop {
            match accept_client.accept().await {
                Ok(conn) => {
                    eprintln!("[+] Connection from {}", conn.remote_service_id);
                    let conn = Arc::new(conn);
                    accept_conns.lock().await.push(conn.clone());

                    let recv_conns = accept_conns.clone();
                    tokio::spawn(async move {
                        let mut stdout = tokio::io::stdout();
                        loop {
                            match conn.recv().await {
                                Ok(data) => {
                                    let tag = format!("{}", conn.remote_service_id);
                                    let short = &tag[..tag.len().min(16)];
                                    let _ = stdout.write_all(format!("[{}] ", short).as_bytes()).await;
                                    let _ = stdout.write_all(&data).await;
                                    let _ = stdout.flush().await;
                                }
                                Err(_) => {
                                    eprintln!("[-] Connection closed");
                                    recv_conns.lock().await.retain(|c| !Arc::ptr_eq(c, &conn));
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    if e.to_string().contains("timeout") {
                        continue;
                    }
                    eprintln!("Accept error: {}", e);
                    break;
                }
            }
        }
    });

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    let mut disconnect_rx = client.subscribe_disconnect();

    loop {
        tokio::select! {
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) => break,
                    Ok(_) => {
                        let conns = connections.lock().await;
                        if conns.is_empty() {
                            eprintln!("[!] No connections yet.");
                        } else {
                            for conn in conns.iter() {
                                let _ = conn.send(line.as_bytes()).await;
                            }
                        }
                        line.clear();
                    }
                    Err(e) => {
                        eprintln!("stdin error: {}", e);
                        break;
                    }
                }
            }
            _ = disconnect_rx.recv() => {
                eprintln!("Daemon connection lost.");
                std::process::exit(1);
            }
        }
    }
}

// ── Tarify ──

async fn cmd_tarify(cli: &Cli, identity: Option<&str>, command: &[String]) {
    // Check preload lib exists before connecting to daemon.
    let preload_path = find_preload_lib();

    let client = connect_daemon(cli).await;

    // Validate identity exists if specified.
    if let Some(id) = identity {
        match client.resolve_identity(id).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Unknown identity '{}': {}", id, e);
                std::process::exit(1);
            }
        }
    }

    let socks_addrs = match client.socks_addr().await {
        Ok(addrs) => addrs,
        Err(e) => {
            eprintln!("Failed to get SOCKS proxy address from daemon: {}", e);
            std::process::exit(1);
        }
    };

    if socks_addrs.is_empty() {
        eprintln!("SOCKS proxy is disabled on the daemon.");
        eprintln!("Enable it in tarnetd.toml or start tarnetd with SOCKS enabled.");
        std::process::exit(1);
    }

    let proxy_addr = socks_addrs[0];

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..])
        .env("LD_PRELOAD", &preload_path)
        .env("TARIFY_PROXY_ADDR", format!("{}", proxy_addr));

    if let Some(id) = identity {
        cmd.env("TARIFY_IDENTITY", id);
    }

    let status = cmd.status();

    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("Failed to execute '{}': {}", command[0], e);
            std::process::exit(1);
        }
    }
}

fn find_preload_lib() -> String {
    let builtin = env!("TARNET_PRELOAD_PATH");
    if std::path::Path::new(builtin).exists() {
        return builtin.to_string();
    }

    if let Ok(path) = std::env::var("TARIFY_PRELOAD_PATH") {
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("libtarnet_preload.so");
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }

    for dir in &["/usr/local/lib", "/usr/lib", "/lib"] {
        let candidate = format!("{}/libtarnet_preload.so", dir);
        if std::path::Path::new(&candidate).exists() {
            return candidate;
        }
    }

    if std::path::Path::new("libtarnet_preload.so").exists() {
        return "libtarnet_preload.so".to_string();
    }

    eprintln!("Cannot find libtarnet_preload.so");
    eprintln!("Set TARIFY_PRELOAD_PATH or place it next to the tarnet binary.");
    std::process::exit(1);
}

// ── Status ──

async fn cmd_status(cli: &Cli) {
    use tarnet_api::types::PrivacyLevel;

    let client = connect_daemon(cli).await;
    let status = client.node_status().await;
    let identities = client.list_identities().await.unwrap_or_default();

    // Header: one compact line
    println!(
        "{} {} {} {}",
        bold("tarnetd"),
        dim(&format!("up {}", format_duration(status.uptime_secs))),
        dim("peer"),
        short_peer(&status.peer_id),
    );

    // Identities
    if !identities.is_empty() {
        let name_w = identities.iter()
            .map(|(l, ..)| l.len())
            .max().unwrap_or(4)
            .max(4) + 2; // +2 gutter
        println!(
            "  {} {} {} {}",
            lpad_dim("name", name_w), lpad_dim("privacy", 8),
            lpad_dim("hops", 6), dim("address"),
        );
        for (label, sid, privacy, hops, _, _, _) in &identities {
            let badge = match privacy {
                PrivacyLevel::Public => color("\x1b[32m", &format!("{:<8}", "public")),
                PrivacyLevel::Hidden { .. } => color("\x1b[33m", &format!("{:<8}", "hidden")),
            };
            println!(
                "  {} {} {:<6} {}",
                bold(&format!("{:<width$}", label, width = name_w)),
                badge, hops, dim(&censor_address(&sid.to_string())),
            );
        }
    }

    // Peers — grouped by peer, active link on main line, standby summarized
    if !status.peers.is_empty() {
        let xport_w = status.peers.iter()
            .flat_map(|p| p.links.iter())
            .map(|l| l.transport.len())
            .max().unwrap_or(3)
            .max(3);

        println!();
        for peer in &status.peers {
            let active = peer.links.iter().find(|l| l.state == "active");
            let standby: Vec<_> = peer.links.iter().filter(|l| l.state != "active").collect();

            // Main line: active link
            if let Some(link) = active {
                let arrow = if link.direction == "outbound" { "->" } else { "<-" };
                println!(
                    "  {} {}  {:<w$}  {}  {}",
                    color("\x1b[36m", arrow), short_peer(&peer.peer_id),
                    link.transport, format_rtt(link.rtt_us),
                    dim(&format!("idle {}", format_duration(link.idle_secs))),
                    w = xport_w,
                );
            } else {
                // No active link (shouldn't happen, but handle gracefully)
                println!("  {} {}  {}", dim("--"), short_peer(&peer.peer_id), dim("no active link"));
            }

            // Standby summary: indented, dim, grouped by transport
            if !standby.is_empty() {
                let mut by_transport: std::collections::BTreeMap<&str, (usize, usize)> = std::collections::BTreeMap::new();
                for l in &standby {
                    let entry = by_transport.entry(l.transport.as_str()).or_insert((0, 0));
                    if l.direction == "outbound" { entry.0 += 1; } else { entry.1 += 1; }
                }
                let parts: Vec<String> = by_transport.iter().map(|(xport, (out, inp))| {
                    let mut dirs = Vec::new();
                    if *out > 0 { dirs.push(format!("{}->", out)); }
                    if *inp > 0 { dirs.push(format!("<-{}", inp)); }
                    format!("{} {}", dirs.join(" "), xport)
                }).collect();
                println!("  {}", dim(&format!("     + {} standby: {}", standby.len(), parts.join(", "))));
            }
        }
    }

    // Routes
    if !status.routes.is_empty() {
        // "via" + space + 16-char peer = 20 visible chars
        let via_w = 4 + 16; // "via " + short_peer length
        println!();
        for (dest, next_hop, cost) in &status.routes {
            let via = if dest == next_hop {
                lpad_dim("direct", via_w)
            } else {
                format!("{} {}", dim("via"), short_peer(next_hop))
            };
            println!("  {}  {}  {}", short_peer(dest), via, dim(&format!("cost {}", cost)));
        }
    }

    // Subsystems: dht + circuits on one line each
    println!();
    let watches = if status.dht.local_watches == 0 && status.dht.remote_watches == 0 {
        dim("none")
    } else {
        format!("{}/{}", status.dht.local_watches, status.dht.remote_watches)
    };
    println!(
        "  {} {} {}  {} {}  {} {}  {} ~{}",
        dim("dht"),
        status.dht.stored_records, dim(&format!("records / {} keys", status.dht.stored_keys)),
        dim("kbucket"), status.dht.kbucket_peers,
        dim("watches"), watches,
        dim("nse"), status.dht.nse,
    );

    let c = &status.circuits;
    let parts: Vec<String> = [
        (c.outbound_circuits, "out"),
        (c.relay_forwards, "fwd"),
        (c.relay_endpoints, "end"),
        (c.rendezvous_points, "rdv"),
        (c.intro_points, "intro"),
    ].iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, l)| format!("{} {}", n, l))
        .collect();
    println!(
        "  {} {}",
        dim("circuits"),
        if parts.is_empty() { dim("none") } else { parts.join("  ") },
    );

    // Traffic
    let t = &status.traffic;
    println!();
    print_traffic_header();
    print_traffic_row("↑",    Some("\x1b[32m"), &t.bytes_up, false);
    print_traffic_row("↓",    Some("\x1b[34m"), &t.bytes_down, false);
    print_traffic_row("pkt↑", None,             &t.packets_up, true);
    print_traffic_row("pkt↓", None,             &t.packets_down, true);
    if t.cells_relayed.total > 0 {
        print_traffic_row("relay", None, &t.cells_relayed, true);
    }
}

// ── Status display helpers ──

/// Whether stdout is a TTY that supports ANSI escape codes.
fn use_color() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
}

fn bold(s: &str) -> String {
    if use_color() { format!("\x1b[1m{}\x1b[0m", s) } else { s.to_string() }
}

fn dim(s: &str) -> String {
    if use_color() { format!("\x1b[2m{}\x1b[0m", s) } else { s.to_string() }
}

fn color(code: &str, s: &str) -> String {
    if use_color() { format!("{}{}\x1b[0m", code, s) } else { s.to_string() }
}

/// Right-aligned dim text: pad first, then wrap in ANSI.
fn rpad_dim(s: &str, width: usize) -> String {
    dim(&format!("{:>width$}", s, width = width))
}

/// Left-aligned dim text: pad first, then wrap in ANSI.
fn lpad_dim(s: &str, width: usize) -> String {
    dim(&format!("{:<width$}", s, width = width))
}

fn short_peer(peer: &tarnet_api::types::PeerId) -> String {
    let hex: String = peer.0[..8].iter().map(|b| format!("{:02x}", b)).collect();
    hex
}

/// Censor a private address: show first 8 and last 4 chars, replace middle with "...".
fn censor_address(s: &str) -> String {
    if s.len() <= 16 {
        return s.to_string();
    }
    format!("{}...{}", &s[..8], &s[s.len()-4..])
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{}h", secs / 86400, (secs % 86400) / 3600)
    }
}

fn format_rtt(rtt_us: u64) -> String {
    if rtt_us == 0 {
        dim("-")
    } else {
        format_rtt_plain(rtt_us)
    }
}

fn format_rtt_plain(rtt_us: u64) -> String {
    if rtt_us == 0 {
        "-".into()
    } else if rtt_us < 1_000 {
        format!("{}us", rtt_us)
    } else if rtt_us < 1_000_000 {
        format!("{:.1}ms", rtt_us as f64 / 1_000.0)
    } else {
        format!("{:.1}s", rtt_us as f64 / 1_000_000.0)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        dim("0")
    } else if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_count(n: u64) -> String {
    if n == 0 {
        dim("0")
    } else if n < 1_000 {
        format!("{}", n)
    } else if n < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    }
}

const COL: usize = 8;
const LABEL_W: usize = 6;

fn print_traffic_header() {
    println!(
        "  {} {} {} {} {}",
        lpad_dim("", LABEL_W),
        rpad_dim("total", COL), rpad_dim("5m", COL),
        rpad_dim("1h", COL), rpad_dim("1d", COL),
    );
}

fn print_traffic_row(
    label: &str,
    label_color: Option<&str>,
    stats: &tarnet_api::types::WindowedStats,
    is_count: bool,
) {
    let fmt = if is_count { format_count } else { format_bytes };
    let padded_label = format!("{:>width$}", label, width = LABEL_W);
    let colored_label = match label_color {
        Some(code) => color(code, &padded_label),
        None => padded_label,
    };
    // Pad visible values, then wrap dim on zeros
    println!(
        "  {} {} {} {} {}",
        colored_label,
        rpad_val(&fmt(stats.total), COL),
        rpad_val(&fmt(stats.last_5min), COL),
        rpad_val(&fmt(stats.last_1hr), COL),
        rpad_val(&fmt(stats.last_1day), COL),
    );
}

/// Right-pad a value that may contain ANSI (from dim("0")).
/// If it's plain text, just pad. If it already has escapes, it was
/// produced by format_bytes/format_count which only use dim for zero.
fn rpad_val(s: &str, width: usize) -> String {
    if s.contains("\x1b[") {
        // Already has ANSI — pad based on visible character count
        let vis = strip_ansi_len(s);
        let pad = width.saturating_sub(vis);
        format!("{}{}", " ".repeat(pad), s)
    } else {
        format!("{:>width$}", s, width = width)
    }
}

fn strip_ansi_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else {
            len += 1;
        }
    }
    len
}

async fn cmd_reload(cli: &Cli) {
    let client = connect_daemon(cli).await;
    match client.reload().await {
        Ok(()) => println!("Reload triggered."),
        Err(e) => {
            eprintln!("Reload failed: {}", e);
            std::process::exit(1);
        }
    }
}

// ── Helpers ──

fn parse_dht_hash(hex_str: &str) -> [u8; 64] {
    let bytes = hex_decode(hex_str);
    if bytes.len() != 64 {
        eprintln!("Invalid hash: expected 128 hex chars, got {}", hex_str.len());
        std::process::exit(1);
    }
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&bytes);
    hash
}

fn parse_service_id(input: &str) -> ServiceId {
    match ServiceId::parse(input) {
        Ok(sid) => sid,
        Err(_) => {
            eprintln!("'{}' doesn't look like a ServiceId", input);
            std::process::exit(1);
        }
    }
}

fn parse_peer_id(hex_str: &str) -> PeerId {
    let bytes = hex_decode(hex_str);
    if bytes.len() != 32 {
        eprintln!("Invalid peer ID: expected 64 hex chars, got {}", hex_str.len());
        std::process::exit(1);
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    PeerId(id)
}

fn parse_scheme(s: &str) -> tarnet_api::types::IdentityScheme {
    match s {
        "ed25519" => tarnet_api::types::IdentityScheme::Ed25519,
        "falcon_ed25519" => tarnet_api::types::IdentityScheme::FalconEd25519,
        other => {
            eprintln!("Unknown scheme: {}. Use 'falcon_ed25519' or 'ed25519'.", other);
            std::process::exit(1);
        }
    }
}

fn parse_privacy(s: &str, intro_points: u8) -> tarnet_api::types::PrivacyLevel {
    match s {
        "public" => tarnet_api::types::PrivacyLevel::Public,
        "hidden" => tarnet_api::types::PrivacyLevel::Hidden { intro_points },
        other => {
            eprintln!("Unknown privacy level: {}. Use 'public' or 'hidden'.", other);
            std::process::exit(1);
        }
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("Invalid hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
