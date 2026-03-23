/// Echo client: connects to the overlay via bootstrap peers, sends messages
/// to a remote peer ID, and prints echoed responses.
///
/// Usage:
///   cargo run --example echo_client -- --connect <bootstrap_addr> --peer <dest_peer_id>
///
/// The client doesn't need a direct connection to the echo server — messages
/// are routed through the overlay network hop by hop. Connect to a `tarnet run`
/// bootstrap node which relays traffic between peers.
///
/// Type lines and press Enter to send. Ctrl-C to quit.
use std::sync::Arc;

use tarnet::identity::Keypair;
use tarnet::node::Node;
use tarnet::transport::tcp::TcpDiscovery;
use tarnet::types::PeerId;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let connect_addrs = get_all_flags(&args, "--connect");
    let dest_hex = get_flag(&args, "--peer");

    if connect_addrs.is_empty() || dest_hex.is_none() {
        eprintln!("Usage: echo_client --connect <addr> --peer <peer_id_hex>");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --connect <addr>    Bootstrap peer address (repeatable)");
        eprintln!("  --peer <hex>        Destination peer ID (64 hex chars)");
        eprintln!("  --listen <addr>     Local listen address (default: 127.0.0.1:0)");
        std::process::exit(1);
    }

    let dest_peer = parse_peer_id(&dest_hex.unwrap());
    let listen_addr = get_flag(&args, "--listen").unwrap_or("127.0.0.1:0".into());

    let identity = Keypair::generate();
    println!("Client peer ID: {}", identity.peer_id());
    println!("Destination:    {:?}", dest_peer);

    let node = Arc::new(Node::new(identity));
    let discovery = TcpDiscovery::bind(&[listen_addr])
        .await
        .expect("failed to bind");

    // Take the app receiver before starting the event loop
    let mut app_rx = node.take_app_receiver().await.unwrap();

    // Spawn response printer
    tokio::spawn(async move {
        while let Some((from, data)) = app_rx.recv().await {
            let text = String::from_utf8_lossy(&data);
            println!("  echo from {:?}: {}", from, text);
        }
    });

    // Run node event loop in background (connects to bootstrap peers internally)
    let run_node = node.clone();
    let bootstrap = connect_addrs.clone();
    tokio::spawn(async move {
        run_node
            .run(Box::new(discovery), bootstrap, vec![])
            .await
            .ok();
    });

    // Wait for bootstrap connections and route propagation
    println!("Waiting for routes to propagate...");
    let dest = dest_peer;
    let n = node.clone();
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let routes = n.routing_entries().await;
        if routes.iter().any(|(d, _, _)| *d == dest) {
            println!("Route found!");
            for (d, next_hop, cost) in &routes {
                let marker = if *d == dest { " <-- target" } else { "" };
                println!("  {:?} via {:?} cost {}{}", d, next_hop, cost, marker);
            }
            break;
        }
        let peers = n.connected_peers().await;
        if !peers.is_empty() {
            println!(
                "  connected to {} peers, waiting for routes...",
                peers.len()
            );
        }
    }

    // Read lines from stdin and send to destination peer
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    println!();
    println!("Type a message and press Enter (Ctrl-C to quit):");
    while let Ok(Some(line)) = lines.next_line().await {
        if line.is_empty() {
            continue;
        }
        match node.send_data(&dest_peer, line.as_bytes()).await {
            Ok(()) => {}
            Err(e) => eprintln!("  send failed: {}", e),
        }
    }
}

fn parse_peer_id(hex: &str) -> PeerId {
    if hex.len() != 64 {
        eprintln!("Peer ID must be 64 hex characters (got {})", hex.len());
        std::process::exit(1);
    }
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex in peer ID"))
        .collect();
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    PeerId(id)
}

fn get_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn get_all_flags(args: &[String], flag: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(val) = args.get(i + 1) {
                result.push(val.clone());
                i += 1;
            }
        }
        i += 1;
    }
    result
}
