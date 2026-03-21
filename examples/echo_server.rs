/// Echo server: runs a tarnet node that echoes back any data message it receives.
///
/// Usage:
///   cargo run --example echo_server [-- --listen <addr> --connect <peer>]
///
/// The server prints its peer ID on startup. Clients use this ID to address
/// messages through the overlay — they don't need a direct connection.
///
/// Example 3-node setup (server ← relay ← client):
///
///   Terminal 1 (relay / bootstrap node):
///     cargo run -- run --listen 127.0.0.1:7946
///
///   Terminal 2 (server, connects to relay):
///     cargo run --example echo_server -- --listen 127.0.0.1:7001 --connect 127.0.0.1:7946
///
///   Terminal 3 (client, connects to relay — messages route through overlay):
///     cargo run --example echo_client -- --connect 127.0.0.1:7946 --peer <server_peer_id>
use std::sync::Arc;

use tarnet::identity::Keypair;
use tarnet::node::Node;
use tarnet::transport::tcp::TcpDiscovery;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let listen_addr = get_flag(&args, "--listen").unwrap_or("127.0.0.1:7001".into());
    let connect_addrs = get_all_flags(&args, "--connect");

    let identity = load_identity("echo_server.key");
    println!("Echo server peer ID: {}", identity.peer_id());

    let node = Arc::new(Node::new(identity));
    let discovery = TcpDiscovery::bind(&[listen_addr])
        .await
        .expect("failed to bind");
    println!("Listening on {:?}", discovery.local_addrs());

    // Take the app receiver before starting the event loop
    let mut app_rx = node.take_app_receiver().await.unwrap();
    let echo_node = node.clone();

    // Echo handler: receives data, sends it back to the origin
    tokio::spawn(async move {
        while let Some((origin, data)) = app_rx.recv().await {
            let text = String::from_utf8_lossy(&data);
            println!("  echo {:?}: {}", origin, text);
            if let Err(e) = echo_node.send_data(&origin, &data).await {
                eprintln!("  echo send failed: {}", e);
            }
        }
    });

    // Run the node (accepts connections, connects to bootstrap, runs event loop)
    node.run(Box::new(discovery), connect_addrs, vec![]).await.ok();
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

fn load_identity(path: &str) -> Keypair {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Keypair::from_bytes(key);
        }
    }
    let kp = Keypair::generate();
    std::fs::write(path, kp.to_bytes()).ok();
    kp
}
