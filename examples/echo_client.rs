/// Echo client: connects to an echo server by ServiceId or TNS name.
///
/// Requires a running `tarnetd`. Type lines and press Enter to send.
///
/// Usage:
///   cargo run --example echo_client -- <service-id or tns-name>
use tarnet_api::service::{PortMode, ServiceApi};
use tarnet_client::IpcServiceApi;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: echo_client <service-id or tns-name>");
        std::process::exit(1);
    });

    let client = IpcServiceApi::connect_default()
        .await
        .expect("failed to connect to tarnetd — is it running?");

    println!("Connecting to {} ...", target);

    let conn = client
        .connect_to(&target, PortMode::ReliableOrdered, "echo")
        .await
        .expect("failed to connect");

    println!("Connected. Type a message and press Enter. Ctrl-C to quit.");

    // Print incoming messages
    tokio::spawn(async move {
        loop {
            match conn.recv().await {
                Ok(data) => println!("  < {}", String::from_utf8_lossy(&data)),
                Err(_) => {
                    eprintln!("Disconnected.");
                    std::process::exit(0);
                }
            }
        }
    });

    // Read lines from stdin and send
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.is_empty() {
            continue;
        }
        if client
            .connect_to(&target, PortMode::ReliableOrdered, "echo")
            .await
            .is_err()
        {
            eprintln!("Connection lost.");
            break;
        }
    }
}
