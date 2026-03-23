/// Echo server: listens on the default identity and echoes back messages.
///
/// Requires a running `tarnetd`. The server prints its ServiceId on startup.
///
/// Usage:
///   cargo run --example echo_server
use std::sync::Arc;

use tarnet_api::service::{ListenerOptions, PortMode, ServiceApi};
use tarnet_client::IpcServiceApi;

#[tokio::main]
async fn main() {
    let client = IpcServiceApi::connect_default()
        .await
        .expect("failed to connect to tarnetd — is it running?");

    let identities = client.list_identities().await.expect("failed to list identities");
    let (_, service_id, ..) = &identities[0];
    println!("Echo server: {}", service_id);

    let listener = client
        .listen(*service_id, PortMode::ReliableOrdered, "echo", ListenerOptions::default())
        .await
        .expect("failed to listen");

    println!("Listening on port 'echo'. Ctrl-C to quit.");

    let client = Arc::new(client);
    loop {
        let conn = match client.accept(&listener).await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("accept error: {}", e);
                continue;
            }
        };

        println!("[+] Connection from {}", conn.remote_service_id);

        tokio::spawn(async move {
            loop {
                match conn.recv().await {
                    Ok(data) => {
                        let text = String::from_utf8_lossy(&data);
                        println!("  echo: {}", text);
                        if conn.send(&data).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            println!("[-] Disconnected");
        });
    }
}
