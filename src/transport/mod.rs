pub mod firewall;
pub(crate) mod metered;
pub mod tcp;
pub mod webrtc;
pub mod ws;

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};

use crate::types::{Error, Result};

/// Abstract transport for sending and receiving framed messages.
/// Implementations handle framing internally (e.g., length-prefix for TCP).
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a complete message.
    async fn send(&self, data: &[u8]) -> Result<()>;
    /// Send an encrypted link frame with its scheduler class. Handshake sends
    /// use `send`; both paths are charged by the common I/O policy.
    async fn send_frame(&self, data: &[u8], _control: bool) -> Result<()> {
        self.send(data).await
    }
    /// Bind subsequent I/O statistics to the authenticated peer.
    fn authenticated(&self, _peer: crate::types::PeerId) {}
    /// Mark successful frame authentication, before any delivery throttle.
    fn authenticated_frame(&self) {}
    /// Account for local delivery time after frame authentication. The
    /// receive itself must finish before authentication can be checked.
    async fn deliver_frame(&self, _bytes: usize, _authenticated: bool) {}
    /// Authenticated activity, adjusted for time paused by local throttling.
    fn receive_activity(&self) -> Option<std::time::Instant> { None }
    /// Receive a complete message into the buffer. Returns bytes written.
    ///
    /// Not required to be cancel-safe: dropping an in-progress `recv` may
    /// lose stream framing (TCP reads a length prefix, then the body). Callers
    /// must let a started `recv` finish unless they are abandoning the
    /// transport.
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
    /// Receive an established-link frame. The network stall deadline is
    /// slightly longer than the node heartbeat timeout (180 s). I/O policies
    /// apply delivery throttling outside that deadline.
    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
        tokio::time::timeout(std::time::Duration::from_secs(210), self.recv(buf))
            .await.map_err(|_| crate::types::Error::Wire("link recv stalled".into()))?
    }
    /// Maximum transmission unit (payload size per message).
    fn mtu(&self) -> usize;
    /// Whether this transport guarantees ordered, reliable delivery.
    fn is_reliable(&self) -> bool;
    /// Human-readable transport name (e.g. "tcp", "ws", "webrtc").
    /// Pluggable transports return their own name (e.g. "obfs4", "rs232").
    fn name(&self) -> &'static str;
    /// Approximate bandwidth in bytes/s, if known. Links use it to size frames
    /// and to scale timers, so a slow radio link isn't timed out while a
    /// message is still on the air. `None` means fast or unknown.
    fn bandwidth_hint(&self) -> Option<u64> {
        None
    }
}

/// Accepts and initiates transport connections.
#[async_trait]
pub trait Discovery: Send + Sync {
    /// Whether this discovery understands the address syntax. Custom
    /// discoveries retain the existing try-in-order behavior by default.
    fn supports_address(&self, _addr: &str) -> bool {
        true
    }
    /// Accept an incoming connection.
    async fn accept(&self) -> Result<Box<dyn Transport>>;
    /// Connect to a peer at the given address.
    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>>;
}

/// Combines multiple Discovery implementations into one.
/// Accepts from all listeners, dispatches connect by trying compatible
/// discoveries in order. Unsupported address schemes cannot mask a failure
/// from the transport that actually understands the address.
pub struct MultiDiscovery {
    accept_rx: Mutex<mpsc::Receiver<Box<dyn Transport>>>,
    discoveries: Vec<Arc<dyn Discovery>>,
}

impl MultiDiscovery {
    pub fn new(discoveries: Vec<Box<dyn Discovery>>) -> Self {
        let (tx, rx) = mpsc::channel(128);
        let mut arcs: Vec<Arc<dyn Discovery>> = Vec::new();

        for disc in discoveries {
            let disc: Arc<dyn Discovery> = Arc::from(disc);
            arcs.push(disc.clone());
            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    match disc.accept().await {
                        Ok(transport) => {
                            if tx.send(transport).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("MultiDiscovery accept error: {}", e);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }

        Self {
            accept_rx: Mutex::new(rx),
            discoveries: arcs,
        }
    }
}

#[async_trait]
impl Discovery for MultiDiscovery {
    fn supports_address(&self, addr: &str) -> bool {
        self.discoveries.iter().any(|disc| disc.supports_address(addr))
    }

    async fn accept(&self) -> Result<Box<dyn Transport>> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::Wire("all listeners closed".into()))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        let mut last_err = None;
        for disc in &self.discoveries {
            if !disc.supports_address(addr) {
                continue;
            }
            match disc.connect(addr).await {
                Ok(t) => return Ok(t),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| Error::Wire(format!("no discovery can connect to {}", addr))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn discovery() -> MultiDiscovery {
        MultiDiscovery::new(vec![
            Box::new(ws::WsConnector::new()),
            Box::new(tcp::TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap()),
        ])
    }

    #[tokio::test]
    async fn websocket_http_response_is_not_masked_by_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        let error = match discovery().await.connect(&url).await {
            Err(error) => error,
            Ok(_) => panic!("ordinary HTTP endpoint should fail WebSocket upgrade"),
        };
        let message = error.to_string();
        assert!(matches!(error, Error::Protocol(_)));
        assert!(message.contains("invalid WebSocket communication"), "{message}");
        assert!(message.contains("expected HTTP 101"), "{message}");
        assert!(message.contains("received HTTP 200"), "{message}");
        assert!(message.contains(&url), "{message}");
        assert!(!message.contains("invalid port"), "{message}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_address_skips_websocket_connector() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = discovery().await.connect(&listener.local_addr().unwrap().to_string()).await.unwrap();
        assert_eq!(transport.name(), "tcp");
    }

    #[tokio::test]
    async fn websocket_address_connects() {
        let listener = ws::WsDiscovery::bind("127.0.0.1:0", "/tarnet".into()).await.unwrap();
        let url = format!("ws://{}/tarnet", listener.local_addr());
        let transport = discovery().await.connect(&url).await.unwrap();
        assert_eq!(transport.name(), "ws");
    }
}
