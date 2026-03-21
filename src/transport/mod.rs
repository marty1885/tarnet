pub mod firewall;
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
    /// Receive a complete message into the buffer. Returns bytes written.
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
    /// Maximum transmission unit (payload size per message).
    fn mtu(&self) -> usize;
    /// Whether this transport guarantees ordered, reliable delivery.
    fn is_reliable(&self) -> bool;
    /// Human-readable transport name (e.g. "tcp", "ws", "webrtc").
    /// Pluggable transports return their own name (e.g. "obfs4", "rs232").
    fn name(&self) -> &'static str;
}

/// Accepts and initiates transport connections.
#[async_trait]
pub trait Discovery: Send + Sync {
    /// Accept an incoming connection.
    async fn accept(&self) -> Result<Box<dyn Transport>>;
    /// Connect to a peer at the given address.
    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>>;
}

/// Combines multiple Discovery implementations into one.
/// Accepts from all listeners, dispatches connect by trying each in order.
/// Place scheme-specific discoveries (WS) before generic ones (TCP) so that
/// scheme detection short-circuits without attempting invalid connections.
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
    async fn accept(&self) -> Result<Box<dyn Transport>> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::Wire("all listeners closed".into()))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        let mut last_err = None;
        for disc in &self.discoveries {
            match disc.connect(addr).await {
                Ok(t) => return Ok(t),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Wire(format!("no discovery can connect to {}", addr))))
    }
}
