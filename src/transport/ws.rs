use std::net::SocketAddr;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use super::{Discovery, Transport};
use crate::types::{Error, Result};

/// WebSocket transport — uses binary WebSocket frames for message delivery.
/// WebSocket handles framing natively, so no length-prefix is needed.
pub struct WsTransport {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    // Keep task handles alive so the reader/writer loops don't get cancelled.
    _reader: tokio::task::JoinHandle<()>,
    _writer: tokio::task::JoinHandle<()>,
}

impl WsTransport {
    /// Wrap a WebSocket stream into a Transport.
    pub fn wrap<S>(ws: WebSocketStream<S>) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sink, mut stream) = ws.split();
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(64);

        let writer = tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if sink.send(Message::Binary(data)).await.is_err() {
                    break;
                }
            }
        });

        let reader = tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                match msg {
                    Message::Binary(data) => {
                        if read_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {} // ping/pong handled internally by tungstenite
                }
            }
        });

        Self {
            tx: write_tx,
            rx: Mutex::new(read_rx),
            _reader: reader,
            _writer: writer,
        }
    }
}

#[async_trait]
impl Transport for WsTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|_| Error::Wire("WebSocket closed".into()))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut rx = self.rx.lock().await;
        let data = rx
            .recv()
            .await
            .ok_or_else(|| Error::Wire("WebSocket closed".into()))?;
        if data.len() > buf.len() {
            return Err(Error::Wire(format!(
                "WS message {} bytes exceeds buffer {}",
                data.len(),
                buf.len()
            )));
        }
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }

    fn mtu(&self) -> usize {
        65535
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "ws"
    }
}

/// WebSocket listener that accepts upgrades on a configurable HTTP path.
/// Designed to sit behind a reverse proxy — server speaks plain ws://,
/// TLS termination is handled by nginx/caddy/etc.
pub struct WsDiscovery {
    path: String,
    local_addr: SocketAddr,
    accept_rx: Mutex<mpsc::Receiver<Box<dyn Transport>>>,
}

impl WsDiscovery {
    /// Bind a WebSocket listener. Only requests matching `path` are upgraded.
    pub async fn bind(addr: &str, path: String) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        log::info!("WebSocket listening on {} (path: {})", local_addr, path);

        let (tx, rx) = mpsc::channel(64);
        let accept_path = path.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let tx = tx.clone();
                        let path = accept_path.clone();
                        tokio::spawn(async move {
                            match ws_accept(stream, &path).await {
                                Ok(ws) => {
                                    log::debug!("WebSocket accepted from {}", peer_addr);
                                    let transport: Box<dyn Transport> =
                                        Box::new(WsTransport::wrap(ws));
                                    let _ = tx.send(transport).await;
                                }
                                Err(e) => {
                                    log::debug!(
                                        "WebSocket upgrade failed from {}: {}",
                                        peer_addr, e
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("WS accept error on {}: {}", local_addr, e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok(Self {
            path,
            local_addr,
            accept_rx: Mutex::new(rx),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Perform WebSocket upgrade with path validation.
async fn ws_accept(
    stream: TcpStream,
    expected_path: &str,
) -> Result<WebSocketStream<TcpStream>> {
    let expected = expected_path.to_string();
    tokio_tungstenite::accept_hdr_async(
        stream,
        |req: &tokio_tungstenite::tungstenite::http::Request<()>, resp| {
            if req.uri().path() != expected {
                let mut err =
                    tokio_tungstenite::tungstenite::http::Response::new(Some("Not Found".into()));
                *err.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
                return Err(err);
            }
            Ok(resp)
        },
    )
    .await
    .map_err(|e| Error::Wire(format!("WebSocket handshake: {}", e)))
}

/// Outbound-only WebSocket connector. Always available, no listener required.
pub struct WsConnector;

impl WsConnector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Discovery for WsConnector {
    async fn accept(&self) -> Result<Box<dyn Transport>> {
        // Never accepts — this is outbound-only.
        futures_util::future::pending().await
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        ws_connect(addr).await
    }
}

#[async_trait]
impl Discovery for WsDiscovery {
    async fn accept(&self) -> Result<Box<dyn Transport>> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::Wire("WS listener closed".into()))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        ws_connect(addr).await
    }
}

async fn ws_connect(addr: &str) -> Result<Box<dyn Transport>> {
    if !addr.starts_with("ws://") && !addr.starts_with("wss://") {
        return Err(Error::Wire("not a WebSocket URL".into()));
    }
    let (ws, _) = tokio_tungstenite::connect_async(addr)
        .await
        .map_err(|e| Error::Wire(format!("WebSocket connect to {}: {}", addr, e)))?;
    log::debug!("WebSocket connected to {}", addr);
    Ok(Box::new(WsTransport::wrap(ws)))
}
