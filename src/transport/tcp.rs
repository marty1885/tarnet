use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use super::{Discovery, Transport};
use crate::types::{Error, Result};

/// Length-prefix framed TCP transport.
pub struct TcpTransport {
    reader: Mutex<tokio::net::tcp::OwnedReadHalf>,
    writer: Mutex<tokio::net::tcp::OwnedWriteHalf>,
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        if data.len() > u32::MAX as usize {
            return Err(Error::Wire("message too large".into()));
        }
        let mut writer = self.writer.lock().await;
        writer.write_all(&(data.len() as u32).to_be_bytes()).await?;
        writer.write_all(data).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut reader = self.reader.lock().await;
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > buf.len() {
            return Err(Error::Wire(format!(
                "message {} bytes exceeds buffer {}",
                len,
                buf.len()
            )));
        }
        reader.read_exact(&mut buf[..len]).await?;
        Ok(len)
    }

    fn mtu(&self) -> usize {
        65535 // TCP has no inherent MTU limit; cap at wire format max
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "tcp"
    }
}

/// TCP listener that accepts connections on one or more addresses.
pub struct TcpDiscovery {
    local_addrs: Vec<SocketAddr>,
    accept_rx: Mutex<mpsc::Receiver<(TcpStream, SocketAddr)>>,
}

impl TcpDiscovery {
    /// Bind to one or more addresses. Spawns an accept task per listener.
    pub async fn bind(addrs: &[String]) -> Result<Self> {
        if addrs.is_empty() {
            return Err(Error::Wire("no listen addresses specified".into()));
        }

        let (tx, rx) = mpsc::channel(64);
        let mut local_addrs = Vec::new();

        for addr in addrs {
            let socket_addr = crate::types::parse_socket_addr(addr)?;
            let listener = TcpListener::bind(socket_addr).await?;
            let local = listener.local_addr()?;
            log::info!("TCP listening on {}", local);
            local_addrs.push(local);

            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok(conn) => {
                            if tx.send(conn).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("TCP accept error on {}: {}", local, e);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }

        Ok(Self {
            local_addrs,
            accept_rx: Mutex::new(rx),
        })
    }

    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }
}

#[async_trait]
impl Discovery for TcpDiscovery {
    async fn accept(&self) -> Result<Box<dyn Transport>> {
        let mut rx = self.accept_rx.lock().await;
        let (stream, addr) = rx.recv().await.ok_or_else(|| {
            Error::Wire("all listeners closed".into())
        })?;
        stream.set_nodelay(true)?;
        log::debug!("TCP accepted connection from {}", addr);
        Ok(Box::new(TcpTransport::new(stream)))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        let socket_addr = crate::types::parse_socket_addr(addr)?;
        let stream = TcpStream::connect(socket_addr).await?;
        stream.set_nodelay(true)?;
        log::debug!("TCP connected to {}", addr);
        Ok(Box::new(TcpTransport::new(stream)))
    }
}
