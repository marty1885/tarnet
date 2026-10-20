//! Foreground forwarding sessions. One authenticated, reliable overlay connection
//! multiplexes TCP byte streams or UDP datagrams, preserving datagram boundaries.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tarnet_api::error::{ApiError, ApiResult};
use tarnet_api::forward::Proof;
use tarnet_api::service::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::Instant;

pub const PORT: &str = "tarnet-forward-v1";
const MAX_FLOWS: usize = 256;
const IDLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction { In, Out }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub direction: Direction,
    /// Destination for In, listening address for Out, on the policy host.
    pub endpoint: SocketAddr,
    pub udp: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Frame {
    Challenge([u8; 32]),
    Authenticate { request: Vec<u8>, proof: Proof },
    Ready,
    Error(String),
    Open(u32),
    Data(u32, Vec<u8>),
    Eof(u32),
    Close(u32),
    Ping,
    Pong,
}

pub fn encode<T: Serialize>(value: &T) -> ApiResult<Vec<u8>> {
    rmp_serde::to_vec(value).map_err(|e| ApiError::Protocol(e.to_string()))
}
pub fn decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> ApiResult<T> {
    if data.len() > 128 * 1024 { return Err(ApiError::Protocol("forward frame too large".into())); }
    rmp_serde::from_slice(data).map_err(|e| ApiError::Protocol(e.to_string()))
}
pub async fn send(conn: &Connection, frame: &Frame) -> ApiResult<()> {
    conn.send(&encode(frame)?).await
}
pub async fn recv(conn: &Connection) -> ApiResult<Frame> {
    decode(&conn.recv().await?)
}

pub enum Binding { Tcp(TcpListener), Udp(Arc<UdpSocket>) }
impl Binding {
    pub async fn bind(address: SocketAddr, udp: bool) -> ApiResult<Self> {
        if udp { Ok(Self::Udp(Arc::new(UdpSocket::bind(address).await?))) }
        else { Ok(Self::Tcp(TcpListener::bind(address).await?)) }
    }
}

#[derive(Debug)]
enum Input { Data(Vec<u8>), Eof }
struct Flow { input: mpsc::Sender<Input>, touched: Instant, peer: Option<SocketAddr> }

enum Local { Frame(Frame), Finished(u32) }

async fn tcp_flow(id: u32, stream: TcpStream, mut input: mpsc::Receiver<Input>, output: mpsc::Sender<Local>) {
    let (mut rd, mut wr) = stream.into_split();
    let read = async {
        let mut buf = vec![0; 16384];
        loop {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                output.send(Local::Frame(Frame::Eof(id))).await.map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                return Ok::<_, std::io::Error>(());
            }
            output.send(Local::Frame(Frame::Data(id, buf[..n].to_vec()))).await.map_err(|_| std::io::ErrorKind::BrokenPipe)?;
        }
    };
    let write = async {
        while let Some(packet) = input.recv().await {
            match packet {
                Input::Data(bytes) => wr.write_all(&bytes).await?,
                Input::Eof => { wr.shutdown().await?; return Ok::<_, std::io::Error>(()); }
            }
        }
        Err(std::io::ErrorKind::ConnectionAborted.into())
    };
    let _ = tokio::try_join!(read, write);
}

async fn udp_flow(id: u32, socket: UdpSocket, mut input: mpsc::Receiver<Input>, output: mpsc::Sender<Local>) {
    let mut buf = vec![0; 65535];
    loop {
        tokio::select! {
            result = socket.recv(&mut buf) => match result {
                Ok(n) => if output.send(Local::Frame(Frame::Data(id, buf[..n].to_vec()))).await.is_err() { break; },
                Err(_) => break,
            },
            packet = input.recv() => match packet {
                Some(Input::Data(bytes)) => if socket.send(&bytes).await.is_err() { break; },
                _ => break,
            }
        }
    }
}

/// The listener side alone allocates flow IDs. All child sockets and tasks are
/// owned by this future; cancelling it closes the whole tunnel.
pub async fn session(conn: &Connection, binding: Option<Binding>, destination: SocketAddr, udp: bool) -> ApiResult<()> {
    let listening = binding.is_some();
    let mut flows: HashMap<u32, Flow> = HashMap::new();
    let mut peers: HashMap<SocketAddr, u32> = HashMap::new();
    let mut tasks = JoinSet::new();
    let (output, mut events) = mpsc::channel::<Local>(256);
    let mut next_id = 1u32;
    let mut last_remote_id = 0u32;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    let mut last_receive = Instant::now();
    let mut datagram = vec![0; 65535];
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if last_receive.elapsed() > Duration::from_secs(30) { return Err(ApiError::Timeout); }
                send(conn, &Frame::Ping).await?;
                if udp {
                    let expired: Vec<_> = flows.iter().filter(|(_, f)| f.touched.elapsed() > IDLE).map(|(id, _)| *id).collect();
                    for id in expired {
                        if let Some(flow) = flows.remove(&id) {
                            if let Some(peer) = flow.peer { peers.remove(&peer); }
                        }
                        send(conn, &Frame::Close(id)).await?;
                    }
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            Some(event) = events.recv() => match event {
                Local::Frame(frame) => {
                    let id = match &frame { Frame::Data(id, _) | Frame::Eof(id) => Some(*id), _ => None };
                    if let Some(id) = id {
                        if let Some(flow) = flows.get_mut(&id) { flow.touched = Instant::now(); }
                        else { continue; }
                    }
                    send(conn, &frame).await?;
                }
                Local::Finished(id) => {
                    if let Some(flow) = flows.remove(&id) {
                        if let Some(peer) = flow.peer { peers.remove(&peer); }
                        send(conn, &Frame::Close(id)).await?;
                    }
                }
            },
            accepted = async {
                match &binding { Some(Binding::Tcp(listener)) => listener.accept().await, _ => std::future::pending().await }
            } => {
                let (stream, _) = accepted?;
                if flows.len() >= MAX_FLOWS { continue; }
                let id = next_id;
                next_id = next_id.checked_add(1).ok_or_else(|| ApiError::Protocol("flow IDs exhausted".into()))?;
                send(conn, &Frame::Open(id)).await?;
                let (tx, rx) = mpsc::channel(64);
                flows.insert(id, Flow { input: tx, touched: Instant::now(), peer: None });
                let output = output.clone();
                tasks.spawn(async move {
                    tcp_flow(id, stream, rx, output.clone()).await;
                    let _ = output.send(Local::Finished(id)).await;
                });
            }
            packet = async {
                match &binding { Some(Binding::Udp(socket)) => socket.recv_from(&mut datagram).await, _ => std::future::pending().await }
            } => {
                let (n, peer) = packet?;
                let id = match peers.get(&peer) {
                    Some(id) => *id,
                    None => {
                        if flows.len() >= MAX_FLOWS { continue; }
                        let id = next_id;
                        next_id = next_id.checked_add(1).ok_or_else(|| ApiError::Protocol("flow IDs exhausted".into()))?;
                        let (tx, mut rx) = mpsc::channel(64);
                        flows.insert(id, Flow { input: tx, touched: Instant::now(), peer: Some(peer) });
                        peers.insert(peer, id);
                        let socket = match &binding { Some(Binding::Udp(s)) => s.clone(), _ => unreachable!() };
                        let output = output.clone();
                        tasks.spawn(async move {
                            while let Some(Input::Data(data)) = rx.recv().await {
                                if socket.send_to(&data, peer).await.is_err() { break; }
                            }
                            let _ = output.send(Local::Finished(id)).await;
                        });
                        send(conn, &Frame::Open(id)).await?;
                        id
                    }
                };
                flows.get_mut(&id).unwrap().touched = Instant::now();
                send(conn, &Frame::Data(id, datagram[..n].to_vec())).await?;
            }
            frame = recv(conn) => {
                last_receive = Instant::now();
                match frame? {
                    Frame::Ping => send(conn, &Frame::Pong).await?,
                    Frame::Pong => {},
                    Frame::Open(id) => {
                        if listening || id <= last_remote_id { return Err(ApiError::Protocol("invalid forwarding flow".into())); }
                        last_remote_id = id;
                        if flows.len() >= MAX_FLOWS { send(conn, &Frame::Close(id)).await?; continue; }
                        let (tx, rx) = mpsc::channel(64);
                        flows.insert(id, Flow { input: tx, touched: Instant::now(), peer: None });
                        let output = output.clone();
                        tasks.spawn(async move {
                            if udp {
                                let bind = if destination.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                                if let Ok(socket) = UdpSocket::bind(bind).await {
                                    if socket.connect(destination).await.is_ok() { udp_flow(id, socket, rx, output.clone()).await; }
                                }
                            } else if let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(destination)).await {
                                tcp_flow(id, stream, rx, output.clone()).await;
                            }
                            let _ = output.send(Local::Finished(id)).await;
                        });
                    }
                    Frame::Data(id, data) => {
                        if data.len() > 65535 { return Err(ApiError::Protocol("forward payload too large".into())); }
                        if let Some(flow) = flows.get_mut(&id) {
                            flow.touched = Instant::now();
                            // Backpressure is bounded per flow. Do not let an unresponsive
                            // application block control messages and all other streams.
                            if flow.input.try_send(Input::Data(data)).is_err() {
                                if let Some(flow) = flows.remove(&id) {
                                    if let Some(peer) = flow.peer { peers.remove(&peer); }
                                }
                                send(conn, &Frame::Close(id)).await?;
                            }
                        }
                    }
                    Frame::Eof(id) if !udp => {
                        if let Some(flow) = flows.get(&id) {
                            if flow.input.try_send(Input::Eof).is_err() { flows.remove(&id); send(conn, &Frame::Close(id)).await?; }
                        }
                    }
                    Frame::Close(id) => {
                        if let Some(flow) = flows.remove(&id) {
                            if let Some(peer) = flow.peer { peers.remove(&peer); }
                        }
                    }
                    Frame::Error(e) => return Err(ApiError::Service(e)),
                    _ => return Err(ApiError::Protocol("unexpected forwarding frame".into())),
                }
            }
        }
    }
}
