use std::net::SocketAddr;
use std::sync::Arc;

use log::{debug, error, info, warn};
use tarnet_api::service::{PortMode, ServiceApi};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::socks5;

/// State shared across the proxy.
struct ProxyState<S: ServiceApi> {
    api: Arc<S>,
    allow_clearnet: bool,
    /// Round-robin cursor per (pool, service) for endpoint selection.
    rr: std::sync::Mutex<std::collections::HashMap<(String, String), usize>>,
}

impl<S: ServiceApi> ProxyState<S> {
    /// Next round-robin start index for a pool service, advancing the cursor.
    fn next_rr(&self, pool: &str, service: &str, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let mut map = self.rr.lock().unwrap();
        let key = (pool.to_string(), service.to_string());
        let cur = map.entry(key).or_insert(0);
        let idx = *cur % len;
        *cur = idx.wrapping_add(1);
        idx
    }
}

/// How long to wait for a pool resolution before giving up (seconds).
const POOL_RESOLVE_TIMEOUT_SECS: u32 = 5;

/// Run the SOCKS5 proxy on one or more bind addresses.
///
/// If an individual bind fails, logs a warning and continues.
/// Returns an error only if zero addresses bind successfully.
/// The proxy runs until `shutdown` is signaled.
pub async fn run_proxy<S: ServiceApi + 'static>(
    api: Arc<S>,
    bind_addrs: &[SocketAddr],
    allow_clearnet: bool,
    mut shutdown: mpsc::Receiver<()>,
) -> std::io::Result<Vec<SocketAddr>> {
    let mut bound = Vec::new();
    let mut listeners = Vec::new();

    for addr in bind_addrs {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                let local = listener.local_addr()?;
                info!("SOCKS5 proxy listening on {}", local);
                bound.push(local);
                listeners.push(listener);
            }
            Err(e) => {
                warn!("Failed to bind SOCKS5 on {}: {}", addr, e);
            }
        }
    }

    if listeners.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no SOCKS5 bind addresses succeeded",
        ));
    }

    let state = Arc::new(ProxyState {
        api: api.clone(),
        allow_clearnet,
        rr: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    // Spawn an accept loop per listener.
    for listener in listeners {
        let state_accept = state.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("SOCKS5 connection from {}", addr);
                        let st = state_accept.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(st, stream).await {
                                debug!("Client error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("SOCKS5 accept error: {}", e);
                    }
                }
            }
        });
    }

    // Wait for shutdown signal.
    tokio::spawn(async move {
        shutdown.recv().await;
        info!("SOCKS5 proxy shutting down");
    });

    Ok(bound)
}

async fn handle_client<S: ServiceApi + 'static>(
    state: Arc<ProxyState<S>>,
    mut stream: TcpStream,
) -> std::io::Result<()> {
    let req = socks5::server_handshake(&mut stream).await?;

    match req.command {
        socks5::SocksCommand::Connect => {
            debug!("CONNECT request: {}:{}", req.hostname, req.port);

            // Pool route: if the rightmost label names a joined pool, resolve as
            // a pool service (e.g. "payment.mycluster" → service "payment" in
            // pool "mycluster") with round-robin + failover.
            if let Some((pool, service)) = pool_match(&state, &req.hostname).await {
                return handle_pool_route(state, stream, &pool, &service).await;
            }

            handle_connect(state, stream, &req.hostname, req.port).await
        }
        socks5::SocksCommand::UdpAssociate => {
            debug!("UDP ASSOCIATE request: {}:{}", req.hostname, req.port);
            handle_udp_associate(state, stream, &req).await
        }
    }
}

/// If the rightmost label of `hostname` names a joined pool, return
/// `(pool, service)`. Pools are addressed `<service>.<pool>`.
async fn pool_match<S: ServiceApi>(
    state: &ProxyState<S>,
    hostname: &str,
) -> Option<(String, String)> {
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let pool_name = labels[labels.len() - 1];
    let pools = state.api.pool_list().await.ok()?;
    if pools.iter().any(|(n, _)| n == pool_name) {
        Some((pool_name.to_string(), labels[0].to_string()))
    } else {
        None
    }
}

/// Route a CONNECT through the single `connect_to` chokepoint. The daemon
/// resolves the target (SID / VHost / apex Identity) and *derives* the wire
/// port from the canonical label + supplied port — no first-label heuristic, no
/// numeric fallback. On failure, fall through to clearnet if allowed.
async fn handle_connect<S: ServiceApi + 'static>(
    state: Arc<ProxyState<S>>,
    mut stream: TcpStream,
    hostname: &str,
    port: u16,
) -> std::io::Result<()> {
    match state
        .api
        .connect_to(hostname, PortMode::ReliableOrdered, &port.to_string())
        .await
    {
        Ok(conn) => {
            info!("Tarnet route to {}:{}", hostname, port);
            socks5::send_success(&mut stream).await?;
            splice(stream, conn).await;
            Ok(())
        }
        Err(e) => {
            if state.allow_clearnet {
                debug!("connect_to {} failed ({}), falling through to clearnet", hostname, e);
                handle_clearnet_route(stream, hostname, port).await
            } else {
                warn!("Refusing connection to {}:{}: {}", hostname, port, e);
                socks5::send_host_unreachable(&mut stream).await?;
                Ok(())
            }
        }
    }
}

/// Shuttle bytes bidirectionally between a SOCKS client TCP stream and a tarnet
/// circuit connection until either side closes.
async fn splice(stream: TcpStream, conn: tarnet_api::service::Connection) {
    let (mut read_half, mut write_half) = stream.into_split();
    let conn = Arc::new(conn);

    let conn_send = conn.clone();
    let upload = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if conn_send.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let download = tokio::spawn(async move {
        loop {
            match conn.recv().await {
                Ok(payload) => {
                    if write_half.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let _ = tokio::join!(upload, download);
}

/// Route a connection to a pool service: resolve the live endpoint set, pick one
/// round-robin, and fail over to the next on circuit-connect failure (liveness tier 1).
async fn handle_pool_route<S: ServiceApi + 'static>(
    state: Arc<ProxyState<S>>,
    mut stream: TcpStream,
    pool: &str,
    service: &str,
) -> std::io::Result<()> {
    let endpoints = state
        .api
        .pool_resolve(pool, service, POOL_RESOLVE_TIMEOUT_SECS)
        .await
        .unwrap_or_default();

    if endpoints.is_empty() {
        warn!("No endpoints for pool '{}' service '{}'", pool, service);
        socks5::send_host_unreachable(&mut stream).await?;
        return Ok(());
    }

    // Round-robin start, then try each endpoint in turn (failover).
    let n = endpoints.len();
    let start = state.next_rr(pool, service, n);
    let mut conn = None;
    for i in 0..n {
        let ep = &endpoints[(start + i) % n];
        match state
            .api
            .connect_via(ep.owner, PortMode::ReliableOrdered, &ep.port, ep.peer_id)
            .await
        {
            Ok(c) => {
                info!(
                    "Pool '{}' service '{}' -> endpoint {} (port {})",
                    pool, service, ep.owner, ep.port
                );
                conn = Some(c);
                break;
            }
            Err(e) => {
                warn!(
                    "Pool '{}' endpoint {} unreachable, failing over: {}",
                    pool, ep.owner, e
                );
            }
        }
    }

    let conn = match conn {
        Some(c) => c,
        None => {
            error!("All {} endpoint(s) for pool '{}' failed", n, pool);
            socks5::send_host_unreachable(&mut stream).await?;
            return Ok(());
        }
    };

    socks5::send_success(&mut stream).await?;
    splice(stream, conn).await;
    Ok(())
}

async fn handle_clearnet_route(
    mut stream: TcpStream,
    host: &str,
    port: u16,
) -> std::io::Result<()> {
    info!("Clearnet route to {}:{}", host, port);

    let target = format!("{}:{}", host, port);
    match TcpStream::connect(&target).await {
        Ok(mut remote) => {
            socks5::send_success(&mut stream).await?;

            let (mut ri, mut wi) = stream.split();
            let (mut ro, mut wo) = remote.split();

            tokio::select! {
                r = tokio::io::copy(&mut ri, &mut wo) => {
                    if let Err(e) = r { debug!("copy client->remote: {}", e); }
                }
                r = tokio::io::copy(&mut ro, &mut wi) => {
                    if let Err(e) = r { debug!("copy remote->client: {}", e); }
                }
            }
        }
        Err(e) => {
            error!("Clearnet connect to {} failed: {}", target, e);
            socks5::send_host_unreachable(&mut stream).await?;
        }
    }

    Ok(())
}

/// Handle a SOCKS5 UDP ASSOCIATE request.
///
/// Binds a local UDP relay socket, tells the client about it, then relays
/// datagrams between the UDP socket and a tarnet UnreliableUnordered channel.
/// The association lives until the TCP control connection drops.
async fn handle_udp_associate<S: ServiceApi + 'static>(
    state: Arc<ProxyState<S>>,
    mut stream: TcpStream,
    req: &socks5::ConnectRequest,
) -> std::io::Result<()> {
    // Bind a local UDP socket on the same interface as the TCP control connection.
    // Use port 0 to let the OS pick an available port.
    let local_tcp_addr = stream.local_addr()?;
    let udp_bind_addr = SocketAddr::new(local_tcp_addr.ip(), 0);
    let udp_socket = UdpSocket::bind(udp_bind_addr).await?;
    let udp_local_addr = udp_socket.local_addr()?;

    debug!("UDP relay socket bound on {}", udp_local_addr);

    // Tell the client the address of our UDP relay socket.
    socks5::send_success_with_addr(&mut stream, udp_local_addr).await?;

    let udp_socket = Arc::new(udp_socket);

    // The client address for the UDP relay. Per RFC 1928, the client sends
    // datagrams from the address specified in the request (or any address if
    // 0.0.0.0:0). We track the actual client address from the first datagram.
    let client_addr: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    // Channel to signal shutdown when the TCP control connection drops.
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Monitor the TCP control connection — when it closes, shut everything down.
    let tcp_monitor = tokio::spawn(async move {
        let mut buf = [0u8; 1];
        // read will return Ok(0) or Err when the client disconnects.
        let _ = stream.read(&mut buf).await;
        debug!("UDP ASSOCIATE TCP control connection closed");
        drop(shutdown_tx);
    });

    // Channel for parsed datagrams from the UDP socket to the relay logic.
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<(String, u16, Vec<u8>)>(64);

    // Task: receive datagrams from the UDP socket and parse the SOCKS5 UDP header.
    let udp_recv = udp_socket.clone();
    let client_addr_recv = client_addr.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match udp_recv.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("UDP recv_from error: {}", e);
                    break;
                }
            };

            // Track the client address from the first datagram.
            {
                let mut addr = client_addr_recv.lock().await;
                if addr.is_none() {
                    *addr = Some(peer);
                }
            }

            // Parse the SOCKS5 UDP request header.
            // RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2) + DATA
            if n < 4 {
                debug!("UDP datagram too short ({} bytes), dropping", n);
                continue;
            }

            let frag = buf[2];
            if frag != 0 {
                // Drop fragmented packets — no fragmentation support.
                debug!("Dropping fragmented UDP packet (frag={})", frag);
                continue;
            }

            let atyp = buf[3];
            let (hostname, port, data_offset) = match parse_udp_addr(&buf[..n], atyp) {
                Some(r) => r,
                None => {
                    debug!("Failed to parse UDP SOCKS5 address header");
                    continue;
                }
            };

            let data = buf[data_offset..n].to_vec();
            if inbound_tx.send((hostname, port, data)).await.is_err() {
                break;
            }
        }
    });

    // Process datagrams: resolve route once per (hostname, port) pair, relay to tarnet.
    // For simplicity, we resolve on the first datagram and keep the connection for the
    // lifetime of the association.
    let identity = req.identity.clone();
    let udp_send = udp_socket.clone();
    let client_addr_send = client_addr.clone();

    let allow_clearnet = state.allow_clearnet;
    let relay_task = tokio::spawn(async move {
        // Wait for the first datagram to know where to connect.
        let (hostname, port, first_payload) = match inbound_rx.recv().await {
            Some(v) => v,
            None => return,
        };

        // Pool services over UDP are not supported in Phase 1.
        let _ = &identity;
        if let Some((pool, _)) = pool_match(&state, &hostname).await {
            warn!("UDP to pool '{}' not supported; refusing", pool);
            return;
        }

        // Try tarnet via the single connect_to chokepoint (derives the wire port).
        let tarnet_conn = state
            .api
            .connect_to(&hostname, PortMode::UnreliableUnordered, &port.to_string())
            .await;

        match tarnet_conn {
            Ok(c) => {
                info!("UDP Tarnet route to {}:{}", hostname, port);
                let conn = Arc::new(c);

                // Send the first datagram.
                if let Err(e) = conn.send(&first_payload).await {
                    error!("Failed to send first UDP datagram: {}", e);
                    return;
                }

                // Forward client -> tarnet.
                let conn_up = conn.clone();
                let upload = tokio::spawn(async move {
                    while let Some((_host, _port, data)) = inbound_rx.recv().await {
                        if conn_up.send(&data).await.is_err() {
                            break;
                        }
                    }
                });

                // Forward tarnet -> client.
                let download = tokio::spawn(async move {
                    loop {
                        let payload = match conn.recv().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };

                        let addr = {
                            let guard = client_addr_send.lock().await;
                            match *guard {
                                Some(a) => a,
                                None => continue,
                            }
                        };

                        // Build the SOCKS5 UDP response header.
                        let header =
                            build_udp_header(&hostname, port);
                        let mut packet = Vec::with_capacity(header.len() + payload.len());
                        packet.extend_from_slice(&header);
                        packet.extend_from_slice(&payload);

                        if let Err(e) = udp_send.send_to(&packet, addr).await {
                            debug!("UDP send_to error: {}", e);
                            break;
                        }
                    }
                });

                tokio::select! {
                    _ = upload => {}
                    _ = download => {}
                    _ = shutdown_rx.recv() => {
                        debug!("UDP ASSOCIATE shutting down (TCP control closed)");
                    }
                }
            }
            Err(e) if !allow_clearnet => {
                warn!(
                    "Refusing UDP association to {}:{}: {}",
                    hostname, port, e
                );
            }
            Err(e) => {
                debug!(
                    "UDP connect_to {} failed ({}), falling through to clearnet",
                    hostname, e
                );
                let host = hostname.clone();
                info!("UDP clearnet relay to {}:{}", host, port);

                // Resolve destination address.
                let dest_addr = match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(a) => a,
                        None => {
                            error!("No addresses for {}:{}", host, port);
                            return;
                        }
                    },
                    Err(e) => {
                        error!("DNS lookup failed for {}:{}: {}", host, port, e);
                        return;
                    }
                };

                // Bind a second UDP socket for clearnet forwarding.
                let clearnet_udp = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        error!("Failed to bind clearnet UDP socket: {}", e);
                        return;
                    }
                };

                // Send the first datagram.
                if let Err(e) = clearnet_udp.send_to(&first_payload, dest_addr).await {
                    error!("Failed to send first UDP datagram to clearnet: {}", e);
                    return;
                }

                // Forward client -> clearnet.
                let clearnet_up = clearnet_udp.clone();
                let upload = tokio::spawn(async move {
                    while let Some((_host, _port, data)) = inbound_rx.recv().await {
                        if clearnet_up.send_to(&data, dest_addr).await.is_err() {
                            break;
                        }
                    }
                });

                // Forward clearnet -> client.
                let download = tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    loop {
                        let (n, _peer) = match clearnet_udp.recv_from(&mut buf).await {
                            Ok(r) => r,
                            Err(e) => {
                                debug!("Clearnet UDP recv error: {}", e);
                                break;
                            }
                        };

                        let addr = {
                            let guard = client_addr_send.lock().await;
                            match *guard {
                                Some(a) => a,
                                None => continue,
                            }
                        };

                        let header = build_udp_header(&host, port);
                        let mut packet = Vec::with_capacity(header.len() + n);
                        packet.extend_from_slice(&header);
                        packet.extend_from_slice(&buf[..n]);

                        if let Err(e) = udp_send.send_to(&packet, addr).await {
                            debug!("UDP send_to client error: {}", e);
                            break;
                        }
                    }
                });

                tokio::select! {
                    _ = upload => {}
                    _ = download => {}
                    _ = shutdown_rx.recv() => {
                        debug!("UDP ASSOCIATE shutting down (TCP control closed)");
                    }
                }
            }
        }
    });

    let _ = tokio::join!(tcp_monitor, recv_task, relay_task);
    Ok(())
}

/// Parse the address portion of a SOCKS5 UDP request header.
/// Returns (hostname, port, data_offset) or None on failure.
fn parse_udp_addr(buf: &[u8], atyp: u8) -> Option<(String, u16, usize)> {
    match atyp {
        0x01 => {
            // IPv4: 4 bytes addr + 2 bytes port, starting at offset 4
            if buf.len() < 10 {
                return None;
            }
            let hostname = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Some((hostname, port, 10))
        }
        0x03 => {
            // Domain name: 1 byte length + domain + 2 bytes port
            if buf.len() < 5 {
                return None;
            }
            let len = buf[4] as usize;
            if buf.len() < 5 + len + 2 {
                return None;
            }
            let hostname = String::from_utf8(buf[5..5 + len].to_vec()).ok()?;
            let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
            Some((hostname, port, 5 + len + 2))
        }
        0x04 => {
            // IPv6: 16 bytes addr + 2 bytes port
            if buf.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let addr = std::net::Ipv6Addr::from(octets);
            let hostname = addr.to_string();
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Some((hostname, port, 22))
        }
        _ => None,
    }
}

/// Build a SOCKS5 UDP response header: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT.
fn build_udp_header(hostname: &str, port: u16) -> Vec<u8> {
    let mut header = Vec::new();
    // RSV + FRAG
    header.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Try to parse as IPv4 first, then IPv6, fall back to domain.
    if let Ok(v4) = hostname.parse::<std::net::Ipv4Addr>() {
        header.push(0x01);
        header.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = hostname.parse::<std::net::Ipv6Addr>() {
        header.push(0x04);
        header.extend_from_slice(&v6.octets());
    } else {
        header.push(0x03);
        header.push(hostname.len() as u8);
        header.extend_from_slice(hostname.as_bytes());
    }

    header.extend_from_slice(&port.to_be_bytes());
    header
}
