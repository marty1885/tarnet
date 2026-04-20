use std::net::SocketAddr;
use std::sync::Arc;

use log::{debug, error, info, warn};
use tarnet_api::service::{PortMode, ServiceApi, TnsRecord, TnsResolution};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::socks5;

/// Where to route a connection.
#[derive(Debug)]
enum Route {
    /// Route through tarnet to a ServiceId + port.
    Tarnet {
        service_id: tarnet_api::types::ServiceId,
        service_name: String,
        port: u16,
    },
    /// Fall through to clearnet (direct TCP).
    Clearnet { host: String, port: u16 },
    /// Refuse the connection (clearnet disallowed, TNS not found).
    Refused,
}

/// State shared across the proxy.
struct ProxyState<S: ServiceApi> {
    api: Arc<S>,
    allow_clearnet: bool,
}

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
            let identity = req.identity.clone();
            let route =
                resolve_route(&state, &req.hostname, req.port, identity.as_deref()).await;

            match route {
                Route::Tarnet {
                    service_id,
                    service_name,
                    port,
                } => {
                    handle_tarnet_route(
                        state,
                        stream,
                        service_id,
                        &service_name,
                        port,
                        identity.as_deref(),
                    )
                    .await
                }
                Route::Clearnet { host, port } => {
                    handle_clearnet_route(stream, &host, port).await
                }
                Route::Refused => {
                    warn!("Refusing connection to {}:{}", req.hostname, req.port);
                    socks5::send_host_unreachable(&mut stream).await?;
                    Ok(())
                }
            }
        }
        socks5::SocksCommand::UdpAssociate => {
            debug!("UDP ASSOCIATE request: {}:{}", req.hostname, req.port);
            handle_udp_associate(state, stream, &req).await
        }
    }
}

async fn resolve_route<S: ServiceApi>(
    state: &ProxyState<S>,
    hostname: &str,
    port: u16,
    identity: Option<&str>,
) -> Route {
    // Try TNS resolution — from a specific identity's zone if requested.
    let result = if let Some(id_label) = identity {
        match state.api.resolve_identity(id_label).await {
            Ok(zone_sid) => state.api.tns_resolve(zone_sid, hostname).await,
            Err(e) => {
                warn!("Unknown identity '{}': {}", id_label, e);
                state.api.tns_resolve_name(hostname).await
            }
        }
    } else {
        state.api.tns_resolve_name(hostname).await
    };

    match result {
        Ok(TnsResolution::Records(records)) => {
            // Look for Identity records.
            let service_name = first_label(hostname);

            for rec in &records {
                if let TnsRecord::Identity(sid) = rec {
                    return Route::Tarnet {
                        service_id: *sid,
                        service_name: service_name.to_string(),
                        port,
                    };
                }
            }

            // Records found but no routable ones.
            if state.allow_clearnet {
                Route::Clearnet {
                    host: hostname.to_string(),
                    port,
                }
            } else {
                warn!(
                    "TNS records found but no routable Identity for {}",
                    hostname
                );
                Route::Refused
            }
        }
        Ok(TnsResolution::NotFound) | Ok(TnsResolution::Error(_)) => {
            if state.allow_clearnet {
                Route::Clearnet {
                    host: hostname.to_string(),
                    port,
                }
            } else {
                warn!("TNS not found for {} and clearnet disallowed", hostname);
                Route::Refused
            }
        }
        Err(e) => {
            warn!("TNS resolve error for {}: {}", hostname, e);
            if state.allow_clearnet {
                Route::Clearnet {
                    host: hostname.to_string(),
                    port,
                }
            } else {
                Route::Refused
            }
        }
    }
}

async fn handle_tarnet_route<S: ServiceApi + 'static>(
    state: Arc<ProxyState<S>>,
    mut stream: TcpStream,
    service_id: tarnet_api::types::ServiceId,
    service_name: &str,
    port: u16,
    identity: Option<&str>,
) -> std::io::Result<()> {
    info!(
        "Tarnet route to {} service={} port={}",
        service_id, service_name, port
    );

    // Resolve source identity ServiceId for connect_as.
    let source_sid = if let Some(id_label) = identity {
        state.api.resolve_identity(id_label).await.ok()
    } else {
        None
    };

    // Try the service name (hostname first label) as the port name first.
    // Subdomain services register using their subdomain as the port name,
    // so e.g. "nina" in "nina.service-directory" maps to port "nina".
    // Fall back to the numeric URL port for apex services.
    let conn = match state
        .api
        .connect_as(
            service_id,
            PortMode::ReliableOrdered,
            service_name,
            source_sid,
        )
        .await
    {
        Ok(c) => c,
        Err(_) => {
            let port_name = port.to_string();
            match state
                .api
                .connect_as(
                    service_id,
                    PortMode::ReliableOrdered,
                    &port_name,
                    source_sid,
                )
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to connect to {}: {}", service_id, e);
                    socks5::send_host_unreachable(&mut stream).await?;
                    return Ok(());
                }
            }
        }
    };

    // Send SOCKS5 success.
    socks5::send_success(&mut stream).await?;

    // Shuttle bytes between SOCKS client and circuit connection.
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

    let relay_task = tokio::spawn(async move {
        // Wait for the first datagram to know where to connect.
        let (hostname, port, first_payload) = match inbound_rx.recv().await {
            Some(v) => v,
            None => return,
        };

        let route = resolve_route(&state, &hostname, port, identity.as_deref()).await;

        match route {
            Route::Tarnet {
                service_id,
                service_name,
                port,
                ..
            } => {
                info!(
                    "UDP Tarnet route to {} service={} port={}",
                    service_id, service_name, port
                );

                // Resolve source identity for connect_as.
                let source_sid = if let Some(ref id_label) = identity {
                    state.api.resolve_identity(id_label).await.ok()
                } else {
                    None
                };

                let port_name = port.to_string();
                let conn = match state
                    .api
                    .connect_as(
                        service_id,
                        PortMode::UnreliableUnordered,
                        &port_name,
                        source_sid,
                    )
                    .await
                {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        error!("Failed to connect UDP to {}: {}", service_id, e);
                        return;
                    }
                };

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
            Route::Clearnet { host, port } => {
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
            Route::Refused => {
                warn!("Refusing UDP association to {}:{}", hostname, port);
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

/// Extract the first label from a dot-separated hostname.
/// e.g., "web.alice" -> "web", "ssh.bob.carol" -> "ssh"
fn first_label(hostname: &str) -> &str {
    hostname.split('.').next().unwrap_or(hostname)
}
