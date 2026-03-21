use std::net::SocketAddr;
use std::sync::Arc;

use log::{debug, error, info, warn};
use tarnet_api::service::{ServiceApi, TnsRecord, TnsResolution};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    debug!("CONNECT request: {}:{}", req.hostname, req.port);

    let identity = req.identity.clone();
    let route = resolve_route(&state, &req.hostname, req.port, identity.as_deref()).await;

    match route {
        Route::Tarnet { service_id, service_name, port } => {
            handle_tarnet_route(state, stream, service_id, &service_name, port, identity.as_deref()).await
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
                warn!("TNS records found but no routable Identity for {}", hostname);
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
    info!("Tarnet route to {} service={} port={}", service_id, service_name, port);

    // Resolve source identity ServiceId for connect_as.
    let source_sid = if let Some(id_label) = identity {
        state.api.resolve_identity(id_label).await.ok()
    } else {
        None
    };

    let conn = match state.api.connect_as(service_id, port, source_sid).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to {}: {}", service_id, e);
            socks5::send_host_unreachable(&mut stream).await?;
            return Ok(());
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

/// Extract the first label from a dot-separated hostname.
/// e.g., "web.alice" -> "web", "ssh.bob.carol" -> "ssh"
fn first_label(hostname: &str) -> &str {
    hostname.split('.').next().unwrap_or(hostname)
}
