//! IPC server: accepts Unix socket connections from clients and dispatches
//! requests to the ServiceApi. Each client gets its own task with auto-subscribed events.

use std::collections::HashMap;
use std::sync::Arc;

use rand::Rng;
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use tarnet_api::error::ApiResult;
use tarnet_api::ipc::*;
use tarnet_api::service::{Connection, Listener, ListenerOptions, NodeEvent, ServiceApi};
use tarnet_api::types::{DhtId, IdentityScheme, PeerId, PrivacyLevel, ServiceId};

/// Per-client connection table: maps conn_id -> Connection.
/// Shared between the dispatch task and event-pushing tasks.
type ConnTable = Arc<Mutex<HashMap<u32, Arc<Connection>>>>;
type ListenerTable = Arc<Mutex<HashMap<u32, Listener>>>;

/// Allocate an opaque client-local handle ID for a connection.
/// The handle space is scoped to a single Unix socket connection.
fn allocate_client_conn_id(conns: &HashMap<u32, Arc<Connection>>) -> u32 {
    let mut rng = rand::thread_rng();
    loop {
        let conn_id = rng.gen::<u32>();
        if conn_id != 0 && !conns.contains_key(&conn_id) {
            return conn_id;
        }
    }
}

fn allocate_client_listener_id(listeners: &HashMap<u32, Listener>) -> u32 {
    let mut rng = rand::thread_rng();
    loop {
        let listener_id = rng.gen::<u32>();
        if listener_id != 0 && !listeners.contains_key(&listener_id) {
            return listener_id;
        }
    }
}

async fn register_connection(
    conns: &ConnTable,
    conn: Connection,
    writer: &Arc<Mutex<OwnedWriteHalf>>,
) -> ConnectResp {
    let internal_conn_id = conn.id;
    let remote_service_id = conn.remote_service_id;
    let conn = Arc::new(conn);

    let client_conn_id = {
        let mut guard = conns.lock().await;
        let client_conn_id = allocate_client_conn_id(&guard);
        guard.insert(client_conn_id, conn.clone());
        client_conn_id
    };

    log::debug!(
        "IPC connection registered: client_conn_id={} internal_conn_id={}",
        client_conn_id,
        internal_conn_id
    );

    spawn_conn_recv_relay(client_conn_id, conn.clone(), writer.clone(), conns.clone());

    ConnectResp {
        conn_id: client_conn_id,
        remote_service_id,
        port: conn.port,
    }
}

async fn register_listener(listeners: &ListenerTable, listener: Listener) -> ListenResp {
    let client_listener_id = {
        let mut guard = listeners.lock().await;
        let client_listener_id = allocate_client_listener_id(&guard);
        guard.insert(client_listener_id, listener);
        client_listener_id
    };

    ListenResp {
        listener: Listener {
            id: client_listener_id,
            service_id: listener.service_id,
            port: listener.port,
            options: listener.options,
        },
    }
}

async fn close_client_listeners(api: &dyn ServiceApi, listeners: &ListenerTable) {
    let listeners: Vec<Listener> = listeners.lock().await.drain().map(|(_, listener)| listener).collect();
    for listener in listeners {
        if let Err(e) = api.close_listener(&listener).await {
            log::debug!("Failed to close IPC listener {}: {}", listener.id, e);
        }
    }
}

/// Run the IPC server on the given Unix socket path.
/// Accepts client connections and dispatches requests to the service API.
/// `expose_reload_tx` sends reload requests to the expose service with error feedback.
pub async fn run_ipc_server(
    socket_path: std::path::PathBuf,
    api: Arc<dyn ServiceApi>,
    reload_notify: Arc<tokio::sync::Notify>,
    expose_reload_tx: Option<tarnet_expose::expose::ReloadSender>,
) -> ApiResult<()> {
    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove stale socket
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    log::info!("IPC listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let client_api = api.clone();
                let client_reload = reload_notify.clone();
                let client_expose_reload = expose_reload_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, client_api, client_reload, client_expose_reload).await {
                        log::debug!("IPC client disconnected: {}", e);
                    }
                });
            }
            Err(e) => {
                log::error!("IPC accept error: {}", e);
            }
        }
    }
}

/// Handle a single IPC client connection.
/// Auto-subscribes to all events and starts relaying them immediately.
async fn handle_client(
    mut stream: UnixStream,
    api: Arc<dyn ServiceApi>,
    reload_notify: Arc<tokio::sync::Notify>,
    expose_reload_tx: Option<tarnet_expose::expose::ReloadSender>,
) -> ApiResult<()> {
    // Version handshake before splitting the stream
    let _negotiated_version = tarnet_api::ipc::handshake_server(&mut stream).await?;

    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let conns: ConnTable = Arc::new(Mutex::new(HashMap::new()));
    let listeners: ListenerTable = Arc::new(Mutex::new(HashMap::new()));

    // Auto-subscribe: start relaying all events to this client immediately.
    if let Ok(mut rx) = api.subscribe_events().await {
        let w = writer.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let (event_type, payload) = match &event {
                    NodeEvent::Data { .. } => (EVENT_DATA, encode_payload(&event)),
                    NodeEvent::Tunnel { .. } => (EVENT_TUNNEL, encode_payload(&event)),
                    NodeEvent::Watch(..) => (EVENT_WATCH, encode_payload(&event)),
                    NodeEvent::PeerDisconnected(_) => {
                        // Not relayed to IPC clients.
                        continue;
                    }
                };
                let frame = IpcFrame::Event {
                    event_type,
                    payload,
                };
                let mut w = w.lock().await;
                if send_frame(&mut *w, &frame).await.is_err() {
                    break;
                }
            }
        });
    }

    let result: ApiResult<()> = loop {
        let frame = match recv_frame(&mut reader).await {
            Ok(frame) => frame,
            Err(e) => break Err(e),
        };

        match frame {
            IpcFrame::Request {
                request_id,
                method,
                payload,
            } => {
                match method {
                    // Connection data send: handled inline (needs conn table).
                    METHOD_CONN_SEND => {
                        let req: ConnSendReq = match decode_payload(&payload) {
                            Ok(v) => v,
                            Err(e) => {
                                let mut w = writer.lock().await;
                                let _ = send_frame(&mut *w, &err_response(request_id, &e.to_string())).await;
                                continue;
                            }
                        };
                        let conns = conns.clone();
                        let writer = writer.clone();
                        tokio::spawn(async move {
                            let guard = conns.lock().await;
                            let response = if let Some(conn) = guard.get(&req.conn_id) {
                                match conn.send(&req.data).await {
                                    Ok(()) => ok_response(request_id, &[]),
                                    Err(e) => err_response(request_id, &e.to_string()),
                                }
                            } else {
                                err_response(request_id, "unknown connection id")
                            };
                            drop(guard);
                            let mut w = writer.lock().await;
                            let _ = send_frame(&mut *w, &response).await;
                        });
                    }
                    METHOD_RELOAD => {
                        log::info!("Reload requested via IPC");
                        // Always notify generic reload listeners (bandwidth, etc.)
                        reload_notify.notify_waiters();
                        // Send reload request to expose with error feedback.
                        let response = if let Some(ref tx) = expose_reload_tx {
                            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                            if tx.send(reply_tx).await.is_ok() {
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(10),
                                    reply_rx,
                                ).await {
                                    Ok(Ok(Ok(()))) => ok_response(request_id, &[]),
                                    Ok(Ok(Err(e))) => err_response(request_id, &e),
                                    Ok(Err(_)) => err_response(request_id, "expose reload cancelled"),
                                    Err(_) => err_response(request_id, "expose reload timed out"),
                                }
                            } else {
                                err_response(request_id, "expose service not running")
                            }
                        } else {
                            ok_response(request_id, &[])
                        };
                        let mut w = writer.lock().await;
                        let _ = send_frame(&mut *w, &response).await;
                    }
                    METHOD_CONN_CLOSE => {
                        let conn_id: u32 = match decode_payload(&payload) {
                            Ok(v) => v,
                            Err(_) => {
                                let mut w = writer.lock().await;
                                let _ = send_frame(&mut *w, &ok_response(request_id, &[])).await;
                                continue;
                            }
                        };
                        conns.lock().await.remove(&conn_id);
                        let mut w = writer.lock().await;
                        let _ = send_frame(&mut *w, &ok_response(request_id, &[])).await;
                    }
                    METHOD_LISTENER_CLOSE => {
                        let client_listener_id: u32 = match decode_payload(&payload) {
                            Ok(v) => v,
                            Err(_) => {
                                let mut w = writer.lock().await;
                                let _ = send_frame(&mut *w, &ok_response(request_id, &[])).await;
                                continue;
                            }
                        };
                        let listener = listeners.lock().await.remove(&client_listener_id);
                        let response = match listener {
                            Some(listener) => match api.close_listener(&listener).await {
                                Ok(()) => ok_response(request_id, &[]),
                                Err(e) => err_response(request_id, &e.to_string()),
                            },
                            None => err_response(request_id, "unknown listener id"),
                        };
                        let mut w = writer.lock().await;
                        let _ = send_frame(&mut *w, &response).await;
                    }
                    _ => {
                        let api = api.clone();
                        let writer = writer.clone();
                        let conns = conns.clone();
                        let listeners = listeners.clone();
                        // Handle each request concurrently so one slow DHT lookup
                        // doesn't block quick peer_id queries.
                        tokio::spawn(async move {
                            let response =
                                dispatch_request(&*api, method, &payload, request_id, &writer, &conns, &listeners).await;
                            let mut w = writer.lock().await;
                            if let Err(e) = send_frame(&mut *w, &response).await {
                                log::debug!("Failed to send IPC response: {}", e);
                            }
                        });
                    }
                }
            }
            _ => {
                log::warn!("Unexpected frame type from client");
            }
        }
    };

    close_client_listeners(&*api, &listeners).await;
    result
}

/// Spawn a task that relays conn.recv() -> EVENT_CONN_DATA / EVENT_CONN_CLOSED to the client.
fn spawn_conn_recv_relay(
    conn_id: u32,
    conn: Arc<Connection>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    conns: ConnTable,
) {
    tokio::spawn(async move {
        loop {
            match conn.recv().await {
                Ok(data) => {
                    let payload = encode_payload(&ConnDataEvent { conn_id, data });
                    let frame = IpcFrame::Event {
                        event_type: EVENT_CONN_DATA,
                        payload,
                    };
                    let mut w = writer.lock().await;
                    if send_frame(&mut *w, &frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    conns.lock().await.remove(&conn_id);
                    let frame = IpcFrame::Event {
                        event_type: EVENT_CONN_CLOSED,
                        payload: encode_payload(&conn_id),
                    };
                    let mut w = writer.lock().await;
                    let _ = send_frame(&mut *w, &frame).await;
                    break;
                }
            }
        }
    });
}

/// Dispatch a request to the appropriate ServiceApi method and build a response.
async fn dispatch_request(
    api: &dyn ServiceApi,
    method: u16,
    payload: &[u8],
    request_id: u32,
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    conns: &ConnTable,
    listeners: &ListenerTable,
) -> IpcFrame {
    match method {
        METHOD_GET_PEER_ID => {
            let pid = api.peer_id();
            ok_response(request_id, &encode_payload(&pid))
        }

        METHOD_SEND_DATA => {
            let req: SendDataReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.send_data(&req.dest, &req.data).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_CREATE_TUNNEL => {
            let dest: PeerId = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.create_tunnel(dest).await {
                Ok(peer) => ok_response(request_id, &encode_payload(&peer)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_SEND_TUNNEL_DATA => {
            let req: SendDataReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.send_tunnel_data(&req.dest, &req.data).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_DHT_PUT_CONTENT => {
            let value: serde_bytes::ByteBuf = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            let hash = api.dht_put(&value).await;
            ok_response(request_id, &encode_payload(&hash))
        }

        METHOD_DHT_GET_CONTENT => {
            let (hash, timeout_secs): (DhtId, u32) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.dht_get(&hash, timeout_secs).await {
                Some(data) => ok_response(request_id, &encode_payload(&serde_bytes::ByteBuf::from(data))),
                None => not_found_response(request_id),
            }
        }

        METHOD_DHT_PUT_SIGNED => {
            let req: DhtPutSignedReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            let hash = api.dht_put_signed(&req.value, req.ttl_secs).await;
            ok_response(request_id, &encode_payload(&hash))
        }

        METHOD_DHT_GET_SIGNED => {
            let (hash, timeout_secs): (DhtId, u32) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            let results = api.dht_get_signed(&hash, timeout_secs).await;
            let entries: Vec<SignedContentEntry> = results
                .into_iter()
                .map(|e| SignedContentEntry { signer: e.signer, data: e.data })
                .collect();
            ok_response(request_id, &encode_payload(&entries))
        }

        METHOD_LOOKUP_HELLO => {
            let (pid, timeout_secs): (PeerId, u32) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.lookup_hello(&pid, timeout_secs).await {
                Some(info) => ok_response(request_id, &encode_payload(&info)),
                None => not_found_response(request_id),
            }
        }

        METHOD_DHT_WATCH => {
            let (key, expiry): (DhtId, u32) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            api.dht_watch(&key, expiry).await;
            ok_response(request_id, &[])
        }

        METHOD_DHT_UNWATCH => {
            let key: DhtId = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            api.dht_unwatch(&key).await;
            ok_response(request_id, &[])
        }

        METHOD_CONNECTED_PEERS => {
            let peers = api.connected_peers().await;
            ok_response(request_id, &encode_payload(&peers))
        }

        METHOD_ROUTING_ENTRIES => {
            let entries = api.routing_entries().await;
            ok_response(request_id, &encode_payload(&entries))
        }

        METHOD_NODE_STATUS => {
            let status = api.node_status().await;
            ok_response(request_id, &encode_payload(&status))
        }

        METHOD_TNS_PUBLISH => {
            let (identity, label, records, ttl): (Option<String>, String, Vec<tarnet_api::service::TnsRecord>, u32) =
                match decode_payload(payload) {
                    Ok(v) => v,
                    Err(e) => return err_response(request_id, &e.to_string()),
                };
            match api.tns_publish(identity.as_deref(), &label, records, ttl).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_TNS_RESOLVE => {
            let (zone, name): (ServiceId, String) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.tns_resolve(zone, &name).await {
                Ok(result) => ok_response(request_id, &encode_payload(&result)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_TNS_SET_LABEL => {
            let (identity, label, records, publish): (Option<String>, String, Vec<tarnet_api::service::TnsRecord>, bool) =
                match decode_payload(payload) {
                    Ok(v) => v,
                    Err(e) => return err_response(request_id, &e.to_string()),
                };
            match api.tns_set_label(identity.as_deref(), &label, records, publish).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_TNS_GET_LABEL => {
            let (identity, label): (Option<String>, String) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.tns_get_label(identity.as_deref(), &label).await {
                Ok(Some((records, publish))) => {
                    ok_response(request_id, &encode_payload(&(records, publish)))
                }
                Ok(None) => not_found_response(request_id),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_TNS_REMOVE_LABEL => {
            let (identity, label): (Option<String>, String) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.tns_remove_label(identity.as_deref(), &label).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_TNS_LIST_LABELS => {
            let identity: Option<String> = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.tns_list_labels(identity.as_deref()).await {
                Ok(entries) => ok_response(request_id, &encode_payload(&entries)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_TNS_RESOLVE_NAME => {
            let name: String = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.tns_resolve_name(&name).await {
                Ok(result) => ok_response(request_id, &encode_payload(&result)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_DEFAULT_SERVICE_ID => {
            let sid = api.default_service_id().await;
            ok_response(request_id, &encode_payload(&sid))
        }

        METHOD_LISTEN => {
            let req: ListenReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.listen(req.service_id, req.port, req.options).await {
                Ok(listener) => {
                    let resp = encode_payload(&register_listener(listeners, listener).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_CONNECT => {
            let (sid, port): (ServiceId, u16) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.connect(sid, port).await {
                Ok(conn) => {
                    let resp = encode_payload(&register_connection(conns, conn, writer).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_ACCEPT => {
            let req: AcceptReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            let listener = {
                let guard = listeners.lock().await;
                guard.get(&req.listener_id).copied()
            };
            let listener = match listener {
                Some(listener) => listener,
                None => return err_response(request_id, "unknown listener id"),
            };
            match api.accept(&listener).await {
                Ok(conn) => {
                    let resp = encode_payload(&register_connection(conns, conn, writer).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_PUBLISH_HIDDEN_SERVICE => {
            let (sid, count): (ServiceId, u16) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.listen_hidden(sid, 0, count as usize, ListenerOptions::default()).await {
                Ok(listener) => {
                    let _ = register_listener(listeners, listener).await;
                    ok_response(request_id, &[])
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_LISTEN_HIDDEN => {
            let req: ListenHiddenReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.listen_hidden(
                req.service_id,
                req.port,
                req.num_intro_points as usize,
                req.options,
            ).await {
                Ok(listener) => {
                    let resp = encode_payload(&register_listener(listeners, listener).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_RESOLVE_IDENTITY => {
            let name: String = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.resolve_identity(&name).await {
                Ok(sid) => ok_response(request_id, &encode_payload(&sid)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_CREATE_IDENTITY => {
            let (label, privacy, outbound_hops, scheme): (String, PrivacyLevel, u8, IdentityScheme) =
                match decode_payload(payload) {
                    Ok(v) => v,
                    Err(e) => return err_response(request_id, &e.to_string()),
                };
            match api.create_identity(&label, privacy, outbound_hops, scheme).await {
                Ok(sid) => ok_response(request_id, &encode_payload(&sid)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_LIST_IDENTITIES => {
            match api.list_identities().await {
                Ok(entries) => {
                    let ipc_entries: Vec<IdentityEntry> = entries
                        .into_iter()
                        .map(|(label, service_id, privacy, outbound_hops, scheme, signing_algo, kem_algo)| IdentityEntry {
                            label,
                            service_id,
                            privacy,
                            outbound_hops,
                            scheme,
                            signing_algo,
                            kem_algo,
                        })
                        .collect();
                    ok_response(request_id, &encode_payload(&ipc_entries))
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_DELETE_IDENTITY => {
            let label: String = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.delete_identity(&label).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_UPDATE_IDENTITY => {
            let (label, privacy, outbound_hops): (String, PrivacyLevel, u8) =
                match decode_payload(payload) {
                    Ok(v) => v,
                    Err(e) => return err_response(request_id, &e.to_string()),
                };
            match api.update_identity(&label, privacy, outbound_hops).await {
                Ok((old_privacy, old_hops)) => {
                    ok_response(request_id, &encode_payload(&(old_privacy, old_hops)))
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_SOCKS_ADDR => {
            match api.socks_addr().await {
                Ok(addrs) => ok_response(request_id, &encode_payload(&addrs)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_CONNECT_TO => {
            let (target, port): (String, u16) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.connect_to(&target, port).await {
                Ok(conn) => {
                    let resp = encode_payload(&register_connection(conns, conn, writer).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        _ => err_response(request_id, &format!("unknown method: 0x{:04x}", method)),
    }
}

fn ok_response(request_id: u32, payload: &[u8]) -> IpcFrame {
    IpcFrame::Response {
        request_id,
        status: STATUS_OK,
        payload: payload.to_vec(),
    }
}

fn not_found_response(request_id: u32) -> IpcFrame {
    IpcFrame::Response {
        request_id,
        status: STATUS_NOT_FOUND,
        payload: Vec::new(),
    }
}

fn err_response(request_id: u32, msg: &str) -> IpcFrame {
    IpcFrame::Response {
        request_id,
        status: STATUS_ERROR,
        payload: msg.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocated_client_conn_ids_are_nonzero_and_unique() {
        let mut conns = HashMap::new();
        for _ in 0..512 {
            let conn_id = allocate_client_conn_id(&conns);
            assert_ne!(conn_id, 0);
            assert!(!conns.contains_key(&conn_id));
            conns.insert(
                conn_id,
                Arc::new(Connection::new(
                    ServiceId::LOCAL,
                    0,
                    conn_id,
                    tokio::sync::mpsc::channel(1).0,
                    tokio::sync::mpsc::channel(1).1,
                )),
            );
        }
    }

    #[test]
    fn allocated_client_listener_ids_are_nonzero_and_unique() {
        let mut listeners = HashMap::new();
        for _ in 0..512 {
            let listener_id = allocate_client_listener_id(&listeners);
            assert_ne!(listener_id, 0);
            assert!(!listeners.contains_key(&listener_id));
            listeners.insert(
                listener_id,
                Listener {
                    id: listener_id,
                    service_id: ServiceId::LOCAL,
                    port: 80,
                    options: ListenerOptions::default(),
                },
            );
        }
    }
}
