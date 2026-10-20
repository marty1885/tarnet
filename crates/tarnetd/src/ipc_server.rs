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
use tarnet_api::service::{Connection, Listener, ListenerOptions, NodeEvent, PortMode, ServiceApi};
use tarnet_api::types::{ContentHandle, DhtId, IdentityScheme, PeerId, PrivacyLevel, ServiceId};

/// A registered IPC connection plus the abort handle of its recv-relay task.
/// Holding the relay handle lets `METHOD_CONN_CLOSE` stop the relay so the last
/// `Arc<Connection>` drops — which fires the endpoint's StreamEnd teardown.
struct ConnEntry {
    conn: Arc<Connection>,
    relay: tokio::task::AbortHandle,
}

/// Per-client connection table: maps conn_id -> ConnEntry.
/// Shared between the dispatch task and event-pushing tasks.
type ConnTable = Arc<Mutex<HashMap<u32, ConnEntry>>>;
type ListenerTable = Arc<Mutex<HashMap<u32, Listener>>>;
/// Labels a client published with `tns_publish`: withdrawn when it goes, so
/// a name doesn't outlive the process that serves it.
type PublishedTable = Arc<Mutex<Vec<(Option<String>, String)>>>;

/// State shared by every IPC client of the daemon.
#[derive(Default)]
struct Shared {
    /// How many clients watch each DHT key: the node-wide watch is dropped
    /// only when the last one lets go.
    watch_counts: std::sync::Mutex<HashMap<DhtId, usize>>,
    /// Throwaway identities by owning client.
    ephemeral_owner: std::sync::Mutex<HashMap<ServiceId, u64>>,
    next_client: std::sync::atomic::AtomicU64,
}

/// One IPC client's view: the events meant for it and what it owns.
struct ClientState {
    id: u64,
    /// Opted in to raw overlay events (`Data`, `Tunnel`).
    raw: std::sync::atomic::AtomicBool,
    /// DHT keys this client watches; it hears only their notifications.
    watched: std::sync::Mutex<std::collections::HashSet<DhtId>>,
    /// Throwaway identities this client created.
    ephemerals: std::sync::Mutex<std::collections::HashSet<ServiceId>>,
}

impl ClientState {
    /// Whether this client may act as `sid`: any identity but another
    /// client's throwaway.
    fn may_use(&self, shared: &Shared, sid: &ServiceId) -> bool {
        shared
            .ephemeral_owner
            .lock()
            .unwrap()
            .get(sid)
            .map_or(true, |owner| *owner == self.id)
    }

    /// Whether `event` is meant for this client.
    fn wants(&self, event: &NodeEvent) -> bool {
        match event {
            NodeEvent::Data { .. } | NodeEvent::Tunnel { .. } => {
                self.raw.load(std::sync::atomic::Ordering::Relaxed)
            }
            NodeEvent::Watch(w) => self.watched.lock().unwrap().contains(&w.key),
            NodeEvent::PeerDisconnected(_) => false,
        }
    }
}

/// Allocate an opaque client-local handle ID for a connection.
/// The handle space is scoped to a single Unix socket connection.
fn allocate_client_conn_id<V>(conns: &HashMap<u32, V>) -> u32 {
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
    let mode = conn.mode;
    let port = conn.port.clone();
    let conn = Arc::new(conn);

    // Allocate the id, spawn the recv-relay, and insert the entry under one lock
    // so the abort handle is in place before the client can ever close it.
    let client_conn_id = {
        let mut guard = conns.lock().await;
        let client_conn_id = allocate_client_conn_id(&*guard);
        let relay =
            spawn_conn_recv_relay(client_conn_id, conn.clone(), writer.clone(), conns.clone());
        guard.insert(
            client_conn_id,
            ConnEntry {
                conn: conn.clone(),
                relay,
            },
        );
        client_conn_id
    };

    log::debug!(
        "IPC connection registered: client_conn_id={} internal_conn_id={}",
        client_conn_id,
        internal_conn_id
    );

    ConnectResp {
        conn_id: client_conn_id,
        remote_service_id,
        mode,
        port,
    }
}

async fn register_listener(listeners: &ListenerTable, listener: Listener) -> ListenResp {
    let client_listener_id = {
        let mut guard = listeners.lock().await;
        let client_listener_id = allocate_client_listener_id(&guard);
        guard.insert(client_listener_id, listener.clone());
        client_listener_id
    };

    ListenResp {
        listener: Listener {
            id: client_listener_id,
            service_id: listener.service_id,
            mode: listener.mode,
            port: listener.port,
            options: listener.options,
        },
    }
}

async fn close_client_listeners(api: &dyn ServiceApi, listeners: &ListenerTable) {
    let listeners: Vec<Listener> = listeners
        .lock()
        .await
        .drain()
        .map(|(_, listener)| listener)
        .collect();
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
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // The socket's directory and the socket are the daemon user's alone.
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // Remove stale socket
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    // We just created the socket, so its owner is the daemon's uid.
    let daemon_uid = std::fs::metadata(&socket_path)?.uid();
    log::info!("IPC listening on {}", socket_path.display());
    let shared = Arc::new(Shared::default());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Only processes of the daemon's own user. This separates
                // applications; it is no boundary against a hostile process
                // running as that user.
                match stream.peer_cred() {
                    Ok(cred) if cred.uid() == daemon_uid => {}
                    Ok(cred) => {
                        log::warn!("IPC connection from uid {} refused", cred.uid());
                        continue;
                    }
                    Err(e) => {
                        log::warn!("IPC connection refused: no peer credentials ({})", e);
                        continue;
                    }
                }
                let client_api = api.clone();
                let client_reload = reload_notify.clone();
                let client_expose_reload = expose_reload_tx.clone();
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_client(stream, client_api, client_reload, client_expose_reload, shared).await
                    {
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
    shared: Arc<Shared>,
) -> ApiResult<()> {
    let client = Arc::new(ClientState {
        id: shared.next_client.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        raw: Default::default(),
        watched: Default::default(),
        ephemerals: Default::default(),
    });
    // Version handshake before splitting the stream
    let _negotiated_version = tarnet_api::ipc::handshake_server(&mut stream).await?;

    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let conns: ConnTable = Arc::new(Mutex::new(HashMap::new()));
    let listeners: ListenerTable = Arc::new(Mutex::new(HashMap::new()));
    let published: PublishedTable = Arc::new(Mutex::new(Vec::new()));

    // Relay the events meant for this client: watch notifications for keys
    // it watches, raw overlay events once it opts in. Nothing else.
    if let Ok(mut rx) = api.subscribe_events().await {
        let w = writer.clone();
        let client = client.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if !client.wants(&event) {
                    continue;
                }
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
                                let _ =
                                    send_frame(&mut *w, &err_response(request_id, &e.to_string()))
                                        .await;
                                continue;
                            }
                        };
                        // MUST stay inline. Spawning per frame lets two sends
                        // on the same connection race on conns.lock + conn.send,
                        // reordering bytes on a single stream. Inline preserves
                        // per-client ordering and gives natural backpressure.
                        // Regression guard: tests::conn_send_handler_stays_inline.
                        let response = {
                            let guard = conns.lock().await;
                            if let Some(entry) = guard.get(&req.conn_id) {
                                match entry.conn.send(&req.data).await {
                                    Ok(()) => ok_response(request_id, &[]),
                                    Err(e) => err_response(request_id, &e.to_string()),
                                }
                            } else {
                                err_response(request_id, "unknown connection id")
                            }
                        };
                        let mut w = writer.lock().await;
                        let _ = send_frame(&mut *w, &response).await;
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
                                )
                                .await
                                {
                                    Ok(Ok(Ok(()))) => ok_response(request_id, &[]),
                                    Ok(Ok(Err(e))) => err_response(request_id, &e),
                                    Ok(Err(_)) => {
                                        err_response(request_id, "expose reload cancelled")
                                    }
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
                        // Abort the recv-relay so its Arc<Connection> drops. Once
                        // both this table entry and the relay release the Arc, the
                        // endpoint Connection drops, ending its backward task, which
                        // sends StreamEnd upstream so the initiator resets its client.
                        if let Some(entry) = conns.lock().await.remove(&conn_id) {
                            entry.relay.abort();
                        }
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
                        let published = published.clone();
                        let client = client.clone();
                        let shared = shared.clone();
                        // Handle each request concurrently so one slow DHT lookup
                        // doesn't block quick peer_id queries.
                        tokio::spawn(async move {
                            let response = dispatch_request(
                                &*api, method, &payload, request_id, &writer, &conns, &listeners,
                                &published, &client, &shared,
                            )
                            .await;
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
    // Its watches: the node-wide watch goes with the last watcher.
    let watched: Vec<DhtId> = client.watched.lock().unwrap().drain().collect();
    for key in watched {
        if release_watch(&shared, &key) {
            api.dht_unwatch(&key).await;
        }
    }
    // Its throwaway identities die with it.
    let owned: Vec<ServiceId> = client.ephemerals.lock().unwrap().drain().collect();
    for sid in owned {
        shared.ephemeral_owner.lock().unwrap().remove(&sid);
        if let Err(e) = api.drop_ephemeral_identity(sid).await {
            log::debug!("Failed to drop a throwaway identity after its client left: {}", e);
        }
    }
    for (identity, label) in published.lock().await.drain(..) {
        if let Err(e) = api.tns_withdraw(identity.as_deref(), &label).await {
            log::debug!("Failed to withdraw '{}' after its client left: {}", label, e);
        }
    }
    result
}

/// One watcher fewer for `key`; true when it was the last.
fn release_watch(shared: &Shared, key: &DhtId) -> bool {
    let mut counts = shared.watch_counts.lock().unwrap();
    match counts.get_mut(key) {
        Some(n) if *n > 1 => {
            *n -= 1;
            false
        }
        Some(_) => {
            counts.remove(key);
            true
        }
        None => false,
    }
}

/// Spawn a task that relays conn.recv() -> EVENT_CONN_DATA / EVENT_CONN_CLOSED to the client.
fn spawn_conn_recv_relay(
    conn_id: u32,
    conn: Arc<Connection>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    conns: ConnTable,
) -> tokio::task::AbortHandle {
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
    })
    .abort_handle()
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
    published: &PublishedTable,
    client: &ClientState,
    shared: &Shared,
) -> IpcFrame {
    // Another client's throwaway identity can't be used here.
    macro_rules! owned_or_refuse {
        ($sid:expr) => {
            if !client.may_use(shared, &$sid) {
                return err_response(request_id, "identity not found");
            }
        };
    }
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
            match api.dht_put(&value).await {
                Ok(hash) => ok_response(request_id, &encode_payload(&hash)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_DHT_GET_CONTENT => {
            let (hash, timeout_secs): (ContentHandle, u32) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.dht_get(&hash, timeout_secs).await {
                Some(data) => ok_response(
                    request_id,
                    &encode_payload(&serde_bytes::ByteBuf::from(data)),
                ),
                None => not_found_response(request_id),
            }
        }

        METHOD_DHT_PUT_SIGNED => {
            let req: DhtPutSignedReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.dht_put_signed(&req.value, req.ttl_secs).await {
                Ok(hash) => ok_response(request_id, &encode_payload(&hash)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_DHT_GET_SIGNED => {
            let (hash, timeout_secs): (ContentHandle, u32) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            let results = api.dht_get_signed(&hash, timeout_secs).await;
            let entries: Vec<SignedContentEntry> = results
                .into_iter()
                .map(|e| SignedContentEntry {
                    signer: e.signer,
                    data: e.data,
                })
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
            if client.watched.lock().unwrap().insert(key) {
                *shared.watch_counts.lock().unwrap().entry(key).or_insert(0) += 1;
            }
            api.dht_watch(&key, expiry).await;
            ok_response(request_id, &[])
        }

        METHOD_DHT_UNWATCH => {
            let key: DhtId = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            // Only this client's interest goes; others watching keep theirs.
            if client.watched.lock().unwrap().remove(&key) && release_watch(shared, &key) {
                api.dht_unwatch(&key).await;
            }
            ok_response(request_id, &[])
        }

        METHOD_SUBSCRIBE_RAW => {
            client.raw.store(true, std::sync::atomic::Ordering::Relaxed);
            ok_response(request_id, &[])
        }

        METHOD_CONNECT_AS => {
            let req: ConnectAsReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            owned_or_refuse!(req.source);
            match api.connect_as(req.service_id, req.mode, &req.port, Some(req.source)).await {
                Ok(conn) => {
                    let resp = encode_payload(&register_connection(conns, conn, writer).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_CONNECT_TO_AS => {
            let req: ConnectToAsReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            owned_or_refuse!(req.source);
            match api.connect_to_as(&req.target, req.mode, &req.port, Some(req.source)).await {
                Ok(conn) => {
                    let resp = encode_payload(&register_connection(conns, conn, writer).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_IDENTITY_SIGN => {
            let req: IdentitySignReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            owned_or_refuse!(req.identity);
            match api.identity_sign(req.identity, &req.context, &req.msg).await {
                Ok(sig) => ok_response(request_id, &encode_payload(&sig)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_IDENTITY_VERIFY => {
            let req: IdentityVerifyReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.identity_verify(req.identity, &req.context, &req.msg, &req.signature).await {
                Ok(valid) => ok_response(request_id, &encode_payload(&valid)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_IDENTITY_KEM_DECAP => {
            let req: IdentityKemDecapReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            owned_or_refuse!(req.identity);
            match api.identity_kem_decap(req.identity, &req.context, &req.ciphertext).await {
                Ok(secret) => ok_response(request_id, &encode_payload(&secret)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_IDENTITY_KEM_PUBKEY => {
            let identity: ServiceId = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            owned_or_refuse!(identity);
            match api.identity_kem_pubkey(identity).await {
                Ok(pk) => ok_response(request_id, &encode_payload(&serde_bytes::ByteBuf::from(pk))),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_DHT_PUT_SIGNED_AS => {
            let req: DhtPutSignedAsReq = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            owned_or_refuse!(req.identity);
            match api.dht_put_signed_as(req.identity, &req.value, req.ttl_secs).await {
                Ok(handle) => ok_response(request_id, &encode_payload(&handle)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_CREATE_EPHEMERAL => {
            let options: tarnet_api::service::EphemeralOptions = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.create_ephemeral_identity(options).await {
                Ok(sid) => {
                    shared.ephemeral_owner.lock().unwrap().insert(sid, client.id);
                    client.ephemerals.lock().unwrap().insert(sid);
                    ok_response(request_id, &encode_payload(&sid))
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_DROP_EPHEMERAL => {
            let sid: ServiceId = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            if !client.ephemerals.lock().unwrap().remove(&sid) {
                return err_response(request_id, "not a throwaway identity of this client");
            }
            shared.ephemeral_owner.lock().unwrap().remove(&sid);
            match api.drop_ephemeral_identity(sid).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
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
            let (identity, label, records): (
                Option<String>,
                String,
                Vec<tarnet_api::service::TnsRecord>,
            ) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api
                .tns_publish(identity.as_deref(), &label, records)
                .await
            {
                Ok(()) => {
                    let mut published = published.lock().await;
                    let entry = (identity, label);
                    if !published.contains(&entry) {
                        published.push(entry);
                    }
                    ok_response(request_id, &[])
                }
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
            let (identity, label, records, publish): (
                Option<String>,
                String,
                Vec<tarnet_api::service::TnsRecord>,
                bool,
            ) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api
                .tns_set_label(identity.as_deref(), &label, records, publish)
                .await
            {
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

        METHOD_TNS_LOOKUP_LABEL => {
            let (zone, name): (ServiceId, String) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.tns_lookup_label(zone, &name).await {
                Ok(result) => ok_response(request_id, &encode_payload(&result)),
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
            owned_or_refuse!(req.service_id);
            match api
                .listen(req.service_id, req.mode, &req.port, req.options)
                .await
            {
                Ok(listener) => {
                    let resp = encode_payload(&register_listener(listeners, listener).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_CONNECT => {
            let (sid, mode, port): (ServiceId, PortMode, String) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.connect(sid, mode, &port).await {
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
                guard.get(&req.listener_id).cloned()
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
            let (sid, mode, port, count): (ServiceId, PortMode, String, u16) =
                match decode_payload(payload) {
                    Ok(v) => v,
                    Err(e) => return err_response(request_id, &e.to_string()),
                };
            match api
                .listen_hidden(sid, mode, &port, count as usize, ListenerOptions::default())
                .await
            {
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
            owned_or_refuse!(req.service_id);
            match api
                .listen_hidden(
                    req.service_id,
                    req.mode,
                    &req.port,
                    req.num_intro_points as usize,
                    req.options,
                )
                .await
            {
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
            let (label, privacy, outbound_hops, scheme): (
                String,
                PrivacyLevel,
                u8,
                IdentityScheme,
            ) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api
                .create_identity(&label, privacy, outbound_hops, scheme)
                .await
            {
                Ok(sid) => ok_response(request_id, &encode_payload(&sid)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_LIST_IDENTITIES => match api.list_identities().await {
            Ok(entries) => {
                // Other clients' throwaway identities are invisible.
                let ipc_entries: Vec<IdentityEntry> = entries
                    .into_iter()
                    .filter(|e| client.may_use(shared, &e.1))
                    .map(
                        |(
                            label,
                            service_id,
                            privacy,
                            outbound_hops,
                            scheme,
                            signing_algo,
                            kem_algo,
                        )| IdentityEntry {
                            label,
                            service_id,
                            privacy,
                            outbound_hops,
                            scheme,
                            signing_algo,
                            kem_algo,
                        },
                    )
                    .collect();
                ok_response(request_id, &encode_payload(&ipc_entries))
            }
            Err(e) => err_response(request_id, &e.to_string()),
        },

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

        METHOD_SOCKS_ADDR => match api.socks_addr().await {
            Ok(addrs) => ok_response(request_id, &encode_payload(&addrs)),
            Err(e) => err_response(request_id, &e.to_string()),
        },

        METHOD_CONNECT_TO => {
            let (target, mode, port): (String, PortMode, String) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.connect_to(&target, mode, &port).await {
                Ok(conn) => {
                    let resp = encode_payload(&register_connection(conns, conn, writer).await);
                    ok_response(request_id, &resp)
                }
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_POOL_JOIN => {
            let (name, kind): (String, tarnet_api::service::PoolKind) = match decode_payload(payload)
            {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.pool_join(&name, kind).await {
                Ok(root) => ok_response(request_id, &encode_payload(&root)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_POOL_LEAVE => {
            let name: String = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.pool_leave(&name).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_POOL_LIST => match api.pool_list().await {
            Ok(list) => ok_response(request_id, &encode_payload(&list)),
            Err(e) => err_response(request_id, &e.to_string()),
        },

        METHOD_POOL_REGISTER => {
            let (pool, service, identity, port, opts): (
                String,
                String,
                Option<String>,
                String,
                tarnet_api::service::PoolRegisterOptions,
            ) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api
                .pool_register(&pool, &service, identity.as_deref(), &port, opts)
                .await
            {
                Ok(claim) => ok_response(request_id, &encode_payload(&claim)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_POOL_WITHDRAW => {
            let claim: tarnet_api::service::PoolClaim = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.pool_withdraw(claim).await {
                Ok(()) => ok_response(request_id, &[]),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_POOL_RESOLVE => {
            let (pool, service, timeout): (String, String, u32) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.pool_resolve(&pool, &service, timeout).await {
                Ok(endpoints) => ok_response(request_id, &encode_payload(&endpoints)),
                Err(e) => err_response(request_id, &e.to_string()),
            }
        }

        METHOD_POOL_CATALOG => {
            let (pool, timeout): (String, u32) = match decode_payload(payload) {
                Ok(v) => v,
                Err(e) => return err_response(request_id, &e.to_string()),
            };
            match api.pool_catalog(&pool, timeout).await {
                Ok(names) => ok_response(request_id, &encode_payload(&names)),
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

    fn client(id: u64) -> ClientState {
        ClientState {
            id,
            raw: Default::default(),
            watched: Default::default(),
            ephemerals: Default::default(),
        }
    }

    #[test]
    fn clients_hear_only_their_own_events() {
        let a = client(1);
        let b = client(2);
        let key = DhtId([7; 64]);
        a.watched.lock().unwrap().insert(key);
        let watch = NodeEvent::Watch(tarnet_api::service::WatchEvent {
            key,
            signer: PeerId([0; 32]),
            value: Vec::new(),
        });
        assert!(a.wants(&watch));
        assert!(!b.wants(&watch));
        let data = NodeEvent::Data {
            peer: PeerId([0; 32]),
            payload: Vec::new(),
        };
        assert!(!a.wants(&data), "raw events are opt-in");
        a.raw.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(a.wants(&data));
        assert!(!b.wants(&data));
    }

    #[test]
    fn a_watch_is_dropped_only_by_its_last_watcher() {
        let shared = Shared::default();
        let key = DhtId([9; 64]);
        *shared.watch_counts.lock().unwrap().entry(key).or_insert(0) += 2;
        assert!(!release_watch(&shared, &key), "another client still watches");
        assert!(release_watch(&shared, &key));
        assert!(!release_watch(&shared, &key), "nothing left to release");
    }

    #[test]
    fn another_clients_throwaway_is_off_limits() {
        let shared = Shared::default();
        let sid = ServiceId([3; 32]);
        shared.ephemeral_owner.lock().unwrap().insert(sid, 1);
        assert!(client(1).may_use(&shared, &sid));
        assert!(!client(2).may_use(&shared, &sid));
        assert!(client(2).may_use(&shared, &ServiceId([4; 32])), "ordinary identities are shared");
    }

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
                    PortMode::ReliableOrdered,
                    "test".to_string(),
                    conn_id,
                    tokio::sync::mpsc::channel(1).0,
                    tokio::sync::mpsc::channel(1).1,
                )),
            );
        }
    }

    /// Regression guard for a real bug: the per-IPC-client reader loop must
    /// process METHOD_CONN_SEND frames sequentially. Spawning a task per frame
    /// races them on `conns.lock()` + `conn.send().await`, reordering bytes on
    /// a single circuit connection (e.g. a WS upload). This bug shipped from
    /// the initial commit and stayed hidden because expose runs in-process and
    /// never crosses METHOD_CONN_SEND; only IPC consumers (tunnel/tarify/socks)
    /// exercise it.
    ///
    /// A behavioural test would need a ~200-line ServiceApi mock plus a Unix
    /// socket harness; this structural check is the highest-leverage guard for
    /// the exact class — any future spawn inside this handler trips it.
    #[test]
    fn conn_send_handler_stays_inline() {
        let src = include_str!("ipc_server.rs");
        let start = src
            .find("METHOD_CONN_SEND =>")
            .expect("METHOD_CONN_SEND arm must exist");
        let after = &src[start + "METHOD_CONN_SEND =>".len()..];
        // The arm ends at the next `METHOD_` match in this dispatch block.
        let end = after
            .find("METHOD_")
            .expect("there should be a sibling arm after METHOD_CONN_SEND");
        let arm = &after[..end];
        assert!(
            !arm.contains("tokio::spawn"),
            "METHOD_CONN_SEND must be handled inline to preserve per-stream \
             send ordering. Spawning a task per frame races on the conn lock \
             and reorders bytes. Arm text:\n{}",
            arm
        );
    }

    /// Regression guard for the tunnel-restart bug: when a client (tunnel CLI,
    /// tarify, socks) drops its Connection — e.g. `pipe_tcp` sees the backend
    /// EOF after a server restart — it sends METHOD_CONN_CLOSE. The daemon must
    /// then drop the endpoint `Connection` so its backward task fires StreamEnd
    /// upstream and the initiator resets its client socket. Removing the conn
    /// from the table is NOT enough: the recv-relay task holds a second
    /// `Arc<Connection>` blocked in `recv()`, so the handler must also abort the
    /// relay. Without the abort, the stale stream lingers and a reused
    /// connection hangs until timeout (the reported symptom).
    ///
    /// A behavioural test would need a ServiceApi mock plus a Unix socket
    /// harness; this structural check guards the exact regression.
    #[test]
    fn conn_close_handler_aborts_recv_relay() {
        let src = include_str!("ipc_server.rs");
        let start = src
            .find("METHOD_CONN_CLOSE =>")
            .expect("METHOD_CONN_CLOSE arm must exist");
        let after = &src[start + "METHOD_CONN_CLOSE =>".len()..];
        let end = after
            .find("METHOD_")
            .expect("there should be a sibling arm after METHOD_CONN_CLOSE");
        let arm = &after[..end];
        assert!(
            arm.contains(".relay.abort()"),
            "METHOD_CONN_CLOSE must abort the recv-relay so the endpoint \
             Connection drops and StreamEnd propagates. Just removing the conn \
             from the table leaves the relay holding an Arc, so the stream never \
             tears down and a reused connection hangs. Arm text:\n{}",
            arm
        );
    }

    /// The recv-relay's abort handle must be stored when the connection is
    /// registered, otherwise `conn_close_handler_aborts_recv_relay` has nothing
    /// to abort. Guards the `register_connection` -> `ConnEntry { relay }` wiring.
    #[test]
    fn register_connection_stores_relay_handle() {
        let src = include_str!("ipc_server.rs");
        let start = src
            .find("async fn register_connection")
            .expect("register_connection must exist");
        let body = &src[start..start + 1200.min(src.len() - start)];
        assert!(
            body.contains("spawn_conn_recv_relay") && body.contains("relay"),
            "register_connection must capture the recv-relay abort handle into \
             the ConnEntry so METHOD_CONN_CLOSE can stop it. Body:\n{}",
            body
        );
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
                    mode: PortMode::ReliableOrdered,
                    port: "80".to_string(),
                    options: ListenerOptions::default(),
                },
            );
        }
    }
}
