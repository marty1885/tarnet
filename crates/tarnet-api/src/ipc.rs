//! IPC wire protocol between tarnetd and clients.
//!
//! Frame format: length(u32 BE) + payload
//! Payload format: frame_type(u8) + body
//!
//! Frame types:
//!   0x01 = Request  (client → daemon)
//!   0x02 = Response (daemon → client)
//!   0x03 = Event    (daemon → client, async push)
//!
//! Request body:  request_id(u32 BE) + method(u16 BE) + method_args
//! Response body: request_id(u32 BE) + status(u8) + response_data
//! Event body:    event_type(u16 BE) + event_data

use serde::{Serialize, Deserialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{ApiError, ApiResult};
use crate::types::{IdentityScheme, KemAlgo, PeerId, PrivacyLevel, ServiceId, SigningAlgo};

// ── Frame types ──

const FRAME_REQUEST: u8 = 0x01;
const FRAME_RESPONSE: u8 = 0x02;
const FRAME_EVENT: u8 = 0x03;

// ── Method IDs (request/response) ──

pub const METHOD_GET_PEER_ID: u16 = 0x0001;
pub const METHOD_SEND_DATA: u16 = 0x0002;
pub const METHOD_CREATE_TUNNEL: u16 = 0x0003;
pub const METHOD_SEND_TUNNEL_DATA: u16 = 0x0004;
pub const METHOD_DHT_PUT_CONTENT: u16 = 0x0010;
pub const METHOD_DHT_GET_CONTENT: u16 = 0x0011;
pub const METHOD_REQUEST_CONTENT: u16 = 0x0012;
pub const METHOD_DHT_PUT_SIGNED: u16 = 0x0013;
pub const METHOD_DHT_GET_SIGNED: u16 = 0x0014;
pub const METHOD_REQUEST_SIGNED: u16 = 0x0015;
pub const METHOD_REGISTER_REPUBLISH: u16 = 0x0016;
pub const METHOD_UNREGISTER_REPUBLISH: u16 = 0x0017;
pub const METHOD_LOOKUP_HELLO: u16 = 0x0020;
pub const METHOD_REQUEST_HELLO: u16 = 0x0021;
pub const METHOD_DHT_WATCH: u16 = 0x0030;
pub const METHOD_DHT_UNWATCH: u16 = 0x0031;
pub const METHOD_CONNECTED_PEERS: u16 = 0x0040;
pub const METHOD_ROUTING_ENTRIES: u16 = 0x0041;
pub const METHOD_NODE_STATUS: u16 = 0x0042;
pub const METHOD_SUBSCRIBE_DATA: u16 = 0x0050;
pub const METHOD_SUBSCRIBE_TUNNELS: u16 = 0x0051;
pub const METHOD_SUBSCRIBE_WATCHES: u16 = 0x0052;

// TNS methods
pub const METHOD_TNS_PUBLISH: u16 = 0x0060;
pub const METHOD_TNS_RESOLVE: u16 = 0x0061;
pub const METHOD_TNS_SET_LABEL: u16 = 0x0062;
pub const METHOD_TNS_GET_LABEL: u16 = 0x0063;
pub const METHOD_TNS_REMOVE_LABEL: u16 = 0x0064;
pub const METHOD_TNS_LIST_LABELS: u16 = 0x0065;
pub const METHOD_TNS_RESOLVE_NAME: u16 = 0x0066;

// Circuit connection methods (Phase 5)
pub const METHOD_DEFAULT_SERVICE_ID: u16 = 0x0070;
pub const METHOD_CONNECT: u16 = 0x0071;
pub const METHOD_LISTEN: u16 = 0x0072;
pub const METHOD_ACCEPT: u16 = 0x0073;
pub const METHOD_PUBLISH_HIDDEN_SERVICE: u16 = 0x0074;
pub const METHOD_DEFAULT_SERVICE_ADDRESS: u16 = 0x0075; // deprecated
pub const METHOD_CREATE_IDENTITY: u16 = 0x0076;
pub const METHOD_LIST_IDENTITIES: u16 = 0x0077;
pub const METHOD_UPDATE_IDENTITY: u16 = 0x0078;
pub const METHOD_LISTEN_HIDDEN: u16 = 0x0079;
pub const METHOD_DELETE_IDENTITY: u16 = 0x007B;
pub const METHOD_RESOLVE_IDENTITY: u16 = 0x007A;
/// Send data on an established connection: conn_id(u32) || data
pub const METHOD_CONN_SEND: u16 = 0x0080;
/// Close a connection: conn_id(u32)
pub const METHOD_CONN_CLOSE: u16 = 0x0081;

// Daemon control
/// Reload daemon configuration (equivalent to SIGHUP).
pub const METHOD_RELOAD: u16 = 0x0090;

// Daemon info
/// Get the daemon's SOCKS proxy bind addresses.
pub const METHOD_SOCKS_ADDR: u16 = 0x00A0;

// Unified connect/listen (string-based resolution)
/// Connect to a target by name/address string: (target: String, port: u16)
pub const METHOD_CONNECT_TO: u16 = 0x00A1;

// ── Response status codes ──

pub const STATUS_OK: u8 = 0x00;
pub const STATUS_NOT_FOUND: u8 = 0x01;
pub const STATUS_ERROR: u8 = 0x02;

// ── Event types ──

pub const EVENT_DATA: u16 = 0x0001;
pub const EVENT_TUNNEL: u16 = 0x0002;
pub const EVENT_WATCH: u16 = 0x0003;
/// Connection data received: conn_id(u32) || data
pub const EVENT_CONN_DATA: u16 = 0x0004;
/// Connection closed by remote: conn_id(u32)
pub const EVENT_CONN_CLOSED: u16 = 0x0005;

// ── Parsed frames ──

#[derive(Debug)]
pub enum IpcFrame {
    Request {
        request_id: u32,
        method: u16,
        payload: Vec<u8>,
    },
    Response {
        request_id: u32,
        status: u8,
        payload: Vec<u8>,
    },
    Event {
        event_type: u16,
        payload: Vec<u8>,
    },
}

impl IpcFrame {
    pub fn encode(&self) -> Vec<u8> {
        let body = match self {
            IpcFrame::Request {
                request_id,
                method,
                payload,
            } => {
                let mut buf = Vec::with_capacity(1 + 4 + 2 + payload.len());
                buf.push(FRAME_REQUEST);
                buf.extend_from_slice(&request_id.to_be_bytes());
                buf.extend_from_slice(&method.to_be_bytes());
                buf.extend_from_slice(payload);
                buf
            }
            IpcFrame::Response {
                request_id,
                status,
                payload,
            } => {
                let mut buf = Vec::with_capacity(1 + 4 + 1 + payload.len());
                buf.push(FRAME_RESPONSE);
                buf.extend_from_slice(&request_id.to_be_bytes());
                buf.push(*status);
                buf.extend_from_slice(payload);
                buf
            }
            IpcFrame::Event {
                event_type,
                payload,
            } => {
                let mut buf = Vec::with_capacity(1 + 2 + payload.len());
                buf.push(FRAME_EVENT);
                buf.extend_from_slice(&event_type.to_be_bytes());
                buf.extend_from_slice(payload);
                buf
            }
        };

        // Length-prefix the body
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    pub fn decode(data: &[u8]) -> ApiResult<Self> {
        if data.is_empty() {
            return Err(ApiError::Protocol("empty frame".into()));
        }

        match data[0] {
            FRAME_REQUEST => {
                if data.len() < 7 {
                    return Err(ApiError::Protocol("request too short".into()));
                }
                let request_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let method = u16::from_be_bytes([data[5], data[6]]);
                let payload = data[7..].to_vec();
                Ok(IpcFrame::Request {
                    request_id,
                    method,
                    payload,
                })
            }
            FRAME_RESPONSE => {
                if data.len() < 6 {
                    return Err(ApiError::Protocol("response too short".into()));
                }
                let request_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let status = data[5];
                let payload = data[6..].to_vec();
                Ok(IpcFrame::Response {
                    request_id,
                    status,
                    payload,
                })
            }
            FRAME_EVENT => {
                if data.len() < 3 {
                    return Err(ApiError::Protocol("event too short".into()));
                }
                let event_type = u16::from_be_bytes([data[1], data[2]]);
                let payload = data[3..].to_vec();
                Ok(IpcFrame::Event {
                    event_type,
                    payload,
                })
            }
            other => Err(ApiError::Protocol(format!("unknown frame type: {}", other))),
        }
    }
}

// ── Framed I/O helpers ──

/// Read one length-prefixed frame from a stream.
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> ApiResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(ApiError::Protocol(format!(
            "frame too large: {} bytes",
            len
        )));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write one length-prefixed frame to a stream.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> ApiResult<()> {
    writer.write_all(&(data.len() as u32).to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Send a complete IpcFrame (length-prefixed).
pub async fn send_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    frame: &IpcFrame,
) -> ApiResult<()> {
    let encoded = frame.encode();
    // encode() already includes the length prefix, write it directly
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

/// Read and decode one IpcFrame.
pub async fn recv_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> ApiResult<IpcFrame> {
    let data = read_frame(reader).await?;
    IpcFrame::decode(&data)
}

// ── Version handshake ──

/// IPC protocol version. Increment when making breaking changes.
pub const IPC_VERSION: u16 = 3;
/// Minimum IPC version we can talk to.
pub const IPC_MIN_VERSION: u16 = 3;
/// Magic bytes for version handshake.
pub const IPC_MAGIC: &[u8; 4] = b"TNET";

/// Perform version handshake as the client side.
pub async fn handshake_client<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> ApiResult<u16> {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(IPC_MAGIC);
    buf[4..6].copy_from_slice(&IPC_VERSION.to_be_bytes());
    buf[6..8].copy_from_slice(&IPC_MIN_VERSION.to_be_bytes());
    stream.write_all(&buf).await?;
    stream.flush().await?;

    let mut server_buf = [0u8; 8];
    stream.read_exact(&mut server_buf).await?;
    if &server_buf[..4] != IPC_MAGIC {
        return Err(ApiError::Protocol("invalid IPC magic".into()));
    }
    let server_version = u16::from_be_bytes([server_buf[4], server_buf[5]]);
    let server_min = u16::from_be_bytes([server_buf[6], server_buf[7]]);

    if IPC_VERSION < server_min {
        return Err(ApiError::Protocol(format!(
            "server requires IPC version >= {}, we are {}",
            server_min, IPC_VERSION
        )));
    }
    if server_version < IPC_MIN_VERSION {
        return Err(ApiError::Protocol(format!(
            "server IPC version {} too old, we require >= {}",
            server_version, IPC_MIN_VERSION
        )));
    }

    Ok(server_version.min(IPC_VERSION))
}

/// Perform version handshake as the server side.
pub async fn handshake_server<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> ApiResult<u16> {
    let mut client_buf = [0u8; 8];
    stream.read_exact(&mut client_buf).await?;
    if &client_buf[..4] != IPC_MAGIC {
        return Err(ApiError::Protocol("invalid IPC magic".into()));
    }
    let client_version = u16::from_be_bytes([client_buf[4], client_buf[5]]);
    let client_min = u16::from_be_bytes([client_buf[6], client_buf[7]]);

    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(IPC_MAGIC);
    buf[4..6].copy_from_slice(&IPC_VERSION.to_be_bytes());
    buf[6..8].copy_from_slice(&IPC_MIN_VERSION.to_be_bytes());
    stream.write_all(&buf).await?;
    stream.flush().await?;

    if IPC_VERSION < client_min {
        return Err(ApiError::Protocol(format!(
            "client requires IPC version >= {}, we are {}",
            client_min, IPC_VERSION
        )));
    }
    if client_version < IPC_MIN_VERSION {
        return Err(ApiError::Protocol(format!(
            "client IPC version {} too old, we require >= {}",
            client_version, IPC_MIN_VERSION
        )));
    }

    Ok(client_version.min(IPC_VERSION))
}

// ── MessagePack payload helpers ──

/// Encode a value as MessagePack bytes for IPC payload.
pub fn encode_payload<T: serde::Serialize>(value: &T) -> Vec<u8> {
    rmp_serde::to_vec(value).expect("msgpack encode failed")
}

/// Decode a MessagePack IPC payload.
pub fn decode_payload<'a, T: serde::Deserialize<'a>>(data: &'a [u8]) -> ApiResult<T> {
    rmp_serde::from_slice(data)
        .map_err(|e| ApiError::Protocol(format!("msgpack decode: {}", e)))
}

// ── IPC request/response types (shared between server and client) ──

/// Request to send data or tunnel data: dest + raw bytes.
#[derive(Serialize, Deserialize)]
pub struct SendDataReq {
    pub dest: PeerId,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Request to put signed content in the DHT.
#[derive(Serialize, Deserialize)]
pub struct DhtPutSignedReq {
    pub ttl_secs: u32,
    pub republish: bool,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// A signed content entry returned from DHT.
#[derive(Serialize, Deserialize)]
pub struct SignedContentEntry {
    pub signer: PeerId,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Response from CONNECT or ACCEPT.
#[derive(Serialize, Deserialize)]
pub struct ConnectResp {
    pub conn_id: u32,
    pub remote_service_id: ServiceId,
}

/// One entry in a list_identities response.
#[derive(Serialize, Deserialize)]
pub struct IdentityEntry {
    pub label: String,
    pub service_id: ServiceId,
    pub privacy: PrivacyLevel,
    pub outbound_hops: u8,
    pub scheme: IdentityScheme,
    pub signing_algo: SigningAlgo,
    pub kem_algo: KemAlgo,
}

/// Event: connection data received.
#[derive(Serialize, Deserialize)]
pub struct ConnDataEvent {
    pub conn_id: u32,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Request to send data on an established connection.
#[derive(Serialize, Deserialize)]
pub struct ConnSendReq {
    pub conn_id: u32,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

// ── Utility functions ──

/// Default data directory for tarnet persistent files (identity, state DB).
///
/// Uses `$XDG_DATA_HOME/tarnet` (typically `~/.local/share/tarnet`).
pub fn default_data_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(dir).join("tarnet")
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home).join(".local/share/tarnet")
    } else {
        std::path::PathBuf::from("/var/lib/tarnet")
    }
}

/// Default config directory.
///
/// Uses `$XDG_CONFIG_HOME/tarnet` (typically `~/.config/tarnet`).
pub fn default_config_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        std::path::PathBuf::from(dir).join("tarnet")
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home).join(".config/tarnet")
    } else {
        std::path::PathBuf::from("/etc/tarnet")
    }
}

/// Default daemon socket path (inside the default data dir).
pub fn default_socket_path() -> std::path::PathBuf {
    socket_path_for(&default_data_dir())
}

/// Socket path for a given data directory.
pub fn socket_path_for(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("sock")
}

/// Services directory for a given config directory.
pub fn services_dir_for(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("services.d")
}

/// Config file path for a given config directory.
pub fn config_path_for(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("tarnetd.toml")
}

/// Defaults reference file path for a given config directory.
pub fn defaults_path_for(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("tarnetd.defaults.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_request_roundtrip() {
        let frame = IpcFrame::Request {
            request_id: 42,
            method: METHOD_GET_PEER_ID,
            payload: vec![1, 2, 3],
        };
        let encoded = frame.encode();
        let body = &encoded[4..];
        let decoded = IpcFrame::decode(body).unwrap();
        match decoded {
            IpcFrame::Request {
                request_id,
                method,
                payload,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(method, METHOD_GET_PEER_ID);
                assert_eq!(payload, vec![1, 2, 3]);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn frame_response_roundtrip() {
        let frame = IpcFrame::Response {
            request_id: 99,
            status: STATUS_OK,
            payload: vec![4, 5, 6],
        };
        let encoded = frame.encode();
        let body = &encoded[4..];
        let decoded = IpcFrame::decode(body).unwrap();
        match decoded {
            IpcFrame::Response {
                request_id,
                status,
                payload,
            } => {
                assert_eq!(request_id, 99);
                assert_eq!(status, STATUS_OK);
                assert_eq!(payload, vec![4, 5, 6]);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn frame_event_roundtrip() {
        let frame = IpcFrame::Event {
            event_type: EVENT_DATA,
            payload: vec![7, 8, 9],
        };
        let encoded = frame.encode();
        let body = &encoded[4..];
        let decoded = IpcFrame::decode(body).unwrap();
        match decoded {
            IpcFrame::Event {
                event_type,
                payload,
            } => {
                assert_eq!(event_type, EVENT_DATA);
                assert_eq!(payload, vec![7, 8, 9]);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn msgpack_peer_id_roundtrip() {
        let pid = PeerId([0xAB; 32]);
        let encoded = encode_payload(&pid);
        let decoded: PeerId = decode_payload(&encoded).unwrap();
        assert_eq!(pid, decoded);
    }

    #[test]
    fn msgpack_service_id_roundtrip() {
        let sid = ServiceId::from_signing_pubkey(&[0x42; 32]);
        let encoded = encode_payload(&sid);
        let decoded: ServiceId = decode_payload(&encoded).unwrap();
        assert_eq!(sid, decoded);
    }

    #[test]
    fn msgpack_send_data_req_roundtrip() {
        let req = SendDataReq {
            dest: PeerId([0xCD; 32]),
            data: vec![1, 2, 3, 4, 5],
        };
        let encoded = encode_payload(&req);
        let decoded: SendDataReq = decode_payload(&encoded).unwrap();
        assert_eq!(req.dest, decoded.dest);
        assert_eq!(req.data, decoded.data);
    }
}
