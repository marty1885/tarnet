use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SOCKS5 address types.
const ATYP_DOMAIN: u8 = 0x03;

/// SOCKS5 auth methods.
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;

/// SOCKS5 reply codes.
const REP_SUCCESS: u8 = 0x00;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// SOCKS5 command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksCommand {
    Connect,
    UdpAssociate,
}

/// Parsed SOCKS5 request (CONNECT or UDP ASSOCIATE).
#[derive(Debug)]
pub struct ConnectRequest {
    pub command: SocksCommand,
    pub hostname: String,
    pub port: u16,
    /// Identity label carried via SOCKS5 username/password auth.
    /// None if the client used no-auth.
    pub identity: Option<String>,
}

/// Perform the SOCKS5 server-side handshake. Returns the CONNECT target.
///
/// Supports: version 5, no-auth (0x00) and username/password (0x02),
/// CONNECT command, domain name and IPv4 addresses.
///
/// When the client authenticates with username/password, the username
/// is interpreted as an identity label for TNS resolution context.
pub async fn server_handshake(stream: &mut TcpStream) -> io::Result<ConnectRequest> {
    // --- Auth negotiation ---
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }

    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // Prefer username/password if offered (carries identity label).
    // Fall back to no-auth.
    let identity = if methods.contains(&AUTH_USERNAME_PASSWORD) {
        // Select username/password auth.
        stream.write_all(&[0x05, AUTH_USERNAME_PASSWORD]).await?;

        // RFC 1929 sub-negotiation: VER(1) ULEN(1) UNAME(1-255) PLEN(1) PASSWD(0-255)
        let sub_ver = stream.read_u8().await?;
        if sub_ver != 0x01 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad username/password sub-negotiation version",
            ));
        }
        let ulen = stream.read_u8().await? as usize;
        let mut username = vec![0u8; ulen];
        stream.read_exact(&mut username).await?;
        let plen = stream.read_u8().await? as usize;
        let mut _password = vec![0u8; plen];
        stream.read_exact(&mut _password).await?;

        // Accept unconditionally (password ignored).
        stream.write_all(&[0x01, 0x00]).await?;

        let label = String::from_utf8(username).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UTF-8 in identity label",
            )
        })?;
        if label.is_empty() {
            None
        } else {
            Some(label)
        }
    } else if methods.contains(&AUTH_NO_AUTH) {
        // No-auth.
        stream.write_all(&[0x05, AUTH_NO_AUTH]).await?;
        None
    } else {
        // No acceptable methods.
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable auth method",
        ));
    };

    // --- CONNECT request ---
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS5 request version",
        ));
    }

    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;

    let command = match cmd {
        0x01 => SocksCommand::Connect,
        0x03 => SocksCommand::UdpAssociate,
        _ => {
            send_reply(stream, REP_COMMAND_NOT_SUPPORTED).await?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported SOCKS5 command",
            ));
        }
    };

    let hostname = match atyp {
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            String::from_utf8(buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain name"))?
        }
        0x01 => {
            // IPv4 — convert to dotted-decimal string
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        _ => {
            send_reply(stream, REP_COMMAND_NOT_SUPPORTED).await?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported address type",
            ));
        }
    };

    let port = stream.read_u16().await?;

    Ok(ConnectRequest {
        command,
        hostname,
        port,
        identity,
    })
}

/// Send a SOCKS5 reply.
pub async fn send_reply(stream: &mut TcpStream, reply: u8) -> io::Result<()> {
    // VER(5) REP RESERVED(0) ATYP(1=IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
    let response = [0x05, reply, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    stream.write_all(&response).await
}

pub async fn send_success(stream: &mut TcpStream) -> io::Result<()> {
    send_reply(stream, REP_SUCCESS).await
}

/// Send a SOCKS5 success reply with a specific bound address (for UDP ASSOCIATE).
pub async fn send_success_with_addr(
    stream: &mut TcpStream,
    addr: std::net::SocketAddr,
) -> io::Result<()> {
    let mut response = Vec::with_capacity(10);
    response.extend_from_slice(&[0x05, REP_SUCCESS, 0x00]);
    match addr {
        std::net::SocketAddr::V4(v4) => {
            response.push(0x01); // ATYP IPv4
            response.extend_from_slice(&v4.ip().octets());
            response.extend_from_slice(&v4.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(v6) => {
            response.push(0x04); // ATYP IPv6
            response.extend_from_slice(&v6.ip().octets());
            response.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    stream.write_all(&response).await
}

pub async fn send_host_unreachable(stream: &mut TcpStream) -> io::Result<()> {
    send_reply(stream, REP_HOST_UNREACHABLE).await
}
