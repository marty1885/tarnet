use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

const STUN_TIMEOUT: Duration = Duration::from_secs(3);
const MAGIC_COOKIE: u32 = 0x2112A442;

/// Query STUN servers for our public (server-reflexive) address.
/// Tries servers in order; returns the first successful result.
pub async fn query_public_addr(servers: &[String], local_port: u16) -> Option<SocketAddr> {
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse().ok()?;
    let sock = UdpSocket::bind(bind_addr).await.ok()?;

    for server in servers {
        let host = server.strip_prefix("stun:").unwrap_or(server);
        if let Some(addr) = query_one(&sock, host).await {
            return Some(addr);
        }
    }
    None
}

async fn query_one(sock: &UdpSocket, server: &str) -> Option<SocketAddr> {
    // Resolve STUN server address
    let target: SocketAddr = tokio::net::lookup_host(server).await.ok()?.next()?;

    // Build STUN Binding Request (20 bytes)
    let mut req = [0u8; 20];
    // Type: Binding Request (0x0001)
    req[0] = 0x00;
    req[1] = 0x01;
    // Length: 0 (no attributes)
    req[2] = 0x00;
    req[3] = 0x00;
    // Magic cookie
    req[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 random bytes)
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut req[8..20]);
    let txn_id = &req[8..20];

    sock.send_to(&req, target).await.ok()?;

    let mut buf = [0u8; 512];
    let n = timeout(STUN_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?
        .0;

    if n < 20 {
        return None;
    }

    // Verify it's a Binding Response (0x0101) with matching transaction ID
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != 0x0101 {
        return None;
    }
    if buf[8..20] != *txn_id {
        return None;
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if 20 + msg_len > n {
        return None;
    }

    // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    let mut pos = 20;
    while pos + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let attr_start = pos + 4;
        if attr_start + attr_len > 20 + msg_len {
            break;
        }

        if attr_type == 0x0020 {
            // XOR-MAPPED-ADDRESS
            return parse_xor_mapped(&buf[attr_start..attr_start + attr_len]);
        }
        if attr_type == 0x0001 {
            // MAPPED-ADDRESS (fallback)
            return parse_mapped(&buf[attr_start..attr_start + attr_len]);
        }

        // Attributes are padded to 4-byte boundaries
        pos = attr_start + ((attr_len + 3) & !3);
    }

    None
}

fn parse_xor_mapped(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let xport = u16::from_be_bytes([data[2], data[3]]) ^ (MAGIC_COOKIE >> 16) as u16;

    if family == 0x01 {
        // IPv4
        let xaddr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ MAGIC_COOKIE;
        let ip = std::net::Ipv4Addr::from(xaddr);
        Some(SocketAddr::new(ip.into(), xport))
    } else {
        None // IPv6 STUN parsing omitted for now
    }
}

fn parse_mapped(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    if family == 0x01 {
        let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        Some(SocketAddr::new(ip.into(), port))
    } else {
        None
    }
}
