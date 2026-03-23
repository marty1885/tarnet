use std::fmt;

// Re-export from tarnet-api — these are the canonical definitions.
// Everything in this crate and downstream uses the same types.
pub use tarnet_api::types::{DhtId, PeerId, PrivacyLevel};

/// Monotonic link identifier, never reused. Distinguishes multiple links to the same peer.
pub type LinkId = u64;

/// DHT record types. Each type describes storage semantics (how to validate,
/// when to replace) — not application semantics. The DHT uses types to serve
/// its own correctness: propagation integrity, retrieval correctness, overlay health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// Signed by owning peer, mutable via sequence numbers.
    /// Used for overlay maintenance (peer address announcements).
    /// Replacement: same signer + higher sequence wins.
    Hello,
    /// Signed by publisher, immutable. Content-addressed key.
    /// Relays verify signature before propagating — stops fake data.
    /// Multiple records per key allowed (supplemental, different signers).
    SignedContent,
    /// Unsigned, immutable. Content-addressed key.
    /// Relays cannot verify — lowest trust. Self-authenticating for reader only.
    /// Single record per key (first write wins).
    Content,
    /// Unknown record type from a newer protocol version.
    /// Stored and relayed without validation.
    Unknown(u8),
}

impl RecordType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Hello,
            1 => Self::SignedContent,
            2 => Self::Content,
            _ => Self::Unknown(v),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Hello => 0,
            Self::SignedContent => 1,
            Self::Content => 2,
            Self::Unknown(v) => *v,
        }
    }

    /// Whether this record type requires signature verification.
    pub fn is_signed(&self) -> bool {
        matches!(self, Self::Hello | Self::SignedContent)
    }

    /// Whether this record type supports mutable updates via sequence numbers.
    pub fn is_mutable(&self) -> bool {
        matches!(self, Self::Hello)
    }
}

/// Transport address type codes. Self-describing: the type tells you
/// how to interpret the address bytes and what transport to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// TCP over IPv4. Address: ip4(4 bytes) + port(2 bytes BE) = 6 bytes.
    Tcp4,
    /// TCP over IPv6. Address: ip6(16 bytes) + port(2 bytes BE) = 18 bytes.
    Tcp6,
    /// WebRTC data channel. No address bytes — signaled via overlay.
    WebRtc,
    /// WebSocket. Address: UTF-8 URL (e.g. "wss://host:port/path").
    Ws,
    /// Unknown transport from a newer protocol version.
    Unknown(u16),
}

impl TransportType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0000 => Self::Tcp4,
            0x0001 => Self::Tcp6,
            0x0002 => Self::WebRtc,
            0x0003 => Self::Ws,
            _ => Self::Unknown(v),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            Self::Tcp4 => 0x0000,
            Self::Tcp6 => 0x0001,
            Self::WebRtc => 0x0002,
            Self::Ws => 0x0003,
            Self::Unknown(v) => *v,
        }
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp4 => write!(f, "TCP/IPv4"),
            Self::Tcp6 => write!(f, "TCP/IPv6"),
            Self::WebRtc => write!(f, "WebRTC"),
            Self::Ws => write!(f, "WebSocket"),
            Self::Unknown(v) => write!(f, "unknown(0x{:04x})", v),
        }
    }
}

/// Address scope: describes who can meaningfully use this address.
///
/// Only `Global` and `SiteLocal` are real scopes — they describe connectable
/// addresses that a third party could use to establish a new link.
///
/// Point-to-point transports (RS232, USB) and link-local addresses (127.x, fe80::)
/// are NOT addresses — they are links. They never enter the address system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressScope {
    /// Validated reachable from the public internet.
    /// Published in hello records. Any peer can use this.
    Global,
    /// Routable within a local site (e.g. 192.168.x, 10.x).
    /// Shared only over encrypted channels with same-site peers.
    SiteLocal,
}

impl AddressScope {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Global),
            1 => Some(Self::SiteLocal),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Global => 0,
            Self::SiteLocal => 1,
        }
    }
}

/// A scoped, connectable transport address.
///
/// Represents how a peer *not yet connected* can establish a new link.
/// Point-to-point transports (RS232, USB) never produce a ScopedAddress —
/// they produce links directly, because no third party can use them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedAddress {
    pub scope: AddressScope,
    pub transport_type: TransportType,
    pub address: Vec<u8>,
}

impl ScopedAddress {
    /// Wire format: scope(u8) || transport_type(u16 BE) || addr_len(u16 BE) || addr_bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.address.len());
        buf.push(self.scope.as_u8());
        buf.extend_from_slice(&self.transport_type.as_u16().to_be_bytes());
        buf.extend_from_slice(&(self.address.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.address);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 5 {
            return Err(Error::Wire("ScopedAddress too short".into()));
        }
        let scope = AddressScope::from_u8(data[0])
            .ok_or_else(|| Error::Wire(format!("unknown address scope: {}", data[0])))?;
        let transport_type = TransportType::from_u16(u16::from_be_bytes([data[1], data[2]]));
        let addr_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + addr_len {
            return Err(Error::Wire("ScopedAddress truncated".into()));
        }
        let address = data[5..5 + addr_len].to_vec();
        Ok((
            Self {
                scope,
                transport_type,
                address,
            },
            5 + addr_len,
        ))
    }

    /// Convert to a connectable string (e.g. "127.0.0.1:7946").
    pub fn to_connect_string(&self) -> Option<String> {
        // Delegate to TransportAddress logic
        let ta = TransportAddress {
            transport_type: self.transport_type,
            address: self.address.clone(),
        };
        ta.to_connect_string()
    }

    /// Create a Global-scoped address from a socket addr.
    pub fn global_from_socket_addr(addr: std::net::SocketAddr) -> Self {
        let ta = TransportAddress::from_socket_addr(addr);
        Self {
            scope: AddressScope::Global,
            transport_type: ta.transport_type,
            address: ta.address,
        }
    }

    /// Create a SiteLocal-scoped address from a socket addr.
    pub fn site_local_from_socket_addr(addr: std::net::SocketAddr) -> Self {
        let ta = TransportAddress::from_socket_addr(addr);
        Self {
            scope: AddressScope::SiteLocal,
            transport_type: ta.transport_type,
            address: ta.address,
        }
    }

    /// Classify a socket address and create appropriately scoped ScopedAddress.
    pub fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        let scope = if is_global_addr(&addr) {
            AddressScope::Global
        } else {
            AddressScope::SiteLocal
        };
        let ta = TransportAddress::from_socket_addr(addr);
        Self {
            scope,
            transport_type: ta.transport_type,
            address: ta.address,
        }
    }

    /// Parse from a string like "127.0.0.1:7946" or "[fe80::1%eth0]:7946", auto-classifying scope.
    pub fn from_string(s: &str) -> Result<Self> {
        let addr = parse_socket_addr(s)?;
        Ok(Self::from_socket_addr(addr))
    }

    /// Create a Global-scoped WebSocket address from a URL.
    /// The URL (e.g. "wss://relay.example.com/tarnet") is stored as UTF-8 bytes.
    pub fn from_ws_url(url: &str) -> Self {
        Self {
            scope: AddressScope::Global,
            transport_type: TransportType::Ws,
            address: url.as_bytes().to_vec(),
        }
    }
}

impl fmt::Display for ScopedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scope_str = match self.scope {
            AddressScope::Global => "global",
            AddressScope::SiteLocal => "site",
        };
        match self.to_connect_string() {
            Some(s) => write!(f, "{}:{}", scope_str, s),
            None => write!(
                f,
                "{}:{:?}:{}",
                scope_str,
                self.transport_type,
                hex(&self.address)
            ),
        }
    }
}

/// Parse a socket address string with support for IPv6 zone IDs (e.g. `[fe80::1%eth0]:7946`).
///
/// The zone ID can be a numeric scope ID or an interface name (resolved via `if_nametoindex`).
/// Falls back to standard `ToSocketAddrs` resolution when no zone ID is present.
pub fn parse_socket_addr(s: &str) -> Result<std::net::SocketAddr> {
    if let Some(pct) = s.find('%') {
        // Expect format: [addr%zone]:port
        let close = s[pct..]
            .find(']')
            .map(|i| i + pct)
            .ok_or_else(|| Error::Wire(format!("invalid zone ID address '{}'", s)))?;
        let zone = &s[pct + 1..close];
        let clean = format!("{}{}", &s[..pct], &s[close..]);
        let base: std::net::SocketAddr = clean
            .parse()
            .map_err(|e| Error::Wire(format!("invalid address '{}': {}", s, e)))?;
        match base {
            std::net::SocketAddr::V6(v6) => {
                let scope_id = zone_to_scope_id(zone)?;
                Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    *v6.ip(),
                    v6.port(),
                    v6.flowinfo(),
                    scope_id,
                )))
            }
            _ => Err(Error::Wire(format!(
                "zone ID is only valid for IPv6 addresses: '{}'",
                s
            ))),
        }
    } else {
        use std::net::ToSocketAddrs;
        s.to_socket_addrs()
            .map_err(|e| Error::Wire(format!("invalid address '{}': {}", s, e)))?
            .next()
            .ok_or_else(|| Error::Wire(format!("no address resolved for '{}'", s)))
    }
}

/// Resolve an IPv6 zone ID string to a numeric scope ID.
/// Accepts numeric IDs directly or interface names (e.g. "eth0").
fn zone_to_scope_id(zone: &str) -> Result<u32> {
    if let Ok(id) = zone.parse::<u32>() {
        return Ok(id);
    }
    #[cfg(unix)]
    {
        let name = std::ffi::CString::new(zone)
            .map_err(|_| Error::Wire(format!("invalid interface name '{}'", zone)))?;
        let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if idx == 0 {
            return Err(Error::Wire(format!("unknown interface '{}'", zone)));
        }
        Ok(idx)
    }
    #[cfg(not(unix))]
    {
        Err(Error::Wire(format!(
            "interface name resolution not supported on this platform: '{}'",
            zone
        )))
    }
}

/// Returns true if the socket address is globally routable (not RFC1918, loopback, link-local).
pub fn is_global_addr(addr: &std::net::SocketAddr) -> bool {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let ip = v4.ip();
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
        }
        std::net::SocketAddr::V6(v6) => {
            let ip = v6.ip();
            let segs = ip.segments();
            let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
            let is_site_local = (segs[0] & 0xffc0) == 0xfec0;
            let is_ula = (segs[0] & 0xfe00) == 0xfc00;
            !ip.is_loopback() && !ip.is_unspecified() && !is_link_local && !is_site_local && !is_ula
        }
    }
}

/// A typed, self-describing transport address.
/// Used internally for wire compatibility. Prefer ScopedAddress for new code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportAddress {
    pub transport_type: TransportType,
    pub address: Vec<u8>,
}

impl TransportAddress {
    /// Create from a std::net::SocketAddr.
    pub fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(v4) => {
                let mut address = Vec::with_capacity(6);
                address.extend_from_slice(&v4.ip().octets());
                address.extend_from_slice(&v4.port().to_be_bytes());
                Self {
                    transport_type: TransportType::Tcp4,
                    address,
                }
            }
            std::net::SocketAddr::V6(v6) => {
                let scope_id = v6.scope_id();
                let capacity = if scope_id != 0 { 22 } else { 18 };
                let mut address = Vec::with_capacity(capacity);
                address.extend_from_slice(&v6.ip().octets());
                address.extend_from_slice(&v6.port().to_be_bytes());
                if scope_id != 0 {
                    address.extend_from_slice(&scope_id.to_be_bytes());
                }
                Self {
                    transport_type: TransportType::Tcp6,
                    address,
                }
            }
        }
    }

    /// Convert to a connectable string (e.g. "127.0.0.1:7946").
    pub fn to_connect_string(&self) -> Option<String> {
        match self.transport_type {
            TransportType::Tcp4 => {
                if self.address.len() < 6 {
                    return None;
                }
                let ip = std::net::Ipv4Addr::new(
                    self.address[0],
                    self.address[1],
                    self.address[2],
                    self.address[3],
                );
                let port = u16::from_be_bytes([self.address[4], self.address[5]]);
                Some(format!("{}:{}", ip, port))
            }
            TransportType::Tcp6 => {
                if self.address.len() < 18 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.address[..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([self.address[16], self.address[17]]);
                let scope_id = if self.address.len() >= 22 {
                    u32::from_be_bytes([
                        self.address[18],
                        self.address[19],
                        self.address[20],
                        self.address[21],
                    ])
                } else {
                    0
                };
                if scope_id != 0 {
                    Some(format!("[{}%{}]:{}", ip, scope_id, port))
                } else {
                    Some(format!("[{}]:{}", ip, port))
                }
            }
            TransportType::Ws => std::str::from_utf8(&self.address)
                .ok()
                .map(|s| s.to_string()),
            TransportType::WebRtc | TransportType::Unknown(_) => None,
        }
    }

    /// Parse from a string like "127.0.0.1:7946", "[::1]:7946", or "[fe80::1%eth0]:7946".
    pub fn from_string(s: &str) -> Result<Self> {
        let addr = parse_socket_addr(s)?;
        Ok(Self::from_socket_addr(addr))
    }

    /// Wire format: transport_type(u16 BE) || addr_len(u16 BE) || addr_bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.address.len());
        buf.extend_from_slice(&self.transport_type.as_u16().to_be_bytes());
        buf.extend_from_slice(&(self.address.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.address);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(Error::Wire("TransportAddress too short".into()));
        }
        let transport_type = TransportType::from_u16(u16::from_be_bytes([data[0], data[1]]));
        let addr_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + addr_len {
            return Err(Error::Wire("TransportAddress truncated".into()));
        }
        let address = data[4..4 + addr_len].to_vec();
        Ok((
            Self {
                transport_type,
                address,
            },
            4 + addr_len,
        ))
    }
}

impl fmt::Display for TransportAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_connect_string() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "{:?}:{}", self.transport_type, hex(&self.address)),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("wire format error: {0}")]
    Wire(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("not found")]
    NotFound,
    #[error("replay detected: {0}")]
    Replay(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_roundtrip() {
        assert_eq!(RecordType::from_u8(0), RecordType::Hello);
        assert_eq!(RecordType::from_u8(1), RecordType::SignedContent);
        assert_eq!(RecordType::from_u8(2), RecordType::Content);
        assert_eq!(RecordType::from_u8(3), RecordType::Unknown(3));
        assert_eq!(RecordType::from_u8(255), RecordType::Unknown(255));
    }

    #[test]
    fn record_type_unknown_roundtrip() {
        let rt = RecordType::from_u8(99);
        assert_eq!(rt, RecordType::Unknown(99));
        assert_eq!(rt.as_u8(), 99);
        assert!(!rt.is_signed());
        assert!(!rt.is_mutable());
    }

    #[test]
    fn record_type_properties() {
        assert!(RecordType::Hello.is_signed());
        assert!(RecordType::Hello.is_mutable());
        assert!(RecordType::SignedContent.is_signed());
        assert!(!RecordType::SignedContent.is_mutable());
        assert!(!RecordType::Content.is_signed());
        assert!(!RecordType::Content.is_mutable());
    }

    #[test]
    fn transport_type_roundtrip() {
        assert_eq!(TransportType::from_u16(0x0000), TransportType::Tcp4);
        assert_eq!(TransportType::from_u16(0x0001), TransportType::Tcp6);
        assert_eq!(TransportType::from_u16(0x0002), TransportType::WebRtc);
        assert_eq!(TransportType::from_u16(0x0003), TransportType::Ws);
        assert_eq!(
            TransportType::from_u16(0x0004),
            TransportType::Unknown(0x0004)
        );
    }

    #[test]
    fn transport_type_unknown_roundtrip() {
        let tt = TransportType::from_u16(0x0099);
        assert_eq!(tt, TransportType::Unknown(0x0099));
        assert_eq!(tt.as_u16(), 0x0099);
    }

    #[test]
    fn transport_address_tcp4_roundtrip() {
        let addr = TransportAddress::from_string("127.0.0.1:7946").unwrap();
        assert_eq!(addr.transport_type, TransportType::Tcp4);
        assert_eq!(addr.to_connect_string().unwrap(), "127.0.0.1:7946");

        let bytes = addr.to_bytes();
        let (decoded, consumed) = TransportAddress::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.transport_type, TransportType::Tcp4);
        assert_eq!(decoded.to_connect_string().unwrap(), "127.0.0.1:7946");
    }

    #[test]
    fn transport_address_tcp6_roundtrip() {
        let addr = TransportAddress::from_string("[::1]:8080").unwrap();
        assert_eq!(addr.transport_type, TransportType::Tcp6);
        assert_eq!(addr.to_connect_string().unwrap(), "[::1]:8080");

        let bytes = addr.to_bytes();
        let (decoded, _) = TransportAddress::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.transport_type, TransportType::Tcp6);
        assert_eq!(decoded.to_connect_string().unwrap(), "[::1]:8080");
    }

    #[test]
    fn transport_address_from_socket_addr() {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443));
        let ta4 = TransportAddress::from_socket_addr(v4);
        assert_eq!(ta4.transport_type, TransportType::Tcp4);
        assert_eq!(ta4.to_connect_string().unwrap(), "10.0.0.1:443");

        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9000, 0, 0));
        let ta6 = TransportAddress::from_socket_addr(v6);
        assert_eq!(ta6.transport_type, TransportType::Tcp6);
        assert_eq!(ta6.to_connect_string().unwrap(), "[::1]:9000");
    }

    #[test]
    fn transport_address_display() {
        let addr = TransportAddress::from_string("192.168.1.1:5000").unwrap();
        assert_eq!(format!("{}", addr), "192.168.1.1:5000");
    }

    #[test]
    fn transport_address_wire_too_short() {
        assert!(TransportAddress::from_bytes(&[0, 0]).is_err());
        assert!(TransportAddress::from_bytes(&[]).is_err());
    }

    #[test]
    fn parse_socket_addr_ipv4() {
        let addr = parse_socket_addr("127.0.0.1:8080").unwrap();
        assert_eq!(
            addr,
            "127.0.0.1:8080".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_socket_addr_ipv6_no_zone() {
        let addr = parse_socket_addr("[::1]:9000").unwrap();
        assert_eq!(addr, "[::1]:9000".parse::<std::net::SocketAddr>().unwrap());
    }

    #[test]
    fn parse_socket_addr_ipv6_numeric_zone() {
        let addr = parse_socket_addr("[fe80::1%3]:7946").unwrap();
        match addr {
            std::net::SocketAddr::V6(v6) => {
                assert_eq!(v6.scope_id(), 3);
                assert_eq!(v6.port(), 7946);
                assert_eq!(*v6.ip(), "fe80::1".parse::<std::net::Ipv6Addr>().unwrap());
            }
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn transport_address_tcp6_scope_id_roundtrip() {
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
        let v6 = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            7946,
            0,
            5,
        ));
        let ta = TransportAddress::from_socket_addr(v6);
        assert_eq!(ta.transport_type, TransportType::Tcp6);
        assert_eq!(ta.address.len(), 22); // 16 + 2 + 4
        assert_eq!(ta.to_connect_string().unwrap(), "[fe80::1%5]:7946");

        // Wire roundtrip
        let bytes = ta.to_bytes();
        let (decoded, consumed) = TransportAddress::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.to_connect_string().unwrap(), "[fe80::1%5]:7946");
    }

    #[test]
    fn transport_address_tcp6_no_scope_id() {
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0));
        let ta = TransportAddress::from_socket_addr(v6);
        assert_eq!(ta.address.len(), 18); // no scope_id bytes
        assert_eq!(ta.to_connect_string().unwrap(), "[::1]:8080");
    }

    #[test]
    fn is_global_ipv6_link_local() {
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
        let ll = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            1234,
            0,
            0,
        ));
        assert!(!is_global_addr(&ll));
    }

    #[test]
    fn scoped_address_link_local_is_site_local() {
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
        let ll = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            7946,
            0,
            3,
        ));
        let sa = ScopedAddress::from_socket_addr(ll);
        assert_eq!(sa.scope, AddressScope::SiteLocal);
    }

    #[test]
    fn dht_id_xor_distance() {
        let a = DhtId([0xFF; 64]);
        let b = DhtId([0x00; 64]);
        let dist = a.xor_distance(&b);
        assert_eq!(dist, DhtId([0xFF; 64]));

        let self_dist = a.xor_distance(&a);
        assert_eq!(self_dist, DhtId([0x00; 64]));
    }

    #[test]
    fn peer_id_display_and_debug() {
        let pid = PeerId([0xAB; 32]);
        let display = format!("{}", pid);
        assert_eq!(display.len(), 64); // 32 bytes → 64 hex chars
        let debug = format!("{:?}", pid);
        assert!(debug.starts_with("PeerId("));
    }
}
