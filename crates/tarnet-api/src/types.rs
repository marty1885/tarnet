use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{self, Visitor};

/// Identity scheme identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IdentityScheme {
    Ed25519 = 0x01,
    FalconEd25519 = 0x02,
}

impl IdentityScheme {
    pub const DEFAULT: Self = Self::FalconEd25519;

    pub fn from_u8(v: u8) -> Result<Self, &'static str> {
        match v {
            0x01 => Ok(Self::Ed25519),
            0x02 => Ok(Self::FalconEd25519),
            _ => Err("unknown identity scheme"),
        }
    }

    pub fn signing_algo(self) -> SigningAlgo {
        match self {
            Self::Ed25519 => SigningAlgo::Ed25519,
            Self::FalconEd25519 => SigningAlgo::FalconEd25519,
        }
    }

    pub fn kem_algo(self) -> KemAlgo {
        match self {
            Self::Ed25519 => KemAlgo::X25519,
            Self::FalconEd25519 => KemAlgo::MlkemX25519,
        }
    }
}

impl fmt::Display for IdentityScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "ed25519"),
            Self::FalconEd25519 => write!(f, "falcon_ed25519"),
        }
    }
}

/// Signing algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SigningAlgo {
    Ed25519 = 0x01,
    FalconEd25519 = 0x02,
}

impl SigningAlgo {
    pub fn from_u8(v: u8) -> Result<Self, &'static str> {
        match v {
            0x01 => Ok(Self::Ed25519),
            0x02 => Ok(Self::FalconEd25519),
            _ => Err("unknown signing algorithm"),
        }
    }
}

impl fmt::Display for SigningAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "ed25519"),
            Self::FalconEd25519 => write!(f, "falcon_ed25519"),
        }
    }
}

/// KEM (Key Encapsulation Mechanism) algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum KemAlgo {
    X25519 = 0x01,
    MlkemX25519 = 0x02,
}

impl KemAlgo {
    pub fn from_u8(v: u8) -> Result<Self, &'static str> {
        match v {
            0x01 => Ok(Self::X25519),
            0x02 => Ok(Self::MlkemX25519),
            _ => Err("unknown KEM algorithm"),
        }
    }

    /// Negotiate the KEM algorithm to use for rekey given both sides' identity
    /// KEM algorithms. Returns the strongest algorithm both sides can perform.
    ///
    /// Each pair of algorithms requires an explicit match arm — the numeric
    /// values carry no ordering, so adding a new variant forces the compiler
    /// to handle every combination.
    pub fn negotiate_rekey(my: Self, peer: Self) -> Self {
        match (my, peer) {
            (Self::X25519, Self::X25519) => Self::X25519,
            (Self::MlkemX25519, Self::MlkemX25519) => Self::MlkemX25519,
            (Self::MlkemX25519, Self::X25519)
            | (Self::X25519, Self::MlkemX25519) => Self::X25519,
            // Future variants: add explicit arms here.
            // The compiler will enforce exhaustiveness.
        }
    }
}

impl fmt::Display for KemAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X25519 => write!(f, "x25519"),
            Self::MlkemX25519 => write!(f, "mlkem_x25519"),
        }
    }
}

/// BLAKE3-derived hash of signing public key, used as peer identity (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 32]);

/// Service identity: BLAKE3-derived hash of signing public key (32 bytes).
/// Looked up via DHT to retrieve actual public keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceId(pub [u8; 32]);

/// BLAKE2b hash of PeerId used for DHT distance calculations (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DhtId(pub [u8; 64]);

/// Privacy level for an identity. Strictly local configuration — never transmitted on the wire
/// or stored in DHT. Relay nodes cannot distinguish privacy levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Publish PeerId in TNS. Anyone who resolves the zone can find the node.
    /// Accepts both direct and circuited connections.
    Public,
    /// Rendezvous only. PeerId never exposed. Only IntroductionPoint records published.
    Hidden { intro_points: u8 },
}

impl Default for PrivacyLevel {
    fn default() -> Self {
        PrivacyLevel::Public
    }
}

impl PeerId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ServiceId {
    /// Wildcard: listen on all managed ServiceIds (like `::` / `0.0.0.0`).
    pub const ALL: ServiceId = ServiceId([0xFF; 32]);

    /// Loopback: only local processes, never over the network (like `::1`).
    pub const LOCAL: ServiceId = ServiceId([0x00; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct from a signing public key (any length — hashed).
    pub fn from_signing_pubkey(pubkey: &[u8]) -> Self {
        let hash = blake3::derive_key("tarnet service-id", pubkey);
        ServiceId(hash)
    }

    /// Whether this is the wildcard ServiceId.
    pub fn is_all(&self) -> bool {
        *self == Self::ALL
    }

    /// Whether this is the loopback ServiceId.
    pub fn is_local(&self) -> bool {
        *self == Self::LOCAL
    }

    /// Parse a string as a ServiceId (Crockford Base32).
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if let Ok(bytes) = decode_base32(s) {
            if bytes.len() >= 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes[..32]);
                return Ok(ServiceId(id));
            }
        }

        Err("doesn't look like a ServiceId")
    }
}

impl DhtId {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// XOR distance between two DHT IDs.
    pub fn xor_distance(&self, other: &DhtId) -> DhtId {
        let mut result = [0u8; 64];
        for i in 0..64 {
            result[i] = self.0[i] ^ other.0[i];
        }
        DhtId(result)
    }
}

impl Ord for DhtId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for DhtId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", hex(&self.0[..8]))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

impl fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_all() {
            write!(f, "ServiceId(ALL)")
        } else if self.is_local() {
            write!(f, "ServiceId(LOCAL)")
        } else {
            write!(f, "ServiceId({})", hex(&self.0[..8]))
        }
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_all() {
            write!(f, "::ALL")
        } else if self.is_local() {
            write!(f, "::LOCAL")
        } else {
            // 32 bytes → 52 base32 chars
            write!(f, "{}", encode_base32(&self.0))
        }
    }
}

impl fmt::Debug for DhtId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DhtId({})", hex(&self.0[..8]))
    }
}

impl fmt::Display for DhtId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

// ── Serde: serialize ID types as binary blobs, not arrays of integers ──

impl Serialize for PeerId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = PeerId;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "32 bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<PeerId, E> {
                if v.len() != 32 {
                    return Err(E::custom(format!("expected 32 bytes, got {}", v.len())));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(v);
                Ok(PeerId(arr))
            }
        }
        d.deserialize_bytes(V)
    }
}

impl Serialize for ServiceId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ServiceId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ServiceId;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "32 bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<ServiceId, E> {
                if v.len() != 32 {
                    return Err(E::custom(format!("expected 32 bytes, got {}", v.len())));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(v);
                Ok(ServiceId(arr))
            }
        }
        d.deserialize_bytes(V)
    }
}

impl Serialize for DhtId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for DhtId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = DhtId;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "64 bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<DhtId, E> {
                if v.len() != 64 {
                    return Err(E::custom(format!("expected 64 bytes, got {}", v.len())));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(DhtId(arr))
            }
        }
        d.deserialize_bytes(V)
    }
}

/// Serde helper for `[u8; 64]` fields that aren't wrapped in DhtId.
pub mod serde_byte_array_64 {
    use serde::{Deserializer, Serializer};
    use serde::de::{self, Visitor};
    use std::fmt;

    pub fn serialize<S: Serializer>(data: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(data)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "64 bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<[u8; 64], E> {
                if v.len() != 64 {
                    return Err(E::custom(format!("expected 64 bytes, got {}", v.len())));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(arr)
            }
        }
        d.deserialize_bytes(V)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Crockford Base32 encoding
// ---------------------------------------------------------------------------

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode bytes as Crockford Base32 (no padding).
pub fn encode_base32(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let bit_len = bytes.len() * 8;
    let out_len = (bit_len + 4) / 5;
    let mut out = String::with_capacity(out_len);

    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | byte as u64;
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let idx = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            out.push(CROCKFORD_ALPHABET[idx] as char);
        }
    }
    if bits_in_buffer > 0 {
        let idx = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        out.push(CROCKFORD_ALPHABET[idx] as char);
    }
    out
}

/// Decode Crockford Base32 string to bytes.
pub fn decode_base32(s: &str) -> Result<Vec<u8>, &'static str> {
    let s = s.to_uppercase();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;
    let mut out = Vec::new();

    for ch in s.chars() {
        let val = match ch {
            '0' | 'O' => 0,
            '1' | 'I' | 'L' => 1,
            '2' => 2,
            '3' => 3,
            '4' => 4,
            '5' => 5,
            '6' => 6,
            '7' => 7,
            '8' => 8,
            '9' => 9,
            'A' => 10,
            'B' => 11,
            'C' => 12,
            'D' => 13,
            'E' => 14,
            'F' => 15,
            'G' => 16,
            'H' => 17,
            'J' => 18,
            'K' => 19,
            'M' => 20,
            'N' => 21,
            'P' => 22,
            'Q' => 23,
            'R' => 24,
            'S' => 25,
            'T' => 26,
            'V' => 27,
            'W' => 28,
            'X' => 29,
            'Y' => 30,
            'Z' => 31,
            '-' => continue, // allow hyphens as separators
            _ => return Err("invalid Crockford Base32 character"),
        };
        buffer = (buffer << 5) | val as u64;
        bits_in_buffer += 5;
        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            out.push((buffer >> bits_in_buffer) as u8);
        }
    }
    Ok(out)
}

// ── Node status types (serialized over IPC) ──

/// Per-link status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkStatus {
    pub link_id: u64,
    pub state: String,
    pub direction: String,
    pub rtt_us: u64,
    pub loss_rate: u8,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub transport: String,
}

/// Per-peer status with all its links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub peer_id: PeerId,
    pub links: Vec<LinkStatus>,
}

/// Traffic statistics for a single metric across time windows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WindowedStats {
    pub total: u64,
    pub last_5min: u64,
    pub last_1hr: u64,
    pub last_1day: u64,
}

/// Global traffic summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStatus {
    pub bytes_up: WindowedStats,
    pub bytes_down: WindowedStats,
    pub packets_up: WindowedStats,
    pub packets_down: WindowedStats,
    pub cells_relayed: WindowedStats,
}

/// DHT subsystem status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStatus {
    pub stored_keys: usize,
    pub stored_records: usize,
    pub kbucket_peers: usize,
    pub local_watches: usize,
    pub remote_watches: usize,
    /// Estimated network size (2^l2nse).
    pub nse: u64,
}

/// Circuit subsystem status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitStatus {
    pub relay_forwards: usize,
    pub relay_endpoints: usize,
    pub outbound_circuits: usize,
    pub rendezvous_points: usize,
    pub intro_points: usize,
}

/// Complete node status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub peer_id: PeerId,
    pub uptime_secs: u64,
    pub peers: Vec<PeerStatus>,
    pub routes: Vec<(PeerId, PeerId, u32)>,
    pub dht: DhtStatus,
    pub circuits: CircuitStatus,
    pub traffic: TrafficStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_id_from_signing_pubkey() {
        let pubkey = [0xAB; 32];
        let sid = ServiceId::from_signing_pubkey(&pubkey);
        assert_eq!(sid.0.len(), 32);
        // Deterministic
        assert_eq!(sid, ServiceId::from_signing_pubkey(&pubkey));
        // Different pubkey gives different ServiceId
        let other = ServiceId::from_signing_pubkey(&[0xCD; 32]);
        assert_ne!(sid, other);
    }

    #[test]
    fn service_id_variable_length_pubkey() {
        // falcon_ed25519 pubkey is 929 bytes
        let pubkey_short = [0x42; 32];
        let pubkey_long = [0x42; 929];
        let sid_short = ServiceId::from_signing_pubkey(&pubkey_short);
        let sid_long = ServiceId::from_signing_pubkey(&pubkey_long);
        // Different length inputs produce different IDs
        assert_ne!(sid_short, sid_long);
    }

    #[test]
    fn identity_scheme_roundtrip() {
        assert_eq!(IdentityScheme::from_u8(0x01).unwrap(), IdentityScheme::Ed25519);
        assert_eq!(IdentityScheme::from_u8(0x02).unwrap(), IdentityScheme::FalconEd25519);
    }

    #[test]
    fn identity_scheme_maps_to_algos() {
        assert_eq!(IdentityScheme::Ed25519.signing_algo(), SigningAlgo::Ed25519);
        assert_eq!(IdentityScheme::Ed25519.kem_algo(), KemAlgo::X25519);
        assert_eq!(
            IdentityScheme::FalconEd25519.signing_algo(),
            SigningAlgo::FalconEd25519
        );
        assert_eq!(
            IdentityScheme::FalconEd25519.kem_algo(),
            KemAlgo::MlkemX25519
        );
    }

    #[test]
    fn base32_roundtrip() {
        let data = b"hello world";
        let encoded = encode_base32(data);
        let decoded = decode_base32(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn base32_32_bytes() {
        let data = [0x42; 32];
        let encoded = encode_base32(&data);
        // 32 bytes * 8 / 5 = 51.2 -> 52 chars
        assert_eq!(encoded.len(), 52);
        let decoded = decode_base32(&encoded).unwrap();
        assert_eq!(&decoded[..32], &data[..]);
    }

    #[test]
    fn base32_case_insensitive() {
        let data = b"test";
        let encoded = encode_base32(data);
        let lower = encoded.to_lowercase();
        let decoded = decode_base32(&lower).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn well_known_service_ids() {
        assert!(ServiceId::ALL.is_all());
        assert!(!ServiceId::ALL.is_local());
        assert!(ServiceId::LOCAL.is_local());
        assert!(!ServiceId::LOCAL.is_all());
        assert_eq!(ServiceId::ALL.0.len(), 32);
        assert_eq!(ServiceId::LOCAL.0.len(), 32);
    }

    #[test]
    fn signing_algo_roundtrip() {
        assert_eq!(SigningAlgo::from_u8(0x01).unwrap(), SigningAlgo::Ed25519);
        assert_eq!(SigningAlgo::from_u8(0x02).unwrap(), SigningAlgo::FalconEd25519);
    }

    #[test]
    fn signing_algo_rejects_unknown() {
        assert!(SigningAlgo::from_u8(0x00).is_err());
        assert!(SigningAlgo::from_u8(0x03).is_err());
        assert!(SigningAlgo::from_u8(0xFF).is_err());
    }

    #[test]
    fn kem_algo_roundtrip() {
        assert_eq!(KemAlgo::from_u8(0x01).unwrap(), KemAlgo::X25519);
        assert_eq!(KemAlgo::from_u8(0x02).unwrap(), KemAlgo::MlkemX25519);
    }

    #[test]
    fn kem_algo_rejects_unknown() {
        assert!(KemAlgo::from_u8(0x00).is_err());
        assert!(KemAlgo::from_u8(0x03).is_err());
        assert!(KemAlgo::from_u8(0xFF).is_err());
    }
}
