use crate::types::{Error, PeerId, Result};

/// Prefix for mainline DHT bootstrap addresses.
pub const MAINLINE_PREFIX: &str = "mainline:";

/// Decode a hex string into a fixed-size byte array.
fn decode_hex<const N: usize>(hex_str: &str) -> Result<[u8; N]> {
    if hex_str.len() != N * 2 {
        return Err(Error::Wire(format!(
            "expected {} hex chars, got {}",
            N * 2,
            hex_str.len()
        )));
    }
    let mut bytes = [0u8; N];
    for i in 0..N {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| Error::Wire(format!("invalid hex: {}", e)))?;
    }
    Ok(bytes)
}

/// Parse a `mainline:<hex-peer-id>` bootstrap address.
/// Returns the target PeerId.
pub fn parse_mainline_addr(addr: &str) -> Result<PeerId> {
    let hex_str = addr
        .strip_prefix(MAINLINE_PREFIX)
        .ok_or_else(|| Error::Wire("not a mainline address".into()))?;
    let bytes = decode_hex::<32>(hex_str)
        .map_err(|_| Error::Wire(format!("invalid hex in mainline address")))?;
    Ok(PeerId(bytes))
}

/// Format a mainline bootstrap address string for a given PeerId.
pub fn format_mainline_addr(peer_id: &PeerId) -> String {
    let hex: String = peer_id
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("{}{}", MAINLINE_PREFIX, hex)
}

/// Derive a 20-byte mainline DHT info_hash from a tarnet PeerId.
/// Each node gets a unique info_hash, spreading DHT load across the network.
#[cfg(feature = "mainline-bootstrap")]
pub fn mainline_info_hash(peer_id: &PeerId) -> [u8; 20] {
    let mut hasher = sha1_smol::Sha1::new();
    hasher.update(b"tarnet-v1");
    hasher.update(peer_id.as_bytes());
    hasher.digest().bytes()
}

#[cfg(feature = "mainline-bootstrap")]
mod mainline_dht {
    use super::*;
    use std::net::SocketAddrV4;

    /// Wrapper around the mainline DHT client.
    pub struct MainlineDht {
        dht: mainline::Dht,
    }

    impl MainlineDht {
        /// Join the mainline DHT network in client mode (lightweight, no serving).
        pub fn new() -> Result<Self> {
            let dht = mainline::Dht::client()
                .map_err(|e| Error::Protocol(format!("mainline DHT client: {}", e)))?;
            Ok(Self { dht })
        }

        /// Announce our TCP port under our PeerId-derived info_hash.
        /// Should be called periodically (mainline announcements expire after ~30 min).
        pub fn announce(&self, peer_id: &PeerId, port: u16) -> Result<()> {
            let hash = mainline_info_hash(peer_id);
            let id = mainline::Id::from(hash);
            self.dht
                .announce_peer(id, Some(port))
                .map_err(|e| Error::Protocol(format!("mainline announce: {}", e)))?;
            log::debug!("Mainline DHT: announced port {} for {:?}", port, peer_id);
            Ok(())
        }

        /// Look up a remote peer's address on the mainline DHT.
        /// Returns the first batch of peer addresses found.
        pub fn lookup(&self, target_peer_id: &PeerId) -> Vec<SocketAddrV4> {
            let hash = mainline_info_hash(target_peer_id);
            let id = mainline::Id::from(hash);
            let mut results = Vec::new();
            for batch in self.dht.get_peers(id) {
                results.extend(batch);
                if !results.is_empty() {
                    break;
                }
            }
            results
        }

    }
}

#[cfg(feature = "mainline-bootstrap")]
pub use mainline_dht::MainlineDht;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mainline_addr_roundtrip() {
        let pid = PeerId([0xab; 32]);
        let addr = format_mainline_addr(&pid);
        assert!(addr.starts_with(MAINLINE_PREFIX));
        assert_eq!(addr.len(), MAINLINE_PREFIX.len() + 64);
        let parsed = parse_mainline_addr(&addr).unwrap();
        assert_eq!(parsed, pid);
    }

    #[test]
    fn parse_mainline_addr_bad_length() {
        assert!(parse_mainline_addr("mainline:abcd").is_err());
    }

    #[test]
    fn parse_mainline_addr_bad_hex() {
        let bad = format!("mainline:{}", "zz".repeat(32));
        assert!(parse_mainline_addr(&bad).is_err());
    }
}
