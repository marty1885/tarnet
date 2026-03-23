use crate::types::{Error, PeerId, RecordType, Result, ScopedAddress, TransportType};

/// Minimum wire protocol version this node supports.
pub const WIRE_VERSION_MIN: u8 = 2;
/// Maximum (current) wire protocol version this node supports.
pub const WIRE_VERSION_MAX: u8 = 2;
/// Current wire version used in outgoing messages.
pub const WIRE_VERSION: u8 = WIRE_VERSION_MAX;
pub const HEADER_SIZE: usize = 5;
pub const MAX_PAYLOAD: usize = 65535;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = u16::from_be_bytes(self.data[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.pos + N > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(arr)
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.pos + n > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    fn read_rest(&mut self) -> Vec<u8> {
        let v = self.data[self.pos..].to_vec();
        self.pos = self.data.len();
        v
    }
}

macro_rules! enum_with_u16 {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($variant:ident = $val:expr),* $(,)? }) => {
        $(#[$meta])*
        $vis enum $name {
            $($variant),*
        }

        impl $name {
            pub fn from_u16(v: u16) -> Option<Self> {
                match v {
                    $($val => Some(Self::$variant),)*
                    _ => None,
                }
            }

            pub fn as_u16(&self) -> u16 {
                match self {
                    $(Self::$variant => $val,)*
                }
            }
        }
    };
}

enum_with_u16! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MessageType {
        // Link-level (0x00xx)
        HandshakeHello = 0x0001,
        HandshakeAuth = 0x0002,
        HandshakeConfirm = 0x0003,
        Rekey = 0x0004,
        Keepalive = 0x0005,
        // Routing (0x01xx)
        RouteAdvertisement = 0x0100,
        RouteProbe = 0x0101,
        RouteProbeFound = 0x0102,
        // DHT (0x02xx)
        DhtPut = 0x0200,
        DhtGet = 0x0201,
        DhtGetResponse = 0x0202,
        DhtWatch = 0x0203,
        DhtWatchNotify = 0x0204,
        DhtFindClosest = 0x0205,
        DhtFindClosestResponse = 0x0206,
        // Tunnel (0x03xx) — stateless key exchange
        TunnelKeyExchange = 0x0300,
        TunnelKeyResponse = 0x0301,
        // Channel (0x04xx)
        ChannelOpen = 0x0400,
        ChannelData = 0x0401,
        ChannelAck = 0x0402,
        ChannelClose = 0x0403,
        // Overlay-routed data (0x05xx)
        Data = 0x0500,
        EncryptedData = 0x0501,
        // Circuit (0x07xx) — circuit-based forwarding
        CircuitCreate = 0x0700,
        CircuitCreated = 0x0701,
        CircuitRelay = 0x0702,
        CircuitDestroy = 0x0703,
    }
}

/// Wire message: VER(u8) | TYPE(u16 BE) | LEN(u16 BE) | PAYLOAD
#[derive(Debug, Clone)]
pub struct WireMessage {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl WireMessage {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Encode to wire format bytes.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.push(WIRE_VERSION);
        buf.extend_from_slice(&self.msg_type.as_u16().to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from wire format bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::Wire("message too short for header".into()));
        }
        let ver = data[0];
        if ver < WIRE_VERSION_MIN || ver > WIRE_VERSION_MAX {
            return Err(Error::Wire(format!(
                "unsupported version: {} (supported {}-{})",
                ver, WIRE_VERSION_MIN, WIRE_VERSION_MAX,
            )));
        }
        let msg_type_raw = u16::from_be_bytes([data[1], data[2]]);
        let len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < HEADER_SIZE + len {
            return Err(Error::Wire(format!(
                "payload too short: expected {} got {}",
                len,
                data.len() - HEADER_SIZE
            )));
        }
        let msg_type = MessageType::from_u16(msg_type_raw)
            .ok_or_else(|| Error::Wire(format!("unknown message type: 0x{:04x}", msg_type_raw)))?;
        let payload = data[HEADER_SIZE..HEADER_SIZE + len].to_vec();
        Ok(Self { msg_type, payload })
    }
}

// ── Specific message payload structs ──

/// HandshakeHello: ephemeral(32) || signing_algo(u8) || signing_pk_len(u16 BE) || signing_pk || kem_algo(u8) || kem_pk_len(u16 BE) || kem_pk || timestamp(u64 BE) || challenge(32) || eph_kem_pk_len(u16 BE) || eph_kem_pk || min_version(u8) || max_version(u8)
#[derive(Debug, Clone)]
pub struct HandshakeHello {
    pub ephemeral_pubkey: [u8; 32],
    pub signing_algo: u8,
    pub signing_pubkey: Vec<u8>,
    pub kem_algo: u8,
    pub kem_pubkey: Vec<u8>,
    pub timestamp: u64,
    pub challenge: [u8; 32],
    /// Ephemeral KEM public key for per-session PQ forward secrecy.
    pub eph_kem_pubkey: Vec<u8>,
    /// Minimum wire protocol version this node supports.
    pub min_version: u8,
    /// Maximum wire protocol version this node supports.
    pub max_version: u8,
}

impl HandshakeHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = 32
            + 1
            + 2
            + self.signing_pubkey.len()
            + 1
            + 2
            + self.kem_pubkey.len()
            + 8
            + 32
            + 2
            + self.eph_kem_pubkey.len()
            + 2;
        let mut buf = Vec::with_capacity(len);
        buf.extend_from_slice(&self.ephemeral_pubkey);
        buf.push(self.signing_algo);
        buf.extend_from_slice(&(self.signing_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signing_pubkey);
        buf.push(self.kem_algo);
        buf.extend_from_slice(&(self.kem_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.kem_pubkey);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&(self.eph_kem_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.eph_kem_pubkey);
        buf.push(self.min_version);
        buf.push(self.max_version);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Minimum: 32 + 1 + 2 + 0 + 1 + 2 + 0 + 8 + 32 + 2 + 0 = 80
        if data.len() < 80 {
            return Err(Error::Wire("HandshakeHello too short".into()));
        }
        let mut r = Reader::new(data);
        let ephemeral_pubkey = r.read_array::<32>()?;
        let signing_algo = r.read_u8()?;
        let signing_pk_len = r.read_u16()? as usize;
        let signing_pubkey = r.read_bytes(signing_pk_len)?;
        let kem_algo = r.read_u8()?;
        let kem_pk_len = r.read_u16()? as usize;
        let kem_pubkey = r.read_bytes(kem_pk_len)?;
        let timestamp = r.read_u64()?;
        let challenge = r.read_array::<32>()?;
        let eph_kem_pk_len = r.read_u16()? as usize;
        let eph_kem_pubkey = r.read_bytes(eph_kem_pk_len)?;
        // Backward compat: old peers don't send version fields
        let (min_version, max_version) = if r.remaining() >= 2 {
            (r.read_u8()?, r.read_u8()?)
        } else {
            (2u8, 2u8)
        };
        Ok(Self {
            ephemeral_pubkey,
            signing_algo,
            signing_pubkey,
            kem_algo,
            kem_pubkey,
            timestamp,
            challenge,
            eph_kem_pubkey,
            min_version,
            max_version,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::HandshakeHello, self.to_bytes())
    }
}

/// HandshakeConfirm: BLAKE2b(shared_secret || "confirm") — 32 bytes
#[derive(Debug, Clone)]
pub struct HandshakeConfirmMsg {
    pub confirm_hash: [u8; 32],
}

impl HandshakeConfirmMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.confirm_hash.to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(Error::Wire("HandshakeConfirm too short".into()));
        }
        let mut r = Reader::new(data);
        let confirm_hash = r.read_array::<32>()?;
        Ok(Self { confirm_hash })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::HandshakeConfirm, self.to_bytes())
    }
}

/// RekeyMsg: kem_algo(u8) || kem_pk_len(u16 BE) || kem_pubkey || kem_ct_len(u16 BE) || kem_ciphertext || sig_len(u16 BE) || signature
///
/// The KEM type owns the entire key exchange. For X25519, the KEM pubkey *is*
/// the ephemeral X25519 public key. For hybrid (MlkemX25519), it contains
/// both the X25519 and ML-KEM public keys.
#[derive(Debug, Clone)]
pub struct RekeyMsg {
    /// KEM algorithm for this rekey exchange.
    pub kem_algo: u8,
    /// Ephemeral KEM public key (sent by initiator for responder to encapsulate to).
    pub kem_pubkey: Vec<u8>,
    /// KEM ciphertext (sent by responder, encapsulated to initiator's kem_pubkey).
    pub kem_ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

impl RekeyMsg {
    /// Bytes covered by the signature: kem_algo + KEM pubkey + KEM ciphertext.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.kem_pubkey.len() + self.kem_ciphertext.len());
        buf.push(self.kem_algo);
        buf.extend_from_slice(&self.kem_pubkey);
        buf.extend_from_slice(&self.kem_ciphertext);
        buf
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + 2
                + self.kem_pubkey.len()
                + 2
                + self.kem_ciphertext.len()
                + 2
                + self.signature.len(),
        );
        buf.push(self.kem_algo);
        buf.extend_from_slice(&(self.kem_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.kem_pubkey);
        buf.extend_from_slice(&(self.kem_ciphertext.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.kem_ciphertext);
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Minimum: 1 + 2 + 0 + 2 + 0 + 2 + 0 = 7
        if data.len() < 7 {
            return Err(Error::Wire("RekeyMsg too short".into()));
        }
        let mut r = Reader::new(data);
        let kem_algo = r.read_u8()?;
        let kem_pk_len = r.read_u16()? as usize;
        let kem_pubkey = r.read_bytes(kem_pk_len)?;
        let kem_ct_len = r.read_u16()? as usize;
        let kem_ciphertext = r.read_bytes(kem_ct_len)?;
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        Ok(Self {
            kem_algo,
            kem_pubkey,
            kem_ciphertext,
            signature,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::Rekey, self.to_bytes())
    }
}

/// Keepalive: optional timestamp (u64 BE, microseconds since link epoch) for RTT measurement.
/// Empty payload is valid (pure keepalive). With timestamp, the receiver echoes it back.
#[derive(Debug, Clone)]
pub struct KeepaliveMsg {
    /// If Some, this is a ping with a timestamp. The receiver should echo it back.
    /// If None, this is a pong (echo response) or a simple keepalive.
    pub timestamp_us: Option<u64>,
}

impl KeepaliveMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.timestamp_us {
            Some(ts) => ts.to_be_bytes().to_vec(),
            None => Vec::new(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() >= 8 {
            let mut r = Reader::new(data);
            let ts = r.read_u64()?;
            Ok(Self {
                timestamp_us: Some(ts),
            })
        } else {
            Ok(Self { timestamp_us: None })
        }
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::Keepalive, self.to_bytes())
    }
}

/// HandshakeAuth: sig_len(u16 BE) || signature || kem_ct_len(u16 BE) || kem_ciphertext || eph_kem_ct_len(u16 BE) || eph_kem_ciphertext
#[derive(Debug, Clone)]
pub struct HandshakeAuth {
    pub signature: Vec<u8>,
    /// KEM ciphertext from initiator→responder static KEM encapsulation.
    /// Empty for the responder's Auth message.
    pub kem_ciphertext: Vec<u8>,
    /// KEM ciphertext from initiator→responder ephemeral KEM encapsulation.
    /// Provides PQ forward secrecy. Empty for the responder's Auth message.
    pub eph_kem_ciphertext: Vec<u8>,
}

impl HandshakeAuth {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            2 + self.signature.len()
                + 2
                + self.kem_ciphertext.len()
                + 2
                + self.eph_kem_ciphertext.len(),
        );
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&(self.kem_ciphertext.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.kem_ciphertext);
        buf.extend_from_slice(&(self.eph_kem_ciphertext.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.eph_kem_ciphertext);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::Wire("HandshakeAuth too short".into()));
        }
        let mut r = Reader::new(data);
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        let kem_ciphertext = if r.remaining() >= 2 {
            let ct_len = r.read_u16()? as usize;
            if ct_len > 0 {
                r.read_bytes(ct_len)?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let eph_kem_ciphertext = if r.remaining() >= 2 {
            let ct_len = r.read_u16()? as usize;
            if ct_len > 0 {
                r.read_bytes(ct_len)?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        Ok(Self {
            signature,
            kem_ciphertext,
            eph_kem_ciphertext,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::HandshakeAuth, self.to_bytes())
    }
}

/// RouteAdvertisement: peer_id(32) || entry_count(u16) || entries || sig_len(u16 BE) || signature
/// Entry: dest_peer_id(32) || cost(u32)
#[derive(Debug, Clone)]
pub struct RouteAdvertisement {
    pub advertiser: PeerId,
    pub entries: Vec<RouteEntry>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: PeerId,
    pub cost: u32,
}

impl RouteAdvertisement {
    /// The signed portion (everything except the signature).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.advertiser.as_bytes());
        buf.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(entry.destination.as_bytes());
            buf.extend_from_slice(&entry.cost.to_be_bytes());
        }
        buf
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.signable_bytes();
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 36 {
            return Err(Error::Wire("RouteAdvertisement too short".into()));
        }
        let mut r = Reader::new(data);
        let advertiser = r.read_array::<32>()?;
        let entry_count = r.read_u16()? as usize;
        if r.remaining() < entry_count * 36 + 2 {
            return Err(Error::Wire("RouteAdvertisement truncated".into()));
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let dest = r.read_array::<32>()?;
            let cost = r.read_u32()?;
            entries.push(RouteEntry {
                destination: PeerId(dest),
                cost,
            });
        }
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        Ok(Self {
            advertiser: PeerId(advertiser),
            entries,
            signature,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::RouteAdvertisement, self.to_bytes())
    }
}

/// RouteProbe: lightweight non-circuit route discovery.
/// nonce(16) || target(32) || ttl(u16 BE) || hops(u16 BE)
#[derive(Debug, Clone)]
pub struct RouteProbeMsg {
    pub nonce: [u8; 16],
    pub target: PeerId,
    pub ttl: u16,
    pub hops: u16,
}

impl RouteProbeMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(52);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(self.target.as_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&self.hops.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 52 {
            return Err(Error::Wire("RouteProbe too short".into()));
        }
        let mut r = Reader::new(data);
        let nonce = r.read_array::<16>()?;
        let target = PeerId(r.read_array::<32>()?);
        let ttl = r.read_u16()?;
        let hops = r.read_u16()?;
        Ok(Self {
            nonce,
            target,
            ttl,
            hops,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::RouteProbe, self.to_bytes())
    }
}

/// RouteProbeFound: reply to a RouteProbe when the target is found.
/// nonce(16) || target(32) || cost(u16 BE)
#[derive(Debug, Clone)]
pub struct RouteProbeFoundMsg {
    pub nonce: [u8; 16],
    pub target: PeerId,
    pub cost: u16,
}

impl RouteProbeFoundMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(50);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(self.target.as_bytes());
        buf.extend_from_slice(&self.cost.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 50 {
            return Err(Error::Wire("RouteProbeFound too short".into()));
        }
        let mut r = Reader::new(data);
        let nonce = r.read_array::<16>()?;
        let target = PeerId(r.read_array::<32>()?);
        let cost = r.read_u16()?;
        Ok(Self {
            nonce,
            target,
            cost,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::RouteProbeFound, self.to_bytes())
    }
}

/// DhtPut: key(64) || record_type(u8) || sequence(u64 BE) || signer(32) || ttl(u32 BE) || value_len(u16 BE) || value || sig_len(u16 BE) || signature || signer_algo(u8) || signer_pk_len(u16 BE) || signer_pubkey || hop_count(u8) || hop_limit(u8) || bloom(256)
#[derive(Debug, Clone)]
pub struct DhtPutMsg {
    pub key: [u8; 64],
    pub record_type: RecordType,
    pub sequence: u64,
    pub signer: [u8; 32],
    pub ttl: u32,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
    /// Number of hops this message has already traversed (incremented by each forwarder).
    pub hop_count: u8,
    pub hop_limit: u8,
    pub bloom: [u8; 256],
}

impl DhtPutMsg {
    /// Default hop limit for DHT PUT messages.
    pub const DEFAULT_HOP_LIMIT: u8 = 10;

    /// The bytes covered by the signature: key || record_type || sequence || value
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + 1 + 8 + self.value.len());
        buf.extend_from_slice(&self.key);
        buf.push(self.record_type.as_u8());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.value);
        buf
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            64 + 1
                + 8
                + 32
                + 4
                + 2
                + self.value.len()
                + 2
                + self.signature.len()
                + 1
                + 2
                + self.signer_pubkey.len()
                + 2
                + 256,
        );
        buf.extend_from_slice(&self.key);
        buf.push(self.record_type.as_u8());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.signer);
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.value);
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf.push(self.signer_algo);
        buf.extend_from_slice(&(self.signer_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signer_pubkey);
        buf.push(self.hop_count);
        buf.push(self.hop_limit);
        buf.extend_from_slice(&self.bloom);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Minimum: 64 + 1 + 8 + 32 + 4 + 2 + 0 + 2 + 0 + 1 + 2 + 0 = 116
        if data.len() < 116 {
            return Err(Error::Wire("DhtPut too short".into()));
        }
        let mut r = Reader::new(data);
        let key = r.read_array::<64>()?;
        let record_type = RecordType::from_u8(r.read_u8()?);
        let sequence = r.read_u64()?;
        let signer = r.read_array::<32>()?;
        let ttl = r.read_u32()?;
        let value_len = r.read_u16()? as usize;
        let value = r.read_bytes(value_len)?;
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        let signer_algo = r.read_u8()?;
        let signer_pk_len = r.read_u16()? as usize;
        let signer_pubkey = r.read_bytes(signer_pk_len)?;

        // New format: hop_count(u8) || hop_limit(u8) || bloom(256) = 258 bytes
        // Old format: hop_limit(u8) || bloom(256) = 257 bytes
        let (hop_count, hop_limit, bloom) = if r.remaining() >= 258 {
            let hop_count = r.read_u8()?;
            let hop_limit = r.read_u8()?;
            let bloom = r.read_array::<256>()?;
            (hop_count, hop_limit, bloom)
        } else if r.remaining() > 0 {
            let hop_limit = r.read_u8()?;
            let mut bloom = [0u8; 256];
            if r.remaining() >= 256 {
                bloom = r.read_array::<256>()?;
            }
            (0, hop_limit, bloom)
        } else {
            (0, Self::DEFAULT_HOP_LIMIT, [0u8; 256])
        };

        Ok(Self {
            key,
            record_type,
            sequence,
            signer,
            ttl,
            value,
            signature,
            signer_algo,
            signer_pubkey,
            hop_count,
            hop_limit,
            bloom,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtPut, self.to_bytes())
    }
}

/// DhtGet: key(64) || query_token(32) || hop_count(u8) || hop_limit(u8) || bloom(256)
#[derive(Debug, Clone)]
pub struct DhtGetMsg {
    pub key: [u8; 64],
    /// Ephemeral token for anonymous reply routing. Each forwarder maps
    /// query_token → previous_hop so responses route back hop-by-hop
    /// without revealing the originator.
    pub query_token: [u8; 32],
    /// Number of hops this message has already traversed (incremented by each forwarder).
    pub hop_count: u8,
    pub hop_limit: u8,
    pub bloom: [u8; 256],
}

impl DhtGetMsg {
    /// Default hop limit for DHT GET messages.
    pub const DEFAULT_HOP_LIMIT: u8 = 10;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + 32 + 2 + 256);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&self.query_token);
        buf.push(self.hop_count);
        buf.push(self.hop_limit);
        buf.extend_from_slice(&self.bloom);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 96 {
            return Err(Error::Wire("DhtGet too short".into()));
        }
        let mut r = Reader::new(data);
        let key = r.read_array::<64>()?;
        let query_token = r.read_array::<32>()?;
        // New format: hop_count(u8) || hop_limit(u8) || bloom(256) = 258 remaining
        // Old format: hop_limit(u8) || bloom(256) = 257 remaining
        let (hop_count, hop_limit) = if r.remaining() >= 258 {
            (r.read_u8()?, r.read_u8()?)
        } else if r.remaining() > 0 {
            (0, r.read_u8()?)
        } else {
            (0, Self::DEFAULT_HOP_LIMIT)
        };
        let mut bloom = [0u8; 256];
        if r.remaining() >= 256 {
            bloom = r.read_array::<256>()?;
        }
        Ok(Self {
            key,
            query_token,
            hop_count,
            hop_limit,
            bloom,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtGet, self.to_bytes())
    }
}

/// A single record within a DhtGetResponse.
#[derive(Debug, Clone)]
pub struct DhtResponseRecord {
    pub record_type: RecordType,
    pub sequence: u64,
    pub signer: [u8; 32],
    pub ttl: u32,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
}

impl DhtResponseRecord {
    /// Encode: record_type(u8) || sequence(u64 BE) || signer(32) || ttl(u32 BE) || value_len(u16 BE) || value || sig_len(u16 BE) || signature || signer_algo(u8) || signer_pk_len(u16 BE) || signer_pubkey
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + 8
                + 32
                + 4
                + 2
                + self.value.len()
                + 2
                + self.signature.len()
                + 1
                + 2
                + self.signer_pubkey.len(),
        );
        buf.push(self.record_type.as_u8());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.signer);
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.value);
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf.push(self.signer_algo);
        buf.extend_from_slice(&(self.signer_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signer_pubkey);
        buf
    }

    /// Decode from bytes, returning (record, bytes_consumed).
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        // Minimum: 1 + 8 + 32 + 4 + 2 + 0 + 2 + 0 + 1 + 2 + 0 = 52
        if data.len() < 52 {
            return Err(Error::Wire("DhtResponseRecord too short".into()));
        }
        let mut r = Reader::new(data);
        let record_type = RecordType::from_u8(r.read_u8()?);
        let sequence = r.read_u64()?;
        let signer = r.read_array::<32>()?;
        let ttl = r.read_u32()?;
        let value_len = r.read_u16()? as usize;
        let value = r.read_bytes(value_len)?;
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        let signer_algo = r.read_u8()?;
        let signer_pk_len = r.read_u16()? as usize;
        let signer_pubkey = r.read_bytes(signer_pk_len)?;
        let consumed = r.pos;
        Ok((
            Self {
                record_type,
                sequence,
                signer,
                ttl,
                value,
                signature,
                signer_algo,
                signer_pubkey,
            },
            consumed,
        ))
    }
}

/// DhtGetResponse: query_token(32) || key(64) || record_count(u16) || records...
#[derive(Debug, Clone)]
pub struct DhtGetResponseMsg {
    /// The query_token from the originating DhtGet, used for hop-by-hop
    /// reply routing back to the requester.
    pub query_token: [u8; 32],
    pub key: [u8; 64],
    pub records: Vec<DhtResponseRecord>,
}

impl DhtGetResponseMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.query_token);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for record in &self.records {
            buf.extend_from_slice(&record.to_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 98 {
            return Err(Error::Wire("DhtGetResponse too short".into()));
        }
        let mut r = Reader::new(data);
        let query_token = r.read_array::<32>()?;
        let key = r.read_array::<64>()?;
        let record_count = r.read_u16()? as usize;
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let (record, consumed) = DhtResponseRecord::from_bytes(&data[r.pos..])?;
            records.push(record);
            r.pos += consumed;
        }
        Ok(Self {
            query_token,
            key,
            records,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtGetResponse, self.to_bytes())
    }
}

/// TunnelKeyExchange: kem_algo(1) || eph_pk_len(2 BE) || eph_pk(variable) || initiator_peer_id(32) || nonce(32) || timestamp(u64 BE)
/// Routed via DataMsg envelope (origin, destination, TTL).
#[derive(Debug, Clone)]
pub struct TunnelKeyExchangeMsg {
    pub kem_algo: u8,
    pub ephemeral_pubkey: Vec<u8>,
    pub initiator_peer_id: PeerId,
    pub nonce: [u8; 32],
    pub timestamp: u64,
}

impl TunnelKeyExchangeMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let pk_len = self.ephemeral_pubkey.len() as u16;
        let mut buf = Vec::with_capacity(3 + self.ephemeral_pubkey.len() + 72);
        buf.push(self.kem_algo);
        buf.extend_from_slice(&pk_len.to_be_bytes());
        buf.extend_from_slice(&self.ephemeral_pubkey);
        buf.extend_from_slice(self.initiator_peer_id.as_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(Error::Wire("TunnelKeyExchange too short".into()));
        }
        let mut r = Reader::new(data);
        let kem_algo = r.read_u8()?;
        let pk_len = r.read_u16()? as usize;
        if r.remaining() < pk_len + 72 {
            return Err(Error::Wire("TunnelKeyExchange truncated".into()));
        }
        let ephemeral_pubkey = r.read_bytes(pk_len)?.to_vec();
        let initiator = r.read_array::<32>()?;
        let nonce = r.read_array::<32>()?;
        let timestamp = r.read_u64()?;
        Ok(Self {
            kem_algo,
            ephemeral_pubkey,
            initiator_peer_id: PeerId(initiator),
            nonce,
            timestamp,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::TunnelKeyExchange, self.to_bytes())
    }
}

/// TunnelKeyResponse: kem_algo(1) || ct_len(2 BE) || ciphertext(variable) || responder_peer_id(32) || nonce(32) || initiator_nonce(32) || timestamp(u64 BE)
/// Echoes back the initiator's nonce to bind the exchange.
#[derive(Debug, Clone)]
pub struct TunnelKeyResponseMsg {
    pub kem_algo: u8,
    pub ciphertext: Vec<u8>,
    pub responder_peer_id: PeerId,
    pub nonce: [u8; 32],
    pub initiator_nonce: [u8; 32],
    pub timestamp: u64,
}

impl TunnelKeyResponseMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len = self.ciphertext.len() as u16;
        let mut buf = Vec::with_capacity(3 + self.ciphertext.len() + 104);
        buf.push(self.kem_algo);
        buf.extend_from_slice(&ct_len.to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(self.responder_peer_id.as_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.initiator_nonce);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(Error::Wire("TunnelKeyResponse too short".into()));
        }
        let mut r = Reader::new(data);
        let kem_algo = r.read_u8()?;
        let ct_len = r.read_u16()? as usize;
        if r.remaining() < ct_len + 104 {
            return Err(Error::Wire("TunnelKeyResponse truncated".into()));
        }
        let ciphertext = r.read_bytes(ct_len)?.to_vec();
        let responder = r.read_array::<32>()?;
        let nonce = r.read_array::<32>()?;
        let initiator_nonce = r.read_array::<32>()?;
        let timestamp = r.read_u64()?;
        Ok(Self {
            kem_algo,
            ciphertext,
            responder_peer_id: PeerId(responder),
            nonce,
            initiator_nonce,
            timestamp,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::TunnelKeyResponse, self.to_bytes())
    }
}

/// Data / EncryptedData: overlay-routed message.
/// origin(32) || destination(32) || ttl(u8) || data
/// Forwarded hop-by-hop via the routing table. TTL decremented at each hop.
/// Used for both plaintext Data and tunnel-encrypted EncryptedData messages
/// (they share the same wire layout; only the MessageType differs).
#[derive(Debug, Clone)]
pub struct DataMsg {
    pub origin: PeerId,
    pub destination: PeerId,
    pub ttl: u8,
    pub data: Vec<u8>,
}

/// Type alias preserving the old name for callers that used EncryptedDataMsg.
pub type EncryptedDataMsg = DataMsg;

impl DataMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(65 + self.data.len());
        buf.extend_from_slice(self.origin.as_bytes());
        buf.extend_from_slice(self.destination.as_bytes());
        buf.push(self.ttl);
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 65 {
            return Err(Error::Wire("Data too short".into()));
        }
        let mut r = Reader::new(data);
        let origin = r.read_array::<32>()?;
        let destination = r.read_array::<32>()?;
        let ttl = r.read_u8()?;
        let rest = r.read_rest();
        Ok(Self {
            origin: PeerId(origin),
            destination: PeerId(destination),
            ttl,
            data: rest,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::Data, self.to_bytes())
    }

    pub fn to_wire_encrypted(&self) -> WireMessage {
        WireMessage::new(MessageType::EncryptedData, self.to_bytes())
    }

    pub fn to_wire_with_type(&self, msg_type: MessageType) -> WireMessage {
        WireMessage::new(msg_type, self.to_bytes())
    }
}

/// ChannelOpen: channel_id(u32) || port(32) || flags(u8)
/// Flags: bit 0 = reliable, bit 1 = ordered
#[derive(Debug, Clone)]
pub struct ChannelOpenMsg {
    pub channel_id: u32,
    pub port: [u8; 32],
    pub reliable: bool,
    pub ordered: bool,
}

impl ChannelOpenMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(37);
        buf.extend_from_slice(&self.channel_id.to_be_bytes());
        buf.extend_from_slice(&self.port);
        let mut flags: u8 = 0;
        if self.reliable {
            flags |= 0x01;
        }
        if self.ordered {
            flags |= 0x02;
        }
        buf.push(flags);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 37 {
            return Err(Error::Wire("ChannelOpen too short".into()));
        }
        let mut r = Reader::new(data);
        let channel_id = r.read_u32()?;
        let port = r.read_array::<32>()?;
        let flags = r.read_u8()?;
        let reliable = flags & 0x01 != 0;
        let ordered = flags & 0x02 != 0;
        Ok(Self {
            channel_id,
            port,
            reliable,
            ordered,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::ChannelOpen, self.to_bytes())
    }
}

/// ChannelData: channel_id(u32) || seq(u32) || data
#[derive(Debug, Clone)]
pub struct ChannelDataMsg {
    pub channel_id: u32,
    pub sequence: u32,
    pub data: Vec<u8>,
}

impl ChannelDataMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.data.len());
        buf.extend_from_slice(&self.channel_id.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::Wire("ChannelData too short".into()));
        }
        let mut r = Reader::new(data);
        let channel_id = r.read_u32()?;
        let sequence = r.read_u32()?;
        let rest = r.read_rest();
        Ok(Self {
            channel_id,
            sequence,
            data: rest,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::ChannelData, self.to_bytes())
    }
}

/// ChannelAck: channel_id(u32) || ack_seq(u32) || selective_count(u16) || selective_seqs(u32 each)
#[derive(Debug, Clone)]
pub struct ChannelAckMsg {
    pub channel_id: u32,
    pub ack_seq: u32,
    pub selective_acks: Vec<u32>,
}

impl ChannelAckMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10 + self.selective_acks.len() * 4);
        buf.extend_from_slice(&self.channel_id.to_be_bytes());
        buf.extend_from_slice(&self.ack_seq.to_be_bytes());
        buf.extend_from_slice(&(self.selective_acks.len() as u16).to_be_bytes());
        for &seq in &self.selective_acks {
            buf.extend_from_slice(&seq.to_be_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 10 {
            return Err(Error::Wire("ChannelAck too short".into()));
        }
        let mut r = Reader::new(data);
        let channel_id = r.read_u32()?;
        let ack_seq = r.read_u32()?;
        let count = r.read_u16()? as usize;
        if r.remaining() < count * 4 {
            return Err(Error::Wire("ChannelAck truncated".into()));
        }
        let mut selective_acks = Vec::with_capacity(count);
        for _ in 0..count {
            selective_acks.push(r.read_u32()?);
        }
        Ok(Self {
            channel_id,
            ack_seq,
            selective_acks,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::ChannelAck, self.to_bytes())
    }
}

/// ChannelClose: channel_id(u32)
#[derive(Debug, Clone)]
pub struct ChannelCloseMsg {
    pub channel_id: u32,
}

impl ChannelCloseMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.channel_id.to_be_bytes().to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::Wire("ChannelClose too short".into()));
        }
        let mut r = Reader::new(data);
        let channel_id = r.read_u32()?;
        Ok(Self { channel_id })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::ChannelClose, self.to_bytes())
    }
}

/// Hello record: overlay presence announcement.
///
/// Published to the DHT at key = BLAKE2b(peer_pubkey) as a signed DhtPutMsg.
/// The signature lives at the DhtPutMsg level, not in the record itself.
///
/// Hello is about identity and reachability, not link-level addressing.
/// Only globally-routable addresses go here. Non-global addresses are
/// exchanged bilaterally over encrypted channels, never broadcast.
///
/// Point-to-point transports (RS232, USB) never produce addresses —
/// they produce links directly. Peers on such transports list introducers
/// so others can reach them through the overlay.
///
/// Wire format:
///   peer_id(32) || capabilities(u32 BE) || signaling_secret(16) ||
///   transport_count(u16) || transports(u16 BE...) ||
///   introducer_count(u16) || introducers(PeerId...) ||
///   addr_count(u16) || global_addresses(ScopedAddress...)
#[derive(Debug, Clone)]
pub struct HelloRecord {
    pub peer_id: PeerId,
    /// Bitflags describing node capabilities.
    pub capabilities: u32,
    /// Random secret used to derive the WebRTC signaling channel port name.
    /// Only peers who have received this hello can compute the port,
    /// preventing unsolicited signaling from nodes that haven't seen the hello.
    pub signaling_secret: [u8; 16],
    /// Transport types this peer speaks (e.g. Tcp4, Tcp6, Serial).
    /// Tells others what kinds of connections are possible, without
    /// revealing specific addresses.
    pub transports: Vec<TransportType>,
    /// Peers that can relay to us or help establish direct connections.
    /// Listed in the hello so anyone can discover how to reach a NAT'd
    /// or point-to-point-only node through the overlay.
    pub introducers: Vec<PeerId>,
    /// Only Global-scoped addresses. Published openly — these are public
    /// by definition. SiteLocal addresses are never put here.
    pub global_addresses: Vec<ScopedAddress>,
}

/// Capability bitflags for HelloRecord.
pub mod capabilities {
    /// This node is willing to relay traffic for others.
    pub const RELAY: u32 = 1 << 0;
    /// This node supports encrypted tunnels.
    pub const TUNNEL: u32 = 1 << 1;

    /// Format capability bitflags as a human-readable string.
    pub fn format(caps: u32) -> String {
        let mut names = Vec::new();
        if caps & RELAY != 0 {
            names.push("relay");
        }
        if caps & TUNNEL != 0 {
            names.push("tunnel");
        }
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(", ")
        }
    }
}

impl HelloRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.peer_id.as_bytes());
        buf.extend_from_slice(&self.capabilities.to_be_bytes());
        buf.extend_from_slice(&self.signaling_secret);
        buf.extend_from_slice(&(self.transports.len() as u16).to_be_bytes());
        for t in &self.transports {
            buf.extend_from_slice(&t.as_u16().to_be_bytes());
        }
        buf.extend_from_slice(&(self.introducers.len() as u16).to_be_bytes());
        for intro in &self.introducers {
            buf.extend_from_slice(intro.as_bytes());
        }
        buf.extend_from_slice(&(self.global_addresses.len() as u16).to_be_bytes());
        for addr in &self.global_addresses {
            buf.extend_from_slice(&addr.to_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Minimum: peer_id(32) + capabilities(4) + signaling_secret(16) +
        //          transport_count(2) + introducer_count(2) + addr_count(2) = 58
        if data.len() < 58 {
            return Err(Error::Wire("HelloRecord too short".into()));
        }
        let mut r = Reader::new(data);
        let peer_id = r.read_array::<32>()?;
        let capabilities = r.read_u32()?;
        let signaling_secret = r.read_array::<16>()?;
        let transport_count = r.read_u16()? as usize;

        let mut transports = Vec::with_capacity(transport_count);
        for _ in 0..transport_count {
            transports.push(TransportType::from_u16(r.read_u16()?));
        }

        let introducer_count = r.read_u16()? as usize;

        let mut introducers = Vec::with_capacity(introducer_count);
        for _ in 0..introducer_count {
            let id = r.read_array::<32>()?;
            introducers.push(PeerId(id));
        }

        let addr_count = r.read_u16()? as usize;

        let mut global_addresses = Vec::with_capacity(addr_count);
        for _ in 0..addr_count {
            let (addr, consumed) = ScopedAddress::from_bytes(&data[r.pos..])?;
            // Only keep known transports and Global scope
            if !matches!(addr.transport_type, TransportType::Unknown(_)) {
                global_addresses.push(addr);
            }
            r.pos += consumed;
        }

        Ok(Self {
            peer_id: PeerId(peer_id),
            capabilities,
            signaling_secret,
            transports,
            introducers,
            global_addresses,
        })
    }
}

/// DhtFindClosest: key(64)
#[derive(Debug, Clone)]
pub struct DhtFindClosestMsg {
    pub key: [u8; 64],
}

impl DhtFindClosestMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            return Err(Error::Wire("DhtFindClosest too short".into()));
        }
        let mut r = Reader::new(data);
        let key = r.read_array::<64>()?;
        Ok(Self { key })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtFindClosest, self.to_bytes())
    }
}

/// DhtFindClosestResponse: key(64) || peer_count(u16) || [peer_id(32) || dht_id(64)]...
#[derive(Debug, Clone)]
pub struct DhtFindClosestResponseMsg {
    pub key: [u8; 64],
    pub peers: Vec<(PeerId, crate::types::DhtId)>,
}

impl DhtFindClosestResponseMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(66 + self.peers.len() * 96);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&(self.peers.len() as u16).to_be_bytes());
        for (peer_id, dht_id) in &self.peers {
            buf.extend_from_slice(peer_id.as_bytes());
            buf.extend_from_slice(dht_id.as_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 66 {
            return Err(Error::Wire("DhtFindClosestResponse too short".into()));
        }
        let mut r = Reader::new(data);
        let key = r.read_array::<64>()?;
        let peer_count = r.read_u16()? as usize;
        let mut peers = Vec::with_capacity(peer_count);
        for _ in 0..peer_count {
            if r.remaining() < 96 {
                return Err(Error::Wire("DhtFindClosestResponse truncated".into()));
            }
            let pid = r.read_array::<32>()?;
            let did = r.read_array::<64>()?;
            peers.push((PeerId(pid), crate::types::DhtId(did)));
        }
        Ok(Self { key, peers })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtFindClosestResponse, self.to_bytes())
    }
}

/// DhtWatch: key(64) || query_token(32) || expiration(u32 BE seconds, 0 = cancel)
/// The query_token is used for anonymous notification routing — the storing
/// node never learns the watcher's identity, only a token to route through.
#[derive(Debug, Clone)]
pub struct DhtWatchMsg {
    pub key: [u8; 64],
    pub query_token: [u8; 32],
    pub expiration_secs: u32,
}

impl DhtWatchMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&self.query_token);
        buf.extend_from_slice(&self.expiration_secs.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 100 {
            return Err(Error::Wire("DhtWatch too short".into()));
        }
        let mut r = Reader::new(data);
        let key = r.read_array::<64>()?;
        let query_token = r.read_array::<32>()?;
        let expiration_secs = r.read_u32()?;
        Ok(Self {
            key,
            query_token,
            expiration_secs,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtWatch, self.to_bytes())
    }
}

/// DhtWatchNotify: query_token(32) || DhtPutMsg bytes
/// The query_token routes the notification back to the watcher hop-by-hop.
#[derive(Debug, Clone)]
pub struct DhtWatchNotifyMsg {
    pub query_token: [u8; 32],
    pub put: DhtPutMsg,
}

impl DhtWatchNotifyMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let put_bytes = self.put.to_bytes();
        let mut buf = Vec::with_capacity(32 + put_bytes.len());
        buf.extend_from_slice(&self.query_token);
        buf.extend_from_slice(&put_bytes);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(Error::Wire("DhtWatchNotify too short".into()));
        }
        let mut r = Reader::new(data);
        let query_token = r.read_array::<32>()?;
        let put = DhtPutMsg::from_bytes(&data[r.pos..])?;
        Ok(Self { query_token, put })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtWatchNotify, self.to_bytes())
    }
}

// ── Circuit messages (0x07xx) ──

/// CircuitRelay: circuit_id(u32 BE) || data
/// The ONLY thing a relay sees. No origin, no destination.
#[derive(Debug, Clone)]
pub struct CircuitRelayMsg {
    pub circuit_id: u32,
    pub data: Vec<u8>,
}

impl CircuitRelayMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.data.len());
        buf.extend_from_slice(&self.circuit_id.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::Wire("CircuitRelay too short".into()));
        }
        let mut r = Reader::new(data);
        let circuit_id = r.read_u32()?;
        let rest = r.read_rest();
        Ok(Self {
            circuit_id,
            data: rest,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::CircuitRelay, self.to_bytes())
    }
}

/// Encode a CircuitRelay wire message in one allocation.
///
/// Avoids the two intermediate `Vec`s that `CircuitRelayMsg::to_wire().encode()` produces
/// (one for the payload, one for the framed message). This is the hot path for relay nodes.
pub fn encode_circuit_relay_cell(circuit_id: u32, data: &[u8]) -> Vec<u8> {
    let payload_len = 4 + data.len();
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
    buf.push(WIRE_VERSION);
    buf.extend_from_slice(&MessageType::CircuitRelay.as_u16().to_be_bytes());
    buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
    buf.extend_from_slice(&circuit_id.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// CircuitCreate: circuit_id(u32 BE) || encrypted_payload
/// The circuit_id is what the sender will use; the relay assigns its own outbound ID.
/// The encrypted payload contains the next-hop instruction (encrypted to this relay's key).
#[derive(Debug, Clone)]
pub struct CircuitCreateMsg {
    pub circuit_id: u32,
    pub encrypted_payload: Vec<u8>,
}

impl CircuitCreateMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.encrypted_payload.len());
        buf.extend_from_slice(&self.circuit_id.to_be_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::Wire("CircuitCreate too short".into()));
        }
        let mut r = Reader::new(data);
        let circuit_id = r.read_u32()?;
        let encrypted_payload = r.read_rest();
        Ok(Self {
            circuit_id,
            encrypted_payload,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::CircuitCreate, self.to_bytes())
    }
}

/// CircuitCreated: circuit_id(u32 BE) || encrypted_reply
/// Sent back to confirm circuit creation.
#[derive(Debug, Clone)]
pub struct CircuitCreatedMsg {
    pub circuit_id: u32,
    pub encrypted_reply: Vec<u8>,
}

impl CircuitCreatedMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.encrypted_reply.len());
        buf.extend_from_slice(&self.circuit_id.to_be_bytes());
        buf.extend_from_slice(&self.encrypted_reply);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::Wire("CircuitCreated too short".into()));
        }
        let mut r = Reader::new(data);
        let circuit_id = r.read_u32()?;
        let encrypted_reply = r.read_rest();
        Ok(Self {
            circuit_id,
            encrypted_reply,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::CircuitCreated, self.to_bytes())
    }
}

/// CircuitDestroy: circuit_id(u32 BE)
/// Teardown a circuit. Propagates hop-by-hop.
#[derive(Debug, Clone)]
pub struct CircuitDestroyMsg {
    pub circuit_id: u32,
}

impl CircuitDestroyMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.circuit_id.to_be_bytes().to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::Wire("CircuitDestroy too short".into()));
        }
        let mut r = Reader::new(data);
        let circuit_id = r.read_u32()?;
        Ok(Self { circuit_id })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::CircuitDestroy, self.to_bytes())
    }
}

/// Hash a port name string to a 32-byte port identifier.
pub fn hash_port_name(name: &str) -> [u8; 32] {
    *blake3::hash(name.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_message_roundtrip() {
        let msg = WireMessage::new(MessageType::HandshakeHello, vec![1, 2, 3, 4]);
        let encoded = msg.encode();
        let decoded = WireMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, MessageType::HandshakeHello);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn handshake_hello_roundtrip() {
        let hello = HandshakeHello {
            ephemeral_pubkey: [42u8; 32],
            signing_algo: 1,
            signing_pubkey: vec![99u8; 32],
            kem_algo: 2,
            kem_pubkey: vec![88u8; 1184],
            timestamp: 1234567890,
            challenge: [0xAB; 32],
            eph_kem_pubkey: vec![77u8; 1216],
            min_version: 2,
            max_version: 3,
        };
        let bytes = hello.to_bytes();
        let decoded = HandshakeHello::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.ephemeral_pubkey, hello.ephemeral_pubkey);
        assert_eq!(decoded.signing_algo, 1);
        assert_eq!(decoded.signing_pubkey, vec![99u8; 32]);
        assert_eq!(decoded.kem_algo, 2);
        assert_eq!(decoded.kem_pubkey, vec![88u8; 1184]);
        assert_eq!(decoded.timestamp, 1234567890);
        assert_eq!(decoded.challenge, [0xAB; 32]);
        assert_eq!(decoded.eph_kem_pubkey, vec![77u8; 1216]);
        assert_eq!(decoded.min_version, 2);
        assert_eq!(decoded.max_version, 3);
    }

    #[test]
    fn handshake_hello_backward_compat() {
        // Simulate old-format hello without version fields
        let hello = HandshakeHello {
            ephemeral_pubkey: [42u8; 32],
            signing_algo: 1,
            signing_pubkey: vec![99u8; 32],
            kem_algo: 2,
            kem_pubkey: vec![88u8; 32],
            timestamp: 1234567890,
            challenge: [0xAB; 32],
            eph_kem_pubkey: vec![77u8; 32],
            min_version: 2,
            max_version: 2,
        };
        let mut bytes = hello.to_bytes();
        // Strip the trailing version bytes to simulate old format
        bytes.truncate(bytes.len() - 2);
        let decoded = HandshakeHello::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.min_version, 2);
        assert_eq!(decoded.max_version, 2);
    }

    #[test]
    fn channel_ack_roundtrip() {
        let ack = ChannelAckMsg {
            channel_id: 5,
            ack_seq: 100,
            selective_acks: vec![102, 105],
        };
        let bytes = ack.to_bytes();
        let decoded = ChannelAckMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.channel_id, 5);
        assert_eq!(decoded.ack_seq, 100);
        assert_eq!(decoded.selective_acks, vec![102, 105]);
    }

    #[test]
    fn port_hash_deterministic() {
        let h1 = hash_port_name("echo");
        let h2 = hash_port_name("echo");
        assert_eq!(h1, h2);
        let h3 = hash_port_name("other");
        assert_ne!(h1, h3);
    }

    #[test]
    fn dht_put_msg_roundtrip() {
        let put = DhtPutMsg {
            key: [0xAA; 64],
            record_type: RecordType::Hello,
            sequence: 42,
            signer: [0xBB; 32],
            ttl: 600,
            value: b"hello world".to_vec(),
            signature: vec![0xCC; 64],
            signer_algo: 1,
            signer_pubkey: vec![0xEE; 32],
            hop_count: 3,
            hop_limit: 7,
            bloom: [0xDD; 256],
        };
        let bytes = put.to_bytes();
        let decoded = DhtPutMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key, put.key);
        assert_eq!(decoded.record_type, RecordType::Hello);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.signer, put.signer);
        assert_eq!(decoded.ttl, 600);
        assert_eq!(decoded.value, b"hello world");
        assert_eq!(decoded.signature, put.signature);
        assert_eq!(decoded.signer_algo, 1);
        assert_eq!(decoded.signer_pubkey, vec![0xEE; 32]);
        assert_eq!(decoded.hop_count, 3);
        assert_eq!(decoded.hop_limit, 7);
        assert_eq!(decoded.bloom, [0xDD; 256]);
    }

    #[test]
    fn dht_put_msg_signable_bytes() {
        let put = DhtPutMsg {
            key: [1; 64],
            record_type: RecordType::SignedContent,
            sequence: 7,
            signer: [2; 32],
            ttl: 100,
            value: b"data".to_vec(),
            signature: vec![0; 64],
            signer_algo: 0,
            signer_pubkey: vec![],
            hop_count: 0,
            hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
            bloom: [0; 256],
        };
        let signable = put.signable_bytes();
        // signable = key(64) || record_type(1) || sequence(8) || value(4) = 77 bytes
        assert_eq!(signable.len(), 64 + 1 + 8 + 4);
        assert_eq!(&signable[..64], &[1u8; 64]);
        assert_eq!(signable[64], RecordType::SignedContent.as_u8());
        assert_eq!(&signable[73..], b"data");
    }

    #[test]
    fn dht_get_response_empty_roundtrip() {
        let resp = DhtGetResponseMsg {
            query_token: [0xFF; 32],
            key: [0x11; 64],
            records: vec![],
        };
        let bytes = resp.to_bytes();
        let decoded = DhtGetResponseMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key, resp.key);
        assert_eq!(decoded.query_token, [0xFF; 32]);
        assert!(decoded.records.is_empty());
    }

    #[test]
    fn dht_get_response_multi_record_roundtrip() {
        let resp = DhtGetResponseMsg {
            query_token: [0xEE; 32],
            key: [0x22; 64],
            records: vec![
                DhtResponseRecord {
                    record_type: RecordType::SignedContent,
                    sequence: 0,
                    signer: [0xAA; 32],
                    ttl: 3600,
                    value: b"first".to_vec(),
                    signature: vec![0x11; 64],
                    signer_algo: 1,
                    signer_pubkey: vec![0xAA; 32],
                },
                DhtResponseRecord {
                    record_type: RecordType::SignedContent,
                    sequence: 0,
                    signer: [0xBB; 32],
                    ttl: 1800,
                    value: b"second record".to_vec(),
                    signature: vec![0x22; 64],
                    signer_algo: 1,
                    signer_pubkey: vec![0xBB; 32],
                },
            ],
        };
        let bytes = resp.to_bytes();
        let decoded = DhtGetResponseMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key, resp.key);
        assert_eq!(decoded.query_token, [0xEE; 32]);
        assert_eq!(decoded.records.len(), 2);
        assert_eq!(decoded.records[0].signer, [0xAA; 32]);
        assert_eq!(decoded.records[0].value, b"first");
        assert_eq!(decoded.records[1].signer, [0xBB; 32]);
        assert_eq!(decoded.records[1].value, b"second record");
        assert_eq!(decoded.records[1].ttl, 1800);
    }

    #[test]
    fn hello_record_roundtrip() {
        use crate::types::{AddressScope, ScopedAddress, TransportType};
        let hello = HelloRecord {
            peer_id: PeerId([0x55; 32]),
            capabilities: capabilities::RELAY | capabilities::TUNNEL,
            signaling_secret: [0xCC; 16],
            transports: vec![TransportType::Tcp4, TransportType::Tcp6],
            introducers: vec![PeerId([0xAA; 32])],
            global_addresses: vec![
                ScopedAddress {
                    scope: AddressScope::Global,
                    transport_type: TransportType::Tcp4,
                    address: vec![203, 0, 113, 5, 0x1F, 0x0A], // 203.0.113.5:7946
                },
                ScopedAddress {
                    scope: AddressScope::Global,
                    transport_type: TransportType::Tcp6,
                    address: vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1F,
                        0x0A, // port 7946
                    ],
                },
            ],
        };
        let bytes = hello.to_bytes();
        let decoded = HelloRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.peer_id, hello.peer_id);
        assert_eq!(
            decoded.capabilities,
            capabilities::RELAY | capabilities::TUNNEL
        );
        assert_eq!(decoded.signaling_secret, [0xCC; 16]);
        assert_eq!(decoded.transports.len(), 2);
        assert_eq!(decoded.transports[0], TransportType::Tcp4);
        assert_eq!(decoded.transports[1], TransportType::Tcp6);
        assert_eq!(decoded.introducers.len(), 1);
        assert_eq!(decoded.introducers[0], PeerId([0xAA; 32]));
        assert_eq!(decoded.global_addresses.len(), 2);
        assert_eq!(decoded.global_addresses[0].scope, AddressScope::Global);
        assert_eq!(
            decoded.global_addresses[0].transport_type,
            TransportType::Tcp4
        );
        assert_eq!(
            decoded.global_addresses[0].to_connect_string().unwrap(),
            "203.0.113.5:7946"
        );
        assert_eq!(
            decoded.global_addresses[1].transport_type,
            TransportType::Tcp6
        );
    }

    #[test]
    fn hello_record_no_addresses_with_introducer() {
        // RS232-only node: no addresses, just an introducer
        let hello = HelloRecord {
            peer_id: PeerId([0x33; 32]),
            capabilities: 0,
            signaling_secret: [0xDD; 16],
            transports: vec![],
            introducers: vec![PeerId([0xBB; 32])],
            global_addresses: vec![],
        };
        let bytes = hello.to_bytes();
        let decoded = HelloRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.peer_id, hello.peer_id);
        assert_eq!(decoded.capabilities, 0);
        assert!(decoded.transports.is_empty());
        assert_eq!(decoded.introducers.len(), 1);
        assert_eq!(decoded.introducers[0], PeerId([0xBB; 32]));
        assert!(decoded.global_addresses.is_empty());
    }

    #[test]
    fn hello_record_empty() {
        let hello = HelloRecord {
            peer_id: PeerId([0x33; 32]),
            capabilities: 0,
            signaling_secret: [0; 16],
            transports: vec![],
            introducers: vec![],
            global_addresses: vec![],
        };
        let bytes = hello.to_bytes();
        let decoded = HelloRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.peer_id, hello.peer_id);
        assert!(decoded.global_addresses.is_empty());
    }

    #[test]
    fn dht_put_unknown_record_type_roundtrip() {
        let put = DhtPutMsg {
            key: [0xAA; 64],
            record_type: RecordType::Unknown(42),
            sequence: 1,
            signer: [0xBB; 32],
            ttl: 600,
            value: b"unknown data".to_vec(),
            signature: vec![0xCC; 64],
            signer_algo: 0,
            signer_pubkey: vec![],
            hop_count: 0,
            hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
            bloom: [0; 256],
        };
        let bytes = put.to_bytes();
        let decoded = DhtPutMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.record_type, RecordType::Unknown(42));
        assert_eq!(decoded.value, b"unknown data");
        assert_eq!(decoded.sequence, 1);
    }

    #[test]
    fn hello_record_skips_unknown_transport() {
        use crate::types::{AddressScope, ScopedAddress, TransportType};

        // Build a HelloRecord with Global Tcp4 + an unknown transport manually
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x55u8; 32]); // peer_id
        buf.extend_from_slice(&0u32.to_be_bytes()); // capabilities
        buf.extend_from_slice(&[0u8; 16]); // signaling_secret
        buf.extend_from_slice(&0u16.to_be_bytes()); // transport_count = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // introducer_count = 0
        buf.extend_from_slice(&2u16.to_be_bytes()); // addr_count = 2

        // First address: Global Tcp4 203.0.113.5:7946
        let tcp4 = ScopedAddress {
            scope: AddressScope::Global,
            transport_type: TransportType::Tcp4,
            address: vec![203, 0, 113, 5, 0x1F, 0x0A],
        };
        buf.extend_from_slice(&tcp4.to_bytes());

        // Second address: Global Unknown(0x99) with some opaque bytes
        let unknown = ScopedAddress {
            scope: AddressScope::Global,
            transport_type: TransportType::Unknown(0x0099),
            address: vec![1, 2, 3, 4, 5],
        };
        buf.extend_from_slice(&unknown.to_bytes());

        let decoded = HelloRecord::from_bytes(&buf).unwrap();
        assert_eq!(decoded.global_addresses.len(), 1); // only Tcp4 kept
        assert_eq!(
            decoded.global_addresses[0].transport_type,
            TransportType::Tcp4
        );
    }

    #[test]
    fn dht_watch_msg_roundtrip() {
        let watch = DhtWatchMsg {
            key: [0xAA; 64],
            query_token: [0x11; 32],
            expiration_secs: 300,
        };
        let bytes = watch.to_bytes();
        let decoded = DhtWatchMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key, [0xAA; 64]);
        assert_eq!(decoded.query_token, [0x11; 32]);
        assert_eq!(decoded.expiration_secs, 300);
    }

    #[test]
    fn dht_watch_msg_cancel() {
        let watch = DhtWatchMsg {
            key: [0xBB; 64],
            query_token: [0x22; 32],
            expiration_secs: 0,
        };
        let bytes = watch.to_bytes();
        let decoded = DhtWatchMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key, [0xBB; 64]);
        assert_eq!(decoded.query_token, [0x22; 32]);
        assert_eq!(decoded.expiration_secs, 0);
    }

    #[test]
    fn dht_watch_notify_msg_roundtrip() {
        let notify = DhtWatchNotifyMsg {
            query_token: [0xFF; 32],
            put: DhtPutMsg {
                key: [0xCC; 64],
                record_type: RecordType::Hello,
                sequence: 5,
                signer: [0xDD; 32],
                ttl: 600,
                value: b"notify data".to_vec(),
                signature: vec![0xEE; 64],
                signer_algo: 1,
                signer_pubkey: vec![0xDD; 32],
                hop_count: 0,
                hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
                bloom: [0; 256],
            },
        };
        let bytes = notify.to_bytes();
        let decoded = DhtWatchNotifyMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.query_token, [0xFF; 32]);
        assert_eq!(decoded.put.key, [0xCC; 64]);
        assert_eq!(decoded.put.record_type, RecordType::Hello);
        assert_eq!(decoded.put.sequence, 5);
        assert_eq!(decoded.put.value, b"notify data");
    }

    #[test]
    fn tunnel_key_exchange_roundtrip() {
        let ke = TunnelKeyExchangeMsg {
            kem_algo: 0x02,
            ephemeral_pubkey: vec![0x11; 1216],
            initiator_peer_id: PeerId([0x22; 32]),
            nonce: [0x33; 32],
            timestamp: 1234567890,
        };
        let bytes = ke.to_bytes();
        let decoded = TunnelKeyExchangeMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.kem_algo, 0x02);
        assert_eq!(decoded.ephemeral_pubkey, vec![0x11; 1216]);
        assert_eq!(decoded.initiator_peer_id, PeerId([0x22; 32]));
        assert_eq!(decoded.nonce, [0x33; 32]);
        assert_eq!(decoded.timestamp, 1234567890);
    }

    #[test]
    fn tunnel_key_response_roundtrip() {
        let kr = TunnelKeyResponseMsg {
            kem_algo: 0x02,
            ciphertext: vec![0xAA; 1120],
            responder_peer_id: PeerId([0xBB; 32]),
            nonce: [0xCC; 32],
            initiator_nonce: [0xDD; 32],
            timestamp: 9876543210,
        };
        let bytes = kr.to_bytes();
        let decoded = TunnelKeyResponseMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.kem_algo, 0x02);
        assert_eq!(decoded.ciphertext, vec![0xAA; 1120]);
        assert_eq!(decoded.responder_peer_id, PeerId([0xBB; 32]));
        assert_eq!(decoded.nonce, [0xCC; 32]);
        assert_eq!(decoded.initiator_nonce, [0xDD; 32]);
        assert_eq!(decoded.timestamp, 9876543210);
    }

    #[test]
    fn encrypted_data_msg_roundtrip() {
        let msg = EncryptedDataMsg {
            origin: PeerId([0x11; 32]),
            destination: PeerId([0x22; 32]),
            ttl: 42,
            data: b"encrypted payload".to_vec(),
        };
        let bytes = msg.to_bytes();
        let decoded = EncryptedDataMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.origin, PeerId([0x11; 32]));
        assert_eq!(decoded.destination, PeerId([0x22; 32]));
        assert_eq!(decoded.ttl, 42);
        assert_eq!(decoded.data, b"encrypted payload");
    }

    #[test]
    fn channel_open_flags_roundtrip() {
        // reliable + ordered (flags = 0x03)
        let open = ChannelOpenMsg {
            channel_id: 7,
            port: [0xAA; 32],
            reliable: true,
            ordered: true,
        };
        let bytes = open.to_bytes();
        let decoded = ChannelOpenMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.channel_id, 7);
        assert!(decoded.reliable);
        assert!(decoded.ordered);

        // reliable only (flags = 0x01) — wire-compatible with old reliable=true
        let open2 = ChannelOpenMsg {
            channel_id: 8,
            port: [0xBB; 32],
            reliable: true,
            ordered: false,
        };
        let bytes2 = open2.to_bytes();
        assert_eq!(bytes2[36], 0x01);
        let decoded2 = ChannelOpenMsg::from_bytes(&bytes2).unwrap();
        assert!(decoded2.reliable);
        assert!(!decoded2.ordered);

        // neither (flags = 0x00)
        let open3 = ChannelOpenMsg {
            channel_id: 9,
            port: [0xCC; 32],
            reliable: false,
            ordered: false,
        };
        let bytes3 = open3.to_bytes();
        assert_eq!(bytes3[36], 0x00);
        let decoded3 = ChannelOpenMsg::from_bytes(&bytes3).unwrap();
        assert!(!decoded3.reliable);
        assert!(!decoded3.ordered);
    }
}
