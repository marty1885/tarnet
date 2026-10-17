use crate::types::{Error, PeerId, RecordType, Result, ScopedAddress, TransportType};

/// Minimum wire protocol version this node supports. Version 9 introduces
/// stream receive credit and unsequenced stream window probes.
pub const WIRE_VERSION_MIN: u8 = 9;
/// Maximum (current) wire protocol version this node supports.
pub const WIRE_VERSION_MAX: u8 = 9;
/// Current wire version used in outgoing messages.
pub const WIRE_VERSION: u8 = WIRE_VERSION_MAX;
pub const HEADER_SIZE: usize = 5;
pub const MAX_PAYLOAD: usize = 65535;

use crate::codec::Reader;

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
        RouteUpdate = 0x0110,
        RouteDigest = 0x0111,
        RouteRequest = 0x0112,
        DirPublish = 0x0130,
        DirLookup = 0x0131,
        DirResult = 0x0132,
        PathTrace = 0x0133,
        PathTraceResult = 0x0134,
        RouteSearch = 0x0140,
        RouteSearchFound = 0x0141,
        SampleWalk = 0x0150,
        SampleResult = 0x0151,
        // DHT (0x02xx)
        DhtPut = 0x0200,
        DhtGet = 0x0201,
        DhtGetResponse = 0x0202,
        DhtWatch = 0x0203,
        DhtWatchNotify = 0x0204,
        DhtNeighbor = 0x0205,
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

    /// The type of an encoded message, from its header alone.
    pub fn peek_type(data: &[u8]) -> Option<MessageType> {
        let raw = data.get(1..3)?;
        MessageType::from_u16(u16::from_be_bytes([raw[0], raw[1]]))
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
        if data.len() != HEADER_SIZE + len {
            return Err(Error::Wire(format!(
                "payload length {} does not match its header ({})",
                data.len() - HEADER_SIZE,
                len
            )));
        }
        let msg_type = MessageType::from_u16(msg_type_raw)
            .ok_or_else(|| Error::Wire(format!("unknown message type: 0x{:04x}", msg_type_raw)))?;
        let payload = data[HEADER_SIZE..HEADER_SIZE + len].to_vec();
        Ok(Self { msg_type, payload })
    }
}

// ── Specific message payload structs ──

/// HandshakeHello: ephemeral(32) || signing_algo(u8) || signing_pk_len(u16 BE) || signing_pk || kem_algo(u8) || kem_pk_len(u16 BE) || kem_pk || challenge(32) || eph_kem_pk_len(u16 BE) || eph_kem_pk || min_version(u8) || max_version(u8)
#[derive(Debug, Clone)]
pub struct HandshakeHello {
    pub ephemeral_pubkey: [u8; 32],
    pub signing_algo: u8,
    pub signing_pubkey: Vec<u8>,
    pub kem_algo: u8,
    pub kem_pubkey: Vec<u8>,
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
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&(self.eph_kem_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.eph_kem_pubkey);
        buf.push(self.min_version);
        buf.push(self.max_version);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Minimum: 32 + 1 + 2 + 0 + 1 + 2 + 0 + 32 + 2 + 0 = 72
        let mut r = Reader::new(data);
        let ephemeral_pubkey = r.read_array::<32>()?;
        let signing_algo = r.read_u8()?;
        let signing_pk_len = r.read_u16()? as usize;
        let signing_pubkey = r.read_bytes(signing_pk_len)?;
        let kem_algo = r.read_u8()?;
        let kem_pk_len = r.read_u16()? as usize;
        let kem_pubkey = r.read_bytes(kem_pk_len)?;
        let challenge = r.read_array::<32>()?;
        let eph_kem_pk_len = r.read_u16()? as usize;
        let eph_kem_pubkey = r.read_bytes(eph_kem_pk_len)?;
        let (min_version, max_version) = (r.read_u8()?, r.read_u8()?);
        r.finish()?;
        Ok(Self {
            ephemeral_pubkey,
            signing_algo,
            signing_pubkey,
            kem_algo,
            kem_pubkey,
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
        let mut r = Reader::new(data);
        let confirm_hash = r.read_array::<32>()?;
        r.finish()?;
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
    /// Bytes covered by the signature: a domain label, then kem_algo and the
    /// KEM pubkey and ciphertext, each length-prefixed (a request's key and
    /// a response's ciphertext with the same bytes sign differently).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = b"tarnet link rekey v1".to_vec();
        buf.push(self.kem_algo);
        for field in [&self.kem_pubkey, &self.kem_ciphertext] {
            buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buf.extend_from_slice(field);
        }
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
        let mut r = Reader::new(data);
        let kem_algo = r.read_u8()?;
        let kem_pk_len = r.read_u16()? as usize;
        let kem_pubkey = r.read_bytes(kem_pk_len)?;
        let kem_ct_len = r.read_u16()? as usize;
        let kem_ciphertext = r.read_bytes(kem_ct_len)?;
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        r.finish()?;
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

/// Heartbeat / keepalive. Doubles as cover traffic: the wire format always
/// carries random padding so size-based traffic analysis can't trivially tell
/// heartbeats from real protocol messages.
///
/// Format: flags(u8) || [ping_id(u64 BE) if flags & 1]
///         || [probe_nonce(16 bytes) if flags & 2] || padding(rest)
///   - flags bit 0: 1 = ping (carries a random ping id), 0 = pong
///   - flags bit 1: a 128-bit challenge follows the optional legacy ping id
///     on requests, and is echoed on replies. Older peers ignore this extension.
///   - padding: random bytes, ignored on receive
#[derive(Debug, Clone)]
pub struct KeepaliveMsg {
    /// If Some, this is a ping: an opaque random id (never a clock reading,
    /// which would fingerprint the sender). The receiver answers with a pong.
    /// If None, this is a pong.
    pub ping_id: Option<u64>,
    /// Random challenge, never a timestamp. Replies echo it on the same link.
    pub probe_nonce: Option<[u8; 16]>,
    /// Random padding bytes. Set by sender; receiver discards.
    pub padding: Vec<u8>,
}

impl KeepaliveMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 16 + self.padding.len());
        let flags: u8 =
            u8::from(self.ping_id.is_some()) | (u8::from(self.probe_nonce.is_some()) << 1);
        out.push(flags);
        if let Some(ts) = self.ping_id {
            out.extend_from_slice(&ts.to_be_bytes());
        }
        if let Some(nonce) = self.probe_nonce {
            out.extend_from_slice(&nonce);
        }
        out.extend_from_slice(&self.padding);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self {
                ping_id: None,
                probe_nonce: None,
                padding: Vec::new(),
            });
        }
        let mut r = Reader::new(data);
        let flags = r.read_u8()?;
        let ping_id = if flags & 1 != 0 {
            Some(r.read_u64()?)
        } else {
            None
        };
        let probe_nonce = if flags & 2 != 0 {
            Some(r.read_bytes(16)?.try_into().unwrap())
        } else {
            None
        };
        Ok(Self {
            ping_id,
            probe_nonce,
            padding: Vec::new(),
        })
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
        let mut r = Reader::new(data);
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        // Both ciphertexts are always encoded (possibly empty).
        let ct_len = r.read_u16()? as usize;
        let kem_ciphertext = r.read_bytes(ct_len)?;
        let ct_len = r.read_u16()? as usize;
        let eph_kem_ciphertext = r.read_bytes(ct_len)?;
        r.finish()?;
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

/// Metric value that retracts a route.
pub const ROUTE_INFINITY: u16 = 0xFFFF;
/// `RouteUpdate` flag: these entries are part of a full dump.
pub const ROUTE_FULL: u8 = 0x01;
/// `RouteUpdate` flag: first message of a full dump.
pub const ROUTE_FULL_START: u8 = 0x02;
/// `RouteUpdate` flag: last message of a full dump.
pub const ROUTE_FULL_END: u8 = 0x04;
/// Route entry flag: the destination is a landmark.
pub const ROUTE_LANDMARK: u8 = 0x01;
/// `RouteRequest` flag: send a full dump.
pub const ROUTE_REQ_FULL_DUMP: u8 = 0x01;
/// `RouteRequest` flag: ask for a newer seqno for one destination.
pub const ROUTE_REQ_SEQNO: u8 = 0x02;
/// Wire size of one route entry.
pub const ROUTE_ENTRY_SIZE: usize = 32 + 2 + 2 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEntry {
    pub dest: PeerId,
    pub seqno: u16,
    pub metric: u16,
    pub eflags: u8,
}

impl RouteEntry {
    pub fn write(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.dest.as_bytes());
        buf.extend_from_slice(&self.seqno.to_be_bytes());
        buf.extend_from_slice(&self.metric.to_be_bytes());
        buf.push(self.eflags);
    }
}

/// RouteUpdate: flags(u8) || degree(u8) || dump_id(u16) || count(u16) || count × entry.
/// Entry: dest(32) || seqno(u16) || metric(u16) || eflags(u8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteUpdateMsg {
    pub flags: u8,
    pub degree: u8,
    pub dump_id: u16,
    pub entries: Vec<RouteEntry>,
}

impl RouteUpdateMsg {
    /// Entries that fit one wire message.
    pub const MAX_ENTRIES: usize = (MAX_PAYLOAD - 6) / ROUTE_ENTRY_SIZE;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6 + self.entries.len() * ROUTE_ENTRY_SIZE);
        buf.push(self.flags);
        buf.push(self.degree);
        buf.extend_from_slice(&self.dump_id.to_be_bytes());
        buf.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for e in &self.entries {
            e.write(&mut buf);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let flags = r.read_u8()?;
        let degree = r.read_u8()?;
        let dump_id = r.read_u16()?;
        let count = r.read_u16()? as usize;
        if r.remaining() < count * ROUTE_ENTRY_SIZE {
            return Err(Error::Wire("RouteUpdate truncated".into()));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(RouteEntry {
                dest: PeerId(r.read_array::<32>()?),
                seqno: r.read_u16()?,
                metric: r.read_u16()?,
                eflags: r.read_u8()?,
            });
        }
        r.finish()?;
        Ok(Self {
            flags,
            degree,
            dump_id,
            entries,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::RouteUpdate, self.to_bytes())
    }
}

/// RouteDigest: digest(16) || count(u16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDigestMsg {
    pub digest: [u8; 16],
    pub count: u16,
}

impl RouteDigestMsg {
    /// Synchronize topology metadata along with the route set. The wire
    /// envelope is unchanged; degree is part of the digest input.
    pub fn of_with_degree<'a>(entries: impl Iterator<Item = &'a RouteEntry>, degree: u8) -> Self {
        let mut result = Self::of(entries);
        let mut input = result.digest.to_vec();
        input.push(degree);
        let key = blake3::derive_key("tarnet route digest degree v1", &input);
        result.digest.copy_from_slice(&key[..16]);
        result
    }

    /// Digest of a route set: entries sorted by destination, encoded as in
    /// `RouteUpdate`.
    fn of<'a>(entries: impl Iterator<Item = &'a RouteEntry>) -> Self {
        let mut buf = Vec::new();
        let mut count = 0usize;
        for e in entries {
            e.write(&mut buf);
            count += 1;
        }
        let key = blake3::derive_key("tarnet route digest v1", &buf);
        Self {
            digest: key[..16].try_into().unwrap(),
            count: count.min(u16::MAX as usize) as u16,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.digest.to_vec();
        buf.extend_from_slice(&self.count.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let msg = Self {
            digest: r.read_array::<16>()?,
            count: r.read_u16()?,
        };
        r.finish()?;
        Ok(msg)
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::RouteDigest, self.to_bytes())
    }
}

/// RouteRequest: flags(u8) || [dest(32) || seqno(u16) || hop_count(u8)] iff SEQNO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequestMsg {
    pub full_dump: bool,
    /// `(dest, seqno, hop_count)`
    pub seqno: Option<(PeerId, u16, u8)>,
}

impl RouteRequestMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut flags = 0;
        if self.full_dump {
            flags |= ROUTE_REQ_FULL_DUMP;
        }
        if self.seqno.is_some() {
            flags |= ROUTE_REQ_SEQNO;
        }
        let mut buf = vec![flags];
        if let Some((dest, seqno, hops)) = self.seqno {
            buf.extend_from_slice(dest.as_bytes());
            buf.extend_from_slice(&seqno.to_be_bytes());
            buf.push(hops);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let flags = r.read_u8()?;
        let seqno = if flags & ROUTE_REQ_SEQNO != 0 {
            Some((PeerId(r.read_array::<32>()?), r.read_u16()?, r.read_u8()?))
        } else {
            None
        };
        r.finish()?;
        Ok(Self {
            full_dump: flags & ROUTE_REQ_FULL_DUMP != 0,
            seqno,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::RouteRequest, self.to_bytes())
    }
}

/// Most path entries a `SampleResult` carries (`PATH_MAX`).
pub const SAMPLE_PATH_MAX: usize = 8;

/// SampleWalk: token(32) || steps(u8). A Metropolis–Hastings walk for a
/// uniformly random relay. The token is replaced at every hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleWalkMsg {
    pub token: [u8; 32],
    pub steps: u8,
}

impl SampleWalkMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.token.to_vec();
        buf.push(self.steps);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let msg = Self {
            token: r.read_array::<32>()?,
            steps: r.read_u8()?,
        };
        r.finish()?;
        Ok(msg)
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::SampleWalk, self.to_bytes())
    }
}

/// One sampled relay: who, the walk's last stretch before it (nearest it
/// first), and its address record if it publishes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub peer: PeerId,
    pub path: Vec<PeerId>,
    pub address: Option<AddressRecord>,
}

/// SampleResult: token(32) || status(u8) ||
/// [peer(32) || count(u8) || count × path(32) || addr_len(u16) ||
/// address_record(addr_len)] iff status 0.
/// `path` holds the walk's last nodes before `peer`, nearest it first: hints
/// that reach `peer` without saying where the walk began. `addr_len` 0 means
/// the sample has no address record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleResultMsg {
    pub token: [u8; 32],
    /// `None` for no sample.
    pub sample: Option<Sample>,
}

impl SampleResultMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.token.to_vec();
        match &self.sample {
            None => buf.push(1),
            Some(s) => {
                buf.push(0);
                buf.extend_from_slice(s.peer.as_bytes());
                write_peers(&mut buf, &s.path, SAMPLE_PATH_MAX);
                let addr = s.address.as_ref().map(|a| a.to_bytes()).unwrap_or_default();
                buf.extend_from_slice(&(addr.len() as u16).to_be_bytes());
                buf.extend_from_slice(&addr);
            }
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let token = r.read_array::<32>()?;
        let sample = match r.read_u8()? {
            0 => {
                let peer = PeerId(r.read_array::<32>()?);
                let path = r.read_peers(SAMPLE_PATH_MAX, "SampleResult path")?;
                let addr_len = r.read_u16()? as usize;
                let address = if addr_len == 0 {
                    None
                } else {
                    Some(AddressRecord::from_bytes(&r.read_bytes(addr_len)?)?)
                };
                Some(Sample { peer, path, address })
            }
            1 => None,
            s => return Err(Error::Wire(format!("SampleResult status {}", s))),
        };
        r.finish()?;
        Ok(Self { token, sample })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::SampleResult, self.to_bytes())
    }
}

// ── Addresses and the directory ──

/// Most entries (nearest landmarks) in an address record.
pub const ADDRESS_ENTRIES_MAX: usize = 3;
/// Most nodes in an address path (`PATH_MAX`).
pub const PATH_MAX: usize = 8;
/// Most nodes a `PathTrace` may list: its origin, `PATH_MAX` relays and the
/// target.
pub const PATH_TRACE_MAX: usize = PATH_MAX + 2;

use crate::codec::write_peers;

/// One way to reach a node: a landmark, and the nodes after it up to, but
/// excluding, the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressEntry {
    pub landmark: PeerId,
    pub path: Vec<PeerId>,
}

/// A node's signed address:
/// `peer(32) || seq(u32) || ttl_secs(u32) || count(u8) ||
/// count × (landmark(32) || path_len(u8) || path(32 × path_len)) ||
/// signer_algo(u8) || pk_len(u16) || signer_pubkey || sig_len(u16) || signature`,
/// signed over `"tarnet address v2"` and the body except its mutable TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRecord {
    pub peer: PeerId,
    pub seq: u32,
    pub ttl_secs: u32,
    pub entries: Vec<AddressEntry>,
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AddressRecord {
    fn body(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(41 + self.entries.len() * (33 + 32 * PATH_MAX));
        buf.extend_from_slice(self.peer.as_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.ttl_secs.to_be_bytes());
        buf.push(self.entries.len() as u8);
        for e in &self.entries {
            buf.extend_from_slice(e.landmark.as_bytes());
            write_peers(&mut buf, &e.path, PATH_MAX);
        }
        buf
    }

    /// A record for `keypair`'s node, signed.
    pub fn sign(
        keypair: &crate::identity::Keypair,
        seq: u32,
        ttl_secs: u32,
        entries: Vec<AddressEntry>,
    ) -> Self {
        let mut rec = Self {
            peer: keypair.peer_id(),
            seq,
            ttl_secs,
            entries,
            signer_algo: keypair.identity.signing_algo() as u8,
            signer_pubkey: keypair.identity.signing.signing_pubkey_bytes(),
            signature: Vec::new(),
        };
        rec.signature = keypair.sign(&rec.signed_bytes());
        rec
    }

    /// The bytes the signature covers.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let body = self.body();
        let mut msg = b"tarnet address v2".to_vec();
        msg.extend_from_slice(&body[..36]); // peer and sequence
        msg.extend_from_slice(&body[40..]); // entries; remaining TTL is mutable
        msg
    }

    /// Whether two copies carry the same authenticated record. A relay may
    /// reduce the unsigned remaining TTL without changing the version.
    pub fn same_version(&self, other: &Self) -> bool {
        self.signed_bytes() == other.signed_bytes()
            && self.signer_algo == other.signer_algo
            && self.signer_pubkey == other.signer_pubkey
    }

    /// The signer key hashes to `peer` and signs the record.
    pub fn verify(&self) -> bool {
        let Ok(algo) = tarnet_api::types::SigningAlgo::from_u8(self.signer_algo) else {
            return false;
        };
        crate::identity::verify_with_pubkey(
            algo,
            &self.signer_pubkey,
            &self.peer,
            &self.signed_bytes(),
            &self.signature,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.body();
        buf.push(self.signer_algo);
        buf.extend_from_slice(&(self.signer_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signer_pubkey);
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let peer = PeerId(r.read_array::<32>()?);
        let seq = r.read_u32()?;
        let ttl_secs = r.read_u32()?;
        let count = r.read_u8()? as usize;
        if count > ADDRESS_ENTRIES_MAX {
            return Err(Error::Wire(format!("address record has {} entries", count)));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let landmark = PeerId(r.read_array::<32>()?);
            let path = r.read_peers(PATH_MAX, "address path")?;
            entries.push(AddressEntry { landmark, path });
        }
        let signer_algo = r.read_u8()?;
        let pk_len = r.read_u16()? as usize;
        let signer_pubkey = r.read_bytes(pk_len)?;
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        Ok(Self {
            peer,
            seq,
            ttl_secs,
            entries,
            signer_algo,
            signer_pubkey,
            signature,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let rec = Self::read(&mut r)?;
        if r.remaining() != 0 {
            return Err(Error::Wire("trailing bytes after address record".into()));
        }
        r.finish()?;
        Ok(rec)
    }
}

/// Most hops a route search may flood, and so the longest hop list an
/// answer carries (the answering node plus the relays back to the searcher).
pub const ROUTE_SEARCH_MAX_TTL: u8 = 16;
pub const ROUTE_SEARCH_PATH_MAX: usize = ROUTE_SEARCH_MAX_TTL as usize + 1;

/// RouteSearch: nonce(16) || target(32) || ttl(u8). A deduplicated flood for
/// a node the directory can't place. No originator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSearchMsg {
    pub nonce: [u8; 16],
    pub target: PeerId,
    pub ttl: u8,
}

impl RouteSearchMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.nonce.to_vec();
        buf.extend_from_slice(self.target.as_bytes());
        buf.push(self.ttl);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let msg = Self {
            nonce: r.read_array::<16>()?,
            target: PeerId(r.read_array::<32>()?),
            ttl: r.read_u8()?,
        };
        r.finish()?;
        Ok(msg)
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::RouteSearch, self.to_bytes())
    }
}

/// RouteSearchFound: nonce(16) || target(32) || count(u8) || count × peer(32).
/// `hops` starts with the node that answered (it has a route to `target`, or
/// is it); each node on the way back appends itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSearchFoundMsg {
    pub nonce: [u8; 16],
    pub target: PeerId,
    pub hops: Vec<PeerId>,
}

impl RouteSearchFoundMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.nonce.to_vec();
        buf.extend_from_slice(self.target.as_bytes());
        write_peers(&mut buf, &self.hops, ROUTE_SEARCH_PATH_MAX);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let nonce = r.read_array::<16>()?;
        let target = PeerId(r.read_array::<32>()?);
        let hops = r.read_peers(ROUTE_SEARCH_PATH_MAX, "RouteSearchFound")?;
        r.finish()?;
        Ok(Self { nonce, target, hops })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::RouteSearchFound, self.to_bytes())
    }
}

/// DirPublish: landmark(32) || replica(u8) || address_record. Routed toward
/// the landmark, which stores the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirPublishMsg {
    pub landmark: PeerId,
    pub replica: u8,
    pub record: AddressRecord,
}

impl DirPublishMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.landmark.as_bytes().to_vec();
        buf.push(self.replica);
        buf.extend_from_slice(&self.record.to_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let landmark = PeerId(r.read_array::<32>()?);
        let replica = r.read_u8()?;
        let record = AddressRecord::from_bytes(&r.read_rest())?;
        r.finish()?;
        Ok(Self {
            landmark,
            replica,
            record,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DirPublish, self.to_bytes())
    }
}

/// `DirLookup` flag: still in the random-walk phase.
pub const DIR_LOOKUP_WALKING: u8 = 0x01;

/// DirLookup: flags(u8) || lookup_token(32) || target(32) || replica(u8) ||
/// landmark(32). No originator; `landmark` is all zero while walking and set
/// by the node that ends the walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirLookupMsg {
    pub walking: bool,
    pub token: [u8; 32],
    pub target: PeerId,
    pub replica: u8,
    pub landmark: PeerId,
}

impl DirLookupMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(98);
        buf.push(if self.walking { DIR_LOOKUP_WALKING } else { 0 });
        buf.extend_from_slice(&self.token);
        buf.extend_from_slice(self.target.as_bytes());
        buf.push(self.replica);
        buf.extend_from_slice(self.landmark.as_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let flags = r.read_u8()?;
        let msg = Self {
            walking: flags & DIR_LOOKUP_WALKING != 0,
            token: r.read_array::<32>()?,
            target: PeerId(r.read_array::<32>()?),
            replica: r.read_u8()?,
            landmark: PeerId(r.read_array::<32>()?),
        };
        r.finish()?;
        Ok(msg)
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DirLookup, self.to_bytes())
    }
}

/// DirResult: lookup_token(32) || status(u8) || [address_record] iff found
/// (status 0; 1 is not found). Returns along the lookup's reverse path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirResultMsg {
    pub token: [u8; 32],
    pub record: Option<AddressRecord>,
}

impl DirResultMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.token.to_vec();
        match &self.record {
            Some(rec) => {
                buf.push(0);
                buf.extend_from_slice(&rec.to_bytes());
            }
            None => buf.push(1),
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let token = r.read_array::<32>()?;
        let record = match r.read_u8()? {
            0 => Some(AddressRecord::from_bytes(&r.read_rest())?),
            1 => None,
            s => return Err(Error::Wire(format!("DirResult status {}", s))),
        };
        r.finish()?;
        Ok(Self { token, record })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DirResult, self.to_bytes())
    }
}

/// PathTrace: token(32) || target(32) || count(u8) || count × peer(32).
/// Routed toward `target`; every node appends itself, starting with the
/// origin. The target answers `PathTraceResult` with the whole list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTraceMsg {
    pub token: [u8; 32],
    pub target: PeerId,
    pub path: Vec<PeerId>,
}

impl PathTraceMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.token.to_vec();
        buf.extend_from_slice(self.target.as_bytes());
        write_peers(&mut buf, &self.path, PATH_TRACE_MAX);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let token = r.read_array::<32>()?;
        let target = PeerId(r.read_array::<32>()?);
        let path = r.read_peers(PATH_TRACE_MAX, "PathTrace")?;
        r.finish()?;
        Ok(Self {
            token,
            target,
            path,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::PathTrace, self.to_bytes())
    }
}

/// PathTraceResult: token(32) || count(u8) || count × peer(32). Returns
/// along the listed path: each node passes it to the entry before its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTraceResultMsg {
    pub token: [u8; 32],
    pub path: Vec<PeerId>,
}

impl PathTraceResultMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.token.to_vec();
        write_peers(&mut buf, &self.path, PATH_TRACE_MAX);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let token = r.read_array::<32>()?;
        let path = r.read_peers(PATH_TRACE_MAX, "PathTraceResult")?;
        r.finish()?;
        Ok(Self { token, path })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::PathTraceResult, self.to_bytes())
    }
}

/// Current DHT protocol version, the first byte of every walk header and of
/// `DhtNeighbor`. Messages with any other version are dropped.
pub const DHT_VERSION: u8 = 1;

/// Walk-header flag bits. Unknown bits are sent as zero and ignored.
pub mod walk_flags {
    /// Random-walk phase: forward to a random neighbour until a coin flip ends it.
    pub const WALKING: u8 = 0x01;
    /// Detour around a relay-only local minimum: the first storing node to
    /// receive the message is the end of the walk.
    pub const DELIVER: u8 = 0x02;
}

/// Routing state carried by every DHT PUT, GET and WATCH walk.
///
/// Deliberately has no hop counter, originator-chosen hop limit or replication
/// count: nothing here distinguishes the originator of a walking message from
/// a node forwarding someone else's walk. See `docs/spec/dht.md`.
///
/// Wire: version(u8) || flags(u8) || greedy_budget(u8) || bloom_salt(u32 BE) || bloom(256)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkHeader {
    pub flags: u8,
    /// Greedy steps left. Set by the node that ends the random phase; unused
    /// while `WALKING` is set.
    pub greedy_budget: u8,
    /// Salt for the bloom hash, chosen by the first node that inserts into it.
    pub bloom_salt: u32,
    /// Relay-only nodes visited on a `DELIVER` detour. Nobody else is inserted.
    pub bloom: [u8; 256],
}

impl WalkHeader {
    pub const LEN: usize = 1 + 1 + 1 + 4 + 256;

    /// The header an originator sends: walking, empty bloom.
    pub fn origin() -> Self {
        Self {
            flags: walk_flags::WALKING,
            greedy_budget: 0,
            bloom_salt: 0,
            bloom: [0u8; 256],
        }
    }

    pub fn walking(&self) -> bool {
        self.flags & walk_flags::WALKING != 0
    }

    pub fn deliver(&self) -> bool {
        self.flags & walk_flags::DELIVER != 0
    }

    fn write(&self, buf: &mut Vec<u8>) {
        buf.push(DHT_VERSION);
        buf.push(self.flags & (walk_flags::WALKING | walk_flags::DELIVER));
        buf.push(self.greedy_budget);
        buf.extend_from_slice(&self.bloom_salt.to_be_bytes());
        buf.extend_from_slice(&self.bloom);
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let version = r.read_u8()?;
        if version != DHT_VERSION {
            return Err(Error::Wire(format!("unsupported DHT version {}", version)));
        }
        let flags = r.read_u8()? & (walk_flags::WALKING | walk_flags::DELIVER);
        let greedy_budget = r.read_u8()?;
        let bloom_salt = r.read_u32()?;
        let bloom = r.read_array::<256>()?;
        Ok(Self {
            flags,
            greedy_budget,
            bloom_salt,
            bloom,
        })
    }
}

impl Default for WalkHeader {
    fn default() -> Self {
        Self::origin()
    }
}

/// DhtPut: walk_header || record
///
/// record: key(64) || record_type(u8) || sequence(u64) || signer(32) || ttl(u32)
///   || value_len(u16) || value || sig_len(u16) || signature || signer_algo(u8)
///   || pk_len(u16) || signer_pubkey
#[derive(Debug, Clone)]
pub struct DhtPutMsg {
    pub walk: WalkHeader,
    pub key: [u8; 64],
    pub record_type: RecordType,
    pub sequence: u64,
    pub signer: PeerId,
    /// Remaining lifetime in seconds; unsigned, clamped per type by every node.
    pub ttl: u32,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
}

impl DhtPutMsg {
    /// The bytes covered by the signature: key || record_type || sequence || value
    pub fn signable_bytes(&self) -> Vec<u8> {
        // Single source of truth, shared with the verify gate.
        crate::dht::record_signable(&self.key, self.record_type, self.sequence, &self.value)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.walk.write(&mut buf);
        self.write_record(&mut buf);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let walk = WalkHeader::read(&mut r)?;
        let put = Self::read_record(&mut r, walk)?;
        r.finish()?;
        Ok(put)
    }

    /// Encode only the signed record (no walk header), as carried by
    /// `DhtWatchNotify`.
    pub fn record_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_record(&mut buf);
        buf
    }

    /// Decode a bare record (no walk header); the walk header is set to
    /// [`WalkHeader::origin`].
    pub fn from_record_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let put = Self::read_record(&mut r, WalkHeader::origin())?;
        r.finish()?;
        Ok(put)
    }

    fn write_record(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.key);
        write_record_body(
            buf,
            self.record_type,
            self.sequence,
            self.signer.as_bytes(),
            self.ttl,
            &self.value,
            &self.signature,
            self.signer_algo,
            &self.signer_pubkey,
        );
    }

    fn read_record(r: &mut Reader, walk: WalkHeader) -> Result<Self> {
        let key = r.read_array::<64>()?;
        let body = DhtResponseRecord::read(r)?;
        Ok(Self {
            walk,
            key,
            record_type: body.record_type,
            sequence: body.sequence,
            signer: body.signer,
            ttl: body.ttl,
            value: body.value,
            signature: body.signature,
            signer_algo: body.signer_algo,
            signer_pubkey: body.signer_pubkey,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtPut, self.to_bytes())
    }
}

/// DhtGet: walk_header || key(64) || query_token(32)
#[derive(Debug, Clone)]
pub struct DhtGetMsg {
    pub walk: WalkHeader,
    pub key: [u8; 64],
    /// Ephemeral per-walk token for anonymous reply routing. Each forwarder maps
    /// query_token → previous_hop so responses route back hop-by-hop
    /// without revealing the originator.
    pub query_token: [u8; 32],
}

impl DhtGetMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(WalkHeader::LEN + 64 + 32);
        self.walk.write(&mut buf);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&self.query_token);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let walk = WalkHeader::read(&mut r)?;
        let key = r.read_array::<64>()?;
        let query_token = r.read_array::<32>()?;
        r.finish()?;
        Ok(Self {
            walk,
            key,
            query_token,
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
    pub signer: PeerId,
    /// Remaining lifetime in seconds; unsigned, clamped per type by every node.
    pub ttl: u32,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
}

impl DhtResponseRecord {
    /// Encode: record_type(u8) || sequence(u64 BE) || signer(32) || ttl(u32 BE) || value_len(u16 BE) || value || sig_len(u16 BE) || signature || signer_algo(u8) || signer_pk_len(u16 BE) || signer_pubkey
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_record_body(
            &mut buf,
            self.record_type,
            self.sequence,
            self.signer.as_bytes(),
            self.ttl,
            &self.value,
            &self.signature,
            self.signer_algo,
            &self.signer_pubkey,
        );
        buf
    }

    /// Read one record body (a GET response's record, or a PUT's after
    /// its key).
    fn read(r: &mut Reader) -> Result<Self> {
        let record_type = RecordType::from_u8(r.read_u8()?);
        let sequence = r.read_u64()?;
        let signer = PeerId(r.read_array::<32>()?);
        let ttl = r.read_u32()?;
        let value_len = r.read_u16()? as usize;
        let value = r.read_bytes(value_len)?;
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?;
        let signer_algo = r.read_u8()?;
        let signer_pk_len = r.read_u16()? as usize;
        let signer_pubkey = r.read_bytes(signer_pk_len)?;
        Ok(Self {
            record_type,
            sequence,
            signer,
            ttl,
            value,
            signature,
            signer_algo,
            signer_pubkey,
        })
    }
}

/// The one encoding of a DHT record's body, for PUTs (after the key) and GET
/// responses alike. Read back by [`DhtResponseRecord::read`].
#[allow(clippy::too_many_arguments)]
fn write_record_body(
    buf: &mut Vec<u8>,
    record_type: RecordType,
    sequence: u64,
    signer: &[u8; 32],
    ttl: u32,
    value: &[u8],
    signature: &[u8],
    signer_algo: u8,
    signer_pubkey: &[u8],
) {
    buf.push(record_type.as_u8());
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(signer);
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    buf.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    buf.extend_from_slice(signature);
    buf.push(signer_algo);
    buf.extend_from_slice(&(signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(signer_pubkey);
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
    /// The record count a response claims, read from its header alone (0 if
    /// the header is short), for charging before it is parsed.
    pub fn record_count(payload: &[u8]) -> u16 {
        // query_token(32) || key(64) || count(u16)
        payload
            .get(96..98)
            .map_or(0, |c| u16::from_be_bytes([c[0], c[1]]))
    }

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
        let mut r = Reader::new(data);
        let query_token = r.read_array::<32>()?;
        let key = r.read_array::<64>()?;
        let record_count = r.read_u16()? as usize;
        // Bound the pre-allocation by what the payload can actually hold (52 is
        // the minimum encoded record), not by the attacker-supplied count.
        let mut records = Vec::with_capacity(record_count.min(r.remaining() / 52));
        for _ in 0..record_count {
            records.push(DhtResponseRecord::read(&mut r)?);
        }
        r.finish()?;
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

/// TunnelKeyExchange: kem_algo(1) || eph_pk_len(2 BE) || eph_pk(variable) || initiator_peer_id(32) || nonce(32)
///   || signer_algo(1) || signer_pk_len(2 BE) || signer_pubkey(variable) || sig_len(2 BE) || signature(variable)
/// Routed via DataMsg envelope (origin, destination, TTL).
///
/// The signature binds the ephemeral KEM offer to the initiator's static
/// identity and to the intended responder (`destination`), so an on-path relay
/// cannot substitute its own ephemeral key to mount a man-in-the-middle attack.
/// See [`tunnel_kex_signed_bytes`].
#[derive(Debug, Clone)]
pub struct TunnelKeyExchangeMsg {
    pub kem_algo: u8,
    pub ephemeral_pubkey: Vec<u8>,
    pub initiator_peer_id: PeerId,
    pub nonce: [u8; 32],
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl TunnelKeyExchangeMsg {
    /// Bytes the initiator signs (and the responder verifies). Binds the
    /// ephemeral KEM pubkey to the initiator identity and the intended
    /// responder so a relay cannot redirect or MITM the exchange.
    pub fn signed_bytes(&self, destination: &PeerId) -> Vec<u8> {
        tunnel_kex_signed_bytes(
            destination,
            self.kem_algo,
            &self.ephemeral_pubkey,
            &self.initiator_peer_id,
            &self.nonce,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let pk_len = self.ephemeral_pubkey.len() as u16;
        let mut buf = Vec::new();
        buf.push(self.kem_algo);
        buf.extend_from_slice(&pk_len.to_be_bytes());
        buf.extend_from_slice(&self.ephemeral_pubkey);
        buf.extend_from_slice(self.initiator_peer_id.as_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.push(self.signer_algo);
        buf.extend_from_slice(&(self.signer_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signer_pubkey);
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let kem_algo = r.read_u8()?;
        let pk_len = r.read_u16()? as usize;
        let ephemeral_pubkey = r.read_bytes(pk_len)?.to_vec();
        let initiator = r.read_array::<32>()?;
        let nonce = r.read_array::<32>()?;
        let signer_algo = r.read_u8()?;
        let signer_pk_len = r.read_u16()? as usize;
        let signer_pubkey = r.read_bytes(signer_pk_len)?.to_vec();
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?.to_vec();
        r.finish()?;
        Ok(Self {
            kem_algo,
            ephemeral_pubkey,
            initiator_peer_id: PeerId(initiator),
            nonce,
            signer_algo,
            signer_pubkey,
            signature,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::TunnelKeyExchange, self.to_bytes())
    }
}

/// Canonical bytes signed by the initiator of a tunnel key exchange.
///
/// Length-prefixes the variable-length ephemeral pubkey so no two distinct
/// field sets can produce the same transcript. The `destination` binds the
/// offer to one responder; the responder verifies with its own PeerId.
pub fn tunnel_kex_signed_bytes(
    destination: &PeerId,
    kem_algo: u8,
    ephemeral_pubkey: &[u8],
    initiator_peer_id: &PeerId,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + 32 + 1 + 2 + ephemeral_pubkey.len() + 32 + 32);
    buf.extend_from_slice(b"tarnet tunnel kex v1");
    buf.extend_from_slice(destination.as_bytes());
    buf.push(kem_algo);
    buf.extend_from_slice(&(ephemeral_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(ephemeral_pubkey);
    buf.extend_from_slice(initiator_peer_id.as_bytes());
    buf.extend_from_slice(nonce);
    buf
}

/// TunnelKeyResponse: kem_algo(1) || ct_len(2 BE) || ciphertext(variable) || responder_peer_id(32) || nonce(32) || initiator_nonce(32)
///   || signer_algo(1) || signer_pk_len(2 BE) || signer_pubkey(variable) || sig_len(2 BE) || signature(variable)
/// Echoes back the initiator's nonce to bind the exchange.
///
/// The signature binds the KEM ciphertext to the responder's static identity
/// and to the initiator's *original* ephemeral pubkey. The initiator verifies
/// using the ephemeral key it actually sent, so a relay that substituted a
/// different ephemeral key is detected. See [`tunnel_kex_resp_signed_bytes`].
#[derive(Debug, Clone)]
pub struct TunnelKeyResponseMsg {
    pub kem_algo: u8,
    pub ciphertext: Vec<u8>,
    pub responder_peer_id: PeerId,
    pub nonce: [u8; 32],
    pub initiator_nonce: [u8; 32],
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl TunnelKeyResponseMsg {
    /// Bytes the responder signs (and the initiator verifies). `ephemeral_pubkey`
    /// is the initiator's offered KEM key — the responder supplies what it
    /// received, the initiator supplies what it sent; a mismatch (relay
    /// substitution) makes verification fail.
    pub fn signed_bytes(&self, initiator_peer_id: &PeerId, ephemeral_pubkey: &[u8]) -> Vec<u8> {
        tunnel_kex_resp_signed_bytes(
            initiator_peer_id,
            &self.responder_peer_id,
            self.kem_algo,
            ephemeral_pubkey,
            &self.ciphertext,
            &self.initiator_nonce,
            &self.nonce,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len = self.ciphertext.len() as u16;
        let mut buf = Vec::new();
        buf.push(self.kem_algo);
        buf.extend_from_slice(&ct_len.to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(self.responder_peer_id.as_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.initiator_nonce);
        buf.push(self.signer_algo);
        buf.extend_from_slice(&(self.signer_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signer_pubkey);
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let kem_algo = r.read_u8()?;
        let ct_len = r.read_u16()? as usize;
        let ciphertext = r.read_bytes(ct_len)?.to_vec();
        let responder = r.read_array::<32>()?;
        let nonce = r.read_array::<32>()?;
        let initiator_nonce = r.read_array::<32>()?;
        let signer_algo = r.read_u8()?;
        let signer_pk_len = r.read_u16()? as usize;
        let signer_pubkey = r.read_bytes(signer_pk_len)?.to_vec();
        let sig_len = r.read_u16()? as usize;
        let signature = r.read_bytes(sig_len)?.to_vec();
        r.finish()?;
        Ok(Self {
            kem_algo,
            ciphertext,
            responder_peer_id: PeerId(responder),
            nonce,
            initiator_nonce,
            signer_algo,
            signer_pubkey,
            signature,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::TunnelKeyResponse, self.to_bytes())
    }
}

/// Canonical bytes signed by the responder of a tunnel key exchange.
///
/// Length-prefixes the variable-length ephemeral pubkey and ciphertext so no
/// two distinct field sets collide. Binds the ciphertext to both identities and
/// to the initiator's original ephemeral key.
#[allow(clippy::too_many_arguments)]
pub fn tunnel_kex_resp_signed_bytes(
    initiator_peer_id: &PeerId,
    responder_peer_id: &PeerId,
    kem_algo: u8,
    ephemeral_pubkey: &[u8],
    ciphertext: &[u8],
    initiator_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        25 + 32 + 32 + 1 + 2 + ephemeral_pubkey.len() + 2 + ciphertext.len() + 32 + 32,
    );
    buf.extend_from_slice(b"tarnet tunnel kex-resp v1");
    buf.extend_from_slice(initiator_peer_id.as_bytes());
    buf.extend_from_slice(responder_peer_id.as_bytes());
    buf.push(kem_algo);
    buf.extend_from_slice(&(ephemeral_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(ephemeral_pubkey);
    buf.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    buf.extend_from_slice(ciphertext);
    buf.extend_from_slice(initiator_nonce);
    buf.extend_from_slice(responder_nonce);
    buf
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
    /// Forwarding hints toward the destination (its landmark and path),
    /// for relays with no route to it; carried unchanged when forwarding.
    pub hints: Vec<PeerId>,
    pub data: Vec<u8>,
}

/// Most forwarding hints a Data message or EXTEND may carry: a landmark plus
/// a path of up to `PATH_MAX` (8) peers.
pub const MAX_HINTS: usize = 9;

/// Most selective acks a channel or stream ACK carries.
pub const MAX_SELECTIVE_ACKS: usize = 32;

/// Hops an overlay-routed `Data` / `EncryptedData` may take: what every
/// sender starts with, and what a receiver clamps a larger TTL to.
pub const DATA_TTL: u8 = 64;

/// Type alias preserving the old name for callers that used EncryptedDataMsg.
pub type EncryptedDataMsg = DataMsg;

impl DataMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(66 + 32 * self.hints.len() + self.data.len());
        buf.extend_from_slice(self.origin.as_bytes());
        buf.extend_from_slice(self.destination.as_bytes());
        buf.push(self.ttl);
        write_peers(&mut buf, &self.hints, MAX_HINTS);
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let origin = r.read_array::<32>()?;
        let destination = r.read_array::<32>()?;
        let ttl = r.read_u8()?;
        let hints = r.read_peers(MAX_HINTS, "Data hints")?;
        let rest = r.read_rest();
        r.finish()?;
        Ok(Self {
            origin: PeerId(origin),
            destination: PeerId(destination),
            ttl,
            hints,
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
        let mut r = Reader::new(data);
        let channel_id = r.read_u32()?;
        let port = r.read_array::<32>()?;
        let flags = r.read_u8()?;
        let reliable = flags & 0x01 != 0;
        let ordered = flags & 0x02 != 0;
        r.finish()?;
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
        let mut r = Reader::new(data);
        let channel_id = r.read_u32()?;
        let sequence = r.read_u32()?;
        let rest = r.read_rest();
        r.finish()?;
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
        let mut r = Reader::new(data);
        let channel_id = r.read_u32()?;
        let ack_seq = r.read_u32()?;
        let count = r.read_u16()? as usize;
        if count > MAX_SELECTIVE_ACKS {
            return Err(Error::Wire(format!("ChannelAck with {} selective acks", count)));
        }
        if r.remaining() < count * 4 {
            return Err(Error::Wire("ChannelAck truncated".into()));
        }
        let mut selective_acks = Vec::with_capacity(count);
        for _ in 0..count {
            selective_acks.push(r.read_u32()?);
        }
        r.finish()?;
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

/// StreamAck (wire v9): receive_limit(u32) || ack_seq(u32) ||
/// selective_count(u16) || selective_seqs(u32 each). `receive_limit` is an
/// exclusive, wrapping sequence boundary for new DATA, independent of ACKs.
#[derive(Debug, Clone)]
pub struct StreamAckMsg {
    pub receive_limit: u32,
    pub ack_seq: u32,
    pub selective_acks: Vec<u32>,
}

impl StreamAckMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        ChannelAckMsg {
            channel_id: self.receive_limit,
            ack_seq: self.ack_seq,
            selective_acks: self.selective_acks.clone(),
        }
        .to_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let ack = ChannelAckMsg::from_bytes(data)?;
        Ok(Self {
            receive_limit: ack.channel_id,
            ack_seq: ack.ack_seq,
            selective_acks: ack.selective_acks,
        })
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
        let mut r = Reader::new(data);
        let channel_id = r.read_u32()?;
        r.finish()?;
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
    /// This node may become a landmark.
    pub const LANDMARK_ELIGIBLE: u32 = 1 << 2;
    /// This node is a landmark now.
    pub const LANDMARK: u32 = 1 << 3;

    /// Format capability bitflags as a human-readable string.
    pub fn format(caps: u32) -> String {
        let mut names = Vec::new();
        if caps & RELAY != 0 {
            names.push("relay");
        }
        if caps & TUNNEL != 0 {
            names.push("tunnel");
        }
        if caps & LANDMARK_ELIGIBLE != 0 {
            names.push("landmark-eligible");
        }
        if caps & LANDMARK != 0 {
            names.push("landmark");
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
        let mut r = Reader::new(data);
        let peer_id = r.read_array::<32>()?;
        let capabilities = r.read_u32()?;
        let signaling_secret = r.read_array::<16>()?;
        let transport_count = r.read_u16()? as usize;

        let mut transports = Vec::with_capacity(transport_count.min(r.remaining() / 2));
        for _ in 0..transport_count {
            transports.push(TransportType::from_u16(r.read_u16()?));
        }

        let introducer_count = r.read_u16()? as usize;

        let mut introducers = Vec::with_capacity(introducer_count.min(r.remaining() / 32));
        for _ in 0..introducer_count {
            let id = r.read_array::<32>()?;
            introducers.push(PeerId(id));
        }

        let addr_count = r.read_u16()? as usize;

        let mut global_addresses = Vec::with_capacity(addr_count.min(r.remaining() / 5));
        for _ in 0..addr_count {
            let (addr, consumed) = ScopedAddress::from_bytes(&data[r.pos..])?;
            if addr.is_dialable_global() {
                global_addresses.push(addr);
            }
            r.pos += consumed;
        }

        r.finish()?;
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

/// DhtWatch: walk_header || key(64) || query_token(32) || expiration_secs(u32)
///
/// Travels like a GET walk; every node on the walk registers the watch with the
/// previous hop as the notification return path.
#[derive(Debug, Clone)]
pub struct DhtWatchMsg {
    pub walk: WalkHeader,
    pub key: [u8; 64],
    pub query_token: [u8; 32],
    pub expiration_secs: u32,
}

impl DhtWatchMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(WalkHeader::LEN + 100);
        self.walk.write(&mut buf);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&self.query_token);
        buf.extend_from_slice(&self.expiration_secs.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let walk = WalkHeader::read(&mut r)?;
        let key = r.read_array::<64>()?;
        let query_token = r.read_array::<32>()?;
        let expiration_secs = r.read_u32()?;
        r.finish()?;
        Ok(Self {
            walk,
            key,
            query_token,
            expiration_secs,
        })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtWatch, self.to_bytes())
    }
}

/// DhtWatchNotify: query_token(32) || record (DhtPut without the walk header)
/// The query_token routes the notification back to the watcher hop-by-hop.
#[derive(Debug, Clone)]
pub struct DhtWatchNotifyMsg {
    pub query_token: [u8; 32],
    pub put: DhtPutMsg,
}

impl DhtWatchNotifyMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let record = self.put.record_bytes();
        let mut buf = Vec::with_capacity(32 + record.len());
        buf.extend_from_slice(&self.query_token);
        buf.extend_from_slice(&record);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let query_token = r.read_array::<32>()?;
        // The record runs to the end (its decoder checks nothing follows).
        let put = DhtPutMsg::from_record_bytes(&data[r.pos..])?;
        Ok(Self { query_token, put })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtWatchNotify, self.to_bytes())
    }
}

/// Flag bits of [`DhtNeighborMsg`].
pub mod dht_neighbor_flags {
    /// The sender stores DHT records for others. Relay-only nodes clear it.
    pub const STORES: u8 = 0x01;
}

/// DhtNeighbor: version(u8) || flags(u8). Sent once to each neighbour on
/// link-up so relay-only nodes can steer `DELIVER` detours to a storing node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhtNeighborMsg {
    pub flags: u8,
}

impl DhtNeighborMsg {
    pub fn stores(&self) -> bool {
        self.flags & dht_neighbor_flags::STORES != 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        vec![DHT_VERSION, self.flags & dht_neighbor_flags::STORES]
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let version = r.read_u8()?;
        if version != DHT_VERSION {
            return Err(Error::Wire(format!("unsupported DHT version {}", version)));
        }
        let flags = r.read_u8()? & dht_neighbor_flags::STORES;
        r.finish()?;
        Ok(Self { flags })
    }

    pub fn to_wire(&self) -> WireMessage {
        WireMessage::new(MessageType::DhtNeighbor, self.to_bytes())
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
        let mut r = Reader::new(data);
        let circuit_id = r.read_u32()?;
        let rest = r.read_rest();
        r.finish()?;
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
        let mut r = Reader::new(data);
        let circuit_id = r.read_u32()?;
        let encrypted_payload = r.read_rest();
        r.finish()?;
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
        let mut r = Reader::new(data);
        let circuit_id = r.read_u32()?;
        let encrypted_reply = r.read_rest();
        r.finish()?;
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
        let mut r = Reader::new(data);
        let circuit_id = r.read_u32()?;
        r.finish()?;
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

    /// `bytes` with the peer list whose count byte is at `at` grown to `n`
    /// entries: what a sender could put on the wire, though our encoders
    /// never would.
    fn grow_list(mut bytes: Vec<u8>, at: usize, n: usize) -> Vec<u8> {
        let old = bytes[at] as usize;
        bytes[at] = n as u8;
        let end = at + 1 + 32 * old;
        bytes.splice(end..end, std::iter::repeat(0xAB).take(32 * (n - old)));
        bytes
    }

    #[test]
    fn keepalive_challenges_are_optional_and_truncation_is_rejected() {
        for ping_id in [None, Some(123)] {
            for probe_nonce in [None, Some([42; 16])] {
                let ka = KeepaliveMsg {
                    ping_id,
                    probe_nonce,
                    padding: vec![99; 10],
                };
                let encoded = ka.to_bytes();
                let decoded = KeepaliveMsg::from_bytes(&encoded).unwrap();
                assert_eq!(decoded.ping_id, ping_id);
                assert_eq!(decoded.probe_nonce, probe_nonce);
                if probe_nonce.is_some() {
                    let header = 1 + if ping_id.is_some() { 8 } else { 0 };
                    for end in header..header + 16 {
                        assert!(KeepaliveMsg::from_bytes(&encoded[..end]).is_err());
                    }
                    // Legacy readers inspect only bit 0 and ignore the rest.
                    assert_eq!(encoded[0] & 1 != 0, ping_id.is_some());
                }
            }
        }
        assert!(KeepaliveMsg::from_bytes(&[]).unwrap().probe_nonce.is_none());
    }

    #[test]
    fn sample_messages_round_trip() {
        let walk = SampleWalkMsg { token: [3; 32], steps: 24 };
        assert_eq!(SampleWalkMsg::from_bytes(&walk.to_bytes()).unwrap(), walk);
        let kp = crate::identity::Keypair::generate();
        let address = AddressRecord::sign(&kp, 1, 3600, Vec::new());
        for address in [None, Some(address)] {
            let found = SampleResultMsg {
                token: [4; 32],
                sample: Some(Sample {
                    peer: PeerId([5; 32]),
                    path: vec![PeerId([6; 32]), PeerId([7; 32])],
                    address,
                }),
            };
            assert_eq!(SampleResultMsg::from_bytes(&found.to_bytes()).unwrap(), found);
        }
        let none = SampleResultMsg { token: [4; 32], sample: None };
        assert_eq!(SampleResultMsg::from_bytes(&none.to_bytes()).unwrap(), none);
        let ok = SampleResultMsg {
            token: [4; 32],
            sample: Some(Sample {
                peer: PeerId([5; 32]),
                path: vec![PeerId([6; 32])],
                address: None,
            }),
        };
        // token(32) status(1) peer(32) count
        let long = grow_list(ok.to_bytes(), 65, SAMPLE_PATH_MAX + 1);
        assert!(SampleResultMsg::from_bytes(&long).is_err());
    }

    fn address_entries() -> Vec<AddressEntry> {
        vec![
            AddressEntry {
                landmark: PeerId([1; 32]),
                path: vec![PeerId([2; 32]), PeerId([3; 32])],
            },
            AddressEntry {
                landmark: PeerId([4; 32]),
                path: Vec::new(),
            },
        ]
    }

    #[test]
    fn address_record_signs_round_trips_and_rejects_tampering() {
        for kp in [
            crate::identity::Keypair::generate(),
            crate::identity::Keypair::generate_ed25519(),
        ] {
            let rec = AddressRecord::sign(&kp, 7, 3 * 3600, address_entries());
            assert!(rec.verify());
            let back = AddressRecord::from_bytes(&rec.to_bytes()).unwrap();
            assert_eq!(back, rec);
            assert!(back.verify());

            let mut moved = rec.clone();
            moved.entries[0].path.pop();
            assert!(!moved.verify(), "changed path still verifies");
            let mut newer = rec.clone();
            newer.seq += 1;
            assert!(!newer.verify(), "changed seq still verifies");
            // Another node can't sign for this peer.
            let other = crate::identity::Keypair::generate();
            let mut forged = AddressRecord::sign(&other, 7, 3600, address_entries());
            forged.peer = rec.peer;
            assert!(!forged.verify(), "signer key does not hash to peer");
        }
    }

    #[test]
    fn address_record_bounds() {
        let kp = crate::identity::Keypair::generate_ed25519();
        // The first entry's path: peer(32) seq(4) ttl(4) count(1) landmark(32).
        let rec = AddressRecord::sign(&kp, 1, 60, address_entries());
        let long = grow_list(rec.to_bytes(), 73, PATH_MAX + 1);
        assert!(AddressRecord::from_bytes(&long).is_err());
        let rec = AddressRecord::sign(
            &kp,
            1,
            60,
            vec![address_entries()[1].clone(); ADDRESS_ENTRIES_MAX + 1],
        );
        assert!(AddressRecord::from_bytes(&rec.to_bytes()).is_err());
        let mut bytes = AddressRecord::sign(&kp, 1, 60, Vec::new()).to_bytes();
        bytes.push(0);
        assert!(AddressRecord::from_bytes(&bytes).is_err(), "trailing bytes");
    }

    #[test]
    fn route_search_messages_round_trip() {
        let search = RouteSearchMsg {
            nonce: [1; 16],
            target: PeerId([2; 32]),
            ttl: 8,
        };
        assert_eq!(RouteSearchMsg::from_bytes(&search.to_bytes()).unwrap(), search);
        let found = RouteSearchFoundMsg {
            nonce: [1; 16],
            target: PeerId([2; 32]),
            hops: vec![PeerId([3; 32]), PeerId([4; 32])],
        };
        assert_eq!(RouteSearchFoundMsg::from_bytes(&found.to_bytes()).unwrap(), found);
        // nonce(16) target(32) count
        let long = grow_list(found.to_bytes(), 48, ROUTE_SEARCH_PATH_MAX + 1);
        assert!(RouteSearchFoundMsg::from_bytes(&long).is_err());
    }

    #[test]
    fn directory_messages_round_trip() {
        let kp = crate::identity::Keypair::generate_ed25519();
        let record = AddressRecord::sign(&kp, 3, 600, address_entries());
        let publish = DirPublishMsg {
            landmark: PeerId([8; 32]),
            replica: 2,
            record: record.clone(),
        };
        assert_eq!(DirPublishMsg::from_bytes(&publish.to_bytes()).unwrap(), publish);
        for walking in [true, false] {
            let lookup = DirLookupMsg {
                walking,
                token: [5; 32],
                target: kp.peer_id(),
                replica: 1,
                landmark: PeerId([if walking { 0 } else { 8 }; 32]),
            };
            assert_eq!(DirLookupMsg::from_bytes(&lookup.to_bytes()).unwrap(), lookup);
        }
        for record in [Some(record), None] {
            let result = DirResultMsg { token: [6; 32], record };
            assert_eq!(DirResultMsg::from_bytes(&result.to_bytes()).unwrap(), result);
        }
        let trace = PathTraceMsg {
            token: [7; 32],
            target: PeerId([8; 32]),
            path: vec![PeerId([1; 32]), PeerId([2; 32])],
        };
        assert_eq!(PathTraceMsg::from_bytes(&trace.to_bytes()).unwrap(), trace);
        let back = PathTraceResultMsg {
            token: [7; 32],
            path: trace.path.clone(),
        };
        assert_eq!(PathTraceResultMsg::from_bytes(&back.to_bytes()).unwrap(), back);
        // token(32) target(32) count
        let long = grow_list(trace.to_bytes(), 64, PATH_TRACE_MAX + 1);
        assert!(PathTraceMsg::from_bytes(&long).is_err());
    }

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
        assert_eq!(decoded.challenge, [0xAB; 32]);
        assert_eq!(decoded.eph_kem_pubkey, vec![77u8; 1216]);
        assert_eq!(decoded.min_version, 2);
        assert_eq!(decoded.max_version, 3);
    }

    #[test]
    fn handshake_hello_is_exact() {
        let hello = HandshakeHello {
            ephemeral_pubkey: [42u8; 32],
            signing_algo: 1,
            signing_pubkey: vec![99u8; 32],
            kem_algo: 2,
            kem_pubkey: vec![88u8; 32],
            challenge: [0xAB; 32],
            eph_kem_pubkey: vec![77u8; 32],
            min_version: 2,
            max_version: 2,
        };
        let mut bytes = hello.to_bytes();
        assert_eq!(HandshakeHello::from_bytes(&bytes).unwrap().max_version, 2);
        // The version fields are required (the fallback for peers without
        // them could never negotiate a supported version anyway)...
        bytes.truncate(bytes.len() - 2);
        assert!(HandshakeHello::from_bytes(&bytes).is_err());
        // ...and nothing may follow them.
        let mut long = hello.to_bytes();
        long.push(0);
        assert!(HandshakeHello::from_bytes(&long).is_err());
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
    fn stream_ack_preserves_credit_and_rejects_malformed_sacks() {
        let ack = StreamAckMsg {
            receive_limit: 7,
            ack_seq: u32::MAX - 3,
            selective_acks: vec![u32::MAX, 0, 2],
        };
        let bytes = ack.to_bytes();
        let decoded = StreamAckMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.receive_limit, 7);
        assert_eq!(decoded.ack_seq, u32::MAX - 3);
        assert_eq!(decoded.selective_acks, ack.selective_acks);
        assert!(StreamAckMsg::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut oversized = bytes;
        oversized[8..10].copy_from_slice(&((MAX_SELECTIVE_ACKS + 1) as u16).to_be_bytes());
        assert!(StreamAckMsg::from_bytes(&oversized).is_err());
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
            signer: PeerId([0xBB; 32]),
            ttl: 600,
            value: b"hello world".to_vec(),
            signature: vec![0xCC; 64],
            signer_algo: 1,
            signer_pubkey: vec![0xEE; 32],
            walk: WalkHeader {
                flags: walk_flags::DELIVER,
                greedy_budget: 7,
                bloom_salt: 0xDEADBEEF,
                bloom: [0xDD; 256],
            },
        };
        let bytes = put.to_bytes();
        let decoded = DhtPutMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key, put.key);
        assert_eq!(decoded.record_type, RecordType::Hello);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.signer, put.signer);
        assert_eq!(decoded.ttl, put.ttl);
        assert_eq!(decoded.value, b"hello world");
        assert_eq!(decoded.signature, put.signature);
        assert_eq!(decoded.signer_algo, 1);
        assert_eq!(decoded.signer_pubkey, vec![0xEE; 32]);
        assert_eq!(decoded.walk, put.walk);
    }

    #[test]
    fn dht_put_msg_signable_bytes() {
        let put = DhtPutMsg {
            key: [1; 64],
            record_type: RecordType::SignedContent,
            sequence: 7,
            signer: PeerId([2; 32]),
            ttl: 100,
            value: b"data".to_vec(),
            signature: vec![0; 64],
            signer_algo: 0,
            signer_pubkey: vec![],
            walk: Default::default(),
        };
        let signable = put.signable_bytes();
        // The TTL changes per hop and is not signed:
        // label(20) || key(64) || record_type(1) || sequence(8) || value(4)
        assert_eq!(signable.len(), 20 + 64 + 1 + 8 + 4);
        assert_eq!(&signable[..20], b"tarnet dht record v1");
        assert_eq!(&signable[20..84], &[1u8; 64]);
        assert_eq!(signable[84], RecordType::SignedContent.as_u8());
        assert_eq!(&signable[93..], b"data");

        // The signing side (this wire helper) and the verifying side
        // (`dht::record_signable`, used by `verify_incoming_record`) must produce
        // identical bytes, or signatures made here would never verify there.
        assert_eq!(
            signable,
            crate::dht::record_signable(&put.key, put.record_type, put.sequence, &put.value)
        );
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
                    signer: PeerId([0xAA; 32]),
                    ttl: 3600,
                    value: b"first".to_vec(),
                    signature: vec![0x11; 64],
                    signer_algo: 1,
                    signer_pubkey: vec![0xAA; 32],
                },
                DhtResponseRecord {
                    record_type: RecordType::SignedContent,
                    sequence: 0,
                    signer: PeerId([0xBB; 32]),
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
        assert_eq!(decoded.records[0].signer, PeerId([0xAA; 32]));
        assert_eq!(decoded.records[0].value, b"first");
        assert_eq!(decoded.records[1].signer, PeerId([0xBB; 32]));
        assert_eq!(decoded.records[1].value, b"second record");
        assert_eq!(decoded.records[1].ttl, resp.records[1].ttl);
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
            signer: PeerId([0xBB; 32]),
            ttl: 600,
            value: b"unknown data".to_vec(),
            signature: vec![0xCC; 64],
            signer_algo: 0,
            signer_pubkey: vec![],
            walk: Default::default(),
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
            walk: WalkHeader::origin(),
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
            walk: WalkHeader::origin(),
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
                signer: PeerId([0xDD; 32]),
                ttl: 600,
                value: b"notify data".to_vec(),
                signature: vec![0xEE; 64],
                signer_algo: 1,
                signer_pubkey: vec![0xDD; 32],
                walk: Default::default(),
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
    fn dht_get_msg_roundtrip() {
        let get = DhtGetMsg {
            walk: WalkHeader {
                flags: 0,
                greedy_budget: 9,
                bloom_salt: 1,
                bloom: [0x5A; 256],
            },
            key: [0x42; 64],
            query_token: [0x24; 32],
        };
        let decoded = DhtGetMsg::from_bytes(&get.to_bytes()).unwrap();
        assert_eq!(decoded.walk, get.walk);
        assert_eq!(decoded.key, get.key);
        assert_eq!(decoded.query_token, get.query_token);
    }

    #[test]
    fn walk_header_rejects_other_versions_and_masks_reserved_flags() {
        let get = DhtGetMsg {
            walk: WalkHeader::origin(),
            key: [0; 64],
            query_token: [0; 32],
        };
        let mut bytes = get.to_bytes();
        bytes[1] = 0xFF; // reserved flag bits set by a future sender
        let decoded = DhtGetMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.walk.flags, walk_flags::WALKING | walk_flags::DELIVER);

        bytes[0] = DHT_VERSION + 1;
        assert!(DhtGetMsg::from_bytes(&bytes).is_err());
    }

    #[test]
    fn dht_neighbor_msg_roundtrip() {
        for flags in [0, dht_neighbor_flags::STORES] {
            let msg = DhtNeighborMsg { flags };
            let decoded = DhtNeighborMsg::from_bytes(&msg.to_bytes()).unwrap();
            assert_eq!(decoded, msg);
        }
        assert!(!DhtNeighborMsg::from_bytes(&[DHT_VERSION, 0xFE]).unwrap().stores());
    }

    #[test]
    fn tunnel_key_exchange_roundtrip() {
        let ke = TunnelKeyExchangeMsg {
            kem_algo: 0x02,
            ephemeral_pubkey: vec![0x11; 1216],
            initiator_peer_id: PeerId([0x22; 32]),
            nonce: [0x33; 32],
            signer_algo: 0x01,
            signer_pubkey: vec![0x44; 32],
            signature: vec![0x55; 64],
        };
        let bytes = ke.to_bytes();
        let decoded = TunnelKeyExchangeMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.kem_algo, 0x02);
        assert_eq!(decoded.ephemeral_pubkey, vec![0x11; 1216]);
        assert_eq!(decoded.initiator_peer_id, PeerId([0x22; 32]));
        assert_eq!(decoded.nonce, [0x33; 32]);
        assert_eq!(decoded.signer_algo, 0x01);
        assert_eq!(decoded.signer_pubkey, vec![0x44; 32]);
        assert_eq!(decoded.signature, vec![0x55; 64]);
    }

    #[test]
    fn tunnel_key_response_roundtrip() {
        let kr = TunnelKeyResponseMsg {
            kem_algo: 0x02,
            ciphertext: vec![0xAA; 1120],
            responder_peer_id: PeerId([0xBB; 32]),
            nonce: [0xCC; 32],
            initiator_nonce: [0xDD; 32],
            signer_algo: 0x01,
            signer_pubkey: vec![0xEE; 32],
            signature: vec![0xFF; 64],
        };
        let bytes = kr.to_bytes();
        let decoded = TunnelKeyResponseMsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.kem_algo, 0x02);
        assert_eq!(decoded.ciphertext, vec![0xAA; 1120]);
        assert_eq!(decoded.responder_peer_id, PeerId([0xBB; 32]));
        assert_eq!(decoded.nonce, [0xCC; 32]);
        assert_eq!(decoded.initiator_nonce, [0xDD; 32]);
        assert_eq!(decoded.signer_algo, 0x01);
        assert_eq!(decoded.signer_pubkey, vec![0xEE; 32]);
        assert_eq!(decoded.signature, vec![0xFF; 64]);
    }

    #[test]
    fn tunnel_kex_signature_binds_ephemeral_and_identity() {
        use crate::identity::{verify_with_pubkey, Keypair};
        use tarnet_api::types::SigningAlgo;

        let alice = Keypair::generate_ed25519(); // initiator
        let bob = Keypair::generate_ed25519(); // responder
        let mallory = Keypair::generate_ed25519(); // on-path relay

        let alice_algo = SigningAlgo::Ed25519;
        let eph_alice = vec![0xA1; 1216]; // Alice's genuine ephemeral KEM pubkey
        let mut ke = TunnelKeyExchangeMsg {
            kem_algo: 0x02,
            ephemeral_pubkey: eph_alice.clone(),
            initiator_peer_id: alice.peer_id(),
            nonce: [0x33; 32],
            signer_algo: alice_algo as u8,
            signer_pubkey: alice.identity.signing.signing_pubkey_bytes(),
            signature: Vec::new(),
        };
        ke.signature = alice.sign(&ke.signed_bytes(&bob.peer_id()));

        // Honest path: Bob verifies Alice's offer against his own PeerId.
        assert!(
            verify_with_pubkey(
                alice_algo,
                &ke.signer_pubkey,
                &ke.initiator_peer_id,
                &ke.signed_bytes(&bob.peer_id()),
                &ke.signature,
            ),
            "genuine offer must verify"
        );

        // MITM #1: Mallory swaps the ephemeral key but leaves Alice's id+sig.
        // Bob reconstructs the transcript with the swapped key → verify fails.
        let mut swapped = ke.clone();
        swapped.ephemeral_pubkey = vec![0xEE; 1216];
        assert!(
            !verify_with_pubkey(
                alice_algo,
                &swapped.signer_pubkey,
                &swapped.initiator_peer_id,
                &swapped.signed_bytes(&bob.peer_id()),
                &swapped.signature,
            ),
            "ephemeral substitution must be rejected"
        );

        // MITM #2: Mallory re-signs with her own key but keeps Alice's PeerId.
        // The PeerId↔pubkey binding in verify_with_pubkey rejects it.
        let mut forged = ke.clone();
        forged.signer_pubkey = mallory.identity.signing.signing_pubkey_bytes();
        forged.signature = mallory.sign(&forged.signed_bytes(&bob.peer_id()));
        assert!(
            !verify_with_pubkey(
                alice_algo,
                &forged.signer_pubkey,
                &forged.initiator_peer_id, // still claims to be Alice
                &forged.signed_bytes(&bob.peer_id()),
                &forged.signature,
            ),
            "impersonating Alice's PeerId with another key must be rejected"
        );

        // MITM #3: redirection — Bob's offer was meant for Bob, not Mallory.
        // Verifying with Mallory's PeerId as the destination fails.
        assert!(
            !verify_with_pubkey(
                alice_algo,
                &ke.signer_pubkey,
                &ke.initiator_peer_id,
                &ke.signed_bytes(&mallory.peer_id()),
                &ke.signature,
            ),
            "offer bound to Bob must not verify for a different responder"
        );

        // Response leg: Bob signs over the ephemeral key he received.
        let mut kr = TunnelKeyResponseMsg {
            kem_algo: 0x02,
            ciphertext: vec![0xBB; 1120],
            responder_peer_id: bob.peer_id(),
            nonce: [0xCC; 32],
            initiator_nonce: ke.nonce,
            signer_algo: alice_algo as u8,
            signer_pubkey: bob.identity.signing.signing_pubkey_bytes(),
            signature: Vec::new(),
        };
        kr.signature = bob.sign(&kr.signed_bytes(&alice.peer_id(), &eph_alice));

        // Alice verifies using the ephemeral key SHE actually sent.
        assert!(
            verify_with_pubkey(
                alice_algo,
                &kr.signer_pubkey,
                &bob.peer_id(),
                &kr.signed_bytes(&alice.peer_id(), &eph_alice),
                &kr.signature,
            ),
            "genuine response must verify"
        );

        // MITM on the response: Bob actually encapsulated to a swapped key, so
        // he signs over that swapped key. Alice reconstructs with her real
        // ephemeral key → verify fails, defeating the MITM.
        let kr_swapped_sig = bob.sign(&kr.signed_bytes(&alice.peer_id(), &[0xEE; 1216]));
        assert!(
            !verify_with_pubkey(
                alice_algo,
                &kr.signer_pubkey,
                &bob.peer_id(),
                &kr.signed_bytes(&alice.peer_id(), &eph_alice),
                &kr_swapped_sig,
            ),
            "response signed over a substituted ephemeral key must be rejected"
        );
    }

    #[test]
    fn encrypted_data_msg_roundtrip() {
        let msg = EncryptedDataMsg {
            origin: PeerId([0x11; 32]),
            destination: PeerId([0x22; 32]),
            ttl: 42,
            hints: Vec::new(),
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
    fn data_msg_hints_roundtrip_and_bound() {
        let msg = DataMsg {
            origin: PeerId([1; 32]),
            destination: PeerId([2; 32]),
            ttl: 7,
            hints: vec![PeerId([3; 32]), PeerId([4; 32])],
            data: b"payload".to_vec(),
        };
        let decoded = DataMsg::from_bytes(&msg.to_bytes()).unwrap();
        assert_eq!(decoded.hints, msg.hints);
        assert_eq!(decoded.data, msg.data);
        // origin(32) destination(32) ttl(1) count
        let long = grow_list(msg.to_bytes(), 65, MAX_HINTS + 1);
        assert!(DataMsg::from_bytes(&long).is_err());
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
    #[test]
    fn address_ttl_is_mutable_but_previous_wire_version_is_rejected() {
        let kp = crate::identity::Keypair::generate();
        let mut record = AddressRecord::sign(&kp, 1, 600, Vec::new());
        record.ttl_secs = 10;
        assert!(record.verify());
        let mut message = WireMessage::new(MessageType::DirResult, Vec::new()).encode();
        message[0] = 5;
        assert!(WireMessage::decode(&message).is_err());
    }
}
