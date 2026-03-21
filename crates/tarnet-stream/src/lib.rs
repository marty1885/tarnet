use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Magic byte identifying stream-mux frames.
pub const STREAM_MAGIC: u8 = 0x73;

/// Stream frame flags.
pub const FLAG_DATA: u8 = 0x00;
pub const FLAG_SYN: u8 = 0x01;
pub const FLAG_FIN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_SYN_ACK: u8 = 0x01 | 0x08; // SYN + ACK bit

/// Minimum frame size: magic(1) + service_hash(32) + stream_id(4) + flags(1) = 38.
pub const FRAME_HEADER_SIZE: usize = 38;

/// Hash a service name to a 32-byte identifier using BLAKE2b-256.
pub fn service_hash(name: &str) -> [u8; 32] {
    *blake3::hash(name.as_bytes()).as_bytes()
}

/// A stream-multiplexed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub service_hash: [u8; 32],
    pub stream_id: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl StreamFrame {
    pub fn new(service_hash: [u8; 32], stream_id: u32, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            service_hash,
            stream_id,
            flags,
            payload,
        }
    }

    pub fn syn(service_hash: [u8; 32], stream_id: u32) -> Self {
        Self::new(service_hash, stream_id, FLAG_SYN, Vec::new())
    }

    pub fn syn_ack(service_hash: [u8; 32], stream_id: u32) -> Self {
        Self::new(service_hash, stream_id, FLAG_SYN_ACK, Vec::new())
    }

    pub fn data(service_hash: [u8; 32], stream_id: u32, payload: Vec<u8>) -> Self {
        Self::new(service_hash, stream_id, FLAG_DATA, payload)
    }

    pub fn fin(service_hash: [u8; 32], stream_id: u32) -> Self {
        Self::new(service_hash, stream_id, FLAG_FIN, Vec::new())
    }

    pub fn rst(service_hash: [u8; 32], stream_id: u32) -> Self {
        Self::new(service_hash, stream_id, FLAG_RST, Vec::new())
    }

    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        buf.push(STREAM_MAGIC);
        buf.extend_from_slice(&self.service_hash);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.push(self.flags);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from wire format. Returns None if too short or wrong magic.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < FRAME_HEADER_SIZE {
            return None;
        }
        if data[0] != STREAM_MAGIC {
            return None;
        }
        let mut service_hash = [0u8; 32];
        service_hash.copy_from_slice(&data[1..33]);
        let stream_id = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
        let flags = data[37];
        let payload = data[FRAME_HEADER_SIZE..].to_vec();
        Some(Self {
            service_hash,
            stream_id,
            flags,
            payload,
        })
    }

    /// Check if this is a stream-mux frame (starts with magic byte).
    pub fn is_stream_frame(data: &[u8]) -> bool {
        data.first() == Some(&STREAM_MAGIC)
    }
}

/// Allocates stream IDs and tracks active streams.
pub struct StreamMux {
    next_id: AtomicU32,
    /// Active streams: (peer_bytes, stream_id) -> service_hash
    active: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl StreamMux {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU32::new(1),
            active: HashMap::new(),
        }
    }

    /// Allocate a new stream ID for a connection to a peer+service.
    pub fn open(&mut self, peer: [u8; 32], svc_hash: [u8; 32]) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active.insert((peer, id), svc_hash);
        id
    }

    /// Register an incoming stream (opened by remote).
    pub fn accept(&mut self, peer: [u8; 32], stream_id: u32, svc_hash: [u8; 32]) {
        self.active.insert((peer, stream_id), svc_hash);
    }

    /// Close a stream.
    pub fn close(&mut self, peer: [u8; 32], stream_id: u32) {
        self.active.remove(&(peer, stream_id));
    }

    /// Look up which service a stream belongs to.
    pub fn lookup(&self, peer: [u8; 32], stream_id: u32) -> Option<&[u8; 32]> {
        self.active.get(&(peer, stream_id))
    }

    /// Check if a stream is active.
    pub fn is_active(&self, peer: [u8; 32], stream_id: u32) -> bool {
        self.active.contains_key(&(peer, stream_id))
    }
}

impl Default for StreamMux {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let frame = StreamFrame::data(service_hash("web"), 42, b"hello world".to_vec());
        let encoded = frame.encode();
        let decoded = StreamFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn syn_frame() {
        let frame = StreamFrame::syn(service_hash("ssh"), 1);
        let encoded = frame.encode();
        let decoded = StreamFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.flags, FLAG_SYN);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn syn_ack_frame() {
        let frame = StreamFrame::syn_ack(service_hash("web"), 1);
        let encoded = frame.encode();
        let decoded = StreamFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.flags, FLAG_SYN_ACK);
    }

    #[test]
    fn fin_frame() {
        let frame = StreamFrame::fin(service_hash("web"), 7);
        let encoded = frame.encode();
        let decoded = StreamFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.flags, FLAG_FIN);
    }

    #[test]
    fn rst_frame() {
        let frame = StreamFrame::rst(service_hash("web"), 3);
        let encoded = frame.encode();
        let decoded = StreamFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.flags, FLAG_RST);
    }

    #[test]
    fn magic_byte_check() {
        assert!(StreamFrame::is_stream_frame(&[STREAM_MAGIC, 0, 0]));
        assert!(!StreamFrame::is_stream_frame(&[0x00, 0, 0]));
        assert!(!StreamFrame::is_stream_frame(&[]));
    }

    #[test]
    fn too_short_decode() {
        assert!(StreamFrame::decode(&[STREAM_MAGIC; 10]).is_none());
    }

    #[test]
    fn wrong_magic_decode() {
        let mut data = vec![0u8; FRAME_HEADER_SIZE];
        data[0] = 0xFF;
        assert!(StreamFrame::decode(&data).is_none());
    }

    #[test]
    fn service_hash_deterministic() {
        let h1 = service_hash("web");
        let h2 = service_hash("web");
        assert_eq!(h1, h2);
        let h3 = service_hash("ssh");
        assert_ne!(h1, h3);
    }

    #[test]
    fn stream_mux_lifecycle() {
        let mut mux = StreamMux::new();
        let peer = [1u8; 32];
        let svc = service_hash("web");

        let id = mux.open(peer, svc);
        assert!(mux.is_active(peer, id));
        assert_eq!(mux.lookup(peer, id), Some(&svc));

        mux.close(peer, id);
        assert!(!mux.is_active(peer, id));
    }

    #[test]
    fn stream_mux_accept() {
        let mut mux = StreamMux::new();
        let peer = [2u8; 32];
        let svc = service_hash("ssh");

        mux.accept(peer, 99, svc);
        assert!(mux.is_active(peer, 99));
        assert_eq!(mux.lookup(peer, 99), Some(&svc));
    }
}
