//! The one byte reader every decoder uses: bounds-checked reads, and
//! [`Reader::finish`], which rejects bytes left over, so each message has
//! exactly one encoding.

use crate::types::{Error, PeerId, Result};

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// The message ends here: bytes left over are an error. Every decoder
    /// calls this last, so a message has exactly one encoding (a hash of the
    /// raw bytes identifies it; appending junk can't make a copy look new).
    pub(crate) fn finish(&self) -> Result<()> {
        if self.pos != self.data.len() {
            return Err(Error::Wire(format!(
                "{} trailing bytes after message",
                self.data.len() - self.pos
            )));
        }
        Ok(())
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = u16::from_be_bytes(self.data[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub(crate) fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.pos + N > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(arr)
    }

    pub(crate) fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.pos + n > self.data.len() {
            return Err(Error::Protocol("unexpected end of data".into()));
        }
        let v = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    pub(crate) fn read_rest(&mut self) -> Vec<u8> {
        let v = self.data[self.pos..].to_vec();
        self.pos = self.data.len();
        v
    }
}

impl Reader<'_> {
    /// A peer list: `count(u8) || count × peer(32)`, at most `max` long.
    pub(crate) fn read_peers(&mut self, max: usize, what: &str) -> Result<Vec<PeerId>> {
        let count = self.read_u8()? as usize;
        if count > max {
            return Err(Error::Wire(format!("{} lists {} peers (max {})", what, count, max)));
        }
        (0..count).map(|_| self.read_array::<32>().map(PeerId)).collect()
    }
}

/// Write a peer list as [`Reader::read_peers`] reads it. Senders build lists
/// within `max`; a longer one is a bug, and is cut to `max` rather than
/// sent for the next hop to refuse.
pub(crate) fn write_peers(buf: &mut Vec<u8>, peers: &[PeerId], max: usize) {
    debug_assert!(peers.len() <= max, "peer list of {} over {}", peers.len(), max);
    let peers = &peers[..peers.len().min(max).min(u8::MAX as usize)];
    buf.push(peers.len() as u8);
    for p in peers {
        buf.extend_from_slice(p.as_bytes());
    }
}
