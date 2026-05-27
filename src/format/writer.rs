//! Buffered writer for SSH wire-format values.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// A growable, owned encoder.
#[cfg(feature = "alloc")]
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl Writer {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create a writer with the given capacity hint.
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap) }
    }

    /// Append raw bytes (no length prefix).
    pub fn write_raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Write a single `byte`.
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write an SSH `boolean`.
    pub fn write_bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }

    /// Write a big-endian `uint32`.
    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a big-endian `uint64`.
    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a `string`: 4-byte big-endian length, then bytes.
    pub fn write_string(&mut self, s: &[u8]) {
        self.write_u32(s.len() as u32);
        self.buf.extend_from_slice(s);
    }

    /// Return the underlying buffer.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the encoded bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Current encoded length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}
