//! `mpint`: two's-complement big-endian multi-precision integer (RFC 4251 §5).
//!
//! Encoded as a `string` whose bytes contain the integer in big-endian two's-complement
//! form, with the minimum number of bytes. For positive numbers whose MSB would be
//! set, a leading 0x00 is prepended; the value zero is encoded as a zero-length string.

use super::{Reader, Writer};
use crate::error::Result;

/// Read an `mpint`, returning a slice of its raw two's-complement bytes.
///
/// Most SSH uses are non-negative — callers wanting an unsigned magnitude
/// should strip a leading 0x00 themselves if present.
pub fn read_mpint<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    r.read_string()
}

/// Encode an unsigned integer (given as big-endian magnitude) as an `mpint`.
///
/// A leading 0x00 is prepended automatically when the MSB of the magnitude is set,
/// per RFC 4251 §5. Leading zero bytes in `magnitude` are stripped.
#[cfg(feature = "alloc")]
pub fn write_mpint(w: &mut Writer, magnitude: &[u8]) {
    // Strip leading zero bytes — except keep one to represent the value 0,
    // then we'll re-encode that as an empty string below.
    let mut start = 0usize;
    while start < magnitude.len() && magnitude[start] == 0 {
        start += 1;
    }
    let m = &magnitude[start..];
    if m.is_empty() {
        w.write_u32(0);
        return;
    }
    // If high bit is set, prepend a 0x00 sign byte.
    if m[0] & 0x80 != 0 {
        w.write_u32((m.len() + 1) as u32);
        w.write_u8(0);
        w.write_raw(m);
    } else {
        w.write_u32(m.len() as u32);
        w.write_raw(m);
    }
}
