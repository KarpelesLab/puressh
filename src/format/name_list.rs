//! `name-list`: a `string` of comma-separated, ASCII algorithm names (RFC 4251 §5).

use super::Reader;
use crate::error::Result;

/// A borrowed `name-list` — the raw comma-separated string body.
#[derive(Debug, Clone, Copy)]
pub struct NameList<'a>(pub &'a [u8]);

impl<'a> NameList<'a> {
    /// Decode a `name-list` from the cursor.
    pub fn read(r: &mut Reader<'a>) -> Result<Self> {
        Ok(NameList(r.read_string()?))
    }

    /// Iterate the comma-separated names (as ASCII byte slices).
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.0.split(|&b| b == b',').filter(|s| !s.is_empty())
    }

    /// Pick the first name we offer that the peer also offers.
    ///
    /// Used during KEX guess/negotiation per RFC 4253 §7.1.
    pub fn negotiate<'b>(ours: &'b [&'b str], theirs: NameList<'_>) -> Option<&'b str> {
        for name in ours {
            for t in theirs.iter() {
                if t == name.as_bytes() {
                    return Some(name);
                }
            }
        }
        None
    }
}
