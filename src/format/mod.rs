//! SSH wire-format primitives (RFC 4251 §5).
//!
//! All multi-byte integers are big-endian. Strings are `uint32`-length-prefixed
//! byte blobs; `name-list`s are strings of comma-separated ASCII names;
//! `mpint`s are length-prefixed two's-complement big-endian integers with
//! the minimum number of leading zero/sign bytes.

mod reader;
mod writer;
mod mpint;
mod name_list;

pub use reader::Reader;
pub use writer::Writer;
pub use mpint::{read_mpint, write_mpint};
pub use name_list::NameList;
