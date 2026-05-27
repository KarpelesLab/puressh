//! Minimal base64 decoder (RFC 4648 standard alphabet).
//!
//! Self-contained to avoid pulling in a `base64` dependency. Skips ASCII
//! whitespace transparently (newlines inside PEM bodies are normal).

use alloc::vec::Vec;

use crate::error::{Error, Result};

const INVALID: u8 = 0xff;
const PADDING: u8 = 0xfe;

const fn build_table() -> [u8; 256] {
    let mut t = [INVALID; 256];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i < 64 {
        t[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    t[b'=' as usize] = PADDING;
    t
}

const TABLE: [u8; 256] = build_table();

/// Decode a base64 string. Whitespace bytes (`b' '`, `\r`, `\n`, `\t`) are
/// ignored. Padding `=` is accepted but optional.
pub fn decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = [0u8; 4];
    let mut n = 0usize;
    let mut padding = 0usize;
    for &c in input {
        if matches!(c, b' ' | b'\r' | b'\n' | b'\t') {
            continue;
        }
        let v = TABLE[c as usize];
        if v == INVALID {
            return Err(Error::Format("base64: invalid character"));
        }
        if v == PADDING {
            padding += 1;
            if padding > 2 {
                return Err(Error::Format("base64: too much padding"));
            }
            buf[n] = 0;
        } else {
            if padding != 0 {
                return Err(Error::Format("base64: data after padding"));
            }
            buf[n] = v;
        }
        n += 1;
        if n == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            if padding < 2 {
                out.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if padding < 1 {
                out.push((buf[2] << 6) | buf[3]);
            }
            n = 0;
            if padding != 0 {
                break;
            }
        }
    }
    match n {
        0 => Ok(out),
        2 => {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            Ok(out)
        }
        3 => {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
            Ok(out)
        }
        _ => Err(Error::Format("base64: truncated group")),
    }
}

/// Encode bytes as standard base64 with `=` padding.
pub fn encode(input: &[u8]) -> alloc::string::String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize]);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize]);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize]);
        out.push(ALPHABET[(n & 0x3f) as usize]);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize]);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize]);
            out.push(b'=');
            out.push(b'=');
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize]);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize]);
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize]);
            out.push(b'=');
        }
        _ => {}
    }
    // SAFETY-equivalent: every pushed byte is from ALPHABET or '=' — all ASCII.
    alloc::string::String::from_utf8(out).expect("base64 output is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, enc) in cases {
            assert_eq!(encode(raw), *enc);
            assert_eq!(decode(enc.as_bytes()).unwrap(), *raw);
        }
    }

    #[test]
    fn ignores_whitespace() {
        let s = b"Zm9v\nYmFy\n";
        assert_eq!(decode(s).unwrap(), b"foobar");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode(b"!!!").is_err());
    }
}
