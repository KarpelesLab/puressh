//! Wire format of the knock datagrams (`docs/knock.md` §2–§4): KNOCK and
//! ACCEPT encode/parse, the SSHSIG-style signed-data wrapper, signature
//! verification against an SSH public-key blob, and the open-token KDF.

use alloc::vec::Vec;

use purecrypto::hash::{Digest, Sha256, Sha512};
use purecrypto::kdf::{hkdf_expand, hkdf_extract};
use purecrypto::zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};
use crate::hostkey::HostKey;

/// Protocol version carried in the first byte of every datagram.
pub const VERSION: u8 = 0x01;
/// Datagram type of a client KNOCK.
pub const TYPE_KNOCK: u8 = 0x01;
/// Datagram type of a server ACCEPT.
pub const TYPE_ACCEPT: u8 = 0x02;
/// Largest datagram either side sends or accepts (IPv6 minimum MTU − IPv6 −
/// UDP headers), so a knock never fragments.
pub const MAX_DATAGRAM: usize = 1232;
/// KNOCK flag: the client has no host key on file and wants the full blob.
pub const FLAG_NEED_HOSTKEY: u8 = 0x01;
/// ACCEPT flag: the `hostkey` field is present.
pub const FLAG_HOSTKEY_FULL: u8 = 0x01;
/// Longest accepted login name, in bytes.
pub const MAX_USER_LEN: usize = 64;

/// SSHSIG namespace of sig1 (the static per-(user, key) token).
pub const NS_KNOCK_ID: &str = "knock-id@puressh";
/// SSHSIG namespace of sig2 (the per-knock signature).
pub const NS_KNOCK: &str = "knock@puressh";
/// SSHSIG namespace of the host signature on an ACCEPT.
pub const NS_ACCEPT: &str = "knock-accept@puressh";

const TOKEN_INFO: &[u8] = b"puressh knock open v1";
/// Fixed-size head of an ACCEPT: version, type, flags, knock_hash, eph_s,
/// port, window.
const ACCEPT_HEAD_LEN: usize = 3 + 32 + 32 + 2 + 2;

/// `SHA-256` of an SSH wire-format public-key blob — the `key_fp` /
/// `host_fp` of the protocol (same input as an OpenSSH `SHA256:` fingerprint).
pub fn key_fp(blob: &[u8]) -> [u8; 32] {
    Sha256::digest(blob)
}

/// SHA-256 of a whole KNOCK datagram — binds an ACCEPT to its KNOCK.
pub fn knock_hash(datagram: &[u8]) -> [u8; 32] {
    key_fp(datagram)
}

/// The SSHSIG-style wrapper every knock signature covers (OpenSSH
/// `PROTOCOL.sshsig`, hash `sha512`). Domain-separates knock signatures from
/// SSH userauth signatures and from each other.
pub fn signed_data(namespace: &str, message: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_raw(b"SSHSIG");
    w.write_string(namespace.as_bytes());
    w.write_string(b"");
    w.write_string(b"sha512");
    w.write_string(Sha512::digest(message).as_ref());
    w.into_vec()
}

/// The message sig1 covers: `str8 user ‖ key_fp`.
pub fn knock_id_message(user: &str, key_fp: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + user.len() + 32);
    m.push(user.len() as u8);
    m.extend_from_slice(user.as_bytes());
    m.extend_from_slice(key_fp);
    m
}

/// Sign `message` under `namespace` with `signer`, returning the SSH
/// signature blob.
pub fn sign(signer: &dyn HostKey, namespace: &str, message: &[u8]) -> Result<Vec<u8>> {
    signer.sign(&signed_data(namespace, message))
}

/// Verify an SSH signature blob made under `namespace` over `message` by the
/// key whose wire blob is `key_blob`.
///
/// The signature algorithm must belong to the key's family (`rsa-sha2-256` /
/// `rsa-sha2-512` for an `ssh-rsa` key, otherwise the key's own name).
/// SHA-1 `ssh-rsa` signatures and certificates are refused.
pub fn verify(key_blob: &[u8], namespace: &str, message: &[u8], sig_blob: &[u8]) -> Result<()> {
    let key_alg = Reader::new(key_blob).read_string()?;
    let sig_alg = Reader::new(sig_blob).read_string()?;
    let sig_alg = core::str::from_utf8(sig_alg).map_err(|_| Error::BadSignature)?;
    let family_ok = match key_alg {
        b"ssh-rsa" => matches!(sig_alg, "rsa-sha2-256" | "rsa-sha2-512"),
        b"ssh-ed25519"
        | b"ecdsa-sha2-nistp256"
        | b"ecdsa-sha2-nistp384"
        | b"ecdsa-sha2-nistp521" => sig_alg.as_bytes() == key_alg,
        _ => false,
    };
    if !family_ok {
        return Err(Error::BadSignature);
    }
    let verifier = crate::hostkey::host_key_verify_by_name(sig_alg, key_blob)?;
    verifier.verify(&signed_data(namespace, message), sig_blob)
}

/// Upper bound on the length of an SSH signature blob produced by the key
/// whose wire blob is `key_blob`, or `None` for an unsupported key type.
pub fn max_sig_blob_len(key_blob: &[u8]) -> Option<usize> {
    let mut r = Reader::new(key_blob);
    match r.read_string().ok()? {
        b"ssh-ed25519" => Some(4 + 11 + 4 + 64),
        // string alg ‖ string(mpint r ‖ mpint s); each mpint ≤ 4 + 1 + field.
        b"ecdsa-sha2-nistp256" => Some(4 + 19 + 4 + 2 * (4 + 1 + 32)),
        b"ecdsa-sha2-nistp384" => Some(4 + 19 + 4 + 2 * (4 + 1 + 48)),
        b"ecdsa-sha2-nistp521" => Some(4 + 19 + 4 + 2 * (4 + 1 + 66)),
        b"ssh-rsa" => {
            let _e = r.read_string().ok()?;
            let n = r.read_string().ok()?;
            let n_len = n.iter().skip_while(|b| **b == 0).count();
            // `rsa-sha2-512` is the longest name; the signature is |n| bytes.
            Some(4 + 12 + 4 + n_len)
        }
        _ => None,
    }
}

/// Exact-or-upper-bound size of an ACCEPT signed by `host_key_blob`,
/// carrying the full host key blob or not.
pub fn accept_len_bound(host_key_blob: &[u8], full: bool) -> Option<usize> {
    let sig = max_sig_blob_len(host_key_blob)?;
    let hostkey = if full { 2 + host_key_blob.len() } else { 0 };
    Some(ACCEPT_HEAD_LEN + hostkey + 2 + sig)
}

/// Derive the 32-byte TCP open token from the X25519 shared secret (§4).
pub fn open_token(
    shared: &[u8; 32],
    knock_hash: &[u8; 32],
    eph_s: &[u8; 32],
    port: u16,
) -> Zeroizing<[u8; 32]> {
    let prk = Zeroizing::new(hkdf_extract::<Sha256>(knock_hash, shared));
    let mut info = Vec::with_capacity(TOKEN_INFO.len() + 32 + 2);
    info.extend_from_slice(TOKEN_INFO);
    info.extend_from_slice(eph_s);
    info.extend_from_slice(&port.to_be_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf_expand::<Sha256>(&*prk, &info, &mut out[..]);
    out
}

fn write_str16(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s);
}

fn read_array<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N]> {
    let mut a = [0u8; N];
    a.copy_from_slice(r.take(N)?);
    Ok(a)
}

fn read_u16(r: &mut Reader<'_>) -> Result<u16> {
    let b = r.take(2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_str16<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let n = read_u16(r)? as usize;
    r.take(n)
}

/// A parsed KNOCK datagram, borrowing from the received bytes.
#[derive(Debug, Clone)]
pub struct Knock<'a> {
    /// `FLAG_*` bits.
    pub flags: u8,
    /// Login name.
    pub user: &'a str,
    /// Fingerprint of the client key.
    pub key_fp: [u8; 32],
    /// Static per-(user, key) signature blob.
    pub sig1: &'a [u8],
    /// Client wall clock, ms since the Unix epoch.
    pub nonce: u64,
    /// Client ephemeral X25519 public key.
    pub eph_c: [u8; 32],
    /// Fingerprint of the host key the client expects (zeros with
    /// [`FLAG_NEED_HOSTKEY`]).
    pub host_fp: [u8; 32],
    /// The bytes sig2 covers (everything before sig2's length prefix).
    pub signed: &'a [u8],
    /// Per-knock signature blob.
    pub sig2: &'a [u8],
}

impl<'a> Knock<'a> {
    /// Strictly parse a KNOCK: unknown version / type / flag bits, a bad
    /// length, non-zero padding or trailing bytes are all rejected.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() > MAX_DATAGRAM {
            return Err(Error::Format("knock: datagram too large"));
        }
        let mut r = Reader::new(buf);
        if r.read_u8()? != VERSION || r.read_u8()? != TYPE_KNOCK {
            return Err(Error::Format("knock: version/type"));
        }
        let flags = r.read_u8()?;
        if flags & !FLAG_NEED_HOSTKEY != 0 {
            return Err(Error::Format("knock: unknown flags"));
        }
        let user_len = r.read_u8()? as usize;
        if user_len == 0 || user_len > MAX_USER_LEN {
            return Err(Error::Format("knock: user length"));
        }
        let user = core::str::from_utf8(r.take(user_len)?)
            .map_err(|_| Error::Format("knock: user not UTF-8"))?;
        if user.contains('\0') {
            return Err(Error::Format("knock: NUL in user"));
        }
        let key_fp = read_array::<32>(&mut r)?;
        let sig1 = read_str16(&mut r)?;
        let nonce = r.read_u64()?;
        let eph_c = read_array::<32>(&mut r)?;
        let host_fp = read_array::<32>(&mut r)?;
        if flags & FLAG_NEED_HOSTKEY != 0 && host_fp != [0u8; 32] {
            return Err(Error::Format("knock: host_fp with NEED_HOSTKEY"));
        }
        let padding = read_str16(&mut r)?;
        if padding.iter().any(|b| *b != 0) {
            return Err(Error::Format("knock: non-zero padding"));
        }
        let signed = &buf[..buf.len() - r.remaining()];
        let sig2 = read_str16(&mut r)?;
        if !r.is_empty() {
            return Err(Error::Format("knock: trailing bytes"));
        }
        Ok(Self {
            flags,
            user,
            key_fp,
            sig1,
            nonce,
            eph_c,
            host_fp,
            signed,
            sig2,
        })
    }
}

/// Everything needed to build a KNOCK except sig2.
#[derive(Debug, Clone)]
pub struct KnockFields<'a> {
    /// Login name (1..=64 bytes).
    pub user: &'a str,
    /// Fingerprint of the client key.
    pub key_fp: [u8; 32],
    /// Cached or freshly computed sig1.
    pub sig1: &'a [u8],
    /// Client wall clock, ms since the Unix epoch.
    pub nonce: u64,
    /// Client ephemeral X25519 public key.
    pub eph_c: [u8; 32],
    /// Expected host key fingerprint, or `None` to set
    /// [`FLAG_NEED_HOSTKEY`].
    pub host_fp: Option<[u8; 32]>,
}

impl KnockFields<'_> {
    /// Build and sign a KNOCK of at least `min_len` bytes (padding as needed,
    /// never exceeding [`MAX_DATAGRAM`]).
    pub fn build(&self, signer: &dyn HostKey, min_len: usize) -> Result<Vec<u8>> {
        if self.user.is_empty() || self.user.len() > MAX_USER_LEN {
            return Err(Error::Config("knock: user name must be 1..=64 bytes"));
        }
        let min_len = min_len.min(MAX_DATAGRAM);
        // sig2 comes from the same key as sig1, so sig1's length is a good
        // estimate; ECDSA lengths wobble by a byte or two, hence the retry.
        let mut sig2_estimate = self.sig1.len();
        for _ in 0..4 {
            let mut out = Vec::with_capacity(MAX_DATAGRAM);
            out.push(VERSION);
            out.push(TYPE_KNOCK);
            out.push(if self.host_fp.is_none() {
                FLAG_NEED_HOSTKEY
            } else {
                0
            });
            out.push(self.user.len() as u8);
            out.extend_from_slice(self.user.as_bytes());
            out.extend_from_slice(&self.key_fp);
            write_str16(&mut out, self.sig1);
            out.extend_from_slice(&self.nonce.to_be_bytes());
            out.extend_from_slice(&self.eph_c);
            out.extend_from_slice(&self.host_fp.unwrap_or([0u8; 32]));
            let unpadded = out.len() + 2 + 2 + sig2_estimate;
            let pad = min_len.saturating_sub(unpadded);
            out.extend_from_slice(&(pad as u16).to_be_bytes());
            out.resize(out.len() + pad, 0);
            let sig2 = sign(signer, NS_KNOCK, &out)?;
            write_str16(&mut out, &sig2);
            if out.len() > MAX_DATAGRAM {
                if pad == 0 {
                    return Err(Error::Unsupported("knock: key too large for one datagram"));
                }
                sig2_estimate += out.len() - MAX_DATAGRAM;
                continue;
            }
            if out.len() < min_len {
                sig2_estimate -= min_len - out.len();
                continue;
            }
            return Ok(out);
        }
        Err(Error::Crypto("knock: could not size the datagram"))
    }
}

/// A parsed ACCEPT datagram, borrowing from the received bytes.
#[derive(Debug, Clone)]
pub struct Accept<'a> {
    /// `FLAG_*` bits.
    pub flags: u8,
    /// Hash of the KNOCK this answers.
    pub knock_hash: [u8; 32],
    /// Server ephemeral X25519 public key.
    pub eph_s: [u8; 32],
    /// TCP port of the rendezvous listener.
    pub port: u16,
    /// Seconds the listener stays open.
    pub window: u16,
    /// Full host key blob, present with [`FLAG_HOSTKEY_FULL`].
    pub hostkey: Option<&'a [u8]>,
    /// The bytes `sig_host` covers.
    pub signed: &'a [u8],
    /// Host-key signature blob.
    pub sig_host: &'a [u8],
}

impl<'a> Accept<'a> {
    /// Strictly parse an ACCEPT.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() > MAX_DATAGRAM {
            return Err(Error::Format("accept: datagram too large"));
        }
        let mut r = Reader::new(buf);
        if r.read_u8()? != VERSION || r.read_u8()? != TYPE_ACCEPT {
            return Err(Error::Format("accept: version/type"));
        }
        let flags = r.read_u8()?;
        if flags & !FLAG_HOSTKEY_FULL != 0 {
            return Err(Error::Format("accept: unknown flags"));
        }
        let knock_hash = read_array::<32>(&mut r)?;
        let eph_s = read_array::<32>(&mut r)?;
        let port = read_u16(&mut r)?;
        let window = read_u16(&mut r)?;
        if port == 0 || window == 0 {
            return Err(Error::Format("accept: zero port/window"));
        }
        let hostkey = if flags & FLAG_HOSTKEY_FULL != 0 {
            Some(read_str16(&mut r)?)
        } else {
            None
        };
        let signed = &buf[..buf.len() - r.remaining()];
        let sig_host = read_str16(&mut r)?;
        if !r.is_empty() {
            return Err(Error::Format("accept: trailing bytes"));
        }
        Ok(Self {
            flags,
            knock_hash,
            eph_s,
            port,
            window,
            hostkey,
            signed,
            sig_host,
        })
    }
}

/// Build and sign an ACCEPT with `host_key`.
pub fn build_accept(
    host_key: &dyn HostKey,
    knock_hash: &[u8; 32],
    eph_s: &[u8; 32],
    port: u16,
    window: u16,
    full_hostkey: bool,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(MAX_DATAGRAM);
    out.push(VERSION);
    out.push(TYPE_ACCEPT);
    out.push(if full_hostkey { FLAG_HOSTKEY_FULL } else { 0 });
    out.extend_from_slice(knock_hash);
    out.extend_from_slice(eph_s);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&window.to_be_bytes());
    if full_hostkey {
        write_str16(&mut out, &host_key.public_blob());
    }
    let sig = sign(host_key, NS_ACCEPT, &out)?;
    write_str16(&mut out, &sig);
    Ok(out)
}
