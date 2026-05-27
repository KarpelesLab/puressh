//! High-level synchronous SSH client over `std::net::TcpStream`.
//!
//! ```ignore
//! use puressh::client::{Client, Config};
//!
//! let mut c = Client::connect("example.com:22", Config::default())?;
//! c.authenticate_password("alice", "hunter2")?;
//! let out = c.exec("uname -a")?;
//! print!("{}", String::from_utf8_lossy(&out.stdout));
//! ```

#![cfg(feature = "std")]

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use purecrypto::hash::{Digest, Sha256};
use purecrypto::rng::{OsRng, RngCore};

use crate::auth::{ClientAuth, ClientCredential, ClientStep};
use crate::channel::{
    ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState, SSH_EXTENDED_DATA_STDERR,
};
use crate::error::{Error, Result};
use crate::hostkey::{host_key_verify_by_name, HostKey, HostKeyVerify};
use crate::transport::kex::{defaults, KexAlgorithms};
use crate::transport::{KexInit, KexRunner, PacketCodec, Role, VersionExchange};

/// Maximum line length when reading the peer's identification banner.
const MAX_BANNER_LINE: usize = 1024;
/// Maximum number of banner lines we'll skim through before giving up.
const MAX_BANNER_LINES: usize = 256;
/// Soft cap on the inbound packet-reassembly buffer.
const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
/// Hard cap on accumulated exec stdout+stderr.
const MAX_EXEC_OUTPUT: usize = 64 * 1024 * 1024;
/// Maximum iterations for the KEX driver loop.
const MAX_KEX_STEPS: usize = 32;
/// Maximum iterations for the userauth loop.
const MAX_AUTH_STEPS: usize = 64;
/// Maximum iterations for the exec drain loop.
const MAX_EXEC_ITER: usize = 1_000_000;

const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

/// Policy for accepting (or rejecting) a server's host key.
pub enum HostKeyPolicy {
    /// Trust whatever the server presents — equivalent to OpenSSH's
    /// `StrictHostKeyChecking=no`. Insecure; do not use against untrusted peers.
    AcceptAny,
    /// Accept only if the server's host-key SHA-256 fingerprint (the raw 32
    /// bytes, exactly as `ssh-keygen -lf` reports them) matches.
    AcceptFingerprint([u8; 32]),
}

/// Client configuration knobs.
pub struct Config {
    /// How to decide whether a server's host key is acceptable.
    pub host_key_policy: HostKeyPolicy,
    /// Optional per-operation socket timeout.
    pub timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: None,
        }
    }
}

/// Result of running `exec`.
pub struct ExecOutput {
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes (extended-data channel, code 1).
    pub stderr: Vec<u8>,
    /// Process exit status (POSIX exit code), if the server sent `exit-status`.
    pub exit_status: Option<u32>,
    /// Signal name (no `SIG` prefix), if the server sent `exit-signal`.
    pub exit_signal: Option<String>,
}

/// A blocking SSH client.
pub struct Client {
    stream: TcpStream,
    codec: PacketCodec,
    conn: ConnectionState,
    session_id: Vec<u8>,
    inbox: Vec<u8>,
    rng: OsRng,
}

impl Client {
    /// Connect, complete version exchange + KEX + NEWKEYS, leave the codec keyed
    /// and ready for userauth.
    pub fn connect<A: ToSocketAddrs>(addr: A, cfg: Config) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        if let Some(t) = cfg.timeout {
            stream.set_read_timeout(Some(t))?;
            stream.set_write_timeout(Some(t))?;
        }
        stream.set_nodelay(true)?;

        let mut me = Self {
            stream,
            codec: PacketCodec::new(),
            conn: ConnectionState::new(),
            session_id: Vec::new(),
            inbox: Vec::new(),
            rng: OsRng,
        };
        me.do_version_and_kex(cfg.host_key_policy)?;
        Ok(me)
    }

    /// Try every credential in order until one succeeds or all are refused.
    pub fn authenticate(&mut self, user: &str, credentials: Vec<ClientCredential>) -> Result<()> {
        let mut auth = ClientAuth::new(user, self.session_id.clone());
        for c in credentials {
            auth.add_credential(c);
        }
        let first = auth.start();
        self.write_payload(&first)?;

        for _ in 0..MAX_AUTH_STEPS {
            let payload = self.read_one_packet()?;
            match auth.on_packet(&payload)? {
                ClientStep::Send(p) => self.write_payload(&p)?,
                ClientStep::Success => return Ok(()),
                ClientStep::Failed { .. } => return Err(Error::AuthFailed),
                ClientStep::Banner { .. } => {}
                ClientStep::Idle => {}
            }
        }
        Err(Error::Protocol("auth: too many steps without termination"))
    }

    /// Convenience: try password authentication only.
    pub fn authenticate_password(&mut self, user: &str, password: &str) -> Result<()> {
        self.authenticate(user, vec![ClientCredential::Password(password.into())])
    }

    /// Convenience: try publickey authentication only.
    pub fn authenticate_publickey(
        &mut self,
        user: &str,
        key: Box<dyn HostKey + Send>,
    ) -> Result<()> {
        self.authenticate(user, vec![ClientCredential::PublicKey(key)])
    }

    /// Run a remote command, draining stdout/stderr and capturing the exit
    /// status (or signal). Returns once the server has closed the channel.
    pub fn exec(&mut self, command: &str) -> Result<ExecOutput> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.write_payload(&open_payload)?;

        let mut opened = false;
        let mut iter_guard = 0usize;
        while !opened {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("exec: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => {
                    opened = true;
                }
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("channel open failed"));
                }
                _ => {}
            }
        }

        let exec_req = self.conn.send_request(
            local_id,
            ChannelRequest::Exec {
                command: command.into(),
            },
            true,
        )?;
        self.write_payload(&exec_req)?;

        let mut exec_accepted = false;
        iter_guard = 0;
        while !exec_accepted {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("exec: request loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::Success { channel } if channel == local_id => exec_accepted = true,
                ChannelEvent::Failure { channel } if channel == local_id => {
                    return Err(Error::Protocol("exec request denied"));
                }
                _ => {}
            }
        }

        let mut out = ExecOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: None,
            exit_signal: None,
        };
        let mut local_eof_sent = false;
        let mut local_close_sent = false;
        let mut remote_close_seen = false;

        for _ in 0..MAX_EXEC_ITER {
            if remote_close_seen && local_close_sent {
                break;
            }
            let payload = self.read_one_packet()?;
            let ev = self.conn.on_packet(&payload)?;
            match ev {
                ChannelEvent::Data { channel, data } if channel == local_id => {
                    if out.stdout.len() + out.stderr.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("exec output too large"));
                    }
                    let n = data.len() as u32;
                    out.stdout.extend_from_slice(&data);
                    if let Some(adj) = self.conn.replenish_window(local_id, n)? {
                        self.write_payload(&adj)?;
                    }
                }
                ChannelEvent::ExtendedData {
                    channel,
                    code,
                    data,
                } if channel == local_id => {
                    if out.stdout.len() + out.stderr.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("exec output too large"));
                    }
                    let n = data.len() as u32;
                    if code == SSH_EXTENDED_DATA_STDERR {
                        out.stderr.extend_from_slice(&data);
                    } else {
                        out.stdout.extend_from_slice(&data);
                    }
                    if let Some(adj) = self.conn.replenish_window(local_id, n)? {
                        self.write_payload(&adj)?;
                    }
                }
                ChannelEvent::Request {
                    channel,
                    request,
                    want_reply,
                } if channel == local_id => {
                    match request {
                        ChannelRequest::ExitStatus { code } => out.exit_status = Some(code),
                        ChannelRequest::ExitSignal { name, .. } => out.exit_signal = Some(name),
                        _ => {}
                    }
                    if want_reply {
                        let p = self.conn.send_request_failure(local_id)?;
                        self.write_payload(&p)?;
                    }
                }
                ChannelEvent::Eof { channel } if channel == local_id && !local_eof_sent => {
                    let p = self.conn.send_eof(local_id)?;
                    self.write_payload(&p)?;
                    local_eof_sent = true;
                }
                ChannelEvent::Close { channel } if channel == local_id => {
                    remote_close_seen = true;
                    if !local_close_sent {
                        let p = self.conn.send_close(local_id)?;
                        self.write_payload(&p)?;
                        local_close_sent = true;
                    }
                }
                ChannelEvent::WindowAdjust { .. } => {}
                _ => {}
            }
        }

        if !(remote_close_seen && local_close_sent) {
            return Err(Error::Protocol("exec: drain loop exceeded iteration cap"));
        }
        Ok(out)
    }

    fn do_version_and_kex(&mut self, policy: HostKeyPolicy) -> Result<()> {
        let v_c = crate::transport::version::LOCAL_VERSION.as_bytes().to_vec();
        self.stream.write_all(&VersionExchange::outgoing_bytes())?;

        let v_s = self.read_peer_version()?;

        let advert = build_default_kexinit(&mut self.rng);
        let mut runner = KexRunner::new(Role::Client, advert);
        let initial = runner.start(&mut self.rng)?;
        for p in initial.outbound {
            self.write_payload(&p)?;
        }

        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > MAX_KEX_STEPS {
                return Err(Error::Protocol("kex: too many steps"));
            }
            let payload = self.read_one_packet()?;
            let msg = *payload.first().ok_or(Error::Format("empty kex payload"))?;

            let verifier_box;
            let verifier: Option<&dyn HostKeyVerify> = if msg == SSH_MSG_KEX_ECDH_REPLY {
                verifier_box = Some(build_verifier(&payload, &policy, &runner)?);
                verifier_box.as_deref()
            } else {
                None
            };

            let adv = runner.on_packet(
                &mut self.rng,
                &mut self.codec,
                &payload,
                None,
                verifier,
                &v_c,
                &v_s,
            )?;
            for p in adv.outbound {
                self.write_payload(&p)?;
            }
            if adv.completed {
                break;
            }
        }
        self.session_id = runner
            .session_id()
            .ok_or(Error::Protocol("kex: missing session id"))?
            .to_vec();
        Ok(())
    }

    fn read_peer_version(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        for _ in 0..MAX_BANNER_LINES {
            buf.clear();
            read_line(&mut self.stream, &mut buf, MAX_BANNER_LINE)?;
            if buf.starts_with(b"SSH-") {
                let parsed = VersionExchange::parse_remote(&buf)?;
                return Ok(parsed.into_bytes());
            }
        }
        Err(Error::Protocol("peer banner too long"))
    }

    fn read_one_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            let payload = self.read_one_raw_packet()?;
            match payload.first().copied() {
                // SSH_MSG_DISCONNECT — peer initiated.
                Some(1) => return Err(Error::Protocol("peer sent SSH_MSG_DISCONNECT")),
                // SSH_MSG_IGNORE, SSH_MSG_UNIMPLEMENTED, SSH_MSG_DEBUG — drop.
                Some(2) | Some(3) | Some(4) => continue,
                _ => return Ok(payload),
            }
        }
    }

    fn read_one_raw_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some((payload, consumed)) = self.codec.decode(&self.inbox)? {
                self.inbox.drain(..consumed);
                return Ok(payload);
            }
            let mut tmp = [0u8; 16 * 1024];
            let n = self.stream.read(&mut tmp)?;
            if n == 0 {
                return Err(Error::Protocol("connection closed"));
            }
            self.inbox.extend_from_slice(&tmp[..n]);
            if self.inbox.len() > MAX_INBOX_BYTES {
                return Err(Error::Protocol("inbound buffer too large"));
            }
        }
    }

    fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        let frame = self.codec.encode(payload, &mut self.rng)?;
        self.stream.write_all(&frame)?;
        Ok(())
    }
}

fn build_default_kexinit<R: RngCore>(rng: &mut R) -> KexInit {
    // GEX is in `defaults::KEX` but the runner doesn't wire it up — drop it for now.
    let kex_no_gex: Vec<&str> = defaults::KEX
        .iter()
        .copied()
        .filter(|n| *n != "diffie-hellman-group-exchange-sha256")
        .collect();
    let algs = KexAlgorithms {
        kex: &kex_no_gex,
        server_host_key: defaults::HOST_KEY,
        ciphers_c2s: defaults::CIPHERS,
        ciphers_s2c: defaults::CIPHERS,
        macs_c2s: defaults::MACS,
        macs_s2c: defaults::MACS,
        comp_c2s: defaults::COMP,
        comp_s2c: defaults::COMP,
        lang_c2s: &[],
        lang_s2c: &[],
    };
    let mut cookie = [0u8; 16];
    rng.fill_bytes(&mut cookie);
    KexInit::from_algorithms(&algs, cookie)
}

fn build_verifier(
    reply_payload: &[u8],
    policy: &HostKeyPolicy,
    runner: &KexRunner,
) -> Result<Box<dyn HostKeyVerify>> {
    if reply_payload.len() < 5 {
        return Err(Error::Format("kex-ecdh-reply too short"));
    }
    let k_s_len = u32::from_be_bytes([
        reply_payload[1],
        reply_payload[2],
        reply_payload[3],
        reply_payload[4],
    ]) as usize;
    if reply_payload.len() < 5 + k_s_len {
        return Err(Error::Format("kex-ecdh-reply truncated"));
    }
    let k_s = &reply_payload[5..5 + k_s_len];

    match policy {
        HostKeyPolicy::AcceptAny => {}
        HostKeyPolicy::AcceptFingerprint(fp) => {
            let digest = Sha256::digest(k_s);
            if digest.as_ref() != fp {
                return Err(Error::HostKeyRejected);
            }
        }
    }

    let neg = runner
        .negotiated()
        .ok_or(Error::Protocol("kex: no negotiated algorithms"))?;
    host_key_verify_by_name(&neg.host_key, k_s)
}

fn read_line<S: Read>(stream: &mut S, buf: &mut Vec<u8>, max_len: usize) -> Result<()> {
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(Error::Protocol("connection closed before newline"));
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(());
        }
        if buf.len() >= max_len {
            return Err(Error::Protocol("banner line too long"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::Ed25519HostKey;
    use crate::transport::version::LOCAL_VERSION;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn read_line_caps_length() {
        let mut buf = Vec::new();
        let mut src = Cursor::new(vec![b'A'; 4096]);
        let err = read_line(&mut src, &mut buf, 1024);
        assert!(matches!(err, Err(Error::Protocol(_))));
    }

    #[test]
    fn read_line_returns_at_newline() {
        let mut buf = Vec::new();
        let mut src = Cursor::new(b"hello\r\n".to_vec());
        read_line(&mut src, &mut buf, 1024).unwrap();
        assert_eq!(buf, b"hello\r\n");
    }

    #[test]
    fn config_default_is_accept_any() {
        let cfg = Config::default();
        assert!(matches!(cfg.host_key_policy, HostKeyPolicy::AcceptAny));
        assert!(cfg.timeout.is_none());
    }

    #[test]
    fn exec_output_constructible() {
        let _ = ExecOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: Some(0),
            exit_signal: None,
        };
    }

    fn run_server(
        listener: TcpListener,
        host_key_seed: [u8; 32],
    ) -> thread::JoinHandle<std::result::Result<Vec<u8>, String>> {
        thread::spawn(move || -> std::result::Result<Vec<u8>, String> {
            let (mut s, _) = listener.accept().map_err(|e| e.to_string())?;
            let server_hk = Ed25519HostKey::from_seed(host_key_seed);

            s.write_all(&VersionExchange::outgoing_bytes())
                .map_err(|e| e.to_string())?;
            let mut line = Vec::new();
            let v_c: Vec<u8> = {
                read_line(&mut s, &mut line, 1024).map_err(|e| format!("{e:?}"))?;
                if !line.starts_with(b"SSH-") {
                    return Err("client did not send SSH banner".into());
                }
                let parsed = VersionExchange::parse_remote(&line).map_err(|e| format!("{e:?}"))?;
                parsed.into_bytes()
            };
            let v_s = LOCAL_VERSION.as_bytes().to_vec();

            let mut codec = PacketCodec::new();
            let advert = build_default_kexinit(&mut OsRng);
            let mut runner = KexRunner::new(Role::Server, advert);

            let mut inbox: Vec<u8> = Vec::new();
            let mut rng = OsRng;

            let initial = runner.start(&mut rng).map_err(|e| format!("{e:?}"))?;
            for p in initial.outbound {
                let frame = codec.encode(&p, &mut rng).map_err(|e| format!("{e:?}"))?;
                s.write_all(&frame).map_err(|e| e.to_string())?;
            }

            let mut steps = 0;
            loop {
                steps += 1;
                if steps > MAX_KEX_STEPS {
                    return Err("server kex did not converge".into());
                }
                let payload = read_one_packet_local(&mut s, &mut codec, &mut inbox)
                    .map_err(|e| format!("{e:?}"))?;
                let adv = runner
                    .on_packet(
                        &mut rng,
                        &mut codec,
                        &payload,
                        Some(&server_hk),
                        None,
                        &v_c,
                        &v_s,
                    )
                    .map_err(|e| format!("{e:?}"))?;
                for p in adv.outbound {
                    let frame = codec.encode(&p, &mut rng).map_err(|e| format!("{e:?}"))?;
                    s.write_all(&frame).map_err(|e| e.to_string())?;
                }
                if adv.completed {
                    break;
                }
            }

            let sid = runner.session_id().unwrap().to_vec();
            Ok(sid)
        })
    }

    fn read_one_packet_local(
        s: &mut TcpStream,
        codec: &mut PacketCodec,
        inbox: &mut Vec<u8>,
    ) -> Result<Vec<u8>> {
        loop {
            if let Some((payload, consumed)) = codec.decode(inbox)? {
                inbox.drain(..consumed);
                return Ok(payload);
            }
            let mut tmp = [0u8; 4096];
            let n = s.read(&mut tmp)?;
            if n == 0 {
                return Err(Error::Protocol("connection closed"));
            }
            inbox.extend_from_slice(&tmp[..n]);
            if inbox.len() > MAX_INBOX_BYTES {
                return Err(Error::Protocol("inbound buffer too large"));
            }
        }
    }

    #[test]
    fn handshake_over_real_loopback_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let server = run_server(listener, seed);

        let client = Client::connect(addr, Config::default()).expect("client connect");
        let server_sid = server.join().unwrap().expect("server handshake");
        assert_eq!(client.session_id, server_sid);
        assert!(!client.session_id.is_empty());
    }

    #[test]
    fn fingerprint_mismatch_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let server = run_server(listener, seed);

        let cfg = Config {
            host_key_policy: HostKeyPolicy::AcceptFingerprint([0xffu8; 32]),
            timeout: None,
        };
        let err = Client::connect(addr, cfg).err().expect("must fail");
        assert!(matches!(err, Error::HostKeyRejected));
        // The server thread may have errored after our connect dropped — that's fine.
        let _ = server.join();
    }
}
