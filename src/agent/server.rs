//! The request handling of an `ssh-agent`, without the socket: feed it one
//! decoded message (type byte + body) at a time with [`AgentState::handle`]
//! and send back what it returns. The `ssh-agent` binary wraps it with a
//! Unix socket and a thread per connection.
//!
//! Supported (draft-miller-ssh-agent / OpenSSH `PROTOCOL.agent`): listing,
//! signing (RSA `rsa-sha2-256` / `rsa-sha2-512` flags, legacy SHA-1 when no
//! flag), adding keys with an optional lifetime constraint, removing one or
//! all keys, and locking / unlocking with a passphrase. Requests this agent
//! cannot honour — the `confirm` constraint (no askpass UI), destination
//! constraints, smartcards, extensions — are refused, never silently
//! weakened.

use alloc::vec::Vec;
use std::time::{Duration, Instant};

use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::{Digest, Sha512};
use zeroize::Zeroizing;

use super::protocol::*;
use crate::format::{Reader, Writer};
use crate::key::PrivateKey;

struct Held {
    key: PrivateKey,
    blob: Vec<u8>,
    comment: String,
    expires: Option<Instant>,
}

/// The keys an agent holds and its lock state.
pub struct AgentState {
    keys: Vec<Held>,
    /// SHA-512 of the lock passphrase while locked.
    locked: Option<Zeroizing<[u8; 64]>>,
    default_lifetime: Option<Duration>,
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for AgentState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentState")
            .field("keys", &self.keys.len())
            .field("locked", &self.locked.is_some())
            .finish()
    }
}

fn reply(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(msg_type);
    v.extend_from_slice(body);
    v
}

fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

fn success() -> Vec<u8> {
    vec![SSH_AGENT_SUCCESS]
}

impl AgentState {
    /// An empty, unlocked agent.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            locked: None,
            default_lifetime: None,
        }
    }

    /// Give keys added without a lifetime constraint this lifetime
    /// (`ssh-agent -t`).
    pub fn set_default_lifetime(&mut self, lifetime: Option<Duration>) {
        self.default_lifetime = lifetime;
    }

    /// Number of keys held (expired ones excluded).
    pub fn len(&mut self) -> usize {
        self.expire();
        self.keys.len()
    }

    /// `true` when no key is held.
    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.keys.retain(|k| k.expires.is_none_or(|t| now < t));
    }

    /// Handle one request (`type byte ‖ body`) and return the reply
    /// (`type byte ‖ body`), ready to be length-prefixed onto the socket.
    pub fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        self.expire();
        let Some((&msg_type, body)) = request.split_first() else {
            return failure();
        };
        let locked = self.locked.is_some();
        match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                let mut w = Writer::new();
                // A locked agent lists nothing.
                let shown: Vec<&Held> = if locked {
                    Vec::new()
                } else {
                    self.keys.iter().collect()
                };
                w.write_u32(shown.len() as u32);
                for k in shown {
                    w.write_string(&k.blob);
                    w.write_string(k.comment.as_bytes());
                }
                reply(SSH_AGENT_IDENTITIES_ANSWER, w.as_slice())
            }
            SSH_AGENTC_SIGN_REQUEST if !locked => self.sign(body).unwrap_or_else(failure),
            SSH_AGENTC_ADD_IDENTITY | SSH_AGENTC_ADD_ID_CONSTRAINED if !locked => self
                .add(body, msg_type == SSH_AGENTC_ADD_ID_CONSTRAINED)
                .unwrap_or_else(failure),
            SSH_AGENTC_REMOVE_IDENTITY if !locked => {
                let mut r = Reader::new(body);
                let Ok(blob) = r.read_string() else {
                    return failure();
                };
                let before = self.keys.len();
                self.keys.retain(|k| k.blob != blob);
                if self.keys.len() < before {
                    success()
                } else {
                    failure()
                }
            }
            SSH_AGENTC_REMOVE_ALL_IDENTITIES if !locked => {
                self.keys.clear();
                success()
            }
            SSH_AGENTC_LOCK if !locked => {
                let mut r = Reader::new(body);
                let Ok(pass) = r.read_string() else {
                    return failure();
                };
                self.locked = Some(Zeroizing::new(Sha512::digest(pass)));
                success()
            }
            SSH_AGENTC_UNLOCK if locked => {
                let mut r = Reader::new(body);
                let Ok(pass) = r.read_string() else {
                    return failure();
                };
                let digest = Zeroizing::new(Sha512::digest(pass));
                let ok = self
                    .locked
                    .as_ref()
                    .is_some_and(|h| bool::from(h.ct_eq(&*digest)));
                if ok {
                    self.locked = None;
                    success()
                } else {
                    failure()
                }
            }
            SSH_AGENTC_EXTENSION => vec![SSH_AGENT_EXTENSION_FAILURE],
            _ => failure(),
        }
    }

    fn sign(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let blob = r.read_string().ok()?;
        let data = r.read_string().ok()?;
        let flags = r.read_u32().unwrap_or(0);
        let held = self.keys.iter().find(|k| k.blob == blob)?;
        let signer = held.key.agent_signer(flags).ok()?;
        let sig = signer.sign(data).ok()?;
        let mut w = Writer::new();
        w.write_string(&sig);
        Some(reply(SSH_AGENT_SIGN_RESPONSE, w.as_slice()))
    }

    fn add(&mut self, body: &[u8], constrained: bool) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let key = PrivateKey::from_agent_add_body(&mut r).ok()?;
        let mut lifetime = self.default_lifetime;
        if constrained {
            while !r.is_empty() {
                match r.read_u8().ok()? {
                    SSH_AGENT_CONSTRAIN_LIFETIME => {
                        lifetime = Some(Duration::from_secs(r.read_u32().ok()? as u64));
                    }
                    // `confirm` needs an askpass prompt per use and
                    // extensions (e.g. destination restrictions) narrow
                    // where a key may be used: refuse rather than hold the
                    // key without honouring them.
                    _ => return None,
                }
            }
        } else if !r.is_empty() {
            return None;
        }
        let blob = key.public_key().wire_blob();
        let comment = key.comment().to_string();
        let expires = lifetime.map(|d| Instant::now() + d);
        // Re-adding a key replaces it (new comment / lifetime).
        self.keys.retain(|k| k.blob != blob);
        self.keys.push(Held {
            key,
            blob,
            comment,
            expires,
        });
        Some(success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::client::Agent;

    fn fixture(name: &str) -> PrivateKey {
        let path = format!("{}/tests/fixtures/cert/{name}", env!("CARGO_MANIFEST_DIR"));
        PrivateKey::parse_openssh_pem(&std::fs::read_to_string(path).unwrap(), None).unwrap()
    }

    fn msg(t: u8, body: &[u8]) -> Vec<u8> {
        reply(t, body)
    }

    fn add(state: &mut AgentState, key: &PrivateKey) -> u8 {
        state.handle(&msg(SSH_AGENTC_ADD_IDENTITY, &key.to_agent_add_body()))[0]
    }

    fn sign(state: &mut AgentState, blob: &[u8], data: &[u8], flags: u32) -> Option<Vec<u8>> {
        let mut w = Writer::new();
        w.write_string(blob);
        w.write_string(data);
        w.write_u32(flags);
        let r = state.handle(&msg(SSH_AGENTC_SIGN_REQUEST, w.as_slice()));
        if r[0] != SSH_AGENT_SIGN_RESPONSE {
            return None;
        }
        Some(Reader::new(&r[1..]).read_string().unwrap().to_vec())
    }

    fn count(state: &mut AgentState) -> u32 {
        let r = state.handle(&[SSH_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(r[0], SSH_AGENT_IDENTITIES_ANSWER);
        Reader::new(&r[1..]).read_u32().unwrap()
    }

    fn sig_alg(sig: &[u8]) -> String {
        String::from_utf8(Reader::new(sig).read_string().unwrap().to_vec()).unwrap()
    }

    #[test]
    fn add_list_sign_verify() {
        let mut s = AgentState::new();
        let ed = fixture("u_ed25519");
        let rsa = fixture("u_rsa");
        assert_eq!(add(&mut s, &ed), SSH_AGENT_SUCCESS);
        assert_eq!(add(&mut s, &rsa), SSH_AGENT_SUCCESS);
        assert_eq!(count(&mut s), 2);
        // Re-adding replaces rather than duplicates.
        assert_eq!(add(&mut s, &ed), SSH_AGENT_SUCCESS);
        assert_eq!(count(&mut s), 2);

        let ed_blob = ed.public_key().wire_blob();
        let sig = sign(&mut s, &ed_blob, b"data", 0).unwrap();
        crate::hostkey::host_key_verify_by_name("ssh-ed25519", &ed_blob)
            .unwrap()
            .verify(b"data", &sig)
            .unwrap();

        let rsa_blob = rsa.public_key().wire_blob();
        for (flags, alg) in [(4, "rsa-sha2-512"), (2, "rsa-sha2-256")] {
            let sig = sign(&mut s, &rsa_blob, b"data", flags).unwrap();
            assert_eq!(sig_alg(&sig), alg);
            crate::hostkey::host_key_verify_by_name(alg, &rsa_blob)
                .unwrap()
                .verify(b"data", &sig)
                .unwrap();
        }
        assert_eq!(
            sig_alg(&sign(&mut s, &rsa_blob, b"data", 0).unwrap()),
            "ssh-rsa"
        );
        // Unknown key.
        assert!(sign(&mut s, b"nope", b"data", 0).is_none());
    }

    #[test]
    fn constraints_lock_and_remove() {
        let mut s = AgentState::new();
        let ed = fixture("u_ed25519");
        let ec = fixture("u_ecdsa");
        // Lifetime 0 s: already expired on the next request.
        let mut body = ed.to_agent_add_body();
        body.push(SSH_AGENT_CONSTRAIN_LIFETIME);
        body.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_ADD_ID_CONSTRAINED, &body))[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(count(&mut s), 0);
        // `confirm` cannot be honoured: refused, key not held.
        let mut body = ed.to_agent_add_body();
        body.push(2);
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_ADD_ID_CONSTRAINED, &body))[0],
            SSH_AGENT_FAILURE
        );
        assert_eq!(count(&mut s), 0);

        add(&mut s, &ed);
        add(&mut s, &ec);
        let mut w = Writer::new();
        w.write_string(b"pw");
        let lock = msg(SSH_AGENTC_LOCK, w.as_slice());
        assert_eq!(s.handle(&lock)[0], SSH_AGENT_SUCCESS);
        assert_eq!(count(&mut s), 0, "locked agent lists nothing");
        assert!(sign(&mut s, &ed.public_key().wire_blob(), b"x", 0).is_none());
        assert_eq!(add(&mut s, &ed), SSH_AGENT_FAILURE);
        let mut bad = Writer::new();
        bad.write_string(b"wrong");
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_UNLOCK, bad.as_slice()))[0],
            SSH_AGENT_FAILURE
        );
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_UNLOCK, w.as_slice()))[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(count(&mut s), 2);

        let mut r = Writer::new();
        r.write_string(&ec.public_key().wire_blob());
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_REMOVE_IDENTITY, r.as_slice()))[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(count(&mut s), 1);
        assert_eq!(
            s.handle(&[SSH_AGENTC_REMOVE_ALL_IDENTITIES])[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(count(&mut s), 0);
        assert_eq!(
            s.handle(&[SSH_AGENTC_EXTENSION])[0],
            SSH_AGENT_EXTENSION_FAILURE
        );
        assert_eq!(s.handle(&[99])[0], SSH_AGENT_FAILURE);
        assert_eq!(s.handle(&[])[0], SSH_AGENT_FAILURE);
    }

    /// The client's new requests against this agent, over a real socket.
    #[test]
    fn client_round_trip() {
        use std::io::{Read, Write};
        let dir = std::env::temp_dir().join(format!("puressh-agent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut state = AgentState::new();
            let mut len = [0u8; 4];
            while conn.read_exact(&mut len).is_ok() {
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                conn.read_exact(&mut req).unwrap();
                let resp = state.handle(&req);
                conn.write_all(&(resp.len() as u32).to_be_bytes()).unwrap();
                conn.write_all(&resp).unwrap();
            }
        });
        let mut a = Agent::connect(&path).unwrap();
        let ed = fixture("u_ed25519");
        a.add_identity_with_lifetime(&ed, 600).unwrap();
        assert_eq!(a.identities().unwrap().len(), 1);
        a.lock(b"pw").unwrap();
        assert!(a.identities().unwrap().is_empty());
        assert!(a.unlock(b"bad").is_err());
        a.unlock(b"pw").unwrap();
        a.remove_identity(&ed.public_key().wire_blob()).unwrap();
        assert!(a.remove_identity(&ed.public_key().wire_blob()).is_err());
        a.add_identity(&ed).unwrap();
        a.remove_all_identities().unwrap();
        assert!(a.identities().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
