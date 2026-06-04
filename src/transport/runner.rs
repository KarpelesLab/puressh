//! KEX runner — sans-I/O state machine driving one full key-exchange.
//!
//! The caller is responsible for the wire: it drains outbound payloads through
//! [`crate::transport::PacketCodec::encode`] and feeds decoded inbound payloads
//! into [`KexRunner::on_packet`]. The runner does the maths and, when the
//! exchange completes, installs the negotiated cipher / MAC into the codec for
//! the appropriate direction.
//!
//! Re-keys are triggered by calling [`KexRunner::start`] again on the same
//! runner; the session id (the exchange hash of the *first* KEX of the
//! connection) is preserved across re-keys.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use purecrypto::hash::{Digest, Sha256, Sha384, Sha512};
use purecrypto::rng::{CryptoRng, RngCore};

use crate::cipher::{cipher_by_name, SshCipher};
use crate::compress::{compress_by_name, decompress_by_name};
use crate::error::{Error, Result};
use crate::hostkey::{HostKey, HostKeyVerify};
use crate::kex::{
    curve25519::Curve25519Sha256,
    dh::{GexClientState, GexRequest, GexSha256, Group14Sha256, Group16Sha512, Group18Sha512},
    ecdh::{EcdhSha2Nistp256, EcdhSha2Nistp384, EcdhSha2Nistp521},
    KexContext,
};
use crate::mac::{mac_by_name, SshMac};
use purecrypto::dh::{group14, group16, group18, DhGroup};

use super::ext_info::ExtInfo;
use super::kex::Negotiated;
use super::kexinit::{negotiate, KexInit, NegotiatedOwned, SSH_MSG_NEWKEYS};
use super::packet::PacketCodec;

/// Whose end of the connection this runner represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client side.
    Client,
    /// Server side.
    Server,
}

/// Result of stepping the runner.
#[derive(Debug, Default, Clone)]
pub struct KexAdvance {
    /// Frames to send (decoded payloads — the codec frames them).
    pub outbound: Vec<Vec<u8>>,
    /// `true` once both sides have exchanged NEWKEYS and the codec's
    /// install hooks have been driven.
    pub completed: bool,
}

/// Per-direction key material derived from `(K, H, session_id)` (RFC 4253 §7.2).
///
/// Stored on the runner so callers can inspect what was installed; the runner
/// already pushed this material into the [`PacketCodec`] before returning the
/// completion flag from [`KexRunner::on_packet`].
#[derive(Debug, Clone)]
pub struct DirKeys {
    /// Negotiated cipher name (e.g. `aes256-ctr`).
    pub cipher: String,
    /// IV / nonce bytes; length matches `CipherSpec::iv_len`.
    pub iv: Vec<u8>,
    /// Cipher key bytes; length matches `CipherSpec::key_len`.
    pub key: Vec<u8>,
    /// Negotiated MAC name, empty when the cipher is AEAD.
    pub mac: String,
    /// MAC key bytes; empty when the cipher is AEAD.
    pub mac_key: Vec<u8>,
}

/// Both directions' worth of derived keys.
#[derive(Debug, Clone)]
pub struct InstalledKeys {
    /// Client to server direction.
    pub c2s: DirKeys,
    /// Server to client direction.
    pub s2c: DirKeys,
}

const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
// RFC 4419 §3. Bytes 30 / 31 are also reused as GEX_REQUEST_OLD and
// GEX_GROUP respectively — disambiguated by `KexBackend::Gex` in the runner.
const SSH_MSG_KEX_DH_GEX_REQUEST_OLD: u8 = 30;
const SSH_MSG_KEX_DH_GEX_GROUP: u8 = 31;
const SSH_MSG_KEX_DH_GEX_INIT: u8 = 32;
const SSH_MSG_KEX_DH_GEX_REPLY: u8 = 33;
const SSH_MSG_KEX_DH_GEX_REQUEST: u8 = 34;

/// One of the supported KEX backends. Identifies both the algorithm and the
/// hash used for `H` / KDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KexBackend {
    Curve25519,
    EcdhP256,
    EcdhP384,
    EcdhP521,
    Dh14,
    Dh16,
    Dh18,
    /// `diffie-hellman-group-exchange-sha256` — RFC 4419 three-trip.
    Gex,
}

impl KexBackend {
    fn from_name(name: &str) -> Result<Self> {
        match name {
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => Ok(Self::Curve25519),
            "ecdh-sha2-nistp256" => Ok(Self::EcdhP256),
            "ecdh-sha2-nistp384" => Ok(Self::EcdhP384),
            "ecdh-sha2-nistp521" => Ok(Self::EcdhP521),
            "diffie-hellman-group14-sha256" => Ok(Self::Dh14),
            "diffie-hellman-group16-sha512" => Ok(Self::Dh16),
            "diffie-hellman-group18-sha512" => Ok(Self::Dh18),
            "diffie-hellman-group-exchange-sha256" => Ok(Self::Gex),
            _ => Err(Error::Unsupported("KEX algorithm")),
        }
    }
}

/// Default GEX group selection (RFC 4419 §3). Honour the `[min, max]`
/// range the client requested as a hard constraint: a group whose prime
/// is smaller than `req.min` would let a downgrade attacker force weaker
/// DH parameters. We map to one of the RFC 3526 safe-prime groups we
/// ship (group14 = 2048, group16 = 4096, group18 = 8192) — they're
/// well-formed and conservatively sized for their bit count.
fn default_gex_group(req: GexRequest) -> DhGroup {
    // Pick the smallest group that satisfies `req.min`, then bound by
    // the preferred `n`. If the client demands more than group18 offers,
    // we still hand back group18 (best we have) — the client's
    // `client_finish` independently re-validates that the returned
    // prime/generator lie in its own [min, max] range and will reject if
    // not, which keeps us honest.
    if req.min > 4096 {
        return group18();
    }
    if req.min > 2048 {
        // Need at least 4096 bits. Pick group16 unless the preferred
        // size also demands group18.
        return if req.n > 4096 { group18() } else { group16() };
    }
    // req.min <= 2048: any of our groups qualifies on the min side.
    // Fall back to the existing n-based selection, bounded by req.max
    // so we never hand back something the client said was too large.
    if req.n <= 2048 && req.max >= 2048 {
        group14()
    } else if req.n <= 4096 && req.max >= 4096 {
        group16()
    } else if req.max >= 8192 {
        group18()
    } else if req.max >= 4096 {
        group16()
    } else {
        // req.max < 4096 (and >= 2048 by the path we took here).
        group14()
    }
}

/// Algorithm-specific client state stashed between the init message and the reply.
enum ClientStateInner {
    Curve(crate::kex::curve25519::ClientState),
    Ecdh(crate::kex::ecdh::ClientState),
    Dh(crate::kex::dh::DhClientState),
    Gex(GexClientState),
}

enum Phase {
    /// `start` hasn't been called yet.
    Idle,
    /// We've sent our KEXINIT; awaiting the peer's.
    SentKexInit,
    /// Both KEXINITs are on the wire; algorithm-specific exchange in progress.
    Negotiated {
        /// Client-side ephemeral state. `None` on the server.
        client_state: Option<ClientStateInner>,
    },
    /// GEX-only: client has sent `GEX_REQUEST`, waiting for `GEX_GROUP`.
    /// Owns the partially-initialised client state until `GEX_INIT` is built.
    GexClientAwaitGroup { client_state: GexClientState },
    /// GEX-only: client has sent `GEX_INIT`, waiting for `GEX_REPLY`.
    GexClientAwaitReply { client_state: GexClientState },
    /// GEX-only: server has sent `GEX_GROUP`, waiting for `GEX_INIT`.
    GexServerAwaitInit { request: GexRequest, group: DhGroup },
    /// `(K, H)` computed; awaiting peer NEWKEYS.
    AwaitingPeerNewKeys,
    /// Done.
    Completed,
}

/// State machine driving one SSH key exchange to completion.
pub struct KexRunner {
    role: Role,
    our_advert_owned: KexInit,
    our_advert_bytes: Vec<u8>,
    peer_advert_bytes: Option<Vec<u8>>,
    negotiated: Option<NegotiatedOwned>,
    backend: Option<KexBackend>,
    /// `H` of the first KEX on this connection.
    session_id: Option<Vec<u8>>,
    current_h: Option<Vec<u8>>,
    current_k: Option<Vec<u8>>,
    installed_keys: Option<InstalledKeys>,
    sent_newkeys: bool,
    peer_newkeys: bool,
    phase: Phase,
    /// True when the most recent negotiation enabled strict-kex (Terrapin /
    /// CVE-2023-48795). Locked at `handle_peer_kexinit`. Latched across
    /// re-keys: once enabled it cannot be downgraded.
    strict_kex: bool,
    /// Set after handle_peer_kexinit when the peer's first_kex_packet_follows
    /// hint produced the wrong guess (RFC 4253 §7.1). The next KEX
    /// algorithm-specific packet must be silently discarded.
    pending_wrong_guess_discard: bool,
    /// `true` until [`Self::restart`] is called for the first time. RFC
    /// 8308 §2.1 ties the ext-info advert + send eligibility to the *first*
    /// KEX of a connection; we drop the marker from rekey adverts and
    /// refuse to send/receive a second ext-info even if a peer asks.
    first_kex: bool,
    /// True when the most recent negotiation enabled ext-info (RFC 8308).
    /// Like strict-kex, this is set at `handle_peer_kexinit` time. Unlike
    /// strict-kex it is NOT carried across rekeys: ext-info only fires on
    /// the first KEX.
    ext_info_enabled: bool,
    /// Outbound `SSH_MSG_EXT_INFO` payload the caller would like us to
    /// send. The runner emits it as part of the outbound batch produced by
    /// `handle_peer_newkeys` on the first KEX iff [`ext_info_enabled`] is
    /// true. Caller fills via [`Self::set_outbound_ext_info`].
    outbound_ext_info: Option<ExtInfo>,
    /// Parsed `SSH_MSG_EXT_INFO` received from the peer. Updated by
    /// [`Self::handle_inbound_ext_info`]; consumers read via
    /// [`Self::peer_ext_info`].
    peer_ext_info: Option<ExtInfo>,
    /// True iff the peer is *currently* allowed to send us a single
    /// `SSH_MSG_EXT_INFO`. Becomes true:
    ///
    /// - immediately after the peer's NEWKEYS on the first KEX (when
    ///   both sides advertised the marker), and
    /// - on the client, after the higher layer notes
    ///   `SSH_MSG_USERAUTH_SUCCESS` via [`Self::arm_ext_info_post_auth`].
    ///
    /// Becomes false again on the very next packet of any kind from the
    /// peer (whether or not it was the ext-info).
    accept_ext_info_now: bool,
}

impl KexRunner {
    /// Build a new runner. `advert` is the KEXINIT message this side will send;
    /// callers construct it via [`KexInit::from_algorithms`] with a fresh random
    /// cookie.
    pub fn new(role: Role, advert: KexInit) -> Self {
        let bytes = advert.encode();
        Self {
            role,
            our_advert_owned: advert,
            our_advert_bytes: bytes,
            peer_advert_bytes: None,
            negotiated: None,
            backend: None,
            session_id: None,
            current_h: None,
            current_k: None,
            installed_keys: None,
            sent_newkeys: false,
            peer_newkeys: false,
            phase: Phase::Idle,
            strict_kex: false,
            pending_wrong_guess_discard: false,
            first_kex: true,
            ext_info_enabled: false,
            outbound_ext_info: None,
            peer_ext_info: None,
            accept_ext_info_now: false,
        }
    }

    /// Strict-kex (Terrapin / CVE-2023-48795) enabled on this connection,
    /// as negotiated at the most recent KEX. Once a connection negotiates
    /// strict-kex it stays enabled across all subsequent re-keys.
    pub fn strict_kex_enabled(&self) -> bool {
        self.strict_kex
    }

    /// Kick the runner off: emit our KEXINIT. Both client and server call
    /// this once at the start of the very first key exchange. Re-keys go
    /// through [`restart`](Self::restart) instead.
    pub fn start<R: RngCore + CryptoRng>(&mut self, _rng: &mut R) -> Result<KexAdvance> {
        match self.phase {
            Phase::Idle => {
                self.phase = Phase::SentKexInit;
                Ok(KexAdvance {
                    outbound: vec![self.our_advert_bytes.clone()],
                    completed: false,
                })
            }
            _ => Err(Error::Protocol("KexRunner::start called twice")),
        }
    }

    /// Begin a re-key (RFC 4253 §9). Must be called only when the runner is
    /// in the `Completed` phase (see [`KexRunner::is_completed`]). Caches a
    /// fresh KEXINIT advert (replacing the previous one's cookie) and emits
    /// it; the `session_id` from the first KEX is preserved across re-keys,
    /// but every other transient field is reset so the new exchange runs
    /// cleanly.
    pub fn restart<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        advert: KexInit,
    ) -> Result<KexAdvance> {
        match self.phase {
            Phase::Completed => {}
            _ => return Err(Error::Protocol("KexRunner::restart from non-Completed")),
        }
        let bytes = advert.encode();
        self.our_advert_owned = advert;
        self.our_advert_bytes = bytes;
        self.peer_advert_bytes = None;
        self.negotiated = None;
        self.backend = None;
        self.current_h = None;
        self.current_k = None;
        self.installed_keys = None;
        self.sent_newkeys = false;
        self.peer_newkeys = false;
        self.pending_wrong_guess_discard = false;
        // session_id stays put — it's the H of the FIRST KEX (RFC 4253 §7.2).
        // strict_kex is also latched across re-keys: once enabled on a
        // connection it cannot be downgraded by the peer mid-session.
        // Ext-info, by contrast, is FIRST-KEX-ONLY: clear the per-connection
        // flags and refuse to send/receive a second ext-info regardless of
        // what the peer's rekey advert claims (RFC 8308 §2.1).
        self.first_kex = false;
        self.ext_info_enabled = false;
        self.outbound_ext_info = None;
        self.accept_ext_info_now = false;
        self.phase = Phase::SentKexInit;
        Ok(KexAdvance {
            outbound: vec![self.our_advert_bytes.clone()],
            completed: false,
        })
    }

    /// `true` if a key exchange is in flight (neither idle nor completed).
    pub fn is_kexing(&self) -> bool {
        !matches!(self.phase, Phase::Idle | Phase::Completed)
    }

    /// `true` once a successful KEX has completed at least once.
    pub fn is_completed(&self) -> bool {
        matches!(self.phase, Phase::Completed)
    }

    /// Feed one decoded inbound payload into the runner.
    ///
    /// `host_key` must be supplied on the server when handling
    /// `SSH_MSG_KEX_ECDH_INIT`. `host_key_verifier` must be supplied on the
    /// client when handling `SSH_MSG_KEX_ECDH_REPLY`. `v_c` / `v_s` are the
    /// version strings exchanged earlier, without CR/LF.
    ///
    /// When the exchange completes (peer NEWKEYS has been seen and our own
    /// NEWKEYS has been queued) the runner installs the negotiated cipher and
    /// MAC into `codec` for the right direction(s) before returning.
    #[allow(clippy::too_many_arguments)]
    pub fn on_packet<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        codec: &mut PacketCodec,
        payload: &[u8],
        host_key: Option<&dyn HostKey>,
        host_key_verifier: Option<&dyn HostKeyVerify>,
        v_c: &[u8],
        v_s: &[u8],
    ) -> Result<KexAdvance> {
        if payload.is_empty() {
            return Err(Error::Format("empty payload"));
        }
        let msg = payload[0];

        // RFC 8308 §2.3: the ext-info one-shot window covers exactly the
        // first post-NEWKEYS packet from the peer. Whatever lands here
        // closes it — the higher-layer router only forwards non-KEX
        // packets via [`Self::note_inbound_other`], so this covers the
        // KEX-message case (e.g. a rekey KEXINIT). The window is
        // re-armed later via [`Self::arm_ext_info_post_auth`] for the
        // client's post-USERAUTH_SUCCESS opportunity.
        self.accept_ext_info_now = false;

        // RFC 4253 §7.1 wrong-guess discard. The peer set
        // `first_kex_packet_follows` and our negotiation said the guess
        // was wrong: drop the first KEX algorithm-specific packet that
        // arrives, then resume normally. Anything outside the KEX
        // algorithm-specific byte range falls through and is rejected.
        if self.pending_wrong_guess_discard
            && matches!(
                &self.phase,
                Phase::Negotiated { .. }
                    | Phase::GexClientAwaitGroup { .. }
                    | Phase::GexServerAwaitInit { .. }
            )
            && matches!(msg, 30..=49)
        {
            self.pending_wrong_guess_discard = false;
            return Ok(KexAdvance::default());
        }

        // Strict-kex (Terrapin / CVE-2023-48795) enforcement: between
        // KEXINIT and NEWKEYS, only KEX-bytes (20, 21, 30..=49) may flow.
        // The transport router should already filter, but defence-in-depth:
        // the runner refuses anything else when strict-kex is on.
        if self.strict_kex
            && !matches!(self.phase, Phase::Idle | Phase::Completed)
            && !matches!(msg, 20 | 21 | 30..=49)
        {
            return Err(Error::Protocol("non-KEX message during strict-kex window"));
        }

        let backend_is_gex = matches!(self.backend, Some(KexBackend::Gex));
        let mut adv = match (&self.phase, msg) {
            (Phase::SentKexInit, super::kexinit::SSH_MSG_KEXINIT) => {
                self.handle_peer_kexinit(rng, payload, v_c, v_s)?
            }
            // ECDH and fixed-group DH: bytes 30/31 are INIT/REPLY. For GEX
            // the same bytes mean GEX_REQUEST_OLD/GEX_GROUP, so the backend
            // gates which path runs.
            (Phase::Negotiated { .. }, SSH_MSG_KEX_ECDH_INIT)
                if self.role == Role::Server && !backend_is_gex =>
            {
                self.handle_kex_init_message(rng, codec, payload, host_key, v_c, v_s)?
            }
            (Phase::Negotiated { .. }, SSH_MSG_KEX_ECDH_REPLY)
                if self.role == Role::Client && !backend_is_gex =>
            {
                self.handle_kex_reply_message(codec, payload, host_key_verifier, v_c, v_s)?
            }
            // GEX server: awaiting initial GEX_REQUEST (new form, byte 34) or
            // GEX_REQUEST_OLD (byte 30) in Phase::Negotiated.
            (Phase::Negotiated { .. }, SSH_MSG_KEX_DH_GEX_REQUEST)
                if self.role == Role::Server && backend_is_gex =>
            {
                self.handle_gex_request(payload)?
            }
            (Phase::Negotiated { .. }, SSH_MSG_KEX_DH_GEX_REQUEST_OLD)
                if self.role == Role::Server && backend_is_gex =>
            {
                self.handle_gex_request(payload)?
            }
            // GEX client: GEX_GROUP arrives, build and send GEX_INIT.
            (Phase::GexClientAwaitGroup { .. }, SSH_MSG_KEX_DH_GEX_GROUP) => {
                self.handle_gex_group(rng, payload)?
            }
            // GEX server: GEX_INIT arrives, agree, sign, send GEX_REPLY + NEWKEYS.
            (Phase::GexServerAwaitInit { .. }, SSH_MSG_KEX_DH_GEX_INIT) => {
                self.handle_gex_init(rng, codec, payload, host_key, v_c, v_s)?
            }
            // GEX client: GEX_REPLY arrives, verify, queue NEWKEYS.
            (Phase::GexClientAwaitReply { .. }, SSH_MSG_KEX_DH_GEX_REPLY) => {
                self.handle_gex_reply(codec, payload, host_key_verifier, v_c, v_s)?
            }
            (Phase::AwaitingPeerNewKeys, SSH_MSG_NEWKEYS) => self.handle_peer_newkeys(codec)?,
            // NEWKEYS is ONLY valid after both sides have completed the
            // algorithm-specific KEX. Accepting it earlier (during
            // Phase::Negotiated or any GEX intermediate phase) lets a
            // peer move us into the post-keys regime before the agreed
            // session_id and keys have been derived — a protocol
            // violation. RFC 4253 §7.3 places NEWKEYS strictly after the
            // KEX-method-specific exchange.
            (Phase::Negotiated { .. }, SSH_MSG_NEWKEYS)
            | (Phase::GexClientAwaitGroup { .. }, SSH_MSG_NEWKEYS)
            | (Phase::GexClientAwaitReply { .. }, SSH_MSG_NEWKEYS)
            | (Phase::GexServerAwaitInit { .. }, SSH_MSG_NEWKEYS) => {
                return Err(Error::Protocol("NEWKEYS before KEX completion"));
            }
            (_, _) => return Err(Error::Protocol("unexpected message during KEX")),
        };
        adv.completed = matches!(self.phase, Phase::Completed);
        Ok(adv)
    }

    /// The session id (exchange hash of the *first* KEX on this connection).
    /// `None` until the first KEX has completed.
    pub fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_deref()
    }

    /// The negotiated algorithms once both KEXINITs have been exchanged.
    pub fn negotiated(&self) -> Option<Negotiated> {
        self.negotiated.as_ref().map(|n| Negotiated {
            kex: n.kex.clone(),
            host_key: n.host_key.clone(),
            cipher_c2s: n.cipher_c2s.clone(),
            cipher_s2c: n.cipher_s2c.clone(),
            mac_c2s: n.mac_c2s.clone(),
            mac_s2c: n.mac_s2c.clone(),
            comp_c2s: n.comp_c2s.clone(),
            comp_s2c: n.comp_s2c.clone(),
        })
    }

    /// Derived key material from the most recent KEX completion.
    pub fn installed_keys(&self) -> Option<&InstalledKeys> {
        self.installed_keys.as_ref()
    }

    /// Set the `SSH_MSG_EXT_INFO` we'd like the runner to emit. The runner
    /// only sends it iff (a) ext-info negotiation succeeded on the first
    /// KEX AND (b) this method has been called before the runner has
    /// already produced the post-NEWKEYS outbound batch. Setting it twice
    /// replaces the previous value.
    ///
    /// Set this from the higher layer per role: the server typically wants
    /// to advertise `server-sig-algs`; the client may advertise
    /// `publickey-algorithms-in-use` or simply send an empty ext-info.
    pub fn set_outbound_ext_info(&mut self, ext: ExtInfo) {
        self.outbound_ext_info = Some(ext);
    }

    /// `true` iff RFC 8308 ext-info negotiation succeeded on the first
    /// KEX. Cleared on every rekey. The higher layer consults this when
    /// deciding whether to honour `server-sig-algs` for pubkey algorithm
    /// selection.
    pub fn ext_info_enabled(&self) -> bool {
        self.ext_info_enabled
    }

    /// Most-recent `SSH_MSG_EXT_INFO` received from the peer. The auth
    /// layer reads `server_sig_algs` from here to pick the strongest pubkey
    /// signature algorithm the server accepts.
    pub fn peer_ext_info(&self) -> Option<&ExtInfo> {
        self.peer_ext_info.as_ref()
    }

    /// `true` iff the runner is currently in a state where a
    /// `SSH_MSG_EXT_INFO` from the peer would be accepted per RFC 8308 §2.3.
    /// The higher-layer router uses this as a precondition before calling
    /// [`Self::handle_inbound_ext_info`]; any other inbound packet seen
    /// while this is true *closes* the window (see [`Self::note_inbound_other`]).
    pub fn may_accept_ext_info(&self) -> bool {
        self.accept_ext_info_now
    }

    /// Arm the ext-info acceptance window because the client just observed
    /// `SSH_MSG_USERAUTH_SUCCESS`. RFC 8308 §2.3 permits a server to send a
    /// second ext-info as the very first packet after USERAUTH_SUCCESS.
    ///
    /// Only takes effect when ext-info was negotiated. No-op on the server.
    pub fn arm_ext_info_post_auth(&mut self) {
        if self.role == Role::Client && self.ext_info_enabled {
            self.accept_ext_info_now = true;
        }
    }

    /// Parse and stash an `SSH_MSG_EXT_INFO` payload received from the peer.
    /// Closes the acceptance window and (for the client) also marks that
    /// we've consumed the post-NEWKEYS / post-USERAUTH_SUCCESS one-shot.
    ///
    /// Returns `Error::Protocol("unexpected SSH_MSG_EXT_INFO")` if the
    /// runner is not currently armed to accept one.
    pub fn handle_inbound_ext_info(&mut self, payload: &[u8]) -> Result<()> {
        if !self.accept_ext_info_now {
            return Err(Error::Protocol("unexpected SSH_MSG_EXT_INFO"));
        }
        let parsed = ExtInfo::decode(payload)?;
        self.peer_ext_info = Some(parsed);
        self.accept_ext_info_now = false;
        Ok(())
    }

    /// Tell the runner that the higher layer has just routed a non-ext-info
    /// packet through it. Closes the one-shot ext-info acceptance window
    /// without recording anything. Callers SHOULD invoke this right before
    /// dispatching the inbound packet to the auth / connection layers, on
    /// every post-NEWKEYS packet — RFC 8308 §2.3 makes ext-info a one-shot
    /// at the legal position.
    pub fn note_inbound_other(&mut self) {
        self.accept_ext_info_now = false;
    }

    fn handle_peer_kexinit<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        payload: &[u8],
        _v_c: &[u8],
        _v_s: &[u8],
    ) -> Result<KexAdvance> {
        let peer = KexInit::decode(payload)?;
        self.peer_advert_bytes = Some(payload.to_vec());

        let (client_init, server_init) = match self.role {
            Role::Client => (&self.our_advert_owned, &peer),
            Role::Server => (&peer, &self.our_advert_owned),
        };
        let neg = negotiate(client_init, server_init)?;
        self.backend = Some(KexBackend::from_name(&neg.kex)?);
        // Latch strict-kex across re-keys: once on, stays on.
        if neg.strict_kex_enabled {
            self.strict_kex = true;
        }
        // RFC 8308 §2.1: ext-info MUST be ignored on rekeys. Even if a
        // misbehaving peer advertised the marker again, we refuse.
        self.ext_info_enabled = self.first_kex && neg.ext_info_enabled;
        // Per RFC 4253 §7.1: if the peer prefixed a guess to its KEXINIT
        // and our negotiation says that guess was wrong, the next KEX
        // algorithm-specific packet from the peer must be silently dropped.
        // The peer is the one that sent the guess (`first_kex_packet_follows`
        // on their KEXINIT, not ours).
        if peer.first_kex_packet_follows && neg.first_kex_packet_follows_wrong_guess {
            self.pending_wrong_guess_discard = true;
        }
        self.negotiated = Some(neg);

        let mut outbound = Vec::new();
        let mut client_state = None;

        if self.role == Role::Client {
            let (state, init_payload) = self.build_client_init(rng)?;
            client_state = Some(state);
            outbound.push(init_payload);
        }

        // GEX deviates from the two-trip ECDH flow: the client has just
        // emitted `GEX_REQUEST` and is now waiting for `GEX_GROUP`; the
        // server has emitted nothing and is waiting for `GEX_REQUEST`.
        // Park them in the dedicated intermediate phases.
        self.phase = match (self.role, self.backend) {
            (Role::Client, Some(KexBackend::Gex)) => match client_state {
                Some(ClientStateInner::Gex(s)) => Phase::GexClientAwaitGroup { client_state: s },
                _ => return Err(Error::Protocol("GEX backend without GEX state")),
            },
            _ => Phase::Negotiated { client_state },
        };
        Ok(KexAdvance {
            outbound,
            completed: false,
        })
    }

    fn build_client_init<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientStateInner, Vec<u8>)> {
        let be = self.backend.ok_or(Error::Protocol("backend unset"))?;
        Ok(match be {
            KexBackend::Curve25519 => {
                let (s, out) = Curve25519Sha256::client_init(rng);
                (ClientStateInner::Curve(s), out.payload)
            }
            KexBackend::EcdhP256 => {
                let (s, out) = EcdhSha2Nistp256::client_init(rng);
                (ClientStateInner::Ecdh(s), out.payload)
            }
            KexBackend::EcdhP384 => {
                let (s, out) = EcdhSha2Nistp384::client_init(rng);
                (ClientStateInner::Ecdh(s), out.payload)
            }
            KexBackend::EcdhP521 => {
                let (s, out) = EcdhSha2Nistp521::client_init(rng);
                (ClientStateInner::Ecdh(s), out.payload)
            }
            KexBackend::Dh14 => {
                let (s, out) = Group14Sha256::client_init(rng);
                (ClientStateInner::Dh(s), out.payload)
            }
            KexBackend::Dh16 => {
                let (s, out) = Group16Sha512::client_init(rng);
                (ClientStateInner::Dh(s), out.payload)
            }
            KexBackend::Dh18 => {
                let (s, out) = Group18Sha512::client_init(rng);
                (ClientStateInner::Dh(s), out.payload)
            }
            KexBackend::Gex => {
                // Step 1 of the three-trip: send GEX_REQUEST with our
                // preferred prime-size range. The actual `e` value is built
                // later, after the server tells us which group it chose.
                let (s, out) = GexSha256::client_request(GexRequest::default());
                (ClientStateInner::Gex(s), out.payload)
            }
        })
    }

    fn handle_kex_init_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        codec: &mut PacketCodec,
        payload: &[u8],
        host_key: Option<&dyn HostKey>,
        v_c: &[u8],
        v_s: &[u8],
    ) -> Result<KexAdvance> {
        let hk = host_key.ok_or(Error::Protocol("server requires host key"))?;
        let backend = self.backend.ok_or(Error::Protocol("backend unset"))?;
        let i_c = self.peer_advert_bytes.as_deref().unwrap_or_default();
        let i_s = self.our_advert_bytes.clone();
        let ctx = KexContext {
            v_c,
            v_s,
            i_c,
            i_s: &i_s,
        };

        let (reply_payload, k, h) = match backend {
            KexBackend::Curve25519 => {
                let out = Curve25519Sha256::server_reply(rng, payload, hk, &ctx)?;
                (out.payload, out.kex.k, out.kex.h)
            }
            KexBackend::EcdhP256 => {
                let out = EcdhSha2Nistp256::server_reply(rng, payload, hk, &ctx)?;
                (out.payload, out.kex.k, out.kex.h)
            }
            KexBackend::EcdhP384 => {
                let out = EcdhSha2Nistp384::server_reply(rng, payload, hk, &ctx)?;
                (out.payload, out.kex.k, out.kex.h)
            }
            KexBackend::EcdhP521 => {
                let out = EcdhSha2Nistp521::server_reply(rng, payload, hk, &ctx)?;
                (out.payload, out.kex.k, out.kex.h)
            }
            KexBackend::Dh14 => {
                let out = Group14Sha256::server_reply(rng, payload, hk, &ctx)?;
                (out.payload, out.kex.k, out.kex.h)
            }
            KexBackend::Dh16 => {
                let out = Group16Sha512::server_reply(rng, payload, hk, &ctx)?;
                (out.payload, out.kex.k, out.kex.h)
            }
            KexBackend::Dh18 => {
                let out = Group18Sha512::server_reply(rng, payload, hk, &ctx)?;
                (out.payload, out.kex.k, out.kex.h)
            }
            // GEX takes a separate three-trip path via handle_gex_*; this
            // arm is unreachable thanks to the backend gate in `on_packet`.
            KexBackend::Gex => return Err(Error::Protocol("GEX routed wrong")),
        };

        self.current_k = Some(k);
        self.current_h = Some(h);
        if self.session_id.is_none() {
            self.session_id = self.current_h.clone();
        }
        self.derive_keys()?;

        let outbound = vec![reply_payload, vec![SSH_MSG_NEWKEYS]];
        self.sent_newkeys = true;
        self.maybe_install(codec)?;
        self.advance_after_send_newkeys();
        Ok(KexAdvance {
            outbound,
            completed: false,
        })
    }

    fn handle_kex_reply_message(
        &mut self,
        codec: &mut PacketCodec,
        payload: &[u8],
        verifier: Option<&dyn HostKeyVerify>,
        v_c: &[u8],
        v_s: &[u8],
    ) -> Result<KexAdvance> {
        let backend = self.backend.ok_or(Error::Protocol("backend unset"))?;
        let i_c = self.our_advert_bytes.clone();
        let i_s = self.peer_advert_bytes.clone().unwrap_or_default();
        let ctx = KexContext {
            v_c,
            v_s,
            i_c: &i_c,
            i_s: &i_s,
        };

        let state = match core::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Negotiated {
                client_state: Some(s),
            } => s,
            _ => return Err(Error::Protocol("no client state for KEX reply")),
        };

        let verifier_ref = verifier.ok_or(Error::Protocol("client requires host-key verifier"))?;

        let (k, h) = match backend {
            KexBackend::Curve25519 => {
                let st = match state {
                    ClientStateInner::Curve(s) => s,
                    _ => return Err(Error::Protocol("client state type mismatch")),
                };
                let out = Curve25519Sha256::client_finish(st, payload, verifier_ref, &ctx)?;
                (out.k, out.h)
            }
            KexBackend::EcdhP256 | KexBackend::EcdhP384 | KexBackend::EcdhP521 => {
                let st = match state {
                    ClientStateInner::Ecdh(s) => s,
                    _ => return Err(Error::Protocol("client state type mismatch")),
                };
                let out = match backend {
                    KexBackend::EcdhP256 => {
                        EcdhSha2Nistp256::client_finish(st, payload, verifier_ref, &ctx)?
                    }
                    KexBackend::EcdhP384 => {
                        EcdhSha2Nistp384::client_finish(st, payload, verifier_ref, &ctx)?
                    }
                    KexBackend::EcdhP521 => {
                        EcdhSha2Nistp521::client_finish(st, payload, verifier_ref, &ctx)?
                    }
                    _ => unreachable!(),
                };
                (out.k, out.h)
            }
            KexBackend::Dh14 | KexBackend::Dh16 | KexBackend::Dh18 => {
                let st = match state {
                    ClientStateInner::Dh(s) => s,
                    _ => return Err(Error::Protocol("client state type mismatch")),
                };
                let out = match backend {
                    KexBackend::Dh14 => {
                        Group14Sha256::client_finish(st, payload, verifier_ref, &ctx)?
                    }
                    KexBackend::Dh16 => {
                        Group16Sha512::client_finish(st, payload, verifier_ref, &ctx)?
                    }
                    KexBackend::Dh18 => {
                        Group18Sha512::client_finish(st, payload, verifier_ref, &ctx)?
                    }
                    _ => unreachable!(),
                };
                (out.k, out.h)
            }
            // GEX uses handle_gex_reply, not this path.
            KexBackend::Gex => return Err(Error::Protocol("GEX routed wrong")),
        };

        self.current_k = Some(k);
        self.current_h = Some(h);
        if self.session_id.is_none() {
            self.session_id = self.current_h.clone();
        }
        self.derive_keys()?;

        let outbound = vec![vec![SSH_MSG_NEWKEYS]];
        self.sent_newkeys = true;
        self.maybe_install(codec)?;
        self.advance_after_send_newkeys();
        Ok(KexAdvance {
            outbound,
            completed: false,
        })
    }

    /// Server side, step 2 of GEX: peer sent `GEX_REQUEST` (or the deprecated
    /// `_OLD` form). Pick a group with [`default_gex_group`], emit
    /// `GEX_GROUP`, and park in [`Phase::GexServerAwaitInit`].
    fn handle_gex_request(&mut self, payload: &[u8]) -> Result<KexAdvance> {
        let (request, group, out) = GexSha256::server_group(payload, default_gex_group)?;
        self.phase = Phase::GexServerAwaitInit { request, group };
        Ok(KexAdvance {
            outbound: vec![out.payload],
            completed: false,
        })
    }

    /// Client side, step 3 of GEX: peer sent `GEX_GROUP`. Pick `x`, emit
    /// `GEX_INIT`, and park in [`Phase::GexClientAwaitReply`].
    fn handle_gex_group<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        payload: &[u8],
    ) -> Result<KexAdvance> {
        let state = match core::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::GexClientAwaitGroup { client_state } => client_state,
            _ => return Err(Error::Protocol("GEX_GROUP without prior request")),
        };
        let (state, out) = GexSha256::client_init(state, payload, rng)?;
        self.phase = Phase::GexClientAwaitReply {
            client_state: state,
        };
        Ok(KexAdvance {
            outbound: vec![out.payload],
            completed: false,
        })
    }

    /// Server side, step 4 of GEX: peer sent `GEX_INIT`. Agree, sign, emit
    /// `GEX_REPLY` followed by `NEWKEYS`.
    fn handle_gex_init<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        codec: &mut PacketCodec,
        payload: &[u8],
        host_key: Option<&dyn HostKey>,
        v_c: &[u8],
        v_s: &[u8],
    ) -> Result<KexAdvance> {
        let hk = host_key.ok_or(Error::Protocol("server requires host key"))?;
        let (request, group) = match core::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::GexServerAwaitInit { request, group } => (request, group),
            _ => return Err(Error::Protocol("GEX_INIT without prior group")),
        };
        let i_c = self.peer_advert_bytes.as_deref().unwrap_or_default();
        let i_s = self.our_advert_bytes.clone();
        let ctx = KexContext {
            v_c,
            v_s,
            i_c,
            i_s: &i_s,
        };
        let out = GexSha256::server_reply(rng, request, &group, payload, hk, &ctx)?;

        self.current_k = Some(out.kex.k);
        self.current_h = Some(out.kex.h);
        if self.session_id.is_none() {
            self.session_id = self.current_h.clone();
        }
        self.derive_keys()?;

        let outbound = vec![out.payload, vec![SSH_MSG_NEWKEYS]];
        self.sent_newkeys = true;
        self.maybe_install(codec)?;
        self.advance_after_send_newkeys();
        Ok(KexAdvance {
            outbound,
            completed: false,
        })
    }

    /// Client side, step 5 of GEX: peer sent `GEX_REPLY`. Verify and emit
    /// `NEWKEYS`.
    fn handle_gex_reply(
        &mut self,
        codec: &mut PacketCodec,
        payload: &[u8],
        verifier: Option<&dyn HostKeyVerify>,
        v_c: &[u8],
        v_s: &[u8],
    ) -> Result<KexAdvance> {
        let verifier_ref = verifier.ok_or(Error::Protocol("client requires host-key verifier"))?;
        let state = match core::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::GexClientAwaitReply { client_state } => client_state,
            _ => return Err(Error::Protocol("GEX_REPLY without prior init")),
        };
        let i_c = self.our_advert_bytes.clone();
        let i_s = self.peer_advert_bytes.clone().unwrap_or_default();
        let ctx = KexContext {
            v_c,
            v_s,
            i_c: &i_c,
            i_s: &i_s,
        };
        let out = GexSha256::client_finish(state, payload, verifier_ref, &ctx)?;

        self.current_k = Some(out.k);
        self.current_h = Some(out.h);
        if self.session_id.is_none() {
            self.session_id = self.current_h.clone();
        }
        self.derive_keys()?;

        let outbound = vec![vec![SSH_MSG_NEWKEYS]];
        self.sent_newkeys = true;
        self.maybe_install(codec)?;
        self.advance_after_send_newkeys();
        Ok(KexAdvance {
            outbound,
            completed: false,
        })
    }

    fn advance_after_send_newkeys(&mut self) {
        if self.peer_newkeys {
            self.phase = Phase::Completed;
        } else {
            self.phase = Phase::AwaitingPeerNewKeys;
        }
    }

    fn handle_peer_newkeys(&mut self, codec: &mut PacketCodec) -> Result<KexAdvance> {
        self.peer_newkeys = true;
        self.maybe_install(codec)?;
        self.phase = Phase::Completed;

        // RFC 8308 §2.3: once the peer's NEWKEYS has landed on the first
        // KEX, the next packet from the peer MAY be `SSH_MSG_EXT_INFO`.
        // Arm a one-shot acceptance window the higher-layer router can
        // consult.
        let mut adv = KexAdvance::default();
        if self.first_kex && self.ext_info_enabled {
            self.accept_ext_info_now = true;

            // Emit our own ext-info if the caller supplied one. New keys
            // are now installed (maybe_install fired above), so the codec
            // will frame this packet under the post-NEWKEYS cipher.
            if let Some(ext) = self.outbound_ext_info.take() {
                adv.outbound.push(ext.encode());
            }
        }
        // First-kex bookkeeping: clear the flag now that the first KEX has
        // completed end-to-end. Subsequent rekeys are gated by `first_kex
        // = false` in `restart`.
        Ok(adv)
    }

    fn maybe_install(&mut self, codec: &mut PacketCodec) -> Result<()> {
        if !(self.sent_newkeys && self.peer_newkeys) {
            return Ok(());
        }
        let keys = self
            .installed_keys
            .as_ref()
            .ok_or(Error::Protocol("no derived keys"))?;
        let outbound_dir = match self.role {
            Role::Client => &keys.c2s,
            Role::Server => &keys.s2c,
        };
        let inbound_dir = match self.role {
            Role::Client => &keys.s2c,
            Role::Server => &keys.c2s,
        };

        let (out_cipher, out_mac) = build_cipher_mac(outbound_dir)?;
        codec.install_outbound(out_cipher, out_mac)?;
        let (in_cipher, in_mac) = build_cipher_mac(inbound_dir)?;
        codec.install_inbound(in_cipher, in_mac)?;

        // Wire negotiated compression. The factories return `None` only for
        // names we don't recognise — by the time we get here the negotiation
        // step already verified both sides agreed.
        let neg = self
            .negotiated
            .as_ref()
            .ok_or(Error::Protocol("missing negotiation"))?;
        let (out_comp_name, in_comp_name) = match self.role {
            Role::Client => (&neg.comp_c2s, &neg.comp_s2c),
            Role::Server => (&neg.comp_s2c, &neg.comp_c2s),
        };
        let out_comp =
            compress_by_name(out_comp_name).ok_or(Error::Unsupported("unsupported compression"))?;
        let in_comp = decompress_by_name(in_comp_name)
            .ok_or(Error::Unsupported("unsupported compression"))?;
        codec.install_outbound_compress(out_comp);
        codec.install_inbound_decompress(in_comp);

        // Strict-kex (Terrapin / CVE-2023-48795): reset both sequence
        // counters once both sides have completed NEWKEYS. The OLD-cipher
        // NEWKEYS frames have already been encoded/decoded (so their
        // sequence numbers were consumed normally); the very first packet
        // under the new cipher will be at seq = 0.
        if self.strict_kex {
            codec.reset_sequence_numbers();
        }
        Ok(())
    }

    fn derive_keys(&mut self) -> Result<()> {
        let neg = self
            .negotiated
            .as_ref()
            .ok_or(Error::Protocol("missing negotiation"))?;
        let backend = self.backend.ok_or(Error::Protocol("missing backend"))?;
        let k = self
            .current_k
            .as_deref()
            .ok_or(Error::Protocol("missing K"))?;
        let h = self
            .current_h
            .as_deref()
            .ok_or(Error::Protocol("missing H"))?;
        let sid = self
            .session_id
            .as_deref()
            .ok_or(Error::Protocol("missing session id"))?;

        let c2s = derive_for_direction(
            backend,
            k,
            h,
            sid,
            b'A',
            b'C',
            b'E',
            &neg.cipher_c2s,
            &neg.mac_c2s,
        )?;
        let s2c = derive_for_direction(
            backend,
            k,
            h,
            sid,
            b'B',
            b'D',
            b'F',
            &neg.cipher_s2c,
            &neg.mac_s2c,
        )?;

        self.installed_keys = Some(InstalledKeys { c2s, s2c });
        Ok(())
    }
}

fn build_cipher_mac(dir: &DirKeys) -> Result<(SshCipher, Option<Box<dyn SshMac + Send + Sync>>)> {
    let cipher = cipher_by_name(&dir.cipher, &dir.key, &dir.iv)
        .ok_or(Error::Unsupported("cipher name"))??;
    let mac = if dir.mac.is_empty() {
        None
    } else {
        Some(mac_by_name(&dir.mac, &dir.mac_key).ok_or(Error::Unsupported("MAC name"))?)
    };
    Ok((cipher, mac))
}

#[allow(clippy::too_many_arguments)]
fn derive_for_direction(
    backend: KexBackend,
    k: &[u8],
    h: &[u8],
    sid: &[u8],
    iv_letter: u8,
    key_letter: u8,
    mac_letter: u8,
    cipher: &str,
    mac: &str,
) -> Result<DirKeys> {
    let cipher_spec =
        crate::cipher::by_name(cipher).ok_or(Error::Unsupported("cipher in negotiation"))?;

    let iv = kdf(backend, k, h, sid, iv_letter, cipher_spec.iv_len);
    let key = kdf(backend, k, h, sid, key_letter, cipher_spec.key_len);

    let (mac_name, mac_key) = if cipher_spec.aead {
        (String::new(), Vec::new())
    } else {
        let mac_spec = crate::mac::by_name(mac).ok_or(Error::Unsupported("MAC in negotiation"))?;
        let mk = kdf(backend, k, h, sid, mac_letter, mac_spec.key_len);
        (mac.to_string(), mk)
    };

    Ok(DirKeys {
        cipher: cipher.to_string(),
        iv,
        key,
        mac: mac_name,
        mac_key,
    })
}

fn kdf(backend: KexBackend, k: &[u8], h: &[u8], sid: &[u8], letter: u8, n: usize) -> Vec<u8> {
    match backend {
        KexBackend::Curve25519 | KexBackend::EcdhP256 | KexBackend::Dh14 | KexBackend::Gex => {
            derive_with::<Sha256>(k, h, sid, letter, n)
        }
        KexBackend::EcdhP384 => derive_with::<Sha384>(k, h, sid, letter, n),
        KexBackend::EcdhP521 | KexBackend::Dh16 | KexBackend::Dh18 => {
            derive_with::<Sha512>(k, h, sid, letter, n)
        }
    }
}

fn derive_with<D: Digest>(k: &[u8], h: &[u8], sid: &[u8], letter: u8, n: usize) -> Vec<u8> {
    crate::kex::derive::<D>(k, h, sid, letter, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::Ed25519HostKey;
    use crate::transport::kex::{defaults, KexAlgorithms};
    use crate::transport::version::LOCAL_VERSION;
    use purecrypto::rng::OsRng;

    #[test]
    fn default_gex_group_honours_client_min_floor() {
        // min > 4096: must get group18 (8192-bit), regardless of n/max.
        let req = GexRequest {
            min: 5000,
            n: 5000,
            max: 8192,
        };
        assert_eq!(default_gex_group(req).bit_size(), 8192);

        // min > 2048: at least 4096-bit. n=4096 -> group16.
        let req = GexRequest {
            min: 3000,
            n: 4096,
            max: 8192,
        };
        assert_eq!(default_gex_group(req).bit_size(), 4096);

        // min > 2048, n > 4096 -> group18.
        let req = GexRequest {
            min: 3000,
            n: 6000,
            max: 8192,
        };
        assert_eq!(default_gex_group(req).bit_size(), 8192);

        // Standard request -> group14 / group16 per `n` (legacy behaviour).
        let req = GexRequest {
            min: 1024,
            n: 2048,
            max: 8192,
        };
        assert_eq!(default_gex_group(req).bit_size(), 2048);

        // max caps the n-based pick downward.
        let req = GexRequest {
            min: 1024,
            n: 8192,
            max: 4096,
        };
        assert_eq!(default_gex_group(req).bit_size(), 4096);
    }

    #[test]
    fn every_default_kex_algorithm_maps_to_backend() {
        for &name in defaults::KEX {
            // Strict-kex markers are signalling-only and don't map to a
            // KEX algorithm — skip them.
            if crate::transport::kex::is_strict_kex_marker(name) {
                continue;
            }
            KexBackend::from_name(name).expect(name);
        }
    }

    fn make_advert(cipher: &'static str, mac: &'static str) -> KexInit {
        make_advert_with_comp(cipher, mac, defaults::COMP)
    }

    fn make_advert_with_comp(
        cipher: &'static str,
        mac: &'static str,
        comp: &'static [&'static str],
    ) -> KexInit {
        let kex_only: [&str; 1] = ["curve25519-sha256"];
        let hk_only: [&str; 1] = ["ssh-ed25519"];
        let ciphers: [&str; 1] = [cipher];
        let macs: [&str; 1] = [mac];
        let algs = KexAlgorithms {
            kex: &kex_only,
            server_host_key: &hk_only,
            ciphers_c2s: &ciphers,
            ciphers_s2c: &ciphers,
            macs_c2s: &macs,
            macs_s2c: &macs,
            comp_c2s: comp,
            comp_s2c: comp,
            lang_c2s: &[],
            lang_s2c: &[],
        };
        let mut cookie = [0u8; 16];
        OsRng.fill_bytes(&mut cookie);
        KexInit::from_algorithms(&algs, cookie)
    }

    fn run_loopback(cipher: &'static str, mac: &'static str) {
        let mut rng = OsRng;

        // Host key shared across both ends — the server signs, the client
        // verifies against the same public bytes.
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();

        let mut client = KexRunner::new(Role::Client, make_advert(cipher, mac));
        let mut server = KexRunner::new(Role::Server, make_advert(cipher, mac));
        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;

        let mut steps = 0;
        while !(matches!(client.phase, Phase::Completed)
            && matches!(server.phase, Phase::Completed))
        {
            steps += 1;
            assert!(steps < 16, "handshake did not converge in time");

            let mut next_from_client = Vec::new();
            for p in from_server.drain(..) {
                let adv = client
                    .on_packet(
                        &mut rng,
                        &mut client_codec,
                        &p,
                        None,
                        Some(&client_verifier),
                        v_c,
                        v_s,
                    )
                    .unwrap();
                next_from_client.extend(adv.outbound);
            }
            let mut next_from_server = Vec::new();
            for p in from_client.drain(..) {
                let adv = server
                    .on_packet(
                        &mut rng,
                        &mut server_codec,
                        &p,
                        Some(&server_hk),
                        None,
                        v_c,
                        v_s,
                    )
                    .unwrap();
                next_from_server.extend(adv.outbound);
            }
            from_client = next_from_client;
            from_server = next_from_server;
            if from_client.is_empty() && from_server.is_empty() {
                break;
            }
        }

        assert!(matches!(client.phase, Phase::Completed));
        assert!(matches!(server.phase, Phase::Completed));
        assert_eq!(client.session_id().unwrap(), server.session_id().unwrap());

        // Encrypt/decrypt across the now-installed codecs in both directions.
        let payload_c2s = b"hello, server (from client)";
        let frame = client_codec.encode(payload_c2s, &mut rng).unwrap();
        let (got, n) = server_codec.decode(&frame).unwrap().expect("frame");
        assert_eq!(n, frame.len());
        assert_eq!(got, payload_c2s);

        let payload_s2c = b"greetings, client (from server)";
        let frame = server_codec.encode(payload_s2c, &mut rng).unwrap();
        let (got, n) = client_codec.decode(&frame).unwrap().expect("frame");
        assert_eq!(n, frame.len());
        assert_eq!(got, payload_s2c);
    }

    #[test]
    fn loopback_curve25519_aes256_ctr_etm() {
        run_loopback("aes256-ctr", "hmac-sha2-256-etm@openssh.com");
    }

    #[test]
    fn loopback_curve25519_chachapoly() {
        run_loopback("chacha20-poly1305@openssh.com", "hmac-sha2-256");
    }

    fn make_advert_with_kex(kex: &'static str, cipher: &'static str, mac: &'static str) -> KexInit {
        let kex_only: [&str; 1] = [kex];
        let hk_only: [&str; 1] = ["ssh-ed25519"];
        let ciphers: [&str; 1] = [cipher];
        let macs: [&str; 1] = [mac];
        let algs = KexAlgorithms {
            kex: &kex_only,
            server_host_key: &hk_only,
            ciphers_c2s: &ciphers,
            ciphers_s2c: &ciphers,
            macs_c2s: &macs,
            macs_s2c: &macs,
            comp_c2s: defaults::COMP,
            comp_s2c: defaults::COMP,
            lang_c2s: &[],
            lang_s2c: &[],
        };
        let mut cookie = [0u8; 16];
        OsRng.fill_bytes(&mut cookie);
        KexInit::from_algorithms(&algs, cookie)
    }

    #[test]
    fn loopback_gex_chachapoly() {
        let mut rng = OsRng;

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let kex = "diffie-hellman-group-exchange-sha256";
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        let mut client = KexRunner::new(Role::Client, make_advert_with_kex(kex, cipher, mac));
        let mut server = KexRunner::new(Role::Server, make_advert_with_kex(kex, cipher, mac));
        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;

        // GEX has an extra round trip (REQUEST/GROUP/INIT/REPLY) compared to
        // ECDH — give the loop more headroom.
        let mut steps = 0;
        while !(matches!(client.phase, Phase::Completed)
            && matches!(server.phase, Phase::Completed))
        {
            steps += 1;
            assert!(steps < 24, "GEX handshake did not converge");
            let mut next_from_client = Vec::new();
            for p in from_server.drain(..) {
                let adv = client
                    .on_packet(
                        &mut rng,
                        &mut client_codec,
                        &p,
                        None,
                        Some(&client_verifier),
                        v_c,
                        v_s,
                    )
                    .unwrap();
                next_from_client.extend(adv.outbound);
            }
            let mut next_from_server = Vec::new();
            for p in from_client.drain(..) {
                let adv = server
                    .on_packet(
                        &mut rng,
                        &mut server_codec,
                        &p,
                        Some(&server_hk),
                        None,
                        v_c,
                        v_s,
                    )
                    .unwrap();
                next_from_server.extend(adv.outbound);
            }
            from_client = next_from_client;
            from_server = next_from_server;
            if from_client.is_empty() && from_server.is_empty() {
                break;
            }
        }

        assert!(matches!(client.phase, Phase::Completed));
        assert!(matches!(server.phase, Phase::Completed));
        assert_eq!(client.session_id().unwrap(), server.session_id().unwrap());

        // Data plane works after a GEX-derived key install.
        let frame = client_codec.encode(b"gex c2s", &mut rng).unwrap();
        let (got, _) = server_codec.decode(&frame).unwrap().expect("c2s");
        assert_eq!(got, b"gex c2s");
        let frame = server_codec.encode(b"gex s2c", &mut rng).unwrap();
        let (got, _) = client_codec.decode(&frame).unwrap().expect("s2c");
        assert_eq!(got, b"gex s2c");
    }

    #[cfg(feature = "compress")]
    #[test]
    fn loopback_negotiates_zlib_then_round_trips_compressed() {
        let mut rng = OsRng;

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        static ZLIB_ONLY: &[&str] = &["zlib"];
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        let mut client =
            KexRunner::new(Role::Client, make_advert_with_comp(cipher, mac, ZLIB_ONLY));
        let mut server =
            KexRunner::new(Role::Server, make_advert_with_comp(cipher, mac, ZLIB_ONLY));
        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;

        let mut steps = 0;
        while !(matches!(client.phase, Phase::Completed)
            && matches!(server.phase, Phase::Completed))
        {
            steps += 1;
            assert!(steps < 16, "handshake did not converge");
            let mut next_from_client = Vec::new();
            for p in from_server.drain(..) {
                let adv = client
                    .on_packet(
                        &mut rng,
                        &mut client_codec,
                        &p,
                        None,
                        Some(&client_verifier),
                        v_c,
                        v_s,
                    )
                    .unwrap();
                next_from_client.extend(adv.outbound);
            }
            let mut next_from_server = Vec::new();
            for p in from_client.drain(..) {
                let adv = server
                    .on_packet(
                        &mut rng,
                        &mut server_codec,
                        &p,
                        Some(&server_hk),
                        None,
                        v_c,
                        v_s,
                    )
                    .unwrap();
                next_from_server.extend(adv.outbound);
            }
            from_client = next_from_client;
            from_server = next_from_server;
            if from_client.is_empty() && from_server.is_empty() {
                break;
            }
        }

        // Both codecs should have "zlib" installed — verify via the
        // accessor and then check that a highly-compressible payload comes
        // out smaller than it went in.
        assert_eq!(client_codec.outbound_compress_name(), "zlib");
        assert_eq!(server_codec.inbound_decompress_name(), "zlib");

        let payload = vec![b'z'; 4096];
        let frame = client_codec.encode(&payload, &mut rng).unwrap();
        assert!(
            frame.len() < payload.len(),
            "zlib must have shrunk frame; got {} vs {}",
            frame.len(),
            payload.len()
        );
        let (got, n) = server_codec.decode(&frame).unwrap().expect("decoded");
        assert_eq!(n, frame.len());
        assert_eq!(got, payload);
    }

    #[allow(clippy::too_many_arguments)]
    fn drive_to_completion(
        client: &mut KexRunner,
        server: &mut KexRunner,
        client_codec: &mut PacketCodec,
        server_codec: &mut PacketCodec,
        client_verifier: &dyn HostKeyVerify,
        server_hk: &dyn HostKey,
        from_client: &mut Vec<Vec<u8>>,
        from_server: &mut Vec<Vec<u8>>,
        v_c: &[u8],
        v_s: &[u8],
    ) {
        let mut rng = OsRng;
        let mut steps = 0;
        while !(client.is_completed() && server.is_completed()) {
            steps += 1;
            assert!(steps < 24, "handshake did not converge");
            let mut next_from_client = Vec::new();
            for p in from_server.drain(..) {
                let adv = client
                    .on_packet(
                        &mut rng,
                        client_codec,
                        &p,
                        None,
                        Some(client_verifier),
                        v_c,
                        v_s,
                    )
                    .unwrap();
                next_from_client.extend(adv.outbound);
            }
            let mut next_from_server = Vec::new();
            for p in from_client.drain(..) {
                let adv = server
                    .on_packet(&mut rng, server_codec, &p, Some(server_hk), None, v_c, v_s)
                    .unwrap();
                next_from_server.extend(adv.outbound);
            }
            *from_client = next_from_client;
            *from_server = next_from_server;
            if from_client.is_empty() && from_server.is_empty() {
                break;
            }
        }
    }

    fn make_advert_with_kex_list(
        kex: &'static [&'static str],
        cipher: &'static str,
        mac: &'static str,
    ) -> KexInit {
        let hk_only: [&str; 1] = ["ssh-ed25519"];
        let ciphers: [&str; 1] = [cipher];
        let macs: [&str; 1] = [mac];
        let algs = KexAlgorithms {
            kex,
            server_host_key: &hk_only,
            ciphers_c2s: &ciphers,
            ciphers_s2c: &ciphers,
            macs_c2s: &macs,
            macs_s2c: &macs,
            comp_c2s: defaults::COMP,
            comp_s2c: defaults::COMP,
            lang_c2s: &[],
            lang_s2c: &[],
        };
        let mut cookie = [0u8; 16];
        OsRng.fill_bytes(&mut cookie);
        KexInit::from_algorithms(&algs, cookie)
    }

    #[test]
    fn strict_kex_default_advertised_and_resets_sequence_counters() {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        // Use the full default KEX list — strict-kex markers are in there.
        let mut client = KexRunner::new(
            Role::Client,
            make_advert_with_kex_list(defaults::KEX, cipher, mac),
        );
        let mut server = KexRunner::new(
            Role::Server,
            make_advert_with_kex_list(defaults::KEX, cipher, mac),
        );
        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        // Pre-poison the sequence counters: if strict-kex resets, they'll
        // be 0 after install. Otherwise they'd continue from these values.
        client_codec.seq_in = 7;
        client_codec.seq_out = 11;
        server_codec.seq_in = 11;
        server_codec.seq_out = 7;

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;
        drive_to_completion(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );

        assert!(client.strict_kex_enabled());
        assert!(server.strict_kex_enabled());
        // Both sides must have reset the sequence counters at install.
        assert_eq!(client_codec.seq_in, 0);
        assert_eq!(client_codec.seq_out, 0);
        assert_eq!(server_codec.seq_in, 0);
        assert_eq!(server_codec.seq_out, 0);

        // Data plane still works after the reset.
        let frame = client_codec.encode(b"strict-kex c2s", &mut rng).unwrap();
        let (got, _) = server_codec.decode(&frame).unwrap().expect("c2s");
        assert_eq!(got, b"strict-kex c2s");
    }

    #[test]
    fn newkeys_before_kex_completion_is_rejected() {
        // F2: NEWKEYS arriving in Phase::Negotiated must error, not be
        // silently latched. Drive client through start + KEXINIT but then
        // feed it a NEWKEYS before the ECDH_REPLY.
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        let mut client = KexRunner::new(Role::Client, make_advert(cipher, mac));
        let server_advert = make_advert(cipher, mac);
        let mut client_codec = PacketCodec::new();

        let _ = client.start(&mut rng).unwrap();
        // Feed the server's KEXINIT to the client.
        client
            .on_packet(
                &mut rng,
                &mut client_codec,
                &server_advert.encode(),
                None,
                Some(&client_verifier),
                v_c,
                v_s,
            )
            .unwrap();
        // Now client is in Phase::Negotiated. Inject a stray NEWKEYS.
        let res = client.on_packet(
            &mut rng,
            &mut client_codec,
            &[SSH_MSG_NEWKEYS],
            None,
            Some(&client_verifier),
            v_c,
            v_s,
        );
        match res {
            Err(Error::Protocol(msg)) => {
                assert_eq!(msg, "NEWKEYS before KEX completion");
            }
            other => panic!("expected Protocol(NEWKEYS before KEX completion), got {other:?}"),
        }
        // Server is unused — silence the warning.
        let _ = &server_hk;
    }

    #[test]
    fn restart_preserves_session_id_and_rotates_keys() {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        let mut client = KexRunner::new(Role::Client, make_advert(cipher, mac));
        let mut server = KexRunner::new(Role::Server, make_advert(cipher, mac));
        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;
        drive_to_completion(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );

        let sid_initial = client.session_id().unwrap().to_vec();
        let keys_initial_c2s = client.installed_keys().unwrap().c2s.key.clone();
        assert_eq!(sid_initial, server.session_id().unwrap());

        // Re-key — both sides restart, then drive the second handshake.
        let mut from_client: Vec<Vec<u8>> = client
            .restart(&mut rng, make_advert(cipher, mac))
            .unwrap()
            .outbound;
        let mut from_server: Vec<Vec<u8>> = server
            .restart(&mut rng, make_advert(cipher, mac))
            .unwrap()
            .outbound;
        drive_to_completion(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );

        // RFC 4253 §7.2: session id (H of FIRST kex) is unchanged.
        assert_eq!(client.session_id().unwrap(), sid_initial.as_slice());
        assert_eq!(server.session_id().unwrap(), sid_initial.as_slice());
        // New keys rotated.
        assert_ne!(client.installed_keys().unwrap().c2s.key, keys_initial_c2s);

        // Codec still works with the new keys.
        let frame = client_codec.encode(b"after rekey", &mut rng).unwrap();
        let (got, _) = server_codec.decode(&frame).unwrap().expect("rekeyed frame");
        assert_eq!(got, b"after rekey");
    }

    fn make_advert_ext_info(cipher: &'static str, mac: &'static str, role: Role) -> KexInit {
        make_advert(cipher, mac).with_ext_info_marker(role)
    }

    /// Like [`drive_to_completion`] but ext-info-aware: msg-type 7 packets
    /// are routed to `handle_inbound_ext_info` instead of `on_packet`.
    #[allow(clippy::too_many_arguments)]
    fn drive_to_completion_ext_aware(
        client: &mut KexRunner,
        server: &mut KexRunner,
        client_codec: &mut PacketCodec,
        server_codec: &mut PacketCodec,
        client_verifier: &dyn HostKeyVerify,
        server_hk: &dyn HostKey,
        from_client: &mut Vec<Vec<u8>>,
        from_server: &mut Vec<Vec<u8>>,
        v_c: &[u8],
        v_s: &[u8],
    ) {
        use crate::transport::ext_info::SSH_MSG_EXT_INFO;
        let mut rng = OsRng;
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 24, "handshake did not converge");
            let mut next_from_client = Vec::new();
            for p in from_server.drain(..) {
                if p.first() == Some(&SSH_MSG_EXT_INFO) {
                    client.handle_inbound_ext_info(&p).unwrap();
                } else {
                    let adv = client
                        .on_packet(
                            &mut rng,
                            client_codec,
                            &p,
                            None,
                            Some(client_verifier),
                            v_c,
                            v_s,
                        )
                        .unwrap();
                    next_from_client.extend(adv.outbound);
                }
            }
            let mut next_from_server = Vec::new();
            for p in from_client.drain(..) {
                if p.first() == Some(&SSH_MSG_EXT_INFO) {
                    server.handle_inbound_ext_info(&p).unwrap();
                } else {
                    let adv = server
                        .on_packet(&mut rng, server_codec, &p, Some(server_hk), None, v_c, v_s)
                        .unwrap();
                    next_from_server.extend(adv.outbound);
                }
            }
            *from_client = next_from_client;
            *from_server = next_from_server;
            if from_client.is_empty() && from_server.is_empty() {
                break;
            }
        }
    }

    #[test]
    fn ext_info_round_trips_after_first_kex_when_negotiated() {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        let mut client = KexRunner::new(
            Role::Client,
            make_advert_ext_info(cipher, mac, Role::Client),
        );
        let mut server = KexRunner::new(
            Role::Server,
            make_advert_ext_info(cipher, mac, Role::Server),
        );

        // Server stashes the ext-info it wants to send (server-sig-algs).
        server.set_outbound_ext_info(
            ExtInfo::new().with_server_sig_algs("rsa-sha2-512,rsa-sha2-256,ssh-ed25519"),
        );
        // Client likewise advertises its pubkey algorithms.
        client.set_outbound_ext_info(
            ExtInfo::new().with_publickey_algorithms_in_use("ssh-ed25519,rsa-sha2-512"),
        );

        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;
        drive_to_completion_ext_aware(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );

        // Both sides negotiated ext-info.
        assert!(client.ext_info_enabled());
        assert!(server.ext_info_enabled());

        // Ext-info delivered both ways by the drive helper.
        let client_view = client.peer_ext_info().expect("client got peer ext-info");
        assert_eq!(
            client_view.server_sig_algs.as_deref(),
            Some("rsa-sha2-512,rsa-sha2-256,ssh-ed25519"),
        );
        let server_view = server.peer_ext_info().expect("server got peer ext-info");
        assert_eq!(
            server_view.publickey_algorithms_in_use.as_deref(),
            Some("ssh-ed25519,rsa-sha2-512"),
        );

        // The one-shot window is closed on both sides.
        assert!(!client.may_accept_ext_info());
        assert!(!server.may_accept_ext_info());
    }

    #[test]
    fn ext_info_not_emitted_when_peer_did_not_advertise_marker() {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        // Server advertises the marker; client does not. The runner must
        // refuse to emit ext-info even though the server has one queued.
        let mut client = KexRunner::new(Role::Client, make_advert(cipher, mac));
        let mut server = KexRunner::new(
            Role::Server,
            make_advert_ext_info(cipher, mac, Role::Server),
        );
        server.set_outbound_ext_info(ExtInfo::new().with_server_sig_algs("rsa-sha2-512"));

        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;
        drive_to_completion(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );

        assert!(!server.ext_info_enabled());
        assert!(!client.ext_info_enabled());
        // No EXT_INFO payloads should be in flight on either direction.
        assert!(from_client.is_empty());
        assert!(from_server.is_empty());
        assert!(!client.may_accept_ext_info());
        assert!(!server.may_accept_ext_info());
    }

    #[test]
    fn ext_info_inbound_before_newkeys_is_rejected() {
        // The runner is `Idle` (start hasn't been called). Feeding it an
        // ext-info via `handle_inbound_ext_info` must error.
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";
        let mut client = KexRunner::new(
            Role::Client,
            make_advert_ext_info(cipher, mac, Role::Client),
        );
        let ext_bytes = ExtInfo::new().with_server_sig_algs("ssh-ed25519").encode();
        let err = client.handle_inbound_ext_info(&ext_bytes).unwrap_err();
        match err {
            Error::Protocol(m) => assert_eq!(m, "unexpected SSH_MSG_EXT_INFO"),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn second_ext_info_after_first_is_rejected() {
        // Drive a normal KEX with ext-info negotiated. After the first
        // ext-info is consumed, a second one must be refused — the
        // window is one-shot until `arm_ext_info_post_auth` re-arms it.
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        let mut client = KexRunner::new(
            Role::Client,
            make_advert_ext_info(cipher, mac, Role::Client),
        );
        let mut server = KexRunner::new(
            Role::Server,
            make_advert_ext_info(cipher, mac, Role::Server),
        );
        server.set_outbound_ext_info(ExtInfo::new().with_server_sig_algs("rsa-sha2-512"));

        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;
        drive_to_completion(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );

        // Consume the server's ext-info.
        let first = from_server.remove(0);
        client.handle_inbound_ext_info(&first).unwrap();
        assert!(!client.may_accept_ext_info());

        // Feed a second ext-info directly — must be refused.
        let second = ExtInfo::new().with_server_sig_algs("rsa-sha2-256").encode();
        let err = client.handle_inbound_ext_info(&second).unwrap_err();
        match err {
            Error::Protocol(m) => assert_eq!(m, "unexpected SSH_MSG_EXT_INFO"),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn arm_ext_info_post_auth_re_opens_window_on_client_only() {
        // After USERAUTH_SUCCESS the client may receive a second ext-info.
        // The server has no equivalent re-arm; calling the same method on a
        // server runner is a no-op.
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        let mut client = KexRunner::new(
            Role::Client,
            make_advert_ext_info(cipher, mac, Role::Client),
        );
        let mut server = KexRunner::new(
            Role::Server,
            make_advert_ext_info(cipher, mac, Role::Server),
        );
        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;
        drive_to_completion(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );

        // First-KEX window is open on both sides because ext-info was
        // negotiated. The higher layer normally drains it by routing the
        // peer's ext-info (or by noting some other packet); simulate that
        // closure here.
        assert!(client.may_accept_ext_info());
        assert!(server.may_accept_ext_info());
        client.note_inbound_other();
        server.note_inbound_other();
        assert!(!client.may_accept_ext_info());
        assert!(!server.may_accept_ext_info());

        // Now the client observes USERAUTH_SUCCESS — the window re-opens
        // exactly once.
        client.arm_ext_info_post_auth();
        assert!(client.may_accept_ext_info());

        // Server: no re-arm.
        server.arm_ext_info_post_auth();
        assert!(!server.may_accept_ext_info());
    }

    #[test]
    fn rekey_does_not_advertise_or_accept_ext_info() {
        // After the first KEX completes, restart() must reset first_kex
        // and ext_info_enabled to false, so a rekey advert does not carry
        // the marker and a peer ext-info post-rekey is rejected.
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let v_c = LOCAL_VERSION.as_bytes();
        let v_s = LOCAL_VERSION.as_bytes();
        let cipher = "chacha20-poly1305@openssh.com";
        let mac = "hmac-sha2-256";

        let mut client = KexRunner::new(
            Role::Client,
            make_advert_ext_info(cipher, mac, Role::Client),
        );
        let mut server = KexRunner::new(
            Role::Server,
            make_advert_ext_info(cipher, mac, Role::Server),
        );
        let mut client_codec = PacketCodec::new();
        let mut server_codec = PacketCodec::new();

        let mut from_client: Vec<Vec<u8>> = client.start(&mut rng).unwrap().outbound;
        let mut from_server: Vec<Vec<u8>> = server.start(&mut rng).unwrap().outbound;
        drive_to_completion(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );
        assert!(client.ext_info_enabled());
        assert!(server.ext_info_enabled());

        // Rekey — advert MUST NOT carry the ext-info marker even if a
        // caller mistakenly re-applied `with_ext_info_marker`. The runner
        // strips/ignores it via `first_kex = false` && `ext_info_enabled = false`.
        let rekey_client_advert = make_advert_ext_info(cipher, mac, Role::Client);
        let rekey_server_advert = make_advert_ext_info(cipher, mac, Role::Server);
        let mut from_client: Vec<Vec<u8>> = client
            .restart(&mut rng, rekey_client_advert)
            .unwrap()
            .outbound;
        let mut from_server: Vec<Vec<u8>> = server
            .restart(&mut rng, rekey_server_advert)
            .unwrap()
            .outbound;
        drive_to_completion(
            &mut client,
            &mut server,
            &mut client_codec,
            &mut server_codec,
            &client_verifier,
            &server_hk,
            &mut from_client,
            &mut from_server,
            v_c,
            v_s,
        );

        // Rekey: ext-info MUST be disabled on both sides.
        assert!(!client.ext_info_enabled());
        assert!(!server.ext_info_enabled());
        assert!(!client.may_accept_ext_info());
        assert!(!server.may_accept_ext_info());

        // Even if the peer sends ext-info post-rekey, the runner rejects.
        let stray = ExtInfo::new().with_server_sig_algs("ssh-ed25519").encode();
        assert!(matches!(
            client.handle_inbound_ext_info(&stray),
            Err(Error::Protocol(_))
        ));
    }
}
