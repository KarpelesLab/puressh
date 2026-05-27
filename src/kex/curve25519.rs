//! `curve25519-sha256` (RFC 8731) — X25519 ECDH with SHA-256.
//!
//! Also serves the legacy alias `curve25519-sha256@libssh.org`, which is the
//! same algorithm: the two names exist only because the libssh.org variant
//! pre-dated the IETF assignment.

use alloc::vec::Vec;

use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::hash::Sha256;
use purecrypto::rng::{CryptoRng, RngCore};

use super::common::{KexContext, KexInitOut, KexOutput, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY};
use super::hash::{ExchangeHash, mpint_bytes};
use super::Kex;
use crate::error::{Error, Result};
use crate::format::Reader;
use crate::hostkey::HostKeyVerify;

/// Marker type implementing the `curve25519-sha256` KEX.
pub struct Curve25519Sha256;

impl Kex for Curve25519Sha256 {
    const NAME: &'static str = "curve25519-sha256";
    const HASH_LEN: usize = 32;
}

impl Curve25519Sha256 {
    /// Algorithm name (`curve25519-sha256`).
    pub const NAME: &'static str = <Self as Kex>::NAME;
    /// Legacy libssh.org alias for the same algorithm.
    pub const NAME_LIBSSH: &'static str = "curve25519-sha256@libssh.org";
    /// Exchange-hash output length (SHA-256 = 32 bytes).
    pub const HASH_LEN: usize = <Self as Kex>::HASH_LEN;
}

/// Client-side state retained between sending `KEX_ECDH_INIT` and receiving
/// the matching `KEX_ECDH_REPLY`.
pub struct ClientState {
    secret: X25519PrivateKey,
    q_c: [u8; 32],
}

/// Server-side output of `server_reply`: the wire payload to send and the
/// already-computed `(K, H)` pair.
pub struct ServerReplyOut {
    /// `SSH_MSG_KEX_ECDH_REPLY` payload (message-type byte included).
    pub payload: Vec<u8>,
    /// The shared secret + exchange hash, ready for the KDF.
    pub kex: KexOutput,
}

impl Curve25519Sha256 {
    /// Generate the client's ephemeral key and produce the
    /// `SSH_MSG_KEX_ECDH_INIT` payload.
    pub fn client_init<R: RngCore + CryptoRng>(rng: &mut R) -> (ClientState, KexInitOut) {
        let secret = X25519PrivateKey::generate(rng);
        let q_c = secret.public_key();
        let mut payload = Vec::with_capacity(1 + 4 + 32);
        payload.push(SSH_MSG_KEX_ECDH_INIT);
        payload.extend_from_slice(&(32u32).to_be_bytes());
        payload.extend_from_slice(&q_c);
        (ClientState { secret, q_c }, KexInitOut { payload })
    }

    /// Parse a client `SSH_MSG_KEX_ECDH_INIT`, run scalar mult against the
    /// fresh server ephemeral, sign the resulting exchange hash with the
    /// host key, and assemble the `SSH_MSG_KEX_ECDH_REPLY` payload.
    pub fn server_reply<R, S>(
        rng: &mut R,
        init_payload: &[u8],
        host_key: &S,
        ctx: &KexContext<'_>,
    ) -> Result<ServerReplyOut>
    where
        R: RngCore + CryptoRng,
        S: crate::hostkey::HostKey + ?Sized,
    {
        let mut r = Reader::new(init_payload);
        let msg = r.read_u8()?;
        if msg != SSH_MSG_KEX_ECDH_INIT {
            return Err(Error::Protocol("expected SSH_MSG_KEX_ECDH_INIT"));
        }
        let q_c_bytes = r.read_string()?;
        if q_c_bytes.len() != 32 {
            return Err(Error::Format("X25519 Q_C must be 32 bytes"));
        }
        let mut q_c = [0u8; 32];
        q_c.copy_from_slice(q_c_bytes);

        let secret = X25519PrivateKey::generate(rng);
        let q_s = secret.public_key();
        let k_raw = secret
            .diffie_hellman(&q_c)
            .map_err(|_| Error::Crypto("X25519 small-order peer"))?;

        let k_s = host_key.public_blob();

        let mut eh = ExchangeHash::<Sha256>::new();
        eh.write_string(ctx.v_c);
        eh.write_string(ctx.v_s);
        eh.write_string(ctx.i_c);
        eh.write_string(ctx.i_s);
        eh.write_string(&k_s);
        eh.write_string(&q_c);
        eh.write_string(&q_s);
        eh.write_mpint(&k_raw);
        let h = eh.finalize();

        let sig = host_key.sign(&h)?;

        let mut payload = Vec::with_capacity(1 + 4 + k_s.len() + 4 + 32 + 4 + sig.len());
        payload.push(SSH_MSG_KEX_ECDH_REPLY);
        payload.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
        payload.extend_from_slice(&k_s);
        payload.extend_from_slice(&(32u32).to_be_bytes());
        payload.extend_from_slice(&q_s);
        payload.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        payload.extend_from_slice(&sig);

        let k = mpint_bytes(&k_raw);
        Ok(ServerReplyOut {
            payload,
            kex: KexOutput { k, h },
        })
    }

    /// Parse the server's `SSH_MSG_KEX_ECDH_REPLY`, verify the host-key
    /// signature on `H`, and return `(K, H)`.
    pub fn client_finish(
        state: ClientState,
        reply_payload: &[u8],
        verifier: &dyn HostKeyVerify,
        ctx: &KexContext<'_>,
    ) -> Result<KexOutput> {
        let mut r = Reader::new(reply_payload);
        let msg = r.read_u8()?;
        if msg != SSH_MSG_KEX_ECDH_REPLY {
            return Err(Error::Protocol("expected SSH_MSG_KEX_ECDH_REPLY"));
        }
        let k_s = r.read_string()?;
        let q_s_bytes = r.read_string()?;
        if q_s_bytes.len() != 32 {
            return Err(Error::Format("X25519 Q_S must be 32 bytes"));
        }
        let mut q_s = [0u8; 32];
        q_s.copy_from_slice(q_s_bytes);
        let sig = r.read_string()?;

        let k_raw = state
            .secret
            .diffie_hellman(&q_s)
            .map_err(|_| Error::Crypto("X25519 small-order peer"))?;

        let mut eh = ExchangeHash::<Sha256>::new();
        eh.write_string(ctx.v_c);
        eh.write_string(ctx.v_s);
        eh.write_string(ctx.i_c);
        eh.write_string(ctx.i_s);
        eh.write_string(k_s);
        eh.write_string(&state.q_c);
        eh.write_string(&q_s);
        eh.write_mpint(&k_raw);
        let h = eh.finalize();

        verifier.verify(&h, sig)?;

        let k = mpint_bytes(&k_raw);
        Ok(KexOutput { k, h })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::hash::Sha256;
    use purecrypto::rng::HmacDrbg;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc7748_test_vector_1() {
        // RFC 7748 §5.2 — first X25519 test vector.
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let want = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let sk = X25519PrivateKey::from_bytes(scalar);
        let got = sk.diffie_hellman(&u).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn algorithm_names() {
        assert_eq!(Curve25519Sha256::NAME, "curve25519-sha256");
        assert_eq!(
            Curve25519Sha256::NAME_LIBSSH,
            "curve25519-sha256@libssh.org"
        );
        assert_eq!(Curve25519Sha256::HASH_LEN, 32);
    }

    #[test]
    fn init_payload_layout() {
        let mut rng = HmacDrbg::<Sha256>::new(b"kex-init", b"nonce", &[]);
        let (state, init) = Curve25519Sha256::client_init(&mut rng);
        assert_eq!(init.payload.len(), 1 + 4 + 32);
        assert_eq!(init.payload[0], 30);
        assert_eq!(&init.payload[1..5], &[0, 0, 0, 32]);
        assert_eq!(&init.payload[5..], &state.q_c[..]);
    }
}
