//! `mlkem768x25519-sha256` — hybrid post-quantum key exchange combining
//! ML-KEM-768 (FIPS 203) with X25519, hashed under SHA-256.
//!
//! Standardised as `mlkem768x25519-sha256` in OpenSSH 9.9+ (and previously
//! shipped as the experimental `mlkem768x25519-sha256@openssh.com`). The
//! wire flow mirrors `curve25519-sha256` — two messages, ECDH-style numbers
//! `SSH_MSG_KEX_HYBRID_INIT (30)` and `SSH_MSG_KEX_HYBRID_REPLY (31)` — but
//! the public-blob fields carry an ML-KEM artefact concatenated with the
//! X25519 ephemeral.
//!
//! ```text
//!   client -> server: SSH_MSG_KEX_HYBRID_INIT (30)
//!     string  C_INIT = ek_pq (1184 B) || ephem_pub_x25519 (32 B)   [= 1216 B]
//!
//!   server -> client: SSH_MSG_KEX_HYBRID_REPLY (31)
//!     string  K_S                 (host-key blob)
//!     string  S_REPLY = ct_pq (1088 B) || ephem_pub_x25519_s (32 B) [= 1120 B]
//!     string  signature           (signature over the exchange hash H)
//! ```
//!
//! The shared secret is `K = SHA256(K_PQ || K_ECDH)` where `K_PQ` is the
//! 32-byte ML-KEM-768 shared secret and `K_ECDH` is the raw 32-byte X25519
//! shared secret. The exchange hash `H` is the SHA-256 of
//! `V_C || V_S || I_C || I_S || K_S || C_INIT || S_REPLY || K` with `K`
//! encoded as an SSH `mpint`.
//!
//! Failures from ML-KEM (which never *errors* — implicit rejection produces
//! a random shared secret on invalid input, per FIPS 203 §7.3) and from
//! X25519 small-order peers are both surfaced as the same
//! `Error::Crypto("hybrid KEX agreement failed")` so the implicit-reject
//! contract is preserved: a downstream observer cannot distinguish "bad
//! ciphertext" from "bad X25519 point" from "tampered exchange hash".

use alloc::vec::Vec;

use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::hash::{Digest, Sha256};
use purecrypto::mlkem::{
    MlKem768Ciphertext, MlKem768DecapsKey, MlKem768EncapsKey, SHARED_SECRET_BYTES,
};
use purecrypto::rng::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::common::{
    KexContext, KexInitOut, KexOutput, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY,
};
use super::hash::{mpint_bytes, ExchangeHash};
use super::Kex;
use crate::error::{Error, Result};
use crate::format::Reader;
use crate::hostkey::HostKeyVerify;

/// Marker type implementing the `mlkem768x25519-sha256` KEX.
pub struct MlKem768X25519Sha256;

impl Kex for MlKem768X25519Sha256 {
    const NAME: &'static str = "mlkem768x25519-sha256";
    const HASH_LEN: usize = 32;
}

/// Byte length of the ML-KEM-768 encapsulation key on the wire.
const EK_PQ_LEN: usize = MlKem768DecapsKey::ENCAPS_KEY_BYTES; // 1184
/// Byte length of an ML-KEM-768 ciphertext on the wire.
const CT_PQ_LEN: usize = MlKem768DecapsKey::CIPHERTEXT_BYTES; // 1088
/// Byte length of the X25519 ephemeral public key.
const X25519_PUB_LEN: usize = 32;
/// Byte length of `C_INIT = ek_pq || ephem_pub_x25519` (1184 + 32).
const C_INIT_LEN: usize = EK_PQ_LEN + X25519_PUB_LEN;
/// Byte length of `S_REPLY = ct_pq || ephem_pub_x25519_s` (1088 + 32).
const S_REPLY_LEN: usize = CT_PQ_LEN + X25519_PUB_LEN;

impl MlKem768X25519Sha256 {
    /// Algorithm name (`mlkem768x25519-sha256`).
    pub const NAME: &'static str = <Self as Kex>::NAME;
    /// Exchange-hash output length (SHA-256 = 32 bytes).
    pub const HASH_LEN: usize = <Self as Kex>::HASH_LEN;
    /// `C_INIT` length on the wire.
    pub const C_INIT_LEN: usize = C_INIT_LEN;
    /// `S_REPLY` length on the wire.
    pub const S_REPLY_LEN: usize = S_REPLY_LEN;
}

/// Client-side state retained between `client_init` and `client_finish`.
pub struct ClientState {
    /// X25519 ephemeral secret matching the public bytes embedded in `c_init`.
    x25519_secret: X25519PrivateKey,
    /// ML-KEM-768 decapsulation key matching the EK embedded in `c_init`.
    pq_secret: MlKem768DecapsKey,
    /// The exact 1216-byte `C_INIT` blob sent on the wire — kept to feed the
    /// exchange hash without re-serialising.
    c_init: Vec<u8>,
}

/// Server-side output of [`MlKem768X25519Sha256::server_reply`]: the wire
/// payload to send and the already-computed `(K, H)` pair.
pub struct ServerReplyOut {
    /// `SSH_MSG_KEX_HYBRID_REPLY` payload (message-type byte included).
    pub payload: Vec<u8>,
    /// The shared secret + exchange hash, ready for the KDF.
    pub kex: KexOutput,
}

/// Combine the ML-KEM and X25519 shared secrets into the canonical
/// `SHA256(K_PQ || K_ECDH)` and return it wrapped in `Zeroizing`.
///
/// Both inputs are 32 bytes; the output is 32 bytes.
fn combine_secrets(
    k_pq: &Zeroizing<[u8; SHARED_SECRET_BYTES]>,
    k_ecdh: &Zeroizing<[u8; 32]>,
) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(&**k_pq);
    h.update(&**k_ecdh);
    let digest = h.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(digest.as_ref());
    out
}

impl MlKem768X25519Sha256 {
    /// Generate the client's ephemerals (X25519 + ML-KEM-768) and produce
    /// the `SSH_MSG_KEX_HYBRID_INIT` payload.
    pub fn client_init<R: RngCore + CryptoRng>(rng: &mut R) -> (ClientState, KexInitOut) {
        let x25519_secret = X25519PrivateKey::generate(rng);
        let q_c = x25519_secret.public_key();
        let (pq_secret, pq_public) = MlKem768DecapsKey::generate(rng);
        let ek_bytes = pq_public.to_bytes();

        let mut c_init = Vec::with_capacity(C_INIT_LEN);
        c_init.extend_from_slice(&ek_bytes);
        c_init.extend_from_slice(&q_c);
        debug_assert_eq!(c_init.len(), C_INIT_LEN);

        let mut payload = Vec::with_capacity(1 + 4 + C_INIT_LEN);
        payload.push(SSH_MSG_KEX_ECDH_INIT);
        payload.extend_from_slice(&(C_INIT_LEN as u32).to_be_bytes());
        payload.extend_from_slice(&c_init);

        (
            ClientState {
                x25519_secret,
                pq_secret,
                c_init,
            },
            KexInitOut { payload },
        )
    }

    /// Parse a client `SSH_MSG_KEX_HYBRID_INIT`, run ML-KEM encapsulation
    /// and X25519 against the fresh server ephemerals, derive the combined
    /// shared secret, sign the resulting exchange hash with the host key,
    /// and assemble the `SSH_MSG_KEX_HYBRID_REPLY` payload.
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
            return Err(Error::Protocol("expected SSH_MSG_KEX_HYBRID_INIT"));
        }
        let c_init = r.read_string()?;
        if c_init.len() != C_INIT_LEN {
            return Err(Error::Format("hybrid C_INIT wrong length"));
        }

        // Split C_INIT into its ML-KEM and X25519 halves.
        let (ek_bytes, q_c_bytes) = c_init.split_at(EK_PQ_LEN);
        let mut ek_arr = [0u8; EK_PQ_LEN];
        ek_arr.copy_from_slice(ek_bytes);
        let mut q_c = [0u8; X25519_PUB_LEN];
        q_c.copy_from_slice(q_c_bytes);

        // FIPS 203 §7.2 EK validation: rejects off-modulus encapsulation
        // keys that would otherwise act as an oracle into the encapsulator's
        // noise. Surfaced as the generic "agreement failed" error so we do
        // not leak which half of the hybrid failed.
        let ek = MlKem768EncapsKey::from_bytes_validated(ek_arr)
            .map_err(|_| Error::Crypto("hybrid KEX agreement failed"))?;

        // Server X25519 ephemeral.
        let secret = X25519PrivateKey::generate(rng);
        let q_s = secret.public_key();

        // Both half-secrets land on the stack in Zeroizing buffers so they
        // are wiped when this function returns. Only the combined hash
        // (also Zeroizing while we work with it) is fed into K's mpint
        // encoding; the raw half-secrets never leave this frame.
        let mut k_pq_raw = Zeroizing::new([0u8; SHARED_SECRET_BYTES]);
        let (ct, k_pq_bytes) = ek.encapsulate(rng);
        k_pq_raw.copy_from_slice(&k_pq_bytes);

        let k_ecdh_raw: Zeroizing<[u8; 32]> = Zeroizing::new(
            secret
                .diffie_hellman(&q_c)
                .map_err(|_| Error::Crypto("hybrid KEX agreement failed"))?,
        );

        let k_combined = combine_secrets(&k_pq_raw, &k_ecdh_raw);

        // Assemble S_REPLY = ct_pq || q_s.
        let ct_bytes = ct.to_bytes();
        let mut s_reply = Vec::with_capacity(S_REPLY_LEN);
        s_reply.extend_from_slice(&ct_bytes);
        s_reply.extend_from_slice(&q_s);
        debug_assert_eq!(s_reply.len(), S_REPLY_LEN);

        let k_s = host_key.public_blob();

        let mut eh = ExchangeHash::<Sha256>::new();
        eh.write_string(ctx.v_c);
        eh.write_string(ctx.v_s);
        eh.write_string(ctx.i_c);
        eh.write_string(ctx.i_s);
        eh.write_string(&k_s);
        eh.write_string(c_init);
        eh.write_string(&s_reply);
        eh.write_mpint(&*k_combined);
        let h = eh.finalize();

        let sig = host_key.sign(&h)?;

        let mut payload = Vec::with_capacity(1 + 4 + k_s.len() + 4 + s_reply.len() + 4 + sig.len());
        payload.push(SSH_MSG_KEX_ECDH_REPLY);
        payload.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
        payload.extend_from_slice(&k_s);
        payload.extend_from_slice(&(s_reply.len() as u32).to_be_bytes());
        payload.extend_from_slice(&s_reply);
        payload.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        payload.extend_from_slice(&sig);

        let k = mpint_bytes(&*k_combined);
        Ok(ServerReplyOut {
            payload,
            kex: KexOutput { k, h },
        })
    }

    /// Parse the server's `SSH_MSG_KEX_HYBRID_REPLY`, decapsulate the ML-KEM
    /// ciphertext, run X25519 against the server's ephemeral, derive the
    /// combined shared secret, verify the host-key signature on `H`, and
    /// return `(K, H)`.
    pub fn client_finish(
        state: ClientState,
        reply_payload: &[u8],
        verifier: &dyn HostKeyVerify,
        ctx: &KexContext<'_>,
    ) -> Result<KexOutput> {
        let mut r = Reader::new(reply_payload);
        let msg = r.read_u8()?;
        if msg != SSH_MSG_KEX_ECDH_REPLY {
            return Err(Error::Protocol("expected SSH_MSG_KEX_HYBRID_REPLY"));
        }
        let k_s = r.read_string()?;
        let s_reply = r.read_string()?;
        if s_reply.len() != S_REPLY_LEN {
            return Err(Error::Format("hybrid S_REPLY wrong length"));
        }
        let sig = r.read_string()?;

        let (ct_bytes, q_s_bytes) = s_reply.split_at(CT_PQ_LEN);
        let mut ct_arr = [0u8; CT_PQ_LEN];
        ct_arr.copy_from_slice(ct_bytes);
        let mut q_s = [0u8; X25519_PUB_LEN];
        q_s.copy_from_slice(q_s_bytes);

        // ML-KEM decapsulation never errors — invalid ciphertexts yield a
        // pseudo-random shared secret (implicit rejection, FIPS 203 §6.3).
        // The resulting K mismatch surfaces as a signature-verification
        // failure below, which is exactly the contract the spec wants.
        let ct = MlKem768Ciphertext::from_bytes(ct_arr);
        let mut k_pq_raw = Zeroizing::new([0u8; SHARED_SECRET_BYTES]);
        k_pq_raw.copy_from_slice(&state.pq_secret.decapsulate(&ct));

        let k_ecdh_raw: Zeroizing<[u8; 32]> = Zeroizing::new(
            state
                .x25519_secret
                .diffie_hellman(&q_s)
                .map_err(|_| Error::Crypto("hybrid KEX agreement failed"))?,
        );

        let k_combined = combine_secrets(&k_pq_raw, &k_ecdh_raw);

        let mut eh = ExchangeHash::<Sha256>::new();
        eh.write_string(ctx.v_c);
        eh.write_string(ctx.v_s);
        eh.write_string(ctx.i_c);
        eh.write_string(ctx.i_s);
        eh.write_string(k_s);
        eh.write_string(&state.c_init);
        eh.write_string(s_reply);
        eh.write_mpint(&*k_combined);
        let h = eh.finalize();

        verifier.verify(&h, sig)?;

        let k = mpint_bytes(&*k_combined);
        Ok(KexOutput { k, h })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::{Ed25519HostKey, HostKey};
    use crate::transport::version::LOCAL_VERSION;
    use purecrypto::rng::HmacDrbg;

    fn ctx() -> ([u8; 8], [u8; 8], [u8; 4], [u8; 4]) {
        // Fixed pseudo-context for the round-trip test. The exact contents
        // do not matter as long as both sides see the same bytes.
        let mut v_c = [0u8; 8];
        v_c.copy_from_slice(b"SSH-2.0_");
        let mut v_s = [0u8; 8];
        v_s.copy_from_slice(b"SSH-2.0&");
        (v_c, v_s, [0x11, 0x22, 0x33, 0x44], [0x55, 0x66, 0x77, 0x88])
    }

    #[test]
    fn algorithm_constants() {
        assert_eq!(MlKem768X25519Sha256::NAME, "mlkem768x25519-sha256");
        assert_eq!(MlKem768X25519Sha256::HASH_LEN, 32);
        assert_eq!(MlKem768X25519Sha256::C_INIT_LEN, 1216);
        assert_eq!(MlKem768X25519Sha256::S_REPLY_LEN, 1120);
    }

    #[test]
    fn init_payload_layout() {
        let mut rng = HmacDrbg::<Sha256>::new(b"hybrid-init", b"nonce", &[]);
        let (_state, init) = MlKem768X25519Sha256::client_init(&mut rng);
        assert_eq!(init.payload.len(), 1 + 4 + C_INIT_LEN);
        assert_eq!(init.payload[0], SSH_MSG_KEX_ECDH_INIT);
        assert_eq!(&init.payload[1..5], &(C_INIT_LEN as u32).to_be_bytes());
    }

    #[test]
    fn round_trip_shared_secret_matches() {
        let mut rng = HmacDrbg::<Sha256>::new(b"hybrid-roundtrip", b"nonce", &[]);

        // Shared host key — server signs, client verifies.
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let (v_c, v_s, i_c, i_s) = ctx();
        let kex_ctx = KexContext {
            v_c: &v_c,
            v_s: &v_s,
            i_c: &i_c,
            i_s: &i_s,
        };

        let (state, init) = MlKem768X25519Sha256::client_init(&mut rng);
        let reply =
            MlKem768X25519Sha256::server_reply(&mut rng, &init.payload, &server_hk, &kex_ctx)
                .expect("server_reply");
        let client_out =
            MlKem768X25519Sha256::client_finish(state, &reply.payload, &client_verifier, &kex_ctx)
                .expect("client_finish");

        assert_eq!(client_out.k, reply.kex.k);
        assert_eq!(client_out.h, reply.kex.h);
        // SHA-256 output — sanity that we did not accidentally use a wider hash.
        assert_eq!(client_out.h.len(), 32);
        // Smoke that LOCAL_VERSION is still exported, since reachability of
        // the transport module surfaces if the feature gating drifts.
        assert!(!LOCAL_VERSION.is_empty());
    }

    #[test]
    fn c_init_wrong_length_rejected() {
        let mut rng = HmacDrbg::<Sha256>::new(b"hybrid-bad-c", b"nonce", &[]);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);

        let (v_c, v_s, i_c, i_s) = ctx();
        let kex_ctx = KexContext {
            v_c: &v_c,
            v_s: &v_s,
            i_c: &i_c,
            i_s: &i_s,
        };

        // Too-short C_INIT: header says 100 bytes, body is 100 zeros.
        let mut bad = Vec::with_capacity(1 + 4 + 100);
        bad.push(SSH_MSG_KEX_ECDH_INIT);
        bad.extend_from_slice(&100u32.to_be_bytes());
        bad.extend(core::iter::repeat_n(0u8, 100));
        let result = MlKem768X25519Sha256::server_reply(&mut rng, &bad, &server_hk, &kex_ctx);
        assert!(matches!(
            result.map(|_| ()),
            Err(Error::Format("hybrid C_INIT wrong length"))
        ));
    }

    #[test]
    fn s_reply_wrong_length_rejected() {
        let mut rng = HmacDrbg::<Sha256>::new(b"hybrid-bad-s", b"nonce", &[]);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let public = server_hk.public_bytes();
        let client_verifier = Ed25519HostKey::from_public(public);

        let (v_c, v_s, i_c, i_s) = ctx();
        let kex_ctx = KexContext {
            v_c: &v_c,
            v_s: &v_s,
            i_c: &i_c,
            i_s: &i_s,
        };

        let (state, _init) = MlKem768X25519Sha256::client_init(&mut rng);

        // Fabricate a reply with the right framing but a truncated S_REPLY.
        let k_s = server_hk.public_blob();
        let s_reply_bad = [0u8; 200];
        let sig = [0u8; 64];

        let mut reply = Vec::new();
        reply.push(SSH_MSG_KEX_ECDH_REPLY);
        reply.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
        reply.extend_from_slice(&k_s);
        reply.extend_from_slice(&(s_reply_bad.len() as u32).to_be_bytes());
        reply.extend_from_slice(&s_reply_bad);
        reply.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        reply.extend_from_slice(&sig);

        let result = MlKem768X25519Sha256::client_finish(state, &reply, &client_verifier, &kex_ctx);
        assert!(matches!(
            result.map(|_| ()),
            Err(Error::Format("hybrid S_REPLY wrong length"))
        ));
    }

    #[test]
    fn exchange_hash_uses_sha256() {
        // Indirect check: the round-trip already asserts hash length, but
        // do it as a standalone unit so a future refactor that swaps the
        // hash flips this specific test.
        let mut rng = HmacDrbg::<Sha256>::new(b"hybrid-hash", b"nonce", &[]);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);

        let (v_c, v_s, i_c, i_s) = ctx();
        let kex_ctx = KexContext {
            v_c: &v_c,
            v_s: &v_s,
            i_c: &i_c,
            i_s: &i_s,
        };

        let (_state, init) = MlKem768X25519Sha256::client_init(&mut rng);
        let reply =
            MlKem768X25519Sha256::server_reply(&mut rng, &init.payload, &server_hk, &kex_ctx)
                .expect("server_reply");
        assert_eq!(reply.kex.h.len(), 32);
    }
}
