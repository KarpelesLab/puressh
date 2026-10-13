//! `sntrup761x25519-sha512` (and its original name
//! `sntrup761x25519-sha512@openssh.com`) — hybrid post-quantum key exchange
//! combining Streamlined NTRU Prime 761 with X25519, hashed under SHA-512.
//! OpenSSH's default from 9.0 until ML-KEM took over in 10.0, and still
//! offered by default.
//!
//! The flow is that of [`super::mlkem768x25519`]: the client sends
//! `pk (1158 B) || X25519 public (32 B)`, the server replies with
//! `ciphertext (1039 B) || X25519 public (32 B)`, and the shared secret is
//! `K = SHA512(K_PQ || K_ECDH)`, encoded as an SSH `string` (not `mpint`)
//! in both the exchange hash and the key derivation, as OpenSSH's
//! `kexsntrup761x25519.c` does.

use alloc::vec::Vec;

use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::hash::{Digest, Sha512};
use purecrypto::rng::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::Kex;
use super::common::{
    KexContext, KexInitOut, KexOutput, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY,
};
use super::hash::ExchangeHash;
use super::sntrup761;
use crate::error::{Error, Result};
use crate::format::Reader;
use crate::hostkey::HostKeyVerify;

/// Marker type implementing `sntrup761x25519-sha512`.
pub struct Sntrup761X25519Sha512;

impl Kex for Sntrup761X25519Sha512 {
    const NAME: &'static str = "sntrup761x25519-sha512";
    const HASH_LEN: usize = 64;
}

const X25519_PUB_LEN: usize = 32;
const C_INIT_LEN: usize = sntrup761::PUBLIC_KEY_BYTES + X25519_PUB_LEN;
const S_REPLY_LEN: usize = sntrup761::CIPHERTEXT_BYTES + X25519_PUB_LEN;

impl Sntrup761X25519Sha512 {
    /// Algorithm name (`sntrup761x25519-sha512`).
    pub const NAME: &'static str = <Self as Kex>::NAME;
    /// The name OpenSSH introduced it under; the same method.
    pub const LEGACY_NAME: &'static str = "sntrup761x25519-sha512@openssh.com";
    /// Exchange-hash output length (SHA-512 = 64 bytes).
    pub const HASH_LEN: usize = <Self as Kex>::HASH_LEN;
}

/// Client-side state retained between `client_init` and `client_finish`.
pub struct ClientState {
    x25519_secret: X25519PrivateKey,
    pq_secret: Zeroizing<Vec<u8>>,
    c_init: Vec<u8>,
}

/// Server-side output of [`Sntrup761X25519Sha512::server_reply`].
pub struct ServerReplyOut {
    /// `SSH_MSG_KEX_ECDH_REPLY` payload (message-type byte included).
    pub payload: Vec<u8>,
    /// The shared secret + exchange hash, ready for the KDF.
    pub kex: KexOutput,
}

/// `SHA512(K_PQ || K_ECDH)`.
fn combine_secrets(k_pq: &[u8], k_ecdh: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut h = Sha512::new();
    h.update(k_pq);
    h.update(k_ecdh);
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(h.finalize().as_ref());
    out
}

/// `K` as an SSH `string`.
fn k_string_bytes(k: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + k.len());
    out.extend_from_slice(&(k.len() as u32).to_be_bytes());
    out.extend_from_slice(k);
    out
}

fn exchange_hash(
    ctx: &KexContext<'_>,
    k_s: &[u8],
    c_init: &[u8],
    s_reply: &[u8],
    k: &[u8],
) -> Vec<u8> {
    let mut eh = ExchangeHash::<Sha512>::new();
    eh.write_string(ctx.v_c);
    eh.write_string(ctx.v_s);
    eh.write_string(ctx.i_c);
    eh.write_string(ctx.i_s);
    eh.write_string(k_s);
    eh.write_string(c_init);
    eh.write_string(s_reply);
    eh.write_string(k);
    eh.finalize()
}

impl Sntrup761X25519Sha512 {
    /// Generate the client's ephemerals and the `SSH_MSG_KEX_ECDH_INIT`
    /// payload.
    pub fn client_init<R: RngCore + CryptoRng>(rng: &mut R) -> (ClientState, KexInitOut) {
        let x25519_secret = X25519PrivateKey::generate(rng);
        let (pk, sk) = sntrup761::keypair(rng);
        let mut c_init = Vec::with_capacity(C_INIT_LEN);
        c_init.extend_from_slice(&pk);
        c_init.extend_from_slice(&x25519_secret.public_key());

        let mut payload = Vec::with_capacity(1 + 4 + C_INIT_LEN);
        payload.push(SSH_MSG_KEX_ECDH_INIT);
        payload.extend_from_slice(&(C_INIT_LEN as u32).to_be_bytes());
        payload.extend_from_slice(&c_init);
        (
            ClientState {
                x25519_secret,
                pq_secret: sk,
                c_init,
            },
            KexInitOut { payload },
        )
    }

    /// Answer a client's `SSH_MSG_KEX_ECDH_INIT`: encapsulate to its key,
    /// agree on X25519, sign the exchange hash and build the reply.
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
        if r.read_u8()? != SSH_MSG_KEX_ECDH_INIT {
            return Err(Error::Protocol("expected SSH_MSG_KEX_ECDH_INIT"));
        }
        let c_init = r.read_string()?;
        if c_init.len() != C_INIT_LEN {
            return Err(Error::Format("hybrid C_INIT wrong length"));
        }
        let (pk, q_c_bytes) = c_init.split_at(sntrup761::PUBLIC_KEY_BYTES);
        let mut q_c = [0u8; X25519_PUB_LEN];
        q_c.copy_from_slice(q_c_bytes);

        let (ct, k_pq) = sntrup761::encapsulate(rng, pk);
        let secret = X25519PrivateKey::generate(rng);
        let q_s = secret.public_key();
        let k_ecdh: Zeroizing<[u8; 32]> = Zeroizing::new(
            secret
                .diffie_hellman(&q_c)
                .map_err(|_| Error::Crypto("hybrid KEX agreement failed"))?,
        );
        let k = combine_secrets(&*k_pq, &*k_ecdh);

        let mut s_reply = Vec::with_capacity(S_REPLY_LEN);
        s_reply.extend_from_slice(&ct);
        s_reply.extend_from_slice(&q_s);

        let k_s = host_key.public_blob();
        let h = exchange_hash(ctx, &k_s, c_init, &s_reply, &*k);
        let sig = host_key.sign(&h)?;

        let mut payload = Vec::with_capacity(1 + 4 + k_s.len() + 4 + s_reply.len() + 4 + sig.len());
        payload.push(SSH_MSG_KEX_ECDH_REPLY);
        for field in [&k_s[..], &s_reply, &sig] {
            payload.extend_from_slice(&(field.len() as u32).to_be_bytes());
            payload.extend_from_slice(field);
        }
        Ok(ServerReplyOut {
            payload,
            kex: KexOutput {
                k: k_string_bytes(&*k),
                h,
            },
        })
    }

    /// Process the server's reply: decapsulate, agree on X25519, verify the
    /// host-key signature on `H`, and return `(K, H)`.
    pub fn client_finish(
        state: ClientState,
        reply_payload: &[u8],
        verifier: &dyn HostKeyVerify,
        ctx: &KexContext<'_>,
    ) -> Result<KexOutput> {
        let mut r = Reader::new(reply_payload);
        if r.read_u8()? != SSH_MSG_KEX_ECDH_REPLY {
            return Err(Error::Protocol("expected SSH_MSG_KEX_ECDH_REPLY"));
        }
        let k_s = r.read_string()?;
        let s_reply = r.read_string()?;
        if s_reply.len() != S_REPLY_LEN {
            return Err(Error::Format("hybrid S_REPLY wrong length"));
        }
        let sig = r.read_string()?;
        let (ct, q_s_bytes) = s_reply.split_at(sntrup761::CIPHERTEXT_BYTES);
        let mut q_s = [0u8; X25519_PUB_LEN];
        q_s.copy_from_slice(q_s_bytes);

        // Decapsulation never fails: a bad ciphertext gives another secret,
        // which surfaces as a signature failure below.
        let k_pq = sntrup761::decapsulate(ct, &state.pq_secret);
        let k_ecdh: Zeroizing<[u8; 32]> = Zeroizing::new(
            state
                .x25519_secret
                .diffie_hellman(&q_s)
                .map_err(|_| Error::Crypto("hybrid KEX agreement failed"))?,
        );
        let k = combine_secrets(&*k_pq, &*k_ecdh);
        let h = exchange_hash(ctx, k_s, &state.c_init, s_reply, &*k);
        verifier.verify(&h, sig)?;
        Ok(KexOutput {
            k: k_string_bytes(&*k),
            h,
        })
    }
}
