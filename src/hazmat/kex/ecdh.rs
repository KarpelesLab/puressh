//! `ecdh-sha2-nistp{256,384,521}` (RFC 5656).
//!
//! Q values are exchanged as uncompressed SEC1 points (`0x04 || X || Y`),
//! and the shared secret `K` is the affine X-coordinate of `d * Q_peer`,
//! encoded into `H` and the KDF as an SSH `mpint`.

use alloc::vec::Vec;

use purecrypto::ec::boxed::{BoxedEcdhPrivateKey, BoxedEcdsaPublicKey};
use purecrypto::ec::curves::CurveId;
use purecrypto::hash::{Digest, Sha256, Sha384, Sha512};
use purecrypto::rng::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::Kex;
use super::common::{
    KexContext, KexInitOut, KexOutput, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY,
};
use super::hash::{ExchangeHash, mpint_bytes};
use crate::error::{Error, Result};
use crate::format::Reader;
use crate::hostkey::HostKeyVerify;

/// `ecdh-sha2-nistp256` — P-256 ECDH with SHA-256.
pub struct EcdhSha2Nistp256;
impl Kex for EcdhSha2Nistp256 {
    const NAME: &'static str = "ecdh-sha2-nistp256";
    const HASH_LEN: usize = 32;
}

/// `ecdh-sha2-nistp384` — P-384 ECDH with SHA-384.
pub struct EcdhSha2Nistp384;
impl Kex for EcdhSha2Nistp384 {
    const NAME: &'static str = "ecdh-sha2-nistp384";
    const HASH_LEN: usize = 48;
}

/// `ecdh-sha2-nistp521` — P-521 ECDH with SHA-512.
pub struct EcdhSha2Nistp521;
impl Kex for EcdhSha2Nistp521 {
    const NAME: &'static str = "ecdh-sha2-nistp521";
    const HASH_LEN: usize = 64;
}

/// Client state retained between `init` and `finish`.
pub struct ClientState {
    curve: CurveId,
    secret: BoxedEcdhPrivateKey,
    q_c: Vec<u8>,
}

/// Server reply payload + `(K, H)`.
pub struct ServerReplyOut {
    /// Wire-format `SSH_MSG_KEX_ECDH_REPLY` payload.
    pub payload: Vec<u8>,
    /// The shared secret + exchange hash.
    pub kex: KexOutput,
}

fn field_len(curve: CurveId) -> Option<usize> {
    match curve {
        CurveId::P256 => Some(32),
        CurveId::P384 => Some(48),
        CurveId::P521 => Some(66),
        CurveId::Secp256k1 => Some(32),
        // `CurveId` is `#[non_exhaustive]` upstream. Only the curves above are
        // ever passed here (see the `Kex` impls above), so this arm is
        // unreachable today. We fail closed rather than `unreachable!()`: if a
        // future refactor ever let a peer-influenced curve reach this code, a
        // panic would be a DoS, whereas `None` turns into a clean protocol
        // error at the call site. Returning a guessed length would be worse —
        // it would silently mis-frame crypto.
        _ => None,
    }
}

fn sec1_point_len(curve: CurveId) -> Option<usize> {
    Some(1 + 2 * field_len(curve)?)
}

fn client_init<R: RngCore + CryptoRng>(curve: CurveId, rng: &mut R) -> (ClientState, KexInitOut) {
    let secret = BoxedEcdhPrivateKey::generate(curve, rng);
    let q_c = secret.public_key().to_sec1();
    let mut payload = Vec::with_capacity(1 + 4 + q_c.len());
    payload.push(SSH_MSG_KEX_ECDH_INIT);
    payload.extend_from_slice(&(q_c.len() as u32).to_be_bytes());
    payload.extend_from_slice(&q_c);
    (ClientState { curve, secret, q_c }, KexInitOut { payload })
}

fn server_reply_inner<D, R, S>(
    curve: CurveId,
    rng: &mut R,
    init_payload: &[u8],
    host_key: &S,
    ctx: &KexContext<'_>,
) -> Result<ServerReplyOut>
where
    D: Digest,
    R: RngCore + CryptoRng,
    S: crate::hostkey::HostKey + ?Sized,
{
    let mut r = Reader::new(init_payload);
    let msg = r.read_u8()?;
    if msg != SSH_MSG_KEX_ECDH_INIT {
        return Err(Error::Protocol("expected SSH_MSG_KEX_ECDH_INIT"));
    }
    let q_c_bytes = r.read_string()?;
    let expected_len = sec1_point_len(curve).ok_or(Error::Unsupported("unsupported ECDH curve"))?;
    if q_c_bytes.len() != expected_len {
        return Err(Error::Format("ECDH Q_C wrong length"));
    }
    let peer = BoxedEcdsaPublicKey::from_sec1(curve, q_c_bytes)
        .map_err(|_| Error::Format("invalid ECDH Q_C"))?;

    let secret = BoxedEcdhPrivateKey::generate(curve, rng);
    let q_s = secret.public_key().to_sec1();
    // Raw ECDH shared X-coordinate. Wipe the locally-materialised copy when
    // the function returns; the SSH-mpint re-encoding lives on in
    // `KexOutput.k`.
    let k_raw: Zeroizing<Vec<u8>> = Zeroizing::new(
        secret
            .diffie_hellman(&peer)
            .map_err(|_| Error::Crypto("ECDH agreement failed"))?,
    );

    let k_s = host_key.public_blob();

    let mut eh = ExchangeHash::<D>::new();
    eh.write_string(ctx.v_c);
    eh.write_string(ctx.v_s);
    eh.write_string(ctx.i_c);
    eh.write_string(ctx.i_s);
    eh.write_string(&k_s);
    eh.write_string(q_c_bytes);
    eh.write_string(&q_s);
    eh.write_mpint(&k_raw);
    let h = eh.finalize();

    let sig = host_key.sign(&h)?;

    let mut payload = Vec::with_capacity(1 + 4 + k_s.len() + 4 + q_s.len() + 4 + sig.len());
    payload.push(SSH_MSG_KEX_ECDH_REPLY);
    payload.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
    payload.extend_from_slice(&k_s);
    payload.extend_from_slice(&(q_s.len() as u32).to_be_bytes());
    payload.extend_from_slice(&q_s);
    payload.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    payload.extend_from_slice(&sig);

    let k = mpint_bytes(&k_raw);
    Ok(ServerReplyOut {
        payload,
        kex: KexOutput { k, h },
    })
}

fn client_finish_inner<D: Digest>(
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
    let expected_len =
        sec1_point_len(state.curve).ok_or(Error::Unsupported("unsupported ECDH curve"))?;
    if q_s_bytes.len() != expected_len {
        return Err(Error::Format("ECDH Q_S wrong length"));
    }
    let sig = r.read_string()?;

    let peer = BoxedEcdsaPublicKey::from_sec1(state.curve, q_s_bytes)
        .map_err(|_| Error::Format("invalid ECDH Q_S"))?;
    // Wipe the locally-materialised raw ECDH shared X-coordinate on return.
    let k_raw: Zeroizing<Vec<u8>> = Zeroizing::new(
        state
            .secret
            .diffie_hellman(&peer)
            .map_err(|_| Error::Crypto("ECDH agreement failed"))?,
    );

    let mut eh = ExchangeHash::<D>::new();
    eh.write_string(ctx.v_c);
    eh.write_string(ctx.v_s);
    eh.write_string(ctx.i_c);
    eh.write_string(ctx.i_s);
    eh.write_string(k_s);
    eh.write_string(&state.q_c);
    eh.write_string(q_s_bytes);
    eh.write_mpint(&k_raw);
    let h = eh.finalize();

    verifier.verify(&h, sig)?;

    let k = mpint_bytes(&k_raw);
    Ok(KexOutput { k, h })
}

macro_rules! ecdh_impl {
    ($ty:ident, $curve:expr, $hash:ty) => {
        impl $ty {
            /// Algorithm name.
            pub const NAME: &'static str = <Self as Kex>::NAME;
            /// Exchange-hash output length in bytes.
            pub const HASH_LEN: usize = <Self as Kex>::HASH_LEN;

            /// Generate the client ephemeral and produce
            /// `SSH_MSG_KEX_ECDH_INIT`.
            pub fn client_init<R: RngCore + CryptoRng>(rng: &mut R) -> (ClientState, KexInitOut) {
                client_init($curve, rng)
            }

            /// Server side: parse client init, agree, sign, produce reply.
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
                server_reply_inner::<$hash, _, _>($curve, rng, init_payload, host_key, ctx)
            }

            /// Client side: parse reply, agree, verify signature.
            pub fn client_finish(
                state: ClientState,
                reply_payload: &[u8],
                verifier: &dyn HostKeyVerify,
                ctx: &KexContext<'_>,
            ) -> Result<KexOutput> {
                if state.curve != $curve {
                    return Err(Error::Protocol("ECDH curve mismatch"));
                }
                client_finish_inner::<$hash>(state, reply_payload, verifier, ctx)
            }
        }
    };
}

ecdh_impl!(EcdhSha2Nistp256, CurveId::P256, Sha256);
ecdh_impl!(EcdhSha2Nistp384, CurveId::P384, Sha384);
ecdh_impl!(EcdhSha2Nistp521, CurveId::P521, Sha512);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_constants() {
        assert_eq!(EcdhSha2Nistp256::NAME, "ecdh-sha2-nistp256");
        assert_eq!(EcdhSha2Nistp256::HASH_LEN, 32);
        assert_eq!(EcdhSha2Nistp384::NAME, "ecdh-sha2-nistp384");
        assert_eq!(EcdhSha2Nistp384::HASH_LEN, 48);
        assert_eq!(EcdhSha2Nistp521::NAME, "ecdh-sha2-nistp521");
        assert_eq!(EcdhSha2Nistp521::HASH_LEN, 64);
    }

    #[test]
    fn sec1_lengths_match_curves() {
        assert_eq!(sec1_point_len(CurveId::P256), Some(65));
        assert_eq!(sec1_point_len(CurveId::P384), Some(97));
        assert_eq!(sec1_point_len(CurveId::P521), Some(133));
    }
}
