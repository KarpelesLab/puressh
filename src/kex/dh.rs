//! `diffie-hellman-group{14,16,18}-sha{256,512}` (RFC 8268) and
//! `diffie-hellman-group-exchange-sha256` (RFC 4419).
//!
//! Backed by [`purecrypto::dh`]: the RFC 3526 safe-prime groups (`group14`,
//! `group16`, `group18`) and `DhPrivateKey::generate` for the ephemeral
//! exponents.

use alloc::vec::Vec;

use purecrypto::bignum::BoxedUint;
use purecrypto::dh::{group14, group16, group18, DhGroup, DhPrivateKey, DhPublicKey};
use purecrypto::hash::{Digest, Sha256, Sha512};
use purecrypto::rng::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::common::{
    KexContext, KexInitOut, KexOutput, SSH_MSG_KEX_DH_GEX_GROUP, SSH_MSG_KEX_DH_GEX_INIT,
    SSH_MSG_KEX_DH_GEX_REPLY, SSH_MSG_KEX_DH_GEX_REQUEST, SSH_MSG_KEX_ECDH_INIT,
    SSH_MSG_KEX_ECDH_REPLY,
};
use super::hash::{mpint_bytes, ExchangeHash};
use super::Kex;
use crate::error::{Error, Result};
use crate::format::{read_mpint, Reader};
use crate::hostkey::HostKeyVerify;

/// `diffie-hellman-group14-sha256` — RFC 3526 2048-bit group, SHA-256.
pub struct Group14Sha256;
impl Kex for Group14Sha256 {
    const NAME: &'static str = "diffie-hellman-group14-sha256";
    const HASH_LEN: usize = 32;
}

/// `diffie-hellman-group16-sha512` — RFC 3526 4096-bit group, SHA-512.
pub struct Group16Sha512;
impl Kex for Group16Sha512 {
    const NAME: &'static str = "diffie-hellman-group16-sha512";
    const HASH_LEN: usize = 64;
}

/// `diffie-hellman-group18-sha512` — RFC 3526 8192-bit group, SHA-512.
pub struct Group18Sha512;
impl Kex for Group18Sha512 {
    const NAME: &'static str = "diffie-hellman-group18-sha512";
    const HASH_LEN: usize = 64;
}

/// `diffie-hellman-group-exchange-sha256` — RFC 4419 GEX, SHA-256.
pub struct GexSha256;
impl Kex for GexSha256 {
    const NAME: &'static str = "diffie-hellman-group-exchange-sha256";
    const HASH_LEN: usize = 32;
}

/// Client state for a fixed-group DH exchange.
pub struct DhClientState {
    group: DhGroup,
    secret: DhPrivateKey,
    e_mag: Vec<u8>,
}

/// Server reply for a fixed-group DH exchange.
pub struct DhServerReplyOut {
    /// Wire-format `SSH_MSG_KEXDH_REPLY` payload.
    pub payload: Vec<u8>,
    /// Shared secret and exchange hash.
    pub kex: KexOutput,
}

fn strip_leading_zero(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < b.len() && b[i] == 0 {
        i += 1;
    }
    &b[i..]
}

fn dh_client_init<R: RngCore + CryptoRng>(
    group: DhGroup,
    rng: &mut R,
) -> (DhClientState, KexInitOut) {
    let secret = DhPrivateKey::generate(group.clone(), rng);
    let pub_key = secret.public_key();
    let e_mag = pub_key.to_bytes();
    let mut payload = Vec::with_capacity(1 + 4 + e_mag.len() + 1);
    payload.push(SSH_MSG_KEX_ECDH_INIT);
    encode_mpint_into(&mut payload, &e_mag);
    (
        DhClientState {
            group,
            secret,
            e_mag,
        },
        KexInitOut { payload },
    )
}

fn encode_mpint_into(buf: &mut Vec<u8>, magnitude: &[u8]) {
    let m = strip_leading_zero(magnitude);
    if m.is_empty() {
        buf.extend_from_slice(&0u32.to_be_bytes());
        return;
    }
    if m[0] & 0x80 != 0 {
        buf.extend_from_slice(&((m.len() + 1) as u32).to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(m);
    } else {
        buf.extend_from_slice(&(m.len() as u32).to_be_bytes());
        buf.extend_from_slice(m);
    }
}

fn dh_server_reply<D, R, S>(
    group: DhGroup,
    rng: &mut R,
    init_payload: &[u8],
    host_key: &S,
    ctx: &KexContext<'_>,
) -> Result<DhServerReplyOut>
where
    D: Digest,
    R: RngCore + CryptoRng,
    S: crate::hostkey::HostKey + ?Sized,
{
    let mut r = Reader::new(init_payload);
    let msg = r.read_u8()?;
    if msg != SSH_MSG_KEX_ECDH_INIT {
        return Err(Error::Protocol("expected SSH_MSG_KEXDH_INIT"));
    }
    let e_raw = read_mpint(&mut r)?;
    let peer =
        DhPublicKey::from_bytes(group.clone(), e_raw).map_err(|_| Error::Format("invalid DH e"))?;

    let secret = DhPrivateKey::generate(group.clone(), rng);
    let f_pub = secret.public_key();
    let f_mag = f_pub.to_bytes();
    let shared = secret
        .shared_secret(&peer)
        .map_err(|_| Error::Crypto("DH agreement failed"))?;
    // Locally-materialised raw DH shared secret (magnitude bytes). Wipe on
    // return; the SSH-mpint re-encoding lives on in `KexOutput.k`.
    let k_mag: Zeroizing<Vec<u8>> = Zeroizing::new(shared.into_bytes());

    let k_s = host_key.public_blob();
    let mut eh = ExchangeHash::<D>::new();
    eh.write_string(ctx.v_c);
    eh.write_string(ctx.v_s);
    eh.write_string(ctx.i_c);
    eh.write_string(ctx.i_s);
    eh.write_string(&k_s);
    eh.write_mpint(e_raw);
    eh.write_mpint(&f_mag);
    eh.write_mpint(&k_mag);
    let h = eh.finalize();

    let sig = host_key.sign(&h)?;

    let mut payload = Vec::with_capacity(1 + 4 + k_s.len() + 4 + f_mag.len() + 1 + 4 + sig.len());
    payload.push(SSH_MSG_KEX_ECDH_REPLY);
    payload.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
    payload.extend_from_slice(&k_s);
    encode_mpint_into(&mut payload, &f_mag);
    payload.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    payload.extend_from_slice(&sig);

    let k = mpint_bytes(&k_mag);
    Ok(DhServerReplyOut {
        payload,
        kex: KexOutput { k, h },
    })
}

fn dh_client_finish<D: Digest>(
    state: DhClientState,
    reply_payload: &[u8],
    verifier: &dyn HostKeyVerify,
    ctx: &KexContext<'_>,
) -> Result<KexOutput> {
    let mut r = Reader::new(reply_payload);
    let msg = r.read_u8()?;
    if msg != SSH_MSG_KEX_ECDH_REPLY {
        return Err(Error::Protocol("expected SSH_MSG_KEXDH_REPLY"));
    }
    let k_s = r.read_string()?;
    let f_raw = read_mpint(&mut r)?;
    let sig = r.read_string()?;

    let peer = DhPublicKey::from_bytes(state.group.clone(), f_raw)
        .map_err(|_| Error::Format("invalid DH f"))?;
    let shared = state
        .secret
        .shared_secret(&peer)
        .map_err(|_| Error::Crypto("DH agreement failed"))?;
    // Wipe the locally-materialised raw DH shared secret on return.
    let k_mag: Zeroizing<Vec<u8>> = Zeroizing::new(shared.into_bytes());

    let mut eh = ExchangeHash::<D>::new();
    eh.write_string(ctx.v_c);
    eh.write_string(ctx.v_s);
    eh.write_string(ctx.i_c);
    eh.write_string(ctx.i_s);
    eh.write_string(k_s);
    eh.write_mpint(&state.e_mag);
    eh.write_mpint(f_raw);
    eh.write_mpint(&k_mag);
    let h = eh.finalize();

    verifier.verify(&h, sig)?;

    let k = mpint_bytes(&k_mag);
    Ok(KexOutput { k, h })
}

macro_rules! dh_fixed_group_impl {
    ($ty:ident, $group:expr, $hash:ty) => {
        impl $ty {
            /// Algorithm name.
            pub const NAME: &'static str = <Self as Kex>::NAME;
            /// Exchange-hash output length in bytes.
            pub const HASH_LEN: usize = <Self as Kex>::HASH_LEN;

            /// Client side: generate `x`, compute `e = g^x mod p`, build the
            /// `SSH_MSG_KEXDH_INIT` payload.
            pub fn client_init<R: RngCore + CryptoRng>(rng: &mut R) -> (DhClientState, KexInitOut) {
                dh_client_init($group(), rng)
            }

            /// Server side.
            pub fn server_reply<R, S>(
                rng: &mut R,
                init_payload: &[u8],
                host_key: &S,
                ctx: &KexContext<'_>,
            ) -> Result<DhServerReplyOut>
            where
                R: RngCore + CryptoRng,
                S: crate::hostkey::HostKey + ?Sized,
            {
                dh_server_reply::<$hash, _, _>($group(), rng, init_payload, host_key, ctx)
            }

            /// Client side.
            pub fn client_finish(
                state: DhClientState,
                reply_payload: &[u8],
                verifier: &dyn HostKeyVerify,
                ctx: &KexContext<'_>,
            ) -> Result<KexOutput> {
                dh_client_finish::<$hash>(state, reply_payload, verifier, ctx)
            }
        }
    };
}

dh_fixed_group_impl!(Group14Sha256, group14, Sha256);
dh_fixed_group_impl!(Group16Sha512, group16, Sha512);
dh_fixed_group_impl!(Group18Sha512, group18, Sha512);

// -----------------------------------------------------------------------------
// RFC 4419 — diffie-hellman-group-exchange-sha256.
// -----------------------------------------------------------------------------

/// Client wishes for `(min, n, max)` from RFC 4419.
#[derive(Debug, Clone, Copy)]
pub struct GexRequest {
    /// Minimum acceptable prime bit size.
    pub min: u32,
    /// Preferred prime bit size.
    pub n: u32,
    /// Maximum acceptable prime bit size.
    pub max: u32,
}

impl Default for GexRequest {
    fn default() -> Self {
        // OpenSSH defaults: 2048..=8192, preferring 8192.
        GexRequest {
            min: 2048,
            n: 8192,
            max: 8192,
        }
    }
}

/// Client state for a GEX exchange. Retains the request, the server-supplied
/// group, and the local exponent's `e` value across the three round-trips.
pub struct GexClientState {
    request: GexRequest,
    group: Option<DhGroup>,
    p_bytes: Vec<u8>,
    g_bytes: Vec<u8>,
    secret: Option<DhPrivateKey>,
    e_mag: Vec<u8>,
}

impl GexSha256 {
    /// Algorithm name.
    pub const NAME: &'static str = <Self as Kex>::NAME;
    /// Exchange-hash output length in bytes.
    pub const HASH_LEN: usize = <Self as Kex>::HASH_LEN;

    /// Step 1 (client → server): build `SSH_MSG_KEX_DH_GEX_REQUEST` carrying
    /// `(min, n, max)`.
    pub fn client_request(request: GexRequest) -> (GexClientState, KexInitOut) {
        let mut payload = Vec::with_capacity(1 + 12);
        payload.push(SSH_MSG_KEX_DH_GEX_REQUEST);
        payload.extend_from_slice(&request.min.to_be_bytes());
        payload.extend_from_slice(&request.n.to_be_bytes());
        payload.extend_from_slice(&request.max.to_be_bytes());
        (
            GexClientState {
                request,
                group: None,
                p_bytes: Vec::new(),
                g_bytes: Vec::new(),
                secret: None,
                e_mag: Vec::new(),
            },
            KexInitOut { payload },
        )
    }

    /// Step 2 (server → client): parse the request and emit
    /// `SSH_MSG_KEX_DH_GEX_GROUP` carrying `(p, g)`.
    ///
    /// `select` chooses the group to offer; the default is `group14` for
    /// `n <= 2048` and `group16` for larger requests, but callers can wrap
    /// this to return a custom safe prime per RFC 4419 §3.
    pub fn server_group(
        request_payload: &[u8],
        select: impl FnOnce(GexRequest) -> DhGroup,
    ) -> Result<(GexRequest, DhGroup, KexInitOut)> {
        let mut r = Reader::new(request_payload);
        let msg = r.read_u8()?;
        let request = match msg {
            SSH_MSG_KEX_DH_GEX_REQUEST => {
                let min = r.read_u32()?;
                let n = r.read_u32()?;
                let max = r.read_u32()?;
                GexRequest { min, n, max }
            }
            // SSH_MSG_KEX_DH_GEX_REQUEST_OLD only carries `n`; reuse it as
            // both bounds.
            30 => {
                let n = r.read_u32()?;
                GexRequest { min: n, n, max: n }
            }
            _ => return Err(Error::Protocol("expected SSH_MSG_KEX_DH_GEX_REQUEST")),
        };
        let group = select(request);
        let mut payload = Vec::new();
        payload.push(SSH_MSG_KEX_DH_GEX_GROUP);
        let p_bytes = group.p().to_be_bytes(group.byte_size());
        let g_bytes = group.g().to_be_bytes(group.byte_size());
        encode_mpint_into(&mut payload, &p_bytes);
        encode_mpint_into(&mut payload, &g_bytes);
        Ok((request, group, KexInitOut { payload }))
    }

    /// Step 3 (client → server): parse `SSH_MSG_KEX_DH_GEX_GROUP`, pick a
    /// fresh `x`, and emit `SSH_MSG_KEX_DH_GEX_INIT` carrying `e = g^x mod p`.
    pub fn client_init<R: RngCore + CryptoRng>(
        mut state: GexClientState,
        group_payload: &[u8],
        rng: &mut R,
    ) -> Result<(GexClientState, KexInitOut)> {
        let mut r = Reader::new(group_payload);
        let msg = r.read_u8()?;
        if msg != SSH_MSG_KEX_DH_GEX_GROUP {
            return Err(Error::Protocol("expected SSH_MSG_KEX_DH_GEX_GROUP"));
        }
        let p_raw = read_mpint(&mut r)?;
        let g_raw = read_mpint(&mut r)?;
        let p = BoxedUint::from_be_bytes(strip_leading_zero(p_raw));
        let g = BoxedUint::from_be_bytes(strip_leading_zero(g_raw));

        let bits = p.bit_len();
        if bits < state.request.min as usize || bits > state.request.max as usize {
            return Err(Error::Crypto("GEX group out of requested range"));
        }
        let priv_bits = bits.clamp(160, 512);
        let group = DhGroup::from_custom(p, g, priv_bits)
            .map_err(|_| Error::Format("invalid GEX group"))?;
        let secret = DhPrivateKey::generate(group.clone(), rng);
        let pub_key = secret.public_key();
        let e_mag = pub_key.to_bytes();

        state.p_bytes = strip_leading_zero(p_raw).to_vec();
        state.g_bytes = strip_leading_zero(g_raw).to_vec();
        state.group = Some(group);
        state.secret = Some(secret);
        state.e_mag = e_mag.clone();

        let mut payload = Vec::new();
        payload.push(SSH_MSG_KEX_DH_GEX_INIT);
        encode_mpint_into(&mut payload, &e_mag);
        Ok((state, KexInitOut { payload }))
    }

    /// Step 4 (server → client): parse `SSH_MSG_KEX_DH_GEX_INIT`, agree, sign,
    /// emit `SSH_MSG_KEX_DH_GEX_REPLY`. Returns the `(K, H)` and the wire
    /// payload to send.
    pub fn server_reply<R, S>(
        rng: &mut R,
        request: GexRequest,
        group: &DhGroup,
        init_payload: &[u8],
        host_key: &S,
        ctx: &KexContext<'_>,
    ) -> Result<DhServerReplyOut>
    where
        R: RngCore + CryptoRng,
        S: crate::hostkey::HostKey + ?Sized,
    {
        let mut r = Reader::new(init_payload);
        let msg = r.read_u8()?;
        if msg != SSH_MSG_KEX_DH_GEX_INIT {
            return Err(Error::Protocol("expected SSH_MSG_KEX_DH_GEX_INIT"));
        }
        let e_raw = read_mpint(&mut r)?;
        let peer = DhPublicKey::from_bytes(group.clone(), e_raw)
            .map_err(|_| Error::Format("invalid GEX e"))?;

        let secret = DhPrivateKey::generate(group.clone(), rng);
        let f_pub = secret.public_key();
        let f_mag = f_pub.to_bytes();
        let shared = secret
            .shared_secret(&peer)
            .map_err(|_| Error::Crypto("DH agreement failed"))?;
        // Wipe the locally-materialised raw GEX shared secret on return; the
        // SSH-mpint re-encoding lives on in `KexOutput.k`.
        let k_mag: Zeroizing<Vec<u8>> = Zeroizing::new(shared.into_bytes());
        let p_mag = group.p().to_be_bytes(group.byte_size());
        let g_mag = group.g().to_be_bytes(group.byte_size());

        let k_s = host_key.public_blob();
        let mut eh = ExchangeHash::<Sha256>::new();
        eh.write_string(ctx.v_c);
        eh.write_string(ctx.v_s);
        eh.write_string(ctx.i_c);
        eh.write_string(ctx.i_s);
        eh.write_string(&k_s);
        eh.write_u32(request.min);
        eh.write_u32(request.n);
        eh.write_u32(request.max);
        eh.write_mpint(&p_mag);
        eh.write_mpint(&g_mag);
        eh.write_mpint(e_raw);
        eh.write_mpint(&f_mag);
        eh.write_mpint(&k_mag);
        let h = eh.finalize();

        let sig = host_key.sign(&h)?;

        let mut payload = Vec::new();
        payload.push(SSH_MSG_KEX_DH_GEX_REPLY);
        payload.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
        payload.extend_from_slice(&k_s);
        encode_mpint_into(&mut payload, &f_mag);
        payload.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        payload.extend_from_slice(&sig);

        let k = mpint_bytes(&k_mag);
        Ok(DhServerReplyOut {
            payload,
            kex: KexOutput { k, h },
        })
    }

    /// Step 5 (client side): parse `SSH_MSG_KEX_DH_GEX_REPLY`, verify the
    /// host-key signature on `H`, and return `(K, H)`.
    pub fn client_finish(
        state: GexClientState,
        reply_payload: &[u8],
        verifier: &dyn HostKeyVerify,
        ctx: &KexContext<'_>,
    ) -> Result<KexOutput> {
        let group = state
            .group
            .as_ref()
            .ok_or(Error::Protocol("GEX state missing group"))?;
        let secret = state
            .secret
            .as_ref()
            .ok_or(Error::Protocol("GEX state missing secret"))?;

        let mut r = Reader::new(reply_payload);
        let msg = r.read_u8()?;
        if msg != SSH_MSG_KEX_DH_GEX_REPLY {
            return Err(Error::Protocol("expected SSH_MSG_KEX_DH_GEX_REPLY"));
        }
        let k_s = r.read_string()?;
        let f_raw = read_mpint(&mut r)?;
        let sig = r.read_string()?;

        let peer = DhPublicKey::from_bytes(group.clone(), f_raw)
            .map_err(|_| Error::Format("invalid GEX f"))?;
        let shared = secret
            .shared_secret(&peer)
            .map_err(|_| Error::Crypto("DH agreement failed"))?;
        // Wipe the locally-materialised raw GEX shared secret on return.
        let k_mag: Zeroizing<Vec<u8>> = Zeroizing::new(shared.into_bytes());

        let mut eh = ExchangeHash::<Sha256>::new();
        eh.write_string(ctx.v_c);
        eh.write_string(ctx.v_s);
        eh.write_string(ctx.i_c);
        eh.write_string(ctx.i_s);
        eh.write_string(k_s);
        eh.write_u32(state.request.min);
        eh.write_u32(state.request.n);
        eh.write_u32(state.request.max);
        eh.write_mpint(&state.p_bytes);
        eh.write_mpint(&state.g_bytes);
        eh.write_mpint(&state.e_mag);
        eh.write_mpint(f_raw);
        eh.write_mpint(&k_mag);
        let h = eh.finalize();

        verifier.verify(&h, sig)?;

        let k = mpint_bytes(&k_mag);
        Ok(KexOutput { k, h })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_names() {
        assert_eq!(Group14Sha256::NAME, "diffie-hellman-group14-sha256");
        assert_eq!(Group14Sha256::HASH_LEN, 32);
        assert_eq!(Group16Sha512::NAME, "diffie-hellman-group16-sha512");
        assert_eq!(Group16Sha512::HASH_LEN, 64);
        assert_eq!(Group18Sha512::NAME, "diffie-hellman-group18-sha512");
        assert_eq!(Group18Sha512::HASH_LEN, 64);
        assert_eq!(GexSha256::NAME, "diffie-hellman-group-exchange-sha256");
        assert_eq!(GexSha256::HASH_LEN, 32);
    }

    #[test]
    fn gex_request_payload_layout() {
        let req = GexRequest {
            min: 1024,
            n: 2048,
            max: 8192,
        };
        let (_state, out) = GexSha256::client_request(req);
        assert_eq!(out.payload[0], SSH_MSG_KEX_DH_GEX_REQUEST);
        assert_eq!(&out.payload[1..5], &1024u32.to_be_bytes());
        assert_eq!(&out.payload[5..9], &2048u32.to_be_bytes());
        assert_eq!(&out.payload[9..13], &8192u32.to_be_bytes());
    }

    #[test]
    fn mpint_helpers() {
        let mut v = Vec::new();
        encode_mpint_into(&mut v, &[0x00, 0x80, 0x01]);
        assert_eq!(v, &[0, 0, 0, 3, 0x00, 0x80, 0x01]);
        let mut v = Vec::new();
        encode_mpint_into(&mut v, &[0x00, 0x00, 0x01]);
        assert_eq!(v, &[0, 0, 0, 1, 0x01]);
        let mut v = Vec::new();
        encode_mpint_into(&mut v, &[]);
        assert_eq!(v, &[0, 0, 0, 0]);
    }
}
