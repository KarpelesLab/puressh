//! `mlkem768nistp256-sha256` — hybrid post-quantum key exchange combining
//! ML-KEM-768 (FIPS 203) with ECDH on NIST P-256, hashed under SHA-256.
//!
//! OpenSSH 10.6 implements it (`kexmlkem768ecdh.c`) but leaves it out of the
//! default `KexAlgorithms`: it is only used when configured. The flow is that
//! of [`super::mlkem768x25519`] with the X25519 half replaced by P-256:
//!
//! ```text
//!   client -> server: SSH_MSG_KEX_HYBRID_INIT (30)
//!     string  C_INIT = ek_pq (1184 B) || Q_C (65 B)   [= 1249 B]
//!
//!   server -> client: SSH_MSG_KEX_HYBRID_REPLY (31)
//!     string  K_S                 (host-key blob)
//!     string  S_REPLY = ct_pq (1088 B) || Q_S (65 B)  [= 1153 B]
//!     string  signature           (signature over the exchange hash H)
//! ```
//!
//! `Q_C` / `Q_S` are uncompressed SEC1 points (`0x04 || X || Y`), as in
//! `ecdh-sha2-nistp256`, but without their own length prefix. The shared
//! secret is `K = SHA256(K_PQ || K_ECDH)` where `K_PQ` is the 32-byte
//! ML-KEM-768 shared secret and `K_ECDH` the raw 32-byte affine X-coordinate
//! of the P-256 agreement. As for the X25519 hybrid, `K` is encoded as an
//! SSH `string` (not an `mpint`) in both `H` and the RFC 4253 §7.2 KDF.
//!
//! A bad ML-KEM ciphertext never errors (implicit rejection) and only shows
//! up as a host-key signature failure; a P-256 point off the curve is
//! refused as a format error before any secret is derived, as OpenSSH's
//! `sshkey_ec_validate_public` does.

use alloc::vec::Vec;

use purecrypto::ec::boxed::{BoxedEcdhPrivateKey, BoxedEcdsaPublicKey};
use purecrypto::ec::curves::CurveId;
use purecrypto::hash::{Digest, Sha256};
use purecrypto::mlkem::{
    MlKem768Ciphertext, MlKem768DecapsKey, MlKem768EncapsKey, SHARED_SECRET_BYTES,
};
use purecrypto::rng::{CryptoRng, RngCore};
use purecrypto::zeroize::Zeroizing;

use super::Kex;
use super::common::{
    KexContext, KexInitOut, KexOutput, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY,
};
use super::hash::ExchangeHash;
use crate::error::{Error, Result};
use crate::format::Reader;
use crate::hostkey::HostKeyVerify;

/// Marker type implementing the `mlkem768nistp256-sha256` KEX.
pub struct MlKem768Nistp256Sha256;

impl Kex for MlKem768Nistp256Sha256 {
    const NAME: &'static str = "mlkem768nistp256-sha256";
    const HASH_LEN: usize = 32;
}

/// Byte length of the ML-KEM-768 encapsulation key on the wire.
const EK_PQ_LEN: usize = MlKem768DecapsKey::ENCAPS_KEY_BYTES; // 1184
/// Byte length of an ML-KEM-768 ciphertext on the wire.
const CT_PQ_LEN: usize = MlKem768DecapsKey::CIPHERTEXT_BYTES; // 1088
/// Byte length of an uncompressed P-256 point (`0x04 || X || Y`).
const P256_POINT_LEN: usize = 1 + 2 * 32;
/// Byte length of `C_INIT = ek_pq || Q_C` (1184 + 65).
const C_INIT_LEN: usize = EK_PQ_LEN + P256_POINT_LEN;
/// Byte length of `S_REPLY = ct_pq || Q_S` (1088 + 65).
const S_REPLY_LEN: usize = CT_PQ_LEN + P256_POINT_LEN;

impl MlKem768Nistp256Sha256 {
    /// Algorithm name (`mlkem768nistp256-sha256`).
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
    /// P-256 ephemeral secret matching the point embedded in `c_init`.
    ec_secret: BoxedEcdhPrivateKey,
    /// ML-KEM-768 decapsulation key matching the EK embedded in `c_init`.
    pq_secret: MlKem768DecapsKey,
    /// The exact 1249-byte `C_INIT` blob sent on the wire.
    c_init: Vec<u8>,
}

/// Server-side output of [`MlKem768Nistp256Sha256::server_reply`]: the wire
/// payload to send and the already-computed `(K, H)` pair.
pub struct ServerReplyOut {
    /// `SSH_MSG_KEX_HYBRID_REPLY` payload (message-type byte included).
    pub payload: Vec<u8>,
    /// The shared secret + exchange hash, ready for the KDF.
    pub kex: KexOutput,
}

/// `SHA256(K_PQ || K_ECDH)`, wrapped in `Zeroizing`.
fn combine_secrets(k_pq: &[u8; SHARED_SECRET_BYTES], k_ecdh: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(k_pq);
    h.update(k_ecdh);
    let digest = h.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(digest.as_ref());
    out
}

/// Encode the 32-byte hybrid shared secret `K` as an SSH `string` (see the
/// module docs): length 32, then the digest verbatim.
fn k_string_bytes(k: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&(k.len() as u32).to_be_bytes());
    out.extend_from_slice(k);
    out
}

/// The raw P-256 agreement of `secret` with the uncompressed point `peer`
/// (validated on the curve), as a 32-byte X-coordinate.
fn p256_agree(secret: &BoxedEcdhPrivateKey, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, peer)
        .map_err(|_| Error::Format("invalid hybrid ECDH point"))?;
    Ok(Zeroizing::new(secret.diffie_hellman(&peer).map_err(
        |_| Error::Crypto("hybrid KEX agreement failed"),
    )?))
}

/// The exchange hash over the transcript, `K` `string`-encoded.
fn exchange_hash(
    ctx: &KexContext<'_>,
    k_s: &[u8],
    c_init: &[u8],
    s_reply: &[u8],
    k: &[u8; 32],
) -> Vec<u8> {
    let mut eh = ExchangeHash::<Sha256>::new();
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

/// Build the client state and `SSH_MSG_KEX_HYBRID_INIT` from given keys.
fn client_init_with(
    pq_secret: MlKem768DecapsKey,
    pq_public: &MlKem768EncapsKey,
    ec_secret: BoxedEcdhPrivateKey,
) -> (ClientState, KexInitOut) {
    let mut c_init = Vec::with_capacity(C_INIT_LEN);
    c_init.extend_from_slice(&pq_public.to_bytes());
    c_init.extend_from_slice(&ec_secret.public_key().to_sec1());
    debug_assert_eq!(c_init.len(), C_INIT_LEN);

    let mut payload = Vec::with_capacity(1 + 4 + C_INIT_LEN);
    payload.push(SSH_MSG_KEX_ECDH_INIT);
    payload.extend_from_slice(&(C_INIT_LEN as u32).to_be_bytes());
    payload.extend_from_slice(&c_init);

    (
        ClientState {
            ec_secret,
            pq_secret,
            c_init,
        },
        KexInitOut { payload },
    )
}

/// The server half, with its P-256 ephemeral and the ML-KEM encapsulation
/// supplied (randomly in [`MlKem768Nistp256Sha256::server_reply`], fixed in
/// the known-answer test).
fn server_reply_with<S, E>(
    ec_secret: BoxedEcdhPrivateKey,
    encapsulate: E,
    init_payload: &[u8],
    host_key: &S,
    ctx: &KexContext<'_>,
) -> Result<ServerReplyOut>
where
    S: crate::hostkey::HostKey + ?Sized,
    E: FnOnce(&MlKem768EncapsKey) -> (MlKem768Ciphertext, [u8; SHARED_SECRET_BYTES]),
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
    let (ek_bytes, q_c) = c_init.split_at(EK_PQ_LEN);
    let mut ek_arr = [0u8; EK_PQ_LEN];
    ek_arr.copy_from_slice(ek_bytes);
    // FIPS 203 §7.2 EK validation (see `mlkem768x25519`).
    let ek = MlKem768EncapsKey::from_bytes_validated(ek_arr)
        .map_err(|_| Error::Crypto("hybrid KEX agreement failed"))?;

    // The P-256 half first: a bad client point fails before encapsulating.
    let k_ecdh = p256_agree(&ec_secret, q_c)?;
    let (ct, k_pq) = encapsulate(&ek);
    let k_pq = Zeroizing::new(k_pq);
    let k_combined = combine_secrets(&k_pq, &k_ecdh);

    let mut s_reply = Vec::with_capacity(S_REPLY_LEN);
    s_reply.extend_from_slice(&ct.to_bytes());
    s_reply.extend_from_slice(&ec_secret.public_key().to_sec1());
    debug_assert_eq!(s_reply.len(), S_REPLY_LEN);

    let k_s = host_key.public_blob();
    let h = exchange_hash(ctx, &k_s, c_init, &s_reply, &k_combined);
    let sig = host_key.sign(&h)?;

    let mut payload = Vec::with_capacity(1 + 4 + k_s.len() + 4 + s_reply.len() + 4 + sig.len());
    payload.push(SSH_MSG_KEX_ECDH_REPLY);
    payload.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
    payload.extend_from_slice(&k_s);
    payload.extend_from_slice(&(s_reply.len() as u32).to_be_bytes());
    payload.extend_from_slice(&s_reply);
    payload.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    payload.extend_from_slice(&sig);

    let k = k_string_bytes(&k_combined);
    Ok(ServerReplyOut {
        payload,
        kex: KexOutput { k, h },
    })
}

impl MlKem768Nistp256Sha256 {
    /// Generate the client's ephemerals (P-256 + ML-KEM-768) and produce
    /// the `SSH_MSG_KEX_HYBRID_INIT` payload.
    pub fn client_init<R: RngCore + CryptoRng>(rng: &mut R) -> (ClientState, KexInitOut) {
        let ec_secret = BoxedEcdhPrivateKey::generate(CurveId::P256, rng);
        let (pq_secret, pq_public) = MlKem768DecapsKey::generate(rng);
        client_init_with(pq_secret, &pq_public, ec_secret)
    }

    /// Parse a client `SSH_MSG_KEX_HYBRID_INIT`, encapsulate to its ML-KEM
    /// key and agree with its P-256 point using fresh server ephemerals,
    /// sign the exchange hash with the host key, and assemble the
    /// `SSH_MSG_KEX_HYBRID_REPLY` payload.
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
        let ec_secret = BoxedEcdhPrivateKey::generate(CurveId::P256, rng);
        server_reply_with(
            ec_secret,
            |ek| ek.encapsulate(rng),
            init_payload,
            host_key,
            ctx,
        )
    }

    /// Parse the server's `SSH_MSG_KEX_HYBRID_REPLY`, decapsulate the ML-KEM
    /// ciphertext, agree with the server's P-256 point, verify the host-key
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
            return Err(Error::Protocol("expected SSH_MSG_KEX_HYBRID_REPLY"));
        }
        let k_s = r.read_string()?;
        let s_reply = r.read_string()?;
        if s_reply.len() != S_REPLY_LEN {
            return Err(Error::Format("hybrid S_REPLY wrong length"));
        }
        let sig = r.read_string()?;

        let (ct_bytes, q_s) = s_reply.split_at(CT_PQ_LEN);
        let k_ecdh = p256_agree(&state.ec_secret, q_s)?;
        let mut ct_arr = [0u8; CT_PQ_LEN];
        ct_arr.copy_from_slice(ct_bytes);
        // Implicit rejection: a bad ciphertext yields a pseudo-random K_PQ
        // and so a signature failure below.
        let k_pq = Zeroizing::new(
            state
                .pq_secret
                .decapsulate(&MlKem768Ciphertext::from_bytes(ct_arr)),
        );
        let k_combined = combine_secrets(&k_pq, &k_ecdh);

        let h = exchange_hash(ctx, k_s, &state.c_init, s_reply, &k_combined);
        verifier.verify(&h, sig)?;

        let k = k_string_bytes(&k_combined);
        Ok(KexOutput { k, h })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::{Ed25519HostKey, HostKey};
    use purecrypto::rng::HmacDrbg;

    const V_C: &[u8] = b"SSH-2.0-OpenSSH_10.6";
    const V_S: &[u8] = b"SSH-2.0-puressh_test";
    const I_C: &[u8] = &[0x14, 0x11, 0x22, 0x33];
    const I_S: &[u8] = &[0x14, 0x44, 0x55, 0x66];

    fn ctx() -> KexContext<'static> {
        KexContext {
            v_c: V_C,
            v_s: V_S,
            i_c: I_C,
            i_s: I_S,
        }
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(Sha256::digest(data).as_ref());
        out
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn algorithm_constants() {
        assert_eq!(MlKem768Nistp256Sha256::NAME, "mlkem768nistp256-sha256");
        assert_eq!(MlKem768Nistp256Sha256::HASH_LEN, 32);
        assert_eq!(MlKem768Nistp256Sha256::C_INIT_LEN, 1249);
        assert_eq!(MlKem768Nistp256Sha256::S_REPLY_LEN, 1153);
    }

    #[test]
    fn round_trip_shared_secret_matches() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mlkem-p256-roundtrip", b"nonce", &[]);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let server_hk = Ed25519HostKey::from_seed(seed);
        let verifier = Ed25519HostKey::from_public(server_hk.public_bytes());

        let (state, init) = MlKem768Nistp256Sha256::client_init(&mut rng);
        assert_eq!(init.payload.len(), 1 + 4 + C_INIT_LEN);
        assert_eq!(init.payload[5 + EK_PQ_LEN], 0x04, "uncompressed Q_C");
        let reply =
            MlKem768Nistp256Sha256::server_reply(&mut rng, &init.payload, &server_hk, &ctx())
                .expect("server_reply");
        let client =
            MlKem768Nistp256Sha256::client_finish(state, &reply.payload, &verifier, &ctx())
                .expect("client_finish");
        assert_eq!(client.k, reply.kex.k);
        assert_eq!(client.h, reply.kex.h);
        assert_eq!(client.h.len(), 32);
        // `string`-framed K: 4-byte length 32, then the digest.
        assert_eq!(client.k.len(), 4 + 32);
        assert_eq!(&client.k[..4], &32u32.to_be_bytes());
    }

    /// Fixed inputs, with `K` and `H` checked against values computed
    /// independently (Python `cryptography` 50 on OpenSSL 3.5: ML-KEM-768
    /// key generation from the `d || z` seed and decapsulation of the
    /// ciphertext below, P-256 ECDH of the client scalar with `Q_S`, then
    /// `SHA256(K_PQ || K_ECDH)` and the SHA-256 exchange hash).
    #[test]
    fn known_answer() {
        let d = [0x11u8; 32];
        let z = [0x22u8; 32];
        let m = [0x33u8; 32];
        let client_scalar = [0x44u8; 32];
        let server_scalar = [0x55u8; 32];
        let host_key = Ed25519HostKey::from_seed([0x66u8; 32]);
        let verifier = Ed25519HostKey::from_public(host_key.public_bytes());

        let (pq_secret, pq_public) = MlKem768DecapsKey::from_seeds(&d, &z);
        let ec_client = BoxedEcdhPrivateKey::from_bytes(CurveId::P256, &client_scalar).unwrap();
        let (state, init) = client_init_with(pq_secret, &pq_public, ec_client);
        let ec_server = BoxedEcdhPrivateKey::from_bytes(CurveId::P256, &server_scalar).unwrap();
        let reply = server_reply_with(
            ec_server,
            |ek| ek.encapsulate_deterministic(&m),
            &init.payload,
            &host_key,
            &ctx(),
        )
        .expect("server_reply");
        let client =
            MlKem768Nistp256Sha256::client_finish(state, &reply.payload, &verifier, &ctx())
                .expect("client_finish");

        assert_eq!(
            sha256(&init.payload[5..]).to_vec(),
            hex("64e17e1ef8bf4128cfab252bb525d38f7e0ba6bcdd5605c4404c8af890f0e82b"),
            "C_INIT"
        );
        let mut r = Reader::new(&reply.payload[1..]);
        let _k_s = r.read_string().unwrap();
        let s_reply = r.read_string().unwrap();
        assert_eq!(
            s_reply[CT_PQ_LEN..].to_vec(),
            hex(concat!(
                "0457e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34",
                "c5ab3770ba573bdff5414065640ffb5b346dfa84dec4db4d68e5f59cc471c2ec"
            )),
            "Q_S"
        );
        assert_eq!(
            sha256(s_reply).to_vec(),
            hex("0db5d05722b3a085e4e8ab41a589a221be267be6a1a06e6b5e95bb34fcf5089c"),
            "S_REPLY"
        );
        assert_eq!(
            client.k[4..].to_vec(),
            hex("d63fd495a708a68755391564d39dc0f169168cc4718c7e3ae946854037ee94fb"),
            "K"
        );
        assert_eq!(
            client.h,
            hex("6ea7f4188987d8289e3c9f18b223016accb3ce570d0e94ab963eecebc5b574e4"),
            "H"
        );
        assert_eq!(reply.kex.k, client.k);
        assert_eq!(reply.kex.h, client.h);
    }

    #[test]
    fn wrong_lengths_rejected() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mlkem-p256-bad", b"nonce", &[]);
        let host_key = Ed25519HostKey::from_seed([7u8; 32]);
        let verifier = Ed25519HostKey::from_public(host_key.public_bytes());

        let mut bad = alloc::vec![SSH_MSG_KEX_ECDH_INIT];
        bad.extend_from_slice(&100u32.to_be_bytes());
        bad.extend_from_slice(&[0u8; 100]);
        assert!(matches!(
            MlKem768Nistp256Sha256::server_reply(&mut rng, &bad, &host_key, &ctx()).map(|_| ()),
            Err(Error::Format("hybrid C_INIT wrong length"))
        ));

        let (state, _init) = MlKem768Nistp256Sha256::client_init(&mut rng);
        let k_s = host_key.public_blob();
        let mut reply = alloc::vec![SSH_MSG_KEX_ECDH_REPLY];
        for field in [&k_s[..], &[0u8; 200][..], &[0u8; 64][..]] {
            reply.extend_from_slice(&(field.len() as u32).to_be_bytes());
            reply.extend_from_slice(field);
        }
        assert!(matches!(
            MlKem768Nistp256Sha256::client_finish(state, &reply, &verifier, &ctx()).map(|_| ()),
            Err(Error::Format("hybrid S_REPLY wrong length"))
        ));
    }

    #[test]
    fn point_off_curve_rejected() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mlkem-p256-off", b"nonce", &[]);
        let host_key = Ed25519HostKey::from_seed([8u8; 32]);
        let (_state, mut init) = MlKem768Nistp256Sha256::client_init(&mut rng);
        // Flip a bit of Q_C's Y coordinate: no longer on P-256.
        let last = init.payload.len() - 1;
        init.payload[last] ^= 1;
        assert!(matches!(
            MlKem768Nistp256Sha256::server_reply(&mut rng, &init.payload, &host_key, &ctx())
                .map(|_| ()),
            Err(Error::Format("invalid hybrid ECDH point"))
        ));
        // A compressed point of the right total length is no better.
        let (_state, mut init) = MlKem768Nistp256Sha256::client_init(&mut rng);
        init.payload[5 + EK_PQ_LEN] = 0x02;
        assert!(
            MlKem768Nistp256Sha256::server_reply(&mut rng, &init.payload, &host_key, &ctx())
                .is_err()
        );
    }
}
