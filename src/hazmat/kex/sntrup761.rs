//! Streamlined NTRU Prime `sntrup761`, the key-encapsulation half of the
//! `sntrup761x25519-sha512` hybrid key exchange.
//!
//! A port of the SUPERCOP "compact" reference implementation that OpenSSH
//! ships as `sntrup761.c` (public domain; D. J. Bernstein, C. Chuengsatiansup,
//! T. Lange, C. van Vredendaal). The arithmetic is branch-free on secret
//! data, as in the original: secret-dependent choices are made with masks and
//! the sort of the secret weight vector is a fixed sorting network.

use alloc::vec;
use alloc::vec::Vec;

use purecrypto::hash::{Digest, Sha512};
use purecrypto::rng::{CryptoRng, RngCore};
use purecrypto::zeroize::{Zeroize, Zeroizing};

const P: usize = 761;
const Q: i32 = 4591;
const W: usize = 286;
const Q12: i32 = (Q - 1) / 2;
const HASH_BYTES: usize = 32;
const SMALL_BYTES: usize = P.div_ceil(4);
const ROUNDED_BYTES: usize = 1007;
const SECRET_KEYS_BYTES: usize = 2 * SMALL_BYTES;

/// Public (encapsulation) key length.
pub const PUBLIC_KEY_BYTES: usize = 1158;
/// Secret (decapsulation) key length.
pub const SECRET_KEY_BYTES: usize = SECRET_KEYS_BYTES + PUBLIC_KEY_BYTES + SMALL_BYTES + HASH_BYTES;
/// Ciphertext length.
pub const CIPHERTEXT_BYTES: usize = ROUNDED_BYTES + HASH_BYTES;
/// Shared-secret length.
pub const SHARED_SECRET_BYTES: usize = 32;

type Small = i8;
type Fq = i16;

// ---------------------------------------------------------------------------
// Constant-time helpers
// ---------------------------------------------------------------------------

/// All ones when `x` is negative, else zero.
fn negative_mask(x: i32) -> i32 {
    x >> 31
}

/// All ones when `x` (as a 16-bit value) is nonzero, else zero.
fn nonzero_mask16(x: i32) -> i32 {
    let x = x as i16 as i32;
    negative_mask(x | -x)
}

/// Order `a <= b`, without branching on their values.
fn minmax(a: &mut i32, b: &mut i32) {
    let d = i64::from(*b) - i64::from(*a);
    let swap = (d >> 63) as i32;
    let t = (*a ^ *b) & swap;
    *a ^= t;
    *b ^= t;
}

/// djbsort's portable int32 sorting network (`crypto_sort/int32/portable4`).
fn sort_i32(x: &mut [i32]) {
    let n = x.len();
    if n < 2 {
        return;
    }
    let mut top = 1;
    while top < n - top {
        top += top;
    }
    let mut p = top;
    while p >= 1 {
        let mut i = 0;
        while i + 2 * p <= n {
            for j in i..i + p {
                let (lo, hi) = x.split_at_mut(j + p);
                minmax(&mut lo[j], &mut hi[0]);
            }
            i += 2 * p;
        }
        for j in i..n.saturating_sub(p) {
            let (lo, hi) = x.split_at_mut(j + p);
            minmax(&mut lo[j], &mut hi[0]);
        }

        // Merge `x[j + p]` with `x[j + r]` for r = q, q/2, …, > p.
        let merge = |x: &mut [i32], j: usize, q: usize| {
            let mut a = x[j + p];
            let mut r = q;
            while r > p {
                minmax(&mut a, &mut x[j + r]);
                r >>= 1;
            }
            x[j + p] = a;
        };
        i = 0;
        let mut j = 0;
        let mut q = top;
        'outer: while q > p {
            if j != i {
                loop {
                    if j == n - q {
                        q >>= 1;
                        continue 'outer;
                    }
                    merge(x, j, q);
                    j += 1;
                    if j == i + p {
                        i += 2 * p;
                        break;
                    }
                }
            }
            while i + p <= n - q {
                for jj in i..i + p {
                    merge(x, jj, q);
                }
                i += 2 * p;
            }
            j = i;
            while j < n - q {
                merge(x, j, q);
                j += 1;
            }
            q >>= 1;
        }
        p >>= 1;
    }
}

fn sort_u32(x: &mut [u32]) {
    let mut v: Vec<i32> = x.iter().map(|&e| (e ^ 0x8000_0000) as i32).collect();
    sort_i32(&mut v);
    for (d, s) in x.iter_mut().zip(&v) {
        *d = (*s as u32) ^ 0x8000_0000;
    }
    v.zeroize();
}

// ---------------------------------------------------------------------------
// Arithmetic mod 3 and mod q
// ---------------------------------------------------------------------------

fn f3_freeze(x: i32) -> Small {
    let x = x as i16 as i32;
    (x - 3 * ((10923 * x + 16384) >> 15)) as Small
}

fn fq_freeze(x: i32) -> Fq {
    const Q16: i32 = (0x10000 + Q / 2) / Q;
    const Q20: i32 = (0x10_0000 + Q / 2) / Q;
    const Q28: i32 = (0x1000_0000 + Q / 2) / Q;
    let mut x = x;
    x = x.wrapping_sub(Q.wrapping_mul(Q16.wrapping_mul(x) >> 16));
    x = x.wrapping_sub(Q.wrapping_mul(Q20.wrapping_mul(x) >> 20));
    x.wrapping_sub(Q.wrapping_mul(Q28.wrapping_mul(x).wrapping_add(0x800_0000) >> 28)) as Fq
}

/// Zero when `r` has weight `W`, else all ones.
fn weight_w_mask(r: &[Small]) -> i32 {
    let weight: i32 = r.iter().map(|&c| i32::from(c) & 1).sum();
    nonzero_mask16(weight - W as i32)
}

fn u32_divmod_u14(x: u32, m: u16) -> (u32, u16) {
    let m = u32::from(m);
    let v = 0x8000_0000 / m;
    let mut x = x;
    let mut qpart = ((u64::from(x) * u64::from(v)) >> 31) as u32;
    x = x.wrapping_sub(qpart.wrapping_mul(m));
    let mut quot = qpart;
    qpart = ((u64::from(x) * u64::from(v)) >> 31) as u32;
    x = x.wrapping_sub(qpart.wrapping_mul(m));
    quot = quot.wrapping_add(qpart);
    x = x.wrapping_sub(m);
    quot = quot.wrapping_add(1);
    let mask = negative_mask(x as i32) as u32;
    x = x.wrapping_add(mask & m);
    quot = quot.wrapping_add(mask);
    (quot, x as u16)
}

fn u32_mod_u14(x: u32, m: u16) -> u16 {
    u32_divmod_u14(x, m).1
}

/// Mixed-radix encoding of `r[i] < m[i]`.
fn encode(out: &mut Vec<u8>, r: &[u16], m: &[u16]) {
    let len = r.len();
    if len == 1 {
        let (mut r, mut m) = (r[0], m[0]);
        while m > 1 {
            out.push(r as u8);
            r >>= 8;
            m = (m + 255) >> 8;
        }
        return;
    }
    let half = len.div_ceil(2);
    let mut r2 = vec![0u16; half];
    let mut m2 = vec![0u16; half];
    let mut i = 0;
    while i + 1 < len {
        let m0 = u32::from(m[i]);
        let mut rr = u32::from(r[i]) + u32::from(r[i + 1]) * m0;
        let mut mm = u32::from(m[i + 1]) * m0;
        while mm >= 16384 {
            out.push(rr as u8);
            rr >>= 8;
            mm = (mm + 255) >> 8;
        }
        r2[i / 2] = rr as u16;
        m2[i / 2] = mm as u16;
        i += 2;
    }
    if i < len {
        r2[i / 2] = r[i];
        m2[i / 2] = m[i];
    }
    encode(out, &r2, &m2);
    r2.zeroize();
}

/// Inverse of [`encode`]; `s` holds exactly the encoded bytes (or more).
fn decode(out: &mut [u16], s: &[u8], m: &[u16]) {
    let len = m.len();
    if len == 1 {
        out[0] = if m[0] == 1 {
            0
        } else if m[0] <= 256 {
            u32_mod_u14(u32::from(s[0]), m[0])
        } else {
            u32_mod_u14(u32::from(s[0]) + (u32::from(s[1]) << 8), m[0])
        };
        return;
    }
    let half = len.div_ceil(2);
    let mut r2 = vec![0u16; half];
    let mut m2 = vec![0u16; half];
    let mut bottomr = vec![0u16; len / 2];
    let mut bottomt = vec![0u32; len / 2];
    let mut s = s;
    let mut i = 0;
    while i + 1 < len {
        let mm = u32::from(m[i]) * u32::from(m[i + 1]);
        if mm > 256 * 16383 {
            bottomt[i / 2] = 256 * 256;
            bottomr[i / 2] = u16::from(s[0]) + 256 * u16::from(s[1]);
            s = &s[2..];
            m2[i / 2] = ((((mm + 255) >> 8) + 255) >> 8) as u16;
        } else if mm >= 16384 {
            bottomt[i / 2] = 256;
            bottomr[i / 2] = u16::from(s[0]);
            s = &s[1..];
            m2[i / 2] = ((mm + 255) >> 8) as u16;
        } else {
            bottomt[i / 2] = 1;
            bottomr[i / 2] = 0;
            m2[i / 2] = mm as u16;
        }
        i += 2;
    }
    if i < len {
        m2[i / 2] = m[i];
    }
    decode(&mut r2, s, &m2);
    let mut o = 0;
    i = 0;
    while i + 1 < len {
        let r = u32::from(bottomr[i / 2]) + bottomt[i / 2] * u32::from(r2[i / 2]);
        let (r1, r0) = u32_divmod_u14(r, m[i]);
        out[o] = r0;
        out[o + 1] = u32_mod_u14(r1, m[i + 1]);
        o += 2;
        i += 2;
    }
    if i < len {
        out[o] = r2[i / 2];
    }
    r2.zeroize();
    bottomr.zeroize();
}

fn r3_from_rq(r: &[Fq]) -> Vec<Small> {
    r.iter().map(|&c| f3_freeze(i32::from(c))).collect()
}

/// `h = f * g` in `(Z/3)[x] / (x^p - x - 1)`.
fn r3_mult(f: &[Small], g: &[Small]) -> Vec<Small> {
    let mut fg = vec![0i32; P + P - 1];
    for i in 0..P {
        for j in 0..P {
            fg[i + j] += i32::from(f[i]) * i32::from(g[j]);
        }
    }
    for i in P..P + P - 1 {
        fg[i - P] += fg[i];
        fg[i - P + 1] += fg[i];
    }
    let h = fg[..P].iter().map(|&c| f3_freeze(c)).collect();
    fg.zeroize();
    h
}

/// `out = 1 / in` in R3; returns 0 when invertible, else all ones.
fn r3_recip(out: &mut [Small], input: &[Small]) -> i32 {
    let mut f = [0 as Small; P + 1];
    let mut g = [0 as Small; P + 1];
    let mut v = [0 as Small; P + 1];
    let mut r = [0 as Small; P + 1];
    let mut delta: i32 = 1;
    r[0] = 1;
    f[0] = 1;
    f[P - 1] = -1;
    f[P] = -1;
    for i in 0..P {
        g[P - 1 - i] = input[i];
    }
    for _ in 0..2 * P - 1 {
        for i in (1..=P).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;
        let sign = -i32::from(g[0]) * i32::from(f[0]);
        let swap = negative_mask16(-delta) & nonzero_mask16(i32::from(g[0]));
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for i in 0..=P {
            let t = (swap & (i32::from(f[i]) ^ i32::from(g[i]))) as Small;
            f[i] ^= t;
            g[i] ^= t;
            let t = (swap & (i32::from(v[i]) ^ i32::from(r[i]))) as Small;
            v[i] ^= t;
            r[i] ^= t;
        }
        for i in 0..=P {
            g[i] = f3_freeze(i32::from(g[i]) + sign * i32::from(f[i]));
            r[i] = f3_freeze(i32::from(r[i]) + sign * i32::from(v[i]));
        }
        for i in 0..P {
            g[i] = g[i + 1];
        }
        g[P] = 0;
    }
    let sign = i32::from(f[0]);
    for i in 0..P {
        out[i] = (sign * i32::from(v[P - 1 - i])) as Small;
    }
    f.zeroize();
    g.zeroize();
    v.zeroize();
    r.zeroize();
    nonzero_mask16(delta)
}

fn negative_mask16(x: i32) -> i32 {
    negative_mask(x as i16 as i32)
}

/// `h = f * g` in `(Z/q)[x] / (x^p - x - 1)`, `g` small.
fn rq_mult_small(f: &[Fq], g: &[Small]) -> Vec<Fq> {
    let mut fg = vec![0i32; P + P - 1];
    for i in 0..P {
        for j in 0..P {
            fg[i + j] += i32::from(f[i]) * i32::from(g[j]);
        }
    }
    for i in P..P + P - 1 {
        fg[i - P] += fg[i];
        fg[i - P + 1] += fg[i];
    }
    let h = fg[..P].iter().map(|&c| fq_freeze(c)).collect();
    fg.zeroize();
    h
}

fn fq_recip(a1: Fq) -> Fq {
    let mut ai = a1;
    for _ in 1..Q - 2 {
        ai = fq_freeze(i32::from(a1) * i32::from(ai));
    }
    ai
}

/// `out = 1 / (3 * in)` in Rq; returns 0 when invertible, else all ones.
fn rq_recip3(out: &mut [Fq], input: &[Small]) -> i32 {
    let mut f = [0 as Fq; P + 1];
    let mut g = [0 as Fq; P + 1];
    let mut v = [0 as Fq; P + 1];
    let mut r = [0 as Fq; P + 1];
    let mut delta: i32 = 1;
    r[0] = fq_recip(3);
    f[0] = 1;
    f[P - 1] = -1;
    f[P] = -1;
    for i in 0..P {
        g[P - 1 - i] = Fq::from(input[i]);
    }
    for _ in 0..2 * P - 1 {
        for i in (1..=P).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;
        let swap = negative_mask16(-delta) & nonzero_mask16(i32::from(g[0]));
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for i in 0..=P {
            let t = (swap & (i32::from(f[i]) ^ i32::from(g[i]))) as Fq;
            f[i] ^= t;
            g[i] ^= t;
            let t = (swap & (i32::from(v[i]) ^ i32::from(r[i]))) as Fq;
            v[i] ^= t;
            r[i] ^= t;
        }
        let f0 = i32::from(f[0]);
        let g0 = i32::from(g[0]);
        for i in 0..=P {
            g[i] = fq_freeze(f0 * i32::from(g[i]) - g0 * i32::from(f[i]));
            r[i] = fq_freeze(f0 * i32::from(r[i]) - g0 * i32::from(v[i]));
        }
        for i in 0..P {
            g[i] = g[i + 1];
        }
        g[P] = 0;
    }
    let scale = i32::from(fq_recip(f[0]));
    for i in 0..P {
        out[i] = fq_freeze(scale * i32::from(v[P - 1 - i]));
    }
    f.zeroize();
    g.zeroize();
    v.zeroize();
    r.zeroize();
    nonzero_mask16(delta)
}

fn round(a: &[Fq]) -> Vec<Fq> {
    a.iter()
        .map(|&c| c - Fq::from(f3_freeze(i32::from(c))))
        .collect()
}

fn short_fromlist(input: &[u32]) -> Vec<Small> {
    let mut l: Vec<u32> = input
        .iter()
        .enumerate()
        .map(|(i, &x)| if i < W { x & !1 } else { (x & !3) | 1 })
        .collect();
    sort_u32(&mut l);
    let out = l.iter().map(|&x| (x & 3) as Small - 1).collect();
    l.zeroize();
    out
}

/// The first 32 bytes of `SHA-512(b || input)`.
fn hash_prefix(b: u8, input: &[u8]) -> [u8; HASH_BYTES] {
    let mut h = Sha512::new();
    h.update(&[b]);
    h.update(input);
    let d = h.finalize();
    let mut out = [0u8; HASH_BYTES];
    out.copy_from_slice(&d.as_ref()[..HASH_BYTES]);
    out
}

fn random_u32s<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<Vec<u32>> {
    let mut bytes = Zeroizing::new(vec![0u8; 4 * P]);
    rng.fill_bytes(&mut bytes);
    Zeroizing::new(
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect(),
    )
}

fn short_random<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Small> {
    short_fromlist(&random_u32s(rng))
}

fn small_random<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Small> {
    random_u32s(rng)
        .iter()
        .map(|&x| ((((x & 0x3fff_ffff) * 3) >> 30) as i32 - 1) as Small)
        .collect()
}

fn small_encode(out: &mut Vec<u8>, f: &[Small]) {
    for chunk in f[..P / 4 * 4].as_chunks::<4>().0 {
        let mut x = 0u8;
        for (j, &c) in chunk.iter().enumerate() {
            x = x.wrapping_add(((c + 1) as u8) << (2 * j));
        }
        out.push(x);
    }
    out.push((f[P - 1] + 1) as u8);
}

fn small_decode(s: &[u8]) -> Vec<Small> {
    let mut f = Vec::with_capacity(P);
    for &x in &s[..P / 4] {
        for j in 0..4 {
            f.push(((x >> (2 * j)) & 3) as Small - 1);
        }
    }
    f.push((s[P / 4] & 3) as Small - 1);
    f
}

fn rq_encode(out: &mut Vec<u8>, r: &[Fq]) {
    let rr: Vec<u16> = r.iter().map(|&c| (i32::from(c) + Q12) as u16).collect();
    encode(out, &rr, &[Q as u16; P]);
}

fn rq_decode(s: &[u8]) -> Vec<Fq> {
    let mut r = [0u16; P];
    decode(&mut r, s, &[Q as u16; P]);
    r.iter().map(|&c| (i32::from(c) - Q12) as Fq).collect()
}

fn rounded_encode(out: &mut Vec<u8>, r: &[Fq]) {
    let rr: Vec<u16> = r
        .iter()
        .map(|&c| (((i32::from(c) + Q12) * 10923) >> 15) as u16)
        .collect();
    encode(out, &rr, &[((Q + 2) / 3) as u16; P]);
}

fn rounded_decode(s: &[u8]) -> Vec<Fq> {
    let mut r = [0u16; P];
    decode(&mut r, s, &[((Q + 2) / 3) as u16; P]);
    r.iter().map(|&c| (i32::from(c) * 3 - Q12) as Fq).collect()
}

// ---------------------------------------------------------------------------
// The KEM
// ---------------------------------------------------------------------------

fn hash_confirm(r_enc: &[u8], cache: &[u8]) -> [u8; HASH_BYTES] {
    let mut x = [0u8; 2 * HASH_BYTES];
    x[..HASH_BYTES].copy_from_slice(&hash_prefix(3, r_enc));
    x[HASH_BYTES..].copy_from_slice(cache);
    hash_prefix(2, &x)
}

fn hash_session(b: u8, y: &[u8], z: &[u8]) -> [u8; HASH_BYTES] {
    let mut x = Zeroizing::new(Vec::with_capacity(HASH_BYTES + CIPHERTEXT_BYTES));
    x.extend_from_slice(&hash_prefix(3, y));
    x.extend_from_slice(z);
    hash_prefix(b, &x)
}

/// `c = Encrypt(r, pk) || HashConfirm(r_enc, cache)`; returns `(c, r_enc)`.
fn hide(r: &[Small], pk: &[u8], cache: &[u8]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let mut r_enc = Zeroizing::new(Vec::with_capacity(SMALL_BYTES));
    small_encode(&mut r_enc, r);
    let h = rq_decode(pk);
    let c = round(&rq_mult_small(&h, r));
    let mut out = Vec::with_capacity(CIPHERTEXT_BYTES);
    rounded_encode(&mut out, &c);
    out.extend_from_slice(&hash_confirm(&r_enc, cache));
    (out, r_enc)
}

/// Generate a key pair: `(public key, secret key)`.
pub fn keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let mut ginv = Zeroizing::new(vec![0 as Small; P]);
    let mut g;
    loop {
        g = Zeroizing::new(small_random(rng));
        if r3_recip(&mut ginv, &g) == 0 {
            break;
        }
    }
    let f = Zeroizing::new(short_random(rng));
    let mut finv = Zeroizing::new(vec![0 as Fq; P]);
    rq_recip3(&mut finv, &f);
    let h = rq_mult_small(&finv, &g);

    let mut pk = Vec::with_capacity(PUBLIC_KEY_BYTES);
    rq_encode(&mut pk, &h);
    let mut sk = Zeroizing::new(Vec::with_capacity(SECRET_KEY_BYTES));
    small_encode(&mut sk, &f);
    small_encode(&mut sk, &ginv);
    sk.extend_from_slice(&pk);
    let mut rho = [0u8; SMALL_BYTES];
    rng.fill_bytes(&mut rho);
    sk.extend_from_slice(&rho);
    rho.zeroize();
    sk.extend_from_slice(&hash_prefix(4, &pk));
    debug_assert_eq!((pk.len(), sk.len()), (PUBLIC_KEY_BYTES, SECRET_KEY_BYTES));
    (pk, sk)
}

/// Encapsulate to `pk`: `(ciphertext, shared secret)`. `pk` must be
/// [`PUBLIC_KEY_BYTES`] long.
pub fn encapsulate<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &[u8],
) -> (Vec<u8>, Zeroizing<[u8; SHARED_SECRET_BYTES]>) {
    let cache = hash_prefix(4, pk);
    let r = Zeroizing::new(short_random(rng));
    let (c, r_enc) = hide(&r, pk, &cache);
    let k = Zeroizing::new(hash_session(1, &r_enc, &c));
    (c, k)
}

/// Decapsulate `c` (of [`CIPHERTEXT_BYTES`]) with `sk`. An invalid
/// ciphertext yields a pseudo-random secret (implicit rejection).
pub fn decapsulate(c: &[u8], sk: &[u8]) -> Zeroizing<[u8; SHARED_SECRET_BYTES]> {
    let pk = &sk[SECRET_KEYS_BYTES..SECRET_KEYS_BYTES + PUBLIC_KEY_BYTES];
    let rho = &sk[SECRET_KEYS_BYTES + PUBLIC_KEY_BYTES..][..SMALL_BYTES];
    let cache = &sk[SECRET_KEYS_BYTES + PUBLIC_KEY_BYTES + SMALL_BYTES..][..HASH_BYTES];

    // ZDecrypt.
    let f = Zeroizing::new(small_decode(&sk[..SMALL_BYTES]));
    let v = Zeroizing::new(small_decode(&sk[SMALL_BYTES..]));
    let cq = rounded_decode(&c[..ROUNDED_BYTES]);
    let cf = Zeroizing::new(rq_mult_small(&cq, &f));
    let cf3: Zeroizing<Vec<Fq>> =
        Zeroizing::new(cf.iter().map(|&x| fq_freeze(3 * i32::from(x))).collect());
    let e = Zeroizing::new(r3_from_rq(&cf3));
    let ev = Zeroizing::new(r3_mult(&e, &v));
    let mask = weight_w_mask(&ev) as Small;
    let r: Zeroizing<Vec<Small>> = Zeroizing::new(
        ev.iter()
            .enumerate()
            .map(|(i, &x)| {
                if i < W {
                    ((x ^ 1) & !mask) ^ 1
                } else {
                    x & !mask
                }
            })
            .collect(),
    );

    let (cnew, mut r_enc) = hide(&r, pk, cache);
    let diff = c
        .iter()
        .zip(&cnew)
        .fold(0u16, |acc, (a, b)| acc | u16::from(a ^ b));
    // 0 when equal, all ones when not.
    let mask = (((i32::from(diff) - 1) >> 8) & 1) - 1;
    for (x, &rh) in r_enc.iter_mut().zip(rho) {
        *x ^= (mask as u8) & (*x ^ rh);
    }
    Zeroizing::new(hash_session((1 + mask) as u8, &r_enc, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::HmacDrbg;

    fn rng(seed: u8) -> HmacDrbg<purecrypto::hash::Sha256> {
        HmacDrbg::new(&[seed; 32], &[], &[])
    }

    #[test]
    fn sort_matches_std() {
        let mut r = rng(1);
        for n in [0usize, 1, 2, 3, 7, 64, 100, 761] {
            let mut v: Vec<i32> = (0..n).map(|_| r.next_u32() as i32).collect();
            let mut want = v.clone();
            want.sort();
            sort_i32(&mut v);
            assert_eq!(v, want, "n = {n}");
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut r = rng(2);
        let h: Vec<Fq> = (0..P)
            .map(|_| ((r.next_u32() % Q as u32) as i32 - Q12) as Fq)
            .collect();
        let mut s = Vec::new();
        rq_encode(&mut s, &h);
        assert_eq!(s.len(), PUBLIC_KEY_BYTES);
        assert_eq!(rq_decode(&s), h);
    }

    #[test]
    fn kem_roundtrip() {
        let mut r = rng(3);
        let (pk, sk) = keypair(&mut r);
        let (c, k) = encapsulate(&mut r, &pk);
        assert_eq!(c.len(), CIPHERTEXT_BYTES);
        assert_eq!(*decapsulate(&c, &sk), *k);
        // A tampered ciphertext decapsulates to something else.
        let mut bad = c.clone();
        bad[5] ^= 1;
        assert_ne!(*decapsulate(&bad, &sk), *k);
    }
}
