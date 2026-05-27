# puressh

A pure-Rust [SSH](https://datatracker.ietf.org/doc/html/rfc4251) (Secure Shell)
protocol library in the spirit of [libssh](https://www.libssh.org/), built on
[`purecrypto`](https://crates.io/crates/purecrypto) for every cryptographic
primitive. No `unsafe`, no C dependencies, no FFI.

> **Status: scaffolding.** The wire format, transport-layer module split, and
> cipher/MAC/host-key catalogues are in place; concrete state machines and
> network I/O are still being filled in. See [Implementation status](#implementation-status).

## Goals

- **Pure Rust, no FFI.** Crypto comes from `purecrypto`; networking comes from
  `std::net` (or any I/O trait the user wires up).
- **`no_std` friendly.** The core packet codec, KEX state, and cipher adapters
  build without `std`; only the convenience I/O layer requires it.
- **Modern algorithms first.** `curve25519-sha256`, `chacha20-poly1305@openssh.com`,
  `ssh-ed25519`. Older algorithms are added only where they remain useful for
  interop.
- **Auditable surface.** Small modules, narrow public types, every algorithm
  identifier tracked back to its RFC.

## Supported algorithms

| Category   | Algorithm                                | Status |
|------------|------------------------------------------|--------|
| KEX        | `curve25519-sha256`, `curve25519-sha256@libssh.org` | planned |
| KEX        | `ecdh-sha2-nistp{256,384,521}`           | planned |
| Host key   | `ssh-ed25519`                            | planned |
| Host key   | `ecdsa-sha2-nistp{256,384,521}`          | planned |
| Host key   | `rsa-sha2-256`, `rsa-sha2-512`           | blocked on upstream (see [gaps](#purecrypto-gaps)) |
| Cipher     | `chacha20-poly1305@openssh.com`          | planned |
| Cipher     | `aes{128,256}-gcm@openssh.com`           | planned |
| Cipher     | `aes{128,192,256}-ctr`                   | planned |
| MAC        | `hmac-sha2-{256,512}` (+ `-etm` variants) | planned |
| Compression| `none`                                   | planned |
| Auth       | `none`, `password`, `publickey`          | planned |

## Cargo features

| Feature   | Default | Description                              |
|-----------|---------|------------------------------------------|
| `std`     | yes     | I/O helpers, OS RNG, `std::error::Error` |
| `alloc`   | yes     | Heap-backed types (implied by `std`)     |
| `client`  | yes     | High-level client API                    |
| `server`  | yes     | High-level server API                    |

Disable defaults for `no_std`:

```toml
puressh = { version = "0.0.1", default-features = false, features = ["alloc"] }
```

## Quick start

> The code below shows the intended API. It does not work yet — most calls
> still return `Error::Unsupported`. Watch the implementation-status section.

```rust,ignore
use puressh::client::{Client, Config};

let mut c = Client::connect("example.com:22", Config::default())?;
c.authenticate_password("alice", "hunter2")?;
let mut sess = c.open_session()?;
sess.exec("uname -a")?;
let out = sess.read_stdout_to_end()?;
println!("{}", String::from_utf8_lossy(&out));
```

## Module layout

```
src/
├── lib.rs           public re-exports
├── error.rs         Error / Result
├── format/          SSH wire format (Reader, Writer, mpint, name-list)
├── transport/       binary packet protocol, version exchange, KEX init
├── kex/             curve25519, ecdh-nistp*
├── cipher/          aes-ctr, aes-gcm, chacha20-poly1305
├── mac/             hmac-sha2-* (incl. -etm)
├── hostkey/         ed25519, ecdsa-*, rsa-* (blocked)
├── auth/            userauth state machine
├── channel/         RFC 4254 channels
├── key/             OpenSSH public/private key files
├── client.rs        high-level client API (feature `client`)
└── server.rs        high-level server API (feature `server`)
```

## MSRV

`puressh` follows `purecrypto`'s MSRV: **Rust 1.95** (edition 2024).
If `cargo check` fails with *"rustc X is not supported … requires rustc 1.95"*,
upgrade your toolchain.

## Implementation status

| Layer                    | Status |
|--------------------------|--------|
| Wire format (`format/`)  | ✅ reader, writer, mpint, name-list |
| Module layout            | ✅ |
| Algorithm catalogues     | ✅ cipher/mac/hostkey/kex tables wired |
| Binary packet codec      | 🚧 stub — `Error::Unsupported` |
| Version exchange         | ✅ encode + parse |
| KEX state machine        | ⏳ planned |
| Cipher adapters          | ⏳ planned (mapped to `purecrypto::cipher`) |
| MAC adapters             | ⏳ planned (mapped to `purecrypto::hash::Hmac*`) |
| Ed25519 host keys        | ⏳ planned (mapped to `purecrypto::ec::ed25519`) |
| ECDSA host keys          | ⏳ planned (mapped to `purecrypto::ec::boxed`) |
| RSA host keys            | ❌ blocked — see [gaps](#purecrypto-gaps) |
| OpenSSH key file parsing | ⏳ planned (encrypted keys blocked) |
| Userauth                 | ⏳ planned |
| Channels / sessions      | ⏳ planned |
| Client API               | 🚧 stub |
| Server API               | 🚧 stub |

## purecrypto gaps

`purecrypto` (currently v0.0.7) gives us essentially everything modern SSH
needs for KEX, AEAD ciphers, and `ssh-ed25519` / `ecdsa-sha2-nistp*` host keys.
The following pieces are **not yet exposed upstream**, and `puressh` will need
either upstream additions or a thin local fallback for each.

### 1. RSA operations (`rsa-sha2-256`, `rsa-sha2-512`, `ssh-rsa`) — **blocking**

`purecrypto::rsa` currently only exposes `is_prime`, `random_prime`, and the
bare key structs (`RsaPublicKey`, `RsaPrivateKey`, `BoxedRsaPublicKey`,
`BoxedRsaPrivateKey`) plus a `Pkcs1Digest` trait. No public surface for:

- PKCS#1 v1.5 sign / verify (needed for all three SSH RSA algorithms)
- Key generation (needed if we ever issue host keys)
- Modular exponentiation entry points to build sign/verify on top
- PKCS#1 / PKCS#8 / SubjectPublicKeyInfo encode/decode
- OAEP / PSS (not needed by SSH, but useful elsewhere)

**Impact:** SSH host-key and publickey-auth algorithms `ssh-rsa`,
`rsa-sha2-256`, `rsa-sha2-512` cannot be implemented. These remain the most
common keys on existing servers, so this is the largest interop gap. Modules
under `hostkey::rsa` are kept as type-level placeholders so the algorithm
identifiers are reserved.

**Asks of `purecrypto`:**

- `BoxedRsaPrivateKey::sign_pkcs1v15<H: Pkcs1Digest>(&self, msg: &[u8]) -> Vec<u8>`
- `BoxedRsaPublicKey::verify_pkcs1v15<H: Pkcs1Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<()>`
- `BoxedRsaPublicKey::from_components(n: &[u8], e: &[u8]) -> Result<Self>`
- `BoxedRsaPublicKey::components(&self) -> (Vec<u8>, Vec<u8>)`
- Key generation `BoxedRsaPrivateKey::generate(bits: usize, rng) -> Result<Self>`

### 2. `bcrypt_pbkdf` for encrypted OpenSSH private keys

The OpenSSH "new" private-key format (`openssh-key-v1`) optionally encrypts the
secret block with a symmetric cipher whose key is derived via
[`bcrypt_pbkdf`](https://flak.tedunangst.com/post/bcrypt-pbkdf) — a custom KDF
built on bcrypt's Blowfish core. `purecrypto::kdf` exposes PBKDF2, HKDF,
Argon2 (RFC 9106), and scrypt, but not `bcrypt_pbkdf`.

**Impact:** `puressh` will be able to load OpenSSH keys that are stored
unencrypted, but **not** password-protected ones — which is the OpenSSH default
since 7.8. This is a UX issue for the client side specifically.

**Asks of `purecrypto`:** a `kdf::bcrypt_pbkdf(passphrase, salt, rounds, out)`
function (or expose a Blowfish primitive we can build it on).

### 3. Finite-field Diffie-Hellman (group14, group16, group-exchange)

Modern SSH defaults are ECDH-based, but `diffie-hellman-group14-sha256` and
`diffie-hellman-group-exchange-sha256` still show up on legacy servers.
`purecrypto::bignum` is "constant-time big-integer arithmetic," which is the
heavy lifting, but no DH module is currently exposed.

**Impact:** No interop with very old SSH servers that don't speak ECDH KEX.
Acceptable for a v0; worth flagging for a future release.

**Asks of `purecrypto`:** a `dh` module exposing modular exponentiation on the
SSH MODP groups (RFC 3526), or just `bignum::ModPow` exported publicly so we
can implement DH ourselves.

### 4. Streaming hash interface — confirm coverage

The KEX exchange-hash computation feeds a fairly large blob (`V_C || V_S ||
I_C || I_S || K_S || …`) into a single hash. `purecrypto::hash::Digest` is
documented as supporting `new` / `update` / `finalize`, which is exactly what
we need — listing this only to flag that we depend on it; no upstream change
required.

### 5. Per-curve ECDSA wire-format helpers — nice to have

For `ecdsa-sha2-nistp*`, SSH wire format requires `(r, s)` as a pair of
`mpint`s. `purecrypto::ec::boxed::BoxedEcdsaSignature` exists but its
documented surface doesn't yet show component accessors. We'll do this from
the outside if needed, but a `signature.components() -> (Vec<u8>, Vec<u8>)`
helper would make the SSH adapter trivial.

---

Everything else (AES-CTR, AES-GCM, ChaCha20-Poly1305, HMAC-SHA2, Ed25519,
ECDH/ECDSA over P-256/P-384/P-521, X25519, SHA-1/2/3 family, OS RNG) is
already in `purecrypto` and can be wired directly.

## License

Dual-licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
