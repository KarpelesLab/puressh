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
| KEX        | `diffie-hellman-group{14,16,18}-sha{256,512}` | planned |
| KEX        | `diffie-hellman-group-exchange-sha256`   | planned |
| Host key   | `ssh-ed25519`                            | planned |
| Host key   | `ecdsa-sha2-nistp{256,384,521}`          | planned |
| Host key   | `rsa-sha2-256`, `rsa-sha2-512`, `ssh-rsa` | planned |
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
| RSA host keys            | ⏳ planned (mapped to `purecrypto::rsa::Boxed*`) |
| OpenSSH key file parsing | ⏳ planned (encrypted keys via `purecrypto::kdf::bcrypt_pbkdf`) |
| Userauth                 | ⏳ planned |
| Channels / sessions      | ⏳ planned |
| Client API               | 🚧 stub |
| Server API               | 🚧 stub |

## purecrypto coverage

As of `purecrypto` 0.1.1 every primitive SSH needs is upstream:

| SSH need                                | `purecrypto` entry point |
|-----------------------------------------|--------------------------|
| Modern KEX                              | `ec::x25519`, `ec::ecdh` (NIST P-256), `ec::boxed` (P-256/384/521) |
| Legacy KEX (MODP-DH)                    | `dh::{DhPrivateKey, DhPublicKey, group14, group16, group18}` (RFC 3526 + RFC 4419 GEX) |
| Host-key signatures                     | `ec::ed25519`, `ec::boxed` (ECDSA), `rsa::Boxed*::{sign,verify}_pkcs1v15` |
| AEAD ciphers                            | `cipher::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305}` |
| CTR ciphers                             | `cipher::{Ctr, Aes128, Aes192, Aes256}` |
| MACs                                    | `hash::{HmacSha256, HmacSha512}` |
| Exchange-hash construction              | `hash::Digest` streaming API |
| Encrypted OpenSSH private keys          | `kdf::bcrypt_pbkdf` |
| OS entropy                              | `rng::OsRng` |
| Key-file DER/PEM (RSA in PKCS#1)        | `rsa::Boxed*::{from,to}_pkcs1_{der,pem}` |

A few SSH-specific shaping needs are done inside `puressh` itself rather than
asked of upstream:

- **ECDSA `(r, s)` splitting** — SSH wire format wants the two
  components as separate `mpint`s; `BoxedEcdsaSignature` doesn't expose an
  accessor, so we re-encode locally.
- **SSH-flavoured RSA wire format** — public keys are `string "ssh-rsa" ||
  mpint e || mpint n`, built from `BoxedRsaPublicKey::try_new(n, e)` and
  decomposed back via `modulus()` plus a tracked `e` we hold alongside.

No upstream blockers remain.

## License

Dual-licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
