# puressh

[![CI](https://github.com/KarpelesLab/puressh/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/puressh/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/puressh.svg)](https://crates.io/crates/puressh)
[![Docs.rs](https://docs.rs/puressh/badge.svg)](https://docs.rs/puressh)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A pure-Rust [SSH](https://datatracker.ietf.org/doc/html/rfc4251) (Secure Shell)
protocol library and CLI suite, in the spirit of [libssh](https://www.libssh.org/),
built on [`purecrypto`](https://crates.io/crates/purecrypto) for every
cryptographic primitive. No C dependencies, no FFI in the dependency tree, and
no `unsafe` in the library itself (the optional `ffi` feature is the only place
`unsafe` appears, for the C ABI surface).

> **Status: functional, pre-1.0.** Client, server, SFTP, SCP, port/agent/X11
> and Unix-socket (StreamLocal) forwarding, `known_hosts`, and `ssh_config`
> parsing are all implemented and tested against OpenSSH. Blocking, async,
> tokio, and mio frontends share one sans-I/O core. The crate is `0.0.x`; the
> public API may still change before 1.0.

## What's in the box

- **Library** — a sans-I/O protocol core (the `driver` state machines) plus
  high-level blocking `client` / `server` APIs built on top of it.
- **Async** — optional frontends driving the same `ClientDriver` / `ServerDriver`
  as the blocking APIs: runtime-agnostic over `futures_io` (`async`), with native
  entry points for **tokio** (`tokio`) and a readiness/non-blocking **mio**-style
  client (`mio`).
- **CLI suite** — drop-in `ssh`, `sftp`, `scp`, `sshd`, and `ssh-keygen` binaries
  built on the library.
- **C ABI** — optional `ffi` feature exposing a `pcssh_*` C interface
  (`staticlib` / `cdylib`), with bytes-path SFTP variants for non-UTF-8 paths.

## Goals

- **Pure Rust, no FFI deps.** Crypto comes from `purecrypto`; networking comes
  from `std::net`. Nothing links C.
- **`no_std` friendly.** The protocol core (packet codec, KEX, cipher/MAC
  adapters, key parsing) builds without `std`; only the convenience I/O and the
  client/server/CLI layers require it.
- **Modern algorithms first**, including a post-quantum hybrid KEX
  (`mlkem768x25519-sha256`). Legacy algorithms are present only where they
  remain useful for interop.
- **Auditable surface.** Small modules, narrow public types, every algorithm
  identifier tracked back to its RFC.

## Supported algorithms

| Category    | Algorithm                                |
|-------------|------------------------------------------|
| KEX (PQ)    | `mlkem768x25519-sha256` (ML-KEM-768 + X25519 hybrid) |
| KEX         | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
| KEX         | `ecdh-sha2-nistp{256,384,521}`           |
| KEX         | `diffie-hellman-group{14,16,18}-sha{256,512}` |
| KEX         | `diffie-hellman-group-exchange-sha256`   |
| Host key    | `ssh-ed25519`                            |
| Host key    | `ecdsa-sha2-nistp{256,384,521}`          |
| Host key    | `rsa-sha2-256`, `rsa-sha2-512`, `ssh-rsa` (with auto-upgrade via `server-sig-algs`) |
| Cipher      | `chacha20-poly1305@openssh.com`          |
| Cipher      | `aes{128,256}-gcm@openssh.com`           |
| Cipher      | `aes{128,192,256}-ctr`                   |
| MAC         | `hmac-sha2-{256,512}` (+ `-etm@openssh.com` variants) |
| Compression | `none`, `zlib`, `zlib@openssh.com` (delayed) |
| Auth        | `none`, `password`, `publickey`, `keyboard-interactive` |
| Extensions  | RFC 8308 `ext-info` / `server-sig-algs`  |

## Cargo features

| Feature        | Default | Description                                            |
|----------------|---------|--------------------------------------------------------|
| `std`          | yes     | I/O helpers, OS RNG, `std::error::Error`               |
| `alloc`        | yes     | Heap-backed types (implied by `std`)                   |
| `client`       | yes     | High-level client API                                  |
| `server`       | yes     | High-level server API                                  |
| `compress`     | yes     | `zlib` compression via `compcol`                       |
| `pam`          | yes     | PAM session integration for `sshd` (Linux only)        |
| `multichannel` | yes     | Concurrent multi-channel client (`SharedClient`, `SftpSession`) |
| `async`        | no      | Runtime-agnostic async frontends (`AsyncClient`, `AsyncServerConnection`) over `futures_io` |
| `tokio`        | no      | Native tokio entry points (`connect_tokio` / `accept_tokio`) accepting `tokio::io` streams; builds on `async` |
| `mio`          | no      | Native readiness frontend (`MioClient`) for a `mio`-style `Poll` loop; no `mio` dependency in the library |
| `ffi`          | no      | C ABI surface (`pcssh_*`); implies `client` + `multichannel` |

Disable defaults for `no_std`:

```toml
puressh = { version = "0.1.0", default-features = false, features = ["alloc"] }
```

## Quick start

```rust,no_run
use puressh::client::{Client, Config};

fn main() -> Result<(), puressh::Error> {
    // `Config::insecure()` trusts any host key — fine for a throwaway example.
    // Use `Config::with_known_hosts(store)` for OpenSSH-style strict checking.
    let mut c = Client::connect("example.com:22", Config::insecure())?;
    c.authenticate_password("alice", "hunter2")?;

    let out = c.exec("uname -a")?;
    println!("{}", String::from_utf8_lossy(&out.stdout));
    println!("exit: {:?}", out.exit_status);
    Ok(())
}
```

For concurrent channels (several SFTP / exec / shell / tunnel handles on one
connection), use the `multichannel` layer's `SharedClient` and its
`sftp()` / `exec_stream()` / `shell()` / `open_direct_tcpip()` helpers.

With the `async` feature, the same flow is available without blocking on any
particular runtime — `AsyncClient::connect` takes any
`futures_io::AsyncRead + AsyncWrite` stream (tokio via `tokio-util`'s `Compat`,
`smol`/`async-std`, etc.):

```rust,ignore
use puressh::client::Config;
use puressh::client_async::AsyncClient;

let mut c = AsyncClient::connect(stream, "example.com", 22, Config::insecure()).await?;
c.authenticate_password("alice", "hunter2").await?;
let out = c.exec("uname -a").await?;
```

Two further features expose **native** entry points on the same sans-I/O core,
for callers who would rather not wire up the compat shim themselves:

- **`tokio`** — `AsyncClient::connect_tokio` / `AsyncServerConnection::accept_tokio`
  take tokio's own `AsyncRead`/`AsyncWrite` streams (e.g. `tokio::net::TcpStream`)
  directly. The library links only tokio's io traits, never a runtime.
- **`mio`** — `MioClient` is a readiness/non-blocking client for a `mio`-style
  `Poll` loop: `pump_readable()` / `pump_writable()` advance the connection on
  the matching readiness (WouldBlock = not ready) and `poll_event()` surfaces
  `MioEvent`s. It is generic over `std::io::Read + Write`, so the library takes
  no dependency on `mio` itself.

Every frontend — blocking, `futures`, tokio, and mio — drives the same sans-I/O
`ClientDriver` / `ServerDriver`, so the handshake, auth, and channel logic is
written and tested once.

## CLI binaries

Built with the default features:

```
cargo build --release
```

| Binary       | Purpose                                                    |
|--------------|------------------------------------------------------------|
| `ssh`        | Interactive shell / `exec`, port forwarding (`-L`/`-R`), agent & X11 forwarding |
| `sftp`       | Interactive SFTP client                                    |
| `scp`        | File copy over SSH                                         |
| `sshd`       | SSH server daemon (PTY, PAM sessions on Linux)             |
| `ssh-keygen` | Key generation and OpenSSH key-file management             |

All of them understand `ssh_config` (including `Match` blocks and `Include`),
`known_hosts`, and bracketed-IPv6 host syntax (`[2001:db8::1]:22`).

## Module layout

```
src/
├── lib.rs           public re-exports
├── error.rs         Error / Result
├── format/          SSH wire format (Reader, Writer, mpint, name-list)
├── transport/       binary packet protocol, version exchange, KEX runner
├── kex/             curve25519, ecdh-nistp*, group-DH, GEX, mlkem768x25519
├── cipher/          aes-ctr, aes-gcm, chacha20-poly1305
├── mac/             hmac-sha2-* (incl. -etm)
├── hostkey/         ed25519, ecdsa-*, rsa-*
├── auth/            userauth state machine (RFC 4252)
├── channel/         RFC 4254 channels
├── key/             private/public key files: OpenSSH, PKCS#1, SEC1, PKCS#8
├── known_hosts/     known_hosts store + verification
├── config/          ssh_config / sshd_config parsing (Match, Include)
├── compress/        zlib / zlib@openssh.com
├── forwarding/      direct-tcpip, reverse, agent, X11, StreamLocal
├── sftp/            SFTP client + server (with OpenSSH @openssh.com extensions)
├── scp/             SCP protocol
├── agent/           ssh-agent client protocol
├── driver/          sans-I/O ClientDriver / ServerDriver state machines
├── shared.rs        SharedClient (multichannel layer)
├── ffi/             C ABI surface (feature `ffi`)
├── client.rs        high-level blocking client API (feature `client`)
├── server.rs        high-level blocking server API (feature `server`)
├── client_async.rs  async client frontend (features `async`, `tokio`)
├── server_async.rs  async server frontend (features `async`, `tokio`)
├── client_mio.rs    readiness/non-blocking client frontend (feature `mio`)
└── bin/             ssh, sftp, scp, sshd, ssh-keygen
```

## MSRV

`puressh`'s MSRV is **Rust 1.88**, declared as `rust-version` in `Cargo.toml`
and enforced by a dedicated CI job. Older toolchains are not supported.

## Non-goals

A few OpenSSH directives are intentionally unsupported and are rejected (strict
mode) rather than silently ignored: `PermitTunnel` (tun/tap device forwarding)
and external-command `Subsystem` entries. Two userauth methods are also not yet
implemented: `hostbased` and `gssapi-with-mic`.

## Security

This is pre-1.0 software that has not had an independent third-party audit.
It is built on `purecrypto` and has been the subject of internal security-review
passes (host-key trust handling, forwarding default-deny policies, SFTP jail
hardening, secret zeroization, DoS caps). Use the strict `known_hosts` policy
(`Config::with_known_hosts`) in anything that matters, and review before
deploying in a security-sensitive context.

## License

Dual-licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
