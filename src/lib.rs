#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "ffi"), forbid(unsafe_code))]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

//! puressh — a pure-Rust SSH (Secure Shell) protocol library.
//!
//! Built on [`purecrypto`] for all cryptographic primitives, with no
//! foreign code in the dependency tree.
//!
//! The public API comes in three tiers:
//!
//! 1. **High-level clients and servers** plus the tooling around them:
//!    - [`client`]   — blocking client (feature `client`); [`shared`] adds the
//!      concurrent multi-channel [`SharedClient`](shared::SharedClient).
//!    - [`server`]   — blocking server (feature `server`).
//!    - `client_async` / `server_async` — runtime-agnostic async frontends
//!      (feature `async`, native tokio entry points with `tokio`);
//!      `client_mio` — readiness/non-blocking frontend (feature `mio`).
//!    - [`sftp`], [`scp`], [`known_hosts`], [`agent`], [`forwarding`],
//!      [`config`], [`cert`], [`krl`], [`key`], [`stream`], [`mux`],
//!      [`proc_transport`], [`error`].
//!    - [`hostkey`]  — host keys, certificates and fingerprints; [`auth`] —
//!      the user-facing halves of userauth ([`Authenticator`](auth::Authenticator),
//!      [`ClientCredential`](auth::ClientCredential), …).
//! 2. **Sans-IO drivers** — [`driver`]: [`ClientDriver`](driver::ClientDriver) /
//!    [`ServerDriver`](driver::ServerDriver) state machines for callers that
//!    bring their own I/O and clock (features `client` / `server`).
//! 3. **C ABI** — `ffi` (feature `ffi`).
//!
//! Everything below the drivers lives under [`hazmat`]: the wire format,
//! binary packet protocol, key exchange, ciphers, MACs, compression and the
//! RFC 4254 channel multiplexer. Those modules carry no stability promise and
//! are easy to misuse; see the [`hazmat`] module docs before reaching for them.
//!
//! # Sans-IO core and frontends
//!
//! The protocol layers under [`hazmat`] (`format`, `transport`, `channel`,
//! `auth`) are *sans-IO*: they transform byte buffers and never touch a
//! socket. The `driver` module lifts the connection *orchestration* — the
//! state machine that sequences version exchange → key exchange →
//! authentication → application channels and drives re-key/keepalive timers —
//! into the same sans-IO style: a `ClientDriver` / `ServerDriver` takes inbound
//! bytes (`handle_input`), produces outbound frames (`poll_transmit`) and
//! events (`poll_event`), and ticks timers (`handle_timeout`), with the caller
//! supplying the I/O and the clock.
//!
//! Two frontends drive that one core, sharing all protocol logic:
//!
//! - the blocking [`Client`](client::Client) / [`Server`](server::Server)
//!   (default), which pump the driver over `std::net` sockets and threads;
//! - the async `AsyncClient` (feature `async`), which pumps the same
//!   `ClientDriver` over any `futures_io::AsyncRead` + `AsyncWrite` transport
//!   (tokio via compat, smol, async-std, …) with no runtime dependency of its
//!   own.
//!
//! [`purecrypto`]: https://crates.io/crates/purecrypto

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod auth;
pub mod error;
pub mod hazmat;
pub mod hostkey;
pub mod key;

// Crate-private short paths for the protocol layers that live under
// `hazmat`. Everything inside the crate keeps saying `crate::transport::…`;
// only the public path changed.
pub(crate) use hazmat::{cipher, format, kex, mac, transport};

#[cfg(feature = "alloc")]
pub(crate) use hazmat::compress;

// `channel` is only consumed by the drivers and the frontends built on them;
// an `alloc`-only build would otherwise trip `unused_imports`.
#[cfg(any(feature = "client", feature = "server"))]
pub(crate) use hazmat::channel;

#[cfg(feature = "alloc")]
pub mod cert;

#[cfg(feature = "alloc")]
pub mod krl;

#[cfg(feature = "alloc")]
pub mod config;

#[cfg(feature = "std")]
pub mod stream;

#[cfg(feature = "client")]
pub mod client;

// Sans-IO connection drivers (transport + handshake + auth + channel
// orchestration as a pure state machine). The blocking `client`/`server`
// frontends drive these; an async frontend can too.
#[cfg(any(feature = "client", feature = "server"))]
pub mod driver;

// Runtime-agnostic async client frontend over `futures_io::AsyncRead/AsyncWrite`,
// driving the same `ClientDriver` as the blocking client. Opt-in.
#[cfg(feature = "async")]
pub mod client_async;

// Native readiness/non-blocking client frontend (mio-style) driving the same
// `ClientDriver`. Generic over `std::io::Read + Write` (WouldBlock = not ready),
// so it needs no dependency on `mio` itself. Opt-in.
#[cfg(feature = "mio")]
pub mod client_mio;

// Runtime-agnostic async server connection driving `ServerDriver`. Opt-in
// (needs both the async frontend and the server transport engine).
#[cfg(all(feature = "async", feature = "server"))]
pub mod server_async;

// `ProxyCommand` transport (Unix-only): spawns a helper process and runs the
// SSH session over its stdio. Gated on `client` (which pulls in `std` and the
// `Transport` trait) so a no_std+alloc build still compiles without it.
#[cfg(all(unix, feature = "client"))]
pub mod proc_transport;

// Client connection multiplexing (`ControlMaster` / `ControlPath` /
// `ControlPersist`) over a Unix-domain control socket. Unix-only and gated on
// `client` (which pulls in `std`); the master/accept side additionally needs
// `multichannel` for `SharedClient` and is gated again inside the module. The
// path helpers compile with just `client`, so Windows and no_std+alloc
// builds skip the whole module via its inner
// `#![cfg(all(unix, feature = "client"))]`.
#[cfg(all(unix, feature = "client"))]
pub mod mux;

#[cfg(feature = "multichannel")]
pub mod shared;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "std")]
pub mod sftp;

#[cfg(feature = "std")]
pub mod scp;

#[cfg(feature = "std")]
pub mod known_hosts;

#[cfg(all(feature = "std", unix))]
pub mod agent;

// `forwarding` exposes both server-side handlers (DefaultDirectTcpipHandler,
// DefaultAgentForwardHandler, DefaultX11ForwardHandler, …) AND the matching
// client-side splice callbacks (splice_to_local_agent_callback, splice_to_
// local_display_callback) used by the `ssh` binary's `-A` / `-X` flags. Gate
// it on either feature so a client-only build still picks up the callbacks.
#[cfg(all(feature = "std", any(feature = "client", feature = "server")))]
pub mod forwarding;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use error::{Error, Result};
