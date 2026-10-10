//! Stealth rendezvous over UDP ("knock"), a puressh-only extension.
//!
//! The server keeps no TCP port visibly open. A client sends one signed UDP
//! datagram (a KNOCK) naming a user and key; if the key is authorized for that
//! user, the server opens a short-lived TCP listener for that client alone
//! and replies with an ACCEPT signed by its host key. The client connects,
//! proves it holds the ephemeral X25519 secret from the knock, and then runs
//! an ordinary SSH session, including full user authentication. Invalid
//! knocks are never answered.
//!
//! The protocol is specified in `docs/knock.md`. Layers:
//!
//! - [`wire`]: datagram encode/parse, signatures, key derivation.
//! - [`KnockState`]: sans-IO server logic (filtering, replay protection,
//!   rate limits).
//! - [`KnockServer`]: the UDP socket and rendezvous listeners.
//! - [`knock`] / [`connect_or_knock`]: the client.
//!
//! This is not SSH and is not understood by other implementations.

mod client;
mod server;
mod state;
pub mod wire;

#[cfg(test)]
mod tests;

pub use client::{
    Connected, KnockAccepted, KnockClientConfig, KnockConnectOptions, KnockIdentity, KnockMode,
    KnockRequest, TcpDialer, connect_or_knock, connect_or_knock_addrs, knock,
};
pub use server::{KnockEvent, KnockServer, KnockedConnection, unix_ms};
pub use state::{
    CompletedAccept, DropReason, KnockHostKey, KnockKeyTable, KnockServerConfig, KnockState,
    PendingAccept, Verdict,
};
