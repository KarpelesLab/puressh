//! OpenSSH `ssh-agent` client.
//!
//! Speaks the wire protocol from `draft-miller-ssh-agent` (a.k.a.
//! OpenSSH `PROTOCOL.agent`) over the Unix socket at
//! `$SSH_AUTH_SOCK`. Used by [`crate::client`] as a credential source —
//! identities loaded into the agent are tried as `publickey` auth
//! before any `-i` keys.
//!
//! ```ignore
//! use puressh::agent::Agent;
//!
//! let mut agent = Agent::connect_env()?;
//! for id in agent.identities()? {
//!     println!("{}  {}", id.algorithm(), id.comment());
//! }
//! ```

#![cfg(all(feature = "std", unix))]

pub mod client;
pub mod host_key;
pub mod protocol;

#[cfg(test)]
mod tests;

pub use client::{Agent, AgentIdentity};
pub use host_key::AgentHostKey;
