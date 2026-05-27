//! SSH transport layer — RFC 4253.
//!
//! Implements:
//!
//! - Version exchange (`SSH-2.0-…\r\n`)
//! - Binary Packet Protocol (packet length / padding / payload / MAC)
//! - Key exchange (`SSH_MSG_KEXINIT` + chosen KEX) and key re-exchange
//! - Negotiated symmetric crypto state for inbound and outbound streams

pub mod packet;
pub mod version;
pub mod kex;

pub use kex::{KexAlgorithms, Negotiated};
pub use packet::{Packet, PacketCodec};
pub use version::VersionExchange;
