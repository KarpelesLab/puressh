//! SSH transport layer — RFC 4253.
//!
//! Implements:
//!
//! - Version exchange (`SSH-2.0-…\r\n`)
//! - Binary Packet Protocol (packet length / padding / payload / MAC)
//! - Key exchange (`SSH_MSG_KEXINIT` + chosen KEX) and key re-exchange
//! - Negotiated symmetric crypto state for inbound and outbound streams

pub mod kex;
pub mod kexinit;
pub mod packet;
pub mod runner;
pub mod version;

pub use kex::{KexAlgorithms, Negotiated};
pub use kexinit::{KexInit, NegotiatedOwned, SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS};
pub use packet::{Packet, PacketCodec, BLOCK_SIZE_DEFAULT, MAX_PACKET_LEN};
pub use runner::{DirKeys, InstalledKeys, KexAdvance, KexRunner, Role};
pub use version::VersionExchange;
