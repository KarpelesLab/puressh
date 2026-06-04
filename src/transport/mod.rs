//! SSH transport layer — RFC 4253.
//!
//! Implements:
//!
//! - Version exchange (`SSH-2.0-…\r\n`)
//! - Binary Packet Protocol (packet length / padding / payload / MAC)
//! - Key exchange (`SSH_MSG_KEXINIT` + chosen KEX) and key re-exchange
//! - Negotiated symmetric crypto state for inbound and outbound streams

#[cfg(feature = "alloc")]
pub mod ext_info;
pub mod kex;
pub mod kexinit;
pub mod packet;
#[cfg(feature = "alloc")]
pub mod rekey;
pub mod runner;
pub mod version;

#[cfg(feature = "alloc")]
pub use ext_info::{
    is_ext_info_marker, ExtInfo, EXT_INFO_CLIENT_MARKER, EXT_INFO_SERVER_MARKER, SSH_MSG_EXT_INFO,
};
pub use kex::{KexAlgorithms, Negotiated};
pub use kexinit::{KexInit, NegotiatedOwned, SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS};
pub use packet::{Packet, PacketCodec, BLOCK_SIZE_DEFAULT, MAX_PACKET_LEN};
#[cfg(feature = "alloc")]
pub use rekey::{is_kex_msg, RekeyPolicy};
pub use runner::{DirKeys, InstalledKeys, KexAdvance, KexRunner, Role};
pub use version::VersionExchange;
