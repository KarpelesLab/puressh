//! `SSH_MSG_GLOBAL_REQUEST` payloads (RFC 4254 §4).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

/// A decoded global-request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalRequest {
    /// `"tcpip-forward"` — ask the server to listen on `bind_address:bind_port`
    /// and forward incoming connections (RFC 4254 §7.1).
    TcpipForward {
        /// Address to listen on; `""` means all interfaces, `"localhost"` is loopback only.
        bind_address: String,
        /// Port to listen on; 0 asks the server to pick.
        bind_port: u32,
    },
    /// `"cancel-tcpip-forward"` — undo a previous `tcpip-forward`.
    CancelTcpipForward {
        /// The originally bound address.
        bind_address: String,
        /// The originally bound port.
        bind_port: u32,
    },
    /// OpenSSH's `"keepalive@openssh.com"` heartbeat.
    Keepalive,
    /// Any request type we don't recognise.
    Other {
        /// Request name as advertised on the wire.
        name: String,
        /// Type-specific body verbatim.
        raw: Vec<u8>,
    },
}

impl GlobalRequest {
    /// The `request_name` field of the parent message.
    pub fn name(&self) -> &str {
        match self {
            GlobalRequest::TcpipForward { .. } => "tcpip-forward",
            GlobalRequest::CancelTcpipForward { .. } => "cancel-tcpip-forward",
            GlobalRequest::Keepalive => "keepalive@openssh.com",
            GlobalRequest::Other { name, .. } => name.as_str(),
        }
    }

    /// Encode just the request-name-specific tail (everything after `want_reply`).
    pub fn encode(&self, w: &mut Writer) {
        match self {
            GlobalRequest::TcpipForward { bind_address, bind_port }
            | GlobalRequest::CancelTcpipForward { bind_address, bind_port } => {
                w.write_string(bind_address.as_bytes());
                w.write_u32(*bind_port);
            }
            GlobalRequest::Keepalive => {}
            GlobalRequest::Other { raw, .. } => {
                w.write_raw(raw);
            }
        }
    }

    /// Decode a global-request body given the `request_name`.
    pub fn decode(name: &str, body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        match name {
            "tcpip-forward" => {
                let bind_address = read_utf8(&mut r)?;
                let bind_port = r.read_u32()?;
                Ok(GlobalRequest::TcpipForward { bind_address, bind_port })
            }
            "cancel-tcpip-forward" => {
                let bind_address = read_utf8(&mut r)?;
                let bind_port = r.read_u32()?;
                Ok(GlobalRequest::CancelTcpipForward { bind_address, bind_port })
            }
            "keepalive@openssh.com" => Ok(GlobalRequest::Keepalive),
            other => Ok(GlobalRequest::Other {
                name: other.to_string(),
                raw: body.to_vec(),
            }),
        }
    }
}

fn read_utf8(r: &mut Reader<'_>) -> Result<String> {
    let bytes = r.read_string()?;
    core::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| Error::Format("invalid utf-8 in global request"))
}
