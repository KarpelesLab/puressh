//! `SSH_MSG_CHANNEL_REQUEST` payloads (RFC 4254 §6).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

/// A decoded channel-request body. The `request_type` and `want_reply` fields
/// of `SSH_MSG_CHANNEL_REQUEST` are handled by [`super::ConnectionState`]; the
/// variants here carry only the request-type-specific payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelRequest {
    /// `"pty-req"` — allocate a pseudo-terminal.
    PtyReq {
        /// Value for the `TERM` environment variable.
        term: String,
        /// Terminal width in characters.
        cols: u32,
        /// Terminal height in characters.
        rows: u32,
        /// Terminal width in pixels (0 if not specified).
        px_w: u32,
        /// Terminal height in pixels (0 if not specified).
        px_h: u32,
        /// Encoded terminal modes (RFC 4254 §8).
        modes: Vec<u8>,
    },
    /// `"shell"` — run the user's default shell.
    Shell,
    /// `"exec"` — run a single command.
    Exec {
        /// The command line.
        command: String,
    },
    /// `"subsystem"` — start a named subsystem (e.g. "sftp").
    Subsystem {
        /// Subsystem name.
        name: String,
    },
    /// `"env"` — set an environment variable in the session.
    Env {
        /// Variable name.
        name: String,
        /// Variable value.
        value: String,
    },
    /// `"window-change"` — terminal resized.
    WindowChange {
        /// New width in characters.
        cols: u32,
        /// New height in characters.
        rows: u32,
        /// New width in pixels.
        px_w: u32,
        /// New height in pixels.
        px_h: u32,
    },
    /// `"signal"` — deliver a signal to the remote process.
    Signal {
        /// Signal name without the `SIG` prefix (e.g. `"TERM"`).
        name: String,
    },
    /// `"exit-status"` — process exited normally with this status.
    ExitStatus {
        /// Exit code.
        code: u32,
    },
    /// `"exit-signal"` — process was killed by a signal.
    ExitSignal {
        /// Signal name without the `SIG` prefix.
        name: String,
        /// Whether a core was dumped.
        core_dumped: bool,
        /// Free-text error message.
        message: String,
        /// RFC 3066 language tag for `message`.
        language: String,
    },
    /// `"auth-agent-req@openssh.com"` — client asks the server to set up
    /// authentication-agent forwarding on this session. The request carries
    /// no type-specific payload. RFC pseudo-extension as deployed by OpenSSH.
    AuthAgentReq,
    /// `"x11-req"` — client asks the server to set up X11 forwarding on this
    /// session (RFC 4254 §6.3.1). Payload is `single_connection: bool`,
    /// `auth_protocol: string`, `auth_cookie: string` (hex-encoded), and
    /// `screen: u32`.
    X11Req {
        /// Server should accept only a single X11 connection if `true`.
        single_connection: bool,
        /// Authentication protocol name (e.g. `"MIT-MAGIC-COOKIE-1"`).
        auth_protocol: String,
        /// Authentication cookie, hex-encoded as per RFC 4254 §6.3.1.
        auth_cookie: String,
        /// X11 screen number.
        screen: u32,
    },
    /// Any request type we don't recognise; the raw type-specific body is preserved.
    Other {
        /// Request type as advertised on the wire.
        name: String,
        /// Type-specific body, verbatim.
        raw: Vec<u8>,
    },
}

impl ChannelRequest {
    /// The `request_type` field of the parent message.
    pub fn name(&self) -> &str {
        match self {
            ChannelRequest::PtyReq { .. } => "pty-req",
            ChannelRequest::Shell => "shell",
            ChannelRequest::Exec { .. } => "exec",
            ChannelRequest::Subsystem { .. } => "subsystem",
            ChannelRequest::Env { .. } => "env",
            ChannelRequest::WindowChange { .. } => "window-change",
            ChannelRequest::Signal { .. } => "signal",
            ChannelRequest::ExitStatus { .. } => "exit-status",
            ChannelRequest::ExitSignal { .. } => "exit-signal",
            ChannelRequest::AuthAgentReq => "auth-agent-req@openssh.com",
            ChannelRequest::X11Req { .. } => "x11-req",
            ChannelRequest::Other { name, .. } => name.as_str(),
        }
    }

    /// Encode just the request-type-specific tail (everything after `want_reply`).
    pub fn encode(&self, w: &mut Writer) {
        match self {
            ChannelRequest::PtyReq {
                term,
                cols,
                rows,
                px_w,
                px_h,
                modes,
            } => {
                w.write_string(term.as_bytes());
                w.write_u32(*cols);
                w.write_u32(*rows);
                w.write_u32(*px_w);
                w.write_u32(*px_h);
                w.write_string(modes);
            }
            ChannelRequest::Shell => {}
            ChannelRequest::Exec { command } => {
                w.write_string(command.as_bytes());
            }
            ChannelRequest::Subsystem { name } => {
                w.write_string(name.as_bytes());
            }
            ChannelRequest::Env { name, value } => {
                w.write_string(name.as_bytes());
                w.write_string(value.as_bytes());
            }
            ChannelRequest::WindowChange {
                cols,
                rows,
                px_w,
                px_h,
            } => {
                w.write_u32(*cols);
                w.write_u32(*rows);
                w.write_u32(*px_w);
                w.write_u32(*px_h);
            }
            ChannelRequest::Signal { name } => {
                w.write_string(name.as_bytes());
            }
            ChannelRequest::ExitStatus { code } => {
                w.write_u32(*code);
            }
            ChannelRequest::ExitSignal {
                name,
                core_dumped,
                message,
                language,
            } => {
                w.write_string(name.as_bytes());
                w.write_bool(*core_dumped);
                w.write_string(message.as_bytes());
                w.write_string(language.as_bytes());
            }
            ChannelRequest::AuthAgentReq => {}
            ChannelRequest::X11Req {
                single_connection,
                auth_protocol,
                auth_cookie,
                screen,
            } => {
                w.write_bool(*single_connection);
                w.write_string(auth_protocol.as_bytes());
                w.write_string(auth_cookie.as_bytes());
                w.write_u32(*screen);
            }
            ChannelRequest::Other { raw, .. } => {
                w.write_raw(raw);
            }
        }
    }

    /// Decode the request-type-specific tail given the `request_type` name and
    /// the remaining payload bytes.
    pub fn decode(name: &str, body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        match name {
            "pty-req" => {
                let term = read_utf8(&mut r)?;
                let cols = r.read_u32()?;
                let rows = r.read_u32()?;
                let px_w = r.read_u32()?;
                let px_h = r.read_u32()?;
                let modes = r.read_string()?.to_vec();
                Ok(ChannelRequest::PtyReq {
                    term,
                    cols,
                    rows,
                    px_w,
                    px_h,
                    modes,
                })
            }
            "shell" => Ok(ChannelRequest::Shell),
            "exec" => Ok(ChannelRequest::Exec {
                command: read_utf8(&mut r)?,
            }),
            "subsystem" => Ok(ChannelRequest::Subsystem {
                name: read_utf8(&mut r)?,
            }),
            "env" => {
                let name = read_utf8(&mut r)?;
                let value = read_utf8(&mut r)?;
                Ok(ChannelRequest::Env { name, value })
            }
            "window-change" => {
                let cols = r.read_u32()?;
                let rows = r.read_u32()?;
                let px_w = r.read_u32()?;
                let px_h = r.read_u32()?;
                Ok(ChannelRequest::WindowChange {
                    cols,
                    rows,
                    px_w,
                    px_h,
                })
            }
            "signal" => Ok(ChannelRequest::Signal {
                name: read_utf8(&mut r)?,
            }),
            "exit-status" => Ok(ChannelRequest::ExitStatus {
                code: r.read_u32()?,
            }),
            "exit-signal" => {
                let name = read_utf8(&mut r)?;
                let core_dumped = r.read_bool()?;
                let message = read_utf8(&mut r)?;
                let language = read_utf8(&mut r)?;
                Ok(ChannelRequest::ExitSignal {
                    name,
                    core_dumped,
                    message,
                    language,
                })
            }
            "auth-agent-req@openssh.com" => Ok(ChannelRequest::AuthAgentReq),
            "x11-req" => {
                let single_connection = r.read_bool()?;
                let auth_protocol = read_utf8(&mut r)?;
                let auth_cookie = read_utf8(&mut r)?;
                let screen = r.read_u32()?;
                Ok(ChannelRequest::X11Req {
                    single_connection,
                    auth_protocol,
                    auth_cookie,
                    screen,
                })
            }
            other => Ok(ChannelRequest::Other {
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
        .map_err(|_| Error::Format("invalid utf-8 in channel request"))
}
