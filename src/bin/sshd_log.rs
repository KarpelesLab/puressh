//! OpenSSH's logging, for sshd: the same destination, levels and wording, so
//! auth.log readers (fail2ban, logwatch, admins' greps) see what they saw
//! with OpenSSH.
//!
//! Messages go to syslog as `sshd[pid]` with the `SyslogFacility` (AUTH by
//! default), which journald and rsyslog file under auth.log, unless sshd
//! runs with `-d`, `-e` or `-E` (stderr or the file). `LogLevel` (INFO by
//! default) picks what is said: QUIET, FATAL, ERROR, INFO, VERBOSE and
//! DEBUG1-3, as with OpenSSH.
//!
//! The per-connection half ([`Conn`]) carries what a connection's messages
//! name — the peer, the user and whether it authenticated — so its closing
//! line reads like OpenSSH's (`Disconnected from user …`, `Connection
//! closed by authenticating user … [preauth]`, `Timeout before
//! authentication …`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// OpenSSH's log levels, least verbose first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Quiet = 0,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug1,
    Debug2,
    Debug3,
}

impl Level {
    /// A `LogLevel` value (`DEBUG` is `DEBUG1`).
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s.to_ascii_uppercase().as_str() {
            "QUIET" => Level::Quiet,
            "FATAL" => Level::Fatal,
            "ERROR" => Level::Error,
            "INFO" => Level::Info,
            "VERBOSE" => Level::Verbose,
            "DEBUG" | "DEBUG1" => Level::Debug1,
            "DEBUG2" => Level::Debug2,
            "DEBUG3" => Level::Debug3,
            _ => return None,
        })
    }

    fn from_u8(v: u8) -> Level {
        [
            Level::Quiet,
            Level::Fatal,
            Level::Error,
            Level::Info,
            Level::Verbose,
            Level::Debug1,
            Level::Debug2,
            Level::Debug3,
        ][usize::from(v.min(7))]
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
/// `MaxAuthTries`: failures past half of it are logged at INFO.
static MAX_AUTH_TRIES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(6);

/// The `MaxAuthTries` in force (for how loudly failures are logged).
pub fn set_max_auth_tries(n: u32) {
    MAX_AUTH_TRIES.store(n, Ordering::Relaxed);
}

/// Whether a failure is logged at INFO rather than VERBOSE: OpenSSH's rule
/// (an invalid user, a password, or half of MaxAuthTries already spent).
pub fn failure_is_loud(c: &Conn, method: &str) -> bool {
    !c.invalid_prefix().is_empty()
        || method == "password"
        || c.failures >= MAX_AUTH_TRIES.load(Ordering::Relaxed) / 2
}
static TO_STDERR: AtomicBool = AtomicBool::new(true);

/// A `SyslogFacility` value as the syslog(3) constant.
pub fn facility(name: &str) -> Option<libc::c_int> {
    Some(match name.to_ascii_uppercase().as_str() {
        "DAEMON" => libc::LOG_DAEMON,
        "USER" => libc::LOG_USER,
        "AUTH" => libc::LOG_AUTH,
        #[cfg(not(target_os = "solaris"))]
        "AUTHPRIV" => libc::LOG_AUTHPRIV,
        "LOCAL0" => libc::LOG_LOCAL0,
        "LOCAL1" => libc::LOG_LOCAL1,
        "LOCAL2" => libc::LOG_LOCAL2,
        "LOCAL3" => libc::LOG_LOCAL3,
        "LOCAL4" => libc::LOG_LOCAL4,
        "LOCAL5" => libc::LOG_LOCAL5,
        "LOCAL6" => libc::LOG_LOCAL6,
        "LOCAL7" => libc::LOG_LOCAL7,
        _ => return None,
    })
}

/// Set the level and destination: syslog with `facility`, or stderr.
pub fn init(level: Level, facility: libc::c_int, to_stderr: bool) {
    LEVEL.store(level as u8, Ordering::Relaxed);
    TO_STDERR.store(to_stderr, Ordering::Relaxed);
    if !to_stderr {
        // SAFETY: the ident is a static C string, as openlog(3) requires
        // (it keeps the pointer); the flags and facility are plain ints.
        // LOG_NDELAY connects now, before any chroot.
        unsafe { libc::openlog(c"sshd".as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, facility) };
    }
}

/// Whether messages of `level` are emitted.
pub fn enabled(level: Level) -> bool {
    level <= Level::from_u8(LEVEL.load(Ordering::Relaxed))
}

/// Log `msg` at `level`, worded as OpenSSH words it: syslog lines carry an
/// `error: ` / `fatal: ` prefix, debug lines `debugN: ` everywhere. Control
/// characters (peer-supplied names) are shown as `?`.
pub fn log(level: Level, msg: &str) {
    if level == Level::Quiet || !enabled(level) {
        return;
    }
    let msg: String = msg
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let stderr = TO_STDERR.load(Ordering::Relaxed);
    let prefix = match level {
        Level::Fatal if !stderr => "fatal: ",
        Level::Error if !stderr => "error: ",
        Level::Debug1 => "debug1: ",
        Level::Debug2 => "debug2: ",
        Level::Debug3 => "debug3: ",
        _ => "",
    };
    if stderr {
        eprintln!("{prefix}{msg}");
        return;
    }
    let priority = match level {
        Level::Fatal => libc::LOG_CRIT,
        Level::Error => libc::LOG_ERR,
        Level::Info | Level::Verbose => libc::LOG_INFO,
        _ => libc::LOG_DEBUG,
    };
    if let Ok(line) = std::ffi::CString::new(format!("{prefix}{msg}")) {
        // SAFETY: a constant "%s" format with one NUL-terminated argument.
        unsafe { libc::syslog(priority, c"%s".as_ptr(), line.as_ptr()) };
    }
}

pub fn info(msg: &str) {
    log(Level::Info, msg);
}

pub fn verbose(msg: &str) {
    log(Level::Verbose, msg);
}

pub fn error(msg: &str) {
    log(Level::Error, msg);
}

/// An address as OpenSSH prints it: IPv4-mapped IPv6 as plain IPv4.
pub fn addr_str(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// What one connection's messages name.
#[derive(Default)]
pub struct Conn {
    ip: String,
    port: u16,
    /// The user being authenticated, once known, and whether it exists.
    user: Option<(String, bool)>,
    authenticated: bool,
    /// Failed attempts (not counting `none`), as OpenSSH counts them.
    pub failures: u32,
    /// One-time messages already said (invalid user, not allowed, root).
    said: Vec<&'static str>,
}

static CONN: Mutex<Option<Conn>> = Mutex::new(None);

/// Run `f` on this connection's state, if one is open (connection child).
pub fn with_conn<R>(f: impl FnOnce(&mut Conn) -> R) -> Option<R> {
    CONN.lock().ok()?.as_mut().map(f)
}

impl Conn {
    /// `1.2.3.4 port 5678`.
    pub fn peer(&self) -> String {
        format!("{} port {}", self.ip, self.port)
    }

    /// `invalid user x ` / `` for messages like `Failed password for …`.
    pub fn invalid_prefix(&self) -> &'static str {
        match self.user {
            Some((_, false)) => "invalid user ",
            _ => "",
        }
    }

    /// Whether the one-time message `key` is still to be said (and mark it).
    pub fn first(&mut self, key: &'static str) -> bool {
        if self.said.contains(&key) {
            return false;
        }
        self.said.push(key);
        true
    }

    /// `authenticating user x ` / `invalid user x ` / `` before the peer, as
    /// in `Connection closed by authenticating user x 1.2.3.4 port 5`.
    fn who(&self) -> String {
        match &self.user {
            Some((u, true)) if self.authenticated => format!("user {u} "),
            Some((u, true)) => format!("authenticating user {u} "),
            Some((u, false)) => format!("invalid user {u} "),
            None => String::new(),
        }
    }
}

/// A connection from `peer` begins (connection child).
pub fn conn_begin(peer: SocketAddr, local: Option<SocketAddr>) {
    let c = Conn {
        ip: addr_str(peer.ip()),
        port: peer.port(),
        ..Conn::default()
    };
    let (lip, lport) = local.map_or((String::new(), 0), |l| (addr_str(l.ip()), l.port()));
    verbose(&format!(
        "Connection from {} on {lip} port {lport} rdomain \"\"",
        c.peer()
    ));
    if let Ok(mut g) = CONN.lock() {
        *g = Some(c);
    }
}

/// The user this connection authenticates as is known; `valid` is whether
/// the account exists (`Invalid user …` is said once otherwise).
pub fn conn_user(user: &str, valid: bool) {
    with_conn(|c| {
        if c.user.is_none() {
            c.user = Some((user.to_string(), valid));
            if !valid {
                info(&format!("Invalid user {user} from {}", c.peer()));
            }
        }
    });
}

/// Authentication completed.
pub fn conn_authenticated() {
    with_conn(|c| c.authenticated = true);
}

/// How the connection ended, from the connection handler's result.
pub enum End<'a> {
    /// The peer closed, or the session ended normally.
    Closed,
    /// The peer sent SSH_MSG_DISCONNECT.
    PeerDisconnect { reason: u32, description: &'a str },
    /// LoginGraceTime ran out.
    GraceTimeout,
    /// Authentication was refused for good (MaxAuthTries, not allowed).
    AuthFailed,
    /// No algorithm in common: `no matching cipher found. Their offer: …`.
    NoMatch(String),
    /// Anything else (protocol error, ...).
    Error(String),
}

/// Say how the connection ended, as OpenSSH does.
pub fn conn_end(end: End<'_>) {
    let Some(c) = CONN.lock().ok().and_then(|mut g| g.take()) else {
        return;
    };
    let preauth = if c.authenticated { "" } else { " [preauth]" };
    let peer = c.peer();
    let who = c.who();
    match end {
        End::GraceTimeout if !c.authenticated => {
            log(
                Level::Fatal,
                &format!("Timeout before authentication for {peer}"),
            );
        }
        End::AuthFailed if c.failures > 0 => {
            let (user, inv) = match &c.user {
                Some((u, valid)) => (u.as_str(), if *valid { "" } else { "invalid user " }),
                None => ("", ""),
            };
            error(&format!(
                "maximum authentication attempts exceeded for {inv}{user} from {peer} ssh2{preauth}"
            ));
            info(&format!(
                "Disconnecting {who}{peer}: Too many authentication failures{preauth}"
            ));
        }
        End::PeerDisconnect {
            reason,
            description,
        } => {
            info(&format!(
                "Received disconnect from {peer}:{reason}: {description}{preauth}"
            ));
            info(&format!("Disconnected from {who}{peer}{preauth}"));
        }
        // fail2ban's sshd filter (aggressive mode) matches this line.
        End::NoMatch(m) => info(&format!("Unable to negotiate with {peer}: {m}{preauth}")),
        End::Error(e) if !c.authenticated => {
            info(&format!("Connection closed by {who}{peer}: {e}{preauth}"));
        }
        End::Error(e) => {
            error(&e);
            info(&format!("Disconnected from {who}{peer}"));
        }
        _ if c.authenticated => info(&format!("Disconnected from {who}{peer}")),
        _ => info(&format!("Connection closed by {who}{peer}{preauth}")),
    }
}
