//! High-level client API (feature `client`).
//!
//! Intended shape (still under construction):
//!
//! ```ignore
//! use puressh::client::{Client, Config};
//!
//! let mut c = Client::connect("example.com:22", Config::default()).await?;
//! c.authenticate_password("alice", "hunter2").await?;
//! let mut sess = c.open_session().await?;
//! sess.exec("uname -a").await?;
//! let mut buf = Vec::new();
//! sess.stdout().read_to_end(&mut buf).await?;
//! ```

/// Client-side configuration: algorithm preferences, host-key policy, timeouts.
#[derive(Debug, Default)]
pub struct Config {
    // TODO: host-key callback, algorithm overrides, identity files…
}

/// SSH client handle — not yet implemented.
#[derive(Debug)]
pub struct Client {
    _priv: (),
}
