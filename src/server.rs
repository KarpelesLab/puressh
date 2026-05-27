//! High-level server API (feature `server`).
//!
//! Intended shape (still under construction):
//!
//! ```ignore
//! use puressh::server::{Server, Config};
//!
//! let cfg = Config::default().with_host_key(load_host_key()?);
//! let mut srv = Server::bind("0.0.0.0:2222", cfg).await?;
//! while let Some(session) = srv.accept().await? {
//!     tokio::spawn(handle_session(session));
//! }
//! ```

/// Server-side configuration: host keys, authentication callbacks, banner.
#[derive(Debug, Default)]
pub struct Config {
    // TODO: host-key store, password/publickey auth callbacks, banner, algo overrides…
}

/// SSH server handle — not yet implemented.
#[derive(Debug)]
pub struct Server {
    _priv: (),
}
