//! Algorithm negotiation (RFC 4253 §7) — the `SSH_MSG_KEXINIT` exchange and
//! the KEX runner that drives the round-trip to completion.

extern crate alloc;

/// Algorithm preference lists advertised by one side.
#[derive(Debug, Clone)]
pub struct KexAlgorithms<'a> {
    /// Key exchange algorithms (e.g. `curve25519-sha256`).
    pub kex: &'a [&'a str],
    /// Host key / signature algorithms (e.g. `ssh-ed25519`, `rsa-sha2-512`).
    pub server_host_key: &'a [&'a str],
    /// Ciphers, client→server.
    pub ciphers_c2s: &'a [&'a str],
    /// Ciphers, server→client.
    pub ciphers_s2c: &'a [&'a str],
    /// MACs, client→server.
    pub macs_c2s: &'a [&'a str],
    /// MACs, server→client.
    pub macs_s2c: &'a [&'a str],
    /// Compression, client→server.
    pub comp_c2s: &'a [&'a str],
    /// Compression, server→client.
    pub comp_s2c: &'a [&'a str],
    /// Languages, client→server (usually empty).
    pub lang_c2s: &'a [&'a str],
    /// Languages, server→client (usually empty).
    pub lang_s2c: &'a [&'a str],
}

/// The algorithms agreed by both sides after the KEXINIT exchange.
///
/// Carries owned strings so the runner can keep it across the rest of the
/// KEX round-trip and across re-keys.
#[derive(Debug, Clone)]
pub struct Negotiated {
    /// Key-exchange method.
    pub kex: alloc::string::String,
    /// Server host-key method.
    pub host_key: alloc::string::String,
    /// Client to server cipher.
    pub cipher_c2s: alloc::string::String,
    /// Server to client cipher.
    pub cipher_s2c: alloc::string::String,
    /// Client to server MAC (or "" when cipher is AEAD).
    pub mac_c2s: alloc::string::String,
    /// Server to client MAC (or "" when cipher is AEAD).
    pub mac_s2c: alloc::string::String,
    /// Client to server compression.
    pub comp_c2s: alloc::string::String,
    /// Server to client compression.
    pub comp_s2c: alloc::string::String,
}

/// Sensible default algorithm lists matching modern OpenSSH.
pub mod defaults {
    /// KEX algorithms in preference order.
    pub const KEX: &[&str] = &[
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    ];

    /// Server host-key algorithms in preference order.
    pub const HOST_KEY: &[&str] = &[
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ];

    /// Cipher algorithms (same list for both directions).
    pub const CIPHERS: &[&str] = &[
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
    ];

    /// MAC algorithms (ignored for AEAD ciphers).
    pub const MACS: &[&str] = &[
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    ];

    /// Compression algorithms.
    pub const COMP: &[&str] = &["none"];
}
