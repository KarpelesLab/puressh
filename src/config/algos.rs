//! Crypto-algorithm selection for `ssh_config` / `sshd_config` keywords.
//!
//! Implements the OpenSSH keywords that override the built-in algorithm
//! preference lists — `Ciphers`, `MACs`, `KexAlgorithms`,
//! `HostKeyAlgorithms`, and (client-only) `PubkeyAcceptedAlgorithms`.
//!
//! Every algorithm name a directive resolves to is one this build actually
//! implements. Names OpenSSH knows but puressh lacks (`aes128-cbc`,
//! `ssh-dss`, ...) are dropped, so configs written for OpenSSH still load;
//! any other unknown name fails the parse with [`ConfigError::BadValue`]
//! naming the offending token and the source line. A directive that
//! resolves to the empty set is likewise a `BadValue` — an SSH peer
//! advertising an empty name-list cannot negotiate.
//!
//! ## List-modifier grammar (OpenSSH `ssh_config(5)`)
//!
//! The argument is a comma-separated list. A leading modifier character on
//! the *whole* list selects how it combines with the built-in defaults:
//!
//! | Form        | Effect                                                  |
//! |-------------|---------------------------------------------------------|
//! | `a,b,c`     | **replace** the defaults with exactly this list         |
//! | `+a,b`      | **append** these to the end of the defaults             |
//! | `-a,b*`     | **remove** entries matching these globs from defaults   |
//! | `^a,b`      | **prepend** these to the front of the defaults          |
//!
//! For `+`, `^`, and bare-replace the named tokens are validated against the
//! catalogue. For `-` the tokens are globs (`aes*`) matched against the
//! current list; an unmatched glob is *not* an error (OpenSSH tolerates it),
//! but the resulting set must still be non-empty.
//!
//! The KEX strict-kex marker names (`kex-strict-{c,s}-v00@openssh.com`) are
//! signalling tokens, never user-selectable algorithms: they are excluded
//! from the kex default list exposed here and are re-appended by the KEXINIT
//! builders after override resolution, so a user `-`/replace can never strip
//! the Terrapin (CVE-2023-48795) mitigation.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::ConfigError;
use super::glob::glob_match;
use crate::transport::kex::{defaults, is_strict_kex_marker};

/// Which algorithm family a directive selects, used to pick the catalogue of
/// known names and the default preference list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlgoCategory {
    /// `Ciphers` — symmetric encryption suites.
    Cipher,
    /// `MACs` — message authentication codes.
    Mac,
    /// `KexAlgorithms` — key-exchange methods (excluding strict-kex markers).
    Kex,
    /// `HostKeyAlgorithms` — server host-key / signature algorithms.
    HostKey,
    /// `PubkeyAcceptedAlgorithms` — client publickey-auth signature algorithms.
    PubkeyAccepted,
    /// `CASignatureAlgorithms` — signature algorithms accepted from a
    /// certificate authority when verifying an OpenSSH certificate.
    CaSignature,
}

/// The default `CASignatureAlgorithms` set (OpenSSH default, minus plain
/// SHA-1 `ssh-rsa`). These are the algorithms a CA's signature over a
/// certificate may use.
pub const CA_SIGNATURE_DEFAULTS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

/// Real (non-marker) KEX algorithm names, in default preference order.
///
/// `defaults::KEX` carries the two strict-kex signalling markers as its
/// trailing entries; this filters them out so they are never user-visible
/// or user-removable.
pub fn kex_names() -> Vec<&'static str> {
    defaults::KEX
        .iter()
        .copied()
        .filter(|n| !is_strict_kex_marker(n))
        .collect()
}

/// The set of valid algorithm names for `cat`, derived from the live
/// catalogues (so it can never drift from what the crypto layer implements).
///
/// `HostKeyAlgorithms` accepts one extra name over the strict default set:
/// legacy bare `ssh-rsa` (SHA-1). It is *namable* but never a default (see
/// [`default_list`]), so it can only enter the list when a config explicitly
/// requests it (e.g. `HostKeyAlgorithms +ssh-rsa`). Selecting it flips the
/// per-process SHA-1 opt-in — see `crate::hostkey::set_allow_rsa_sha1` and the
/// wiring in the client config resolver. `PubkeyAcceptedAlgorithms` keeps the
/// strict set (no SHA-1 pubkey auth).
pub fn known_names(cat: AlgoCategory) -> Vec<&'static str> {
    match cat {
        AlgoCategory::Cipher => crate::cipher::ALL.iter().map(|c| c.name).collect(),
        AlgoCategory::Mac => crate::mac::ALL.iter().map(|m| m.name).collect(),
        AlgoCategory::Kex => kex_names(),
        AlgoCategory::HostKey => {
            let mut names = crate::hostkey::HOST_KEY_VERIFY_NAMES.to_vec();
            // Legacy SHA-1 host-key verification, opt-in via config only.
            names.push("ssh-rsa");
            names
        }
        AlgoCategory::PubkeyAccepted => crate::hostkey::HOST_KEY_VERIFY_NAMES.to_vec(),
        AlgoCategory::CaSignature => CA_SIGNATURE_DEFAULTS.to_vec(),
    }
}

/// Algorithm names OpenSSH knows (some versions of it) that this build does
/// not implement. Configs written for OpenSSH name them — `Ciphers
/// +aes128-cbc` for old network gear, `PubkeyAcceptedKeyTypes +ssh-rsa` —
/// and OpenSSH accepts them; here they are dropped from the list (neither
/// side could use them), so such a file still loads. Names OpenSSH does not
/// know either remain an error.
fn openssh_only(cat: AlgoCategory) -> &'static [&'static str] {
    const CIPHERS: &[&str] = &[
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "rijndael-cbc@lysator.liu.se",
        "blowfish-cbc",
        "cast128-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    ];
    const MACS: &[&str] = &[
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-md5",
        "hmac-md5-96",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "hmac-sha1-96-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-md5-etm@openssh.com",
        "hmac-md5-96-etm@openssh.com",
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
    ];
    const KEX: &[&str] = &[
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group-exchange-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "sntrup761x25519-sha512",
        "sntrup761x25519-sha512@openssh.com",
        "mlkem768x25519-sha256",
    ];
    const KEYS: &[&str] = &[
        "ssh-ed25519",
        "ssh-ed25519-cert-v01@openssh.com",
        "sk-ssh-ed25519@openssh.com",
        "sk-ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-dss",
        "ssh-dss-cert-v01@openssh.com",
        "ssh-rsa",
        "ssh-rsa-cert-v01@openssh.com",
        "rsa-sha2-256",
        "rsa-sha2-256-cert-v01@openssh.com",
        "rsa-sha2-512",
        "rsa-sha2-512-cert-v01@openssh.com",
    ];
    match cat {
        AlgoCategory::Cipher => CIPHERS,
        AlgoCategory::Mac => MACS,
        AlgoCategory::Kex => KEX,
        AlgoCategory::HostKey | AlgoCategory::PubkeyAccepted | AlgoCategory::CaSignature => KEYS,
    }
}

/// The built-in default preference list for `cat` (what a bare-replace
/// directive starts from for `+`/`-`/`^`). The KEX list excludes the
/// strict-kex markers.
pub fn default_list(cat: AlgoCategory) -> Vec<&'static str> {
    match cat {
        AlgoCategory::Cipher => defaults::CIPHERS.to_vec(),
        AlgoCategory::Mac => defaults::MACS.to_vec(),
        AlgoCategory::Kex => kex_names(),
        AlgoCategory::HostKey | AlgoCategory::PubkeyAccepted => {
            crate::hostkey::HOST_KEY_VERIFY_NAMES.to_vec()
        }
        AlgoCategory::CaSignature => CA_SIGNATURE_DEFAULTS.to_vec(),
    }
}

/// Split the raw whitespace-tokenised args back into a single comma-separated
/// list and normalise it: join on a single space (OpenSSH tolerates spaces
/// around commas), split on commas, trim each, drop empties.
///
/// Returns the optional leading modifier char (`+`, `-`, `^`) stripped from
/// the *first* element, plus the cleaned token vector.
fn tokenize(args: &[String]) -> (Option<char>, Vec<String>) {
    let joined = args.join(" ");
    let modifier = match joined.chars().find(|c| !c.is_whitespace()) {
        Some(c @ ('+' | '-' | '^')) => Some(c),
        _ => None,
    };
    // Strip the modifier (and any leading whitespace before it) from the
    // working string before splitting on commas.
    let body = if let Some(m) = modifier {
        let trimmed = joined.trim_start();
        trimmed
            .strip_prefix(m)
            .map(|s| s.to_string())
            .unwrap_or_else(|| trimmed.to_string())
    } else {
        joined
    };
    let tokens = body
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    (modifier, tokens)
}

fn bad_value(line_no: usize, keyword: &str, msg: String) -> ConfigError {
    ConfigError::BadValue {
        line: line_no,
        keyword: keyword.to_string(),
        msg,
    }
}

/// Resolve a config algorithm directive into a concrete preference list,
/// applying the OpenSSH list-modifier grammar and validating every resulting
/// name against the catalogue for `cat`.
///
/// `args` is `ParsedLine::args` (already whitespace-split); `line_no` and
/// `keyword` flow into the error so a rejection points at the exact source.
///
/// Returns [`ConfigError::BadValue`] if any named token (for replace / `+` /
/// `^`) is unknown, or if the resolved set is empty.
pub fn resolve_algo_list(
    cat: AlgoCategory,
    args: &[String],
    line_no: usize,
    keyword: &str,
) -> Result<Vec<String>, ConfigError> {
    let (modifier, tokens) = tokenize(args);
    if tokens.is_empty() {
        return Err(bad_value(
            line_no,
            keyword,
            "expected at least one algorithm name".to_string(),
        ));
    }

    let known = known_names(cat);
    let is_known = |name: &str| known.contains(&name);
    // Names only OpenSSH implements are dropped here (see `openssh_only`);
    // `-` takes globs and needs no filtering.
    let named = tokens.len();
    let tokens: Vec<String> = if modifier == Some('-') {
        tokens
    } else {
        tokens
            .into_iter()
            .filter(|t| is_known(t) || !openssh_only(cat).contains(&t.as_str()))
            .collect()
    };
    if named > 0 && tokens.is_empty() && modifier.is_none() {
        return Err(bad_value(
            line_no,
            keyword,
            "none of these algorithms is implemented by puressh".to_string(),
        ));
    }

    let result: Vec<String> = match modifier {
        // `-glob,...` — remove matching entries from the defaults. Tokens are
        // globs, not exact names, so they are NOT validated against the
        // catalogue; an unmatched glob is tolerated, as in OpenSSH.
        Some('-') => default_list(cat)
            .into_iter()
            .filter(|name| !tokens.iter().any(|pat| glob_match(pat, name)))
            .map(|s| s.to_string())
            .collect(),

        // `+a,b` — append validated names to the end of the defaults,
        // skipping any already present.
        Some('+') => {
            for t in &tokens {
                if !is_known(t) {
                    return Err(bad_value(
                        line_no,
                        keyword,
                        format!("unknown algorithm {t:?}"),
                    ));
                }
            }
            let mut out: Vec<String> = default_list(cat)
                .into_iter()
                .map(|s| s.to_string())
                .collect();
            for t in tokens {
                if !out.contains(&t) {
                    out.push(t);
                }
            }
            out
        }

        // `^a,b` — prepend validated names to the front of the defaults,
        // de-duplicating the (now-redundant) later occurrences.
        Some('^') => {
            for t in &tokens {
                if !is_known(t) {
                    return Err(bad_value(
                        line_no,
                        keyword,
                        format!("unknown algorithm {t:?}"),
                    ));
                }
            }
            let mut out: Vec<String> = tokens;
            for name in default_list(cat) {
                if !out.iter().any(|e| e == name) {
                    out.push(name.to_string());
                }
            }
            out
        }

        // Bare list — replace the defaults wholesale with exactly these
        // validated names (preserving the user's order; de-duplicated).
        None => {
            let mut out: Vec<String> = Vec::with_capacity(tokens.len());
            for t in tokens {
                if !is_known(&t) {
                    return Err(bad_value(
                        line_no,
                        keyword,
                        format!("unknown algorithm {t:?}"),
                    ));
                }
                if !out.contains(&t) {
                    out.push(t);
                }
            }
            out
        }

        Some(_) => unreachable!("tokenize only yields +, -, ^"),
    };

    if result.is_empty() {
        return Err(bad_value(
            line_no,
            keyword,
            "directive resolves to an empty algorithm set".to_string(),
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(|t| t.to_string()).collect()
    }

    #[test]
    fn bare_list_replaces() {
        let got = resolve_algo_list(
            AlgoCategory::Cipher,
            &args("aes128-ctr,aes256-ctr"),
            1,
            "Ciphers",
        )
        .unwrap();
        assert_eq!(got, vec!["aes128-ctr", "aes256-ctr"]);
    }

    #[test]
    fn append_modifier() {
        let defaults = default_list(AlgoCategory::Mac);
        let got = resolve_algo_list(AlgoCategory::Mac, &args("+hmac-sha2-256"), 1, "MACs").unwrap();
        // The default list is preserved, hmac-sha2-256 was already in it so
        // it is not duplicated.
        assert_eq!(got.len(), defaults.len());
        assert!(got.iter().any(|m| m == "hmac-sha2-256"));
    }

    #[test]
    fn append_modifier_adds_new() {
        // Build a default list without one entry, then re-append it.
        let got =
            resolve_algo_list(AlgoCategory::Cipher, &args("+aes128-ctr"), 1, "Ciphers").unwrap();
        let count = got.iter().filter(|c| *c == "aes128-ctr").count();
        assert_eq!(count, 1, "append must not duplicate an existing entry");
    }

    #[test]
    fn remove_glob() {
        let got = resolve_algo_list(AlgoCategory::Cipher, &args("-aes*"), 1, "Ciphers").unwrap();
        assert!(got.iter().all(|c| !c.starts_with("aes")));
        assert!(got.iter().any(|c| c == "chacha20-poly1305@openssh.com"));
    }

    #[test]
    fn remove_glob_unmatched_is_ok() {
        // A glob that matches nothing is tolerated; the set is unchanged.
        let got = resolve_algo_list(
            AlgoCategory::Cipher,
            &args("-nonexistent-cipher"),
            1,
            "Ciphers",
        )
        .unwrap();
        assert_eq!(got.len(), default_list(AlgoCategory::Cipher).len());
    }

    #[test]
    fn prepend_modifier() {
        let got =
            resolve_algo_list(AlgoCategory::Cipher, &args("^aes128-ctr"), 1, "Ciphers").unwrap();
        assert_eq!(got[0], "aes128-ctr");
        // The rest of the defaults follow, minus the duplicate we moved up.
        assert_eq!(got.len(), default_list(AlgoCategory::Cipher).len());
    }

    #[test]
    fn unknown_name_rejected_with_line() {
        let err =
            resolve_algo_list(AlgoCategory::Cipher, &args("aes999-ctr"), 7, "Ciphers").unwrap_err();
        match err {
            ConfigError::BadValue { line, keyword, msg } => {
                assert_eq!(line, 7);
                assert_eq!(keyword, "Ciphers");
                assert!(
                    msg.contains("aes999-ctr"),
                    "msg should name the token: {msg}"
                );
            }
            other => panic!("expected BadValue, got {other:?}"),
        }
    }

    #[test]
    fn append_unknown_rejected() {
        let err =
            resolve_algo_list(AlgoCategory::Mac, &args("+hmac-bogus"), 3, "MACs").unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { line: 3, .. }));
    }

    #[test]
    fn empty_directive_rejected() {
        let err = resolve_algo_list(AlgoCategory::Cipher, &[], 2, "Ciphers").unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { line: 2, .. }));
    }

    #[test]
    fn remove_everything_is_empty_error() {
        let err = resolve_algo_list(AlgoCategory::Cipher, &args("-*"), 4, "Ciphers").unwrap_err();
        match err {
            ConfigError::BadValue { line, msg, .. } => {
                assert_eq!(line, 4);
                assert!(msg.contains("empty"), "msg: {msg}");
            }
            other => panic!("expected BadValue, got {other:?}"),
        }
    }

    #[test]
    fn comma_and_whitespace_tolerated() {
        // OpenSSH accepts spaces around commas when the whole thing is one
        // logical list; our tokenizer joins args then splits on commas.
        let got = resolve_algo_list(
            AlgoCategory::Cipher,
            &args("aes128-ctr, aes256-ctr , chacha20-poly1305@openssh.com"),
            1,
            "Ciphers",
        )
        .unwrap();
        assert_eq!(
            got,
            vec!["aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com"]
        );
    }

    #[test]
    fn kex_markers_never_user_visible() {
        // The strict-kex markers are not in the known/default kex names, so a
        // user cannot name them and they cannot be removed.
        assert!(
            !known_names(AlgoCategory::Kex)
                .iter()
                .any(|n| is_strict_kex_marker(n))
        );
        assert!(
            !default_list(AlgoCategory::Kex)
                .iter()
                .any(|n| is_strict_kex_marker(n))
        );
        let err = resolve_algo_list(
            AlgoCategory::Kex,
            &args("kex-strict-c-v00@openssh.com"),
            1,
            "KexAlgorithms",
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { .. }));
    }

    #[test]
    fn hostkey_known_names_include_optin_ssh_rsa() {
        // `ssh-rsa` is namable for HostKeyAlgorithms (opt-in)...
        assert!(known_names(AlgoCategory::HostKey).contains(&"ssh-rsa"));
        assert!(known_names(AlgoCategory::HostKey).contains(&"ssh-ed25519"));
        // ...but never a default, so it only enters a resolved list when the
        // config explicitly requests it.
        assert!(!default_list(AlgoCategory::HostKey).contains(&"ssh-rsa"));
        // PubkeyAcceptedAlgorithms stays strict — no SHA-1 pubkey auth.
        assert!(!known_names(AlgoCategory::PubkeyAccepted).contains(&"ssh-rsa"));
    }

    #[test]
    fn hostkey_plus_ssh_rsa_accepted() {
        // `HostKeyAlgorithms +ssh-rsa` now resolves instead of erroring.
        let got = resolve_algo_list(
            AlgoCategory::HostKey,
            &args("+ssh-rsa"),
            1,
            "HostKeyAlgorithms",
        )
        .unwrap();
        assert!(got.iter().any(|n| n == "ssh-rsa"));
        // The defaults are preserved ahead of the appended legacy name.
        assert!(got.iter().any(|n| n == "ssh-ed25519"));
        assert!(
            got.iter().position(|n| n == "ssh-ed25519") < got.iter().position(|n| n == "ssh-rsa")
        );
    }

    #[test]
    fn pubkey_accepted_never_takes_ssh_rsa() {
        // The SHA-1 opt-in is HostKey-only: `+ssh-rsa` (common in configs
        // for old servers) loads, as with OpenSSH, but adds nothing.
        let got = resolve_algo_list(
            AlgoCategory::PubkeyAccepted,
            &args("+ssh-rsa"),
            1,
            "PubkeyAcceptedAlgorithms",
        )
        .unwrap();
        assert!(!got.iter().any(|n| n == "ssh-rsa"));
        assert_eq!(got, default_list(AlgoCategory::PubkeyAccepted));
    }

    #[test]
    fn openssh_only_names_are_dropped_unknown_ones_refused() {
        let got = resolve_algo_list(
            AlgoCategory::Cipher,
            &args("+aes128-cbc,3des-cbc"),
            1,
            "Ciphers",
        )
        .unwrap();
        assert_eq!(got, default_list(AlgoCategory::Cipher));
        let got = resolve_algo_list(
            AlgoCategory::Cipher,
            &args("aes256-cbc,aes256-ctr"),
            1,
            "Ciphers",
        )
        .unwrap();
        assert_eq!(got, vec!["aes256-ctr"]);
        // Only unimplemented names: nothing left to offer.
        assert!(
            resolve_algo_list(AlgoCategory::Cipher, &args("aes128-cbc"), 1, "Ciphers").is_err()
        );
        // Not an OpenSSH name either: still a typo to report.
        assert!(
            resolve_algo_list(AlgoCategory::Cipher, &args("+aes128-cbx"), 1, "Ciphers").is_err()
        );
        assert!(
            resolve_algo_list(
                AlgoCategory::Kex,
                &args("+diffie-hellman-group1-sha1"),
                1,
                "KexAlgorithms"
            )
            .is_ok()
        );
    }

    #[test]
    fn pubkey_accepted_uses_hostkey_catalogue() {
        let got = resolve_algo_list(
            AlgoCategory::PubkeyAccepted,
            &args("ssh-ed25519,rsa-sha2-512"),
            1,
            "PubkeyAcceptedAlgorithms",
        )
        .unwrap();
        assert_eq!(got, vec!["ssh-ed25519", "rsa-sha2-512"]);
    }
}
