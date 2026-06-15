//! Crypto-algorithm selection for `ssh_config` / `sshd_config` keywords.
//!
//! Implements the OpenSSH keywords that override the built-in algorithm
//! preference lists — `Ciphers`, `MACs`, `KexAlgorithms`,
//! `HostKeyAlgorithms`, and (client-only) `PubkeyAcceptedAlgorithms`.
//!
//! puressh runs these in **strict** mode: every algorithm name a directive
//! resolves to must be one this build actually implements, or the parse
//! fails with [`ConfigError::BadValue`] naming the offending token and the
//! source line. A directive that resolves to the empty set is likewise a
//! `BadValue` — an SSH peer advertising an empty name-list cannot negotiate.
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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::ConfigError;
use super::glob::glob_match;
use crate::transport::kex::{defaults, is_strict_kex_marker};

/// Which algorithm family a directive selects, used to pick the catalogue of
/// known names and the default preference list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

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
pub fn known_names(cat: AlgoCategory) -> Vec<&'static str> {
    match cat {
        AlgoCategory::Cipher => crate::cipher::ALL.iter().map(|c| c.name).collect(),
        AlgoCategory::Mac => crate::mac::ALL.iter().map(|m| m.name).collect(),
        AlgoCategory::Kex => kex_names(),
        AlgoCategory::HostKey | AlgoCategory::PubkeyAccepted => {
            crate::hostkey::HOST_KEY_VERIFY_NAMES.to_vec()
        }
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
    let is_known = |name: &str| known.iter().any(|k| *k == name);

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
                if !out.iter().any(|e| *e == t) {
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
                if !out.iter().any(|e| *e == t) {
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
    fn hostkey_known_names_exclude_bare_ssh_rsa() {
        assert!(
            !known_names(AlgoCategory::HostKey)
                .iter()
                .any(|n| *n == "ssh-rsa")
        );
        assert!(
            known_names(AlgoCategory::HostKey)
                .iter()
                .any(|n| *n == "ssh-ed25519")
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
