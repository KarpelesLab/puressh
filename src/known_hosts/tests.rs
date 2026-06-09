//! Integration tests for the `known_hosts` module.
//!
//! The lower-level format/hash modules have their own unit tests; this
//! file exercises the public [`KnownHosts`] API and cross-cutting
//! behaviours (parse → store → save → reload, lookup, TOFU-style add,
//! `hash_in_place`, marker semantics).

use super::format::{HostSpec, Marker};
use super::{KnownHosts, LookupResult};

/// Tiny on-disk scratch directory, modelled on `src/sftp/tests.rs::SftpTempDir` so
/// we don't pull in the `tempfile` crate.
struct TestTempDir {
    path: std::path::PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("puressh-kh-{prefix}-{pid}-{nanos}"));
        std::fs::create_dir_all(&path).expect("create tempdir");
        Self { path }
    }

    fn child(&self, name: &str) -> std::path::PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn ed25519_blob(seed: u8) -> Vec<u8> {
    // Anything goes for these tests — `KnownHosts` treats key blobs
    // opaquely. Vary by seed so different "keys" don't collide.
    let mut v = vec![0u8; 32];
    v[0] = seed;
    v[31] = seed.wrapping_add(0xA5);
    v
}

#[test]
fn parse_then_save_roundtrips_lines_verbatim() {
    // Mix of comments, blank lines, plain entries, hashed entry,
    // bracketed-host-with-port, and an unparseable line — saving must
    // emit them all back.
    let src = b"# header comment\n\
                \n\
                example.com ssh-ed25519 AAAA my-comment\n\
                [example.com]:2222 ssh-rsa AAAB\n\
                |1|salt+salt+salt+salt+salt+s=|hash+hash+hash+hash+hash+ha= ssh-ed25519 AAAC\n\
                # tail comment\n";
    let kh = KnownHosts::from_bytes(src);
    let out = kh.to_bytes();
    // We don't require byte-for-byte identity (whitespace inside an
    // entry is normalized), but every information-bearing line must
    // round-trip.
    let out_str = String::from_utf8(out).unwrap();
    assert!(out_str.contains("# header comment"));
    assert!(out_str.contains("# tail comment"));
    assert!(out_str.contains("example.com ssh-ed25519 AAAA my-comment"));
    assert!(out_str.contains("[example.com]:2222 ssh-rsa AAAB"));
    assert!(out_str
        .contains("|1|salt+salt+salt+salt+salt+s=|hash+hash+hash+hash+hash+ha= ssh-ed25519 AAAC"));
}

#[test]
fn lookup_plain_match_mismatch_unknown() {
    let mut kh = KnownHosts::new();
    let good = ed25519_blob(1);
    let other = ed25519_blob(2);
    kh.add("example.com", 22, "ssh-ed25519", &good, false);

    match kh.lookup("example.com", 22, "ssh-ed25519", &good) {
        LookupResult::Match => {}
        r => panic!("expected Match, got {r:?}"),
    }
    match kh.lookup("example.com", 22, "ssh-ed25519", &other) {
        LookupResult::Mismatch { expected } => {
            assert_eq!(expected, vec![("ssh-ed25519".to_string(), good.clone())]);
        }
        r => panic!("expected Mismatch, got {r:?}"),
    }
    match kh.lookup("other.invalid", 22, "ssh-ed25519", &good) {
        LookupResult::Unknown => {}
        r => panic!("expected Unknown, got {r:?}"),
    }
}

#[test]
fn lookup_honours_port_in_bracketed_entries() {
    let mut kh = KnownHosts::new();
    let key = ed25519_blob(3);
    kh.add("example.com", 2222, "ssh-ed25519", &key, false);
    // Same host, default port — must not match the 2222 entry.
    assert!(matches!(
        kh.lookup("example.com", 22, "ssh-ed25519", &key),
        LookupResult::Unknown
    ));
    assert!(matches!(
        kh.lookup("example.com", 2222, "ssh-ed25519", &key),
        LookupResult::Match
    ));
}

#[test]
fn multiple_keys_per_host_all_accepted() {
    // OpenSSH allows multiple lines for the same host (e.g. ed25519 +
    // rsa). Any matching key returns Match.
    let mut kh = KnownHosts::new();
    let k1 = ed25519_blob(11);
    let k2 = ed25519_blob(22);
    kh.add("example.com", 22, "ssh-ed25519", &k1, false);
    kh.add("example.com", 22, "ssh-rsa", &k2, false);
    assert!(matches!(
        kh.lookup("example.com", 22, "ssh-ed25519", &k1),
        LookupResult::Match
    ));
    assert!(matches!(
        kh.lookup("example.com", 22, "ssh-rsa", &k2),
        LookupResult::Match
    ));
    // A third unknown key produces Mismatch listing both expected.
    let k3 = ed25519_blob(33);
    match kh.lookup("example.com", 22, "ssh-ed25519", &k3) {
        LookupResult::Mismatch { expected } => {
            assert_eq!(expected.len(), 2);
        }
        r => panic!("expected Mismatch, got {r:?}"),
    }
}

#[test]
fn revoked_marker_refuses_matching_key() {
    let src = b"@revoked example.com ssh-ed25519 AAAA\n";
    let kh = KnownHosts::from_bytes(src);
    // We parsed AAAA as the key blob; reconstruct it and check refusal.
    let blob = crate::key::base64::decode(b"AAAA").unwrap();
    match kh.lookup("example.com", 22, "ssh-ed25519", &blob) {
        LookupResult::Mismatch { expected } => {
            assert_eq!(expected.len(), 1);
            assert_eq!(expected[0].0, "ssh-ed25519");
        }
        r => panic!("expected Mismatch (revoked), got {r:?}"),
    }
}

#[test]
fn cert_authority_marker_records_expected_but_does_not_match_arbitrary_keys() {
    // We don't speak ssh-{ed25519,rsa}-cert-v01 yet, so the CA key is
    // only treated as a match if the candidate equals it exactly.
    let src = b"@cert-authority *.example.com ssh-ed25519 AAAA\n";
    let kh = KnownHosts::from_bytes(src);
    let ca_blob = crate::key::base64::decode(b"AAAA").unwrap();
    let other = ed25519_blob(42);
    match kh.lookup("host.example.com", 22, "ssh-ed25519", &other) {
        LookupResult::Mismatch { .. } => {}
        r => panic!("expected Mismatch (non-CA candidate), got {r:?}"),
    }
    // Exact match against the CA key blob still counts as Match.
    assert!(matches!(
        kh.lookup("host.example.com", 22, "ssh-ed25519", &ca_blob),
        LookupResult::Match
    ));
}

#[test]
fn add_then_save_then_load_roundtrip() {
    let dir = TestTempDir::new("save-load");
    let path = dir.child("known_hosts");
    let key = ed25519_blob(7);

    let mut kh = KnownHosts::new();
    kh.add("example.com", 22, "ssh-ed25519", &key, false);
    kh.add("alt.example.com", 2222, "ssh-rsa", &ed25519_blob(8), false);
    kh.save(&path).expect("save");

    let kh2 = KnownHosts::load(&path).expect("load");
    assert!(matches!(
        kh2.lookup("example.com", 22, "ssh-ed25519", &key),
        LookupResult::Match
    ));
    assert!(matches!(
        kh2.lookup("alt.example.com", 2222, "ssh-rsa", &ed25519_blob(8)),
        LookupResult::Match
    ));
}

#[test]
fn load_missing_file_returns_empty_store() {
    let dir = TestTempDir::new("missing");
    let path = dir.child("nope");
    let kh = KnownHosts::load(&path).expect("missing → empty");
    assert!(matches!(
        kh.lookup("anywhere", 22, "ssh-ed25519", b"x"),
        LookupResult::Unknown
    ));
}

#[test]
fn add_hashed_then_lookup_works() {
    let key = ed25519_blob(9);
    let mut kh = KnownHosts::new();
    kh.add("example.com", 22, "ssh-ed25519", &key, true);
    // The freshly added entry is a hashed token; lookup must HMAC and match.
    assert!(matches!(
        kh.lookup("example.com", 22, "ssh-ed25519", &key),
        LookupResult::Match
    ));
    // A different host hashed under the same salt produces a different
    // HMAC, so we must NOT match.
    assert!(matches!(
        kh.lookup("evil.example", 22, "ssh-ed25519", &key),
        LookupResult::Unknown
    ));

    // Confirm the entry on disk is actually hashed.
    let entries = kh.find("example.com", 22);
    assert_eq!(entries.len(), 1);
    match &entries[0].host_spec {
        HostSpec::Hashed(token) => assert!(token.starts_with("|1|")),
        _ => panic!("expected hashed host_spec"),
    }
}

#[test]
fn remove_drops_matching_entries() {
    let mut kh = KnownHosts::new();
    kh.add("a.example.com", 22, "ssh-ed25519", &ed25519_blob(1), false);
    kh.add("b.example.com", 22, "ssh-ed25519", &ed25519_blob(2), false);
    kh.add("a.example.com", 22, "ssh-rsa", &ed25519_blob(3), false);

    assert_eq!(kh.remove("a.example.com", 22), 2);
    // b. is still there; a. is gone.
    assert!(matches!(
        kh.lookup("b.example.com", 22, "ssh-ed25519", &ed25519_blob(2)),
        LookupResult::Match
    ));
    assert!(matches!(
        kh.lookup("a.example.com", 22, "ssh-ed25519", &ed25519_blob(1)),
        LookupResult::Unknown
    ));
}

#[test]
fn hash_in_place_replaces_plain_entries_with_hashed_tokens() {
    let mut kh = KnownHosts::new();
    let key = ed25519_blob(15);
    kh.add("example.com", 22, "ssh-ed25519", &key, false);
    kh.add("alt.example.com", 2222, "ssh-rsa", &ed25519_blob(16), false);

    kh.hash_in_place();

    // After hashing, lookups still work — they HMAC the candidate host
    // and compare against the stored salted hash.
    assert!(matches!(
        kh.lookup("example.com", 22, "ssh-ed25519", &key),
        LookupResult::Match
    ));
    assert!(matches!(
        kh.lookup("alt.example.com", 2222, "ssh-rsa", &ed25519_blob(16)),
        LookupResult::Match
    ));

    // All entries should now be hashed.
    let bytes = kh.to_bytes();
    let text = String::from_utf8(bytes).unwrap();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(
            line.starts_with("|1|"),
            "expected hashed line, got: {line:?}"
        );
    }
}

#[test]
fn hashed_entry_parses_and_matches_known_host() {
    // Use the runtime to mint a canonical hashed entry, then re-parse
    // it through `from_bytes` and confirm lookup succeeds.
    let key = ed25519_blob(21);
    let mut kh = KnownHosts::new();
    kh.add("example.com", 22, "ssh-ed25519", &key, true);
    let bytes = kh.to_bytes();

    let kh2 = KnownHosts::from_bytes(&bytes);
    assert!(matches!(
        kh2.lookup("example.com", 22, "ssh-ed25519", &key),
        LookupResult::Match
    ));
}

#[test]
fn marker_round_trips_through_save_load() {
    let dir = TestTempDir::new("marker");
    let path = dir.child("known_hosts");

    // Mint a small file with both markers, then load+save and confirm
    // marker semantics survive.
    let blob = crate::key::base64::decode(b"AAAA").unwrap();
    let src = b"@cert-authority *.example.com ssh-ed25519 AAAA\n\
                @revoked bad.example.com ssh-ed25519 AAAA\n";
    std::fs::write(&path, src).unwrap();

    let kh = KnownHosts::load(&path).expect("load");
    // CA exact-key match.
    assert!(matches!(
        kh.lookup("host.example.com", 22, "ssh-ed25519", &blob),
        LookupResult::Match
    ));
    // Revoked refuses the same blob.
    assert!(matches!(
        kh.lookup("bad.example.com", 22, "ssh-ed25519", &blob),
        LookupResult::Mismatch { .. }
    ));

    // Save + reload survives — both the wildcard cert-authority and
    // the targeted revoke entry come back, and the revoke still wins
    // for `bad.example.com`.
    kh.save(&path).unwrap();
    let kh2 = KnownHosts::load(&path).unwrap();
    let markers: Vec<_> = kh2
        .find("bad.example.com", 22)
        .iter()
        .map(|e| e.marker)
        .collect();
    assert!(markers.contains(&Some(Marker::Revoked)));
    assert!(markers.contains(&Some(Marker::CertAuthority)));
    assert!(matches!(
        kh2.lookup("bad.example.com", 22, "ssh-ed25519", &blob),
        LookupResult::Mismatch { .. }
    ));
}

#[test]
fn lookup_ipv6_default_port_matches_bare_pattern() {
    // OpenSSH writes a v6 entry with the default port (22) as a bare
    // (unbracketed) pattern token, identical to a hostname entry. The
    // store must match that bare pattern when the candidate is the same
    // v6 host on port 22.
    let mut kh = KnownHosts::new();
    let key = ed25519_blob(20);
    kh.add("2001:db8::1", 22, "ssh-ed25519", &key, false);
    assert!(matches!(
        kh.lookup("2001:db8::1", 22, "ssh-ed25519", &key),
        LookupResult::Match
    ));
}

#[test]
fn lookup_ipv6_non_default_port_matches_bracketed_pattern() {
    // For a non-default port the on-disk form is `[v6-literal]:port`.
    // The lookup compares the bracketed pattern against the candidate
    // (host, port) and must accept it.
    let mut kh = KnownHosts::new();
    let key = ed25519_blob(21);
    kh.add("2001:db8::1", 2222, "ssh-ed25519", &key, false);
    // Must match at the non-default port.
    assert!(matches!(
        kh.lookup("2001:db8::1", 2222, "ssh-ed25519", &key),
        LookupResult::Match
    ));
    // Default-port lookup must NOT match — that's a different host record.
    assert!(matches!(
        kh.lookup("2001:db8::1", 22, "ssh-ed25519", &key),
        LookupResult::Unknown
    ));
}

#[test]
fn ipv6_save_load_roundtrip_preserves_match() {
    // Add a default-port v6 entry and a non-default-port v6 entry,
    // save the file, load it again, and re-look up both. Verifies the
    // wire format we produce is also the wire format we accept.
    let dir = TestTempDir::new("v6-roundtrip");
    let path = dir.child("known_hosts");
    let k1 = ed25519_blob(30);
    let k2 = ed25519_blob(31);

    let mut kh = KnownHosts::new();
    kh.add("2001:db8::1", 22, "ssh-ed25519", &k1, false);
    kh.add("2001:db8::2", 2222, "ssh-ed25519", &k2, false);
    kh.save(&path).expect("save");

    let kh2 = KnownHosts::load(&path).expect("load");
    assert!(matches!(
        kh2.lookup("2001:db8::1", 22, "ssh-ed25519", &k1),
        LookupResult::Match
    ));
    assert!(matches!(
        kh2.lookup("2001:db8::2", 2222, "ssh-ed25519", &k2),
        LookupResult::Match
    ));
}

#[test]
fn ipv6_hash_in_place_then_lookup_works() {
    // hash_in_place is the path that runs `split_host_port` under the
    // hood — it has to parse `[v6]:port` patterns correctly to compute
    // the canonical hashed host. A v6 entry on a non-default port must
    // survive the conversion and still match the candidate (host, port).
    let mut kh = KnownHosts::new();
    let key = ed25519_blob(32);
    kh.add("2001:db8::1", 2222, "ssh-ed25519", &key, false);
    kh.hash_in_place();
    assert!(matches!(
        kh.lookup("2001:db8::1", 2222, "ssh-ed25519", &key),
        LookupResult::Match
    ));
    // Now confirm the on-disk shape is hashed (not the original bracket
    // form) — proves the split_host_port → hash path actually fired.
    let entries = kh.find("2001:db8::1", 2222);
    assert_eq!(entries.len(), 1);
    match &entries[0].host_spec {
        HostSpec::Hashed(token) => assert!(token.starts_with("|1|")),
        _ => panic!("expected hashed host_spec after hash_in_place"),
    }
}

#[test]
fn known_hosts_file_with_bracketed_v6_line_loads_and_matches() {
    // Hand-write a known_hosts file with both forms and verify the
    // parser + matcher accept them as a unit.
    let dir = TestTempDir::new("v6-handwritten");
    let path = dir.child("known_hosts");
    let blob = crate::key::base64::decode(b"AAAA").unwrap();
    let src = b"2001:db8::1 ssh-ed25519 AAAA\n\
                [2001:db8::2]:2222 ssh-ed25519 AAAA\n";
    std::fs::write(&path, src).unwrap();

    let kh = KnownHosts::load(&path).expect("load");
    assert!(matches!(
        kh.lookup("2001:db8::1", 22, "ssh-ed25519", &blob),
        LookupResult::Match
    ));
    assert!(matches!(
        kh.lookup("2001:db8::2", 2222, "ssh-ed25519", &blob),
        LookupResult::Match
    ));
}

#[cfg(unix)]
#[test]
fn save_produces_mode_0600_file() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TestTempDir::new("perms");
    let path = dir.child("known_hosts");
    let mut kh = KnownHosts::new();
    kh.add("example.com", 22, "ssh-ed25519", &ed25519_blob(1), false);
    kh.save(&path).expect("save");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "known_hosts must be owner-only (0o600), got {mode:o}"
    );
}
