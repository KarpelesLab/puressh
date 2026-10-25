//! How `ssh` resolves its configuration for a destination, checked through
//! `ssh -G` (no network): who the user is, which `Match` blocks see what,
//! and the final pass (`CanonicalizeHostname`, `Match final`), as OpenSSH.

use std::process::Command;

fn g(config: &str, args: &[&str]) -> String {
    // Tests run in parallel: each call its own directory.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "puressh-cfgres-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config");
    std::fs::write(&path, config).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ssh"))
        .arg("-F")
        .arg(&path)
        .arg("-G")
        .args(args)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn value<'a>(out: &'a str, key: &str) -> Vec<&'a str> {
    out.lines()
        .filter_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
        .collect()
}

#[test]
fn user_at_host_beats_the_config_user() {
    let cfg = "Host x\n  User cfguser\n";
    assert_eq!(value(&g(cfg, &["foo@x"]), "user"), ["foo"]);
    assert_eq!(value(&g(cfg, &["-l", "bar", "foo@x"]), "user"), ["bar"]);
    assert_eq!(value(&g(cfg, &["x"]), "user"), ["cfguser"]);
}

#[test]
fn match_user_sees_the_named_user() {
    let cfg = "Match user bob\n  Port 2201\n";
    assert_eq!(value(&g(cfg, &["bob@h"]), "port"), ["2201"]);
    assert_eq!(value(&g(cfg, &["-l", "bob", "h"]), "port"), ["2201"]);
    assert_eq!(value(&g(cfg, &["alice@h"]), "port"), ["22"]);
}

#[test]
fn match_final_sees_the_host_name() {
    let cfg = "Host short\n  HostName short.example.org\n\
               Match final host short.example.org\n  Port 2200\n\
               Host *\n  IdentityFile ~/.ssh/a\n";
    let out = g(cfg, &["short"]);
    assert_eq!(value(&out, "port"), ["2200"]);
    // Blocks matched on both passes do not list their files twice.
    assert_eq!(value(&out, "identityfile"), ["~/.ssh/a"]);
}

#[test]
fn canonicalize_hostname_reparses_for_the_canonical_name() {
    // An anchored name (trailing dot) is canonical without DNS.
    let cfg = "Host *\n  CanonicalizeHostname yes\n\
               Host box.example\n  User canon\n\
               Match canonical\n  ConnectTimeout 7\n";
    let out = g(cfg, &["box.example."]);
    assert_eq!(value(&out, "hostname"), ["box.example"]);
    assert_eq!(value(&out, "user"), ["canon"]);
    assert_eq!(value(&out, "connecttimeout"), ["7"]);
    assert_eq!(value(&out, "canonicalizehostname"), ["true"]);
    // Without canonicalisation there is no final pass.
    let out = g("Match canonical\n  ConnectTimeout 7\n", &["box"]);
    assert_eq!(value(&out, "connecttimeout"), ["none"]);
}

#[test]
fn user_known_hosts_files_default_to_both() {
    let out = g("", &["h"]);
    let files = value(&out, "userknownhostsfile");
    assert_eq!(files.len(), 1, "{out}");
    let files: Vec<&str> = files[0].split(' ').collect();
    assert_eq!(files.len(), 2, "{files:?}");
    assert!(files[0].ends_with("known_hosts") && files[1].ends_with("known_hosts2"));
    let out = g("UserKnownHostsFile none\n", &["h"]);
    assert_eq!(value(&out, "userknownhostsfile"), ["none"]);
}

#[test]
fn client_keywords_print_as_openssh() {
    let out = g(
        "CheckHostIP yes\nVisualHostKey yes\nFingerprintHash md5\nIPQoS af21 16\n\
         ForwardX11Timeout 1h\nChannelTimeout session=5m\nSyslogFacility local3\n\
         StreamLocalBindMask 022\nRequiredRSASize 3072\nWarnWeakCrypto no\n\
         VersionAddendum hi there\nVerifyHostKeyDNS yes\n\
         CanonicalizePermittedCNAMEs *.a:*.b\nTunnel ethernet\nTunnelDevice 3\n",
        &["h"],
    );
    for (key, want) in [
        ("checkhostip", "yes"),
        ("visualhostkey", "yes"),
        ("fingerprinthash", "MD5"),
        ("ipqos", "af21 0x10"),
        ("forwardx11timeout", "3600"),
        ("channeltimeout", "session=5m"),
        ("syslogfacility", "LOCAL3"),
        ("streamlocalbindmask", "022"),
        ("requiredrsasize", "3072"),
        ("warnweakcrypto", "no"),
        ("versionaddendum", "hi there"),
        ("verifyhostkeydns", "true"),
        // VerifyHostKeyDNS turns the UpdateHostKeys default off.
        ("updatehostkeys", "false"),
        ("canonicalizepermittedcnames", "*.a:*.b"),
        ("tunnel", "ethernet"),
        ("tunneldevice", "3:any"),
    ] {
        assert_eq!(value(&out, key), [want], "{key}");
    }
    let out = g("", &["h"]);
    for (key, want) in [
        ("ipqos", "ef cs0"),
        ("logverbose", "none"),
        ("streamlocalbindmask", "0177"),
        ("syslogfacility", "USER"),
        ("warnweakcrypto", "yes"),
        ("xauthlocation", "/usr/bin/xauth"),
    ] {
        assert_eq!(value(&out, key), [want], "{key}");
    }
}

#[test]
fn refuse_connection_stops_before_printing() {
    let dir = std::env::temp_dir().join(format!("puressh-refuse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config");
    std::fs::write(
        &path,
        "Host other\n  Port 2\nHost h\n  RefuseConnection \"go away\"\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ssh"))
        .arg("-F")
        .arg(&path)
        .args(["-G", "h"])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(255));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("config line 4: RefuseConnection: go away"),
        "{err}"
    );
}
