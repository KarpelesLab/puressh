//! `sshd -G` / `sshd -T [-C spec]`: the effective configuration, as admin
//! tooling reads it (`sshd -T | grep -i permitrootlogin`), in OpenSSH 10.6's
//! spelling and order. Runs the binary; binds nothing.

#![cfg(unix)]

use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn run(config: &str, args: &[&str]) -> Output {
    let dir = std::env::temp_dir().join(format!("puressh-sshd-dump-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // One file per call: the tests run in parallel.
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = dir.join(format!("sshd_config.{}", N.fetch_add(1, Ordering::Relaxed)));
    std::fs::write(&path, config).unwrap();
    Command::new(env!("CARGO_BIN_EXE_sshd"))
        .args(args)
        .arg("-f")
        .arg(&path)
        .output()
        .unwrap()
}

fn dump(config: &str, extra: &[&str]) -> Vec<(String, String)> {
    let mut args = vec!["-G"];
    args.extend_from_slice(extra);
    let out = run(config, &args);
    assert!(
        out.status.success(),
        "sshd -G failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| {
            let (k, v) = l.split_once(' ').unwrap_or((l, ""));
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn get<'a>(d: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    d.iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .collect()
}

const CONFIG: &str = "\
Port 2222
PermitRootLogin no
KbdInteractiveAuthentication no
X11Forwarding yes
AcceptEnv LANG LC_*
Match User alice
    PasswordAuthentication no
    AllowTcpForwarding local
    ForceCommand /bin/true
    RefuseConnection yes
";

#[test]
fn dumps_effective_values_and_defaults() {
    let d = dump(CONFIG, &[]);
    // OpenSSH 10.6 spells the keywords as its keyword table does.
    let keys: Vec<&str> = d.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys[..3], ["Port", "AddressFamily", "ListenAddress"]);
    assert_eq!(keys.last(), Some(&"PerSourcePenalties"));
    assert_eq!(get(&d, "Port"), ["2222"]);
    assert_eq!(get(&d, "PermitRootLogin"), ["no"]);
    assert_eq!(get(&d, "KbdInteractiveAuthentication"), ["no"]);
    assert_eq!(get(&d, "X11Forwarding"), ["yes"]);
    assert_eq!(get(&d, "AcceptEnv"), ["LANG", "LC_*"]);
    // OpenSSH's defaults for what the file leaves unset.
    assert_eq!(get(&d, "PasswordAuthentication"), ["yes"]);
    assert_eq!(get(&d, "MaxAuthTries"), ["6"]);
    assert_eq!(get(&d, "MaxStartups"), ["10:30:100"]);
    assert_eq!(get(&d, "LoginGraceTime"), ["120"]);
    assert_eq!(get(&d, "ForceCommand"), ["none"]);
    assert_eq!(get(&d, "RefuseConnection"), ["no"]);
    assert_eq!(get(&d, "X11DisplayOffset"), ["10"]);
    assert_eq!(get(&d, "X11UseLocalhost"), ["yes"]);
    assert_eq!(get(&d, "StreamLocalBindMask"), ["0177"]);
    assert_eq!(get(&d, "StreamLocalBindUnlink"), ["no"]);
    assert_eq!(get(&d, "IPQoS"), ["ef cs0"]);
    assert_eq!(get(&d, "VersionAddendum"), ["none"]);
    assert_eq!(get(&d, "UseDNS"), ["no"]);
    assert_eq!(get(&d, "FingerprintHash"), ["SHA256"]);
    assert_eq!(get(&d, "TCPKeepAlive"), ["true"]);
    assert_eq!(get(&d, "WarnWeakCrypto"), ["true"]);
    assert_eq!(get(&d, "AgentSocketPath"), ["user:.ssh/agent"]);
    assert_eq!(get(&d, "ModuliFile"), ["/etc/ssh/moduli"]);
    assert!(get(&d, "LogVerbose").is_empty());
    assert_eq!(
        get(&d, "AuthorizedKeysFile"),
        [".ssh/authorized_keys .ssh/authorized_keys2"]
    );
    assert_eq!(get(&d, "ListenAddress"), ["[::]:2222", "0.0.0.0:2222"]);
}

#[test]
fn dumps_the_keywords_it_implements() {
    let d = dump(
        "X11DisplayOffset 20\nX11UseLocalhost no\nStreamLocalBindMask 0\n\
         StreamLocalBindUnlink yes\nIPQoS af21 7\nVersionAddendum  hi there\nUseDNS yes\n\
         ModuliFile /etc/moduli\nLogVerbose kex.c:*:1000 packet.c:*\nFingerprintHash md5\n\
         AgentSocketPath shared:/tmp\nWarnWeakCrypto no-pq-kex\nTCPKeepAlive all\n\
         AuthorizedKeysFile none\nPermitOpen localhost:80 [::1]:22\n\
         ListenAddress 127.0.0.1:2200\n",
        &[],
    );
    for (k, v) in [
        ("X11DisplayOffset", "20"),
        ("X11UseLocalhost", "no"),
        ("StreamLocalBindMask", "00"),
        ("StreamLocalBindUnlink", "yes"),
        ("IPQoS", "af21 0x07"),
        ("VersionAddendum", "hi there"),
        ("UseDNS", "yes"),
        ("ModuliFile", "/etc/moduli"),
        ("LogVerbose", "kex.c:*:1000 packet.c:*"),
        ("FingerprintHash", "MD5"),
        ("AgentSocketPath", "shared:/tmp"),
        ("WarnWeakCrypto", "false"),
        ("TCPKeepAlive", "all"),
        ("PermitOpen", "localhost:80 [::1]:22"),
        ("ListenAddress", "127.0.0.1:2200"),
    ] {
        assert_eq!(get(&d, k), [v], "{k}");
    }
    // `AuthorizedKeysFile none` leaves no line, as in OpenSSH.
    assert!(get(&d, "AuthorizedKeysFile").is_empty());
}

#[test]
fn connection_spec_applies_match_blocks() {
    let d = dump(
        CONFIG,
        &["-T", "-C", "user=alice,host=example.com,addr=192.0.2.1"],
    );
    assert_eq!(get(&d, "PasswordAuthentication"), ["no"]);
    assert_eq!(get(&d, "AllowTcpForwarding"), ["local"]);
    assert_eq!(get(&d, "ForceCommand"), ["/bin/true"]);
    assert_eq!(get(&d, "RefuseConnection"), ["yes"]);
    let d = dump(CONFIG, &["-T", "-C", "user=bob", "-C", "addr=192.0.2.1"]);
    assert_eq!(get(&d, "PasswordAuthentication"), ["yes"]);
    assert_eq!(get(&d, "ForceCommand"), ["none"]);
}

#[test]
fn command_line_options_as_openssh() {
    // `-C` needs `-T`; a bad spec is reported first.
    let out = run(CONFIG, &["-G", "-C", "user=x"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("without test mode (-T)"));
    let out = run(CONFIG, &["-G", "-T", "-C", "bogus=1"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("Invalid test mode specification"));
    // `-R` is OpenSSH's internal re-exec flag; `-u` takes at most 65.
    let out = run(CONFIG, &["-G", "-R"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("-R not supported here"));
    let out = run(CONFIG, &["-G", "-u", "66"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("Invalid utmp length."));
    // Ignored: `-Q`, and protocol 1's `-b bits` / `-k seconds`.
    let d = dump(CONFIG, &["-Q", "-b", "1024", "-k", "3600", "-u0"]);
    assert_eq!(get(&d, "ListenAddress"), ["[::]:2222", "0.0.0.0:2222"]);
    // `-d` stacks up to DEBUG3 and wins over the file, like `-q`.
    assert_eq!(get(&dump(CONFIG, &["-d"]), "LogLevel"), ["DEBUG1"]);
    assert_eq!(get(&dump(CONFIG, &["-dd"]), "LogLevel"), ["DEBUG2"]);
    assert_eq!(
        get(&dump(CONFIG, &["-d", "-d", "-dd"]), "LogLevel"),
        ["DEBUG3"]
    );
    assert_eq!(get(&dump(CONFIG, &["-q"]), "LogLevel"), ["QUIET"]);
}

#[test]
fn test_mode_checks_the_host_keys() {
    // `-T`, unlike `-G`, loads the host keys first.
    let out = run("HostKey /nonexistent/puressh-test-host-key\n", &["-T"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}
