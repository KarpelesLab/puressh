//! `sshd -T [-C spec]`: the effective configuration, as admin tooling reads
//! it (`sshd -T | grep -i permitrootlogin`). Runs the binary; binds nothing.

#![cfg(unix)]

use std::process::Command;

fn dump(config: &str, extra: &[&str]) -> Vec<(String, String)> {
    let dir = std::env::temp_dir().join(format!("puressh-sshd-dump-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("sshd_config.{}", extra.len()));
    std::fs::write(&path, config).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sshd"))
        .arg("-T")
        .arg("-f")
        .arg(&path)
        .args(extra)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sshd -T failed: {}",
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
";

#[test]
fn dumps_effective_values_and_defaults() {
    let d = dump(CONFIG, &[]);
    // Keywords are lowercase, as on the Ubuntu releases we replace.
    assert!(
        d.iter()
            .all(|(k, _)| k.chars().all(|c| !c.is_ascii_uppercase()))
    );
    assert_eq!(get(&d, "port"), ["2222"]);
    assert_eq!(get(&d, "permitrootlogin"), ["no"]);
    assert_eq!(get(&d, "kbdinteractiveauthentication"), ["no"]);
    assert_eq!(get(&d, "x11forwarding"), ["yes"]);
    assert_eq!(get(&d, "acceptenv"), ["LANG", "LC_*"]);
    // OpenSSH's defaults for what the file leaves unset.
    assert_eq!(get(&d, "passwordauthentication"), ["yes"]);
    assert_eq!(get(&d, "maxauthtries"), ["6"]);
    assert_eq!(get(&d, "maxstartups"), ["10:30:100"]);
    assert_eq!(get(&d, "logingracetime"), ["120"]);
    assert_eq!(get(&d, "forcecommand"), ["none"]);
    assert_eq!(
        get(&d, "authorizedkeysfile"),
        [".ssh/authorized_keys .ssh/authorized_keys2"]
    );
    assert_eq!(get(&d, "listenaddress"), ["[::]:2222", "0.0.0.0:2222"]);
}

#[test]
fn connection_spec_applies_match_blocks() {
    let d = dump(
        CONFIG,
        &["-C", "user=alice,host=example.com,addr=192.0.2.1"],
    );
    assert_eq!(get(&d, "passwordauthentication"), ["no"]);
    assert_eq!(get(&d, "allowtcpforwarding"), ["local"]);
    assert_eq!(get(&d, "forcecommand"), ["/bin/true"]);
    let d = dump(CONFIG, &["-C", "user=bob", "-C", "addr=192.0.2.1"]);
    assert_eq!(get(&d, "passwordauthentication"), ["yes"]);
    assert_eq!(get(&d, "forcecommand"), ["none"]);
}
