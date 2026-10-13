//! Tunnel device forwarding (`ssh -w`, `PermitTunnel`): our `ssh` and our
//! `sshd -i`, each in a network namespace of its own, with a ping across
//! the tunnel, in point-to-point (tun) and Ethernet (tap) modes; and our
//! client against OpenSSH's `sshd` when it is installed.
//!
//! The namespaces come from unprivileged user namespaces (`unshare -c
//! --keep-caps -n`), so no root is needed; the test skips itself where
//! they are not allowed or `ip` / `ping` are missing.
//!
//! `#[ignore]` by default. Run with:
//! `cargo test --test e2e_tunnel -- --ignored`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd} >/dev/null"))
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether this system lets us make a network namespace with tun devices.
fn namespaces_usable() -> bool {
    have("unshare")
        && have("ip")
        && have("ping")
        && Command::new("unshare")
            .args(["-c", "--keep-caps", "-n", "sh", "-c"])
            .arg("ip link set lo up && ip tuntap add dev tun9 mode tun")
            .status()
            .is_ok_and(|s| s.success())
}

fn keygen(path: &Path) {
    assert!(
        Command::new(env!("CARGO_BIN_EXE_ssh-keygen"))
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .status()
            .expect("ssh-keygen")
            .success()
    );
}

fn setup() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("puressh-tun-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    keygen(&dir.join("host"));
    keygen(&dir.join("id"));
    std::fs::copy(dir.join("id.pub"), dir.join("ak")).unwrap();
    std::fs::write(
        dir.join("sshd_config"),
        format!(
            "HostKey {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\n\
             PermitTunnel yes\nPidFile none\n",
            dir.join("host").display(),
            dir.join("ak").display()
        ),
    )
    .unwrap();
    dir
}

/// Bring a tunnel up between two namespaces with `ssh` and `sshd`, address
/// both ends and ping across; returns the script's output.
fn run_tunnel(dir: &Path, sshd: &str, ethernet: bool) -> String {
    let dev = if ethernet { "tap0" } else { "tun0" };
    let mode = if ethernet { "-oTunnel=ethernet " } else { "" };
    let script = format!(
        r#"ip link set lo up
{ssh} -F none -i {dir}/id -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null \
  -oLogLevel=ERROR {mode}-w 0:0 \
  -oProxyCommand="unshare --keep-caps -n sh -c 'ip link set lo up; exec {sshd} -i -f {dir}/sshd_config'" \
  "$(id -un)@peer" 'echo "remote:$SSH_TUNNEL"; ip addr add 10.9.0.2/30 dev {dev} && ip link set {dev} up && sleep 5' &
pid=$!
sleep 2
ip addr add 10.9.0.1/30 dev {dev} && ip link set {dev} up
ping -c 2 -W 2 10.9.0.2 && echo PING-OK
kill $pid 2>/dev/null
wait
"#,
        ssh = env!("CARGO_BIN_EXE_ssh"),
        dir = dir.display(),
    );
    let out = Command::new("timeout")
        .args(["30", "unshare", "-c", "--keep-caps", "-n", "sh", "-c"])
        .arg(&script)
        .output()
        .expect("unshare");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
#[ignore]
fn tun_and_tap_between_namespaces() {
    if !namespaces_usable() {
        eprintln!("skipping: no unprivileged network namespaces with tun devices");
        return;
    }
    let dir = setup();
    let ours = env!("CARGO_BIN_EXE_sshd");
    let mut sshds = vec![ours.to_string()];
    if Path::new("/usr/sbin/sshd").exists() {
        sshds.push("/usr/sbin/sshd".into());
    }
    for sshd in &sshds {
        for ethernet in [false, true] {
            let out = run_tunnel(&dir, sshd, ethernet);
            let dev = if ethernet { "tap0" } else { "tun0" };
            assert!(out.contains("PING-OK"), "{sshd} {dev}:\n{out}");
            assert!(
                out.contains(&format!("remote:{dev}")),
                "{sshd} {dev}:\n{out}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn permit_tunnel_no_refuses() {
    if !namespaces_usable() {
        eprintln!("skipping: no unprivileged network namespaces with tun devices");
        return;
    }
    let dir = setup();
    let cfg = dir.join("sshd_config");
    let text = std::fs::read_to_string(&cfg)
        .unwrap()
        .replace("PermitTunnel yes", "PermitTunnel no");
    std::fs::write(&cfg, text).unwrap();
    let script = format!(
        r#"ip link set lo up
{ssh} -F none -i {dir}/id -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null \
  -oLogLevel=ERROR -oExitOnForwardFailure=yes -w 0:0 \
  -oProxyCommand="unshare --keep-caps -n sh -c 'ip link set lo up; exec {sshd} -i -f {dir}/sshd_config'" \
  "$(id -un)@peer" true
echo "exit=$?"
"#,
        ssh = env!("CARGO_BIN_EXE_ssh"),
        sshd = env!("CARGO_BIN_EXE_sshd"),
        dir = dir.display(),
    );
    let out = Command::new("timeout")
        .args(["30", "unshare", "-c", "--keep-caps", "-n", "sh", "-c"])
        .arg(&script)
        .output()
        .expect("unshare");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("Tunnel forwarding failed"), "{text}");
    assert!(text.contains("exit=255"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
