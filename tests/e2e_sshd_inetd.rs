//! Our `sshd -i` (inetd mode) driven by OpenSSH's `ssh` and `sftp` through
//! a `ProxyCommand`, as OpenSSH's regression suite drives an sshd: the
//! banner (sent once the first userauth request arrives, or OpenSSH's client
//! refuses it), `user:style` names, a pipe peer that matches no `from=`,
//! command subsystems and a forced `internal-sftp -d`.
//!
//! `#[ignore]` by default (needs OpenSSH's `ssh`, `sftp` and `ssh-keygen`).
//! Run with: `cargo test --test e2e_sshd_inetd -- --ignored`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn find(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn keygen(path: &Path) {
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .status()
            .expect("ssh-keygen")
            .success()
    );
}

struct Setup {
    dir: PathBuf,
    user: String,
}

impl Setup {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The `sshd_config` for this run: the common lines plus `extra`.
    fn config(&self, extra: &str) -> PathBuf {
        let cfg = self.path("sshd_config");
        std::fs::write(
            &cfg,
            format!(
                "HostKey {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\n\
                 LogLevel DEBUG\n{extra}",
                self.path("host").display(),
                self.path("ak").display()
            ),
        )
        .unwrap();
        cfg
    }

    /// Common client options: our `sshd -i` as the ProxyCommand.
    fn client_args(&self, extra: &str) -> Vec<String> {
        let cfg = self.config(extra);
        let kh = self.path("known_hosts");
        let host_pub = std::fs::read_to_string(self.path("host.pub")).unwrap();
        std::fs::write(&kh, format!("inetd-test {host_pub}")).unwrap();
        [
            "-F".to_string(),
            "/dev/null".into(),
            "-i".into(),
            self.path("user").display().to_string(),
            "-oBatchMode=yes".into(),
            "-oIdentitiesOnly=yes".into(),
            "-oIdentityAgent=none".into(),
            "-oHostKeyAlias=inetd-test".into(),
            format!("-oUserKnownHostsFile={}", kh.display()),
            format!(
                "-oProxyCommand={} -i -f {} -E {}",
                env!("CARGO_BIN_EXE_sshd"),
                cfg.display(),
                self.path("sshd.log").display()
            ),
        ]
        .into()
    }

    fn ssh(&self, extra_cfg: &str, args: &[&str], stdin: &[u8]) -> Output {
        use std::io::Write;
        let mut child = Command::new("ssh")
            .args(self.client_args(extra_cfg))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run ssh");
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }
}

#[test]
#[ignore]
fn openssh_client_through_sshd_inetd() {
    if ["ssh", "sftp", "ssh-keygen"]
        .iter()
        .any(|b| find(b).is_none())
    {
        eprintln!("e2e_sshd_inetd: skipping (no ssh / sftp / ssh-keygen)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("puressh-inetd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let s = Setup { dir, user };
    keygen(&s.path("host"));
    keygen(&s.path("user"));
    let user_pub = std::fs::read_to_string(s.path("user.pub")).unwrap();
    std::fs::write(s.path("ak"), &user_pub).unwrap();
    let target = format!("{}@inetd-test", s.user);
    let mut failures = Vec::new();
    let text = |o: &Output| {
        format!(
            "status {:?}, stdout {:?}, stderr {:?}",
            o.status.code(),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    };

    // A plain command; the peer of a pipe is OpenSSH's "UNKNOWN".
    let out = s.ssh("", &[&target, "echo $SSH_CONNECTION"], b"");
    if String::from_utf8_lossy(&out.stdout).trim() != "UNKNOWN 65535 UNKNOWN 65535" {
        failures.push(format!("plain exec: {}", text(&out)));
    }

    // The banner, verbatim and alone on stderr.
    let banner = s.path("banner");
    std::fs::write(&banner, "welcome\nto the test\n").unwrap();
    let out = s.ssh(
        &format!("Banner {}\n", banner.display()),
        &["-oLogLevel=INFO", &target, "true"],
        b"",
    );
    if !out.status.success() || out.stderr != b"welcome\nto the test\n" {
        failures.push(format!("banner: {}", text(&out)));
    }

    // `user:style` authenticates `user`.
    let out = s.ssh(
        "",
        &[&format!("{}:style@inetd-test", s.user), "id -un"],
        b"",
    );
    if String::from_utf8_lossy(&out.stdout).trim() != s.user {
        failures.push(format!("user:style: {}", text(&out)));
    }

    // `from="127.0.0.1"` does not match a pipe's unknown peer.
    std::fs::write(s.path("ak"), format!("from=\"127.0.0.1\" {user_pub}")).unwrap();
    let out = s.ssh("", &[&target, "true"], b"");
    if out.status.success() {
        failures.push(format!("from= on an unknown peer accepted: {}", text(&out)));
    }
    std::fs::write(s.path("ak"), &user_pub).unwrap();

    // A command subsystem, with its arguments.
    let out = s.ssh(
        "Subsystem upcase tr a-z A-Z\n",
        &["-s", &target, "upcase"],
        b"hello\n",
    );
    if out.stdout != b"HELLO\n" {
        failures.push(format!("command subsystem: {}", text(&out)));
    }
    let out = s.ssh("", &["-s", &target, "nosuch"], b"");
    if out.status.success() {
        failures.push(format!("unknown subsystem accepted: {}", text(&out)));
    }

    // A `Match` block's Subsystem wins over the global one; a second
    // definition of a name is ignored.
    let out = s.ssh(
        "Subsystem x echo global\nSubsystem x echo second\nMatch all\n  Subsystem x echo matched\n",
        &["-s", &target, "x"],
        b"",
    );
    if out.stdout != b"matched\n" {
        failures.push(format!("Subsystem in Match: {}", text(&out)));
    }

    // ExposeAuthInfo: the methods that succeeded, in $SSH_USER_AUTH.
    let out = s.ssh(
        "ExposeAuthInfo yes\n",
        &[&target, "cat \"$SSH_USER_AUTH\""],
        b"",
    );
    let want = format!(
        "publickey {}",
        user_pub
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    );
    if String::from_utf8_lossy(&out.stdout).trim() != want {
        failures.push(format!("ExposeAuthInfo: {}", text(&out)));
    }
    let out = s.ssh("", &[&target, "echo \"[$SSH_USER_AUTH]\""], b"");
    if String::from_utf8_lossy(&out.stdout).trim() != "[]" {
        failures.push(format!(
            "SSH_USER_AUTH without ExposeAuthInfo: {}",
            text(&out)
        ));
    }

    // scp (original protocol) of two files onto a plain file: refused, the
    // file left alone.
    let (a, b, dest) = (s.path("a"), s.path("b"), s.path("dest"));
    std::fs::write(&a, "a").unwrap();
    std::fs::write(&b, "b").unwrap();
    std::fs::write(&dest, "keep").unwrap();
    let mut scp_args = vec!["-O".to_string()];
    scp_args.extend(s.client_args(""));
    let out = Command::new("scp")
        .args(&scp_args)
        .arg(&a)
        .arg(&b)
        .arg(format!("{}:{}", target, dest.display()))
        .stdin(Stdio::null())
        .output()
        .expect("run scp");
    if out.status.success()
        || std::fs::read_to_string(&dest).unwrap() != "keep"
        || !String::from_utf8_lossy(&out.stderr).contains("Not a directory")
    {
        failures.push(format!("scp onto a non-directory: {}", text(&out)));
    }

    // A forced `internal-sftp` with a start directory.
    let start = s.path("start");
    std::fs::create_dir_all(&start).unwrap();
    std::fs::write(start.join("marker"), "x").unwrap();
    let mut args = s.client_args(&format!(
        "ForceCommand internal-sftp -d {}\n",
        start.display()
    ));
    args.extend(["-b".to_string(), "-".to_string(), target.clone()]);
    let out = {
        use std::io::Write;
        let mut child = Command::new("sftp")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run sftp");
        child.stdin.take().unwrap().write_all(b"pwd\nls\n").unwrap();
        child.wait_with_output().unwrap()
    };
    let listing = String::from_utf8_lossy(&out.stdout);
    if !listing.contains(&format!("Remote working directory: {}", start.display()))
        || !listing.contains("marker")
    {
        failures.push(format!("forced internal-sftp -d: {}", text(&out)));
    }

    if failures.is_empty() {
        let _ = std::fs::remove_dir_all(&s.dir);
    } else {
        let log = std::fs::read_to_string(s.path("sshd.log")).unwrap_or_default();
        failures.push(format!("sshd log (last run):\n{log}"));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
