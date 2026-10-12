//! Interop of OpenSSH's non-default algorithms, both ways, through the real
//! binaries: our `ssh` against OpenSSH's `sshd`, and OpenSSH's `ssh` against
//! our `sshd`. CBC ciphers, every MAC (UMAC, HMAC-SHA1/MD5 and the `-96`
//! forms, EtM or not), the SHA-1 and group-exchange key exchanges, `ssh-rsa`
//! (SHA-1) user signatures, and the "Unable to negotiate" / "Permission
//! denied" wording admins and tools look for.
//!
//! `#[ignore]` by default (needs OpenSSH's `ssh`, `sshd` and `ssh-keygen`).
//! Names the local OpenSSH does not offer (`ssh -Q`) are skipped. Run with:
//! `cargo test --test e2e_legacy_algos -- --ignored`.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn find(name: &str, extra: &[&str]) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .chain(extra.iter().map(PathBuf::from))
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn keygen(path: &Path, kind: &str) {
    let mut c = Command::new("ssh-keygen");
    c.args(["-q", "-t", kind, "-N", "", "-f"]).arg(path);
    if kind == "rsa" {
        c.args(["-b", "2048"]);
    }
    assert!(c.status().expect("ssh-keygen").success());
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_port(port: u16) {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no daemon on {port}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// What OpenSSH's `ssh -Q <what>` lists.
fn openssh_offers(what: &str) -> Vec<String> {
    let out = Command::new("ssh").args(["-Q", what]).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

struct Setup {
    dir: PathBuf,
    user: String,
    openssh_port: u16,
    ours_port: u16,
    _daemons: Vec<Daemon>,
}

impl Setup {
    /// Run `client` (`ours` / OpenSSH's) against `port`; stdout+stderr and
    /// whether `echo` came back.
    fn run(&self, ours: bool, port: u16, key: &str, opts: &[String]) -> (bool, String) {
        let bin = if ours {
            PathBuf::from(env!("CARGO_BIN_EXE_ssh"))
        } else {
            PathBuf::from("ssh")
        };
        let out = Command::new(bin)
            .args(["-F", "/dev/null", "-p", &port.to_string(), "-i"])
            .arg(self.dir.join(key))
            .args([
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "IdentityAgent=none",
            ])
            .args(opts.iter().flat_map(|o| ["-o", o.as_str()]))
            .arg(format!("{}@127.0.0.1", self.user))
            .arg("echo legacy-$((6*7))")
            .stdin(Stdio::null())
            .output()
            .expect("run ssh");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (text.contains("legacy-42"), text)
    }

    /// Both directions must log in with `opts`.
    fn both_ways(&self, what: &str, key: &str, opts: &[String], failures: &mut Vec<String>) {
        for (ours, port, dir) in [
            (true, self.openssh_port, "puressh ssh -> OpenSSH sshd"),
            (false, self.ours_port, "OpenSSH ssh -> puressh sshd"),
        ] {
            let (ok, out) = self.run(ours, port, key, opts);
            if !ok {
                failures.push(format!("{what}: {dir}: {}", out.trim()));
            }
        }
    }
}

const LEGACY: &str = "Ciphers +aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc\n\
    MACs +hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-sha1-96-etm@openssh.com,\
    hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com\n\
    KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,\
    diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256\n\
    PubkeyAcceptedAlgorithms +ssh-rsa\n";

fn setup() -> Option<Setup> {
    let sshd = find("sshd", &["/usr/sbin", "/usr/local/sbin"])?;
    find("ssh", &[])?;
    find("ssh-keygen", &[])?;
    let dir = std::env::temp_dir().join(format!("puressh-legacy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n);
    keygen(&p("host"), "ed25519");
    keygen(&p("user"), "ed25519");
    keygen(&p("user_rsa"), "rsa");
    keygen(&p("stranger"), "ed25519");
    let mut ak = std::fs::read(p("user.pub")).unwrap();
    ak.extend(std::fs::read(p("user_rsa.pub")).unwrap());
    std::fs::write(p("ak"), ak).unwrap();
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    // OpenSSH only accepts what this build has.
    let kex = openssh_offers("kex");
    let legacy: String = LEGACY
        .lines()
        .map(|l| {
            let (kw, list) = l.split_once(' ').unwrap();
            let kept: Vec<&str> = list
                .trim_start_matches('+')
                .split(',')
                .filter(|n| kw != "KexAlgorithms" || kex.iter().any(|k| k == n))
                .collect();
            format!("{kw} +{}\n", kept.join(","))
        })
        .collect();
    let base = |port: u16, pid: &str| {
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
             StrictModes no\nUsePAM no\nPidFile {}\nLogLevel INFO\n{legacy}",
            p("host").display(),
            p("ak").display(),
            p(pid).display()
        )
    };
    let (openssh_port, ours_port) = (free_port(), free_port());
    std::fs::write(p("openssh.cfg"), base(openssh_port, "o.pid")).unwrap();
    std::fs::write(p("ours.cfg"), base(ours_port, "p.pid")).unwrap();
    let spawn = |bin: &Path, cfg: &str, log: &str| {
        Daemon(
            Command::new(bin)
                .args(["-D", "-f"])
                .arg(p(cfg))
                .arg("-E")
                .arg(p(log))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sshd"),
        )
    };
    let daemons = vec![
        spawn(&sshd, "openssh.cfg", "openssh.log"),
        spawn(
            Path::new(env!("CARGO_BIN_EXE_sshd")),
            "ours.cfg",
            "ours.log",
        ),
    ];
    wait_port(openssh_port);
    wait_port(ours_port);
    Some(Setup {
        dir,
        user,
        openssh_port,
        ours_port,
        _daemons: daemons,
    })
}

#[test]
#[ignore]
fn legacy_algorithms_interoperate_with_openssh() {
    let Some(s) = setup() else {
        eprintln!("e2e_legacy_algos: skipping (OpenSSH ssh/sshd/ssh-keygen not found)");
        return;
    };
    let ciphers = openssh_offers("cipher");
    let macs = openssh_offers("mac");
    let kex = openssh_offers("kex");
    let mut failures = Vec::new();
    let o = |kv: &[&str]| kv.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    for c in ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"] {
        if !ciphers.iter().any(|x| x == c) {
            continue;
        }
        for m in [
            "hmac-sha1",
            "hmac-sha2-256-etm@openssh.com",
            "umac-64@openssh.com",
        ] {
            let opts = o(&[&format!("Ciphers={c}"), &format!("MACs={m}")]);
            s.both_ways(&format!("{c} + {m}"), "user", &opts, &mut failures);
        }
    }
    for m in [
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1-96-etm@openssh.com",
        "hmac-md5-etm@openssh.com",
        "hmac-md5-96-etm@openssh.com",
    ] {
        if !macs.iter().any(|x| x == m) {
            continue;
        }
        let opts = o(&["Ciphers=aes128-ctr", &format!("MACs={m}")]);
        s.both_ways(m, "user", &opts, &mut failures);
    }
    for k in [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group-exchange-sha256",
    ] {
        if !kex.iter().any(|x| x == k) {
            continue;
        }
        s.both_ways(
            k,
            "user",
            &o(&[&format!("KexAlgorithms={k}")]),
            &mut failures,
        );
    }
    // SHA-1 RSA user signatures, the only kind servers before OpenSSH 7.2
    // take: opted into on both sides.
    s.both_ways(
        "ssh-rsa userauth",
        "user_rsa",
        &o(&["PubkeyAcceptedAlgorithms=ssh-rsa"]),
        &mut failures,
    );

    // Failures are worded as OpenSSH words them.
    let (_, out) = s.run(
        true,
        s.openssh_port,
        "user",
        &o(&["KexAlgorithms=diffie-hellman-group18-sha512,ecdh-sha2-nistp521"]),
    );
    let (_, theirs) = s.run(
        false,
        s.openssh_port,
        "user",
        &o(&["KexAlgorithms=diffie-hellman-group18-sha512,ecdh-sha2-nistp521"]),
    );
    if !theirs.contains("no matching key exchange method found") {
        // This OpenSSH takes one of them: nothing to compare against.
    } else if !out.contains(&format!(
        "Unable to negotiate with 127.0.0.1 port {}: no matching key exchange method found. Their offer: ",
        s.openssh_port
    )) {
        failures.push(format!("negotiation failure wording: {out}"));
    }
    let (_, out) = s.run(true, s.openssh_port, "stranger", &[]);
    if !out.contains(&format!(
        "{}@127.0.0.1: Permission denied (publickey",
        s.user
    )) {
        failures.push(format!("auth failure wording: {out}"));
    }
    // Our sshd logs the client's offer, as OpenSSH does.
    let _ = s.run(
        false,
        s.ours_port,
        "user",
        &o(&["KexAlgorithms=sntrup761x25519-sha512"]),
    );
    if kex.iter().any(|k| k == "sntrup761x25519-sha512") {
        let log = std::fs::read_to_string(s.dir.join("ours.log")).unwrap_or_default();
        if !log
            .contains("no matching key exchange method found. Their offer: sntrup761x25519-sha512,")
            || !log.contains("Unable to negotiate with 127.0.0.1 port ")
        {
            failures.push(format!("sshd negotiation log: {log}"));
        }
    }

    let _ = std::fs::remove_dir_all(&s.dir);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
