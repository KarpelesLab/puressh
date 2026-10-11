//! `ssh-keygen` interop with OpenSSH's: SSH signatures (`-Y`, what git
//! uses) and certificates (`-s`, `-L`), in both directions.
//!
//! `#[ignore]` by default; run with `cargo test --test e2e_keygen -- --ignored`.
//! Requires OpenSSH's `ssh-keygen` on PATH. `cfg(unix)`-only.

#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const OURS: &str = env!("CARGO_BIN_EXE_ssh-keygen");

fn tempdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("puressh-e2e-keygen-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run `prog args` in `dir` with `stdin`, returning its output.
fn run(dir: &Path, prog: &str, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(prog)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {prog}: {e}"));
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn ok(dir: &Path, prog: &str, args: &[&str], stdin: &[u8]) -> String {
    let out = run(dir, prog, args, stdin);
    assert!(
        out.status.success(),
        "{prog} {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn keygen(dir: &Path, kind: &str, name: &str) {
    ok(
        dir,
        "ssh-keygen",
        &["-q", "-t", kind, "-N", "", "-f", name, "-C", name],
        b"",
    );
}

fn pub_line(dir: &Path, name: &str) -> String {
    let text = std::fs::read_to_string(dir.join(format!("{name}.pub"))).unwrap();
    text.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
#[ignore]
fn sshsig_interop() {
    let dir = tempdir("sig");
    let msg = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n";
    for kind in ["ed25519", "ecdsa", "rsa"] {
        keygen(&dir, kind, kind);
        let allowed = format!(
            "{kind}@example.com namespaces=\"git\" {}\n",
            pub_line(&dir, kind)
        );
        std::fs::write(dir.join("allowed"), allowed).unwrap();
        for (signer, verifier) in [(OURS, "ssh-keygen"), ("ssh-keygen", OURS)] {
            // Sign from stdin to stdout, as git does with a buffer file.
            let sig = ok(&dir, signer, &["-Y", "sign", "-n", "git", "-f", kind], msg);
            assert!(sig.starts_with("-----BEGIN SSH SIGNATURE-----"));
            std::fs::write(dir.join("msg.sig"), &sig).unwrap();
            let principal = format!("{kind}@example.com");
            let found = ok(
                &dir,
                verifier,
                &["-Y", "find-principals", "-f", "allowed", "-s", "msg.sig"],
                b"",
            );
            assert_eq!(found.trim(), principal);
            let good = ok(
                &dir,
                verifier,
                &[
                    "-Y", "verify", "-n", "git", "-f", "allowed", "-I", &principal, "-s", "msg.sig",
                ],
                msg,
            );
            assert!(
                good.starts_with(&format!("Good \"git\" signature for {principal} with ")),
                "{good}"
            );
            // Wrong namespace and tampered data are refused.
            for (ns, data) in [("file", &msg[..]), ("git", &b"tampered\n"[..])] {
                let out = run(
                    &dir,
                    verifier,
                    &[
                        "-Y", "verify", "-n", ns, "-f", "allowed", "-I", &principal, "-s",
                        "msg.sig",
                    ],
                    data,
                );
                assert!(!out.status.success(), "{signer}->{verifier} {kind} {ns}");
            }
        }
    }
}

#[test]
#[ignore]
fn certificate_interop() {
    let dir = tempdir("cert");
    keygen(&dir, "ed25519", "ca");
    keygen(&dir, "rsa", "rca");
    keygen(&dir, "ecdsa", "user");
    let options: &[&[&str]] = &[
        &["-n", "alice,root", "-V", "-1d:+52w", "-z", "7"],
        &[
            "-n",
            "bob",
            "-O",
            "force-command=/bin/true",
            "-O",
            "source-address=10.0.0.0/8",
            "-O",
            "no-pty",
            "-O",
            "extension:foo@example.com=bar",
        ],
        &["-O", "clear", "-O", "permit-pty", "-V", "always:20300101"],
        &["-h", "-n", "host.example.com"],
    ];
    for ca in ["ca", "rca"] {
        for opts in options {
            let mut args = vec!["-q", "-s", ca, "-I", "key id"];
            args.extend_from_slice(opts);
            args.push("user.pub");
            for signer in [OURS, "ssh-keygen"] {
                ok(&dir, signer, &args, b"");
                // Both tools describe the certificate identically.
                let theirs = ok(&dir, "ssh-keygen", &["-L", "-f", "user-cert.pub"], b"");
                let ours = ok(&dir, OURS, &["-L", "-f", "user-cert.pub"], b"");
                assert_eq!(ours, theirs, "{signer} {ca} {opts:?}");
            }
        }
    }
}

/// Fingerprint forms, randomart, conversions, SSHFP and KRLs agree with
/// OpenSSH's ssh-keygen.
#[test]
#[ignore]
fn formats_fingerprints_krl_interop() {
    let dir = tempdir("fmt");
    for kind in ["rsa", "ecdsa", "ed25519"] {
        keygen(&dir, kind, kind);
        let pubf = format!("{kind}.pub");
        for flags in [
            &["-l", "-f"][..],
            &["-l", "-v", "-f"],
            &["-l", "-E", "md5", "-f"],
            &["-B", "-f"],
            &["-e", "-m", "PKCS8", "-f"],
            &["-r", "host.example", "-f"],
            &["-r", "host.example", "-g", "-f"],
        ] {
            let mut args = flags.to_vec();
            args.push(&pubf);
            // OpenSSH has no PKCS8 export for Ed25519 keys.
            if kind == "ed25519" && flags.contains(&"PKCS8") {
                continue;
            }
            let theirs = ok(&dir, "ssh-keygen", &args, b"");
            let ours = ok(&dir, OURS, &args, b"");
            assert_eq!(ours, theirs, "{kind} {flags:?}");
        }
        // Each side imports the other's exports.
        let exported = ok(&dir, "ssh-keygen", &["-e", "-f", &pubf], b"");
        std::fs::write(dir.join("exp"), exported).unwrap();
        let imported = ok(&dir, OURS, &["-i", "-f", "exp"], b"");
        assert_eq!(
            imported.split_whitespace().nth(1),
            pub_line(&dir, kind).split_whitespace().nth(1)
        );
        // PEM / PKCS8 private keys we write load in OpenSSH.
        for m in ["PEM", "PKCS8"] {
            if kind == "ed25519" && m == "PEM" {
                continue;
            }
            let name = format!("{kind}_{m}");
            ok(
                &dir,
                OURS,
                &["-q", "-t", kind, "-m", m, "-N", "", "-f", &name],
                b"",
            );
            let derived = ok(&dir, "ssh-keygen", &["-y", "-f", &name], b"");
            assert_eq!(
                derived.split_whitespace().nth(1),
                pub_line(&dir, &name).split_whitespace().nth(1)
            );
        }
    }

    // A KRL built by either tool reads the same in both.
    keygen(&dir, "ed25519", "ca");
    keygen(&dir, "ed25519", "u");
    ok(
        &dir,
        "ssh-keygen",
        &["-q", "-s", "ca", "-I", "alice", "-z", "150", "u.pub"],
        b"",
    );
    let spec = format!("serial: 100-200\nkey: {}\n", pub_line(&dir, "rsa"));
    std::fs::write(dir.join("spec"), spec).unwrap();
    let files = ["u-cert.pub", "u.pub", "rsa.pub", "ecdsa.pub"];
    for (builder, krl) in [(OURS, "ours.krl"), ("ssh-keygen", "theirs.krl")] {
        ok(
            &dir,
            builder,
            &["-k", "-f", krl, "-s", "ca.pub", "spec"],
            b"",
        );
        let mut q = vec!["-Q", "-f", krl];
        q.extend_from_slice(&files);
        let theirs = run(&dir, "ssh-keygen", &q, b"");
        let ours = run(&dir, OURS, &q, b"");
        assert_eq!(ours.stdout, theirs.stdout, "{krl}");
        assert_eq!(ours.status.code(), theirs.status.code(), "{krl}");
    }
}
