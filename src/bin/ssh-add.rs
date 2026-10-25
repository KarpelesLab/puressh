//! `ssh-add` — add private keys to, list and remove keys from the agent.
//!
//! ```text
//! ssh-add [-CcDdkLlNqvXx] [-E fingerprint_hash] [-H hostkey_file]
//!         [-h destination_constraint] [-t life] [file ...]
//! ssh-add -Q
//! ssh-add -T pubkey ...
//! ```
//!
//! Works with any agent speaking the standard protocol (puressh's
//! `ssh-agent` or OpenSSH's), found through `$SSH_AUTH_SOCK`. Without files
//! it adds the default identities (`~/.ssh/id_rsa`, `id_ecdsa`,
//! `id_ed25519`) that exist; a key's certificate (`<file>-cert.pub`) is
//! added and removed along with it. `-h` restricts where added keys may be
//! used (OpenSSH's destination constraints, with the hosts' keys from
//! `known_hosts` or the `-H` files). Exit status: 0 on success, 1 on
//! failure, 2 if the agent cannot be reached.

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("ssh-add: only supported on Unix-like systems");
    std::process::ExitCode::from(2)
}

#[cfg(unix)]
#[path = "common.rs"]
mod common;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(imp::run() as u8)
}

#[cfg(unix)]
mod imp {
    use super::common;
    use purecrypto::zeroize::Zeroizing;
    use puressh::agent::{AddConstraints, Agent, DestinationConstraint, DestinationHop};
    use puressh::cert::Certificate;
    use puressh::key::{PrivateKey, PublicKey};

    const USAGE: &str = "usage: ssh-add [-CcDdKkLlqvXx] [-E fingerprint_hash] [-H hostkey_file]\n               [-h destination_constraint] [-S provider] [-t life]\n               [file ...]\n       ssh-add -s pkcs11 [-Cv] [certificate ...]\n       ssh-add -e pkcs11\n       ssh-add -T pubkey ...";

    /// How long after a certificate's expiry it may still be added
    /// (OpenSSH's `CERT_EXPIRY_GRACE`).
    const CERT_EXPIRY_GRACE: u64 = 5 * 60;

    #[derive(Default)]
    struct Opts {
        list: bool,
        list_full: bool,
        delete: bool,
        delete_all: bool,
        lock: bool,
        unlock: bool,
        quiet: bool,
        query: bool,
        test: bool,
        confirm: bool,
        key_only: bool,
        cert_only: bool,
        /// `-N`: don't cap a certificate's lifetime at its expiry.
        no_cert_lifetime: bool,
        lifetime: Option<u32>,
        /// `-E md5`: MD5 fingerprints (else SHA-256).
        md5: bool,
        /// `-v` count: OpenSSH's debug1 to debug3 messages.
        verbose: u8,
        destinations: Vec<String>,
        hostkey_files: Vec<String>,
        files: Vec<String>,
        /// `-S`: the `SecurityKeyProvider`.
        sk_provider: Option<String>,
        /// `-K`: add the authenticator's resident keys.
        download: bool,
        /// `-P`: don't ask for the authenticator's PIN.
        no_pin: bool,
        /// `-s` / `-e`: the PKCS#11 module to add or remove.
        pkcs11: Option<String>,
    }

    /// How `ssh-add` stops before doing anything: OpenSSH's `usage()`
    /// (exit 1, after an optional message), `fatal()` (exit 255) or
    /// another error (exit 1).
    #[derive(Debug, PartialEq)]
    enum Exit {
        Usage(Option<String>),
        Fatal(String),
        Fail(String),
    }

    /// OpenSSH's `convtime`: `90`, `90s`, `1.5`, `10m`, `1h30m`, `2d`,
    /// `1w`, in seconds.
    fn convtime(v: &str) -> Option<u64> {
        if v.is_empty() {
            return None;
        }
        let mut total = 0f64;
        let mut seen_seconds = false;
        let mut rest = v;
        while !rest.is_empty() {
            let end = rest
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(rest.len());
            let (num, tail) = rest.split_at(end);
            let val: f64 = num.parse().ok()?;
            let mut chars = tail.chars();
            let mult = match chars.next() {
                None | Some('s' | 'S') => {
                    if seen_seconds {
                        return None;
                    }
                    seen_seconds = true;
                    1.0
                }
                Some('m' | 'M') => 60.0,
                Some('h' | 'H') => 3600.0,
                Some('d' | 'D') => 86400.0,
                Some('w' | 'W') => 604800.0,
                Some(_) => return None,
            };
            // A fraction only for seconds, and with digits after the dot.
            if num.contains('.') && (mult > 1.0 || num.ends_with('.')) {
                return None;
            }
            total += val * mult;
            rest = chars.as_str();
        }
        (total <= i32::MAX as f64).then_some(total as u64)
    }

    /// `-t`: a lifetime, `None` for `0` (no limit).
    fn parse_lifetime(v: &str) -> Result<Option<u32>, Exit> {
        let t = convtime(v).ok_or_else(|| Exit::Fail("Invalid lifetime".into()))?;
        Ok((t > 0).then_some(t as u32))
    }

    /// OpenSSH's `debugN()`, shown from `N` `-v`s on.
    fn debug(o: &Opts, level: u8, msg: impl FnOnce() -> String) {
        if o.verbose >= level {
            eprintln!("debug{level}: {}", msg());
        }
    }

    /// OpenSSH's `fmt_timeframe`.
    fn fmt_timeframe(t: u32) -> String {
        let (sec, t) = (t % 60, t / 60);
        let (min, t) = (t % 60, t / 60);
        let (hrs, t) = (t % 24, t / 24);
        let (day, week) = (t % 7, t / 7);
        if week > 0 {
            format!("{week:02}w{day}d{hrs:02}h")
        } else if day > 0 {
            format!("{day}d{hrs:02}h{min:02}m")
        } else {
            format!("{hrs:02}:{min:02}:{sec:02}")
        }
    }

    fn parse_args(args: &[String]) -> Result<Opts, Exit> {
        let mut o = Opts::default();
        // The first of -l/-L and of -x/-X, for OpenSSH's message.
        let (mut lflag, mut xflag) = (None, None);
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "--" {
                o.files.extend(args[i + 1..].iter().cloned());
                break;
            }
            if !a.starts_with('-') || a == "-" {
                // Options end at the first operand, as with getopt.
                o.files.extend(args[i..].iter().cloned());
                break;
            }
            let chars: Vec<char> = a[1..].chars().collect();
            let mut j = 0;
            while j < chars.len() {
                let c = chars[j];
                if "tEHhSseMm".contains(c) {
                    let attached: String = chars[j + 1..].iter().collect();
                    let v = if !attached.is_empty() {
                        attached
                    } else {
                        i += 1;
                        args.get(i)
                            .ok_or_else(|| {
                                Exit::Usage(Some(format!("option requires an argument -- {c}")))
                            })?
                            .clone()
                    };
                    match c {
                        't' => o.lifetime = parse_lifetime(&v)?,
                        'E' => match v.to_ascii_lowercase().as_str() {
                            "md5" => o.md5 = true,
                            "sha256" => o.md5 = false,
                            _ => {
                                return Err(Exit::Fatal(format!("Invalid hash algorithm \"{v}\"")));
                            }
                        },
                        'h' => o.destinations.push(v),
                        'H' => o.hostkey_files.push(v),
                        'S' => o.sk_provider = Some(v),
                        's' => o.pkcs11 = Some(v),
                        'e' => {
                            o.delete = true;
                            o.pkcs11 = Some(v);
                        }
                        // Deprecated, ignored (OpenSSH's too).
                        _ => {}
                    }
                    break;
                }
                match c {
                    'l' | 'L' if lflag.is_some() => {
                        let f = lflag.unwrap_or(c);
                        return Err(Exit::Fatal(format!("-{f} flag already specified")));
                    }
                    'x' | 'X' if xflag.is_some() => {
                        let f = xflag.unwrap_or(c);
                        return Err(Exit::Fatal(format!("-{f} flag already specified")));
                    }
                    'l' | 'L' => {
                        lflag = Some(c);
                        o.list = c == 'l';
                        o.list_full = c == 'L';
                    }
                    'd' => o.delete = true,
                    'D' => o.delete_all = true,
                    'x' | 'X' => {
                        xflag = Some(c);
                        o.lock = c == 'x';
                        o.unlock = c == 'X';
                    }
                    'q' => o.quiet = true,
                    'Q' => o.query = true,
                    'T' => o.test = true,
                    'c' => o.confirm = true,
                    'k' => o.key_only = true,
                    'C' => o.cert_only = true,
                    'N' => o.no_cert_lifetime = true,
                    'v' => o.verbose = (o.verbose + 1).min(3),
                    'K' => o.download = true,
                    'P' => o.no_pin = true,
                    _ => return Err(Exit::Usage(Some(format!("unknown option -- {c}")))),
                }
                j += 1;
            }
            i += 1;
        }
        let actions = [
            o.lock || o.unlock,
            o.list || o.list_full,
            o.delete_all,
            o.query,
        ];
        if actions.iter().filter(|a| **a).count() > 1 {
            return Err(Exit::Fatal("Invalid combination of actions".into()));
        }
        Ok(o)
    }

    fn label(pk: &PublicKey) -> &'static str {
        match pk {
            PublicKey::Ed25519 { .. } => "ED25519",
            PublicKey::Rsa { .. } => "RSA",
            PublicKey::MlDsa44Ed25519 { .. } => "MLDSA44-ED25519",
            PublicKey::SkEcdsaP256 { .. } => "ECDSA-SK",
            PublicKey::SkEd25519 { .. } => "ED25519-SK",
            _ => "ECDSA",
        }
    }

    fn default_files() -> Vec<String> {
        let home = std::env::var("HOME").unwrap_or_default();
        [
            "id_rsa",
            "id_ecdsa",
            "id_ecdsa_sk",
            "id_ed25519",
            "id_ed25519_sk",
        ]
        .iter()
        .map(|n| format!("{home}/.ssh/{n}"))
        .filter(|p| std::path::Path::new(p).exists())
        .collect()
    }

    /// A key or certificate file's public half: the key itself, or a
    /// certificate as its embedded key plus the certificate.
    fn read_public(path: &str) -> Result<(PublicKey, Option<Certificate>), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let line = text.trim();
        if let Ok(c) = Certificate::parse_openssh_line(line) {
            let mut pk = PublicKey::parse_wire_blob(c.embedded_pubkey_blob())
                .map_err(|e| format!("{path}: {e}"))?;
            if let Some(comment) = line.splitn(3, ' ').nth(2) {
                pk = PublicKey::parse_authorized_keys_line(&format!(
                    "{} {comment}",
                    pk.to_authorized_keys_line().trim_end()
                ))
                .unwrap_or(pk);
            }
            return Ok((pk, Some(c)));
        }
        PublicKey::parse_authorized_keys_line(line)
            .map(|pk| (pk, None))
            .map_err(|e| format!("{path}: {e}"))
    }

    /// The certificate next to the key at `path` (`path-cert.pub`), if
    /// there is one.
    fn load_cert(path: &str) -> Option<(String, Certificate)> {
        let certpath = format!("{path}-cert.pub");
        let line = std::fs::read_to_string(&certpath).ok()?;
        match Certificate::parse_openssh_line(line.trim()) {
            Ok(c) => Some((certpath, c)),
            Err(e) => {
                eprintln!("Failed to load certificate \"{certpath}\": {e}");
                None
            }
        }
    }

    /// Adds keys, remembering the last passphrase that worked so that keys
    /// sharing one are only asked for once (as OpenSSH's `ssh-add` does).
    struct Adder<'a> {
        agent: &'a mut Agent,
        o: &'a Opts,
        constraints: AddConstraints,
        pass: Option<Zeroizing<String>>,
    }

    impl Adder<'_> {
        fn load_private(&mut self, path: &str, pem: &str) -> Result<PrivateKey, String> {
            match PrivateKey::parse_pem(pem, None) {
                Ok(k) => return Ok(k),
                Err(puressh::Error::Crypto(_)) => {}
                Err(e) => return Err(format!("Error loading key \"{path}\": {e}")),
            }
            if let Some(p) = &self.pass
                && let Ok(k) = PrivateKey::parse_pem(pem, Some(p.as_bytes()))
            {
                return Ok(k);
            }
            self.pass = None;
            let suffix = if self.o.confirm {
                " (will confirm each use)"
            } else {
                ""
            };
            let mut prompt = format!("Enter passphrase for {path}{suffix}: ");
            loop {
                let pass = common::read_secret(&prompt)
                    .map_err(|e| format!("Error loading key \"{path}\": {e}"))?;
                if pass.is_empty() {
                    return Err(String::new());
                }
                if let Ok(k) = PrivateKey::parse_pem(pem, Some(pass.as_bytes())) {
                    self.pass = Some(pass);
                    return Ok(k);
                }
                prompt = format!("Bad passphrase, try again for {path}{suffix}: ");
            }
        }

        fn added_messages(&self, lifetime: Option<u32>) {
            if let Some(t) = lifetime {
                eprintln!("Lifetime set to {}", fmt_timeframe(t));
            }
            if self.o.confirm {
                eprintln!("The user must confirm each use of the key");
            }
        }

        /// OpenSSH's `add_file`.
        fn add_file(&mut self, path: &str) -> bool {
            let (name, pem) = if path == "-" {
                let mut s = String::new();
                if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut s) {
                    eprintln!("Error loading key \"(stdin)\": {e}");
                    return false;
                }
                ("(stdin)", s)
            } else {
                if let Err(e) = common::check_identity_perms(std::path::Path::new(path)) {
                    eprintln!("{e}");
                    return false;
                }
                match std::fs::read_to_string(path) {
                    Ok(s) => (path, s),
                    Err(e) => {
                        eprintln!("{path}: {e}");
                        return false;
                    }
                }
            };
            let mut key = match self.load_private(name, &pem) {
                Ok(k) => k,
                Err(e) => {
                    if !e.is_empty() {
                        eprintln!("{e}");
                    }
                    return false;
                }
            };
            if key.comment().is_empty() {
                key.set_comment(name);
            }
            let comment = key.comment().to_string();
            let mut ok = false;
            if !self.o.cert_only {
                match self.agent.add_constrained(&key, None, &self.constraints) {
                    Ok(()) => {
                        ok = true;
                        if !self.o.quiet {
                            eprintln!("Identity added: {name} ({comment})");
                            self.added_messages(self.constraints.lifetime);
                        }
                    }
                    Err(_) => {
                        eprintln!("Could not add identity \"{name}\": agent refused operation")
                    }
                }
            }
            if self.o.key_only || path == "-" {
                return ok;
            }
            // Like OpenSSH's, the certificate next to the key goes in too.
            let Some((certpath, cert)) = load_cert(path) else {
                return ok;
            };
            if cert.embedded_pubkey_blob() != key.public_key().wire_blob() {
                eprintln!("Certificate {certpath} does not match private key {path}");
                return ok;
            }
            let mut c = self.constraints.clone();
            if !self.o.no_cert_lifetime && cert.valid_before != u64::MAX {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                if now > cert.valid_before.saturating_add(CERT_EXPIRY_GRACE) {
                    eprintln!("Certificate {certpath} has already expired; ignored");
                    return ok;
                }
                let left =
                    (cert.valid_before + CERT_EXPIRY_GRACE - now).min(i32::MAX as u64) as u32;
                c.lifetime = Some(c.lifetime.map_or(left, |l| l.min(left)));
            }
            match self.agent.add_constrained(&key, Some(&cert.raw), &c) {
                Ok(()) => {
                    if !self.o.quiet {
                        eprintln!("Certificate added: {certpath} ({})", cert.key_id);
                        self.added_messages(c.lifetime);
                    }
                    true
                }
                Err(_) => {
                    eprintln!(
                        "Certificate {certpath} ({}) add failed: agent refused operation",
                        cert.key_id
                    );
                    ok
                }
            }
        }
    }

    fn delete_one(
        agent: &mut Agent,
        blob: &[u8],
        kind: &str,
        comment: &str,
        path: &str,
        q: bool,
    ) -> bool {
        match agent.remove_identity(blob) {
            Ok(()) => {
                if !q {
                    let comment = if comment.is_empty() {
                        "no comment"
                    } else {
                        comment
                    };
                    eprintln!("Identity removed: {path} {kind} ({comment})");
                }
                true
            }
            Err(_) => {
                eprintln!("Could not remove identity \"{path}\": agent refused operation");
                false
            }
        }
    }

    /// `ssh-add -d -`: remove the keys and certificates listed on stdin,
    /// one per line.
    fn delete_stdin(agent: &mut Agent, o: &Opts) -> bool {
        let mut text = String::new();
        if std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).is_err() {
            return false;
        }
        let mut ok = false;
        for (n, line) in text.lines().enumerate() {
            let line = line.trim_start_matches([' ', '\t']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let comment = line.splitn(3, ' ').nth(2).unwrap_or("");
            let (blob, kind, is_cert) = if let Ok(c) = Certificate::parse_openssh_line(line) {
                let Ok(pk) = PublicKey::parse_wire_blob(c.embedded_pubkey_blob()) else {
                    continue;
                };
                (c.raw.clone(), format!("{}-CERT", label(&pk)), true)
            } else if let Ok(pk) = PublicKey::parse_authorized_keys_line(line) {
                (pk.wire_blob(), label(&pk).to_string(), false)
            } else {
                eprintln!("(stdin):{}: invalid key", n + 1);
                continue;
            };
            if (!o.key_only && !o.cert_only) || (o.key_only && !is_cert) || (o.cert_only && is_cert)
            {
                ok |= delete_one(agent, &blob, &kind, comment, "(stdin)", o.quiet);
            }
        }
        ok
    }

    /// OpenSSH's `delete_file`.
    fn delete_file(agent: &mut Agent, o: &Opts, path: &str) -> bool {
        if path == "-" {
            return delete_stdin(agent, o);
        }
        let pubpath = if std::path::Path::new(&format!("{path}.pub")).exists() {
            format!("{path}.pub")
        } else {
            path.to_string()
        };
        let public = read_public(&pubpath).or_else(|e| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|pem| PrivateKey::public_key_from_pem(&pem).ok())
                .map(|pk| (pk, None))
                .ok_or(e)
        });
        let (pk, cert) = match public {
            Ok(v) => v,
            Err(e) => {
                println!("Bad key file {path}: {e}");
                return false;
            }
        };
        let mut ok = false;
        let is_cert = cert.is_some();
        if (!o.key_only && !o.cert_only) || (o.key_only && !is_cert) || (o.cert_only && is_cert) {
            let (blob, kind) = match &cert {
                Some(c) => (c.raw.clone(), format!("{}-CERT", label(&pk))),
                None => (pk.wire_blob(), label(&pk).to_string()),
            };
            ok = delete_one(agent, &blob, &kind, pk.comment(), path, o.quiet);
        }
        if o.key_only {
            return ok;
        }
        let certpath = format!("{path}-cert.pub");
        let Ok((cpk, Some(cert))) = read_public(&certpath) else {
            return ok;
        };
        if cpk.wire_blob() != pk.wire_blob() {
            eprintln!("Certificate {certpath} does not match private key {path}");
            std::process::exit(255);
        }
        let kind = format!("{}-CERT", label(&pk));
        delete_one(agent, &cert.raw, &kind, cpk.comment(), &certpath, o.quiet) || ok
    }

    /// `ssh-add -T`: have the agent sign with the key and check the
    /// signature.
    fn test_key(agent: &mut Agent, path: &str) -> bool {
        let (pk, cert) = match read_public(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Couldn't read public key {path}: {e}");
                return false;
            }
        };
        let mut data = [0u8; 1024];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut data))
            .is_err()
        {
            return false;
        }
        let rsa = matches!(pk, PublicKey::Rsa { .. });
        let blob = cert
            .as_ref()
            .map_or_else(|| pk.wire_blob(), |c| c.raw.clone());
        let sig = match agent.sign(&blob, &data, if rsa { 2 } else { 0 }) {
            Ok(s) => s,
            Err(e) => {
                // The agent's SSH_AGENT_FAILURE, worded as OpenSSH's.
                let e = match e {
                    puressh::Error::Protocol(_) => "agent refused operation".to_string(),
                    e => e.to_string(),
                };
                eprintln!("Agent signature failed for {path}: {e}");
                return false;
            }
        };
        let alg = if rsa { "rsa-sha2-256" } else { pk.algorithm() };
        if let Err(e) = puressh::hostkey::verify_signature(alg, &pk.wire_blob(), &data, &sig) {
            eprintln!("Signature verification failed for {path}: {e}");
            return false;
        }
        true
    }

    /// A key type as OpenSSH's `sshkey_type` names it.
    fn blob_label(blob: &[u8]) -> &'static str {
        PublicKey::parse_wire_blob(blob).map_or("unknown", |pk| label(&pk))
    }

    /// The keys `known_hosts`-style `files` hold for `host`: plain keys and
    /// `@cert-authority` keys (revoked ones are skipped), with where each
    /// is from (for `-v`).
    fn host_keys(o: &Opts, files: &[String], host: &str) -> Vec<(Vec<u8>, bool, String)> {
        use puressh::known_hosts::{KnownHosts, Marker};
        let mut keys = Vec::new();
        for f in files {
            let path = common::expand_tilde(f);
            debug(o, 2, || {
                format!("parse_dest_constraint_hop: looking up host keys for \"{host}\" in {path}")
            });
            let Ok(text) = std::fs::read(&path) else {
                continue;
            };
            let mut loaded = 0;
            // Line by line, to say where each key is from.
            for (n, line) in text.split(|b| *b == b'\n').enumerate() {
                for e in KnownHosts::from_bytes(line).find(host, 22) {
                    loaded += 1;
                    let kind = match e.marker {
                        None => "",
                        Some(Marker::CertAuthority) => "ca ",
                        Some(_) => "revoked ",
                    };
                    debug(o, 3, || {
                        format!(
                            "record_hostkey: found {kind}key type {} in file {path}:{}",
                            blob_label(&e.key_blob),
                            n + 1
                        )
                    });
                    let ca = match e.marker {
                        None => false,
                        Some(Marker::CertAuthority) => true,
                        Some(_) => continue,
                    };
                    keys.push((e.key_blob.clone(), ca, format!("{path}:{}", n + 1)));
                }
            }
            if loaded > 0 {
                debug(o, 3, || {
                    format!("load_hostkeys_file: loaded {loaded} keys from {host}")
                });
            }
        }
        keys
    }

    /// One side of a `-h` constraint: `[user@]host`.
    fn parse_hop(o: &Opts, s: &str, files: &[String]) -> Result<DestinationHop, String> {
        let (user, host) = match s.rfind('@') {
            Some(i) => (Some(&s[..i]), &s[i + 1..]),
            None => (None, s),
        };
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let user = user.map(str::to_string);
        if host.is_empty() {
            if user.is_none() {
                return Err(format!(
                    "Invalid key destination constraint \"{s}\": does not specify user or host"
                ));
            }
            return Ok(DestinationHop::new(user, None, Vec::new()));
        }
        let found = host_keys(o, files, host);
        if found.is_empty() {
            return Err(format!("No host keys found for destination \"{host}\""));
        }
        let mut keys = Vec::with_capacity(found.len());
        for (i, (blob, ca, from)) in found.into_iter().enumerate() {
            debug(o, 3, || {
                let user = user.as_ref().map_or(String::new(), |u| format!("{u}@"));
                let ca_tag = if ca { "CA " } else { "" };
                format!(
                    "parse_dest_constraint_hop: {user}{host}: adding {} {ca_tag}key from {from} as key {i}",
                    blob_label(&blob)
                )
            });
            keys.push((blob, ca));
        }
        Ok(DestinationHop::new(user, Some(host.to_string()), keys))
    }

    /// A `-h` argument: `[user@]host` or `host>[user@]host`.
    fn parse_destination(
        o: &Opts,
        s: &str,
        files: &[String],
    ) -> Result<(DestinationConstraint, String), String> {
        let (from, to) = match s.split_once('>') {
            None => (DestinationHop::default(), parse_hop(o, s, files)?),
            Some((from, to)) => {
                let from_hop = parse_hop(o, from, files)?;
                let to_hop = parse_hop(o, to, files)?;
                if from_hop.user.is_some() {
                    return Err(format!(
                        "Invalid key constraint {s}: cannot specify user on 'from' host"
                    ));
                }
                (from_hop, to_hop)
            }
        };
        // OpenSSH's debug2 summary of the constraint.
        let hop = |h: &DestinationHop, none: &str| {
            let user = h.user.as_ref().map_or(String::new(), |u| format!("{u}@"));
            let host = h.hostname.as_deref().unwrap_or(none);
            format!("{user}{host} ({} keys)", h.keys.len())
        };
        let summary = format!("{} > {}", hop(&from, "(ORIGIN)"), hop(&to, "(ANY)"));
        Ok((DestinationConstraint::new(from, to), summary))
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let o = match parse_args(&args) {
            Ok(o) => o,
            Err(Exit::Usage(msg)) => {
                if let Some(m) = msg {
                    eprintln!("{m}");
                }
                eprintln!("{USAGE}");
                return 1;
            }
            Err(Exit::Fatal(m)) => {
                eprintln!("{m}");
                return 255;
            }
            Err(Exit::Fail(m)) => {
                eprintln!("{m}");
                return 1;
            }
        };
        if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") {
            debug(&o, 3, || {
                format!(
                    "ssh_get_authentication_socket_path: path '{}'",
                    sock.to_string_lossy()
                )
            });
        }
        let mut agent = match Agent::connect_env() {
            Ok(Some(a)) => a,
            Ok(None) => {
                eprintln!("Could not open a connection to your authentication agent.");
                return 2;
            }
            Err(puressh::Error::Io(e)) => {
                eprintln!("Error connecting to agent: {e}");
                return 2;
            }
            Err(e) => {
                eprintln!("Error connecting to agent: {e}");
                return 2;
            }
        };

        if o.lock || o.unlock {
            return lock_agent(&mut agent, o.lock);
        }
        if o.list || o.list_full {
            return list(&mut agent, &o);
        }
        if o.delete_all {
            return match agent.remove_all_identities() {
                Ok(()) => {
                    if !o.quiet {
                        eprintln!("All identities removed.");
                    }
                    0
                }
                Err(_) => {
                    eprintln!("Failed to remove all identities.");
                    1
                }
            };
        }
        if o.query {
            return match agent.query_extensions() {
                Ok(exts) => {
                    for e in exts {
                        println!("{e}");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("unable to query supported extensions: {e}");
                    1
                }
            };
        }

        let hostkey_files = if o.hostkey_files.is_empty() {
            vec![
                "~/.ssh/known_hosts".to_string(),
                "~/.ssh/known_hosts2".to_string(),
                "/etc/ssh/ssh_known_hosts".to_string(),
                "/etc/ssh/ssh_known_hosts2".to_string(),
            ]
        } else {
            o.hostkey_files.clone()
        };
        let mut constraints = AddConstraints::default();
        constraints.lifetime = o.lifetime;
        constraints.confirm = o.confirm;
        // OpenSSH's `SSH_SK_PROVIDER` / `-S`, else `internal`.
        constraints.sk_provider = Some(
            o.sk_provider
                .clone()
                .or_else(|| std::env::var("SSH_SK_PROVIDER").ok())
                .unwrap_or_else(|| "internal".into()),
        );
        for d in &o.destinations {
            match parse_destination(&o, d, &hostkey_files) {
                Ok((c, summary)) => {
                    let n = constraints.destinations.len();
                    debug(&o, 2, || {
                        format!("parse_dest_constraint: constraint {n}: {summary}")
                    });
                    constraints.destinations.push(c);
                }
                Err(e) => {
                    eprintln!("{e}");
                    return 255;
                }
            }
        }

        if let Some(module) = &o.pkcs11 {
            return update_card(&mut agent, &o, module, &constraints);
        }

        if o.download {
            #[cfg(feature = "security-key")]
            return add_resident_keys(&mut agent, &o, &constraints);
            #[cfg(not(feature = "security-key"))]
            {
                eprintln!("Unable to load resident keys: requested feature not supported");
                return 1;
            }
        }

        if o.test {
            if o.files.is_empty() {
                eprintln!("no keys to test");
                return 255;
            }
            let mut ok = true;
            for f in &o.files {
                ok &= test_key(&mut agent, f);
            }
            return i32::from(!ok);
        }

        let files = if o.files.is_empty() {
            let d = default_files();
            if d.is_empty() {
                return 1;
            }
            d
        } else {
            o.files.clone()
        };
        let mut status = 0;
        if o.delete {
            for path in &files {
                if !delete_file(&mut agent, &o, path) {
                    status = 1;
                }
            }
            return status;
        }
        let mut adder = Adder {
            agent: &mut agent,
            o: &o,
            constraints,
            pass: None,
        };
        for path in &files {
            if !adder.add_file(path) {
                status = 1;
            }
        }
        status
    }

    /// `ssh-add -K`: add each resident key on the authenticator, as
    /// OpenSSH's `load_resident_keys`.
    #[cfg(feature = "security-key")]
    fn add_resident_keys(agent: &mut Agent, o: &Opts, c: &AddConstraints) -> i32 {
        let provider_path = c.sk_provider.clone().unwrap_or_default();
        let pin = if o.no_pin {
            None
        } else {
            common::read_secret("Enter PIN for authenticator: ")
                .ok()
                .filter(|p| !p.is_empty())
        };
        let keys = puressh::sk::open_provider(&provider_path)
            .map_err(puressh::Error::from)
            .and_then(|p| {
                puressh::sk::load_resident_keys(&*p, pin.as_deref().map(|p| p.as_str()), &[])
            });
        drop(pin);
        let keys = match keys {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Unable to load resident keys: {e}");
                return 1;
            }
        };
        if keys.is_empty() {
            return 1;
        }
        let mut status = 0;
        for rk in keys {
            let mut key = rk.key;
            let app = key
                .sk_credential()
                .map(|s| s.application.clone())
                .unwrap_or_default();
            key.set_comment(app);
            let pk = key.public_key();
            let fp = fingerprint(&pk, o.md5);
            if agent.add_constrained(&key, None, c).is_err() {
                eprintln!("Unable to add key {} {fp}", pk.type_label());
                status = 1;
                continue;
            }
            if !o.quiet {
                eprintln!("Resident identity added: {} {fp}", pk.type_label());
                if let Some(t) = c.lifetime {
                    eprintln!("Lifetime set to {t} seconds");
                }
                if c.confirm {
                    eprintln!("The user must confirm each use of the key");
                }
            }
        }
        status
    }

    /// `ssh-add -s module [certificate …]` / `-e module`: have the agent
    /// add or remove a PKCS#11 module's keys, as OpenSSH's `update_card`.
    fn update_card(agent: &mut Agent, o: &Opts, module: &str, c: &AddConstraints) -> i32 {
        let add = !o.delete;
        let mut certs = Vec::new();
        if add && !o.key_only {
            for f in &o.files {
                match std::fs::read_to_string(f)
                    .map_err(|e| e.to_string())
                    .and_then(|t| Certificate::parse_openssh_line(&t).map_err(|e| e.to_string()))
                {
                    Ok(cert) => certs.push(cert.raw),
                    Err(e) => {
                        eprintln!("load certificate {f}: {e}");
                        return 255;
                    }
                }
            }
        }
        let pin = if add && !o.no_pin {
            match common::read_secret("Enter passphrase for PKCS#11: ") {
                Ok(p) => p,
                Err(_) => return 1,
            }
        } else {
            Zeroizing::new(String::new())
        };
        let res = if add {
            agent.add_smartcard(module, &pin, c, &certs, o.cert_only)
        } else {
            agent.remove_smartcard(module)
        };
        drop(pin);
        match res {
            Ok(()) => {
                if !o.quiet {
                    eprintln!("Card {}: {module}", if add { "added" } else { "removed" });
                }
                0
            }
            Err(_) => {
                eprintln!(
                    "Could not {} card \"{module}\": agent refused operation",
                    if add { "add" } else { "remove" }
                );
                1
            }
        }
    }

    /// `pk`'s fingerprint, MD5 (`-E md5`) or SHA-256.
    fn fingerprint(pk: &PublicKey, md5: bool) -> String {
        if md5 {
            use purecrypto::hash::{Digest, Md5};
            let d = Md5::digest(&pk.wire_blob());
            let hex: Vec<String> = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
            format!("MD5:{}", hex.join(":"))
        } else {
            pk.sha256_fingerprint()
        }
    }

    fn lock_agent(agent: &mut Agent, lock: bool) -> i32 {
        let pass = match common::read_secret("Enter lock password: ") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        };
        if lock {
            match common::read_secret("Again: ") {
                Ok(again) if *again == *pass => {}
                Ok(_) => {
                    eprintln!("Passwords do not match.");
                    return 1;
                }
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            }
        }
        let (res, un) = if lock {
            (agent.lock(pass.as_bytes()), "")
        } else {
            (agent.unlock(pass.as_bytes()), "un")
        };
        match res {
            Ok(()) => {
                eprintln!("Agent {un}locked.");
                0
            }
            Err(_) => {
                eprintln!("Failed to {un}lock agent: agent refused operation");
                1
            }
        }
    }

    fn list(agent: &mut Agent, o: &Opts) -> i32 {
        let ids = match agent.identities() {
            Ok(ids) => ids,
            Err(e) => {
                eprintln!("error fetching identities: {e}");
                return 1;
            }
        };
        if ids.is_empty() {
            println!("The agent has no identities.");
            return 1;
        }
        for id in ids {
            // A certificate is listed by its key, labelled `-CERT`.
            let cert = Certificate::parse(id.key_blob()).ok();
            let blob = cert
                .as_ref()
                .map_or(id.key_blob(), |c| c.embedded_pubkey_blob());
            let Ok(pk) = PublicKey::parse_wire_blob(blob) else {
                continue;
            };
            if o.list_full {
                let mut line = match &cert {
                    Some(c) => c.to_openssh_line(""),
                    None => pk.to_authorized_keys_line(),
                };
                if !id.comment().is_empty() {
                    line = format!("{} {}", line.trim_end(), id.comment());
                }
                println!("{line}");
            } else {
                println!(
                    "{} {} {} ({}{})",
                    pk.bit_length(),
                    fingerprint(&pk, o.md5),
                    if id.comment().is_empty() {
                        "no comment"
                    } else {
                        id.comment()
                    },
                    label(&pk),
                    if cert.is_some() { "-CERT" } else { "" }
                );
            }
        }
        0
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn parse(args: &[&str]) -> Result<Opts, Exit> {
            let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            parse_args(&v)
        }

        #[test]
        fn verbosity_stacks_to_three() {
            assert_eq!(parse(&[]).unwrap().verbose, 0);
            assert_eq!(parse(&["-v", "-v"]).unwrap().verbose, 2);
            assert_eq!(parse(&["-vvvvv"]).unwrap().verbose, 3);
        }

        #[test]
        fn errors_as_openssh() {
            // The first of the two flags is named.
            assert_eq!(
                parse(&["-L", "-l"]).err(),
                Some(Exit::Fatal("-L flag already specified".into()))
            );
            assert_eq!(
                parse(&["-X", "-x"]).err(),
                Some(Exit::Fatal("-X flag already specified".into()))
            );
            assert_eq!(
                parse(&["-l", "-D"]).err(),
                Some(Exit::Fatal("Invalid combination of actions".into()))
            );
            assert_eq!(
                parse(&["-E", "sha1"]).err(),
                Some(Exit::Fatal("Invalid hash algorithm \"sha1\"".into()))
            );
            assert_eq!(
                parse(&["-t", "1y"]).err(),
                Some(Exit::Fail("Invalid lifetime".into()))
            );
            assert_eq!(
                parse(&["-t"]).err(),
                Some(Exit::Usage(Some("option requires an argument -- t".into())))
            );
        }

        #[test]
        fn lifetimes() {
            assert_eq!(parse(&["-t", "0"]).unwrap().lifetime, None);
            assert_eq!(parse(&["-t", "1h30"]).unwrap().lifetime, Some(3630));
            assert_eq!(parse(&["-t", "2.5"]).unwrap().lifetime, Some(2));
            assert_eq!(convtime("1.5h"), None);
            assert_eq!(convtime("1s1"), None);
        }
    }
}
