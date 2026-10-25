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

    const USAGE: &str = "usage: ssh-add [-CcDdKkLlNqvXx] [-E fingerprint_hash] [-H hostkey_file]\n               [-h destination_constraint] [-S provider] [-t life]\n               [file ...]\n       ssh-add -s pkcs11 [-Cv] [certificate ...]\n       ssh-add -e pkcs11\n       ssh-add -T pubkey ...";

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
        destinations: Vec<String>,
        hostkey_files: Vec<String>,
        files: Vec<String>,
        /// `-S`: the `SecurityKeyProvider`.
        sk_provider: Option<String>,
        /// `-K`: add the authenticator's resident keys.
        download: bool,
        /// `-P`: don't ask for the authenticator's PIN.
        no_pin: bool,
    }

    fn parse_lifetime(v: &str) -> Option<u32> {
        let mut total = 0u64;
        let mut num = String::new();
        for c in v.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let n: u64 = num.parse().ok()?;
            num.clear();
            total += n * match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                'w' => 604800,
                _ => return None,
            };
        }
        if !num.is_empty() {
            total += num.parse::<u64>().ok()?;
        }
        u32::try_from(total).ok().filter(|t| *t > 0)
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

    fn parse_args(args: &[String]) -> Result<Opts, String> {
        let mut o = Opts::default();
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
                            .ok_or_else(|| format!("option requires an argument -- {c}"))?
                            .clone()
                    };
                    match c {
                        't' => o.lifetime = Some(parse_lifetime(&v).ok_or("Invalid lifetime")?),
                        'E' => match v.as_str() {
                            "md5" => o.md5 = true,
                            "sha256" => o.md5 = false,
                            other => return Err(format!("Invalid hash algorithm \"{other}\"")),
                        },
                        'h' => o.destinations.push(v),
                        'H' => o.hostkey_files.push(v),
                        'S' => o.sk_provider = Some(v),
                        // Deprecated, ignored (OpenSSH's too).
                        'M' | 'm' => {}
                        _ => {
                            return Err("PKCS#11 tokens (-s/-e) are not supported".into());
                        }
                    }
                    break;
                }
                match c {
                    'l' | 'L' if o.list || o.list_full => {
                        return Err(format!("-{c} flag already specified"));
                    }
                    'x' | 'X' if o.lock || o.unlock => {
                        return Err(format!("-{c} flag already specified"));
                    }
                    'l' => o.list = true,
                    'L' => o.list_full = true,
                    'd' => o.delete = true,
                    'D' => o.delete_all = true,
                    'x' => o.lock = true,
                    'X' => o.unlock = true,
                    'q' => o.quiet = true,
                    'Q' => o.query = true,
                    'T' => o.test = true,
                    'c' => o.confirm = true,
                    'k' => o.key_only = true,
                    'C' => o.cert_only = true,
                    'N' => o.no_cert_lifetime = true,
                    'v' => {}
                    'K' => o.download = true,
                    'P' => o.no_pin = true,
                    _ => return Err(format!("unknown option -- {c}")),
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
            return Err("Invalid combination of actions".into());
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

    /// The keys `known_hosts`-style `files` hold for `host`: plain keys and
    /// `@cert-authority` keys (revoked ones are skipped).
    fn host_keys(files: &[String], host: &str) -> Vec<(Vec<u8>, bool)> {
        use puressh::known_hosts::{KnownHosts, Marker};
        let mut keys = Vec::new();
        for f in files {
            let Ok(kh) = KnownHosts::load(common::expand_tilde(f)) else {
                continue;
            };
            for e in kh.find(host, 22) {
                match e.marker {
                    None => keys.push((e.key_blob.clone(), false)),
                    Some(Marker::CertAuthority) => keys.push((e.key_blob.clone(), true)),
                    Some(_) => {}
                }
            }
        }
        keys
    }

    /// One side of a `-h` constraint: `[user@]host`.
    fn parse_hop(s: &str, files: &[String]) -> Result<DestinationHop, String> {
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
        let keys = host_keys(files, host);
        if keys.is_empty() {
            return Err(format!("No host keys found for destination \"{host}\""));
        }
        Ok(DestinationHop::new(user, Some(host.to_string()), keys))
    }

    /// A `-h` argument: `[user@]host` or `host>[user@]host`.
    fn parse_destination(s: &str, files: &[String]) -> Result<DestinationConstraint, String> {
        match s.split_once('>') {
            None => Ok(DestinationConstraint::new(
                DestinationHop::default(),
                parse_hop(s, files)?,
            )),
            Some((from, to)) => {
                let from_hop = parse_hop(from, files)?;
                if from_hop.user.is_some() {
                    return Err(format!(
                        "Invalid key constraint {from}: cannot specify user on 'from' host"
                    ));
                }
                Ok(DestinationConstraint::new(from_hop, parse_hop(to, files)?))
            }
        }
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let o = match parse_args(&args) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("{e}\n{USAGE}");
                return 1;
            }
        };
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
            match parse_destination(d, &hostkey_files) {
                Ok(c) => constraints.destinations.push(c),
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            }
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
                return 1;
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
}
