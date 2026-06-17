# Follow-ups

Known, intentional limitations left after the modern `ssh_config`/`sshd_config`
coverage work. Everything here is *honest* under strict mode: the unsupported cases
hard-error rather than silently no-op. Each item notes where it lives and what closing
it needs.

## Client

- ~~**No port/dynamic forwarding over ProxyCommand or ControlMaster mux.**~~ **Done.**
  `ProcTransport` now sets `O_NONBLOCK` on the child stdout fd and implements
  `set_read_timeout` as a `poll(2)`-with-deadline read (translating the empty poll into
  `WouldBlock`), so the serve/forwarding poll loop ticks over the pipe carrier — `-L`/`-R`/
  `-D`/`-N` are all supported over `ProxyCommand` (`src/proc_transport.rs`). Over a mux
  client, the protocol gained an `OPEN_DIRECT_TCPIP` frame: each accepted `-L`/`-D`
  connection opens its own control connection to the master, which dials the destination
  over its SSH connection and byte-splices the channel back (`src/mux/`). `-R` over mux
  stays rejected (it needs master-side listener/`tcpip-forward` management the client
  cannot drive); `-A`/`-X`/`-Y` over mux stay rejected (they need a master-side session
  channel for the forwarding-request + callbacks). Those run fine without ControlMaster.

- ~~**ControlPersist `yes`/`<N>` is a detached thread, not a daemon.**~~ **Done.**
  Becoming a persistent master now `fork()`s + `setsid()`s into an independent daemon
  (unix-gated, in `src/bin/ssh.rs`'s `daemonize_master`): the child detaches its stdio to
  `/dev/null` and serves the control socket via `puressh::mux::run_master_daemon`, while
  the launching process continues its own session as an ordinary mux client over that
  socket. Killing the launcher leaves the master (and any attached sessions) alive. The
  parent `mem::forget`s its `SharedClient` so it never runs Drop on the SSH socket the
  daemon now owns. `ControlPersist no` is unchanged (master tied to the foreground).

- ~~**`ssh -O check|exit|stop` has no CLI flag.**~~ **Done.** `src/bin/ssh.rs` now parses
  `-O check|exit|stop`: it resolves the `ControlPath` (required), then talks to the master
  over the control socket without connecting/authenticating. `check` sends `AliveCheck`
  and reports master alive (exit 0) / not running (exit 255); `exit`/`stop` send
  `ExitRequest`, after which the master tears down and unlinks its socket. The mux master's
  reaper unlinks idempotently on shutdown so an `ExitRequest` cleans up correctly.
  `send_control_command` lives in `src/mux/client.rs`.

- ~~**`HostKeyAlgorithms +ssh-rsa` is rejected.**~~ **Done.** `known_names(HostKey)` in
  `src/config/algos.rs` now lists bare `ssh-rsa` as a *namable* algorithm, while
  `default_list(HostKey)` still excludes it — so it only enters a resolved list when a
  config explicitly requests it (`HostKeyAlgorithms +ssh-rsa` or a bare replace). When the
  client's resolved `HostKeyAlgorithms` names `ssh-rsa`, the binary flips
  `hostkey::set_allow_rsa_sha1(true)` (in `config_for_host`), enabling SHA-1 host-key
  verification; the resolved list is advertised in KEXINIT so the connection actually
  negotiates and verifies `ssh-rsa`. `PubkeyAcceptedAlgorithms` stays strict (no SHA-1
  pubkey auth). **SECURITY:** `ssh-rsa` uses SHA-1, which is broken; this is an interop
  opt-in for ancient peers in controlled environments only, OFF by default. The flag is a
  single process-wide atomic, so once any host's config opts in it affects subsequent
  host-key verification in the process.

## Server

- ~~**`Match User`/`Match Group` cannot change the advertised auth-method set mid-userauth.**~~
  **Done.** The effective policy is re-resolved with user/groups context on the first
  `USERAUTH_REQUEST`; the advertised method set is updated and an attempt at a now-forbidden
  method is rejected without consulting the authenticator (`src/server.rs`,
  `src/auth/server.rs`).

- ~~**Banner: user-matched deferred; PrintMotd via PAM only.**~~ **Done.** `Match User`
  banners are sent right after the user-context re-resolve; `PrintMotd=yes` prints
  CRLF-rewritten `/etc/motd` at interactive-shell start (default off to avoid double-print
  with `pam_motd`).

- ~~**`ChrootDirectory` honored for SFTP only.**~~ **Done.** Real `chroot()` for shell/exec
  now runs in the forked child while still root (before `setuid`), with `%h`/`%u` token
  expansion and a root-owned / not-group-or-world-writable ownership check on the dir and
  every ancestor. `SftpRoot`/`--sftp-root` remain the no-privilege virtual jail.

- ~~**`AllowUsers`/`DenyUsers` `user@host` form rejected.**~~ **Done.** `user@host` patterns
  match the user glob plus the host glob against the connection's resolved peer address.

## Authentication (host + user certs, password / keyboard-interactive) — **Done.**

- **Certificate authentication** (host + user OpenSSH certs, `CASignatureAlgorithms`,
  `TrustedUserCAKeys`/`AuthorizedPrincipalsFile`, known_hosts `@cert-authority`).
- **Password / keyboard-interactive authentication** (client + server), unblocking
  `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, and
  multi-factor `AuthenticationMethods` chains.

  Residual gaps the cert-auth work deferred are now closed (workstream FF):
  - ~~User-cert extensions treated as advisory.~~ **Done.** User-certificate extensions
    are default-deny: an absent `permit-pty`/`permit-port-forwarding`/
    `permit-agent-forwarding`/`permit-X11-forwarding` refuses the corresponding capability
    for the whole connection (folded into the per-connection `EffectivePolicy`, ANDed with
    the `sshd_config` gates). Plain-key / password auth is unaffected.
  - ~~Cert `force-command` overrode only the exec path.~~ **Done.** It now overrides the
    interactive shell and the SCP exec-stream path too, converging on the same dispatcher
    machinery as the config `ForceCommand`; the original request is exposed as
    `$SSH_ORIGINAL_COMMAND`, and a cert force-command wins when both are present.
  - ~~Multi-factor `AuthenticationMethods` used set-membership.~~ **Done.** The chain is
    enforced in the LISTED order; `still_required` offers only the next method.
  - ~~`AuthorizedPrincipalsFile` loaded without token expansion.~~ **Done.** `%u`/`%h`
    are expanded per connection against the bound user's passwd entry.

## Permanent non-goals (strict-mode rejections, by design — not bugs)

- `PermitTunnel` (tun/tap device forwarding) and external-command `Subsystem` entries are
  intentionally unsupported and hard-error.

## Deferred (documented, out of scope) — **both now done; this file can be retired.**

- ~~**Full multi-step keyboard-interactive PAM conversation**~~ **Done.** A genuine
  multi-round PAM conversation is now driven over the wire (Linux+PAM build). Each
  kbd-interactive attempt runs PAM `authenticate()` on a dedicated worker thread; PAM's
  pull-based conversation callback (`BridgeConv`) blocks on a channel, handing each prompt
  to the authenticator as a `USERAUTH_INFO_REQUEST` and waiting for the
  `USERAUTH_INFO_RESPONSE` answer, until the terminal PAM verdict (`Accept`/`Reject` via
  `record_and_decide("keyboard-interactive")`). `KbdConversation` (in
  `LocalAuthenticator.kbd_conv`) owns the channel ends + JoinHandle; the PAM `Context`
  lives on the worker thread and is torn down on disconnect (bounded by LoginGraceTime).
  Answers are held in `Zeroizing` and never logged. Non-PAM builds keep the rejecting stub.
  Tested with a scripted fake-worker state-machine (two-prompt accept, reject, empty-
  password refusal, username-change); manual e2e recipe documented on
  `start_kbd_interactive` (`src/bin/sshd.rs`).
- ~~**KRL (key revocation list) binary format.**~~ **Done.** `src/krl/mod.rs` parses the
  OpenSSH binary KRL (certificates section: serial-list / serial-range / serial-bitmap /
  key-id; explicit-key; fingerprint-sha1 / -sha256; signature parse-and-ignore). The
  `RevokedKeys <file>` sshd_config directive loads it at startup (fail-closed on
  read/parse error); `LocalAuthenticator` refuses a cert whose (CA, serial/key-id) or
  signing-CA key is revoked, and a plain/cert blob revoked by explicit-key/fingerprint.
  Client host-key revocation stays with known_hosts `@revoked`.
