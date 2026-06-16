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

- **`ssh -O check|exit|stop` has no CLI flag.** The mux protocol carries `ExitRequest`/
  `AliveCheck` frames and the master honors them, but no `-O` command-line option is
  parsed yet (`src/bin/ssh.rs`). *Closing it:* add `-O` arg parsing that opens the control
  socket and sends the frame.

- **`HostKeyAlgorithms +ssh-rsa` is rejected.** Bare `ssh-rsa` (SHA-1) is default-off
  behind a process-wide flag and is intentionally excluded from the strict known-name set
  (`src/config/algos.rs`), so it can't be re-enabled via config. *Closing it:* thread the
  `allow_rsa_sha1` opt-in through the resolver if interop demand appears.

## Server

- **`Match User`/`Match Group` cannot change the advertised auth-method set mid-userauth.**
  Method-set Match is resolved once, pre-auth, with address-only context
  (`src/server.rs` two-phase resolve). User/group-conditional `AuthenticationMethods` /
  `PubkeyAuthentication` are therefore not honored; only address-based method Match and
  user-based *Banner* are. *Closing it:* re-resolve and re-advertise methods after the
  first `USERAUTH_REQUEST` exposes the username.

- **Banner: user-matched deferred; PrintMotd via PAM only.** Global and `Match Address`
  banners send `SSH_MSG_USERAUTH_BANNER`; user-matched banners are not yet wired. `PrintMotd`
  is resolved but the actual `/etc/motd` print is left to `pam_motd` (the sshd binary
  already runs PAM). *Closing it:* send the banner after the username is known; print motd
  in the forked shell handler when PAM isn't doing it.

- **`ChrootDirectory` honored for SFTP only.** Mapped to the existing SFTP root; for
  shell/exec sessions it returns `Unsupported` (a real `chroot()` before privilege drop
  plus a populated root is out of scope). `ForceCommand internal-sftp` + `ChrootDirectory`
  works. *Closing it:* `chroot()` in the privilege-drop hook (`src/bin/sshd.rs`).

- **`AllowUsers`/`DenyUsers` `user@host` form rejected.** Bare-user globs are honored;
  the `@host` form returns `Unsupported` (`src/bin/sshd.rs` `LocalAuthenticator`).
  *Closing it:* match the host part against the connection's resolved peer address.

- **`AuthenticationMethods` multi-factor chains rejected.** Only `publickey`/`any` are
  honorable (puressh implements publickey only); any non-`publickey` token or `a,b` chain
  returns `Unsupported`. Closing it depends on implementing additional auth methods.

## Cross-cutting

- Directives whose underlying feature puressh cannot perform hard-error by design:
  `PasswordAuthentication yes`, `KbdInteractiveAuthentication yes`,
  `PermitEmptyPasswords yes`, `PermitTunnel`, `CASignatureAlgorithms`, and external-command
  `Subsystem` entries. These are not bugs — they are strict-mode rejections.
