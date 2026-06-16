# Follow-ups

Known, intentional limitations left after the modern `ssh_config`/`sshd_config`
coverage work. Everything here is *honest* under strict mode: the unsupported cases
hard-error rather than silently no-op. Each item notes where it lives and what closing
it needs.

## Client

- **No port/dynamic forwarding over ProxyCommand or ControlMaster mux.** `-L`/`-R`/`-D`
  (and `-N`) are rejected with a clear error when the transport is a `ProxyCommand`
  subprocess (`src/proc_transport.rs`) or a mux client connection (`src/mux/`). The
  serve/forwarding poll loop relies on a real read timeout, which a pipe / mux carrier
  can't honor. *Closing it:* wrap the pipe fd in an `O_NONBLOCK` adapter (translate
  `EAGAIN`→`WouldBlock`) and add forwarded-channel support to the mux protocol.

- **ControlPersist `yes`/`<N>` is a detached thread, not a daemon.** The master stays
  alive in a background thread of the first `ssh` process rather than double-forking into
  an independent daemon (`src/mux/server.rs`). If that first process is killed, the master
  dies with it. *Closing it:* real `fork`+`setsid` daemonization (unix-gated).

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
