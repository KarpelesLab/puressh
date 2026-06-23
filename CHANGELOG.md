# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.8](https://github.com/KarpelesLab/puressh/compare/v0.0.7...v0.0.8) - 2026-06-23

### Added

- *(mio)* native readiness/non-blocking client frontend
- *(tokio)* native connect_tokio / accept_tokio frontends

### Other

- drop Implementation status section
- fix broken intra-doc links in tokio/mio frontends; document features
- rustfmt src/key/pkcs.rs (fix CI Format check)
- refresh README for async frontends, sans-IO drivers, StreamLocal
- note PKCS#1/SEC1/PKCS#8 private-key support
- parse PEM/PKCS#8/SEC1 private keys, not just the OpenSSH container
- stop claiming hostbased auth support
- bump purecrypto 0.6.16 -> 0.6.17
- bump purecrypto 0.6.14 -> 0.6.16

## [0.0.7](https://github.com/KarpelesLab/puressh/compare/v0.0.6...v0.0.7) - 2026-06-22

### Added

- *(async)* runtime-agnostic async server connection (phase 5)
- *(driver)* sans-IO ServerDriver + crate docs (phases 5–6)
- *(async)* runtime-agnostic async client frontend (phase 3)
- *(driver)* add sans-IO ClientDriver (refactor phase 1)
- add StreamLocal (Unix-socket) tunnel support

### Other

- use Waker::noop() in async block_on (fix CI clippy on Rust 1.96)
- fix broken intra-doc links in async frontends (fix CI docs job)
- cargo fmt across the sans-IO refactor (fix CI)
- *(server)* run blocking Server on ServerDriver (phase 5 complete)
- *(client)* reimplement blocking Client over the sans-IO driver (phase 2)
- add MSRV (Rust 1.88) guard job

## [0.0.6](https://github.com/KarpelesLab/puressh/compare/v0.0.5...v0.0.6) - 2026-06-19

### Fixed

- *(windows)* silence dead-code for unix-only request_tty field
- *(windows)* collapse cfg(windows) nested if into let-chain

### Other

- bump purecrypto 0.6.1 -> 0.6.14 to honor the 1.88 MSRV
- fix macOS-only flake in close-on-open-fail test
- use safe nix::geteuid in lib code (no_std build fix)
- fail-closed ECDH curve, writer length assert, include depth bound
- enforce MIT-MAGIC-COOKIE-1 validation by default
- place /tmp fallback socket in a private per-user subdir
- reject out-of-range direct-tcpip ports instead of truncating
- sanitize pre-auth kbd-interactive strings; enforce RSA keygen floor
- chown/chmod PTY slave to user; StrictModes ownership + ancestor checks
- recover poisoned mutex in with_client instead of panicking (Finding E)
- pre-auth DoS hardening — absolute LoginGraceTime + bounded non-panicking accept loop
- enforce 2048-bit RSA floor on cert-embedded keys at parse time
- make serial 0 revocable via serial-list and serial-range
- compare host-cert principals case-insensitively
- validate kbd-interactive response count and pin username (B1, B2)
- SFTP jail: reject symlinked final component in remove/rmdir/rename/posix-rename; sanitize control bytes in longname
- ObscureKeystrokeTiming keystroke-timing obfuscation sender
- add ObscureKeystrokeTiming client option
- add ping@openssh.com PING/PONG handling on both sides
- retire FOLLOWUPS.md — all items closed
- mark kbd-interactive PAM + KRL done; fmt + macOS dead_code
- multi-step keyboard-interactive PAM conversation bridge
- wire RevokedKeys into server cert + pubkey trust gates
- OpenSSH binary key-revocation-list parser
- record closed cert-auth residuals (R1-R4) + deferred PAM/KRL items in FOLLOWUPS
- no_std fix — use String::from in cert force-command decoder (R1)
- expand %u/%h tokens in AuthorizedPrincipalsFile per connection (R4)
- enforce positional order for multi-factor AuthenticationMethods chains (R3)
- enforce user-cert extensions (default-deny) + force-command on shell/SCP (R1+R2)
- e2e interop tests against real OpenSSH sshd (#[ignore], unix)
- fix rustdoc intra-doc link in sshd loader comment
- Phase 5 — critical options (force-command, source-address)
- Phase 4 — user certificates (client offers, server authorizes)
- Phase 3 — host certificates (server presents, client verifies)
- Phase 2 — CASignatureAlgorithms config keyword
- Phase 1 — OpenSSH certificate parse/verify core
- run PAM unconditionally for password timing uniformity + doc manual e2e
- one persistent auth driver, re-promptable password, kbd-interactive
- PAM password / keyboard-interactive auth + multi-factor chains
- *(server)* accept password/kbd-interactive/PermitEmptyPasswords + MFA chains
- mark server follow-ups done; note cert/password auth in progress
- real ChrootDirectory for shell/exec + PrintMotd for shells (F7, F6)
- support AllowUsers/DenyUsers user@host form (F8)
- re-resolve auth method set + banner once username is known (F5, F6)
- HostKeyAlgorithms +ssh-rsa opt-in (F4)
- ssh -O check|exit|stop control commands (F3)
- real ControlPersist daemonization via fork()+setsid() (F2)
- port/dynamic forwarding over ProxyCommand and ControlMaster mux (F1)
- track deferred config follow-ups (FOLLOWUPS.md)
- *(mux)* in-process ControlMaster e2e over loopback Server
- master/client roles, ControlPersist lifetime, ssh.rs wiring
- add framed control-socket codec + ControlPath expansion
- *(client)* add ControlMaster/ControlPath/ControlPersist keywords
- satisfy clippy on AddressFamily/PidFile wiring
- W7 unit + in-process integration tests
- wire W7 startup keywords (RekeyLimit, AddressFamily, PidFile, LogLevel, Compression, Subsystem)
- gate W7 session/forwarding policy at dispatch points
- parse W7 session/forwarding/policy + startup keywords
- per-connection sshd_config policy gate (Match + auth keywords)
- *(server)* refactor SshServerConfig into global + Match blocks
- fix rustdoc private/unresolved intra-doc links (W2+W4)
- document -D/-C/-t/-T and -o passthrough in usage
- reject Compression yes at parse time without `compress`
- wire modern client keywords + DynamicForward (-D) end to end
- honor compression, env, keepalive, pty, add-identity
- SOCKS4/4a/5 CONNECT handshake for DynamicForward
- parse modern client ssh_config keywords (strict)
- wire ProxyJump (-J) and ProxyCommand into the client binary
- ProxyCommand/ProxyJump keywords + ProcTransport
- add Transport abstraction over the byte stream (refactor)
- no_std format import + clippy manual-contains cleanup
- cargo fmt
- cover algorithm overrides, negotiation, and auth filtering
- server + auth + binaries: thread algorithm overrides end-to-end
- kexinit owned advert + client/server config algorithm keywords
- strict algorithm-list resolver + catalogues
- migrate to Rust edition 2024 (rust-version 1.88)
- portable post-fork env scrub + rustfmt the tree
- resolve PermitRootLogin root check at login time, not startup
- add PermitRootLogin policy (config + CLI)
- cache readdir chunks so no directory entries are dropped
- saturate exec exit status so it cannot alias the -1 sentinel
- reject unsolicited forwarded-tcpip opens in serve
- refuse server-renamed/extra files in single-file fetches
- sanitize server-supplied names before TTY output
- clear environment in PTY login shell child (FIX 5)
- gate every session type via PAM at root, before drop (FIX 1, FIX 2)
- bound deferred rekey packet queue (FIX 4)
- cap shell stdout backlog to stop authenticated memory DoS (FIX 3)
- zeroize cleartext password material on drop
- make pattern_match private to remove the negation footgun
- parse line-by-line so one bad UTF-8 byte can't empty the store
- encode hybrid K as SSH string (not mpint) for H and KDF
- remove Clone from stateful AEAD/CTR cipher states (nonce-reuse hardening)
- zeroize derived session keys and redact DirKeys
- zeroize HMAC session integrity keys on drop
- reset rekey byte counters & use epoch-relative seq baseline (rekey storm)
- reject pad_len > packet_length in cleartext decode (CRITICAL pre-auth DoS)
- bump no_std example to 0.0.5
- rewrite stale scaffolding doc to match the implemented crate

## [0.0.5](https://github.com/KarpelesLab/puressh/compare/v0.0.4...v0.0.5) - 2026-06-09

### Other

- macOS portable Match-exec test + Windows-clean FxpStatus gate
- add bytes-path variants for stat/lstat/setstat/symlink/readlink/realpath + update header
- add bytes-path variants for mkdir/rmdir/remove/rename
- add bytes_from_raw helper + open_file_bytes/opendir_bytes
- drop deprecated cstr_to_str
- migrate to with_cstr
- migrate to with_cstr
- migrate to with_cstr
- migrate to with_cstr
- add with_cstr scope-bounded helper
- implement ssh_config Include directive
- implement ssh_config Match blocks
- parse bracketed-IPv6 host arg
- accept bracketed-IPv6 lines
- add bracketed-IPv6 host:port helper
- cover the OpenSSH @openssh.com extension handlers
- implement OpenSSH @openssh.com extensions
- auto-upgrade ssh-rsa signer to rsa-sha2-{256,512} via server-sig-algs
- thread KexOutput mem::take through the MlKem768X25519 arms
- ZeroizeOnDrop on KexOutput; rewrite runner destructures via mem::take
- enable zeroize derive feature
- enable purecrypto mlkem feature
- implement mlkem768x25519-sha256 hybrid PQ KEX
- register mlkem768x25519-sha256 in algorithm tables
- replace two "checked above" unwraps with structurally panic-free forms
- prefer server-sig-algs when available
- route SSH_MSG_EXT_INFO at the legal slots
- send/accept SSH_MSG_EXT_INFO at the legal moments
- advertise + negotiate ext-info-{c,s} markers
- add ext-info wire format + tests
- ssh CLI: signal-safe termios restore for raw-mode guard
- Zeroize K_1, K_2, and Poly1305 OTK locals
- Zeroize raw DH/ECDH shared-secret scratch
- clamp pcssh_sftp_read copy to caller cap
- pcssh_sftp_free must wipe session even when mutex is poisoned
- zero `*out` up-front in new/from_bytes constructors

## [0.0.4](https://github.com/KarpelesLab/puressh/compare/v0.0.3...v0.0.4) - 2026-06-03

### Other

- bump purecrypto 0.2 → 0.6.1
- re-export DEFAULT_MAX_CHANNELS_PER_CONNECTION for intra-doc links
- close apply_attrs chmod TOCTOU with fchmodat AT_SYMLINK_NOFOLLOW
- reject relative .. symlink targets when jailed
- reject symlinked dirs in op_opendir/op_fstat when jailed
- cap max_handles per session (EMFILE DoS)
- default hide_jail_in_realpath to true (info-leak)
- cap incoming file size + use fchmod/fchmodat (no-follow)
- reject C0 control bytes in filenames (terminal injection)
- switch to linear-time iterative matcher (ReDoS)
- warn that -X currently equals -Y (no SECURITY-extension cookie)
- tighten pre-auth banner cap (lines + total bytes)
- split TOFU prompt; show loud mismatch banner with both fingerprints
- don't rotate stored host key under StrictHostKeyChecking=no
- close TOCTOU race on socket setup
- default-deny + add permit_localhost_only
- default-deny (was default-permit, multi-tenant bypass)
- cap per-channel env requests (count + total bytes)
- cap channels-per-connection (RFC 4254 §5.1 resource-shortage)
- unique tmp for passphrase rotation
- create ~/.ssh as 0o700
- reject malformed [host]:port instead of silent port-22 fallback
- unique tmp + O_EXCL on save (race + symlink-bait hardening)
- hard-error on sequence-number overflow (RFC 4253 §6.4)
- hard-error on invocation counter exhaustion (CVE-class nonce reuse)
- *(release-plz)* use RELEASE_PLZ_TOKEN PAT, drop manual binaries dispatch
- interactive shell with PTY, SIGWINCH, exit-status
- add OpenSSH ssh_config / sshd_config parser, wire into bins
- try ~/.ssh/id_* defaults and accept -v/-vv/-vvv

## [0.0.3](https://github.com/KarpelesLab/puressh/compare/v0.0.2...v0.0.3) - 2026-05-30

### Other

- gate mask_mode to cfg(unix) and fix 4 broken rustdoc intra-doc links
- Merge client + FFI + agent + zeroize security fixes
- Merge server + sshd security fixes
- Merge auth/hostkey/key/known_hosts security fixes
- Merge transport/KEX/compression security fixes
- gate loopback SFTP roundtrip test to cfg(unix)
- round-2 fixes — macOS SUN_LEN, Windows clippy, aarch64 cross binary

### Security

- *(agent)* replace libc unsafe with nix + MetadataExt in SSH_AUTH_SOCK validation
- *(sftp)* gate jail-prefix hiding in op_realpath behind opt-in
- rustfmt cleanup across channel/scp/sftp test+impl
- *(forwarding)* X11 single_connection, tcpip-forward allow filter, X11 cookie note
- *(scp)* O_NOFOLLOW recv, canonicalised base, reject '.' name
- *(sftp)* jail-aware symlink rejection, set_len cap, mode masking
- *(channel)* reject traffic on unconfirmed channels

## [0.0.2](https://github.com/KarpelesLab/puressh/compare/v0.0.1...v0.0.2) - 2026-05-30

### Other

- header sections for sftp + C examples driver
- pcssh_agent (unix only)
- pcssh_known_hosts + connect_known_hosts policy
- SharedClient extended to exec_stream/shell/open_direct_tcpip
- pcssh_sftp_* multi-handle SFTP surface
- split into module dir; PcSshClient backed by SharedClient
- SharedClient + OwnedChannelStream for concurrent channel sessions
- migrate zlib to compcol 0.4.2 (drops miniz_oxide)
- X11 forwarding: server display + client proxy + ssh -X/-Y
- agent forwarding: server socket + client proxy + ssh -A
- :serve: ServeContext + outbound direct-tcpip; wire ssh -L
- lib protocol + Client::scp_send/recv + sshd ExecStreamHandler + scp binary + shared bin/common.rs
- tcpip-forward end-to-end: server splice, Client::serve, ssh -R/-N
- server bind/unbind + Client::request_/cancel_tcpip_forward
- client-side open_direct_tcpip + loopback test
- server-side handler + ChannelStream::into_raw
- ssh-agent client + ssh binary auto-uses it
- known_hosts library + ssh TOFU + ssh-keygen -R/-F/-H
- Client SFTP wrapper + sftp binary
- connection-level priv drop, in-process SFTP subsystem
- Library SFTP v3: client + server protocol
- drop to target user (setgid+initgroups+setuid) before exec
- integrate PAM session management (default-on opt-out feature)
- interactive shells with fork-per-connection
- ignore .claude/ and untrack scheduled_tasks.lock
- skip fingerprint_matches_openssh_cli when probe binary isn't OpenSSH
- fix Windows clippy, rustdoc link, and no_std build
- add CI, crates.io, docs.rs, and MIT badges
- compression, GEX dispatch, re-key scheduler
- Full SSH stack: server, ssh-keygen, C ABI — three parallel agents
- Add ssh-keygen binary scaffold
- End-to-end interop with real OpenSSH: client, ssh binary, e2e test
