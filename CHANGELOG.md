# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
