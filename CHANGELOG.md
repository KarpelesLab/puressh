# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
