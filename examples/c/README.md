# puressh C examples

Small drivers that exercise the `pcssh_*` C ABI exported from
`libpuressh`. Use them as living documentation: every example links one
section of `include/puressh.h` to a runnable demo.

## Build

From the repository root:

```sh
cargo build --features ffi --release
```

That produces `target/release/libpuressh.a` and a platform-appropriate
shared library (`libpuressh.so` on Linux, `libpuressh.dylib` on macOS).
Then, from this directory:

```sh
# Linux / macOS
cc -I../../include -L../../target/release \
    -o sftp_demo sftp_demo.c \
    -lpuressh -lpthread -ldl -lm

cc -I../../include -L../../target/release \
    -o agent_demo agent_demo.c \
    -lpuressh -lpthread -ldl -lm
```

(On macOS the `-ldl` is unnecessary but harmless.)

## sftp_demo

Connects to an SSH server, optionally verifies the host key against a
`known_hosts` store with TOFU prompt, opens two SFTP sessions on the
same connection at the same time (one for a directory listing, one for
a file round-trip), and prints what it sees. Demonstrates:

- `pcssh_known_hosts_load` / `pcssh_client_connect_known_hosts`
- `pcssh_client_auth_password`
- **Two `PcSshSftp` open simultaneously on one `PcSshClient`** — the
  multi-handle property the FFI exists to provide
- `pcssh_sftp_opendir` / `pcssh_sftp_readdir`
- `pcssh_sftp_open_file` / `pcssh_sftp_write` / `pcssh_sftp_read`

Usage:

```sh
./sftp_demo <host> <port> <user> <password> <known_hosts_path> <remote_dir> <remote_file>
```

The TOFU prompt accepts whatever key the server presents (insecure;
fine for the demo).

## agent_demo

Connects to `$SSH_AUTH_SOCK`, lists identities, and asks the agent to
sign a fixed challenge under the first identity. Demonstrates:

- `pcssh_agent_connect_env`
- `pcssh_agent_identity_count` + `pcssh_agent_identity`
- `pcssh_agent_sign`

Unix only — matches the lib's `cfg(unix)` gate.

Usage:

```sh
./agent_demo
```

## Notes

- All examples use the high-level error code → `pcssh_error_message()`
  pattern; the message is for humans, the int is the API contract.
- Examples allocate fixed-size buffers (8 KiB) for stdout/stderr,
  filenames, etc.; a real consumer should follow the two-pass pattern
  (call once with `cap=0` to learn the required size, allocate, call
  again).
- The "two SFTP sessions on one client" demo is backed by per-channel
  fairness (one pumper at a time; the other readers sleep on their
  channel's `Condvar`) and per-channel backpressure (receive-window
  credit deferred to drain). A starved session — one a consumer never
  reads from — caps its in-memory mailbox at the initial window size
  and stops the peer rather than growing unbounded. See the
  `src/shared.rs` module doc for the concurrency model.
