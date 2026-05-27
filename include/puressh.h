/*
 * puressh.h — C ABI for the puressh SSH client library.
 *
 * puressh is a pure-Rust SSH protocol library; this header exposes a minimal
 * client-side surface for C callers: connect, authenticate, exec, free.
 *
 * Version: matches CARGO_PKG_VERSION at build time. Call pcssh_version() at
 *          runtime for the exact string.
 * License: MIT OR Apache-2.0
 */

#ifndef PURESSH_H
#define PURESSH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Error codes ------------------------------------------------------- */

#define PCSSH_OK                      0
#define PCSSH_ERR_GENERIC            (-1)
#define PCSSH_ERR_BUFFER_TOO_SMALL   (-2)
#define PCSSH_ERR_INVALID_ARGUMENT   (-3)
#define PCSSH_ERR_IO                 (-4)
#define PCSSH_ERR_CONNECT            (-5)
#define PCSSH_ERR_KEX                (-6)
#define PCSSH_ERR_AUTH_FAILED        (-7)
#define PCSSH_ERR_HOSTKEY_REJECTED   (-8)
#define PCSSH_ERR_PROTOCOL           (-9)
#define PCSSH_ERR_PARSE             (-10)
#define PCSSH_ERR_PANIC             (-99)

/* ----- Types ------------------------------------------------------------- */

/* Opaque client handle. */
typedef struct PcSshClient PcSshClient;

/* ----- API --------------------------------------------------------------- */

/*
 * Connect to `host:port` and complete version-exchange + KEX.
 *
 * `timeout_ms`  socket read/write timeout in milliseconds; 0 = no timeout.
 * `out`         on success, receives a non-NULL handle; on error, set NULL.
 *
 * Host-key policy is currently hardcoded to AcceptAny (TOFU is caller's
 * responsibility).
 *
 * Returns PCSSH_OK on success, a negative PCSSH_ERR_* otherwise.
 */
int pcssh_client_connect(
    const char *host,
    uint16_t port,
    int32_t timeout_ms,
    PcSshClient **out
);

/*
 * Authenticate using a password. Returns PCSSH_OK on success.
 */
int pcssh_client_auth_password(
    PcSshClient *client,
    const char *user,
    const char *password
);

/*
 * Authenticate using an openssh-key-v1 PEM private key.
 *
 * `private_key_pem`     pointer to PEM text (UTF-8, NOT scanned for NUL).
 * `private_key_pem_len` number of bytes at `private_key_pem`.
 * `passphrase`          NULL or empty string for unencrypted keys.
 *
 * Returns PCSSH_OK on success.
 */
int pcssh_client_auth_publickey(
    PcSshClient *client,
    const char *user,
    const char *private_key_pem,
    size_t private_key_pem_len,
    const char *passphrase
);

/*
 * Execute a remote command. Caller supplies stdout/stderr buffers; the
 * function writes captured output and (POSIX) exit status.
 *
 * On PCSSH_ERR_BUFFER_TOO_SMALL, *stdout_out_len / *stderr_out_len are set
 * to the required sizes. `*exit_status_out` is -1 when the server did not
 * report an exit code (e.g. signal termination).
 *
 * Returns PCSSH_OK on success.
 */
int pcssh_client_exec(
    PcSshClient *client,
    const char *command,
    uint8_t *stdout_buf,
    size_t stdout_cap,
    size_t *stdout_out_len,
    uint8_t *stderr_buf,
    size_t stderr_cap,
    size_t *stderr_out_len,
    int32_t *exit_status_out
);

/*
 * Free a client handle. Safe to call with NULL.
 */
void pcssh_client_free(PcSshClient *client);

/*
 * Convert a non-success error code into a static, NUL-terminated ASCII
 * description. The pointer is owned by the library; do not free.
 *
 * Returns NULL for codes the library does not recognise.
 */
const char *pcssh_error_message(int code);

/*
 * Build-time library version (e.g. "0.0.1"), NUL-terminated.
 */
const char *pcssh_version(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* PURESSH_H */
