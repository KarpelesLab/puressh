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

/* ----- known_hosts ------------------------------------------------------- */

/* Opaque known_hosts store handle (in-memory OpenSSH-format store). */
typedef struct PcSshKnownHosts PcSshKnownHosts;

/* Lookup result codes for pcssh_known_hosts_lookup. */
#define PCSSH_KH_MATCH       0
#define PCSSH_KH_MISMATCH    1
#define PCSSH_KH_UNKNOWN     2

/* TOFU policy actions for pcssh_client_connect_known_hosts. */
#define PCSSH_TOFU_REJECT    0
#define PCSSH_TOFU_ACCEPT    1
#define PCSSH_TOFU_PROMPT    2

/*
 * TOFU prompt callback. Invoked when the connecting host is unknown to
 * the store and on_unknown == PCSSH_TOFU_PROMPT. Return 1 to accept the
 * key (caller is responsible for showing the fingerprint to the user),
 * 0 to refuse.
 */
typedef int (*PcSshTofuPromptCb)(
    void *ctx,
    const char *host,
    uint16_t port,
    const char *algorithm,
    const uint8_t *key_blob,
    size_t key_blob_len
);

int pcssh_known_hosts_new(PcSshKnownHosts **out);
int pcssh_known_hosts_load(const char *path, PcSshKnownHosts **out);
int pcssh_known_hosts_save(const PcSshKnownHosts *kh, const char *path);
int pcssh_known_hosts_from_bytes(const uint8_t *buf, size_t len, PcSshKnownHosts **out);
int pcssh_known_hosts_to_bytes(const PcSshKnownHosts *kh,
                               uint8_t *buf, size_t cap, size_t *out_len);
int pcssh_known_hosts_lookup(const PcSshKnownHosts *kh,
                             const char *host, uint16_t port,
                             const char *algorithm,
                             const uint8_t *key_blob, size_t key_blob_len,
                             int *out_result);
int pcssh_known_hosts_add(PcSshKnownHosts *kh,
                          const char *host, uint16_t port,
                          const char *algorithm,
                          const uint8_t *key_blob, size_t key_blob_len,
                          int hash_host);
int pcssh_known_hosts_remove(PcSshKnownHosts *kh,
                             const char *host, uint16_t port,
                             size_t *out_removed);
int pcssh_known_hosts_hash_in_place(PcSshKnownHosts *kh);
void pcssh_known_hosts_free(PcSshKnownHosts *kh);

/*
 * Connect with a known_hosts-backed host-key policy. On an unknown host
 * the policy follows on_unknown (REJECT / ACCEPT / PROMPT). Mismatch is
 * always a hard reject.
 *
 * save_path (if non-NULL) is the file the store is persisted back to on
 * a successful TOFU accept. hash_new != 0 stores newly added entries
 * with hashed host fields.
 *
 * The PcSshKnownHosts handle remains owned by the caller; the policy
 * holds an internal shared reference to it for the connect's duration.
 */
int pcssh_client_connect_known_hosts(
    const char *host,
    uint16_t port,
    int32_t timeout_ms,
    PcSshKnownHosts *kh,
    int on_unknown,
    PcSshTofuPromptCb prompt_cb,
    void *prompt_ctx,
    const char *save_path,
    int hash_new,
    PcSshClient **out_client
);

/* ----- ssh-agent (Unix only) -------------------------------------------- */

#if defined(__unix__) || defined(__APPLE__)

/* Opaque agent handle. */
typedef struct PcSshAgent PcSshAgent;

/* Agent-sign flags (mirror SSH_AGENT_RSA_SHA2_* wire bits). */
#define PCSSH_AGENT_SIGN_DEFAULT    0
#define PCSSH_AGENT_RSA_SHA2_256    2
#define PCSSH_AGENT_RSA_SHA2_512    4

/*
 * Connect to a Unix-socket ssh-agent at `path`.
 *
 * Returns PCSSH_OK and writes *out on success.
 */
int pcssh_agent_connect(const char *path, PcSshAgent **out);

/*
 * Connect using $SSH_AUTH_SOCK. If unset or empty, returns PCSSH_OK
 * with *out set to NULL (callers treat that as "no agent available").
 */
int pcssh_agent_connect_env(PcSshAgent **out);

/*
 * Query the agent's identity list, caching the result. Subsequent
 * pcssh_agent_identity(i) calls index into the cache. Call
 * pcssh_agent_refresh_identities to drop the cache and re-query.
 */
int pcssh_agent_identity_count(PcSshAgent *agent, size_t *out_count);

/*
 * Drop the cached identity list. Next pcssh_agent_identity_count call
 * re-queries the agent.
 */
int pcssh_agent_refresh_identities(PcSshAgent *agent);

/*
 * Read the identity at `index` from the cache. Two-pass buffer pattern:
 * pass NULL buffers with capacity 0 to query required lengths.
 */
int pcssh_agent_identity(
    PcSshAgent *agent,
    size_t index,
    uint8_t *algorithm_buf, size_t algorithm_cap, size_t *algorithm_len,
    uint8_t *comment_buf,   size_t comment_cap,   size_t *comment_len,
    uint8_t *key_blob_buf,  size_t key_blob_cap,  size_t *key_blob_len
);

/*
 * Sign `data` under the identity whose public key blob equals
 * `key_blob`. Returns SSH wire-format signature (string algo || string
 * raw_sig). Two-pass buffer pattern for sig_buf/sig_cap/sig_len.
 *
 * `flags` selects RSA hash variant (default = SHA1; SHA2_256; SHA2_512).
 */
int pcssh_agent_sign(
    PcSshAgent *agent,
    const uint8_t *key_blob, size_t key_blob_len,
    const uint8_t *data,     size_t data_len,
    uint32_t flags,
    uint8_t *sig_buf, size_t sig_cap, size_t *sig_len
);

/* Free an agent handle. Safe to call with NULL. */
void pcssh_agent_free(PcSshAgent *agent);

#endif /* unix */

/* ----- diagnostics ------------------------------------------------------- */

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
