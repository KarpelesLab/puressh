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
#define PCSSH_ERR_CONFIG            (-11)
#define PCSSH_ERR_INVALID_HANDLE    (-12)
#define PCSSH_ERR_PANIC             (-99)

/* ----- Host-key policy (pcssh_client_connect_ex) ------------------------ */

/* Accept any host key the server presents.  Insecure; equivalent to
 * OpenSSH `StrictHostKeyChecking=no` with no known_hosts. */
#define PCSSH_HOSTKEY_POLICY_ACCEPT_ANY          0
/* Accept only host keys matching the SHA-256 fingerprint given as a
 * base64 string (with or without a `SHA256:` prefix; `=` padding
 * optional). Mismatch ⇒ PCSSH_ERR_HOSTKEY_REJECTED. */
#define PCSSH_HOSTKEY_POLICY_ACCEPT_FINGERPRINT  1
/* Defer to a PcSshKnownHosts store. Not supported via
 * pcssh_client_connect_ex — use pcssh_client_connect_known_hosts. */
#define PCSSH_HOSTKEY_POLICY_KNOWN_HOSTS         2

/* ----- Types ------------------------------------------------------------- */

/* Opaque client handle. */
typedef struct PcSshClient PcSshClient;

/* ----- API --------------------------------------------------------------- */

/*
 * DEPRECATED.  Connect to `host:port` with the AcceptAny host-key policy.
 *
 * Insecure: the client trusts whatever key the server presents. Prefer
 * pcssh_client_connect_ex (explicit policy enum) or
 * pcssh_client_connect_known_hosts (real TOFU/known_hosts verifier).
 *
 * Kept as a thin shim so existing C callers continue to link.
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
 * Connect to `host:port` and complete version-exchange + KEX with an
 * explicit host-key policy.
 *
 * `policy`           one of PCSSH_HOSTKEY_POLICY_*.
 * `fingerprint_b64`  used only when policy == ACCEPT_FINGERPRINT; a NUL-
 *                    terminated base64 SHA-256 fingerprint (`SHA256:`
 *                    prefix and `=` padding both tolerated). Otherwise
 *                    pass NULL.
 * `out`              on success, receives a non-NULL handle; on error,
 *                    set NULL.
 *
 * Returns PCSSH_OK on success, a negative PCSSH_ERR_* otherwise.
 * Passing PCSSH_HOSTKEY_POLICY_KNOWN_HOSTS returns PCSSH_ERR_CONFIG —
 * use pcssh_client_connect_known_hosts (which takes the store handle).
 */
int pcssh_client_connect_ex(
    const char *host,
    uint16_t port,
    int32_t timeout_ms,
    int policy,
    const char *fingerprint_b64,
    PcSshClient **out
);

/*
 * Authenticate using a password. Returns PCSSH_OK on success.
 *
 * NOTE: the password bytes are borrowed from caller-owned storage; the
 * FFI does not heap-copy them, so the caller is responsible for wiping
 * (e.g. explicit_bzero) the buffer once this call returns.
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

/* ----- SFTP ------------------------------------------------------------- */

/* Opaque SFTP session, file, and directory handles. */
typedef struct PcSshSftp     PcSshSftp;
typedef struct PcSshSftpFile PcSshSftpFile;
typedef struct PcSshSftpDir  PcSshSftpDir;

/* Open-flags for pcssh_sftp_open_file (mirrors SFTP wire bits). */
#define PCSSH_SFTP_READ      0x00000001u
#define PCSSH_SFTP_WRITE     0x00000002u
#define PCSSH_SFTP_APPEND    0x00000004u
#define PCSSH_SFTP_CREAT     0x00000008u
#define PCSSH_SFTP_TRUNC     0x00000010u
#define PCSSH_SFTP_EXCL      0x00000020u

/* Bits set in PcSshSftpAttrs.flags to mark which fields are valid. */
#define PCSSH_ATTR_SIZE          0x00000001u
#define PCSSH_ATTR_UIDGID        0x00000002u
#define PCSSH_ATTR_PERMISSIONS   0x00000004u
#define PCSSH_ATTR_ACMODTIME     0x00000008u

/*
 * File attributes (POSIX-shaped). Use `flags` to discover which fields
 * are meaningful for this entry — unset bits leave the field zero.
 */
typedef struct PcSshSftpAttrs {
    uint32_t flags;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    uint32_t permissions;
    uint32_t atime;
    uint32_t mtime;
} PcSshSftpAttrs;

/*
 * Multi-handle concurrency contract:
 *   - One PcSshClient supports any combination of SFTP / shell / exec /
 *     forward channels open simultaneously (SharedClient layer).
 *   - PcSshSftp / PcSshSftpFile / PcSshSftpDir each hold a back-pointer
 *     to their parent; the caller MUST NOT free a parent while any
 *     child handle is live.
 *   - Per-handle state (file cursor, dir read position) is NOT
 *     thread-safe — do not share one file/dir handle across threads.
 */

/* Lifecycle. */
int  pcssh_sftp_open(PcSshClient *client, PcSshSftp **out_sftp);
void pcssh_sftp_free(PcSshSftp *sftp);

/* File ops. */
int  pcssh_sftp_open_file(PcSshSftp *sftp, const char *path,
                          uint32_t flags, uint32_t mode,
                          PcSshSftpFile **out_file);
int  pcssh_sftp_read(PcSshSftpFile *file,
                     uint8_t *buf, size_t cap, size_t *out_len);
int  pcssh_sftp_write(PcSshSftpFile *file,
                      const uint8_t *buf, size_t len);
int  pcssh_sftp_seek(PcSshSftpFile *file, uint64_t offset);
int  pcssh_sftp_tell(PcSshSftpFile *file, uint64_t *out_offset);
int  pcssh_sftp_close_file(PcSshSftpFile *file);
void pcssh_sftp_file_free(PcSshSftpFile *file);

/* Directory ops. */
int  pcssh_sftp_opendir(PcSshSftp *sftp, const char *path,
                        PcSshSftpDir **out_dir);
/*
 * Read one directory entry. EOF is signalled by PCSSH_OK with
 * *name_len == 0 and out_attrs->flags == 0.
 */
int  pcssh_sftp_readdir(PcSshSftpDir *dir,
                        uint8_t *name_buf,     size_t name_cap,     size_t *name_len,
                        uint8_t *longname_buf, size_t longname_cap, size_t *longname_len,
                        PcSshSftpAttrs *out_attrs);
int  pcssh_sftp_closedir(PcSshSftpDir *dir);
void pcssh_sftp_dir_free(PcSshSftpDir *dir);

/* Stat family. */
int  pcssh_sftp_stat(PcSshSftp *sftp, const char *path, PcSshSftpAttrs *out_attrs);
int  pcssh_sftp_lstat(PcSshSftp *sftp, const char *path, PcSshSftpAttrs *out_attrs);
int  pcssh_sftp_fstat(PcSshSftpFile *file, PcSshSftpAttrs *out_attrs);
int  pcssh_sftp_setstat(PcSshSftp *sftp, const char *path,
                        const PcSshSftpAttrs *attrs);
int  pcssh_sftp_fsetstat(PcSshSftpFile *file, const PcSshSftpAttrs *attrs);

/* Path ops. */
int  pcssh_sftp_mkdir(PcSshSftp *sftp, const char *path, uint32_t mode);
int  pcssh_sftp_rmdir(PcSshSftp *sftp, const char *path);
int  pcssh_sftp_remove(PcSshSftp *sftp, const char *path);
int  pcssh_sftp_rename(PcSshSftp *sftp,
                       const char *old_path, const char *new_path);
int  pcssh_sftp_symlink(PcSshSftp *sftp,
                        const char *target, const char *link_path);
int  pcssh_sftp_readlink(PcSshSftp *sftp, const char *path,
                         uint8_t *buf, size_t cap, size_t *out_len);
int  pcssh_sftp_realpath(PcSshSftp *sftp, const char *path,
                         uint8_t *buf, size_t cap, size_t *out_len);

/* ----- Bytes-path variants ---------------------------------------------- *
 *
 * SFTP paths on the wire are arbitrary octets — OpenSSH happily hands out
 * filenames in Shift-JIS, Latin-1, or mixed-encoding directories. The
 * cstr entry points above route every path through UTF-8 validation and
 * reject non-UTF-8 with PCSSH_ERR_INVALID_ARGUMENT.
 *
 * The `_bytes` companions below accept a raw (ptr, len) pair so the
 * library can hand the server exactly the bytes the peer sent. (NULL, 0)
 * is accepted as the empty path; a NULL pointer with non-zero length
 * yields PCSSH_ERR_INVALID_ARGUMENT before any dereference. All other
 * behaviour mirrors the cstr cousin (output buffers, error codes,
 * parent-handle liveness rules).
 *
 * `readdir` already returns the entry name as bytes (uint8_t name_buf),
 * so there is no `_bytes` variant for it. `fstat` / `fsetstat` operate on
 * file handles and take no path. */

int  pcssh_sftp_open_file_bytes(PcSshSftp *sftp,
                                const uint8_t *path_ptr, size_t path_len,
                                uint32_t flags, uint32_t mode,
                                PcSshSftpFile **out_file);
int  pcssh_sftp_opendir_bytes(PcSshSftp *sftp,
                              const uint8_t *path_ptr, size_t path_len,
                              PcSshSftpDir **out_dir);
int  pcssh_sftp_stat_bytes(PcSshSftp *sftp,
                           const uint8_t *path_ptr, size_t path_len,
                           PcSshSftpAttrs *out_attrs);
int  pcssh_sftp_lstat_bytes(PcSshSftp *sftp,
                            const uint8_t *path_ptr, size_t path_len,
                            PcSshSftpAttrs *out_attrs);
int  pcssh_sftp_setstat_bytes(PcSshSftp *sftp,
                              const uint8_t *path_ptr, size_t path_len,
                              const PcSshSftpAttrs *attrs);
int  pcssh_sftp_mkdir_bytes(PcSshSftp *sftp,
                            const uint8_t *path_ptr, size_t path_len,
                            uint32_t mode);
int  pcssh_sftp_rmdir_bytes(PcSshSftp *sftp,
                            const uint8_t *path_ptr, size_t path_len);
int  pcssh_sftp_remove_bytes(PcSshSftp *sftp,
                             const uint8_t *path_ptr, size_t path_len);
int  pcssh_sftp_rename_bytes(PcSshSftp *sftp,
                             const uint8_t *old_ptr, size_t old_len,
                             const uint8_t *new_ptr, size_t new_len);
int  pcssh_sftp_symlink_bytes(PcSshSftp *sftp,
                              const uint8_t *target_ptr,   size_t target_len,
                              const uint8_t *linkpath_ptr, size_t linkpath_len);
int  pcssh_sftp_readlink_bytes(PcSshSftp *sftp,
                               const uint8_t *path_ptr, size_t path_len,
                               uint8_t *buf, size_t cap, size_t *out_len);
int  pcssh_sftp_realpath_bytes(PcSshSftp *sftp,
                               const uint8_t *path_ptr, size_t path_len,
                               uint8_t *buf, size_t cap, size_t *out_len);

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

/* Opaque agent handle.
 *
 * Thread-safety: the handle is Send + Sync (an internal mutex serialises
 * concurrent calls), so it may be shared across threads. A poisoned
 * mutex (panic in another thread) surfaces as PCSSH_ERR_GENERIC.
 */
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
