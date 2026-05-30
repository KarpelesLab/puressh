/*
 * sftp_demo.c — multi-handle SFTP over puressh's C ABI.
 *
 * Builds and links against libpuressh; see ./README.md for the cc line.
 *
 * What it shows:
 *   - host-key verification via a known_hosts store with TOFU prompt
 *   - password auth
 *   - opening TWO SFTP sessions on ONE connection simultaneously
 *     (the entire reason this FFI surface exists)
 *   - a directory listing on one session
 *   - a file round-trip (write → close → read → verify) on the other
 */

#include <puressh.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tofu_accept_anything(
    void *ctx,
    const char *host, uint16_t port,
    const char *algorithm,
    const uint8_t *key_blob, size_t key_blob_len)
{
    (void)ctx;
    (void)key_blob;
    (void)key_blob_len;
    fprintf(stderr,
            "TOFU: unknown host %s:%u (%s), accepting blind for demo.\n",
            host, (unsigned)port, algorithm);
    return 1;
}

static void die(const char *what, int rc)
{
    const char *m = pcssh_error_message(rc);
    fprintf(stderr, "%s failed: %d (%s)\n",
            what, rc, m ? m : "unknown");
    exit(2);
}

int main(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr,
                "usage: %s <host> <port> <user> <password>"
                " <known_hosts_path> <remote_dir> <remote_file>\n",
                argv[0]);
        return 1;
    }
    const char *host  = argv[1];
    uint16_t    port  = (uint16_t)atoi(argv[2]);
    const char *user  = argv[3];
    const char *pass  = argv[4];
    const char *kh_p  = argv[5];
    const char *r_dir = argv[6];
    const char *r_fil = argv[7];

    fprintf(stderr, "puressh version: %s\n", pcssh_version());

    /* 1. Load known_hosts store. */
    PcSshKnownHosts *kh = NULL;
    int rc = pcssh_known_hosts_load(kh_p, &kh);
    if (rc != PCSSH_OK) die("pcssh_known_hosts_load", rc);

    /* 2. Connect under a KnownHosts policy with TOFU prompt. */
    PcSshClient *client = NULL;
    rc = pcssh_client_connect_known_hosts(
        host, port, /* timeout_ms */ 5000,
        kh,
        PCSSH_TOFU_PROMPT,
        tofu_accept_anything,
        /* ctx */ NULL,
        /* save_path */ kh_p,
        /* hash_new */ 1,
        &client);
    if (rc != PCSSH_OK) die("pcssh_client_connect_known_hosts", rc);

    /* 3. Auth. */
    rc = pcssh_client_auth_password(client, user, pass);
    if (rc != PCSSH_OK) die("pcssh_client_auth_password", rc);

    /* 4. THE point of this demo: open two SFTP sessions on one
     *    connection at the same time. */
    PcSshSftp *sftp_a = NULL;
    rc = pcssh_sftp_open(client, &sftp_a);
    if (rc != PCSSH_OK) die("pcssh_sftp_open (a)", rc);

    PcSshSftp *sftp_b = NULL;
    rc = pcssh_sftp_open(client, &sftp_b);
    if (rc != PCSSH_OK) die("pcssh_sftp_open (b)", rc);

    /* 5. Session A: directory listing. */
    PcSshSftpDir *dir = NULL;
    rc = pcssh_sftp_opendir(sftp_a, r_dir, &dir);
    if (rc != PCSSH_OK) die("pcssh_sftp_opendir", rc);

    printf("Listing %s via SFTP session A:\n", r_dir);
    for (;;) {
        uint8_t name[1024], longname[1024];
        size_t name_len = 0, long_len = 0;
        PcSshSftpAttrs attrs;
        rc = pcssh_sftp_readdir(
            dir, name, sizeof name, &name_len,
            longname, sizeof longname, &long_len,
            &attrs);
        if (rc != PCSSH_OK) die("pcssh_sftp_readdir", rc);
        if (name_len == 0) break; /* EOF */
        printf("  %.*s\n", (int)name_len, name);
    }
    pcssh_sftp_closedir(dir);
    pcssh_sftp_dir_free(dir);

    /* 6. Session B: file round-trip — runs concurrently with A having
     *    been live; both sessions are still alive on one connection. */
    const char payload[] = "hello from puressh sftp demo\n";

    PcSshSftpFile *fw = NULL;
    rc = pcssh_sftp_open_file(
        sftp_b, r_fil,
        PCSSH_SFTP_WRITE | PCSSH_SFTP_CREAT | PCSSH_SFTP_TRUNC,
        /* mode */ 0644,
        &fw);
    if (rc != PCSSH_OK) die("pcssh_sftp_open_file (write)", rc);
    rc = pcssh_sftp_write(fw, (const uint8_t *)payload, sizeof payload - 1);
    if (rc != PCSSH_OK) die("pcssh_sftp_write", rc);
    pcssh_sftp_close_file(fw);
    pcssh_sftp_file_free(fw);

    PcSshSftpFile *fr = NULL;
    rc = pcssh_sftp_open_file(sftp_b, r_fil, PCSSH_SFTP_READ, 0, &fr);
    if (rc != PCSSH_OK) die("pcssh_sftp_open_file (read)", rc);

    uint8_t got[256];
    size_t got_len = 0;
    rc = pcssh_sftp_read(fr, got, sizeof got, &got_len);
    if (rc != PCSSH_OK) die("pcssh_sftp_read", rc);

    if (got_len != sizeof payload - 1 ||
        memcmp(got, payload, got_len) != 0) {
        fprintf(stderr,
                "round-trip mismatch: wrote %zu, got %zu\n",
                sizeof payload - 1, got_len);
        return 3;
    }
    printf("Round-tripped %zu bytes through SFTP session B; OK.\n",
           got_len);

    pcssh_sftp_close_file(fr);
    pcssh_sftp_file_free(fr);

    /* 7. Tear down. */
    pcssh_sftp_free(sftp_a);
    pcssh_sftp_free(sftp_b);
    pcssh_client_free(client);
    pcssh_known_hosts_free(kh);
    return 0;
}
