/*
 * agent_demo.c — list identities and sign a challenge via the running
 * ssh-agent ($SSH_AUTH_SOCK).
 *
 * Unix only — matches the lib's cfg(unix) gate on the agent module.
 *
 * See ./README.md for the cc command and prerequisites.
 */

#include <puressh.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what, int rc)
{
    const char *m = pcssh_error_message(rc);
    fprintf(stderr, "%s failed: %d (%s)\n",
            what, rc, m ? m : "unknown");
    exit(2);
}

int main(void)
{
    fprintf(stderr, "puressh version: %s\n", pcssh_version());

    PcSshAgent *agent = NULL;
    int rc = pcssh_agent_connect_env(&agent);
    if (rc != PCSSH_OK) die("pcssh_agent_connect_env", rc);
    if (agent == NULL) {
        fprintf(stderr,
                "SSH_AUTH_SOCK is unset; no agent to talk to.\n");
        return 1;
    }

    size_t n = 0;
    rc = pcssh_agent_identity_count(agent, &n);
    if (rc != PCSSH_OK) die("pcssh_agent_identity_count", rc);
    printf("Agent has %zu identit%s loaded.\n",
           n, n == 1 ? "y" : "ies");
    if (n == 0) {
        pcssh_agent_free(agent);
        return 0;
    }

    /* Iterate identities, print algorithm + comment. */
    uint8_t algo[256], comment[1024], key[4096];
    size_t algo_len, comment_len, key_len;
    for (size_t i = 0; i < n; i++) {
        algo_len = comment_len = key_len = 0;
        rc = pcssh_agent_identity(
            agent, i,
            algo,    sizeof algo,    &algo_len,
            comment, sizeof comment, &comment_len,
            key,     sizeof key,     &key_len);
        if (rc != PCSSH_OK) die("pcssh_agent_identity", rc);
        printf("  [%zu] %.*s  (%zu-byte blob)  %.*s\n",
               i,
               (int)algo_len, algo,
               key_len,
               (int)comment_len, comment);
    }

    /* Sign a fixed challenge under identity 0. */
    const char challenge[] = "puressh-agent-demo-challenge";

    /* Re-read identity 0's key blob into a stable buffer. */
    rc = pcssh_agent_identity(
        agent, 0,
        algo,    sizeof algo,    &algo_len,
        comment, sizeof comment, &comment_len,
        key,     sizeof key,     &key_len);
    if (rc != PCSSH_OK) die("pcssh_agent_identity (sign target)", rc);

    uint8_t sig[8192];
    size_t sig_len = 0;
    rc = pcssh_agent_sign(
        agent,
        key, key_len,
        (const uint8_t *)challenge, sizeof challenge - 1,
        PCSSH_AGENT_SIGN_DEFAULT,
        sig, sizeof sig, &sig_len);
    if (rc != PCSSH_OK) die("pcssh_agent_sign", rc);
    printf("Signed %zu-byte challenge under identity 0; %zu-byte signature.\n",
           sizeof challenge - 1, sig_len);

    pcssh_agent_free(agent);
    return 0;
}
