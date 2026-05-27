/*
 * ffi_smoke.c — link-and-invariants smoke test for libpuressh.
 *
 * 1. pcssh_version() returns a non-NULL string.
 * 2. pcssh_client_connect to 127.0.0.1:1 fails (negative return, NULL handle).
 * 3. pcssh_client_free(NULL) does not crash.
 * 4. pcssh_error_message(PCSSH_OK) is non-NULL.
 * 5. pcssh_error_message(unknown) is NULL.
 *
 * Exit 0 if all expectations hold, 1 otherwise.
 *
 * This test exercises ONLY the FFI surface and link; real protocol coverage
 * lives in tests/e2e_real_sshd.rs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "puressh.h"

static int failures = 0;

#define EXPECT(cond, msg)                                                      \
    do {                                                                        \
        if (!(cond)) {                                                          \
            fprintf(stderr, "FAIL: %s\n", (msg));                               \
            ++failures;                                                         \
        }                                                                       \
    } while (0)

int main(void) {
    /* 1. version */
    const char *ver = pcssh_version();
    EXPECT(ver != NULL, "pcssh_version returned NULL");
    if (ver != NULL) {
        printf("puressh version: %s\n", ver);
        EXPECT(strlen(ver) > 0, "pcssh_version returned empty string");
    }

    /* 2. connect to a port that should refuse */
    PcSshClient *c = (PcSshClient *)0xDEADBEEF;
    int rc = pcssh_client_connect("127.0.0.1", 1, 1000, &c);
    EXPECT(rc < 0, "pcssh_client_connect to 127.0.0.1:1 should have failed");
    EXPECT(c == NULL, "client pointer should be NULL on connect failure");
    if (rc < 0) {
        const char *msg = pcssh_error_message(rc);
        printf("connect failed (rc=%d, message=%s)\n",
               rc, msg ? msg : "<unknown>");
    }

    /* 3. free NULL */
    pcssh_client_free(NULL);

    /* 4. PCSSH_OK has a description */
    const char *ok_msg = pcssh_error_message(PCSSH_OK);
    EXPECT(ok_msg != NULL, "pcssh_error_message(PCSSH_OK) returned NULL");
    if (ok_msg != NULL) {
        printf("PCSSH_OK message: %s\n", ok_msg);
    }

    /* Sanity: every documented error code has a description. */
    int codes[] = {
        PCSSH_ERR_GENERIC,
        PCSSH_ERR_BUFFER_TOO_SMALL,
        PCSSH_ERR_INVALID_ARGUMENT,
        PCSSH_ERR_IO,
        PCSSH_ERR_CONNECT,
        PCSSH_ERR_KEX,
        PCSSH_ERR_AUTH_FAILED,
        PCSSH_ERR_HOSTKEY_REJECTED,
        PCSSH_ERR_PROTOCOL,
        PCSSH_ERR_PARSE,
        PCSSH_ERR_PANIC,
    };
    size_t n_codes = sizeof(codes) / sizeof(codes[0]);
    for (size_t i = 0; i < n_codes; ++i) {
        const char *m = pcssh_error_message(codes[i]);
        if (m == NULL) {
            fprintf(stderr,
                    "FAIL: pcssh_error_message(%d) returned NULL\n",
                    codes[i]);
            ++failures;
        }
    }

    /* 5. unknown code → NULL */
    EXPECT(pcssh_error_message(12345) == NULL,
           "pcssh_error_message(unknown positive) should be NULL");
    EXPECT(pcssh_error_message(-12345) == NULL,
           "pcssh_error_message(unknown negative) should be NULL");

    /* Invalid-argument smoke: NULL out pointer to connect. */
    rc = pcssh_client_connect("127.0.0.1", 22, 100, NULL);
    EXPECT(rc == PCSSH_ERR_INVALID_ARGUMENT,
           "connect with NULL out should be PCSSH_ERR_INVALID_ARGUMENT");

    if (failures == 0) {
        printf("ffi_smoke: ok\n");
        return 0;
    }
    fprintf(stderr, "ffi_smoke: %d failure(s)\n", failures);
    return 1;
}
