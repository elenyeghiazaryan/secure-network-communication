#include "../src/handshake.h"
#include "../src/log.h"
#include "testutil.h"
#include <sys/wait.h>
#include <unistd.h>

/* fork a server, run a client against it, compare derived keys through a pipe */
static int run(const char *spsk, const char *cpsk, int port, session_t *cs, session_t *ss, int *srv_rc, int *cli_rc)
{
    int pfd[2];
    if (pipe(pfd)) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        session_t s; memset(&s, 0, sizeof s);
        int rc = hs_server("127.0.0.1", (uint16_t)port, (const uint8_t *)spsk, strlen(spsk), 4, &s);
        if (write(pfd[1], &rc, sizeof rc) < 0 || write(pfd[1], &s, sizeof s) < 0) _exit(2);
        _exit(0);
    }
    usleep(200 * 1000);
    memset(cs, 0, sizeof *cs);
    *cli_rc = hs_client("127.0.0.1", (uint16_t)port, (const uint8_t *)cpsk, strlen(cpsk), 4, cs);
    if (read(pfd[0], srv_rc, sizeof *srv_rc) != sizeof *srv_rc || read(pfd[0], ss, sizeof *ss) != sizeof *ss) return -1;
    waitpid(pid, NULL, 0);
    return 0;
}

int main(void)
{
    int base = 39000 + (getpid() % 2000), sr, cr;
    static session_t cs, ss;
    fprintf(stderr, "(error lines below from the wrong-PSK case are expected)\n");

    CHECK(run("0123456789abcdef-shared", "0123456789abcdef-shared", base, &cs, &ss, &sr, &cr) == 0 && sr == 0 && cr == 0,
          "handshake succeeds with matching PSK");
    CHECK(!memcmp(cs.tx_key, ss.rx_key, 32) && !memcmp(cs.rx_key, ss.tx_key, 32), "client tx key == server rx key and vice versa");
    CHECK(!memcmp(cs.tx_salt, ss.rx_salt, 4) && !memcmp(cs.rx_salt, ss.tx_salt, 4), "nonce salts mirror");
    CHECK(memcmp(cs.tx_key, cs.rx_key, 32) != 0, "the two directions use different keys");
    CHECK(!memcmp(cs.id, ss.id, SESSION_ID_LEN), "both sides report the same session id");

    static session_t cs2, ss2;
    CHECK(run("0123456789abcdef-shared", "0123456789abcdef-shared", base + 1, &cs2, &ss2, &sr, &cr) == 0 && sr == 0,
          "second handshake succeeds");
    CHECK(memcmp(cs.tx_key, cs2.tx_key, 32) != 0 && memcmp(cs.id, cs2.id, 8) != 0, "fresh keys per session (DH is ephemeral)");

    static session_t cs3, ss3;
    CHECK(run("0123456789abcdef-shared", "WRONG-PSK-WRONG-PSK-1", base + 2, &cs3, &ss3, &sr, &cr) == 0 && cr != 0 && sr != 0,
          "handshake fails with a different PSK (both sides refuse)");
    CHECK(!cs3.established && !ss3.established, "no session is established after failed authentication");
    TEST_DONE();
}
