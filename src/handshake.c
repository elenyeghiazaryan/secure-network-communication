#include "handshake.h"
#include "log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int g_verbose = 0;   /* shared by the whole program (defined here so the test binaries link) */

#define MAGIC "SGW2"
#define M1_LEN (4 + 32 + DH_PUB_LEN)
#define M2_BODY (4 + 32 + DH_PUB_LEN)
#define IO_TIMEOUT_S 5

static int rd_full(int fd, uint8_t *b, size_t n)
{
    while (n) { ssize_t r = recv(fd, b, n, 0); if (r <= 0) return -1; b += r; n -= (size_t)r; }
    return 0;
}
static int wr_full(int fd, const uint8_t *b, size_t n)
{
    while (n) { ssize_t r = send(fd, b, n, MSG_NOSIGNAL); if (r <= 0) return -1; b += r; n -= (size_t)r; }
    return 0;
}
static void set_timeouts(int fd)
{
    struct timeval tv = { IO_TIMEOUT_S, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}
static int mac(const uint8_t *psk, size_t pl, const char *label, const uint8_t *t1, size_t l1,
               const uint8_t *t2, size_t l2, uint8_t out[SHA256_LEN])
{
    uint8_t buf[64 + M1_LEN + M2_BODY];
    size_t ll = strlen(label);
    if (ll + l1 + l2 > sizeof buf) return -1;
    memcpy(buf, label, ll); memcpy(buf + ll, t1, l1); memcpy(buf + ll + l1, t2, l2);
    return hmac_sha256(psk, pl, buf, ll + l1 + l2, out);
}
static long long now_ms(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// client
static int client_exchange(int fd, const uint8_t *psk, size_t pl, session_t *out)
{
    uint8_t m1[M1_LEN], m2[M2_BODY + SHA256_LEN], z[DH_PUB_LEN];
    uint8_t mac_s[SHA256_LEN], mac_c[SHA256_LEN];
    dh_ctx_t *dh = dh_new();
    int rc = -1;
    if (!dh) return -1;
    memcpy(m1, MAGIC, 4);
    if (secure_random(m1 + 4, 32) || dh_public(dh, m1 + 36)) goto done;
    if (wr_full(fd, m1, sizeof m1)) { LOGE("handshake: send M1 failed"); goto done; }
    if (rd_full(fd, m2, sizeof m2)) { LOGE("handshake: receive M2 failed"); goto done; }
    if (memcmp(m2, MAGIC, 4)) { LOGE("handshake: bad magic in M2"); goto done; }
    if (mac(psk, pl, "SGW2-server", m1, sizeof m1, m2, M2_BODY, mac_s) ||
        !ct_equal(mac_s, m2 + M2_BODY, SHA256_LEN)) {
        LOGE("handshake: server authentication FAILED (wrong PSK or MITM)");
        goto done;
    }
    if (dh_shared(dh, m2 + 36, z)) { LOGE("handshake: invalid DH value from server"); goto done; }
    if (mac(psk, pl, "SGW2-client", m1, sizeof m1, m2, M2_BODY, mac_c) ||
        wr_full(fd, mac_c, sizeof mac_c)) goto done;
    if (session_derive(out, 1, z, m1 + 4, m2 + 4)) goto done;
    rc = 0;
done:
    secure_zero(z, sizeof z);
    dh_free(dh);
    return rc;
}

int hs_client(const char *peer_ip, uint16_t port, const uint8_t *psk, size_t pl,
              int timeout_s, session_t *out)
{
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    long long deadline = timeout_s ? now_ms() + timeout_s * 1000LL : 0;
    if (inet_pton(AF_INET, peer_ip, &sa.sin_addr) != 1) { LOGE("bad peer address %s", peer_ip); return -1; }
    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        set_timeouts(fd);
        if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
            int rc = client_exchange(fd, psk, pl, out);
            close(fd);
            return rc;                       /* auth/protocol errors are fatal */
        }
        close(fd);
        if (deadline && now_ms() >= deadline) { LOGE("handshake: timed out connecting to %s:%u", peer_ip, port); return -1; }
        LOGD("peer not reachable yet, retrying");
        usleep(500 * 1000);
    }
}

//server 
static int server_exchange(int fd, const uint8_t *psk, size_t pl, session_t *out)
{
    uint8_t m1[M1_LEN], m2[M2_BODY + SHA256_LEN], m3[SHA256_LEN], z[DH_PUB_LEN], exp[SHA256_LEN];
    dh_ctx_t *dh = dh_new();
    int rc = -1;
    if (!dh) return -1;
    if (rd_full(fd, m1, sizeof m1)) { LOGE("handshake: receive M1 failed"); goto done; }
    if (memcmp(m1, MAGIC, 4)) { LOGE("handshake: bad magic in M1"); goto done; }
    memcpy(m2, MAGIC, 4);
    if (secure_random(m2 + 4, 32) || dh_public(dh, m2 + 36)) goto done;
    if (dh_shared(dh, m1 + 36, z)) { LOGE("handshake: invalid DH value from client"); goto done; }
    if (mac(psk, pl, "SGW2-server", m1, sizeof m1, m2, M2_BODY, m2 + M2_BODY)) goto done;
    if (wr_full(fd, m2, sizeof m2)) goto done;
    if (rd_full(fd, m3, sizeof m3)) { LOGE("handshake: receive M3 failed"); goto done; }
    if (mac(psk, pl, "SGW2-client", m1, sizeof m1, m2, M2_BODY, exp) || !ct_equal(exp, m3, SHA256_LEN)) {
        LOGE("handshake: client authentication FAILED (wrong PSK or MITM)");
        goto done;
    }
    if (session_derive(out, 0, z, m1 + 4, m2 + 4)) goto done;
    rc = 0;
done:
    secure_zero(z, sizeof z);
    dh_free(dh);
    return rc;
}

int hs_server(const char *bind_ip, uint16_t port, const uint8_t *psk, size_t pl,
              int timeout_s, session_t *out)
{
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    long long deadline = timeout_s ? now_ms() + timeout_s * 1000LL : 0;
    int one = 1, lfd, rc = -1;
    if (inet_pton(AF_INET, bind_ip, &sa.sin_addr) != 1) { LOGE("bad listen address %s", bind_ip); return -1; }
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return -1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) || listen(lfd, 4)) {
        LOGE("handshake: cannot listen on %s:%u: %s", bind_ip, port, strerror(errno));
        close(lfd);
        return -1;
    }
    for (;;) {   
        struct pollfd p = { lfd, POLLIN, 0 };
        int wait = -1;
        if (deadline) { long long left = deadline - now_ms(); if (left <= 0) break; wait = (int)left; }
        if (poll(&p, 1, wait) <= 0) { if (deadline) break; continue; }
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) continue;
        set_timeouts(fd);
        rc = server_exchange(fd, psk, pl, out);
        close(fd);
        if (rc == 0) break;
    }
    if (rc) LOGE("handshake: no peer authenticated before the timeout");
    close(lfd);
    return rc;
}
