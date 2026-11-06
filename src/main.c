/* secgw - inline secure gateway daemon (Device1 / Device2).
 *
 * 1. Runs the authenticated Diffie-Hellman handshake with the peer device.
 * 2. Only then attaches to two NFQUEUEs:
 *      queue OUT : packets arriving from the local host, heading to the peer  -> encrypt
 *      queue IN  : packets arriving from the peer, heading to the local host  -> decrypt
 *    Until the handshake is done nothing is read from the queues, so queued
 *    traffic is dropped by the kernel (fail closed).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "handshake.h"
#include "log.h"
#include "packet.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0, g_dump = 0;

#define MAX_PORTS 16
#define WORKBUF (65535 + 64)

typedef struct { int encrypt; } qctx_t;
static struct {
    session_t sess;
    uint16_t ports[MAX_PORTS]; size_t nports;
    uint64_t enc_ok, dec_ok, passthru, drop_auth, drop_other;
} G;
static uint8_t work[WORKBUF];

static void on_sig(int s) { if (s == SIGUSR1) g_dump = 1; else g_stop = 1; }

static void print_stats(void)
{
    LOGI("stats: encrypted=%llu decrypted=%llu passthrough=%llu dropped(auth)=%llu dropped(other)=%llu tx_ctr=%llu",
         (unsigned long long)G.enc_ok, (unsigned long long)G.dec_ok, (unsigned long long)G.passthru,
         (unsigned long long)G.drop_auth, (unsigned long long)G.drop_other,
         (unsigned long long)G.sess.tx_ctr);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    qctx_t *q = data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    unsigned char *pl = NULL;
    int len = nfq_get_payload(nfa, &pl);
    size_t newlen = 0;
    pkt_view_t v;
    int rc;
    (void)nfmsg;

    if (len <= 0 || len > 65535) { G.drop_other++; return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); }
    memcpy(work, pl, (size_t)len);

    /* only the selected TCP flows are touched; everything else is forwarded as-is */
    rc = pkt_parse(work, (size_t)len, &v);
    if (rc == PKT_NOT_APPLICABLE || (rc == PKT_PARSE_OK && !pkt_is_selected(&v, G.ports, G.nports))) {
        G.passthru++;
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    if (rc != PKT_PARSE_OK || pkt_restore_forward_ttl(work) != 0) {
        G.drop_other++;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    rc = q->encrypt ? pkt_protect(&G.sess, work, (size_t)len, sizeof work, &newlen)
                    : pkt_unprotect(&G.sess, work, (size_t)len, &newlen);
    switch (rc) {
    case PKT_MODIFIED:
        if (q->encrypt) G.enc_ok++; else G.dec_ok++;
        LOGD("%s ok: %d -> %zu bytes", q->encrypt ? "encrypt" : "decrypt", len, newlen);
        return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)newlen, work);
    case PKT_UNCHANGED:
        G.passthru++;
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    case PKT_ERR_AUTH:
        G.drop_auth++;
        LOGD("DROP (%s): %s", q->encrypt ? "encrypt" : "decrypt", pkt_strerror(rc));
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    default:
        G.drop_other++;
        LOGD("DROP (%s): %s", q->encrypt ? "encrypt" : "decrypt", pkt_strerror(rc));
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

static int load_psk(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) { LOGE("cannot open PSK file %s: %s", path, strerror(errno)); return -1; }
    n = fread(buf, 1, cap, f);
    fclose(f);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;   /* strip trailing newline */
    if (n < 16) { LOGE("PSK must be at least 16 bytes (use: openssl rand -hex 32 > psk.key)"); return -1; }
    *len = n;
    return 0;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s --role client|server --psk-file FILE --port PORT [--port PORT ...] [options]\n"
        "  --role client|server   client connects to --peer, server listens on --listen\n"
        "  --peer IP              (client) control address of the other device\n"
        "  --listen IP            (server) address to listen on for the handshake\n"
        "  --ctrl-port N          handshake TCP port (default 9000)\n"
        "  --port N               protected TCP port, matches src OR dst port (repeatable)\n"
        "  --psk-file FILE        pre-shared authentication key (>= 16 bytes)\n"
        "  --queue-out N          NFQUEUE for host->peer packets, encrypt (default 0)\n"
        "  --queue-in N           NFQUEUE for peer->host packets, decrypt (default 1)\n"
        "  --hs-timeout SEC       handshake timeout, 0 = wait forever (default 0)\n"
        "  -v                     verbose per-packet logging\n", p);
}

int main(int argc, char **argv)
{
    const char *role = NULL, *peer = NULL, *listen_ip = "0.0.0.0", *pskf = NULL;
    int ctrl_port = 9000, qout = 0, qin = 1, hs_timeout = 0, c;
    uint8_t psk[256]; size_t psklen = 0;
    static const struct option lo[] = {
        {"role", 1, 0, 'r'}, {"peer", 1, 0, 'p'}, {"listen", 1, 0, 'l'}, {"ctrl-port", 1, 0, 'c'},
        {"port", 1, 0, 'P'}, {"psk-file", 1, 0, 'k'}, {"queue-out", 1, 0, 'o'}, {"queue-in", 1, 0, 'i'},
        {"hs-timeout", 1, 0, 't'}, {"help", 0, 0, 'h'}, {0, 0, 0, 0} };

    while ((c = getopt_long(argc, argv, "vh", lo, NULL)) != -1) {
        switch (c) {
        case 'r': role = optarg; break;
        case 'p': peer = optarg; break;
        case 'l': listen_ip = optarg; break;
        case 'c': ctrl_port = atoi(optarg); break;
        case 'P': { int p = atoi(optarg);
                    if (p < 1 || p > 65535 || G.nports >= MAX_PORTS) { LOGE("bad --port"); return 2; }
                    G.ports[G.nports++] = (uint16_t)p; break; }
        case 'k': pskf = optarg; break;
        case 'o': qout = atoi(optarg); break;
        case 'i': qin = atoi(optarg); break;
        case 't': hs_timeout = atoi(optarg); break;
        case 'v': g_verbose = 1; break;
        default: usage(argv[0]); return 2;
        }
    }
    if (!role || !pskf || !G.nports || ctrl_port < 1 || ctrl_port > 65535 ||
        (strcmp(role, "client") && strcmp(role, "server")) || (!strcmp(role, "client") && !peer)) {
        usage(argv[0]);
        return 2;
    }
    if (load_psk(pskf, psk, sizeof psk, &psklen)) return 2;

    LOGI("role=%s, starting handshake ...", role);
    if (!strcmp(role, "client"))
        c = hs_client(peer, (uint16_t)ctrl_port, psk, psklen, hs_timeout, &G.sess);
    else
        c = hs_server(listen_ip, (uint16_t)ctrl_port, psk, psklen, hs_timeout, &G.sess);
    secure_zero(psk, sizeof psk);
    if (c) { LOGE("handshake failed - no traffic will be forwarded through the secure channel"); return 1; }
    {
        char hex[2 * SESSION_ID_LEN + 1];
        for (int i = 0; i < SESSION_ID_LEN; i++) sprintf(hex + 2 * i, "%02x", G.sess.id[i]);
        LOGI("session established (id %s); AES-256-GCM active for TCP port(s) listed", hex);
    }

    struct sigaction sa = { .sa_handler = on_sig };      /* no SA_RESTART: recv() must return on signal */
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL); sigaction(SIGUSR1, &sa, NULL);

    struct nfq_handle *h = nfq_open();
    if (!h) { LOGE("nfq_open failed (are you root? is nfnetlink_queue loaded?)"); return 1; }
    qctx_t out_ctx = { 1 }, in_ctx = { 0 };
    struct nfq_q_handle *qo = nfq_create_queue(h, (uint16_t)qout, &cb, &out_ctx);
    struct nfq_q_handle *qi = nfq_create_queue(h, (uint16_t)qin, &cb, &in_ctx);
    if (!qo || !qi) { LOGE("cannot bind NFQUEUE %d/%d (already in use?)", qout, qin); return 1; }
    nfq_set_mode(qo, NFQNL_COPY_PACKET, 0xffff); nfq_set_mode(qi, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_queue_maxlen(qo, 4096); nfq_set_queue_maxlen(qi, 4096);
    int fd = nfq_fd(h), rcvbuf = 1 << 22;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    LOGI("processing packets: queue %d = encrypt, queue %d = decrypt (Ctrl-C to stop, SIGUSR1 = stats)", qout, qin);

    static uint8_t buf[WORKBUF + 4096];
    while (!g_stop) {
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (g_dump) { print_stats(); g_dump = 0; }
        if (n >= 0) { nfq_handle_packet(h, (char *)buf, (int)n); continue; }
        if (errno == EINTR) continue;
        if (errno == ENOBUFS) { LOGE("queue overflow, packets dropped by kernel"); continue; }
        LOGE("recv: %s", strerror(errno));
        break;
    }
    print_stats();
    nfq_destroy_queue(qo); nfq_destroy_queue(qi); nfq_close(h);
    session_wipe(&G.sess);
    return 0;
}
