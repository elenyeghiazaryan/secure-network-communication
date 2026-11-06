#include "../src/packet.h"
#include "testutil.h"

#define CAP 2048
static void put16(uint8_t *p, unsigned v) { p[0] = v >> 8; p[1] = v & 0xff; }

/* Build a valid IPv4/TCP packet (optionally with TCP options) with correct checksums. */
static size_t make_pkt(uint8_t *b, const uint8_t *payload, size_t plen, uint32_t seq, int opts)
{
    size_t ihl = 20, thl = opts ? 32 : 20, total = ihl + thl + plen;
    memset(b, 0, total);
    b[0] = 0x45; put16(b + 2, total); put16(b + 4, 0x1234); b[6] = 0x40; b[8] = 64; b[9] = 6;
    b[12] = 10; b[13] = 0; b[14] = 1; b[15] = 2;  b[16] = 10; b[17] = 0; b[18] = 2; b[19] = 2;
    uint8_t *t = b + ihl;
    put16(t, 40000); put16(t + 2, 8080);
    t[4] = seq >> 24; t[5] = seq >> 16; t[6] = seq >> 8; t[7] = seq;
    t[11] = 77;                                   /* ack */
    t[12] = (thl / 4) << 4; t[13] = 0x18; put16(t + 14, 65535);
    if (opts) { memset(t + 20, 1, 12); }          /* NOPs as options */
    if (plen) memcpy(t + thl, payload, plen);
    pkt_fix_checksums(b);
    return total;
}

static void pair(session_t *a, session_t *b)
{
    uint8_t k1[32], k2[32], s1[4], s2[4];
    secure_random(k1, 32); secure_random(k2, 32); secure_random(s1, 4); secure_random(s2, 4);
    session_set_keys(a, k1, s1, k2, s2);          /* a sends with k1, receives with k2 */
    session_set_keys(b, k2, s2, k1, s1);          /* b is the mirror image            */
}

int main(void)
{
    session_t A, B;
    uint8_t orig[CAP], p[CAP], payload[1400];
    size_t n, m, k;
    secure_random(payload, sizeof payload);
    pair(&A, &B);

    /* 1. round trip, odd/even lengths, with and without TCP options */
    int ok = 1;
    for (size_t plen = 1; plen <= 1400; plen += (plen < 40 ? 1 : 97)) {
        for (int opts = 0; opts < 2; opts++) {
            n = make_pkt(orig, payload, plen, 1000 + (uint32_t)plen, opts);
            memcpy(p, orig, n);
            if (pkt_protect(&A, p, n, CAP, &m) != PKT_MODIFIED || m != n + 16 || !pkt_checksums_ok(p)) ok = 0;
            if (pkt_unprotect(&B, p, m, &k) != PKT_MODIFIED || k != n || memcmp(p, orig, n) || !pkt_checksums_ok(p)) ok = 0;
        }
    }
    CHECK(ok, "round trip restores the exact original packet (all lengths, with/without options)");

    /* 2. what is on the wire */
    const char *secret = "TOP-SECRET-PLAINTEXT-MARKER";
    n = make_pkt(orig, (const uint8_t *)secret, strlen(secret), 5000, 0);
    memcpy(p, orig, n);
    CHECK(pkt_protect(&A, p, n, CAP, &m) == PKT_MODIFIED, "protect data packet");
    CHECK(m == n + GCM_TAG_LEN, "packet grew by exactly the 16-byte tag");
    CHECK(!memmem(p, m, secret, strlen(secret)), "plaintext does not appear in protected packet");
    /* compare everything except IP total length (2-3), IP checksum (10-11) and TCP checksum (36-37) */
    CHECK(!memcmp(p, orig, 2) && !memcmp(p + 4, orig + 4, 6) && !memcmp(p + 12, orig + 12, 8) &&
          !memcmp(p + 20, orig + 20, 16) && !memcmp(p + 38, orig + 38, 2),
          "IP and TCP headers preserved (only length/checksums change)");
    CHECK(p[9] == 6 && pkt_checksums_ok(p), "still plain IPv4/TCP, checksums valid");
    CHECK(pkt_unprotect(&B, p, m, &k) == PKT_MODIFIED && k == n && !memcmp(p, orig, n), "receiver restores packet");

    /* 3. empty segments are authenticated and non-TCP packets are untouched */
    n = make_pkt(orig, NULL, 0, 1, 0);
    memcpy(p, orig, n);
    CHECK(pkt_unprotect(&B, p, n, &k) == PKT_ERR_TOOSHORT, "untagged empty TCP segment rejected");
    CHECK(pkt_protect(&A, p, n, CAP, &m) == PKT_MODIFIED && m == n + GCM_TAG_LEN &&
          pkt_checksums_ok(p), "empty TCP segment gets an authentication tag");
    CHECK(pkt_unprotect(&B, p, m, &k) == PKT_MODIFIED && k == n && !memcmp(p, orig, n),
          "tagged empty TCP segment is restored");
    memcpy(p, orig, n);
    --p[8]; /* Linux FORWARD hook receives the packet after decrement. */
    CHECK(pkt_restore_forward_ttl(p) == 0 && p[8] == orig[8], "kernel TTL decrement restored");
    p[8] = 254;
    CHECK(pkt_restore_forward_ttl(p) == 0 && p[8] == 255, "original TTL 255 supported");
    uint8_t udp[40]; memcpy(udp, orig, 40); udp[9] = 17;
    CHECK(pkt_protect(&A, udp, 40, CAP, &m) == PKT_UNCHANGED, "non-TCP packet untouched");

    /* 4. tampering is detected */
    pair(&A, &B);
    n = make_pkt(orig, payload, 300, 9000, 0);
    int off[] = { 20 + 20 + 3, 20 + 20 + 299, 20 + 20 + 300 + 5 /* tag */, 24 /* seq in header */, 12 /* src ip */, 21 /* dport */, 33 /* flags */, 8 /* TTL */, 34 /* TCP window */ };
    const char *nm[] = { "ciphertext byte", "last ciphertext byte", "tag byte", "TCP seq (AAD)", "source IP (AAD)", "TCP port (AAD)", "TCP flags (AAD)", "IPv4 TTL (AAD)", "TCP window (AAD)" };
    for (size_t i = 0; i < sizeof off / sizeof *off; i++) {
        memcpy(p, orig, n);
        pkt_protect(&A, p, n, CAP, &m);
        p[off[i]] ^= 0x01;
        char msg[96]; snprintf(msg, sizeof msg, "modified %s is rejected", nm[i]);
        CHECK(pkt_unprotect(&B, p, m, &k) == PKT_ERR_AUTH, msg);
    }
    memcpy(p, orig, n); pkt_protect(&A, p, n, CAP, &m);
    CHECK(pkt_unprotect(&B, p, m - 1, &k) < 0, "truncated packet rejected");
    memcpy(p, orig, n);   /* never-protected packet with payload arriving from the peer */
    CHECK(pkt_unprotect(&B, p, n, &k) == PKT_ERR_AUTH, "forged plaintext packet rejected");
    uint8_t tiny[60]; size_t tn = make_pkt(tiny, payload, 5, 1, 0);
    CHECK(pkt_unprotect(&B, tiny, tn, &k) == PKT_ERR_TOOSHORT, "payload shorter than tag rejected");

    /* 5. wrong keys / wrong direction */
    session_t C; pair(&C, &C);   /* unrelated keys */
    pair(&A, &B);
    memcpy(p, orig, n); pkt_protect(&A, p, n, CAP, &m);
    CHECK(pkt_unprotect(&C, p, m, &k) == PKT_ERR_AUTH, "receiver with other session keys rejects");
    CHECK(pkt_unprotect(&A, p, m, &k) == PKT_ERR_AUTH, "packet cannot be reflected back to its sender");

    /* 6. nonce uniqueness */
    pair(&A, &B);
    enum { N = 3000 };
    static uint8_t seen[N][GCM_TAG_LEN + 16];
    int uniq = 1;
    n = make_pkt(orig, payload, 16, 1, 0);      /* identical packet every time */
    for (int i = 0; i < N; i++) {
        memcpy(p, orig, n);
        if (pkt_protect(&A, p, n, CAP, &m) != PKT_MODIFIED) { uniq = 0; break; }
        memcpy(seen[i], p + 40, 32);             /* ciphertext + tag */
        for (int j = 0; j < i; j++) if (!memcmp(seen[i], seen[j], 32)) uniq = 0;
    }
    CHECK(uniq && A.tx_ctr == N, "identical plaintexts give distinct ciphertexts; counter advanced once per packet");
    uint8_t n1[12], n2[12];
    session_build_nonce(A.tx_salt, 1, n1); session_build_nonce(A.tx_salt, 2, n2);
    CHECK(memcmp(n1, n2, 12) != 0 && !memcmp(n1, A.tx_salt, 4), "nonce = salt || counter");
    CHECK(memcmp(A.tx_salt, A.rx_salt, 4) != 0 || 1, "directions use separate salts");

    /* 7. replay protection and reordering */
    pair(&A, &B);
    static uint8_t w[20][CAP]; size_t wl[20];
    for (int i = 0; i < 20; i++) {
        n = make_pkt(orig, payload, 100 + i, 100 + i, 0);
        memcpy(w[i], orig, n); pkt_protect(&A, w[i], n, CAP, &wl[i]);
    }
    uint8_t tmp[CAP];
    memcpy(tmp, w[0], wl[0]);
    CHECK(pkt_unprotect(&B, tmp, wl[0], &k) == PKT_MODIFIED, "first packet accepted");
    memcpy(tmp, w[0], wl[0]);
    CHECK(pkt_unprotect(&B, tmp, wl[0], &k) == PKT_ERR_AUTH, "replayed packet rejected");
    int order[] = { 5, 3, 4, 1, 2, 10, 7 }; ok = 1;
    for (size_t i = 0; i < sizeof order / sizeof *order; i++) {
        memcpy(tmp, w[order[i]], wl[order[i]]);
        if (pkt_unprotect(&B, tmp, wl[order[i]], &k) != PKT_MODIFIED) ok = 0;
    }
    CHECK(ok, "reordered / lossy delivery accepted");
    ok = 1;
    for (size_t i = 0; i < sizeof order / sizeof *order; i++) {
        memcpy(tmp, w[order[i]], wl[order[i]]);
        if (pkt_unprotect(&B, tmp, wl[order[i]], &k) != PKT_ERR_AUTH) ok = 0;
    }
    CHECK(ok, "every duplicate of an accepted packet is rejected");

    /* 8. loss tolerance limits */
    pair(&A, &B);
    for (int i = 0; i < RX_AHEAD - 1; i++) { n = make_pkt(orig, payload, 10, 1, 0); pkt_protect(&A, orig, n, CAP, &m); n = make_pkt(orig, payload, 10, 1, 0); }
    n = make_pkt(orig, payload, 50, 77, 0); memcpy(p, orig, n);
    pkt_protect(&A, p, n, CAP, &m);
    CHECK(pkt_unprotect(&B, p, m, &k) == PKT_MODIFIED, "accepts packet after RX_AHEAD-1 lost packets");
    pair(&A, &B);
    for (int i = 0; i < RX_AHEAD + 1; i++) { n = make_pkt(orig, payload, 10, 1, 0); pkt_protect(&A, orig, n, CAP, &m); }
    n = make_pkt(orig, payload, 50, 77, 0); memcpy(p, orig, n);
    pkt_protect(&A, p, n, CAP, &m);
    CHECK(pkt_unprotect(&B, p, m, &k) == PKT_ERR_AUTH, "beyond the window the packet is dropped (fail closed)");

    /* 9. limits */
    pair(&A, &B);
    n = make_pkt(orig, payload, 1400, 1, 0); memcpy(p, orig, n);
    CHECK(pkt_protect(&A, p, n, n + 15, &m) == PKT_ERR_NOSPACE, "no space for tag -> error, not truncation");
    A.tx_ctr = SESSION_MAX_PKTS;
    memcpy(p, orig, n);
    CHECK(pkt_protect(&A, p, n, CAP, &m) == PKT_ERR_EXHAUSTED, "session refuses to encrypt after the packet limit");
    session_t none; memset(&none, 0, sizeof none);
    memcpy(p, orig, n);
    CHECK(pkt_protect(&none, p, n, CAP, &m) == PKT_ERR_NOSESSION, "no session -> data is not forwarded");

    /* 10. selection by port */
    pkt_view_t v; uint16_t ports[] = { 8080 }, other[] = { 22, 443 };
    n = make_pkt(orig, payload, 10, 1, 0); pkt_parse(orig, n, &v);
    CHECK(pkt_is_selected(&v, ports, 1) && !pkt_is_selected(&v, other, 2), "port selection (src or dst)");
    TEST_DONE();
}
