#include "packet.h"
#include <string.h>

#define AAD_LEN 21
#define MAX_IP_TOTAL 65535

// checksums 
static uint32_t csum_add(uint32_t sum, const uint8_t *d, size_t n)
{
    while (n > 1) { sum += ((uint32_t)d[0] << 8) | d[1]; d += 2; n -= 2; }
    if (n) sum += (uint32_t)d[0] << 8;
    return sum;
}
static uint16_t csum_fold(uint32_t s)
{
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static uint32_t tcp_sum(const uint8_t *ip, size_t ihl, size_t total)
{
    size_t tl = total - ihl;
    uint8_t ph[4] = { 0, 6, (uint8_t)(tl >> 8), (uint8_t)tl };
    uint32_t s = csum_add(0, ip + 12, 8);          /* src + dst address */
    s = csum_add(s, ph, 4);
    return csum_add(s, ip + ihl, tl);
}

void pkt_fix_checksums(uint8_t *ip)
{
    size_t ihl = (ip[0] & 0xf) * 4, total = get16(ip + 2);
    ip[10] = ip[11] = 0;
    put16(ip + 10, csum_fold(csum_add(0, ip, ihl)));
    ip[ihl + 16] = ip[ihl + 17] = 0;
    put16(ip + ihl + 16, csum_fold(tcp_sum(ip, ihl, total)));
}

int pkt_checksums_ok(const uint8_t *ip)
{
    size_t ihl = (ip[0] & 0xf) * 4, total = get16(ip + 2);
    return csum_fold(csum_add(0, ip, ihl)) == 0 && csum_fold(tcp_sum(ip, ihl, total)) == 0;
}

// parsing
int pkt_parse(uint8_t *buf, size_t len, pkt_view_t *v)
{
    size_t ihl, total, tl, thl;
    if (len < 1 || (buf[0] >> 4) != 4) return PKT_NOT_APPLICABLE;      /* not IPv4 */
    if (len < 20) return PKT_MALFORMED;
    ihl = (size_t)(buf[0] & 0xf) * 4;
    if (ihl < 20 || len < ihl) return PKT_MALFORMED;
    if (buf[9] != 6) return PKT_NOT_APPLICABLE;                          /* not TCP  */
    total = get16(buf + 2);
    if (total < ihl || total > len) return PKT_MALFORMED;
    /* fragments cannot be protected safely: reject (fail closed) */
    if ((buf[6] & 0x20) || (((buf[6] & 0x1f) << 8) | buf[7])) return PKT_MALFORMED;
    tl = total - ihl;
    if (tl < 20) return PKT_MALFORMED;
    thl = (size_t)(buf[ihl + 12] >> 4) * 4;
    if (thl < 20 || thl > tl) return PKT_MALFORMED;
    v->ip = buf; v->tcp = buf + ihl; v->ihl = ihl; v->thl = thl; v->total = total;
    v->payload = buf + ihl + thl; v->plen = tl - thl;
    v->sport = get16(v->tcp); v->dport = get16(v->tcp + 2);
    return PKT_PARSE_OK;
}

int pkt_is_selected(const pkt_view_t *v, const uint16_t *ports, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (v->sport == ports[i] || v->dport == ports[i]) return 1;
    return 0;
}

/* AAD = src ip | dst ip | sport | dport | seq | ack | tcp flags (all immutable in transit) */
static void build_aad(const pkt_view_t *v, uint8_t aad[AAD_LEN])
{
    memcpy(aad, v->ip + 12, 8);
    memcpy(aad + 8, v->tcp, 4);          /* sport, dport */
    memcpy(aad + 12, v->tcp + 4, 8);     /* seq, ack     */
    aad[20] = v->tcp[13];                /* flags        */
}

// protect
int pkt_protect(session_t *s, uint8_t *buf, size_t len, size_t cap, size_t *newlen)
{
    pkt_view_t v; uint8_t aad[AAD_LEN], nonce[GCM_NONCE_LEN];
    int pr = pkt_parse(buf, len, &v);
    if (pr == PKT_NOT_APPLICABLE) { *newlen = len; return PKT_UNCHANGED; }
    if (pr != PKT_PARSE_OK) return PKT_ERR_MALFORMED;
    if (!s || !s->established) return PKT_ERR_NOSESSION;
    if (v.plen == 0) { *newlen = len; return PKT_UNCHANGED; }          /* SYN/ACK/FIN... */
    if (s->tx_ctr >= SESSION_MAX_PKTS) return PKT_ERR_EXHAUSTED;
    if (v.total + GCM_TAG_LEN > MAX_IP_TOTAL || v.total + GCM_TAG_LEN > cap) return PKT_ERR_NOSPACE;

    build_aad(&v, aad);
    session_build_nonce(s->tx_salt, s->tx_ctr, nonce);
    if (aes256gcm_encrypt(s->tx_key, nonce, aad, AAD_LEN, v.payload, v.plen,
                          v.payload, v.payload + v.plen))
        return PKT_ERR_CRYPTO;
    s->tx_ctr++;                                   /* never reuse a nonce */
    put16(buf + 2, (uint16_t)(v.total + GCM_TAG_LEN));
    pkt_fix_checksums(buf);
    *newlen = v.total + GCM_TAG_LEN;
    return PKT_MODIFIED;
}

//unprotect 
static int try_counter(session_t *s, const pkt_view_t *v, const uint8_t *aad, uint64_t c,
                       uint8_t *scratch)
{
    uint8_t nonce[GCM_NONCE_LEN];
    size_t ctlen = v->plen - GCM_TAG_LEN;
    session_build_nonce(s->rx_salt, c, nonce);
    return aes256gcm_decrypt(s->rx_key, nonce, aad, AAD_LEN, v->payload, ctlen,
                             v->payload + ctlen, scratch);
}

int pkt_unprotect(session_t *s, uint8_t *buf, size_t len, size_t *newlen)
{
    pkt_view_t v; uint8_t aad[AAD_LEN];
    static uint8_t scratch[MAX_IP_TOTAL];
    uint64_t found = 0; int ok = 0;
    int pr = pkt_parse(buf, len, &v);
    if (pr == PKT_NOT_APPLICABLE) { *newlen = len; return PKT_UNCHANGED; }
    if (pr != PKT_PARSE_OK) return PKT_ERR_MALFORMED;
    if (!s || !s->established) return PKT_ERR_NOSESSION;
    if (v.plen == 0) { *newlen = len; return PKT_UNCHANGED; }
    if (v.plen < GCM_TAG_LEN) return PKT_ERR_TOOSHORT;

    build_aad(&v, aad);
    /* 1) expected counter and the packets ahead of it (loss tolerance) */
    for (uint64_t k = 0; k < RX_AHEAD && !ok; k++) {
        uint64_t c = s->rx_next + k;
        if (try_counter(s, &v, aad, c, scratch) == 0) { ok = 1; found = c; }
    }
    /* 2) not-yet-seen counters behind it (reordering); seen ones = replay */
    for (uint64_t k = 1; k <= RX_WINDOW && k <= s->rx_next && !ok; k++) {
        uint64_t c = s->rx_next - k;
        if (session_rx_seen(s, c)) continue;
        if (try_counter(s, &v, aad, c, scratch) == 0) { ok = 1; found = c; }
    }
    if (!ok) return PKT_ERR_AUTH;

    session_rx_accept(s, found);
    memcpy(v.payload, scratch, v.plen - GCM_TAG_LEN);
    put16(buf + 2, (uint16_t)(v.total - GCM_TAG_LEN));
    pkt_fix_checksums(buf);
    *newlen = v.total - GCM_TAG_LEN;
    return PKT_MODIFIED;
}

const char *pkt_strerror(int rc)
{
    switch (rc) {
    case PKT_MODIFIED: return "modified";
    case PKT_UNCHANGED: return "unchanged";
    case PKT_ERR_MALFORMED: return "malformed packet";
    case PKT_ERR_NOSPACE: return "no space for tag";
    case PKT_ERR_AUTH: return "authentication failed / replay";
    case PKT_ERR_EXHAUSTED: return "session packet limit reached";
    case PKT_ERR_TOOSHORT: return "payload shorter than tag";
    case PKT_ERR_CRYPTO: return "crypto error";
    case PKT_ERR_NOSESSION: return "no session";
    }
    return "unknown";
}
