/* packet.h - in-place protection of the TCP payload of an IPv4 packet.
 *
 * protect:   [IP hdr][TCP hdr][payload]          -> [IP hdr][TCP hdr][ciphertext][16B tag]
 * unprotect: [IP hdr][TCP hdr][ciphertext][tag]  -> [IP hdr][TCP hdr][payload]
 *
 * IP and TCP headers (incl. options) are preserved; only IP total length and
 * the IP/TCP checksums are rewritten. No outer header, no UDP, no custom
 * protocol header is added.
 *
 * The nonce is NOT transmitted: both ends keep a synchronised 64-bit packet
 * counter. The receiver recovers the counter of each packet by trial
 * verification inside a bounded window, which also gives replay protection
 * and tolerance to loss/reordering. Immutable header fields (addresses,
 * ports, seq, ack, flags) are bound to the tag as AES-GCM AAD.
 */
#ifndef PACKET_H
#define PACKET_H
#include "session.h"

typedef struct {
    uint8_t *ip, *tcp, *payload;
    size_t   ihl, thl, plen, total;
    uint16_t sport, dport;
} pkt_view_t;

enum { PKT_PARSE_OK = 0, PKT_NOT_APPLICABLE = 1, PKT_MALFORMED = -1 };
enum {
    PKT_MODIFIED = 0,        /* buffer rewritten, *newlen set               */
    PKT_UNCHANGED = 1,       /* nothing to do (no payload / not IPv4 TCP)   */
    PKT_ERR_MALFORMED = -1,
    PKT_ERR_NOSPACE = -2,
    PKT_ERR_AUTH = -3,       /* no counter in the window verified the tag   */
    PKT_ERR_EXHAUSTED = -4,  /* session packet limit reached                */
    PKT_ERR_TOOSHORT = -5,   /* payload shorter than a tag                  */
    PKT_ERR_CRYPTO = -6,
    PKT_ERR_NOSESSION = -7
};

int  pkt_parse(uint8_t *buf, size_t len, pkt_view_t *v);
void pkt_fix_checksums(uint8_t *buf);           /* IP header + TCP checksum   */
int  pkt_checksums_ok(const uint8_t *buf);      /* 1 if both are valid        */
int  pkt_is_selected(const pkt_view_t *v, const uint16_t *ports, size_t nports);

int  pkt_protect(session_t *s, uint8_t *buf, size_t len, size_t cap, size_t *newlen);
int  pkt_unprotect(session_t *s, uint8_t *buf, size_t len, size_t *newlen);
const char *pkt_strerror(int rc);
#endif
