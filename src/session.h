/* session.h - per-session key material, nonce construction, replay window.
 *
 * Nonce (96 bit) = 4-byte per-direction salt || 64-bit big-endian counter.
 * Each direction has its own key AND salt, and the counter is incremented
 * for every encrypted packet, so a (key, nonce) pair is never reused.
 */
#ifndef SESSION_H
#define SESSION_H
#include "crypto.h"

#define RX_WINDOW 256                 /* how far behind we accept reordered pkts */
#define RX_AHEAD  256                 /* how many lost packets we can skip over  */
#define SESSION_MAX_PKTS (1ULL << 32) /* hard cap per session: fail closed       */
#define SESSION_ID_LEN 8

typedef struct {
    uint8_t  tx_key[AES_KEY_LEN], rx_key[AES_KEY_LEN];
    uint8_t  tx_salt[4], rx_salt[4];
    uint8_t  id[SESSION_ID_LEN];
    uint64_t tx_ctr;                  /* next counter to use when sending       */
    uint64_t rx_next;                 /* highest accepted counter + 1           */
    uint64_t rx_ring[RX_WINDOW];      /* slot c%W holds c+1 if c was accepted   */
    int      established;
} session_t;

/* tx_key/rx_key: 32 bytes each; tx_salt/rx_salt: 4 bytes each */
void session_set_keys(session_t *s, const uint8_t *tx_key, const uint8_t *tx_salt,
                      const uint8_t *rx_key, const uint8_t *rx_salt);
/* Derive all session keys from the DH secret z and both handshake nonces. */
int  session_derive(session_t *s, int is_client, const uint8_t z[DH_PUB_LEN],
                    const uint8_t cnonce[32], const uint8_t snonce[32]);
void session_build_nonce(const uint8_t salt[4], uint64_t ctr, uint8_t nonce[GCM_NONCE_LEN]);
int  session_rx_seen(const session_t *s, uint64_t c);
void session_rx_accept(session_t *s, uint64_t c);
void session_wipe(session_t *s);
#endif
