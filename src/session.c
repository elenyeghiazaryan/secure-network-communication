#include "session.h"
#include <string.h>

void session_set_keys(session_t *s, const uint8_t *txk, const uint8_t *txs,
                      const uint8_t *rxk, const uint8_t *rxs)
{
    memset(s, 0, sizeof *s);
    memcpy(s->tx_key, txk, AES_KEY_LEN); memcpy(s->tx_salt, txs, 4);
    memcpy(s->rx_key, rxk, AES_KEY_LEN); memcpy(s->rx_salt, rxs, 4);
    s->established = 1;
}

int session_derive(session_t *s, int is_client, const uint8_t z[DH_PUB_LEN],
                   const uint8_t cnonce[32], const uint8_t snonce[32])
{
    static const char info[] = "SGW2 session keys";
    uint8_t salt[64], okm[32 + 32 + 4 + 4 + SESSION_ID_LEN];
    const uint8_t *c2s_k = okm, *s2c_k = okm + 32, *c2s_s = okm + 64, *s2c_s = okm + 68;
    memcpy(salt, cnonce, 32); memcpy(salt + 32, snonce, 32);
    if (hkdf_sha256(salt, sizeof salt, z, DH_PUB_LEN, (const uint8_t *)info, sizeof info - 1,
                    okm, sizeof okm))
        return -1;
    /* Reserve a direction bit so nonce prefixes cannot collide within a session. */
    okm[64] &= 0x7f;
    okm[68] |= 0x80;
    if (is_client) session_set_keys(s, c2s_k, c2s_s, s2c_k, s2c_s);
    else           session_set_keys(s, s2c_k, s2c_s, c2s_k, c2s_s);
    memcpy(s->id, okm + 72, SESSION_ID_LEN);
    secure_zero(okm, sizeof okm);
    return 0;
}

void session_build_nonce(const uint8_t salt[4], uint64_t ctr, uint8_t nonce[GCM_NONCE_LEN])
{
    memcpy(nonce, salt, 4);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(ctr >> (56 - 8 * i));
}

int session_rx_seen(const session_t *s, uint64_t c)
{
    return s->rx_ring[c % RX_WINDOW] == c + 1;
}

void session_rx_accept(session_t *s, uint64_t c)
{
    s->rx_ring[c % RX_WINDOW] = c + 1;
    if (c + 1 > s->rx_next) s->rx_next = c + 1;
}

void session_wipe(session_t *s) { secure_zero(s, sizeof *s); }
