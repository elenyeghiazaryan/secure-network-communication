/* handshake.h - authenticated Diffie-Hellman handshake between Device1 and Device2.
 *
 *   C -> S : "SGW2" | cnonce[32] | A[256]
 *   S -> C : "SGW2" | snonce[32] | B[256] | HMAC(psk, "SGW2-server"|T)
 *   C -> S : HMAC(psk, "SGW2-client"|T)             T = M1 | M2-without-mac
 *
 * Z = DH shared secret; keys = HKDF-SHA256(salt = cnonce|snonce, ikm = Z).
 * The pre-shared key only authenticates the exchange (stops MITM); it is not
 * used as encryption key material, so the session keys are forward secret.
 * Data traffic is only processed after this handshake has succeeded.
 */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H
#include "session.h"

/* timeout_s: total seconds to wait (0 = forever). Return 0 on success. */
int hs_client(const char *peer_ip, uint16_t port, const uint8_t *psk, size_t psklen,
              int timeout_s, session_t *out);
int hs_server(const char *bind_ip, uint16_t port, const uint8_t *psk, size_t psklen,
              int timeout_s, session_t *out);
#endif
