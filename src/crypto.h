/* crypto.h - thin, auditable wrappers around OpenSSL primitives.
 *   - Diffie-Hellman over RFC 3526 group 14 (2048-bit MODP, g = 2)
 *   - HKDF-SHA256 (RFC 5869) and HMAC-SHA256
 *   - AES-256-GCM (12-byte nonce, 16-byte tag)
 */
#ifndef CRYPTO_H
#define CRYPTO_H
#include <stddef.h>
#include <stdint.h>

#define DH_PUB_LEN    256
#define AES_KEY_LEN   32
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN   16
#define SHA256_LEN    32

typedef struct dh_ctx dh_ctx_t;

int  secure_random(uint8_t *buf, size_t len);

dh_ctx_t *dh_new(void);                                   /* fresh key pair */
int  dh_public(const dh_ctx_t *d, uint8_t out[DH_PUB_LEN]);
/* Validates the peer value (1 < y < p-1 and y in the order-q subgroup). */
int  dh_shared(const dh_ctx_t *d, const uint8_t peer[DH_PUB_LEN],
               uint8_t out[DH_PUB_LEN]);
void dh_free(dh_ctx_t *d);

int  hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen, uint8_t out[SHA256_LEN]);
int  hkdf_sha256(const uint8_t *salt, size_t saltlen,
                 const uint8_t *ikm, size_t ikmlen,
                 const uint8_t *info, size_t infolen,
                 uint8_t *out, size_t outlen);

/* Encrypt: ct may equal pt (in place). Returns 0 on success. */
int  aes256gcm_encrypt(const uint8_t key[AES_KEY_LEN],
                       const uint8_t nonce[GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aadlen,
                       const uint8_t *pt, size_t ptlen,
                       uint8_t *ct, uint8_t tag[GCM_TAG_LEN]);
/* Decrypt into a SEPARATE buffer. Returns 0 only if the tag verifies. */
int  aes256gcm_decrypt(const uint8_t key[AES_KEY_LEN],
                       const uint8_t nonce[GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aadlen,
                       const uint8_t *ct, size_t ctlen,
                       const uint8_t tag[GCM_TAG_LEN], uint8_t *pt);

int  ct_equal(const uint8_t *a, const uint8_t *b, size_t n);   /* 1 = equal */
void secure_zero(void *p, size_t n);
#endif
