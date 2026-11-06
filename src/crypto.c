#include "crypto.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#define DH_PRIV_BITS 320   /* >= 2x the ~128-bit security level of group 14 */

struct dh_ctx { BIGNUM *p; BIGNUM *x; BIGNUM *y; };

void secure_zero(void *p, size_t n) { OPENSSL_cleanse(p, n); }
int  secure_random(uint8_t *buf, size_t len) { return RAND_bytes(buf, (int)len) == 1 ? 0 : -1; }
int  ct_equal(const uint8_t *a, const uint8_t *b, size_t n) { return CRYPTO_memcmp(a, b, n) == 0; }

// DH 
void dh_free(dh_ctx_t *d)
{
    if (!d) return;
    BN_clear_free(d->x);
    BN_free(d->p);
    BN_free(d->y);
    free(d);
}

dh_ctx_t *dh_new(void)
{
    dh_ctx_t *d = calloc(1, sizeof *d);
    BN_CTX *bc = BN_CTX_new();
    BIGNUM *g = BN_new();
    if (!d || !bc || !g) goto err;
    d->p = BN_get_rfc3526_prime_2048(NULL);
    d->x = BN_new();
    d->y = BN_new();
    if (!d->p || !d->x || !d->y) goto err;
    if (!BN_set_word(g, 2)) goto err;
    if (!BN_priv_rand(d->x, DH_PRIV_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) goto err;
    if (!BN_mod_exp(d->y, g, d->x, d->p, bc)) goto err;
    BN_free(g);
    BN_CTX_free(bc);
    return d;
err:
    BN_free(g);
    BN_CTX_free(bc);
    dh_free(d);
    return NULL;
}

int dh_public(const dh_ctx_t *d, uint8_t out[DH_PUB_LEN])
{
    return BN_bn2binpad(d->y, out, DH_PUB_LEN) == DH_PUB_LEN ? 0 : -1;
}

int dh_shared(const dh_ctx_t *d, const uint8_t peer[DH_PUB_LEN], uint8_t out[DH_PUB_LEN])
{
    int rc = -1;
    BN_CTX *bc = BN_CTX_new();
    BIGNUM *y = BN_bin2bn(peer, DH_PUB_LEN, NULL);
    BIGNUM *pm1 = BN_dup(d->p);
    BIGNUM *q = BN_new(), *t = BN_new(), *z = BN_new();
    if (!bc || !y || !pm1 || !q || !t || !z) goto done;
    if (!BN_sub_word(pm1, 1)) goto done;
    /* 1 < y < p-1 */
    if (BN_cmp(y, BN_value_one()) <= 0 || BN_cmp(y, pm1) >= 0) goto done;
    /* y must lie in the prime-order subgroup: y^q mod p == 1, q = (p-1)/2 */
    if (!BN_rshift1(q, pm1)) goto done;
    if (!BN_mod_exp(t, y, q, d->p, bc) || !BN_is_one(t)) goto done;
    if (!BN_mod_exp(z, y, d->x, d->p, bc)) goto done;
    if (BN_bn2binpad(z, out, DH_PUB_LEN) != DH_PUB_LEN) goto done;
    rc = 0;
done:
    BN_clear_free(z);
    BN_free(t); BN_free(q); BN_free(pm1); BN_free(y);
    BN_CTX_free(bc);
    return rc;
}

// HMAC / HKDF 
int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t datalen,
                uint8_t out[SHA256_LEN])
{
    unsigned int n = 0;
    static const uint8_t empty = 0;
    if (!key) { key = &empty; keylen = 0; }
    if (!data) { data = &empty; datalen = 0; }
    return HMAC(EVP_sha256(), key, (int)keylen, data, datalen, out, &n) && n == SHA256_LEN ? 0 : -1;
}

int hkdf_sha256(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
                const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen)
{
    uint8_t zero[SHA256_LEN] = {0}, prk[SHA256_LEN], t[SHA256_LEN] = {0};
    uint8_t buf[SHA256_LEN + 128 + 1];
    size_t tl = 0, pos = 0;
    uint8_t ctr = 1;
    int rc = -1;

    if (outlen > 255 * SHA256_LEN || infolen > 128) return -1;
    if (!salt || !saltlen) { salt = zero; saltlen = SHA256_LEN; }
    if (hmac_sha256(salt, saltlen, ikm, ikmlen, prk)) goto done;
    while (pos < outlen) {
        size_t bl = 0, take;
        memcpy(buf, t, tl); bl = tl;
        if (infolen) { memcpy(buf + bl, info, infolen); bl += infolen; }
        buf[bl++] = ctr++;
        if (hmac_sha256(prk, SHA256_LEN, buf, bl, t)) goto done;
        tl = SHA256_LEN;
        take = outlen - pos < SHA256_LEN ? outlen - pos : SHA256_LEN;
        memcpy(out + pos, t, take);
        pos += take;
    }
    rc = 0;
done:
    secure_zero(prk, sizeof prk); secure_zero(t, sizeof t); secure_zero(buf, sizeof buf);
    return rc;
}

// AES-GCM 
int aes256gcm_encrypt(const uint8_t key[AES_KEY_LEN], const uint8_t nonce[GCM_NONCE_LEN],
                      const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t ptlen,
                      uint8_t *ct, uint8_t tag[GCM_TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, rc = -1;
    if (!c) return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) != 1) goto done;
    if (aadlen && EVP_EncryptUpdate(c, NULL, &l, aad, (int)aadlen) != 1) goto done;
    if (ptlen && EVP_EncryptUpdate(c, ct, &l, pt, (int)ptlen) != 1) goto done;
    if (EVP_EncryptFinal_ex(c, ct + (ptlen ? l : 0), &l) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) goto done;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int aes256gcm_decrypt(const uint8_t key[AES_KEY_LEN], const uint8_t nonce[GCM_NONCE_LEN],
                      const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t ctlen,
                      const uint8_t tag[GCM_TAG_LEN], uint8_t *pt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    uint8_t tagcopy[GCM_TAG_LEN];
    int l = 0, rc = -1;
    if (!c) return -1;
    memcpy(tagcopy, tag, GCM_TAG_LEN);
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) != 1) goto done;
    if (aadlen && EVP_DecryptUpdate(c, NULL, &l, aad, (int)aadlen) != 1) goto done;
    if (ctlen && EVP_DecryptUpdate(c, pt, &l, ct, (int)ctlen) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tagcopy) != 1) goto done;
    if (EVP_DecryptFinal_ex(c, pt + (ctlen ? l : 0), &l) != 1) goto done;   /* tag check */
    rc = 0;
done:
    EVP_CIPHER_CTX_free(c);
    return rc;
}
