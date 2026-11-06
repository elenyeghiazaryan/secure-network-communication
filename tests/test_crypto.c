#include "../src/crypto.h"
#include "testutil.h"

int main(void)
{
    unsigned char ikm[22], salt[13], info[10], expect[42], okm[42];
    memset(ikm, 0x0b, sizeof ikm);
    hex2bin("000102030405060708090a0b0c", salt, NULL);
    hex2bin("f0f1f2f3f4f5f6f7f8f9", info, NULL);
    hex2bin("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", expect, NULL);
    CHECK(hkdf_sha256(salt, 13, ikm, 22, info, 10, okm, 42) == 0 && !memcmp(okm, expect, 42),
          "HKDF-SHA256 matches RFC 5869 test case 1");

    /* AES-256-GCM known answer: GCM spec test case 14 (zero key, zero IV, 16 zero bytes) */
    unsigned char key[32] = {0}, nonce[12] = {0}, pt[16] = {0}, ct[16], tag[16], ect[16], etag[16], dec[16];
    hex2bin("cea7403d4d606b6e074ec5d3baf39d18", ect, NULL);
    hex2bin("d0d1c8a799996bf0265b98b5d48ab919", etag, NULL);
    CHECK(aes256gcm_encrypt(key, nonce, NULL, 0, pt, 16, ct, tag) == 0 && !memcmp(ct, ect, 16) &&
          !memcmp(tag, etag, 16), "AES-256-GCM matches NIST/McGrew-Viega test case 14");
    CHECK(aes256gcm_decrypt(key, nonce, NULL, 0, ct, 16, tag, dec) == 0 && !memcmp(dec, pt, 16),
          "AES-GCM decrypt of known vector");

    /* round trip with AAD + tamper detection */
    unsigned char k2[32], n2[12], aad[21], msg[100], c2[100], t2[16], d2[100];
    secure_random(k2, 32); secure_random(n2, 12); secure_random(aad, 21); secure_random(msg, 100);
    CHECK(aes256gcm_encrypt(k2, n2, aad, 21, msg, 100, c2, t2) == 0, "encrypt with AAD");
    CHECK(aes256gcm_decrypt(k2, n2, aad, 21, c2, 100, t2, d2) == 0 && !memcmp(d2, msg, 100), "round trip");
    c2[5] ^= 1;  CHECK(aes256gcm_decrypt(k2, n2, aad, 21, c2, 100, t2, d2) != 0, "flipped ciphertext bit rejected");
    c2[5] ^= 1;  t2[0] ^= 1;
    CHECK(aes256gcm_decrypt(k2, n2, aad, 21, c2, 100, t2, d2) != 0, "flipped tag bit rejected");
    t2[0] ^= 1;  aad[3] ^= 1;
    CHECK(aes256gcm_decrypt(k2, n2, aad, 21, c2, 100, t2, d2) != 0, "modified AAD rejected");
    aad[3] ^= 1; n2[11] ^= 1;
    CHECK(aes256gcm_decrypt(k2, n2, aad, 21, c2, 100, t2, d2) != 0, "different nonce rejected");

    /* in-place encryption */
    unsigned char buf[100]; memcpy(buf, msg, 100); n2[11] ^= 1;
    CHECK(aes256gcm_encrypt(k2, n2, aad, 21, buf, 100, buf, t2) == 0 &&
          aes256gcm_decrypt(k2, n2, aad, 21, buf, 100, t2, d2) == 0 && !memcmp(d2, msg, 100), "in-place encrypt");

    /* Diffie-Hellman */
    dh_ctx_t *a = dh_new(), *b = dh_new();
    unsigned char pa[DH_PUB_LEN], pb[DH_PUB_LEN], za[DH_PUB_LEN], zb[DH_PUB_LEN];
    CHECK(a && b && dh_public(a, pa) == 0 && dh_public(b, pb) == 0, "DH key generation");
    CHECK(dh_shared(a, pb, za) == 0 && dh_shared(b, pa, zb) == 0 && !memcmp(za, zb, DH_PUB_LEN),
          "both sides derive the same DH secret");
    CHECK(memcmp(pa, pb, DH_PUB_LEN) != 0, "two key pairs differ");
    unsigned char bad[DH_PUB_LEN] = {0}, z[DH_PUB_LEN];
    CHECK(dh_shared(a, bad, z) != 0, "DH rejects public value 0");
    bad[DH_PUB_LEN - 1] = 1;
    CHECK(dh_shared(a, bad, z) != 0, "DH rejects public value 1");
    memset(bad, 0xff, DH_PUB_LEN);
    CHECK(dh_shared(a, bad, z) != 0, "DH rejects value >= p");
    dh_free(a); dh_free(b);
    TEST_DONE();
}
