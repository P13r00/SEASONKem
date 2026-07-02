
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include "core/inc/crypto_api.h"

#define CHACHA_KEY_BYTES   32u
#define CHACHA_NONCE_BYTES 12u
#define POLY1305_TAG_BYTES 16u

static int chacha_keygen(uint8_t *key, uint8_t *nonce)
{
    if (platform_rng_generate(key,   CHACHA_KEY_BYTES)   != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    if (platform_rng_generate(nonce, CHACHA_NONCE_BYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}

static int chacha_encrypt(uint8_t *ct, size_t *ctlen,
                          const uint8_t *pt, size_t ptlen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *nonce,
                          const uint8_t *key)
{
    int ret = wc_ChaCha20Poly1305_Encrypt(key, nonce,
                                          ad, (word32)adlen,
                                          pt, (word32)ptlen,
                                          ct, ct + ptlen);
    if (ctlen)
        *ctlen = ptlen + POLY1305_TAG_BYTES;
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int chacha_decrypt(uint8_t *pt, size_t *ptlen,
                          const uint8_t *ct, size_t ctlen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *nonce,
                          const uint8_t *key)
{
    if (ctlen < POLY1305_TAG_BYTES)
        return CRYPTO_ERROR;
    size_t msglen = ctlen - POLY1305_TAG_BYTES;
    int ret = wc_ChaCha20Poly1305_Decrypt(key, nonce,
                                          ad, (word32)adlen,
                                          ct, (word32)msglen,
                                          ct + msglen, pt);
    if (ptlen)
        *ptlen = msglen;
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_aead_ops_t chacha20_poly1305_ops = {
    .type        = ALG_CHACHA20_POLY1305,
    .name        = "ChaCha20-Poly1305",
    .key_bytes   = CHACHA_KEY_BYTES,
    .nonce_bytes = CHACHA_NONCE_BYTES,
    .tag_bytes   = POLY1305_TAG_BYTES,
    .init        = platform_rng_init,   /* was ensure_rng */
    .keygen      = chacha_keygen,
    .encrypt     = chacha_encrypt,
    .decrypt     = chacha_decrypt,
};