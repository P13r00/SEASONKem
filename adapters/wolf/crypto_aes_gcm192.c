#include <wolfssl/wolfcrypt/aes.h>
#include "core/inc/crypto_api.h"

#define AES_GCM192_KEY_BYTES   24u
#define AES_GCM192_NONCE_BYTES 12u
#define AES_GCM192_TAG_BYTES   16u

static int aes_gcm192_keygen(uint8_t *key, uint8_t *nonce)
{
    if (platform_rng_generate(key,   AES_GCM192_KEY_BYTES)   != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    if (platform_rng_generate(nonce, AES_GCM192_NONCE_BYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}

static int aes_gcm192_encrypt(uint8_t *ct, size_t *ctlen,
                             const uint8_t *pt, size_t ptlen,
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *nonce,
                             const uint8_t *key)
{
    Aes aes;
    int ret;
    
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return CRYPTO_ERROR;

    ret = wc_AesGcmSetKey(&aes, key, AES_GCM192_KEY_BYTES);
    if (ret != 0) {
        wc_AesFree(&aes);
        return CRYPTO_ERROR;
    }

    ret = wc_AesGcmEncrypt(&aes, ct, pt, (word32)ptlen,
                           nonce, AES_GCM192_NONCE_BYTES,
                           ct + ptlen, AES_GCM192_TAG_BYTES,
                           ad, (word32)adlen);

    wc_AesFree(&aes);

    if (ctlen)
        *ctlen = ptlen + AES_GCM192_TAG_BYTES;
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int aes_gcm192_decrypt(uint8_t *pt, size_t *ptlen,
                             const uint8_t *ct, size_t ctlen,
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *nonce,
                             const uint8_t *key)
{
    Aes aes;
    int ret;

    if (ctlen < AES_GCM192_TAG_BYTES)
        return CRYPTO_ERROR;
    size_t msglen = ctlen - AES_GCM192_TAG_BYTES;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return CRYPTO_ERROR;

    ret = wc_AesGcmSetKey(&aes, key, AES_GCM192_KEY_BYTES);
    if (ret != 0) {
        wc_AesFree(&aes);
        return CRYPTO_ERROR;
    }

    ret = wc_AesGcmDecrypt(&aes, pt, ct, (word32)msglen,
                           nonce, AES_GCM192_NONCE_BYTES,
                           ct + msglen, AES_GCM192_TAG_BYTES,
                           ad, (word32)adlen);

    wc_AesFree(&aes);

    if (ptlen)
        *ptlen = msglen;
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_aead_ops_t aes_gcm192_ops = {
    .type        = ALG_AES_GCM192,
    .name        = "AES-192-GCM",
    .key_bytes   = AES_GCM192_KEY_BYTES,
    .nonce_bytes = AES_GCM192_NONCE_BYTES,
    .tag_bytes   = AES_GCM192_TAG_BYTES,
    .init        = platform_rng_init,
    .keygen      = aes_gcm192_keygen,
    .encrypt     = aes_gcm192_encrypt,
    .decrypt     = aes_gcm192_decrypt,
};