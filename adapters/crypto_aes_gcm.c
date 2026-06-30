#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

#define AES_GCM_KEY_BYTES   16u
#define AES_GCM_NONCE_BYTES 12u
#define AES_GCM_TAG_BYTES   16u

static int aes_gcm_keygen(uint8_t *key, uint8_t *nonce) {
    if (wc_RNG_GenerateBlock(&s_rng, key,   AES_GCM_KEY_BYTES)   != 0) return CRYPTO_ERROR;
    if (wc_RNG_GenerateBlock(&s_rng, nonce, AES_GCM_NONCE_BYTES) != 0) return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}

static int aes_gcm_encrypt(uint8_t *ct,       size_t *ctlen,
                            const uint8_t *pt, size_t  ptlen,
                            const uint8_t *ad, size_t  adlen,
                            const uint8_t *nonce,
                            const uint8_t *key) {
    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return CRYPTO_ERROR;
    if (wc_AesGcmSetKey(&aes, key, AES_GCM_KEY_BYTES) != 0) {
        wc_AesFree(&aes); return CRYPTO_ERROR;
    }
    int ret = wc_AesGcmEncrypt(&aes,
                                ct, pt, (word32)ptlen,
                                nonce, AES_GCM_NONCE_BYTES,
                                ct + ptlen, AES_GCM_TAG_BYTES,
                                ad, (word32)adlen);
    if (ctlen) *ctlen = ptlen + AES_GCM_TAG_BYTES;
    wc_AesFree(&aes);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int aes_gcm_decrypt(uint8_t *pt,        size_t *ptlen,
                            const uint8_t *ct,  size_t  ctlen,
                            const uint8_t *ad,  size_t  adlen,
                            const uint8_t *nonce,
                            const uint8_t *key) {
    if (ctlen < AES_GCM_TAG_BYTES) return CRYPTO_ERROR;
    size_t msglen = ctlen - AES_GCM_TAG_BYTES;
    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return CRYPTO_ERROR;
    if (wc_AesGcmSetKey(&aes, key, AES_GCM_KEY_BYTES) != 0) {
        wc_AesFree(&aes); return CRYPTO_ERROR;
    }
    int ret = wc_AesGcmDecrypt(&aes,
                                pt, ct, (word32)msglen,
                                nonce, AES_GCM_NONCE_BYTES,
                                ct + msglen, AES_GCM_TAG_BYTES,
                                ad, (word32)adlen);
    if (ptlen) *ptlen = msglen;
    wc_AesFree(&aes);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_aead_ops_t aes_gcm_ops = {
    .type        = ALG_AES_GCM,
    .name        = "AES-128-GCM (wolfcrypt)",
    .key_bytes   = AES_GCM_KEY_BYTES,
    .nonce_bytes = AES_GCM_NONCE_BYTES,
    .tag_bytes   = AES_GCM_TAG_BYTES,
    .init        = ensure_rng,
    .keygen      = aes_gcm_keygen,
    .encrypt     = aes_gcm_encrypt,
    .decrypt     = aes_gcm_decrypt,
};