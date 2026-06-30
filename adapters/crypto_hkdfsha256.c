#include <wolfssl/wolfcrypt/hmac.h>
#include "core/inc/crypto_api.h"

static int hkdf_sha256_derive(uint8_t       *okm,  size_t okm_len,
                        const uint8_t *ikm,  size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len) 
{
    if (!okm || okm_len == 0) return CRYPTO_ERROR;

    int ret = wc_HKDF(WC_SHA256,
                       ikm,  (word32)ikm_len,
                       salt, (word32)salt_len,
                       info, (word32)info_len,
                       okm,  (word32)okm_len);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_kdf_ops_t hkdf_sha256_ops = {
    .type   = ALG_HKDF_SHA256,
    .name   = "HKDF-SHA-256 (wolfcrypt)",
    .derive = hkdf_sha256_derive,
};