/* crypto_hkdf.c — HKDF-SHA-256 via wolfcrypt (RFC 5869) */

#include <wolfssl/wolfcrypt/hmac.h>      /* wc_HKDF */
#include "core/inc/crypto_api.h"

/* wc_HKDF signature:
 *   int wc_HKDF(int type,
 *               const byte* inKey,  word32 inKeySz,
 *               const byte* salt,   word32 saltSz,
 *               const byte* info,   word32 infoSz,
 *               byte*       out,    word32 outSz);
 *
 * type = WC_SHA256 (defined in wolfssl/wolfcrypt/hash.h, included by hmac.h)
 * Single call covers both extract and expand phases.
 * salt == NULL is permitted; wolfSSL uses a zero vector of HashLen bytes.  */

static int hkdf_derive(uint8_t       *okm,  size_t okm_len,
                        const uint8_t *ikm,  size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len) {
    if (!okm || okm_len == 0) return CRYPTO_ERROR;

    int ret = wc_HKDF(WC_SHA256,
                       ikm,  (word32)ikm_len,
                       salt, (word32)salt_len,
                       info, (word32)info_len,
                       okm,  (word32)okm_len);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_kdf_ops_t hkdf_ops = {
    .type   = ALG_HKDF,
    .name   = "HKDF-SHA-256 (wolfcrypt)",
    .derive = hkdf_derive,
};