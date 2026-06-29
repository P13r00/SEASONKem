#include <stdint.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

static WC_RNG s_rng;
static int s_rng_ready = 0;

static int ensure_rng(void)
{
    if (!s_rng_ready)
    {
        if (wc_InitRng(&s_rng) != 0)
            return CRYPTO_ERROR;
        s_rng_ready = 1;
    }
    return CRYPTO_SUCCESS;
}

extern int crypto_hash(unsigned char *out,
                       const unsigned char *in,
                       unsigned long long inlen);

static int asconxof_derive(uint8_t       *okm,  size_t okm_len,
                          const uint8_t *ikm,  size_t ikm_len,
                          const uint8_t *salt, size_t salt_len,
                          const uint8_t *info, size_t info_len)
{
    (void)salt; /* unused */
    (void)info; /* unused */

    if (!okm || okm_len == 0) return CRYPTO_ERROR;

    int rc = crypto_hash(okm, ikm, (unsigned long long)ikm_len);
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_kdf_ops_t asconxof_ops = {
    .type   = ALG_ASCON_XOF,
    .name   = "ASCON-XOF (ascon)",
    .derive = asconxof_derive,
};