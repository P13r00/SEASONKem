#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

static WC_RNG s_rng;
static int    s_rng_ready = 0;

int platform_rng_init(void)
{
    if (!s_rng_ready) {
        if (wc_InitRng(&s_rng) != 0)
            return CRYPTO_ERROR;
        s_rng_ready = 1;
    }
    return CRYPTO_SUCCESS;
}

int platform_rng_generate(uint8_t *buf, size_t len)
{
    if (platform_rng_init() != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    return wc_RNG_GenerateBlock(&s_rng, buf, (word32)len) == 0
               ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

void randombytes(uint8_t *buf, size_t len)
{
    platform_rng_generate(buf, len);
}

void PQCLEAN_randombytes(uint8_t *buf, size_t len)
{
    platform_rng_generate(buf, len);
}