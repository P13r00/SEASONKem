
#include <stdint.h>
#include <stddef.h>
#include "randombytes.h"
#include "core/inc/crypto_api.h"

int platform_rng_init(void)
{
    return CRYPTO_SUCCESS;
}

int platform_rng_generate(uint8_t *buf, size_t len)
{
    return (PQCLEAN_randombytes(buf, len) == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}
