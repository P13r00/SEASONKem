#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "core/inc/crypto_api.h"

#define ASCON_HASH256_OUTLEN 32u

extern int crypto_hash(unsigned char *out,
                       const unsigned char *in,
                       unsigned long long inlen);

static int asconhash256_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;
    
    if (outlen != ASCON_HASH256_OUTLEN) return CRYPTO_ERROR;

    int rc = crypto_hash(out, in, (unsigned long long)inlen);
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_hash_ops_t asconhash256_ops = {
    .type           = ALG_ASCON_HASH256,
    .name           = "Ascon-Hash-256",
    .is_xof         = false,
    .default_outlen = ASCON_HASH256_OUTLEN,
    .hash           = asconhash256_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};