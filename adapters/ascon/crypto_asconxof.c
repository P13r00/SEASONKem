#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "core/inc/crypto_api.h"

#define ASCON_XOF_DEFAULT_OUTLEN 32u


extern int ascon_xof(uint8_t* out, uint64_t outlen, const uint8_t* in, uint64_t inlen);

static int asconxof_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;

    int rc = ascon_xof(out, (uint64_t)outlen, in, (uint64_t)inlen);
    
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_hash_ops_t asconxof_ops = {
    .type           = ALG_ASCON_XOF,
    .name           = "ASCON-XOF (accelerated) (ascon)",
    .is_xof         = true,
    .default_outlen = ASCON_XOF_DEFAULT_OUTLEN,
    .hash           = asconxof_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};