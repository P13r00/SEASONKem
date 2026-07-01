#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "core/inc/crypto_api.h"

#define ASCON_XOF_DEFAULT_OUTLEN 32u

/* * The true variable-length XOF API provided by your Ascon library 
 */
extern int ascon_xof(uint8_t* out, uint64_t outlen, const uint8_t* in, uint64_t inlen);

static int asconxof_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;

    /* * We can now pass 'outlen' directly to the backend!
     * Casting size_t to uint64_t to safely match the Ascon API signature.
     */
    int rc = ascon_xof(out, (uint64_t)outlen, in, (uint64_t)inlen);
    
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_hash_ops_t asconxof_ops = {
    .type           = ALG_ASCON_XOF,
    .name           = "ASCON-XOF (ascon)",
    .is_xof         = true,
    .default_outlen = ASCON_XOF_DEFAULT_OUTLEN,
    .hash           = asconxof_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};