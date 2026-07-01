#include <stdint.h>
#include <stddef.h>
#include "core/inc/crypto_api.h"


/* One-shot execution wrapper */
static int pqm4_sha3_256_hash(uint8_t *output, const uint8_t *input, size_t inlen)
{
    if (!output || (inlen > 0 && !input)) return CRYPTO_ERROR;
    
    sha3_256(output, input, inlen);
    return CRYPTO_SUCCESS;
}

/* Incremental: Initialize context */
static int pqm4_sha3_256_init(sha3_256incctx *state)
{
    if (!state) return CRYPTO_ERROR;
    
    sha3_256_inc_init(state);
    return CRYPTO_SUCCESS;
}

/* Incremental: Absorb a chunk of data */
static int pqm4_sha3_256_absorb(sha3_256incctx *state, const uint8_t *input, size_t inlen)
{
    if (!state || (inlen > 0 && !input)) return CRYPTO_ERROR;
    
    sha3_256_inc_absorb(state, input, inlen);
    return CRYPTO_SUCCESS;
}

/* Incremental: Finalize and squeeze output (frees state automatically) */
static int pqm4_sha3_256_finalize(uint8_t *output, sha3_256incctx *state)
{
    if (!output || !state) return CRYPTO_ERROR;
    
    sha3_256_inc_finalize(output, state);
    return CRYPTO_SUCCESS;
}

/* Incremental: Clone current context state */
static int pqm4_sha3_256_clone(sha3_256incctx *dest, const sha3_256incctx *src)
{
    if (!dest || !src) return CRYPTO_ERROR;
    
    sha3_256_inc_ctx_clone(dest, src);
    return CRYPTO_SUCCESS;
}

/* Incremental: Safe release (only needed if finalize wasn't called) */
static int pqm4_sha3_256_release(sha3_256incctx *state)
{
    if (!state) return CRYPTO_ERROR;
    
    sha3_256_inc_ctx_release(state);
    return CRYPTO_SUCCESS;
}

/* * Adapter Operations Structure 
 * (You can map these fields to your exact crypto_api.h definitions later)
 */
const crypto_hash_ops_t pqm4_sha3_256_ops = {
    .type     = ALG_PQM4_SHA3_256,
    .name     = "SHA3-256 (pqm4/mupq)",
    .hash     = pqm4_sha3_256_hash,
    .init     = pqm4_sha3_256_init,
    .absorb   = pqm4_sha3_256_absorb,
    .finalize = pqm4_sha3_256_finalize,
    .clone    = pqm4_sha3_256_clone,
    .release  = pqm4_sha3_256_release,
};