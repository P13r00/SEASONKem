#include <stdint.h>
#include <stddef.h>
#include "core/inc/crypto_api.h"

/* * Define a default output length. 
 * Standard hash APIs often lack an outlen parameter, 
 * so we define it here for the XOF squeeze phase.
 */
#ifndef SHAKE256_OUTLEN
#define SHAKE256_OUTLEN 32
#endif

/* One-shot execution wrapper */
static int pqm4_shake256_hash(uint8_t *output, const uint8_t *input, size_t inlen)
{
    if (!output || (inlen > 0 && !input)) return CRYPTO_ERROR;
    
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, input, inlen);
    
    /* Prepare for squeeze phase */
    shake256_inc_finalize(&state);
    
    /* Squeeze out the required bytes */
    shake256_inc_squeeze(output, SHAKE256_OUTLEN, &state);
    
    /* Free the context */
    shake256_inc_ctx_release(&state);
    
    return CRYPTO_SUCCESS;
}

/* Incremental: Initialize context */
static int pqm4_shake256_init(shake256incctx *state)
{
    if (!state) return CRYPTO_ERROR;
    
    shake256_inc_init(state);
    return CRYPTO_SUCCESS;
}

/* Incremental: Absorb a chunk of data */
static int pqm4_shake256_absorb(shake256incctx *state, const uint8_t *input, size_t inlen)
{
    if (!state || (inlen > 0 && !input)) return CRYPTO_ERROR;
    
    shake256_inc_absorb(state, input, inlen);
    return CRYPTO_SUCCESS;
}

/* Incremental: Finalize and squeeze output (frees state automatically) */
static int pqm4_shake256_finalize(uint8_t *output, shake256incctx *state)
{
    if (!output || !state) return CRYPTO_ERROR;
    
    /* Transition from absorb to squeeze phase */
    shake256_inc_finalize(state);
    
    /* Squeeze output */
    shake256_inc_squeeze(output, SHAKE256_OUTLEN, state);
    
    /* Free context */
    shake256_inc_ctx_release(state);
    
    return CRYPTO_SUCCESS;
}

/* Incremental: Clone current context state */
static int pqm4_shake256_clone(shake256incctx *dest, const shake256incctx *src)
{
    if (!dest || !src) return CRYPTO_ERROR;
    
    shake256_inc_ctx_clone(dest, src);
    return CRYPTO_SUCCESS;
}

/* Incremental: Safe release (only needed if finalize wasn't called) */
static int pqm4_shake256_release(shake256incctx *state)
{
    if (!state) return CRYPTO_ERROR;
    
    shake256_inc_ctx_release(state);
    return CRYPTO_SUCCESS;
}

/* * Adapter Operations Structure 
 */
const crypto_hash_ops_t pqm4_shake256_ops = {
    .type     = ALG_PQM4_SHAKE256,
    .name     = "SHAKE256 (pqm4/mupq)",
    .hash     = pqm4_shake256_hash,
    .init     = pqm4_shake256_init,
    .absorb   = pqm4_shake256_absorb,
    .finalize = pqm4_shake256_finalize,
    .clone    = pqm4_shake256_clone,
    .release  = pqm4_shake256_release,
};