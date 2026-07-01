#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "core/inc/crypto_api.h"
#include "fips202.h"


#ifndef SHAKE256_OUTLEN
#define SHAKE256_OUTLEN 32u
#endif

/* One-shot execution wrapper */
static int pqm4_shake256_hash(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen)
{
    if (!output || (inlen > 0 && !input)) return CRYPTO_ERROR;
    
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, input, inlen);
    
    /* Prepare for squeeze phase */
    shake256_inc_finalize(&state);
    
    /* Squeeze out dynamically requested bytes */
    shake256_inc_squeeze(output, outlen, &state);
    
    /* Free the context */
    shake256_inc_ctx_release(&state);
    
    return CRYPTO_SUCCESS;
}

/* Incremental: Initialize context */
static int pqm4_shake256_init(void *ctx)
{
    if (!ctx) return CRYPTO_ERROR;
    
    shake256_inc_init((shake256incctx *)ctx);
    return CRYPTO_SUCCESS;
}

/* Incremental: Absorb a chunk of data */
static int pqm4_shake256_absorb(void *ctx, const uint8_t *input, size_t inlen)
{
    if (!ctx || (inlen > 0 && !input)) return CRYPTO_ERROR;
    
    shake256_inc_absorb((shake256incctx *)ctx, input, inlen);
    return CRYPTO_SUCCESS;
}

/* Incremental: Finalize and squeeze output (frees state automatically) */
static int pqm4_shake256_finalize(uint8_t *output, size_t outlen, void *ctx)
{
    if (!output || !ctx) return CRYPTO_ERROR;
    
    shake256incctx *state = (shake256incctx *)ctx;
    
    /* Transition from absorb to squeeze phase */
    shake256_inc_finalize(state);
    
    /* Squeeze dynamically requested output */
    shake256_inc_squeeze(output, outlen, state);
    
    /* Free context */
    shake256_inc_ctx_release(state);
    
    return CRYPTO_SUCCESS;
}

/* Incremental: Clone current context state */
static int pqm4_shake256_clone(void *dst, const void *src)
{
    if (!dst || !src) return CRYPTO_ERROR;
    
    shake256_inc_ctx_clone((shake256incctx *)dst, (const shake256incctx *)src);
    return CRYPTO_SUCCESS;
}

/* Incremental: Safe release (only needed if finalize wasn't called) */
static int pqm4_shake256_release(void *ctx)
{
    if (!ctx) return CRYPTO_ERROR;
    
    shake256_inc_ctx_release((shake256incctx *)ctx);
    return CRYPTO_SUCCESS;
}

/* * Adapter Operations Structure */
const crypto_hash_ops_t pqm4_shake256_ops = {
    .type           = ALG_PQM4_SHAKE256,
    .name           = "SHAKE256 (pqm4/mupq)",
    .is_xof         = true,
    .default_outlen = SHAKE256_OUTLEN,
    .hash           = pqm4_shake256_hash,
    .init           = pqm4_shake256_init,
    .absorb         = pqm4_shake256_absorb,
    .finalize       = pqm4_shake256_finalize,
    .clone          = pqm4_shake256_clone,
    .release        = pqm4_shake256_release,
};