#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "core/inc/crypto_api.h"
#include "fips202.h"


#define SHA3_256_OUTLEN 32u

/* One-shot execution wrapper */
static int pqm4_sha3_256_hash(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen)
{
    if (!output || (inlen > 0 && !input)) return CRYPTO_ERROR;
    
    /* Strict check: SHA3-256 only outputs 32 bytes */
    if (outlen != SHA3_256_OUTLEN) return CRYPTO_ERROR;
    
    sha3_256(output, input, inlen);
    return CRYPTO_SUCCESS;
}

/* Incremental: Initialize context */
static int pqm4_sha3_256_init(void *ctx)
{
    if (!ctx) return CRYPTO_ERROR;
    
    sha3_256_inc_init((sha3_256incctx *)ctx);
    return CRYPTO_SUCCESS;
}

/* Incremental: Absorb a chunk of data */
static int pqm4_sha3_256_absorb(void *ctx, const uint8_t *input, size_t inlen)
{
    if (!ctx || (inlen > 0 && !input)) return CRYPTO_ERROR;
    
    sha3_256_inc_absorb((sha3_256incctx *)ctx, input, inlen);
    return CRYPTO_SUCCESS;
}

/* Incremental: Finalize and squeeze output (frees state automatically) */
static int pqm4_sha3_256_finalize(uint8_t *output, size_t outlen, void *ctx)
{
    if (!output || !ctx) return CRYPTO_ERROR;
    
    /* Strict check: SHA3-256 only outputs 32 bytes */
    if (outlen != SHA3_256_OUTLEN) return CRYPTO_ERROR;
    
    sha3_256_inc_finalize(output, (sha3_256incctx *)ctx);
    return CRYPTO_SUCCESS;
}

/* Incremental: Clone current context state */
static int pqm4_sha3_256_clone(void *dst, const void *src)
{
    if (!dst || !src) return CRYPTO_ERROR;
    
    sha3_256_inc_ctx_clone((sha3_256incctx *)dst, (const sha3_256incctx *)src);
    return CRYPTO_SUCCESS;
}

/* Incremental: Safe release (only needed if finalize wasn't called) */
static int pqm4_sha3_256_release(void *ctx)
{
    if (!ctx) return CRYPTO_ERROR;
    
    sha3_256_inc_ctx_release((sha3_256incctx *)ctx);
    return CRYPTO_SUCCESS;
}

/* * Adapter Operations Structure */
const crypto_hash_ops_t pqm4_sha3_256_ops = {
    .type           = ALG_PQM4_SHA3_256,
    .name           = "SHA3-256 (pqm4/mupq)",
    .is_xof         = false,
    .default_outlen = SHA3_256_OUTLEN,
    .hash           = pqm4_sha3_256_hash,
    .init           = pqm4_sha3_256_init,
    .absorb         = pqm4_sha3_256_absorb,
    .finalize       = pqm4_sha3_256_finalize,
    .clone          = pqm4_sha3_256_clone,
    .release        = pqm4_sha3_256_release,
};