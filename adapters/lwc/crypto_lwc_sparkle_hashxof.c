#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "core/inc/crypto_api.h"

#define ESCH_256_DEFAULT_OUTLEN 32u

/* Opaque state struct matching esch_256_hash_state_t in lwc-finalists */
typedef union {
    uint8_t state[48]; 
} esch_256_hash_state_t;

/* Externs mapped directly from the lwc-finalists sparkle-hash API */
extern void esch_256_hash_init(esch_256_hash_state_t *state);
extern void esch_256_hash_update(esch_256_hash_state_t *state, const uint8_t *in, size_t inlen);
extern void esch_256_hash_squeeze(esch_256_hash_state_t *state, uint8_t *out, size_t outlen);

static int lwc_sparkle_hashxof_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;

    esch_256_hash_state_t st;
    
    esch_256_hash_init(&st);
    
    if (inlen > 0) {
        esch_256_hash_update(&st, in, inlen);
    }
    
    /* Squeeze allows us to pull variable-length output (XOF) */
    esch_256_hash_squeeze(&st, out, outlen);
    
    return CRYPTO_SUCCESS;
}

const crypto_hash_ops_t lwc_sparkle_hashxof_ops = {
    .type           = ALG_LWC_SPARKLE_HASHXOF,
    .name           = "SPARKLE-XOF (lwc)",
    .is_xof         = true,
    .default_outlen = ESCH_256_DEFAULT_OUTLEN,
    .hash           = lwc_sparkle_hashxof_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};