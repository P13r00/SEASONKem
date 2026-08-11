#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "core/inc/crypto_api.h"

#define ESCH_384_DEFAULT_OUTLEN 48u

typedef union {
    struct {
        uint8_t state[64];
        uint8_t block[16];
        uint8_t count;
        uint8_t mode;
    } s;
    uint64_t align;
} esch_384_hash_state_t;

extern void esch_384_hash_init(esch_384_hash_state_t *state);
extern void esch_384_hash_update(esch_384_hash_state_t *state, const uint8_t *in, size_t inlen);
extern void esch_384_hash_squeeze(esch_384_hash_state_t *state, uint8_t *out, size_t outlen);

static int lwc_sparkle_hashxof384_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;

    __attribute__((aligned(8))) esch_384_hash_state_t st;

    esch_384_hash_init(&st);

    if (inlen > 0) {
        esch_384_hash_update(&st, in, inlen);
    }

    esch_384_hash_squeeze(&st, out, outlen);

    return CRYPTO_SUCCESS;
}

const crypto_hash_ops_t lwc_sparkle_hashxof384_ops = {
    .type           = ALG_LWC_SPARKLE_HASHXOF384,
    .name           = "SPARKLE-XOF384 (lwc)",
    .is_xof         = true,
    .default_outlen = ESCH_384_DEFAULT_OUTLEN,
    .hash           = lwc_sparkle_hashxof384_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};