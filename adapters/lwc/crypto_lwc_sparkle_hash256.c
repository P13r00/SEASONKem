#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "core/inc/crypto_api.h"

#define ESCH_256_HASH_OUTLEN 32u

typedef union {
    struct {
        uint8_t state[48];
        uint8_t block[16];  
        uint8_t count;
        uint8_t mode;
    } s;
    uint64_t align;
} esch_256_hash_state_t;

extern void esch_256_hash_init(esch_256_hash_state_t *state);
extern void esch_256_hash_update(esch_256_hash_state_t *state, const uint8_t *in, size_t inlen);
extern void esch_256_hash_squeeze(esch_256_hash_state_t *state, uint8_t *out, size_t outlen);

static int lwc_sparkle_hash256_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;

    /* ESCH-256 is a fixed-digest member of the SPARKLE family: the caller
     * must request exactly the native 32-byte output. Variable-length
     * output is only supported by the XOF variant (lwc_sparkle_hashxof). */
    if (outlen != ESCH_256_HASH_OUTLEN) return CRYPTO_ERROR;

    __attribute__((aligned(8))) esch_256_hash_state_t st;

    esch_256_hash_init(&st);

    if (inlen > 0) {
        esch_256_hash_update(&st, in, inlen);
    }

    esch_256_hash_squeeze(&st, out, outlen);

    return CRYPTO_SUCCESS;
}

const crypto_hash_ops_t lwc_sparkle_hash256_ops = {
    .type           = ALG_LWC_SPARKLE_HASH256,
    .name           = "SPARKLE-ESCH256 (lwc)",
    .is_xof         = false,
    .default_outlen = ESCH_256_HASH_OUTLEN,
    .hash           = lwc_sparkle_hash256_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};