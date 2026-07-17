#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "core/inc/crypto_api.h"

#define ASCON_HASH256_OUTLEN 32u

typedef union {
    struct {
        uint8_t state[40];
        uint8_t count;
        uint8_t mode;
    } s;
    uint64_t align;
} ascon_hash256_state_t;
 
extern void ascon_hash_init(ascon_hash256_state_t *state);
extern void ascon_hash_update(ascon_hash256_state_t *state, const uint8_t *in, size_t inlen);
extern void ascon_hash_finalize(ascon_hash256_state_t *state, uint8_t *out);


static int lwc_ascon_hash256_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;
    if (outlen != ASCON_HASH256_OUTLEN) return CRYPTO_ERROR;

    __attribute__((aligned(8))) ascon_hash256_state_t st;

    ascon_hash_init(&st);

    if (inlen > 0) {
        ascon_hash_update(&st, in, inlen);
    }
#define ASCON_HASH256_OUTLEN 32u
    ascon_hash_finalize(&st, out);

    return CRYPTO_SUCCESS;
}

const crypto_hash_ops_t lwc_ascon_hash256_ops = {
    .type           = ALG_LWC_ASCON_HASH256,
    .name           = "ASCON-Hash256 (lwc)",
    .is_xof         = false,
    .default_outlen = ASCON_HASH256_OUTLEN,
    .hash           = lwc_ascon_hash256_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};