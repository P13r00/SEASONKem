#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "core/inc/crypto_api.h"

#define ASCON_HASHXOF_DEFAULT_OUTLEN 32u

typedef union {
    struct {
        uint8_t state[40];
        uint8_t count;
        uint8_t mode;
    } s;
    uint64_t align;
} ascon_xof_state_t;

extern void ascon_xof_init(ascon_xof_state_t *state);
extern void ascon_xof_absorb(ascon_xof_state_t *state, const uint8_t *in, size_t inlen);
extern void ascon_xof_squeeze(ascon_xof_state_t *state, uint8_t *out, size_t outlen);

static int lwc_ascon_hashxof_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;

    __attribute__((aligned(8))) ascon_xof_state_t st;

    ascon_xof_init(&st);

    if (inlen > 0) {
        ascon_xof_absorb(&st, in, inlen);
    }

    ascon_xof_squeeze(&st, out, outlen);

    return CRYPTO_SUCCESS;
}

const crypto_hash_ops_t lwc_ascon_hashxof_ops = {
    .type           = ALG_LWC_ASCON_HASHXOF,
    .name           = "ASCON-XOF (lwc)",
    .is_xof         = true,
    .default_outlen = ASCON_HASHXOF_DEFAULT_OUTLEN,
    .hash           = lwc_ascon_hashxof_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};