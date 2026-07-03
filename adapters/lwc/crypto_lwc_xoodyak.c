#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "core/inc/crypto_api.h"

#define XOODYAK_HASH_SIZE        32u
#define XOODYAK_HASH_DEFAULT_OUTLEN XOODYAK_HASH_SIZE

typedef union {
    struct {
        uint8_t state[48];
        uint8_t count;
        uint8_t mode;
    } s;
    uint64_t align;
} xoodyak_hash_state_t;

extern void xoodyak_hash_init(xoodyak_hash_state_t *state);
extern void xoodyak_hash_absorb(xoodyak_hash_state_t *state, const uint8_t *in, size_t inlen);
extern void xoodyak_hash_finalize(xoodyak_hash_state_t *state, uint8_t *out);

static int lwc_xoodyak_hash_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (!out || (inlen > 0 && !in)) return CRYPTO_ERROR;

    if (outlen != XOODYAK_HASH_SIZE) return CRYPTO_ERROR;


    __attribute__((aligned(8))) xoodyak_hash_state_t st;

    xoodyak_hash_init(&st);
    if (inlen > 0) {
        xoodyak_hash_absorb(&st, in, inlen);
    }

    xoodyak_hash_finalize(&st, out);

    return CRYPTO_SUCCESS;
}

const crypto_hash_ops_t lwc_xoodyak_hash_ops = {
    .type           = ALG_LWC_XOODYAK_HASH,
    .name           = "XOODYAK-HASH (lwc)",
    .is_xof         = false,
    .default_outlen = XOODYAK_HASH_DEFAULT_OUTLEN,
    .hash           = lwc_xoodyak_hash_hash,
    .init           = NULL,
    .absorb         = NULL,
    .finalize       = NULL,
    .clone          = NULL,
    .release        = NULL,
};