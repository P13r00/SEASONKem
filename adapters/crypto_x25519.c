
#include <stdint.h>
#include <stddef.h>

#include "x25519-cortex-m4.h"
#include "core/inc/crypto_api.h"

#define X25519_PRIV_SIZE  32u   /* raw RFC 7748 scalar, no padding/struct */
#define X25519_PUB_SIZE   32u
#define X25519_SS_SIZE    32u


static int x25519_keygen(uint8_t *pk, uint8_t *sk)
{
    if (platform_rng_generate(sk, X25519_PRIV_SIZE) != CRYPTO_SUCCESS) {
        return CRYPTO_ERROR;
    }

    X25519_calc_public_key(pk, sk);

    return CRYPTO_SUCCESS;
}

static int x25519_shared_secret(uint8_t *ss, const uint8_t *peer_pk, const uint8_t *sk)
{
    X25519_calc_shared_secret(ss, sk, peer_pk);
    return CRYPTO_SUCCESS;
}

const crypto_kex_ops_t x25519_ops = {
    .type          = ALG_X25519,
    .name          = "X25519 (Cortex-M4 asm)",
    .keygen        = x25519_keygen,
    .shared_secret = x25519_shared_secret,
};