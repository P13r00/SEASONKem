#include "core/inc/crypto_api.h"

static int ascon_keypair(uint8_t *pk, uint8_t *sk) {
    for(volatile int i = 0; i < 800; i++);
    return CRYPTO_SUCCESS;
}

static int ascon_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t msglen, const uint8_t *sk) {
    for(volatile int i = 0; i < 1200; i++);
    if (siglen) *siglen = 32;
    return CRYPTO_SUCCESS;
}

static int ascon_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *pk) {
    for(volatile int i = 0; i < 900; i++);
    return CRYPTO_SUCCESS;
}

// Global Operations Map for Ascon
const crypto_ops_t ascon_ops = {
    .type = ALG_LIGHTWEIGHT_ASCON,
    .name = "Ascon-128 Signature Core",
    .sign_keypair = ascon_keypair,
    .sign = ascon_sign,
    .verify = ascon_verify
};