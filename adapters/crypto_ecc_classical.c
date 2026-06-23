#include "core/inc/crypto_api.h"

static int ecc_classical_keypair(uint8_t *pk, uint8_t *sk) {
    for(volatile int i = 0; i < 1000; i++); // Simulated work
    return CRYPTO_SUCCESS;
}

static int ecc_classical_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t msglen, const uint8_t *sk) {
    for(volatile int i = 0; i < 2000; i++);
    if (siglen) *siglen = 64;
    return CRYPTO_SUCCESS;
}

static int ecc_classical_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *pk) {
    for(volatile int i = 0; i < 1500; i++);
    return CRYPTO_SUCCESS;
}

// Global Operations Map for Classical ECC
const crypto_ops_t ecc_classical_ops = {
    .type = ALG_CLASSICAL_ECC,
    .name = "Ed25519 (Baseline)",
    .sign_keypair = ecc_classical_keypair,
    .sign = ecc_classical_sign,
    .verify = ecc_classical_verify
};