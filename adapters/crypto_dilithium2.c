
#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/random.h> /* Added for WC_RNG */
#include "core/inc/crypto_api.h"

extern int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_sign(uint8_t *sm, size_t *smlen, 
                const uint8_t *msg, size_t len,
                const uint8_t *sk);
extern int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

/* ------------------------------------------------------------------ */
/* Randomness Provider for PQM4                                       */
/* ------------------------------------------------------------------ */
static WC_RNG s_dilithium2_rng;
static int    s_dilithium2_rng_ready = 0;

/* This function is externally called by pqm4's kem.c */
int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    /* 1. Initialize the RNG on the first call */
    if (!s_dilithium2_rng_ready) {
        if (wc_InitRng(&s_dilithium2_rng) != 0) {
            return -1; /* Failed to initialize */
        }
        s_dilithium2_rng_ready = 1;
    }

    /* 2. Generate the requested amount of random bytes */
    if (wc_RNG_GenerateBlock(&s_dilithium2_rng, out, (word32)outlen) != 0) {
        return -1; /* Failed to generate randomness */
    }

    return 0; /* Success */
}

static int dilithium2_keypair(uint8_t *pk, uint8_t *sk) {
    int ret = crypto_sign_keypair(pk, sk);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int dilithium2_sign(uint8_t *sig, size_t *siglen,
                           const uint8_t *msg, size_t msglen,
                           const uint8_t *sk) {
    int ret = crypto_sign(sig, siglen, msg, msglen, sk);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int dilithium2_verify(const uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *pk) {
    int ret = crypto_sign_open(NULL, NULL, sig, siglen, pk);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_ops_t dilithium2_ops = {
    .type         = ALG_DILITHIUM2,
    .name         = "Dilithium2 (pqm4)",
    .sign_keypair = dilithium2_keypair,
    .sign         = dilithium2_sign,
    .verify       = dilithium2_verify,
};