/* crypto_kyber.c — ML-KEM-512 via pqm4 */

#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/random.h> /* Added for WC_RNG */
#include "core/inc/crypto_api.h"

/* ------------------------------------------------------------------ */
/* NIST Post-Quantum Cryptography API Prototypes                      */
/* ------------------------------------------------------------------ */
extern int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* ------------------------------------------------------------------ */
/* Randomness Provider for PQM4                                       */
/* ------------------------------------------------------------------ */
static WC_RNG s_kyber_rng;
static int    s_kyber_rng_ready = 0;

/* This function is externally called by pqm4's kem.c */
int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    /* 1. Initialize the RNG on the first call */
    if (!s_kyber_rng_ready) {
        if (wc_InitRng(&s_kyber_rng) != 0) {
            return -1; /* Failed to initialize */
        }
        s_kyber_rng_ready = 1;
    }

    /* 2. Generate the requested amount of random bytes */
    if (wc_RNG_GenerateBlock(&s_kyber_rng, out, (word32)outlen) != 0) {
        return -1; /* Failed to generate randomness */
    }

    return 0; /* Success */
}

/* ------------------------------------------------------------------ */
/* Adapter Wrapper Functions                                          */
/* ------------------------------------------------------------------ */

static int kyber512_keypair(uint8_t *pk, uint8_t *sk) {
    int ret = crypto_kem_keypair(pk, sk);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
    
}
static int kyber512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    int ret = crypto_kem_enc(ct, ss, pk);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int kyber512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    int ret = crypto_kem_dec(ss, ct, sk);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

/* ------------------------------------------------------------------ */
/* KEM Operations Registry Definition                                 */
/* ------------------------------------------------------------------ */
const crypto_kem_ops_t kyber512_ops = {
    .type    = ALG_KYBER512,
    .name    = "Kyber-512 (pqm4)",
    .keygen  = kyber512_keypair,
    .encaps  = kyber512_encaps,
    .decaps  = kyber512_decaps,
};