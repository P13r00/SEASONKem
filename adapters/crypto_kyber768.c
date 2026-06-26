/* crypto_kyber.c — ML-KEM-768 adapter via pqm4/m4fspeed.
 *
 * randombytes() is defined here using wolfcrypt's WC_RNG (same engine as
 * crypto_ed25519.c).  It is marked weak so the linker discards the duplicate
 * silently when crypto_dilithium2.c is also compiled — both definitions are
 * identical so it does not matter which one is kept.
 */

#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

/* pqm4 NIST KEM API */
extern int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static WC_RNG s_rng;
static int    s_rng_ready = 0;

static void ensure_rng(void) {
    if (!s_rng_ready) {
        (void)wc_InitRng(&s_rng);
        s_rng_ready = 1;
    }
}


void PQCLEAN_randombytes(uint8_t *buf, size_t len) {
    ensure_rng();
    (void)wc_RNG_GenerateBlock(&s_rng, buf, (word32)len);
}


/* pqm4 RNG hook — called internally by the ML-KEM-512 library.
 * Weak so the linker drops the duplicate when Dilithium is also active. */
__attribute__((weak)) void randombytes(uint8_t *buf, size_t len) {
    ensure_rng();
    (void)wc_RNG_GenerateBlock(&s_rng, buf, (word32)len);
}

static int kyber768_keypair(uint8_t *pk, uint8_t *sk) {
    return crypto_kem_keypair(pk, sk) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int kyber768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return crypto_kem_enc(ct, ss, pk) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int kyber768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return crypto_kem_dec(ss, ct, sk) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_kem_ops_t kyber768_ops = {
    .type    = ALG_KYBER768,
    .name    = "ML-KEM-768 (pqm4/m4fspeed)",
    .keygen  = kyber768_keypair,
    .encaps  = kyber768_encaps,
    .decaps  = kyber768_decaps,
};