/* crypto_dilithium2.c — ML-DSA-44 (Dilithium2) adapter via pqm4/m4f.
 *
 * All staging buffers are static — crypto_sign_ctx and crypto_sign_open_ctx
 * each need ~50 KB of stack internally for NTT/polynomial temporaries.
 * Every byte saved in local variables matters on a 128 KB device.
 *
 * randombytes() is defined here using wolfcrypt's WC_RNG (same engine as
 * crypto_ed25519.c).  It is marked weak so the linker discards the duplicate
 * silently when crypto_kyber.c is also compiled — both definitions are
 * identical so it does not matter which one is kept.
 */

#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/random.h>
#include "api.h"
#include "core/inc/crypto_api.h"

#define MLDSA44_SIG_BYTES  2420
#define MLDSA44_MSG_MAX    256

/* All large buffers in BSS — none on the call stack */
static uint8_t s_sm[MLDSA44_SIG_BYTES + MLDSA44_MSG_MAX]; /* sign: sm=sig||msg output  */
                                                            /* verify: sm=sig||msg input */
static uint8_t s_m[MLDSA44_MSG_MAX];                       /* verify: recovered msg     */

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

/* pqm4 RNG hook — called internally by the ML-DSA-44 library.
 * Weak so the linker drops the duplicate when Kyber is also active. */
__attribute__((weak)) void randombytes(uint8_t *buf, size_t len) {
    ensure_rng();
    (void)wc_RNG_GenerateBlock(&s_rng, buf, (word32)len);
}

static int dilithium2_keypair(uint8_t *pk, uint8_t *sk) {
    return crypto_sign_keypair(pk, sk) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int dilithium2_sign(uint8_t *sig, size_t *siglen,
                           const uint8_t *msg, size_t msglen,
                           const uint8_t *sk) {
    size_t smlen = 0;
    if (msglen > MLDSA44_MSG_MAX) return CRYPTO_ERROR;
    if (crypto_sign(s_sm, &smlen, msg, msglen, sk) != 0) return CRYPTO_ERROR;
    *siglen = smlen - msglen;
    for (size_t i = 0; i < *siglen; i++) sig[i] = s_sm[i];
    return CRYPTO_SUCCESS;
}

static int dilithium2_verify(const uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *pk) {
    size_t mlen = 0;
    if (msglen > MLDSA44_MSG_MAX) return CRYPTO_ERROR;
    /* Reconstruct sm = sig || msg in the static buffer */
    for (size_t i = 0; i < siglen; i++) s_sm[i]          = sig[i];
    for (size_t i = 0; i < msglen; i++) s_sm[siglen + i]  = msg[i];
    return crypto_sign_open(s_m, &mlen, s_sm, siglen + msglen, pk) == 0
               ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_ops_t dilithium2_ops = {
    .type         = ALG_DILITHIUM2,
    .name         = "ML-DSA-44 (pqm4/m4f)",
    .sign_keypair = dilithium2_keypair,
    .sign         = dilithium2_sign,
    .verify       = dilithium2_verify,
};