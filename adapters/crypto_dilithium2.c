/* crypto_dilithium2.c — ML-DSA-44 (Dilithium2) adapter via pqm4/m4f.
 *
 * All staging buffers are static — crypto_sign_ctx and crypto_sign_open_ctx
 * each need ~50 KB of stack internally for NTT/polynomial temporaries.
 * Every byte saved in local variables matters on a 128 KB device.
 *
 * RNG is provided by adapters/pqm4_randombytes.c — do NOT define it here.
 */

#include <stdint.h>
#include <stddef.h>
#include "api.h"
#include "core/inc/crypto_api.h"

#define MLDSA44_SIG_BYTES  2420
#define MLDSA44_MSG_MAX    256

/* All large buffers in BSS — none on the call stack */
static uint8_t s_sm[MLDSA44_SIG_BYTES + MLDSA44_MSG_MAX]; /* sign: sm=sig||msg output  */
                                                            /* verify: sm=sig||msg input */
static uint8_t s_m[MLDSA44_MSG_MAX];                       /* verify: recovered msg     */

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