/* crypto_falcon512.c — FN-DSA-512 (provisional Falcon) adapter via pqm4/m4f.
 *
 * api.h provides the combined sign API only (no detached variant).
 * Same split/reconstruct pattern as dilithium2.
 *
 * FN-DSA-512 sizes: pk=897 B, sk=1281 B, sig=666 B.
 *
 * sysrng() is defined here using wolfcrypt's WC_RNG (same engine as
 * crypto_ed25519.c).  The bundled pqm4 sysrng.c is excluded from the build
 * by the CMakeLists filter.  No weak attribute needed — only Falcon calls
 * sysrng() so there is no risk of a duplicate symbol.
 *
 * All staging buffers are static — Falcon signing uses a large
 * internal stack for its sampler (~30 KB). Keep local frames minimal.
 */

#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

#define FALCON512_SIG_BYTES  666
#define FALCON512_MSG_MAX    256

extern int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
extern int crypto_sign(unsigned char *sm, size_t *smlen,
                       const unsigned char *m, size_t mlen,
                       const unsigned char *sk);
extern int crypto_sign_open(unsigned char *m, size_t *mlen,
                            const unsigned char *sm, size_t smlen,
                            const unsigned char *pk);

static uint8_t s_sm[FALCON512_SIG_BYTES + FALCON512_MSG_MAX];
static uint8_t s_m[FALCON512_MSG_MAX];

static int falcon512_keypair(uint8_t *pk, uint8_t *sk) {
    return crypto_sign_keypair((unsigned char *)pk,
                               (unsigned char *)sk) == 0
               ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int falcon512_sign(uint8_t *sig, size_t *siglen,
                          const uint8_t *msg, size_t msglen,
                          const uint8_t *sk) {
    size_t smlen = 0;
    if (msglen > FALCON512_MSG_MAX) return CRYPTO_ERROR;
    if (crypto_sign(s_sm, &smlen,
                    (const unsigned char *)msg, msglen,
                    (const unsigned char *)sk) != 0) return CRYPTO_ERROR;
    *siglen = smlen - msglen;
    for (size_t i = 0; i < *siglen; i++) sig[i] = s_sm[i];
    return CRYPTO_SUCCESS;
}

static int falcon512_verify(const uint8_t *sig, size_t siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *pk) {
    size_t mlen = 0;
    if (msglen > FALCON512_MSG_MAX) return CRYPTO_ERROR;
    for (size_t i = 0; i < siglen; i++) s_sm[i]          = sig[i];
    for (size_t i = 0; i < msglen; i++) s_sm[siglen + i]  = msg[i];
    return crypto_sign_open(s_m, &mlen, s_sm, siglen + msglen,
                            (const unsigned char *)pk) == 0
               ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_ops_t falcon512_ops = {
    .type         = ALG_FALCON,
    .name         = "FN-DSA-512 (pqm4/m4f)",
    .sign_keypair = falcon512_keypair,
    .sign         = falcon512_sign,
    .verify       = falcon512_verify,
};