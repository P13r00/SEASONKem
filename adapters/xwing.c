/*
 * X-Wing hybrid PQ/T KEM
 * draft-connolly-cfrg-xwing-kem-01
 *
 * X-Wing = ML-KEM-768  +  X25519  combined via a SHA3-256 combiner.
 *
 * This file contains no cryptographic primitives of its own: it is a thin
 * combiner built strictly on top of the three ops structs already provided
 * in this codebase:
 *
 *   - pqm4_kyber768_ops   (ML-KEM-768: keygen / encaps / decaps)
 *   - x25519_ops     (X25519: keygen / shared_secret)   <-- same RNG
 *                          path as crypto_x25519.c, since we call
 *                          straight into x25519_ops.keygen(), which
 *                          internally uses platform_rng_handle()/WC_RNG.
 *   - pqm4_sha3_256_ops   (SHA3-256, used as the combiner hash)
 *
 * Encoding (draft-connolly-cfrg-xwing-kem-01, Section 5.1):
 *
 *   decapsulation key (sk): 2464 bytes = sk_M(2400) || sk_X(32) || pk_X(32)
 *   encapsulation key (pk): 1216 bytes = pk_M(1184) || pk_X(32)
 *   ciphertext (ct):        1120 bytes = ct_M(1088) || ct_X(32)
 *   shared secret (ss):       32 bytes
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "core/inc/crypto_api.h"

/* ---- ML-KEM-768 sizes (FIPS 203 / pqm4 kyber768) ---- */
#define MLKEM768_PK_BYTES   1184u
#define MLKEM768_SK_BYTES   2400u
#define MLKEM768_CT_BYTES   1088u
#define MLKEM768_SS_BYTES     32u

/* ---- X25519 sizes ---- */
#define X25519_PK_BYTES   32u
#define X25519_SK_BYTES   32u
#define X25519_SS_BYTES   32u

/* ---- X-Wing sizes ---- */
#define XWING_PK_BYTES  (MLKEM768_PK_BYTES + X25519_PK_BYTES)   /* 1216 */
#define XWING_SK_BYTES  (MLKEM768_SK_BYTES + X25519_SK_BYTES + X25519_PK_BYTES) /* 2464 */
#define XWING_CT_BYTES  (MLKEM768_CT_BYTES + X25519_PK_BYTES)   /* 1120 */
#define XWING_SS_BYTES  32u

/* Offsets into the flat sk / pk / ct byte strings, per the spec layout. */
#define SK_OFF_SK_M   0u
#define SK_OFF_SK_X   MLKEM768_SK_BYTES
#define SK_OFF_PK_X   (MLKEM768_SK_BYTES + X25519_SK_BYTES)

#define PK_OFF_PK_M   0u
#define PK_OFF_PK_X   MLKEM768_PK_BYTES

#define CT_OFF_CT_M   0u
#define CT_OFF_CT_X   MLKEM768_CT_BYTES

/* Existing ops structs this file builds on top of. */
extern const crypto_kem_ops_t  pqm4_kyber768_ops;
extern const crypto_kex_ops_t  x25519_ops;
extern const crypto_hash_ops_t pqm4_sha3_256_ops;

/*
 * XWingLabel, Section 5.3:
 *   XWingLabel = concat("\./", "/^\")
 * i.e. the 6 raw ASCII bytes: 5C 2E 2F 2F 5E 5C
 */
static const uint8_t xwing_label[6] = { 0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C };

/*
 * Combiner(ss_M, ss_X, ct_X, pk_X) = SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X)
 */
static int xwing_combiner(uint8_t ss[XWING_SS_BYTES],
                           const uint8_t ss_m[MLKEM768_SS_BYTES],
                           const uint8_t ss_x[X25519_SS_BYTES],
                           const uint8_t ct_x[X25519_PK_BYTES],
                           const uint8_t pk_x[X25519_PK_BYTES])
{
    uint8_t buf[sizeof(xwing_label) + MLKEM768_SS_BYTES + X25519_SS_BYTES
                + X25519_PK_BYTES + X25519_PK_BYTES];
    size_t off = 0;

    memcpy(buf + off, xwing_label, sizeof(xwing_label)); off += sizeof(xwing_label);
    memcpy(buf + off, ss_m, MLKEM768_SS_BYTES);           off += MLKEM768_SS_BYTES;
    memcpy(buf + off, ss_x, X25519_SS_BYTES);             off += X25519_SS_BYTES;
    memcpy(buf + off, ct_x, X25519_PK_BYTES);             off += X25519_PK_BYTES;
    memcpy(buf + off, pk_x, X25519_PK_BYTES);             off += X25519_PK_BYTES;

    int ret = pqm4_sha3_256_ops.hash(ss, XWING_SS_BYTES, buf, off);

    /* Wipe the intermediate buffer: it contains both shared secrets in the clear. */
    volatile uint8_t *wipe = (volatile uint8_t *)buf;
    for (size_t i = 0; i < sizeof(buf); i++) wipe[i] = 0;

    return ret;
}

/*
 * GenerateKeyPair():
 *   (pk_M, sk_M) = ML-KEM-768.KeyGen()
 *   sk_X = random(32); pk_X = X25519(sk_X, BASE)
 *   sk = concat(sk_M, sk_X, pk_X)
 *   pk = concat(pk_M, pk_X)
 */
static int xwing_keypair(uint8_t *pk, uint8_t *sk)
{
    if (!pk || !sk) return CRYPTO_ERROR;

    if (pqm4_kyber768_ops.keygen(pk + PK_OFF_PK_M, sk + SK_OFF_SK_M) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;

    /*
     * x25519_ops.keygen writes (pk_X, sk_X) directly; pk_X lands straight
     * into pk[PK_OFF_PK_X ..], and we also need a copy of pk_X appended to sk
     * (per the -01 draft's change: the decapsulation key carries pk_X too).
     */
    if (x25519_ops.keygen(pk + PK_OFF_PK_X, sk + SK_OFF_SK_X) != CRYPTO_SUCCESS) {
        return CRYPTO_ERROR;
    }

    memcpy(sk + SK_OFF_PK_X, pk + PK_OFF_PK_X, X25519_PK_BYTES);

    return CRYPTO_SUCCESS;
}

/*
 * Encapsulate(pk):
 *   pk_M = pk[0:1184]; pk_X = pk[1184:1216]
 *   ek_X = random(32); ct_X = X25519(ek_X, BASE); ss_X = X25519(ek_X, pk_X)
 *   (ss_M, ct_M) = ML-KEM-768.Encaps(pk_M)
 *   ss = Combiner(ss_M, ss_X, ct_X, pk_X)
 *   ct = concat(ct_M, ct_X)
 */
static int xwing_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    if (!ct || !ss || !pk) return CRYPTO_ERROR;

    const uint8_t *pk_m = pk + PK_OFF_PK_M;
    const uint8_t *pk_x = pk + PK_OFF_PK_X;

    uint8_t *ct_m = ct + CT_OFF_CT_M;
    uint8_t *ct_x = ct + CT_OFF_CT_X;

    uint8_t ek_x[X25519_SK_BYTES];
    uint8_t ss_x[X25519_SS_BYTES];
    uint8_t ss_m[MLKEM768_SS_BYTES];

    int ret = CRYPTO_ERROR;

    /* Ephemeral X25519 keypair: ct_x is the ephemeral public key, ek_x the scalar. */
    if (x25519_ops.keygen(ct_x, ek_x) != CRYPTO_SUCCESS) goto out;

    if (x25519_ops.shared_secret(ss_x, pk_x, ek_x) != CRYPTO_SUCCESS) goto out;

    if (pqm4_kyber768_ops.encaps(ct_m, ss_m, pk_m) != CRYPTO_SUCCESS) goto out;

    ret = xwing_combiner(ss, ss_m, ss_x, ct_x, pk_x);

out:
    {
        volatile uint8_t *w1 = (volatile uint8_t *)ek_x;
        volatile uint8_t *w2 = (volatile uint8_t *)ss_x;
        volatile uint8_t *w3 = (volatile uint8_t *)ss_m;
        for (size_t i = 0; i < sizeof(ek_x); i++) w1[i] = 0;
        for (size_t i = 0; i < sizeof(ss_x); i++) w2[i] = 0;
        for (size_t i = 0; i < sizeof(ss_m); i++) w3[i] = 0;
    }
    return ret;
}

/*
 * Decapsulate(ct, sk):
 *   ct_M = ct[0:1088]; ct_X = ct[1088:1120]
 *   sk_M = sk[0:2400]; sk_X = sk[2400:2432]; pk_X = sk[2432:2464]
 *   ss_M = ML-KEM-768.Decaps(ct_M, sk_M)
 *   ss_X = X25519(sk_X, ct_X)
 *   return Combiner(ss_M, ss_X, ct_X, pk_X)
 */
static int xwing_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    if (!ss || !ct || !sk) return CRYPTO_ERROR;

    const uint8_t *ct_m = ct + CT_OFF_CT_M;
    const uint8_t *ct_x = ct + CT_OFF_CT_X;

    const uint8_t *sk_m = sk + SK_OFF_SK_M;
    const uint8_t *sk_x = sk + SK_OFF_SK_X;
    const uint8_t *pk_x = sk + SK_OFF_PK_X;

    uint8_t ss_x[X25519_SS_BYTES];
    uint8_t ss_m[MLKEM768_SS_BYTES];

    int ret = CRYPTO_ERROR;

    if (pqm4_kyber768_ops.decaps(ss_m, ct_m, sk_m) != CRYPTO_SUCCESS) goto out;

    if (x25519_ops.shared_secret(ss_x, ct_x, sk_x) != CRYPTO_SUCCESS) goto out;

    ret = xwing_combiner(ss, ss_m, ss_x, ct_x, pk_x);

out:
    {
        volatile uint8_t *w1 = (volatile uint8_t *)ss_x;
        volatile uint8_t *w2 = (volatile uint8_t *)ss_m;
        for (size_t i = 0; i < sizeof(ss_x); i++) w1[i] = 0;
        for (size_t i = 0; i < sizeof(ss_m); i++) w2[i] = 0;
    }
    return ret;
}

const crypto_kem_ops_t xwing_ops = {
    .type    = ALG_XWING,
    .name    = "X-Wing (ML-KEM-768 + X25519)",
    .keygen  = xwing_keypair,
    .encaps  = xwing_encaps,
    .decaps  = xwing_decaps,
};