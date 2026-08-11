/*
 * Winter (ML-KEM-768 + X25519 + Sparkle-Hash384 / ESCH-384)
 *
 * Same X-Wing-shaped construction as crypto_xwing_kem.c, with the KEM half
 * swapped to ML-KEM-768 and the combiner hash swapped to ESCH-384, a
 * fixed-digest (48-byte native output) member of the Sparkle family. The
 * combiner squeezes the native 48 bytes and truncates to the 32-byte
 * shared secret the KEM interface requires.
 *
 * Built strictly on top of the ops structs already provided:
 *
 *   - pqm4_kyber768_ops    (ML-KEM-768: keygen / encaps / decaps)
 *   - x25519_ops      (X25519: keygen / shared_secret)   <-- same RNG
 *                           path as crypto_x25519.c, since we call
 *                           straight into x25519_ops.keygen(), which
 *                           internally uses platform_rng_handle()/WC_RNG.
 *   - lwc_sparkle_hash384_ops (ESCH-384, used as the combiner hash;
 *                           fixed-digest, requires exactly 48-byte outlen)
 *
 * Encoding (same layout as X-Wing, Section 5.1 of
 * draft-connolly-cfrg-xwing-kem-01, with ML-KEM-768 sizes instead of
 * ML-KEM-768's):
 *
 *   decapsulation key (sk): 1696 bytes = sk_M(1632) || sk_X(32) || pk_X(32)
 *   encapsulation key (pk):  832 bytes = pk_M(800)  || pk_X(32)
 *   ciphertext (ct):         800 bytes = ct_M(768)  || ct_X(32)
 *   shared secret (ss):       32 bytes
 *
 * NOTE - label: this uses its own distinct label (NOT X-Wing's), since a
 * different (KEM, hash) pairing must be domain-separated from X-Wing's
 * combiner. Reusing X-Wing's label here would be a security bug.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "core/inc/crypto_api.h"

#define MLKEM768_PK_BYTES   1184u
#define MLKEM768_SK_BYTES   2400u
#define MLKEM768_CT_BYTES   1088u
#define MLKEM768_SS_BYTES     32u

/* ---- X25519 sizes ---- */
#define X25519_PK_BYTES   32u
#define X25519_SK_BYTES   32u
#define X25519_SS_BYTES   32u

/* ---- Winter Kyber768 */
#define WINTER_PK_BYTES  (MLKEM768_PK_BYTES + X25519_PK_BYTES)
#define WINTER_SK_BYTES  (MLKEM768_SK_BYTES + X25519_SK_BYTES + X25519_PK_BYTES)
#define WINTER_CT_BYTES  (MLKEM768_CT_BYTES + X25519_PK_BYTES)
#define WINTER_SS_BYTES  32u

/* Offsets into the flat sk / pk / ct byte strings. */
#define SK_OFF_SK_M   0u
#define SK_OFF_SK_X   MLKEM768_SK_BYTES
#define SK_OFF_PK_X   (MLKEM768_SK_BYTES + X25519_SK_BYTES)

#define PK_OFF_PK_M   0u
#define PK_OFF_PK_X   MLKEM768_PK_BYTES

#define CT_OFF_CT_M   0u
#define CT_OFF_CT_X   MLKEM768_CT_BYTES

extern const crypto_kem_ops_t  pqm4_kyber768_ops;
extern const crypto_kex_ops_t  x25519_ops;
extern const crypto_hash_ops_t lwc_sparkle_hash384_ops;


static const uint8_t winter_label[6] = { 'w', 'i', 'n', 't', 'e', 'r' };

#define ESCH_384_HASH_OUTLEN 48u

static int winter_combiner(uint8_t ss[WINTER_SS_BYTES],
                              const uint8_t ss_m[MLKEM768_SS_BYTES],
                              const uint8_t ss_x[X25519_SS_BYTES],
                              const uint8_t ct_x[X25519_PK_BYTES],
                              const uint8_t pk_x[X25519_PK_BYTES])
{
    uint8_t buf[sizeof(winter_label) + MLKEM768_SS_BYTES + X25519_SS_BYTES
                + X25519_PK_BYTES + X25519_PK_BYTES];
    size_t off = 0;

    memcpy(buf + off, winter_label, sizeof(winter_label)); off += sizeof(winter_label);
    memcpy(buf + off, ss_m, MLKEM768_SS_BYTES);                 off += MLKEM768_SS_BYTES;
    memcpy(buf + off, ss_x, X25519_SS_BYTES);                   off += X25519_SS_BYTES;
    memcpy(buf + off, ct_x, X25519_PK_BYTES);                   off += X25519_PK_BYTES;
    memcpy(buf + off, pk_x, X25519_PK_BYTES);                   off += X25519_PK_BYTES;

    uint8_t digest[ESCH_384_HASH_OUTLEN];
    int ret = lwc_sparkle_hash384_ops.hash(digest, ESCH_384_HASH_OUTLEN, buf, off);

    if (ret == CRYPTO_SUCCESS) {
        memcpy(ss, digest, WINTER_SS_BYTES);
    }

    /* Wipe intermediates: both shared secrets and the full 48-byte digest. */
    volatile uint8_t *wipe = (volatile uint8_t *)buf;
    for (size_t i = 0; i < sizeof(buf); i++) wipe[i] = 0;
    volatile uint8_t *wipe_d = (volatile uint8_t *)digest;
    for (size_t i = 0; i < sizeof(digest); i++) wipe_d[i] = 0;

    return ret;
}


static int winter_keypair(uint8_t *pk, uint8_t *sk)
{
    if (!pk || !sk) return CRYPTO_ERROR;

    if (pqm4_kyber768_ops.keygen(pk + PK_OFF_PK_M, sk + SK_OFF_SK_M) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;

    if (x25519_ops.keygen(pk + PK_OFF_PK_X, sk + SK_OFF_SK_X) != CRYPTO_SUCCESS) {
        return CRYPTO_ERROR;
    }

    memcpy(sk + SK_OFF_PK_X, pk + PK_OFF_PK_X, X25519_PK_BYTES);

    return CRYPTO_SUCCESS;
}

static int winter_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
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

    if (x25519_ops.keygen(ct_x, ek_x) != CRYPTO_SUCCESS) goto out;

    if (x25519_ops.shared_secret(ss_x, pk_x, ek_x) != CRYPTO_SUCCESS) goto out;

    if (pqm4_kyber768_ops.encaps(ct_m, ss_m, pk_m) != CRYPTO_SUCCESS) goto out;

    ret = winter_combiner(ss, ss_m, ss_x, ct_x, pk_x);

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


static int winter_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
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

    ret = winter_combiner(ss, ss_m, ss_x, ct_x, pk_x);

out:
    {
        volatile uint8_t *w1 = (volatile uint8_t *)ss_x;
        volatile uint8_t *w2 = (volatile uint8_t *)ss_m;
        for (size_t i = 0; i < sizeof(ss_x); i++) w1[i] = 0;
        for (size_t i = 0; i < sizeof(ss_m); i++) w2[i] = 0;
    }
    return ret;
}

const crypto_kem_ops_t winter_ops = {
    .type    = ALG_WINTER,
    .name    = "Winter (ML-KEM-768 + X25519 + Sparkle-Hash384)",
    .keygen  = winter_keypair,
    .encaps  = winter_encaps,
    .decaps  = winter_decaps,
};