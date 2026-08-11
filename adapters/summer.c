/*
 * Summer (ML-KEM-512 + X25519 + Xoodyak-Hash)
 *
 * Same X-Wing-shaped construction as crypto_xwing_kem.c, with the KEM half
 * swapped to ML-KEM-512 and the combiner hash swapped to Xoodyak-Hash (an
 * 256, used here as a one-shot 32-byte squeeze).
 *
 * Built strictly on top of the ops structs already provided:
 *
 *   - pqm4_kyber512_ops    (ML-KEM-512: keygen / encaps / decaps)
 *   - x25519_ops      (X25519: keygen / shared_secret)   <-- same RNG
 *                           path as crypto_x25519.c, since we call
 *                           straight into x25519_ops.keygen(), which
 *                           internally uses platform_rng_handle()/WC_RNG.
 *   - lwc_ascon_hash256_ops (Xoodyak-Hash, used as the combiner hash)
 *
 * Encoding (same layout as X-Wing, Section 5.1 of
 * draft-connolly-cfrg-xwing-kem-01, with ML-KEM-512 sizes instead of
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

/* ---- ML-KEM-512 sizes (FIPS 203 / pqm4 kyber512) ---- */
#define MLKEM512_PK_BYTES   800u
#define MLKEM512_SK_BYTES  1632u
#define MLKEM512_CT_BYTES   768u
#define MLKEM512_SS_BYTES    32u

/* ---- X25519 sizes ---- */
#define X25519_PK_BYTES   32u
#define X25519_SK_BYTES   32u
#define X25519_SS_BYTES   32u

/* ---- Summer (Kyber512 / Xoodyak) sizes ---- */
#define SUMMER_PK_BYTES  (MLKEM512_PK_BYTES + X25519_PK_BYTES)
#define SUMMER_SK_BYTES  (MLKEM512_SK_BYTES + X25519_SK_BYTES + X25519_PK_BYTES) 
#define SUMMER_CT_BYTES  (MLKEM512_CT_BYTES + X25519_PK_BYTES)
#define SUMMER_SS_BYTES  32u

/* Offsets into the flat sk / pk / ct byte strings. */
#define SK_OFF_SK_M   0u
#define SK_OFF_SK_X   MLKEM512_SK_BYTES
#define SK_OFF_PK_X   (MLKEM512_SK_BYTES + X25519_SK_BYTES)

#define PK_OFF_PK_M   0u
#define PK_OFF_PK_X   MLKEM512_PK_BYTES

#define CT_OFF_CT_M   0u
#define CT_OFF_CT_X   MLKEM512_CT_BYTES

/* Existing ops structs this file builds on top of. */
extern const crypto_kem_ops_t  pqm4_kyber512_ops;
extern const crypto_kex_ops_t  x25519_ops;
extern const crypto_hash_ops_t lwc_ascon_hash256_ops;


static const uint8_t summer_label[6] = { 's', 'u', 'm', 'm', 'e', 'r' };


static int summer_combiner(uint8_t ss[SUMMER_SS_BYTES],
                              const uint8_t ss_m[MLKEM512_SS_BYTES],
                              const uint8_t ss_x[X25519_SS_BYTES],
                              const uint8_t ct_x[X25519_PK_BYTES],
                              const uint8_t pk_x[X25519_PK_BYTES])
{
    uint8_t buf[sizeof(summer_label) + MLKEM512_SS_BYTES + X25519_SS_BYTES
                + X25519_PK_BYTES + X25519_PK_BYTES];
    size_t off = 0;

    memcpy(buf + off, summer_label, sizeof(summer_label)); off += sizeof(summer_label);
    memcpy(buf + off, ss_m, MLKEM512_SS_BYTES);                 off += MLKEM512_SS_BYTES;
    memcpy(buf + off, ss_x, X25519_SS_BYTES);                   off += X25519_SS_BYTES;
    memcpy(buf + off, ct_x, X25519_PK_BYTES);                   off += X25519_PK_BYTES;
    memcpy(buf + off, pk_x, X25519_PK_BYTES);                   off += X25519_PK_BYTES;

    int ret = lwc_ascon_hash256_ops.hash(ss, SUMMER_SS_BYTES, buf, off);

    volatile uint8_t *wipe = (volatile uint8_t *)buf;
    for (size_t i = 0; i < sizeof(buf); i++) wipe[i] = 0;

    return ret;
}


static int summer_keypair(uint8_t *pk, uint8_t *sk)
{
    if (!pk || !sk) return CRYPTO_ERROR;

    if (pqm4_kyber512_ops.keygen(pk + PK_OFF_PK_M, sk + SK_OFF_SK_M) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;


    if (x25519_ops.keygen(pk + PK_OFF_PK_X, sk + SK_OFF_SK_X) != CRYPTO_SUCCESS) {
        return CRYPTO_ERROR;
    }

    memcpy(sk + SK_OFF_PK_X, pk + PK_OFF_PK_X, X25519_PK_BYTES);

    return CRYPTO_SUCCESS;
}


static int summer_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    if (!ct || !ss || !pk) return CRYPTO_ERROR;

    const uint8_t *pk_m = pk + PK_OFF_PK_M;
    const uint8_t *pk_x = pk + PK_OFF_PK_X;

    uint8_t *ct_m = ct + CT_OFF_CT_M;
    uint8_t *ct_x = ct + CT_OFF_CT_X;

    uint8_t ek_x[X25519_SK_BYTES];
    uint8_t ss_x[X25519_SS_BYTES];
    uint8_t ss_m[MLKEM512_SS_BYTES];

    int ret = CRYPTO_ERROR;


    if (x25519_ops.keygen(ct_x, ek_x) != CRYPTO_SUCCESS) goto out;

    if (x25519_ops.shared_secret(ss_x, pk_x, ek_x) != CRYPTO_SUCCESS) goto out;

    if (pqm4_kyber512_ops.encaps(ct_m, ss_m, pk_m) != CRYPTO_SUCCESS) goto out;

    ret = summer_combiner(ss, ss_m, ss_x, ct_x, pk_x);

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


static int summer_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    if (!ss || !ct || !sk) return CRYPTO_ERROR;

    const uint8_t *ct_m = ct + CT_OFF_CT_M;
    const uint8_t *ct_x = ct + CT_OFF_CT_X;

    const uint8_t *sk_m = sk + SK_OFF_SK_M;
    const uint8_t *sk_x = sk + SK_OFF_SK_X;
    const uint8_t *pk_x = sk + SK_OFF_PK_X;

    uint8_t ss_x[X25519_SS_BYTES];
    uint8_t ss_m[MLKEM512_SS_BYTES];

    int ret = CRYPTO_ERROR;

    if (pqm4_kyber512_ops.decaps(ss_m, ct_m, sk_m) != CRYPTO_SUCCESS) goto out;

    if (x25519_ops.shared_secret(ss_x, ct_x, sk_x) != CRYPTO_SUCCESS) goto out;

    ret = summer_combiner(ss, ss_m, ss_x, ct_x, pk_x);

out:
    {
        volatile uint8_t *w1 = (volatile uint8_t *)ss_x;
        volatile uint8_t *w2 = (volatile uint8_t *)ss_m;
        for (size_t i = 0; i < sizeof(ss_x); i++) w1[i] = 0;
        for (size_t i = 0; i < sizeof(ss_m); i++) w2[i] = 0;
    }
    return ret;
}

const crypto_kem_ops_t summer_ops = {
    .type    = ALG_SUMMER,
    .name    = "Summer (ML-KEM-512 + X25519 + Ascon-Hash)",
    .keygen  = summer_keypair,
    .encaps  = summer_encaps,
    .decaps  = summer_decaps,
};