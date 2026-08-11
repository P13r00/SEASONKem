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

/* ---- Spring (Kyber512 / Xoodyak) sizes ---- */
#define SPRING_PK_BYTES  (MLKEM512_PK_BYTES + X25519_PK_BYTES) 
#define SPRING_SK_BYTES  (MLKEM512_SK_BYTES + X25519_SK_BYTES + X25519_PK_BYTES) 
#define SPRING_CT_BYTES  (MLKEM512_CT_BYTES + X25519_PK_BYTES)
#define SPRING_SS_BYTES  32u

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
extern const crypto_hash_ops_t lwc_xoodyak_hash_ops;


static const uint8_t spring_label[6] = { 's', 'p', 'r', 'i', 'n', 'g' };

static int spring_combiner(uint8_t ss[SPRING_SS_BYTES],
                              const uint8_t ss_m[MLKEM512_SS_BYTES],
                              const uint8_t ss_x[X25519_SS_BYTES],
                              const uint8_t ct_x[X25519_PK_BYTES],
                              const uint8_t pk_x[X25519_PK_BYTES])
{
    uint8_t buf[sizeof(spring_label) + MLKEM512_SS_BYTES + X25519_SS_BYTES
                + X25519_PK_BYTES + X25519_PK_BYTES];
    size_t off = 0;

    memcpy(buf + off, spring_label, sizeof(spring_label)); off += sizeof(spring_label);
    memcpy(buf + off, ss_m, MLKEM512_SS_BYTES);                 off += MLKEM512_SS_BYTES;
    memcpy(buf + off, ss_x, X25519_SS_BYTES);                   off += X25519_SS_BYTES;
    memcpy(buf + off, ct_x, X25519_PK_BYTES);                   off += X25519_PK_BYTES;
    memcpy(buf + off, pk_x, X25519_PK_BYTES);                   off += X25519_PK_BYTES;

    int ret = lwc_xoodyak_hash_ops.hash(ss, SPRING_SS_BYTES, buf, off);

    /* Wipe the intermediate buffer: it contains both shared secrets in the clear. */
    volatile uint8_t *wipe = (volatile uint8_t *)buf;
    for (size_t i = 0; i < sizeof(buf); i++) wipe[i] = 0;

    return ret;
}

static int spring_keypair(uint8_t *pk, uint8_t *sk)
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

/*
 * Encapsulate(pk):
 *   pk_M = pk[0:800]; pk_X = pk[800:832]
 *   ek_X = random(32); ct_X = X25519(ek_X, BASE); ss_X = X25519(ek_X, pk_X)
 *   (ss_M, ct_M) = ML-KEM-512.Encaps(pk_M)
 *   ss = Combiner(ss_M, ss_X, ct_X, pk_X)
 *   ct = concat(ct_M, ct_X)
 */
static int spring_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
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

    /* Ephemeral X25519 keypair: ct_x is the ephemeral public key, ek_x the scalar. */
    if (x25519_ops.keygen(ct_x, ek_x) != CRYPTO_SUCCESS) goto out;

    if (x25519_ops.shared_secret(ss_x, pk_x, ek_x) != CRYPTO_SUCCESS) goto out;

    if (pqm4_kyber512_ops.encaps(ct_m, ss_m, pk_m) != CRYPTO_SUCCESS) goto out;

    ret = spring_combiner(ss, ss_m, ss_x, ct_x, pk_x);

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

static int spring_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
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

    ret = spring_combiner(ss, ss_m, ss_x, ct_x, pk_x);

out:
    {
        volatile uint8_t *w1 = (volatile uint8_t *)ss_x;
        volatile uint8_t *w2 = (volatile uint8_t *)ss_m;
        for (size_t i = 0; i < sizeof(ss_x); i++) w1[i] = 0;
        for (size_t i = 0; i < sizeof(ss_m); i++) w2[i] = 0;
    }
    return ret;
}

const crypto_kem_ops_t spring_ops = {
    .type    = ALG_SPRING,
    .name    = "Spring (ML-KEM-512 + X25519 + Xoodyak-Hash)",
    .keygen  = spring_keypair,
    .encaps  = spring_encaps,
    .decaps  = spring_decaps,
};