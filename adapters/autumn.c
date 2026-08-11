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

/* ---- Autumn (Kyber512 / Xoodyak) sizes ---- */
#define AUTUMN_PK_BYTES  (MLKEM512_PK_BYTES + X25519_PK_BYTES)
#define AUTUMN_SK_BYTES  (MLKEM512_SK_BYTES + X25519_SK_BYTES + X25519_PK_BYTES)
#define AUTUMN_CT_BYTES  (MLKEM512_CT_BYTES + X25519_PK_BYTES)
#define AUTUMN_SS_BYTES  32u

#define SK_OFF_SK_M   0u
#define SK_OFF_SK_X   MLKEM512_SK_BYTES
#define SK_OFF_PK_X   (MLKEM512_SK_BYTES + X25519_SK_BYTES)

#define PK_OFF_PK_M   0u
#define PK_OFF_PK_X   MLKEM512_PK_BYTES

#define CT_OFF_CT_M   0u
#define CT_OFF_CT_X   MLKEM512_CT_BYTES

extern const crypto_kem_ops_t  pqm4_kyber512_ops;
extern const crypto_kex_ops_t  x25519_ops;
extern const crypto_hash_ops_t lwc_sparkle_hash256_ops;


static const uint8_t autumn_label[6] = { 'a', 'u', 't', 'u', 'm', 'n' };


static int autumn_combiner(uint8_t ss[AUTUMN_SS_BYTES],
                              const uint8_t ss_m[MLKEM512_SS_BYTES],
                              const uint8_t ss_x[X25519_SS_BYTES],
                              const uint8_t ct_x[X25519_PK_BYTES],
                              const uint8_t pk_x[X25519_PK_BYTES])
{
    uint8_t buf[sizeof(autumn_label) + MLKEM512_SS_BYTES + X25519_SS_BYTES
                + X25519_PK_BYTES + X25519_PK_BYTES];
    size_t off = 0;

    memcpy(buf + off, autumn_label, sizeof(autumn_label)); off += sizeof(autumn_label);
    memcpy(buf + off, ss_m, MLKEM512_SS_BYTES);                 off += MLKEM512_SS_BYTES;
    memcpy(buf + off, ss_x, X25519_SS_BYTES);                   off += X25519_SS_BYTES;
    memcpy(buf + off, ct_x, X25519_PK_BYTES);                   off += X25519_PK_BYTES;
    memcpy(buf + off, pk_x, X25519_PK_BYTES);                   off += X25519_PK_BYTES;

    int ret = lwc_sparkle_hash256_ops.hash(ss, AUTUMN_SS_BYTES, buf, off);
    
    volatile uint8_t *wipe = (volatile uint8_t *)buf;
    for (size_t i = 0; i < sizeof(buf); i++) wipe[i] = 0;

    return ret;
}

static int autumn_keypair(uint8_t *pk, uint8_t *sk)
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


static int autumn_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
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

    ret = autumn_combiner(ss, ss_m, ss_x, ct_x, pk_x);

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

static int autumn_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
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

    ret = autumn_combiner(ss, ss_m, ss_x, ct_x, pk_x);

out:
    {
        volatile uint8_t *w1 = (volatile uint8_t *)ss_x;
        volatile uint8_t *w2 = (volatile uint8_t *)ss_m;
        for (size_t i = 0; i < sizeof(ss_x); i++) w1[i] = 0;
        for (size_t i = 0; i < sizeof(ss_m); i++) w2[i] = 0;
    }
    return ret;
}

const crypto_kem_ops_t autumn_ops = {
    .type    = ALG_AUTUMN,
    .name    = "Autumn (ML-KEM-512 + X25519 + Sparkle-Hash)",
    .keygen  = autumn_keypair,
    .encaps  = autumn_encaps,
    .decaps  = autumn_decaps,
};