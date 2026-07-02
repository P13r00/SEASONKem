#include <stdint.h>
#include <stddef.h>
#include "core/inc/crypto_api.h"

extern int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static int kyber768_keypair(uint8_t *pk, uint8_t *sk)
{
    return crypto_kem_keypair(pk, sk) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int kyber768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    return crypto_kem_enc(ct, ss, pk) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int kyber768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return crypto_kem_dec(ss, ct, sk) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_kem_ops_t pqm4_kyber768_ops = {
    .type    = ALG_PQM4_KYBER768,
    .name    = "ML-KEM-768 (pqm4/m4fspeed)",
    .keygen  = kyber768_keypair,
    .encaps  = kyber768_encaps,
    .decaps  = kyber768_decaps,
};