#include <stdint.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"


extern int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

extern int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k);

#define A80PQ_KEYBYTES 20u
#define A80PQ_NPUBBYTES 16u
#define A80PQ_ABYTES 16u

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(seed ^ (uint8_t)i);
}

static int a80pq_keypair(uint8_t *key, uint8_t *nonce)
{
    if (platform_rng_generate(key, A80PQ_KEYBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    if (platform_rng_generate(nonce, A80PQ_NPUBBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}

static int a80pq_encrypt(uint8_t *c, size_t *clen,
                         const uint8_t *m, size_t mlen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    unsigned long long ascon_clen = 0;

    int rc = crypto_aead_encrypt(
        c, &ascon_clen,
        m, (unsigned long long)mlen,
        ad, (unsigned long long)adlen,
        NULL, /* nsec — not used by Ascon */
        npub,
        k);

    if (clen)
    {
        *clen = (size_t)ascon_clen;
    }

    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int a80pq_decrypt(uint8_t *m, size_t *mlen,
                         const uint8_t *c, size_t clen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    unsigned long long ascon_mlen = 0;

    int rc = crypto_aead_decrypt(
        m, &ascon_mlen,
        NULL,
        c, (unsigned long long)clen,
        ad, (unsigned long long)adlen,
        npub,
        k);

    if (mlen)
    {
        *mlen = (size_t)ascon_mlen;
    }

    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_aead_ops_t ascon80pq_ops = {
    .type = ALG_ASCON80PQ,
    .name = "Ascon-80pq",
    .key_bytes = A80PQ_KEYBYTES,
    .nonce_bytes = A80PQ_NPUBBYTES,
    .tag_bytes = A80PQ_ABYTES,
    .init = platform_rng_init,
    .keygen = a80pq_keypair,
    .encrypt = a80pq_encrypt,
    .decrypt = a80pq_decrypt,
};