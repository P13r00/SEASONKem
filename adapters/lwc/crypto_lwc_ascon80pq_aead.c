#include <stdint.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

extern int ascon80pq_aead_encrypt(
    unsigned char *c, size_t *clen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ad, size_t adlen,
    const unsigned char *npub,
    const unsigned char *k);

extern int ascon80pq_aead_decrypt(
    unsigned char *m, size_t *mlen,
    const unsigned char *c, size_t clen,
    const unsigned char *ad, size_t adlen,
    const unsigned char *npub,
    const unsigned char *k);


#define ASCON80PQ_AEAD_KEYBYTES  20u
#define ASCON80PQ_AEAD_NPUBBYTES 16u
#define ASCON80PQ_AEAD_ABYTES    16u


static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(seed ^ (uint8_t)i);
}

static int lwc_ascon80pq_aead_keypair(uint8_t *key, uint8_t *nonce)
{
    if (platform_rng_generate(key, ASCON80PQ_AEAD_KEYBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    if (platform_rng_generate(nonce, ASCON80PQ_AEAD_NPUBBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}

static int lwc_ascon80pq_aead_encrypt(uint8_t *c, size_t *clen,
                         const uint8_t *m, size_t mlen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    size_t sparkle_clen = 0;

    int rc = ascon80pq_aead_encrypt(
        c, &sparkle_clen,
        m, mlen,
        ad, adlen,
        npub,
        k);

    if (clen)
    {
        *clen = sparkle_clen;
    }

    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int lwc_ascon80pq_aead_decrypt(uint8_t *m, size_t *mlen,
                         const uint8_t *c, size_t clen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    size_t sparkle_mlen = 0;

    int rc = ascon80pq_aead_decrypt(
        m, &sparkle_mlen,
        c, clen,
        ad, adlen,
        npub,
        k);

    if (mlen)
    {
        *mlen = sparkle_mlen;
    }

    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_aead_ops_t lwc_ascon80pq_aead_ops = {
    .type = ALG_LWC_ASCON80PQ_AEAD,
    .name = "Ascon80pq (lwc)",
    .key_bytes = ASCON80PQ_AEAD_KEYBYTES,
    .nonce_bytes = ASCON80PQ_AEAD_NPUBBYTES,
    .tag_bytes = ASCON80PQ_AEAD_ABYTES,
    .init = platform_rng_init,
    .keygen = lwc_ascon80pq_aead_keypair,
    .encrypt = lwc_ascon80pq_aead_encrypt,
    .decrypt = lwc_ascon80pq_aead_decrypt,
};