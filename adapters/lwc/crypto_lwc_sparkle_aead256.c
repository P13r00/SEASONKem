#include <stdint.h>
#include "core/inc/crypto_api.h"

extern int schwaemm_256_256_aead_encrypt(
    unsigned char *c, size_t *clen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ad, size_t adlen,
    const unsigned char *npub,
    const unsigned char *k);

extern int schwaemm_256_256_aead_decrypt(
    unsigned char *m, size_t *mlen,
    const unsigned char *c, size_t clen,
    const unsigned char *ad, size_t adlen,
    const unsigned char *npub,
    const unsigned char *k);


#define SPARKLE_AEAD256_KEYBYTES  32u
#define SPARKLE_AEAD256_NPUBBYTES 32u
#define SPARKLE_AEAD256_ABYTES    32u


static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(seed ^ (uint8_t)i);
}

static int lwc_sparkle_aead256_keypair(uint8_t *key, uint8_t *nonce)
{
    if (platform_rng_generate(key, SPARKLE_AEAD256_KEYBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    if (platform_rng_generate(nonce, SPARKLE_AEAD256_NPUBBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}

static int lwc_sparkle_aead256_encrypt(uint8_t *c, size_t *clen,
                         const uint8_t *m, size_t mlen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    size_t sparkle_clen = 0;

    int rc = schwaemm_256_256_aead_encrypt(
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

static int lwc_sparkle_aead256_decrypt(uint8_t *m, size_t *mlen,
                         const uint8_t *c, size_t clen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    size_t sparkle_mlen = 0;

    int rc = schwaemm_256_256_aead_decrypt(
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

const crypto_aead_ops_t lwc_sparkle_aead256_ops = {
    .type = ALG_LWC_SPARKLE_AEAD256,
    .name = "Schwaemm256-256 (lwc)",
    .key_bytes = SPARKLE_AEAD256_KEYBYTES,
    .nonce_bytes = SPARKLE_AEAD256_NPUBBYTES,
    .tag_bytes = SPARKLE_AEAD256_ABYTES,
    .init = platform_rng_init,
    .keygen = lwc_sparkle_aead256_keypair,
    .encrypt = lwc_sparkle_aead256_encrypt,
    .decrypt = lwc_sparkle_aead256_decrypt,
};