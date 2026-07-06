#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

/* lwc-finalists xoodyak.h API - lengths are unsigned long long, not size_t.
 * Note the decrypt parameter order differs from encrypt: nsec comes before
 * c/clen on decrypt, matching the upstream xoodyak_aead_decrypt() signature. */
extern int xoodyak_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

extern int xoodyak_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k);


#define XOODYAK_AEAD_KEYBYTES  16u
#define XOODYAK_AEAD_NPUBBYTES 16u
#define XOODYAK_AEAD_ABYTES    16u


static int lwc_xoodyak_aead_keypair(uint8_t *key, uint8_t *nonce)
{
    if (platform_rng_generate(key, XOODYAK_AEAD_KEYBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    if (platform_rng_generate(nonce, XOODYAK_AEAD_NPUBBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}

static int lwc_xoodyak_aead_encrypt(uint8_t *c, size_t *clen,
                         const uint8_t *m, size_t mlen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    unsigned long long xoodyak_clen = 0;

    int rc = xoodyak_aead_encrypt(
        c, &xoodyak_clen,
        m, (unsigned long long)mlen,
        ad, (unsigned long long)adlen,
        NULL, /* nsec: secret nonce, not used by Xoodyak */
        npub,
        k);

    if (clen)
    {
        *clen = (size_t)xoodyak_clen;
    }

    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int lwc_xoodyak_aead_decrypt(uint8_t *m, size_t *mlen,
                         const uint8_t *c, size_t clen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    unsigned long long xoodyak_mlen = 0;

    int rc = xoodyak_aead_decrypt(
        m, &xoodyak_mlen,
        NULL, /* nsec: secret nonce, not used by Xoodyak */
        c, (unsigned long long)clen,
        ad, (unsigned long long)adlen,
        npub,
        k);

    if (mlen)
    {
        *mlen = (size_t)xoodyak_mlen;
    }

    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_aead_ops_t lwc_xoodyak_aead_ops = {
    .type = ALG_LWC_XOODYAK_AEAD,
    .name = "Xoodyak-AEAD (lwc)",
    .key_bytes = XOODYAK_AEAD_KEYBYTES,
    .nonce_bytes = XOODYAK_AEAD_NPUBBYTES,
    .tag_bytes = XOODYAK_AEAD_ABYTES,
    .init = platform_rng_init,
    .keygen = lwc_xoodyak_aead_keypair,
    .encrypt = lwc_xoodyak_aead_encrypt,
    .decrypt = lwc_xoodyak_aead_decrypt,
};