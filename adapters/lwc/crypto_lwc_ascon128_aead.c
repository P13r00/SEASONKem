#include <stdint.h>
#include "core/inc/crypto_api.h"

extern int ascon128_aead_encrypt(
    unsigned char *c, size_t *clen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ad, size_t adlen,
    const unsigned char *npub,
    const unsigned char *k);
 
extern int ascon128_aead_decrypt(
    unsigned char *m, size_t *mlen,
    const unsigned char *c, size_t clen,
    const unsigned char *ad, size_t adlen,
    const unsigned char *npub,
    const unsigned char *k);

#define ASCON128_AEAD_KEYBYTES  16u
#define ASCON128_AEAD_NPUBBYTES 16u
#define ASCON128_AEAD_ABYTES    16u
 

static int lwc_ascon128_aead_keypair(uint8_t *key, uint8_t *nonce)
{
    if (platform_rng_generate(key, ASCON128_AEAD_KEYBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    if (platform_rng_generate(nonce, ASCON128_AEAD_NPUBBYTES) != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}
 
static int lwc_ascon128_aead_encrypt(uint8_t *c, size_t *clen,
                         const uint8_t *m, size_t mlen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    size_t out_clen = 0;
 
    int rc = ascon128_aead_encrypt(
        c, &out_clen,
        m, mlen,
        ad, adlen,
        npub,
        k);
 
    if (clen)
    {
        *clen = out_clen;
    }
 
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}
 
static int lwc_ascon128_aead_decrypt(uint8_t *m, size_t *mlen,
                         const uint8_t *c, size_t clen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    size_t out_mlen = 0;
 
    int rc = ascon128_aead_decrypt(
        m, &out_mlen,
        c, clen,
        ad, adlen,
        npub,
        k);
 
    if (mlen)
    {
        *mlen = out_mlen;
    }
 
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}
 
const crypto_aead_ops_t lwc_ascon128_aead_ops = {
    .type = ALG_LWC_ASCON128_AEAD,
    .name = "Ascon-AEAD128 (lwc)",
    .key_bytes = ASCON128_AEAD_KEYBYTES,
    .nonce_bytes = ASCON128_AEAD_NPUBBYTES,
    .tag_bytes = ASCON128_AEAD_ABYTES,
    .init = platform_rng_init,
    .keygen = lwc_ascon128_aead_keypair,
    .encrypt = lwc_ascon128_aead_encrypt,
    .decrypt = lwc_ascon128_aead_decrypt,
};