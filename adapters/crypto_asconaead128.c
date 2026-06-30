#include <stdint.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

extern int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, /* always NULL for Ascon   */
    const unsigned char *npub, /* nonce, 16 bytes         */
    const unsigned char *k);   /* key,   20 bytes         */

extern int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec, /* always NULL for Ascon   */
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, /* nonce, 16 bytes         */
    const unsigned char *k);   /* key,   20 bytes         */

/* ------------------------------------------------------------------ */
/*  Ascon-80pq static parameters                                      */
/* ------------------------------------------------------------------ */

#define ASCON_128_KEYBYTES 16u
#define ASCON_128_NPUBBYTES 16u /* 128-bit nonce                      */
#define ASCON_128_ABYTES 16u    /* 128-bit authentication tag         */

/* ------------------------------------------------------------------ */
/*  Deterministic pattern fill (replaces TRNG on bare metal)          */
/* ------------------------------------------------------------------ */

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* ------------------------------------------------------------------ */
/*  Adapter: sign_keypair                                              */
/* ------------------------------------------------------------------ */

static int asconaead128_keypair(uint8_t *pk, uint8_t *sk)
{
    /* key   → sk[0..19]  */
    fill_pattern(sk, ASCON_128_KEYBYTES, 0xA5u);
    /* nonce → sk[20..35] */
    fill_pattern(sk + ASCON_128_KEYBYTES, ASCON_128_NPUBBYTES, 0x5Au);

    /* pk[0..15] = nonce copy so verify() can run without sk */
    for (size_t i = 0; i < ASCON_128_NPUBBYTES; i++)
        pk[i] = sk[ASCON_128_KEYBYTES + i];
    for (size_t i = ASCON_128_NPUBBYTES; i < 32u; i++)
        pk[i] = 0u;

    return CRYPTO_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Adapter: encrypt                                                  */
/* ------------------------------------------------------------------ */

static int asconaead128_encrypt(uint8_t *c, size_t *clen,
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
/* ------------------------------------------------------------------ */
/* Adapter: decrypt                                                  */
/* ------------------------------------------------------------------ */

static int asconaead128_decrypt(uint8_t *m, size_t *mlen,
                         const uint8_t *c, size_t clen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *npub, const uint8_t *k)
{
    unsigned long long ascon_mlen = 0;

    int rc = crypto_aead_decrypt(
        m, &ascon_mlen,
        NULL, /* nsec — not used by Ascon */
        c, (unsigned long long)clen,
        ad, (unsigned long long)adlen,
        npub,
        k);

    if (mlen)
    {
        *mlen = (size_t)ascon_mlen;
    }

    /* Note: The underlying Ascon decrypt already does constant-time tag
       verification internally. If rc == 0, the message is authentic. */
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

/* ------------------------------------------------------------------ */
/*  Public ops struct                                                  */
/* ------------------------------------------------------------------ */

const crypto_aead_ops_t asconaead128_ops = {
    .type = ALG_ASCON_AEAD128,
    .name = "Ascon-AEAD-128",
    .key_bytes = ASCON_128_KEYBYTES,
    .nonce_bytes = ASCON_128_NPUBBYTES,
    .tag_bytes = ASCON_128_ABYTES,
    .init = platform_rng_init,
    .keygen = asconaead128_keypair,
    .encrypt = asconaead128_encrypt,
    .decrypt = asconaead128_decrypt,
};