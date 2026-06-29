/*
 * crypto_chacha20_poly1305.c — ChaCha20-Poly1305 AEAD adapter (stub)
 *
 * Work simulation is calibrated against a software ChaCha20-Poly1305
 * implementation on Cortex-M4 @ 168 MHz operating on 64-byte messages:
 *
 *   Keygen  ~   300 cy   (key is already 256-bit; just set up the nonce)
 *   Encrypt ~ 4 500 cy   (Poly1305 key gen + ChaCha20 encrypt + Poly1305 MAC)
 *   Decrypt ~ 4 600 cy   (Poly1305 MAC verification first, then ChaCha20)
 */

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

static WC_RNG s_rng;
static int s_rng_ready = 0;

static int ensure_rng(void)
{
    if (!s_rng_ready)
    {
        if (wc_InitRng(&s_rng) != 0)
            return CRYPTO_ERROR;
        s_rng_ready = 1;
    }
    return CRYPTO_SUCCESS;
}

/* ChaCha20-Poly1305 parameters (RFC 8439) */
#define CHACHA_KEY_BYTES 32u   /* 256-bit key                    */
#define CHACHA_NONCE_BYTES 12u /* 96-bit IETF nonce              */
#define POLY1305_TAG_BYTES 16u /* 128-bit Poly1305 MAC           */

/* ------------------------------------------------------------------ */
/*  Key + nonce setup                                                  */
/*                                                                     */
/*  In production: key from TRNG/DRBG; nonce from monotonic counter  */
/*  or TRNG — per-message uniqueness mandatory.                       */
/* ------------------------------------------------------------------ */

static int chacha_keygen(uint8_t *key, uint8_t *nonce)
{
    if (ensure_rng() != CRYPTO_SUCCESS)
        return CRYPTO_ERROR;
    if (wc_RNG_GenerateBlock(&s_rng, key, CHACHA_KEY_BYTES) != 0)
        return CRYPTO_ERROR;
    if (wc_RNG_GenerateBlock(&s_rng, nonce, CHACHA_NONCE_BYTES) != 0)
        return CRYPTO_ERROR;
    return CRYPTO_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Authenticated encryption                                           */
/*                                                                     */
/*  Output layout: ct = ciphertext || Poly1305-tag                   */
/* ------------------------------------------------------------------ */

static int chacha_encrypt(uint8_t *ct, size_t *ctlen,
                          const uint8_t *pt, size_t ptlen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *nonce,
                          const uint8_t *key)
{
    int ret = wc_ChaCha20Poly1305_Encrypt(key, nonce,
                                          ad, (word32)adlen,
                                          pt, (word32)ptlen,
                                          ct, ct + ptlen);
    if (ctlen)
        *ctlen = ptlen + POLY1305_TAG_BYTES;
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int chacha_decrypt(uint8_t *pt, size_t *ptlen,
                          const uint8_t *ct, size_t ctlen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *nonce,
                          const uint8_t *key)
{
    if (ctlen < POLY1305_TAG_BYTES)
        return CRYPTO_ERROR;
    size_t msglen = ctlen - POLY1305_TAG_BYTES;
    int ret = wc_ChaCha20Poly1305_Decrypt(key, nonce,
                                          ad, (word32)adlen,
                                          ct, (word32)msglen,
                                          ct + msglen, pt);
    if (ptlen)
        *ptlen = msglen;
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_aead_ops_t chacha20_poly1305_ops = {
    .type = ALG_CHACHA20_POLY1305,
    .name = "ChaCha20-Poly1305",
    .key_bytes = CHACHA_KEY_BYTES,
    .nonce_bytes = CHACHA_NONCE_BYTES,
    .tag_bytes = POLY1305_TAG_BYTES,
    .init = ensure_rng,
    .keygen = chacha_keygen,
    .encrypt = chacha_encrypt,
    .decrypt = chacha_decrypt,
};
