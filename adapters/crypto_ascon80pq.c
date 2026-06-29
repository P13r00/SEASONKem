/*
 * adapters/crypto_ascon80pq.c
 *
 * Adapter: Ascon-80pq AEAD → crypto_ops_t (sign/verify interface).
 *
 * Ascon-80pq (NIST LWC round 2 finalist, ISO/IEC 29192-6):
 *   Key   : 20 bytes  (CRYPTO_KEYBYTES)
 *   Nonce : 16 bytes  (CRYPTO_NPUBBYTES)
 *   Tag   : 16 bytes  (CRYPTO_ABYTES)
 *
 * sk buffer layout (fits the 64-byte sk[] in execute_signature_benchmark):
 *   sk[0..19]  = 20-byte key
 *   sk[20..35] = 16-byte nonce
 *
 * pk buffer layout (32-byte pk[]):
 *   pk[0..15]  = nonce copy  (so verify() runs without sk)
 *   pk[16..31] = 0x00 padding
 *
 * sign:   crypto_aead_encrypt(key=sk[0..19], nonce=sk[20..35],
 *                             pt=msg, ad=∅)
 *         → sig = ct ∥ tag,  siglen = msglen + 16
 *         For the 4-byte test message: siglen = 20 B ≪ sig[64].
 *
 * verify: crypto_aead_decrypt(key=reconstructed, nonce=pk[0..15],
 *                             ct=sig, ad=∅)
 *         → compare recovered plaintext with original msg
 *
 * Keying: deterministic fill (no TRNG on bare metal).  Replace with
 *         hardware RNG or DRBG output in a production build.
 *
 * ARMv7-M path:
 *   The armv7m-optimised permutation (Thumb-2 assembly) is compiled from
 *   third_party/ascon-c/crypto_aead/ascon80pq/armv7m/ and linked in via
 *   CMakeLists.txt.  Required sources:
 *     encrypt.c       – crypto_aead_encrypt / crypto_aead_decrypt
 *     permutations.S  – ascon_permutation_6 / _8 / _12 in Thumb-2
 *   or, if your copy uses a .c permutation:
 *     permutations.c
 *
 *   CMake snippet:
 *     set(ASCON80PQ_DIR third_party/ascon-c/crypto_aead/ascon80pq/armv7m)
 *     target_sources(cryptoBenchmark PRIVATE
 *         ${ASCON80PQ_DIR}/encrypt.c
 *         ${ASCON80PQ_DIR}/permutations.c   # or .S
 *     )
 *     target_include_directories(cryptoBenchmark PRIVATE ${ASCON80PQ_DIR})
 *
 * benchmark_runner.c change needed:
 *   extern const crypto_ops_t ascon80pq_ops;      // add extern
 *   static const crypto_ops_t *sign_registry[] = {
 *       &ed25519_ops,
 *       &ascon80pq_ops,                           // add entry
 *   };
 */

#include <stdint.h>
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

#define A80PQ_KEYBYTES 20u  /* 160-bit key                        */
#define A80PQ_NPUBBYTES 16u /* 128-bit nonce                      */
#define A80PQ_ABYTES 16u    /* 128-bit authentication tag         */

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

static int a80pq_keypair(uint8_t *pk, uint8_t *sk)
{
    /* key   → sk[0..19]  */
    fill_pattern(sk, A80PQ_KEYBYTES, 0xA5u);
    /* nonce → sk[20..35] */
    fill_pattern(sk + A80PQ_KEYBYTES, A80PQ_NPUBBYTES, 0x5Au);

    /* pk[0..15] = nonce copy so verify() can run without sk */
    for (size_t i = 0; i < A80PQ_NPUBBYTES; i++)
        pk[i] = sk[A80PQ_KEYBYTES + i];
    for (size_t i = A80PQ_NPUBBYTES; i < 32u; i++)
        pk[i] = 0u;

    return CRYPTO_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Adapter: encrypt                                                  */
/* ------------------------------------------------------------------ */

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
/* ------------------------------------------------------------------ */
/* Adapter: decrypt                                                  */
/* ------------------------------------------------------------------ */

static int a80pq_decrypt(uint8_t *m, size_t *mlen,
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

const crypto_aead_ops_t ascon80pq_ops = {
    .type = ALG_ASCON80PQ,
    .name = "Ascon-80pq",
    .key_bytes = A80PQ_KEYBYTES,
    .nonce_bytes = A80PQ_NPUBBYTES,
    .tag_bytes = A80PQ_ABYTES,
    .init = ensure_rng,
    .keygen = a80pq_keypair,
    .encrypt = a80pq_encrypt,
    .decrypt = a80pq_decrypt,
};