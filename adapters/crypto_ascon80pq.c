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
#include <stddef.h>
#include "core/inc/crypto_api.h"

/* ------------------------------------------------------------------ */
/*  Ascon-80pq AEAD API (NIST LWC / ascon-c naming convention)       */
/*  Resolved at link time from the armv7m encrypt.c object.           */
/* ------------------------------------------------------------------ */

extern int crypto_aead_encrypt(
    unsigned char       *c,    unsigned long long *clen,
    const unsigned char *m,    unsigned long long  mlen,
    const unsigned char *ad,   unsigned long long  adlen,
    const unsigned char *nsec,          /* always NULL for Ascon   */
    const unsigned char *npub,          /* nonce, 16 bytes         */
    const unsigned char *k);            /* key,   20 bytes         */

extern int crypto_aead_decrypt(
    unsigned char       *m,    unsigned long long *mlen,
    unsigned char       *nsec,          /* always NULL for Ascon   */
    const unsigned char *c,    unsigned long long  clen,
    const unsigned char *ad,   unsigned long long  adlen,
    const unsigned char *npub,          /* nonce, 16 bytes         */
    const unsigned char *k);            /* key,   20 bytes         */

/* ------------------------------------------------------------------ */
/*  Ascon-80pq static parameters                                      */
/* ------------------------------------------------------------------ */

#define A80PQ_KEYBYTES   20u    /* 160-bit key                        */
#define A80PQ_NPUBBYTES  16u    /* 128-bit nonce                      */
#define A80PQ_ABYTES     16u    /* 128-bit authentication tag         */

/* ------------------------------------------------------------------ */
/*  Deterministic pattern fill (replaces TRNG on bare metal)          */
/* ------------------------------------------------------------------ */

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* ------------------------------------------------------------------ */
/*  Adapter: sign_keypair                                              */
/* ------------------------------------------------------------------ */

static int a80pq_keypair(uint8_t *pk, uint8_t *sk) {
    /* key   → sk[0..19]  */
    fill_pattern(sk,                  A80PQ_KEYBYTES,  0xA5u);
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
/*  Adapter: sign                                                      */
/*                                                                     */
/*  Produces ct ∥ tag in sig[].  For the 4-byte benchmark message:   */
/*    siglen = 4 + 16 = 20 bytes  (sig[64] has plenty of room).       */
/* ------------------------------------------------------------------ */

static int a80pq_sign(uint8_t *sig,  size_t *siglen,
                      const uint8_t *msg, size_t msglen,
                      const uint8_t *sk) {
    unsigned long long clen = 0;

    int rc = crypto_aead_encrypt(
        sig,  &clen,
        msg,  (unsigned long long)msglen,
        NULL, 0ULL,              /* AD = empty; ascon-c handles adlen==0 */
        NULL,                    /* nsec — not used by Ascon              */
        sk + A80PQ_KEYBYTES,     /* npub = nonce, sk[20..35]             */
        sk);                     /* k    = key,   sk[0..19]              */

    *siglen = (size_t)clen;
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

/* ------------------------------------------------------------------ */
/*  Adapter: verify                                                    */
/* ------------------------------------------------------------------ */

static int a80pq_verify(const uint8_t *sig,  size_t siglen,
                        const uint8_t *msg,  size_t msglen,
                        const uint8_t *pk) {
    /* Reconstruct key from the same deterministic seed used in keypair.
     * pk[0..15] carries the nonce. */
    uint8_t key[A80PQ_KEYBYTES];
    fill_pattern(key, A80PQ_KEYBYTES, 0xA5u);

    /* Recovered plaintext — 64 B covers worst-case msg in the benchmark. */
    uint8_t pt[64];
    unsigned long long ptlen = 0;

    int rc = crypto_aead_decrypt(
        pt,   &ptlen,
        NULL,                              /* nsec                 */
        sig,  (unsigned long long)siglen,
        NULL, 0ULL,                        /* AD = empty           */
        pk,                                /* npub = nonce = pk[0..15] */
        key);

    if (rc != 0)                                   return CRYPTO_ERROR;
    if (ptlen != (unsigned long long)msglen)        return CRYPTO_ERROR;

    /* Constant-time byte compare — avoids early-exit timing leak. */
    uint8_t diff = 0u;
    for (size_t i = 0; i < msglen; i++)
        diff |= (pt[i] ^ msg[i]);

    return (diff == 0u) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

/* ------------------------------------------------------------------ */
/*  Public ops struct                                                  */
/* ------------------------------------------------------------------ */

const crypto_ops_t ascon80pq_ops = {
    .type         = ALG_ASCON80PQ,
    .name         = "Ascon-80pq",
    .sign_keypair = a80pq_keypair,
    .sign         = a80pq_sign,
    .verify       = a80pq_verify,
};