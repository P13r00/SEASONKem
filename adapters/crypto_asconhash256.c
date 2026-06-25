/*
 * adapters/crypto_asconhash256.c
 *
 * Adapter: Ascon-Hash-256 → crypto_ops_t (sign/verify interface).
 *
 * Ascon-Hash (NIST LWC):
 *   Output : 32 bytes  (CRYPTO_BYTES = 256-bit digest)
 *   Input  : arbitrary-length byte string
 *   Rounds : p^12 initialisation, p^8 absorb, p^12 squeeze (Ascon-Hash)
 *
 * Ascon-Hash is unkeyed, so we derive a MAC via a prefix construction:
 *
 *   sign(sk, msg)  = Hash(sk[0..31] ∥ msg)   →  32-byte tag  (siglen = 32)
 *   verify(pk,msg) = Hash(pk[0..31] ∥ msg) == sig  (constant-time cmp)
 *
 * This is a standard prefix-MAC; security holds as long as sk is secret
 * and Ascon-Hash is collision-resistant (both hold per the NIST submission).
 *
 * Buffer layout (matches execute_signature_benchmark allocations):
 *   sk[0..31] = 32-byte "key"  (deterministic fill; replace with RNG)
 *   pk[0..31] = copy of sk     (used verbatim in verify)
 *   sig[0..31]= 32-byte digest (siglen = 32;  sig[64] has room)
 *
 * Scratch buffer in sign/verify:
 *   buf[128] = sk/pk (32 B) ∥ msg (≤96 B) — stack allocated.
 *   The 4-byte benchmark message makes the actual peak 36 B.
 *
 * ARMv7-M path:
 *   The armv7m-optimised Ascon permutation (Thumb-2 assembly) is compiled
 *   from third_party/ascon-c/crypto_hash/asconhash/armv7m/ and linked
 *   in via CMakeLists.txt.  Required sources:
 *     hash.c          – crypto_hash()
 *     permutations.S  – ascon_permutation_{8,12} in Thumb-2
 *   or permutations.c if your copy has no .S variant.
 *
 *   CMake snippet:
 *     set(ASCONHASH_DIR third_party/ascon-c/crypto_hash/asconhash/armv7m)
 *     target_sources(cryptoBenchmark PRIVATE
 *         ${ASCONHASH_DIR}/hash.c
 *         ${ASCONHASH_DIR}/permutations.c   # or .S
 *     )
 *     target_include_directories(cryptoBenchmark PRIVATE ${ASCONHASH_DIR})
 *
 * Note: crypto_hash (asconhash) and crypto_aead_encrypt (ascon80pq) are
 * distinct symbols — no clash when both adapters are linked together.
 *
 * benchmark_runner.c change needed (if scheduling ALG_ASCON_HASH_256):
 *   extern const crypto_ops_t asconhash256_ops;   // add extern
 *   static const crypto_ops_t *sign_registry[] = {
 *       &ed25519_ops,
 *       &ascon80pq_ops,
 *       &asconhash256_ops,                        // add entry
 *   };
 */

#include <stdint.h>
#include <stddef.h>
#include "core/inc/crypto_api.h"

/* ------------------------------------------------------------------ */
/*  Ascon-Hash API (NIST LWC / ascon-c naming convention)            */
/*  Resolved at link time from the armv7m hash.c object.             */
/* ------------------------------------------------------------------ */

extern int crypto_hash(
    unsigned char       *out,           /* 32-byte digest output     */
    const unsigned char *in,            /* input message             */
    unsigned long long   inlen);        /* input length in bytes     */

/* ------------------------------------------------------------------ */
/*  Ascon-Hash static parameters                                      */
/* ------------------------------------------------------------------ */

#define AHASH256_BYTES    32u   /* digest size (CRYPTO_BYTES)         */
#define AHASH256_MAX_MSG  96u   /* guard: max msg in sign/verify      */

/* ------------------------------------------------------------------ */
/*  Deterministic pattern fill (replaces TRNG on bare metal)          */
/* ------------------------------------------------------------------ */

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* ------------------------------------------------------------------ */
/*  Adapter: sign_keypair                                              */
/*                                                                     */
/*  sk[0..31] = 32-byte key (deterministic)                           */
/*  pk[0..31] = copy of sk (verify runs from pk alone)                */
/* ------------------------------------------------------------------ */

static int ahash256_keypair(uint8_t *pk, uint8_t *sk) {
    fill_pattern(sk, AHASH256_BYTES, 0xB3u);
    for (size_t i = 0; i < AHASH256_BYTES; i++)
        pk[i] = sk[i];
    return CRYPTO_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Adapter: sign                                                      */
/*                                                                     */
/*  Computes Hash(sk[0..31] ∥ msg) into sig[0..31].                  */
/*  siglen = 32 always.                                                */
/*                                                                     */
/*  Stack cost: buf[128] = 128 B  (key prefix + msg + sentinel guard) */
/* ------------------------------------------------------------------ */

static int ahash256_sign(uint8_t *sig,  size_t *siglen,
                         const uint8_t *msg, size_t msglen,
                         const uint8_t *sk) {
    if (msglen > AHASH256_MAX_MSG)
        return CRYPTO_ERROR;

    /* Concatenate key ∥ msg on the stack */
    uint8_t buf[AHASH256_BYTES + AHASH256_MAX_MSG];
    for (size_t i = 0; i < AHASH256_BYTES; i++)
        buf[i] = sk[i];
    for (size_t i = 0; i < msglen; i++)
        buf[AHASH256_BYTES + i] = msg[i];

    int rc = crypto_hash(sig, buf,
                         (unsigned long long)(AHASH256_BYTES + msglen));
    *siglen = AHASH256_BYTES;
    return (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

/* ------------------------------------------------------------------ */
/*  Adapter: verify                                                    */
/*                                                                     */
/*  Recomputes Hash(pk[0..31] ∥ msg) and compares to sig in          */
/*  constant time (XOR accumulator — no early exit).                  */
/* ------------------------------------------------------------------ */

static int ahash256_verify(const uint8_t *sig,  size_t siglen,
                           const uint8_t *msg,  size_t msglen,
                           const uint8_t *pk) {
    if (siglen != AHASH256_BYTES)   return CRYPTO_ERROR;
    if (msglen > AHASH256_MAX_MSG)  return CRYPTO_ERROR;

    uint8_t buf[AHASH256_BYTES + AHASH256_MAX_MSG];
    for (size_t i = 0; i < AHASH256_BYTES; i++)
        buf[i] = pk[i];
    for (size_t i = 0; i < msglen; i++)
        buf[AHASH256_BYTES + i] = msg[i];

    uint8_t digest[AHASH256_BYTES];
    int rc = crypto_hash(digest, buf,
                         (unsigned long long)(AHASH256_BYTES + msglen));
    if (rc != 0) return CRYPTO_ERROR;

    /* Constant-time comparison */
    uint8_t diff = 0u;
    for (size_t i = 0; i < AHASH256_BYTES; i++)
        diff |= (digest[i] ^ sig[i]);

    return (diff == 0u) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

/* ------------------------------------------------------------------ */
/*  Public ops struct                                                  */
/* ------------------------------------------------------------------ */

const crypto_ops_t asconhash256_ops = {
    .type         = ALG_ASCON_HASH_256,
    .name         = "Ascon-Hash-256",
    .sign_keypair = ahash256_keypair,
    .sign         = ahash256_sign,
    .verify       = ahash256_verify,
};