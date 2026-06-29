/* crypto_ecc_p256.c — ECDSA P-256 via wolfcrypt */

#include <string.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

/* One RNG instance shared across keygen calls.
 * Initialised on first keygen; wolfcrypt's ChaCha20-DRBG is seeded
 * by our wc_GenerateSeed stub in rng_stub.c.                         */
static WC_RNG s_rng;
static int    s_rng_ready = 0;

static int ensure_rng(void) {
    if (!s_rng_ready) {
        if (wc_InitRng(&s_rng) != 0) return CRYPTO_ERROR;
        s_rng_ready = 1;
    }
    return CRYPTO_SUCCESS;
}

#define ECC_P256_KEY_SIZE      32   /* 32 B scalar private key */
#define ECC_P256_PUB_KEY_SIZE  65   /* 65 B ANSI X9.63 uncompressed public key: [0x04 | X-coord | Y-coord] */

/* sk layout (97 B): [32 B private key scalar | 65 B public key copy]
 * This aligns with standard practices of appending public components to private structures
 * to make signature operations self-contained without needing standalone parsing. */

static int ecdsap256_keypair(uint8_t *pk, uint8_t *sk) {
    if (ensure_rng() != CRYPTO_SUCCESS) return CRYPTO_ERROR;

    ecc_key key;
    if (wc_ecc_init(&key) != 0) return CRYPTO_ERROR;

    /* Passing 32 (bytes) informs wolfCrypt to generate a key for the 256-bit SECP256R1 curve */
    int ret = wc_ecc_make_key(&s_rng, ECC_P256_KEY_SIZE, &key);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    /* Export the public key point format (X9.63 uncompressed) */
    word32 pkLen = ECC_P256_PUB_KEY_SIZE;
    ret = wc_ecc_export_x963(&key, pk, &pkLen);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    /* Export only the raw 32-byte private scalar component */
    word32 skLen = ECC_P256_KEY_SIZE;
    ret = wc_ecc_export_private_only(&key, sk, &skLen);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    /* Append the public key directly behind the private key inside the sk buffer */
    memcpy(sk + ECC_P256_KEY_SIZE, pk, ECC_P256_PUB_KEY_SIZE);

    wc_ecc_free(&key);
    return CRYPTO_SUCCESS;
}

static int ecdsap256_sign(uint8_t *sig, size_t *siglen,
                         const uint8_t *msg, size_t msglen,
                         const uint8_t *sk) {
    if (ensure_rng() != CRYPTO_SUCCESS) return CRYPTO_ERROR;

    ecc_key key;
    if (wc_ecc_init(&key) != 0) return CRYPTO_ERROR;

    /* Import both components from our packed private key layout */
    int ret = wc_ecc_import_private_key(sk, ECC_P256_KEY_SIZE,
                                        sk + ECC_P256_KEY_SIZE, ECC_P256_PUB_KEY_SIZE,
                                        &key);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    /* ECDSA requires hashing the message data prior to math execution */
    Sha256 sha;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    if (wc_InitSha256(&sha) != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }
    wc_Sha256Update(&sha, msg, (word32)msglen);
    wc_Sha256Final(&sha, hash);

    /* Fetch worst-case upper bound length for a DER-encoded ECDSA signature */
    word32 outLen = wc_ecc_sig_size(&key);
    
    ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &outLen, &s_rng, &key);
    if (siglen) *siglen = (size_t)outLen;

    wc_ecc_free(&key);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int ecdsap256_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *msg, size_t msglen,
                           const uint8_t *pk) {
    ecc_key key;
    if (wc_ecc_init(&key) != 0) return CRYPTO_ERROR;

    /* Load the uncompressed public key point */
    int ret = wc_ecc_import_x963(pk, ECC_P256_PUB_KEY_SIZE, &key);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    /* Hash raw incoming buffer verification payload matching signer parameters */
    Sha256 sha;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    if (wc_InitSha256(&sha) != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }
    wc_Sha256Update(&sha, msg, (word32)msglen);
    wc_Sha256Final(&sha, hash);

    int stat = 0;
    ret = wc_ecc_verify_hash(sig, (word32)siglen, hash, sizeof(hash), &stat, &key);
    
    wc_ecc_free(&key);
    
    /* wc_ecc_verify_hash returns 0 on execution success; 
     * verify validity status via 'stat' parameter (1 = Valid, 0 = Invalid) */
    return (ret == 0 && stat == 1) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_ops_t ecdsap256_ops = {
    .name         = "ECDSA P-256 (wolfcrypt)",
    .type         = ALG_ECDSA_P256,
    .sign_keypair = ecdsap256_keypair,
    .sign         = ecdsap256_sign,
    .verify       = ecdsap256_verify,
};