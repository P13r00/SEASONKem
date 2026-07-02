#include <string.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include "core/inc/crypto_api.h"

#define ECC_P256_KEY_SIZE      32
#define ECC_P256_PUB_KEY_SIZE  65

static int ecdsap256_keypair(uint8_t *pk, uint8_t *sk) 
{
    WC_RNG *rng = platform_rng_handle();
    if (!rng) return CRYPTO_ERROR;

    ecc_key key;
    if (wc_ecc_init(&key) != 0) return CRYPTO_ERROR;

    int ret = wc_ecc_make_key(rng, ECC_P256_KEY_SIZE, &key);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    word32 pkLen = ECC_P256_PUB_KEY_SIZE;
    ret = wc_ecc_export_x963(&key, pk, &pkLen);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    word32 skLen = ECC_P256_KEY_SIZE;
    ret = wc_ecc_export_private_only(&key, sk, &skLen);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    memcpy(sk + ECC_P256_KEY_SIZE, pk, ECC_P256_PUB_KEY_SIZE);

    wc_ecc_free(&key);
    return CRYPTO_SUCCESS;
}

static int ecdsap256_sign(uint8_t *sig, size_t *siglen,
                         const uint8_t *msg, size_t msglen,
                         const uint8_t *sk) 
{
    WC_RNG *rng = platform_rng_handle();
    if (!rng) return CRYPTO_ERROR;

    ecc_key key;
    if (wc_ecc_init(&key) != 0) return CRYPTO_ERROR;

    int ret = wc_ecc_import_private_key(sk, ECC_P256_KEY_SIZE,
                                        sk + ECC_P256_KEY_SIZE, ECC_P256_PUB_KEY_SIZE,
                                        &key);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    Sha256 sha;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    if (wc_InitSha256(&sha) != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }
    wc_Sha256Update(&sha, msg, (word32)msglen);
    wc_Sha256Final(&sha, hash);

    word32 outLen = wc_ecc_sig_size(&key);
    ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &outLen, rng, &key);
    if (siglen) *siglen = (size_t)outLen;

    wc_ecc_free(&key);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int ecdsap256_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *msg, size_t msglen,
                           const uint8_t *pk) 
{
    ecc_key key;
    if (wc_ecc_init(&key) != 0) return CRYPTO_ERROR;

    int ret = wc_ecc_import_x963(pk, ECC_P256_PUB_KEY_SIZE, &key);
    if (ret != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }

    Sha256 sha;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    if (wc_InitSha256(&sha) != 0) { wc_ecc_free(&key); return CRYPTO_ERROR; }
    wc_Sha256Update(&sha, msg, (word32)msglen);
    wc_Sha256Final(&sha, hash);

    int stat = 0;
    ret = wc_ecc_verify_hash(sig, (word32)siglen, hash, sizeof(hash), &stat, &key);

    wc_ecc_free(&key);
    return (ret == 0 && stat == 1) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_ops_t ecdsap256_ops = {
    .name         = "ECDSA P-256 (wolfcrypt)",
    .type         = ALG_ECDSA_P256,
    .sign_keypair = ecdsap256_keypair,
    .sign         = ecdsap256_sign,
    .verify       = ecdsap256_verify,
};