#include <wolfssl/wolfcrypt/curve25519.h>
#include "core/inc/crypto_api.h"

#define X25519_PRIV_SIZE  CURVE25519_KEYSIZE   /* 32 */
#define X25519_PUB_SIZE   CURVE25519_KEYSIZE   /* 32 */
#define X25519_SS_SIZE    CURVE25519_KEYSIZE   /* 32 */

static int x25519_keypair(uint8_t *pk, uint8_t *sk)
{
    WC_RNG *rng = platform_rng_handle();
    if (!rng) return CRYPTO_ERROR;

    curve25519_key key;
    if (wc_curve25519_init(&key) != 0) return CRYPTO_ERROR;

    int ret = wc_curve25519_make_key(rng, X25519_PRIV_SIZE, &key);
    if (ret != 0) { wc_curve25519_free(&key); return CRYPTO_ERROR; }

    word32 pkSz = X25519_PUB_SIZE;
    word32 skSz = X25519_PRIV_SIZE;

    ret  = wc_curve25519_export_public(&key, pk, &pkSz);
    ret |= wc_curve25519_export_private_raw(&key, sk, &skSz);

    if (ret == 0) {
        /* sk = [32-byte private | 32-byte public copy] */
        const uint8_t *src = pk;
        uint8_t       *dst = sk + X25519_PRIV_SIZE;
        for (word32 i = 0; i < pkSz; i++) dst[i] = src[i];
    }

    wc_curve25519_free(&key);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int x25519_shared_secret(uint8_t *ss,
                                const uint8_t *peer_pk,
                                const uint8_t *sk)
{
    curve25519_key priv_key, pub_key;
    int ret;

    if (wc_curve25519_init(&priv_key) != 0) return CRYPTO_ERROR;
    if (wc_curve25519_init(&pub_key)  != 0) {
        wc_curve25519_free(&priv_key);
        return CRYPTO_ERROR;
    }
    ret = wc_curve25519_import_private(sk, X25519_PRIV_SIZE, &priv_key);
    if (ret != 0) goto cleanup;

    ret = wc_curve25519_import_public(sk + X25519_PRIV_SIZE, X25519_PUB_SIZE,
                                      &priv_key);
    if (ret != 0) goto cleanup;
    
    ret = wc_curve25519_import_public(peer_pk, X25519_PUB_SIZE, &pub_key);
    if (ret != 0) goto cleanup;

    word32 ssLen = X25519_SS_SIZE;
    ret = wc_curve25519_shared_secret(&priv_key, &pub_key, ss, &ssLen);

cleanup:
    wc_curve25519_free(&priv_key);
    wc_curve25519_free(&pub_key);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_kex_ops_t x25519_ops = {
    .type          = ALG_X25519,
    .name          = "X25519 (wolfcrypt)",
    .keygen        = x25519_keypair,
    .shared_secret = x25519_shared_secret,
};