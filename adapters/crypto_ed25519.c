/* crypto_ed25519.c — Ed25519 via wolfcrypt */

#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include "core/inc/crypto_api.h"

/* sk layout (64 B): [32 B private seed | 32 B public key copy]
 * This matches wolfSSL's ED25519_PRV_KEY_SIZE and the import API.    */

static int ed25519_keypair(uint8_t *pk, uint8_t *sk) {
    if (ensure_rng() != CRYPTO_SUCCESS) return CRYPTO_ERROR;

    ed25519_key key;
    if (wc_ed25519_init(&key) != 0) return CRYPTO_ERROR;

    int ret = wc_ed25519_make_key(&s_rng, ED25519_KEY_SIZE, &key);
    if (ret != 0) { wc_ed25519_free(&key); return CRYPTO_ERROR; }

    word32 pkSz = ED25519_PUB_KEY_SIZE;     /* 32 */
    word32 skSz = ED25519_PRV_KEY_SIZE;     /* 64 */

    ret  = wc_ed25519_export_public(&key, pk, &pkSz);
    ret |= wc_ed25519_export_private(&key, sk, &skSz);
    wc_ed25519_free(&key);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int ed25519_sign(uint8_t *sig, size_t *siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *sk) {
    ed25519_key key;
    if (wc_ed25519_init(&key) != 0) return CRYPTO_ERROR;

    /* sk = [32-byte seed | 32-byte public key] */
    int ret = wc_ed25519_import_private_key(
                  sk,                    ED25519_KEY_SIZE,   /* private seed */
                  sk + ED25519_KEY_SIZE, ED25519_PUB_KEY_SIZE, /* public key */
                  &key);
    if (ret != 0) { wc_ed25519_free(&key); return CRYPTO_ERROR; }

    word32 outLen = ED25519_SIG_SIZE;   /* 64 */
    ret = wc_ed25519_sign_msg(msg, (word32)msglen, sig, &outLen, &key);
    if (siglen) *siglen = (size_t)outLen;
    wc_ed25519_free(&key);
    return (ret == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

static int ed25519_verify(const uint8_t *sig, size_t siglen,
                                 const uint8_t *msg, size_t msglen,
                                 const uint8_t *pk) {
    ed25519_key key;
    if (wc_ed25519_init(&key) != 0) return CRYPTO_ERROR;

    int ret = wc_ed25519_import_public(pk, ED25519_PUB_KEY_SIZE, &key);
    if (ret != 0) { wc_ed25519_free(&key); return CRYPTO_ERROR; }

    int verified = 0;
    ret = wc_ed25519_verify_msg(sig, (word32)siglen,
                                 msg, (word32)msglen,
                                 &verified, &key);
    wc_ed25519_free(&key);
    return (ret == 0 && verified == 1) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

const crypto_ops_t ed25519_ops = {
    .type         = ALG_ED25519,
    .name         = "Ed25519 (wolfcrypt)",
    .sign_keypair = ed25519_keypair,
    .sign         = ed25519_sign,
    .verify       = ed25519_verify,
};