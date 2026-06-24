#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/*  Algorithm type tags                                                */
/* ------------------------------------------------------------------ */

typedef enum {
    /* Signature / authentication */
    ALG_CLASSICAL_ECC,
    ALG_LIGHTWEIGHT_ASCON,
    ALG_PHOTON_BEETLE,
    ALG_PQC_SIGN,
    ALG_HYBRID_SIGN,
    /* Key encapsulation */
    ALG_PQC_KEM,
    ALG_HYBRID_KEM,
    /* Symmetric AEAD */
    ALG_AES_GCM,
    ALG_CHACHA20_POLY1305,
    /* Key derivation */
    ALG_HKDF,
} crypto_type_t;

#define CRYPTO_SUCCESS  0
#define CRYPTO_ERROR   -1

/* ------------------------------------------------------------------ */
/*  Signing / verification ops                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    crypto_type_t  type;
    const char    *name;
    int (*sign_keypair)(uint8_t *pk, uint8_t *sk);
    int (*sign)(uint8_t *sig, size_t *siglen,
                const uint8_t *msg, size_t msglen,
                const uint8_t *sk);
    int (*verify)(const uint8_t *sig, size_t siglen,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *pk);
} crypto_ops_t;

/* ------------------------------------------------------------------ */
/*  Symmetric AEAD ops                                                 */
/*                                                                     */
/*  keygen  – populate key[key_bytes] and nonce[nonce_bytes]          */
/*  encrypt – write ciphertext || tag into ct; set *ctlen             */
/*            = ptlen + tag_bytes                                      */
/*  decrypt – write recovered plaintext into pt; set *ptlen           */
/*            = ctlen - tag_bytes; return CRYPTO_ERROR on tag fail    */
/* ------------------------------------------------------------------ */

typedef struct {
    crypto_type_t  type;
    const char    *name;
    size_t         key_bytes;    /* key length in bytes              */
    size_t         nonce_bytes;  /* nonce / IV length in bytes       */
    size_t         tag_bytes;    /* authentication tag length        */
    int (*init)(void);
    int (*keygen)(uint8_t *key, uint8_t *nonce);
    int (*encrypt)(uint8_t *ct,   size_t *ctlen,
                   const uint8_t *pt,    size_t ptlen,
                   const uint8_t *ad,    size_t adlen,
                   const uint8_t *nonce,
                   const uint8_t *key);
    int (*decrypt)(uint8_t *pt,   size_t *ptlen,
                   const uint8_t *ct,    size_t ctlen,
                   const uint8_t *ad,    size_t adlen,
                   const uint8_t *nonce,
                   const uint8_t *key);
} crypto_aead_ops_t;

/* ------------------------------------------------------------------ */
/*  Key-derivation ops (extract-then-expand, e.g. HKDF)              */
/*                                                                     */
/*  derive – okm_len bytes into okm                                   */
/*           ikm   = input key material (e.g. raw shared secret)     */
/*           salt  = optional salt; NULL → zero-length treated as    */
/*                   algorithm-specific zero vector                   */
/*           info  = optional context label; NULL → zero-length      */
/* ------------------------------------------------------------------ */

typedef struct {
    crypto_type_t  type;
    const char    *name;
    int (*derive)(uint8_t       *okm,  size_t okm_len,
                  const uint8_t *ikm,  size_t ikm_len,
                  const uint8_t *salt, size_t salt_len,
                  const uint8_t *info, size_t info_len);
} crypto_kdf_ops_t;

/* ------------------------------------------------------------------ */
/*  Measurement utilities (defined in core/src/benchmark_runner.c)   */
/* ------------------------------------------------------------------ */

void     fill_stack_watermark(void);
void     reset_stack_watermark(void);
uint32_t measure_stack_used(void);
uint32_t measure_static_ram(void);

/* ------------------------------------------------------------------ */
/*  Benchmark entry points                                             */
/* ------------------------------------------------------------------ */

void execute_signature_benchmark(crypto_type_t type);
void execute_aead_benchmark(crypto_type_t type);
void execute_kdf_benchmark(crypto_type_t type);

void heap_reset(void);

#endif /* CRYPTO_API_H */
