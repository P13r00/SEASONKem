#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

int platform_rng_init(void);
int platform_rng_generate(uint8_t *buf, size_t len);

typedef enum {
    ALG_CHACHA20_POLY1305,
    ALG_AES_GCM192,
    ALG_AES_GCM256,
    ALG_PQM4_DILITHIUM2,
    ALG_WOLF_ED25519,
    ALG_PQM4_FALCON512,
    ALG_PQM4_KYBER512,
    ALG_PQM4_KYBER768,
    ALG_SHAKE256,
    ALG_X25519,
    ALG_PQM4_SHA3_256,
    ALG_PQM4_SHAKE256,
    ALG_LWC_SPARKLE_AEAD256,
    ALG_LWC_SPARKLE_AEAD192,
    ALG_LWC_SPARKLE_AEAD128,
    ALG_LWC_SPARKLE_HASHXOF256,
    ALG_LWC_SPARKLE_HASHXOF384,
    ALG_LWC_SPARKLE_HASH256,
    ALG_LWC_SPARKLE_HASH384,
    ALG_LWC_XOODYAK_HASH,
    ALG_LWC_ASCON80PQ_AEAD,
    ALG_LWC_ASCON128_AEAD,
    ALG_LWC_ASCON_HASHXOF,
    ALG_LWC_ASCON_HASH256,
    ALG_LWC_XOODYAK_AEAD,
    ALG_XWING,
    ALG_SEASON0,
    ALG_SPRING,
    ALG_SUMMER,
    ALG_AUTUMN,
    ALG_WINTER
} crypto_type_t;

#define CRYPTO_SUCCESS  0
#define CRYPTO_ERROR   -1


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


typedef struct {
    crypto_type_t  type;
    const char    *name;
    size_t         key_bytes;
    size_t         nonce_bytes;
    size_t         tag_bytes;
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

typedef struct {
    crypto_type_t type;
    const char    *name;
    
    bool   is_xof;
    size_t default_outlen;

    int (*hash)(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
    
    int (*init)(void *ctx);
    int (*absorb)(void *ctx, const uint8_t *in, size_t inlen);
    int (*finalize)(uint8_t *out, size_t outlen, void *ctx); 
    int (*clone)(void *dst, const void *src);
    int (*release)(void *ctx);
} crypto_hash_ops_t;


typedef struct {
    crypto_type_t  type;
    const char    *name;
    int (*keygen)(uint8_t *pk, uint8_t *sk);
    int (*encaps)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*decaps)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
} crypto_kem_ops_t;


typedef struct {
    crypto_type_t  type;
    const char    *name;
    int (*keygen)(uint8_t *pk, uint8_t *sk);
    int (*shared_secret)(uint8_t *ss, const uint8_t *peer_pk, const uint8_t *sk);
} crypto_kex_ops_t;


typedef struct WC_RNG WC_RNG;
WC_RNG *platform_rng_handle(void);


void     heap_reset(void);
void    *heap_malloc(size_t size);
uint32_t heap_peak_used(void);
uint32_t heap_current_used(void);
uint32_t heap_capacity(void);


void     fill_stack_watermark(void);
void     reset_stack_watermark(void);
uint32_t measure_stack_used(void);
uint32_t measure_stack_capacity(void);
uint32_t measure_static_ram(void);


uint32_t measure_algo_flash(crypto_type_t type);


void platform_print_string(const char *str);
void platform_print_number(uint32_t num);


void platform_print_hex(uint32_t val);


void execute_signature_benchmark(crypto_type_t type);
void execute_aead_benchmark(crypto_type_t type);
void execute_kem_benchmark(crypto_type_t type);
void execute_kex_benchmark(crypto_type_t type);

#endif
