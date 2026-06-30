#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <stdint.h>
#include <stddef.h>

int platform_rng_init(void);
int platform_rng_generate(uint8_t *buf, size_t len);

typedef enum {
    ALG_AES_GCM,
    ALG_ASCON80PQ,
    ALG_ASCON_AEAD128,
    ALG_ASCON_HASH256,
    ALG_ASCON_XOF,
    ALG_BLAKE3,
    ALG_CHACHA20_POLY1305,
    ALG_DILITHIUM2,
    ALG_ECDH_P256,
    ALG_ECDSA_P256,
    ALG_ED25519,
    ALG_FALCON,
    ALG_HKDF_SHA256,
    ALG_HYBRID_KEX,
    ALG_HYBRID_SIGN,
    ALG_KYBER512,
    ALG_KYBER768,
    ALG_PHOTON_BEETLE_AEAD,
    ALG_SHAKE256,
    ALG_X25519
} crypto_type_t;

#define CRYPTO_SUCCESS  0
#define CRYPTO_ERROR   -1

// Signing / verification ops
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

/*
Symmetric AEAD ops
keygen  – populate key[key_bytes] and nonce[nonce_bytes]
encrypt – write ciphertext || tag into ct; set *ctlen
          = ptlen + tag_bytes
decrypt – write recovered plaintext into pt; set *ptlen
          = ctlen - tag_bytes; return CRYPTO_ERROR on tag fail
*/

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


/*
Key-derivation ops
derive – okm_len bytes into okm
         ikm   = input key material
         salt  = optional salt; NULL → zero-length
         info  = optional context label; NULL → zero-length
*/

typedef struct {
    crypto_type_t  type;
    const char    *name;
    int (*derive)(uint8_t       *okm,  size_t okm_len,
                  const uint8_t *ikm,  size_t ikm_len,
                  const uint8_t *salt, size_t salt_len,
                  const uint8_t *info, size_t info_len);
} crypto_kdf_ops_t;


// Key Encapsulation Mechanism (KEM) ops

typedef struct {
    crypto_type_t  type;
    const char    *name;
    int (*keygen)(uint8_t *pk, uint8_t *sk);
    int (*encaps)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*decaps)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
} crypto_kem_ops_t;


//  Key Exchange (KEX) ops


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
void execute_kdf_benchmark(crypto_type_t type);
void execute_kem_benchmark(crypto_type_t type);
void execute_kex_benchmark(crypto_type_t type);

#endif
