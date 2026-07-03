#include <stddef.h>
#include "../benchmark_config.h"
#include "../benchmark_private.h"

#if COMPILE_AES_GCM
extern const crypto_aead_ops_t aes_gcm_ops;
#endif
#if COMPILE_ASCON80
extern const crypto_aead_ops_t ascon80pq_ops;
#endif
#if COMPILE_ASCON_AEAD128
extern const crypto_aead_ops_t asconaead128_ops;
#endif
#if COMPILE_CHACHA20_POLY1305
extern const crypto_aead_ops_t chacha20_poly1305_ops;
#endif
#if COMPILE_LWC_SPARKLE_AEAD256
extern const crypto_aead_ops_t lwc_sparkle_aead256_ops;
#endif
#if COMPILE_LWC_SPARKLE_AEAD192
extern const crypto_aead_ops_t lwc_sparkle_aead192_ops;
#endif
#if COMPILE_LWC_ASCON80PQ_AEAD
extern const crypto_aead_ops_t lwc_ascon80pq_aead_ops;
#endif

static const crypto_aead_ops_t *aead_registry[] = {
#if COMPILE_AES_GCM
    &aes_gcm_ops,
#endif
#if COMPILE_ASCON80
    &ascon80pq_ops,
#endif
#if COMPILE_ASCON_AEAD128
    &asconaead128_ops,
#endif
#if COMPILE_CHACHA20_POLY1305
    &chacha20_poly1305_ops,
#endif
#if COMPILE_LWC_SPARKLE_AEAD256
    &lwc_sparkle_aead256_ops,
#endif
#if COMPILE_LWC_SPARKLE_AEAD192
    &lwc_sparkle_aead192_ops,
#endif
#if COMPILE_LWC_ASCON80PQ_AEAD
    &lwc_ascon80pq_aead_ops,
#endif
    NULL
};
#define AEAD_REGISTRY_COUNT \
    ((sizeof(aead_registry) / sizeof(aead_registry[0])) - 1u)

#define AEAD_MSG_LEN  128u
#define AEAD_AD_LEN   0u

void execute_aead_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_aead_ops_t *ops = NULL;
    for (size_t i = 0u; i < AEAD_REGISTRY_COUNT; i++) {
        if (aead_registry[i]->type == type) { ops = aead_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered AEAD algorithm !!\n"); return; }

    if (ops->init && ops->init() != CRYPTO_SUCCESS) {
        platform_print_string("!! AEAD init failed !!\n");
        return;
    }

    uint8_t *key   = (uint8_t *)heap_malloc(ops->key_bytes);
    uint8_t *nonce = (uint8_t *)heap_malloc(ops->nonce_bytes);
    uint8_t *pt    = (uint8_t *)heap_malloc(AEAD_MSG_LEN);
    uint8_t *ad    = (uint8_t *)heap_malloc(AEAD_AD_LEN);
    uint8_t *ct    = (uint8_t *)heap_malloc(AEAD_MSG_LEN + ops->tag_bytes);
    uint8_t *pt2   = (uint8_t *)heap_malloc(AEAD_MSG_LEN);

    if (!key || !nonce || !pt || !ad || !ct || !pt2) {
        platform_print_string("!! Heap OOM in AEAD benchmark !!\n");
        return;
    }

    for (size_t i = 0u; i < AEAD_MSG_LEN; i++) pt[i] = (uint8_t)i;
    for (size_t i = 0u; i < AEAD_AD_LEN;  i++) ad[i] = (uint8_t)(0xA0u | i);

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    uint64_t total_keygen  = 0;
    uint64_t total_encrypt = 0;
    uint64_t total_decrypt = 0;
    uint32_t s, e;
    size_t ctlen = 0u, ptlen = 0u;
    int rc = CRYPTO_SUCCESS;

    for (uint32_t r = 0; r < RUNS_AEAD; r++) {
        s = get_cycles(); ops->keygen(key, nonce); e = get_cycles();
        total_keygen += CYCLE_DELTA(s, e);

        s = get_cycles(); ops->encrypt(ct, &ctlen, pt, AEAD_MSG_LEN, ad, AEAD_AD_LEN, nonce, key); e = get_cycles();
        total_encrypt += CYCLE_DELTA(s, e);

        s = get_cycles(); rc = ops->decrypt(pt2, &ptlen, ct, ctlen, ad, AEAD_AD_LEN, nonce, key); e = get_cycles();
        total_decrypt += CYCLE_DELTA(s, e);
    }

    p_cy_avg("   Keygen:  ", total_keygen, RUNS_AEAD);
    p_cy_avg("   Encrypt: ", total_encrypt, RUNS_AEAD);

    platform_print_string("   Decrypt: ");
    platform_print_number((uint32_t)(total_decrypt / RUNS_AEAD));
    platform_print_string(rc == CRYPTO_SUCCESS ? " cy (avg) [OK]\n" : " cy (avg) [TAG FAIL]\n");

    print_memory_report(type);
}

void run_aead_benchmarks(void) {
    if (AEAD_REGISTRY_COUNT > 0u) {
        platform_print_string("[Symmetric AEAD]\n");
        for (size_t i = 0u; i < AEAD_REGISTRY_COUNT; i++)
            execute_aead_benchmark(aead_registry[i]->type);
    }
}