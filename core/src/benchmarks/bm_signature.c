#include <stddef.h>
#include "../benchmark_config.h"
#include "../benchmark_private.h"

typedef struct {
    crypto_type_t type;
    uint16_t      pk_bytes;
    uint16_t      sk_bytes;
    uint16_t      sig_bytes;    /* worst-case or fixed output length */
} sign_size_t;

static const sign_size_t s_sign_sizes[] = {
    /*  type                      pk     sk    sig                             */
    {  ALG_WOLF_ED25519,          32,    64,    64  },  /* Ed25519             */
    {  ALG_ECDSA_P256,            65,    97,    72  },  /* DER r+s worst-case  */
    {  ALG_PQM4_DILITHIUM2,     1312,  2560,  2420  },  /* ML-DSA-44           */
    {  ALG_PQM4_FALCON512,       897,  1281,   666  },  /* FN-DSA-512          */
};
#define SIGN_SIZE_COUNT (sizeof(s_sign_sizes) / sizeof(s_sign_sizes[0]))

static const sign_size_t *lookup_sign_sizes(crypto_type_t t) {
    for (size_t i = 0u; i < SIGN_SIZE_COUNT; i++)
        if (s_sign_sizes[i].type == t) return &s_sign_sizes[i];
    return NULL;
}

#if COMPILE_WOLF_ED25519
extern const crypto_ops_t wolf_ed25519_ops;
#endif
#if COMPILE_ECDSAP256
extern const crypto_ops_t ecdsap256_ops;
#endif
#if COMPILE_PQM4_DILITHIUM2
extern const crypto_ops_t pqm4_dilithium2_ops;
#endif
#if COMPILE_PQM4_FALCON512
extern const crypto_ops_t pqm4_falcon512_ops;
#endif

static const crypto_ops_t *sign_registry[] = {
#if COMPILE_WOLF_ED25519
    &wolf_ed25519_ops,
#endif
#if COMPILE_ECDSAP256
    &ecdsap256_ops,
#endif
#if COMPILE_PQM4_DILITHIUM2
    &pqm4_dilithium2_ops,
#endif
#if COMPILE_PQM4_FALCON512
    &pqm4_falcon512_ops,
#endif
    NULL
};
#define SIGN_REGISTRY_COUNT \
    ((sizeof(sign_registry) / sizeof(sign_registry[0])) - 1u)

void execute_signature_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    /* ---- locate ops ---- */
    const crypto_ops_t *ops = NULL;
    for (size_t i = 0u; i < SIGN_REGISTRY_COUNT; i++) {
        if (sign_registry[i]->type == type) { ops = sign_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered signature algorithm !!\n"); return; }

    /* ---- exact allocation sizes for this algorithm ---- */
    const sign_size_t *sz = lookup_sign_sizes(type);
    uint16_t pk_bytes  = sz ? sz->pk_bytes  : 1312u;  /* Dilithium2 max fallback */
    uint16_t sk_bytes  = sz ? sz->sk_bytes  : 2560u;
    uint16_t sig_bytes = sz ? sz->sig_bytes : 2420u;

    uint8_t *pk  = (uint8_t *)heap_malloc((size_t)pk_bytes);
    uint8_t *sk  = (uint8_t *)heap_malloc((size_t)sk_bytes);
    uint8_t *sig = (uint8_t *)heap_malloc((size_t)sig_bytes);

    if (!pk || !sk || !sig) {
        platform_print_string("!! Heap OOM in signature benchmark !!\n");
        return;
    }

    size_t  siglen = 0u;
    uint8_t msg[4] = {0x01u, 0x02u, 0x03u, 0x04u};

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    uint32_t s, e;

    s = get_cycles(); ops->sign_keypair(pk, sk);               e = get_cycles();
    p_cy("   Keygen: ", CYCLE_DELTA(s, e));

    s = get_cycles(); ops->sign(sig, &siglen, msg, 4u, sk);    e = get_cycles();
    p_cy("   Sign:   ", CYCLE_DELTA(s, e));

    s = get_cycles(); ops->verify(sig, siglen, msg, 4u, pk);   e = get_cycles();
    p_cy("   Verify: ", CYCLE_DELTA(s, e));

    print_memory_report(type);
}

void run_signature_benchmarks(void) {
    if (SIGN_REGISTRY_COUNT > 0u) {
        platform_print_string("[Signature]\n");
        for (size_t i = 0u; i < SIGN_REGISTRY_COUNT; i++)
            execute_signature_benchmark(sign_registry[i]->type);
    }
}