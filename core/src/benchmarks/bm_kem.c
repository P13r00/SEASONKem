#include <stddef.h>
#include "../benchmark_config.h"
#include "../benchmark_private.h"

typedef struct {
    crypto_type_t type;
    uint16_t      pk_bytes;
    uint16_t      sk_bytes;
    uint16_t      ct_bytes;
    uint16_t      ss_bytes;
} kem_size_t;

static const kem_size_t s_kem_sizes[] = {
    {  ALG_PQM4_KYBER512,   800,  1632,   768,   32  },
    {  ALG_PQM4_KYBER768,  1184,  2400,  1088,   32  },
    {  ALG_XWING,          1216,  2464,  1120,   32  },
    {  ALG_FLEXWING0,       832,  1696,   800,   32  },
    {  ALG_FLEXWING1,       832,  1696,   800,   32  },
    {  ALG_FLEXWING2,       832,  1696,   800,   32  },
    {  ALG_FLEXWING3,       832,  1696,   800,   32  },
};
#define KEM_SIZE_COUNT (sizeof(s_kem_sizes) / sizeof(s_kem_sizes[0]))

static const kem_size_t *lookup_kem_sizes(crypto_type_t t) {
    for (size_t i = 0u; i < KEM_SIZE_COUNT; i++)
        if (s_kem_sizes[i].type == t) return &s_kem_sizes[i];
    return NULL;
}

#if COMPILE_PQM4_KYBER512
extern const crypto_kem_ops_t pqm4_kyber512_ops;
#endif
#if COMPILE_PQM4_KYBER768
extern const crypto_kem_ops_t pqm4_kyber768_ops;
#endif
#if COMPILE_XWING
extern const crypto_kem_ops_t xwing_ops;
#endif
#if COMPILE_FLEXWING0
extern const crypto_kem_ops_t flexwing0_ops;
#endif
#if COMPILE_FLEXWING1
extern const crypto_kem_ops_t flexwing1_ops;
#endif
#if COMPILE_FLEXWING2
extern const crypto_kem_ops_t flexwing2_ops;
#endif
#if COMPILE_FLEXWING3
extern const crypto_kem_ops_t flexwing3_ops;
#endif

static const crypto_kem_ops_t *kem_registry[] = {
#if COMPILE_PQM4_KYBER512
    &pqm4_kyber512_ops,
#endif
#if COMPILE_PQM4_KYBER768
    &pqm4_kyber768_ops,
#endif
#if COMPILE_XWING
    &xwing_ops,
#endif
#if COMPILE_FLEXWING0
    &flexwing0_ops,
#endif
#if COMPILE_FLEXWING1
    &flexwing1_ops,
#endif
#if COMPILE_FLEXWING2
    &flexwing2_ops,
#endif
#if COMPILE_FLEXWING3
    &flexwing3_ops,
#endif
    NULL
};

#define KEM_REGISTRY_COUNT \
    ((sizeof(kem_registry) / sizeof(kem_registry[0])) - 1u)

void execute_kem_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_kem_ops_t *ops = NULL;
    for (size_t i = 0u; i < KEM_REGISTRY_COUNT; i++) {
        if (kem_registry[i]->type == type) { ops = kem_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered KEM algorithm !!\n"); return; }

    const kem_size_t *sz = lookup_kem_sizes(type);
    uint16_t pk_bytes = sz ? sz->pk_bytes : 1216u;
    uint16_t sk_bytes = sz ? sz->sk_bytes : 2464u;
    uint16_t ct_bytes = sz ? sz->ct_bytes : 1120u;
    uint16_t ss_bytes = sz ? sz->ss_bytes :   32u;

    uint8_t *pk     = (uint8_t *)heap_malloc((size_t)pk_bytes);
    uint8_t *sk     = (uint8_t *)heap_malloc((size_t)sk_bytes);
    uint8_t *ct     = (uint8_t *)heap_malloc((size_t)ct_bytes);
    uint8_t *ss_enc = (uint8_t *)heap_malloc((size_t)ss_bytes);
    uint8_t *ss_dec = (uint8_t *)heap_malloc((size_t)ss_bytes);

    if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
        platform_print_string("!! Heap OOM in KEM benchmark !!\n");
        return;
    }

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    uint64_t total_keygen = 0;
    uint64_t total_encaps = 0;
    uint64_t total_decaps = 0;
    uint32_t s, e;

    for (uint32_t r = 0; r < RUNS_KEM; r++) {
        s = get_cycles(); ops->keygen(pk, sk);          e = get_cycles();
        total_keygen += CYCLE_DELTA(s, e);

        s = get_cycles(); ops->encaps(ct, ss_enc, pk);  e = get_cycles();
        total_encaps += CYCLE_DELTA(s, e);

        s = get_cycles(); ops->decaps(ss_dec, ct, sk);  e = get_cycles();
        total_decaps += CYCLE_DELTA(s, e);
    }

    p_cy_avg("   Keygen:  ", total_keygen, RUNS_KEM);
    p_cy_avg("   Encaps:  ", total_encaps, RUNS_KEM);
    p_cy_avg("   Decaps:  ", total_decaps, RUNS_KEM);

    uint8_t diff = 0u;
    for (size_t i = 0u; i < (size_t)ss_bytes; i++) diff |= (ss_enc[i] ^ ss_dec[i]);
    platform_print_string("   SS Match: ");
    platform_print_string(diff == 0u ? "[OK]\n" : "[MISMATCH]\n");

    print_memory_report(type);
}

void run_kem_benchmarks(void) {
    if (KEM_REGISTRY_COUNT > 0u) {
        platform_print_string("[Key Encapsulation (KEM)]\n");
        for (size_t i = 0u; i < KEM_REGISTRY_COUNT; i++)
            execute_kem_benchmark(kem_registry[i]->type);
    }
}