#include <stddef.h>
#include <string.h>
#include "../benchmark_config.h"
#include "../benchmark_private.h"

typedef struct {
    crypto_type_t type;
    uint16_t      pk_bytes;
    uint16_t      sk_bytes;
    uint16_t      ss_bytes;
} kex_size_t;

static const kex_size_t s_kex_sizes[] = {
    {  ALG_X25519, 32,   32,   32  },
    {  ALG_ECDH_P256,   65,   32,   32  },
};
#define KEX_SIZE_COUNT (sizeof(s_kex_sizes) / sizeof(s_kex_sizes[0]))

static const kex_size_t *lookup_kex_sizes(crypto_type_t t) {
    for (size_t i = 0u; i < KEX_SIZE_COUNT; i++)
        if (s_kex_sizes[i].type == t) return &s_kex_sizes[i];
    return NULL;
}

#if COMPILE_X25519
extern const crypto_kex_ops_t x25519_ops;
#endif

static const crypto_kex_ops_t *kex_registry[] = {
#if COMPILE_X25519
    &x25519_ops,
#endif
    NULL
};
#define KEX_REGISTRY_COUNT \
    ((sizeof(kex_registry) / sizeof(kex_registry[0])) - 1u)

void execute_kex_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_kex_ops_t *ops = NULL;
    for (size_t i = 0u; i < KEX_REGISTRY_COUNT; i++) {
        if (kex_registry[i]->type == type) { ops = kex_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered KEX algorithm !!\n"); return; }

    const kex_size_t *sz = lookup_kex_sizes(type);
    uint16_t pk_bytes = sz ? sz->pk_bytes : 65u;
    uint16_t sk_bytes = sz ? sz->sk_bytes : 32u;
    uint16_t ss_bytes = sz ? sz->ss_bytes : 32u;

    uint8_t *pk_a  = (uint8_t *)heap_malloc((size_t)pk_bytes);
    uint8_t *sk_a  = (uint8_t *)heap_malloc((size_t)sk_bytes);
    uint8_t *pk_b  = (uint8_t *)heap_malloc((size_t)pk_bytes);
    uint8_t *sk_b  = (uint8_t *)heap_malloc((size_t)sk_bytes);
    uint8_t *ss_a  = (uint8_t *)heap_malloc((size_t)ss_bytes);
    uint8_t *ss_b  = (uint8_t *)heap_malloc((size_t)ss_bytes);

    if (!pk_a || !sk_a || !pk_b || !sk_b || !ss_a || !ss_b) {
        platform_print_string("!! Heap OOM in KEX benchmark !!\n");
        return;
    }

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    ops->keygen(pk_b, sk_b);

    uint64_t total_keygen = 0;
    uint64_t total_ss     = 0;
    uint32_t s, e;

    for (uint32_t r = 0; r < RUNS_KEX; r++) {
        s = get_cycles(); ops->keygen(pk_a, sk_a);              e = get_cycles();
        total_keygen += CYCLE_DELTA(s, e);

        s = get_cycles(); ops->shared_secret(ss_a, pk_b, sk_a); e = get_cycles();
        total_ss += CYCLE_DELTA(s, e);
    }

    p_cy_avg("   Keygen:        ", total_keygen, RUNS_KEX);
    p_cy_avg("   SharedSecret:  ", total_ss, RUNS_KEX);

    /* --- CANARY POISON CHECK --- */
    memset(ss_a, 0xAA, (size_t)ss_bytes);
    memset(ss_b, 0x55, (size_t)ss_bytes);

    int r1 = ops->shared_secret(ss_a, pk_b, sk_a);
    int r2 = ops->shared_secret(ss_b, pk_a, sk_b);

    platform_print_string("   r1="); platform_print_hex((uint32_t)r1);
    platform_print_string("   r2="); platform_print_hex((uint32_t)r2);
    platform_print_string("\n");

    uint8_t still_canary_a = 1u, still_canary_b = 1u;
    uint8_t all_zero_a = 1u, all_zero_b = 1u;
    for (size_t i = 0u; i < (size_t)ss_bytes; i++) {
        if (ss_a[i] != 0xAAu) still_canary_a = 0u;
        if (ss_b[i] != 0x55u) still_canary_b = 0u;
        if (ss_a[i] != 0x00u) all_zero_a = 0u;
        if (ss_b[i] != 0x00u) all_zero_b = 0u;
    }

    platform_print_string("   ss_a: ");
    for (size_t i = 0u; i < (size_t)ss_bytes; i++) platform_print_hex(ss_a[i]);
    platform_print_string("\n   ss_b: ");
    for (size_t i = 0u; i < (size_t)ss_bytes; i++) platform_print_hex(ss_b[i]);
    platform_print_string("\n");

    if (still_canary_a || still_canary_b)
        platform_print_string("   !! CANARY UNTOUCHED - shared_secret did not write output !!\n");
    if (all_zero_a || all_zero_b)
        platform_print_string("   !! ALL-ZERO SECRET - degenerate/failure result !!\n");
    
   
    uint8_t diff = 0u;
    for (size_t i = 0u; i < (size_t)ss_bytes; i++) diff |= (ss_a[i] ^ ss_b[i]);
    platform_print_string("   SS Match:     ");
    platform_print_string(diff == 0u ? "[OK]\n" : "[MISMATCH]\n");

    print_memory_report(type);
}

void run_kex_benchmarks(void) {
    if (KEX_REGISTRY_COUNT > 0u) {
        platform_print_string("[KEX]\n");
        for (size_t i = 0u; i < KEX_REGISTRY_COUNT; i++)
            execute_kex_benchmark(kex_registry[i]->type);
    }
}