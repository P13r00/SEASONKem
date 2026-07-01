#include <stddef.h>
#include "../benchmark_config.h"
#include "../benchmark_private.h"


typedef struct {
    crypto_type_t type;
    uint16_t      pk_bytes;
    uint16_t      sk_bytes;
    uint16_t      ss_bytes;
} kex_size_t;

static const kex_size_t s_kex_sizes[] = {
    /*  type          pk    sk    ss  */
    {  ALG_WOLF_X25519,    32,   32,   32  },
    {  ALG_ECDH_P256, 65,   32,   32  },
};
#define KEX_SIZE_COUNT (sizeof(s_kex_sizes) / sizeof(s_kex_sizes[0]))

static const kex_size_t *lookup_kex_sizes(crypto_type_t t) {
    for (size_t i = 0u; i < KEX_SIZE_COUNT; i++)
        if (s_kex_sizes[i].type == t) return &s_kex_sizes[i];
    return NULL;
}


#if COMPILE_WOLF_X25519
extern const crypto_kex_ops_t wolf_x25519_ops;
#endif

static const crypto_kex_ops_t *kex_registry[] = {
#if COMPILE_WOLF_X25519
    &wolf_x25519_ops,
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

    /* Both parties' key material lives on the heap for peak accuracy */
    uint8_t *pk_a  = (uint8_t *)heap_malloc((size_t)pk_bytes);  /* local public  */
    uint8_t *sk_a  = (uint8_t *)heap_malloc((size_t)sk_bytes);  /* local private */
    uint8_t *pk_b  = (uint8_t *)heap_malloc((size_t)pk_bytes);  /* peer  public  */
    uint8_t *sk_b  = (uint8_t *)heap_malloc((size_t)sk_bytes);  /* peer  private */
    uint8_t *ss_a  = (uint8_t *)heap_malloc((size_t)ss_bytes);  /* shared secret (local side)  */
    uint8_t *ss_b  = (uint8_t *)heap_malloc((size_t)ss_bytes);  /* shared secret (peer  side)  */

    if (!pk_a || !sk_a || !pk_b || !sk_b || !ss_a || !ss_b) {
        platform_print_string("!! Heap OOM in KEX benchmark !!\n");
        return;
    }

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    /* Untimed: generate peer's keypair (setup only) */
    ops->keygen(pk_b, sk_b);

    uint32_t s, e;

    /* Timed: local key generation */
    s = get_cycles(); ops->keygen(pk_a, sk_a);               e = get_cycles();
    p_cy("   Keygen:        ", CYCLE_DELTA(s, e));

    /* Timed: local party derives shared secret from peer's public key */
    s = get_cycles(); ops->shared_secret(ss_a, pk_b, sk_a);  e = get_cycles();
    p_cy("   SharedSecret:  ", CYCLE_DELTA(s, e));

    /* Correctness: peer derives the same secret (untimed) */
    ops->shared_secret(ss_b, pk_a, sk_b);
    uint8_t diff = 0u;
    for (size_t i = 0u; i < (size_t)ss_bytes; i++) diff |= (ss_a[i] ^ ss_b[i]);
    platform_print_string("   SS Match:     ");
    platform_print_string(diff == 0u ? "[OK]\n" : "[MISMATCH]\n");

    print_memory_report(type);
}

void run_kex_benchmarks(void) {
    if (KEX_REGISTRY_COUNT > 0u) {
        platform_print_string("[Key Exchange (KEX)]\n");
        for (size_t i = 0u; i < KEX_REGISTRY_COUNT; i++)
            execute_kex_benchmark(kex_registry[i]->type);
    }
}