#include <stddef.h>
#include "../benchmark_config.h"
#include "../benchmark_private.h"

#if COMPILE_PQM4_SHA3_256
extern const crypto_hash_ops_t pqm4_sha3_256_ops;
#endif
#if COMPILE_PQM4_SHAKE256
extern const crypto_hash_ops_t pqm4_shake256_ops;
#endif
#if COMPILE_LWC_SPARKLE_HASHXOF256
extern const crypto_hash_ops_t lwc_sparkle_hashxof256_ops;
#endif
#if COMPILE_LWC_SPARKLE_HASHXOF384
extern const crypto_hash_ops_t lwc_sparkle_hashxof384_ops;
#endif
#if COMPILE_LWC_SPARKLE_HASH256
extern const crypto_hash_ops_t lwc_sparkle_hash256_ops;
#endif
#if COMPILE_LWC_SPARKLE_HASH384
extern const crypto_hash_ops_t lwc_sparkle_hash384_ops;
#endif
#if COMPILE_LWC_XOODYAK_HASH
extern const crypto_hash_ops_t lwc_xoodyak_hash_ops;
#endif
#if COMPILE_LWC_ASCON_HASHXOF
extern const crypto_hash_ops_t lwc_ascon_hashxof_ops;
#endif
#if COMPILE_LWC_ASCON_HASH256
extern const crypto_hash_ops_t lwc_ascon_hash256_ops;
#endif

static const crypto_hash_ops_t *hash_registry[] = {
#if COMPILE_PQM4_SHA3_256
    &pqm4_sha3_256_ops,
#endif
#if COMPILE_PQM4_SHAKE256
    &pqm4_shake256_ops,
#endif
#if COMPILE_LWC_SPARKLE_HASHXOF256
    &lwc_sparkle_hashxof256_ops,
#endif
#if COMPILE_LWC_SPARKLE_HASHXOF384
    &lwc_sparkle_hashxof384_ops,
#endif
#if COMPILE_LWC_SPARKLE_HASH256
    &lwc_sparkle_hash256_ops,
#endif
#if COMPILE_LWC_SPARKLE_HASH384
    &lwc_sparkle_hash384_ops,
#endif
#if COMPILE_LWC_XOODYAK_HASH
    &lwc_xoodyak_hash_ops,
#endif
#if COMPILE_LWC_ASCON_HASHXOF
    &lwc_ascon_hashxof_ops,
#endif
#if COMPILE_LWC_ASCON_HASH256
    &lwc_ascon_hash256_ops,
#endif

    NULL
};
#define HASH_REGISTRY_COUNT \
    ((sizeof(hash_registry) / sizeof(hash_registry[0])) - 1u)

void execute_dynamic_hash_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_hash_ops_t *ops = NULL;
    for (size_t i = 0u; i < HASH_REGISTRY_COUNT; i++) {
        if (hash_registry[i]->type == type) { ops = hash_registry[i]; break; }
    }
    
    if (!ops) { platform_print_string("!! Unregistered Hash/XOF !!\n"); return; }

    size_t test_lengths[] = {ops->default_outlen, 16u, 20u, 24u, 64u, 1024u};
    size_t num_tests      = ops->is_xof ? 6 : 1; 

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    for (size_t i = 0; i < num_tests; i++) {
        size_t current_outlen = test_lengths[i];

        heap_reset();

        uint8_t *input = (uint8_t *)heap_malloc(HASH_BUFFER_SIZE);
        if (!input) {
            platform_print_string("!! Heap OOM allocating input !!\n");
            continue;
        }
        for (size_t j = 0u; j < HASH_BUFFER_SIZE; j++) {
            input[j] = (uint8_t)(j & 0xFFu);
        }

        uint8_t *output = (uint8_t *)heap_malloc(current_outlen);
        if (!output) {
            platform_print_string("!! Heap OOM allocating output !!\n");
            continue;
        }

        uint64_t total_cycles = 0;
        int res = CRYPTO_SUCCESS;

        for (uint32_t r = 0; r < RUNS_HASH; r++) {
            uint32_t s = get_cycles();
            res = ops->hash(output, current_outlen, input, HASH_BUFFER_SIZE);
            uint32_t e = get_cycles();
            total_cycles += CYCLE_DELTA(s, e);
        }
        
        if (res == CRYPTO_SUCCESS) {
            if (i == 0) p_cy_avg("   Default/32B: ", total_cycles, RUNS_HASH);
            if (i == 1) p_cy_avg("   Squeeze 16B: ", total_cycles, RUNS_HASH);
            if (i == 2) p_cy_avg("   Sqz 20B:     ", total_cycles, RUNS_HASH);
            if (i == 3) p_cy_avg("   Sqz 24B:     ", total_cycles, RUNS_HASH);
            if (i == 4) p_cy_avg("   Sqz 64B:     ", total_cycles, RUNS_HASH);
            if (i == 5) p_cy_avg("   Sqz 1024B:   ", total_cycles, RUNS_HASH);
            
        } else {
            platform_print_string("   [Error executing hash]\n");
        }

        if (i == 0) platform_print_string("   Heap Peak (Default/32B): ");
        if (i == 1) platform_print_string("   Heap Peak (Squeeze 16B): ");
        if (i == 2) platform_print_string("   Heap Peak (Sqz 20B):     ");
        if (i == 3) platform_print_string("   Heap Peak (Sqz 24B):     ");
        if (i == 4) platform_print_string("   Heap Peak (Sqz 64B):     ");
        if (i == 5) platform_print_string("   Heap Peak (Sqz 1024B):   ");
        platform_print_number(heap_peak_used());
        platform_print_string(" B\n");
    }

    print_memory_report(type);
}

void run_hash_benchmarks(void) {
    if (HASH_REGISTRY_COUNT > 0u) {
        platform_print_string("[Hash / XOF]\n");
        for (size_t i = 0u; i < HASH_REGISTRY_COUNT; i++)
            execute_dynamic_hash_benchmark(hash_registry[i]->type);
    }
}