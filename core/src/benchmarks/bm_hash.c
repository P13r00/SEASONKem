#include <stddef.h>
#include "../benchmark_config.h"
#include "../benchmark_private.h"


#if COMPILE_PQM4_SHA3_256
extern const crypto_hash_ops_t pqm4_sha3_256_ops;
#endif
#if COMPILE_PQM4_SHAKE256
extern const crypto_hash_ops_t pqm4_shake256_ops;
#endif
#if COMPILE_ASCON_HASH256
extern const crypto_hash_ops_t asconhash256_ops;
#endif
#if COMPILE_ASCON_XOF
extern const crypto_hash_ops_t asconxof_ops;
#endif
static const crypto_hash_ops_t *hash_registry[] = {
#if COMPILE_PQM4_SHA3_256
    &pqm4_sha3_256_ops,
#endif
#if COMPILE_PQM4_SHAKE256
    &pqm4_shake256_ops,
#endif
#if COMPILE_ASCON_HASH256
    &asconhash256_ops,
#endif
#if COMPILE_ASCON_XOF
    &asconxof_ops,
#endif
    NULL
};
#define HASH_REGISTRY_COUNT \
    ((sizeof(hash_registry) / sizeof(hash_registry[0])) - 1u)

// EXECUTE: HASHING BENCHMARK
#define HASH_INPUT_LEN 128u

void execute_dynamic_hash_benchmark(crypto_type_t type) {
    /* Reset memory and stack tracking */
    reset_stack_watermark();
    heap_reset();

    /* Find the algorithm in the registry */
    const crypto_hash_ops_t *ops = NULL;
    for (size_t i = 0u; i < HASH_REGISTRY_COUNT; i++) {
        if (hash_registry[i]->type == type) { 
            ops = hash_registry[i]; 
            break; 
        }
    }
    
    if (!ops) { 
        platform_print_string("!! Unregistered Hash/XOF !!\n"); 
        return; 
    }

    /* Set up test conditions */
    /* Index 0 is always the baseline/fixed length */
    size_t test_lengths[] = {ops->default_outlen, 64u, 1024u, 16u, 20u};
    size_t num_tests      = ops->is_xof ? 5 : 1; 


    /* Print header */
    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    /* Allocate and populate input */
    uint8_t *input = (uint8_t *)heap_malloc(HASH_INPUT_LEN);
    if (!input) {
        platform_print_string("!! Heap OOM allocating input !!\n");
        return;
    }
    for (size_t i = 0u; i < HASH_INPUT_LEN; i++) {
        input[i] = (uint8_t)(i & 0xFFu);
    }

    /* Benchmark Loop */
    for (size_t i = 0; i < num_tests; i++) {
        size_t current_outlen = test_lengths[i];
        
        /* Allocate output buffer for this specific test length */
        uint8_t *output = (uint8_t *)heap_malloc(current_outlen);
        if (!output) {
            platform_print_string("!! Heap OOM allocating output !!\n");
            continue;
        }

        /* Benchmark the one-shot hash/XOF operation */
        uint32_t s = get_cycles();
        int res = ops->hash(output, current_outlen, input, HASH_INPUT_LEN);
        uint32_t e = get_cycles();
        
        if (res == CRYPTO_SUCCESS) {
            if (i == 0) p_cy("   Default/32B: ", CYCLE_DELTA(s, e));
            if (i == 1) p_cy("   Squeeze 64B: ", CYCLE_DELTA(s, e));
            if (i == 2) p_cy("   Sqz 1024B:   ", CYCLE_DELTA(s, e));
            if (i == 3) p_cy("   Sqz 16B:     ", CYCLE_DELTA(s, e));
            if (i == 4) p_cy("   Sqz 20B:     ", CYCLE_DELTA(s, e));
        } else {
            platform_print_string("   [Error executing hash]\n");
        }
    }

    /* Print memory footprint */
    print_memory_report(type);
}

void run_hash_benchmarks(void) {
    if (HASH_REGISTRY_COUNT > 0u) {
        platform_print_string("[Hash / XOF]\n");
        for (size_t i = 0u; i < HASH_REGISTRY_COUNT; i++)
            execute_dynamic_hash_benchmark(hash_registry[i]->type);
    }
}