#include <stddef.h>
#include "../benchmark_config.h"
#include "../benchmark_private.h"

#if COMPILE_HKDF_SHA256
extern const crypto_kdf_ops_t hkdf_sha256_ops;
#endif

static const crypto_kdf_ops_t *kdf_registry[] = {
#if COMPILE_HKDF_SHA256
    &hkdf_sha256_ops,
#endif
    NULL
};
#define KDF_REGISTRY_COUNT \
    ((sizeof(kdf_registry) / sizeof(kdf_registry[0])) - 1u)

#define KDF_IKM_LEN   32u
#define KDF_SALT_LEN  16u
#define KDF_INFO_LEN   8u
#define KDF_OKM_LEN   32u

void execute_kdf_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_kdf_ops_t *ops = NULL;
    for (size_t i = 0u; i < KDF_REGISTRY_COUNT; i++) {
        if (kdf_registry[i]->type == type) { ops = kdf_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered KDF !!\n"); return; }

    uint8_t *ikm  = (uint8_t *)heap_malloc(KDF_IKM_LEN);
    uint8_t *salt = (uint8_t *)heap_malloc(KDF_SALT_LEN);
    uint8_t *info = (uint8_t *)heap_malloc(KDF_INFO_LEN);
    uint8_t *okm  = (uint8_t *)heap_malloc(KDF_OKM_LEN);

    if (!ikm || !salt || !info || !okm) {
        platform_print_string("!! Heap OOM in KDF benchmark !!\n");
        return;
    }

    for (size_t i = 0u; i < KDF_IKM_LEN;  i++) ikm[i]  = 0x0Bu;
    for (size_t i = 0u; i < KDF_SALT_LEN; i++) salt[i] = (uint8_t)i;
    info[0]='b'; info[1]='e'; info[2]='n'; info[3]='c';
    info[4]='h'; info[5]='m'; info[6]='r'; info[7]='k';

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    uint64_t total_cycles = 0;
    uint32_t s, e;

    for (uint32_t r = 0; r < RUNS_KDF; r++) {
        s = get_cycles();
        ops->derive(okm, KDF_OKM_LEN, ikm, KDF_IKM_LEN, salt, KDF_SALT_LEN, info, KDF_INFO_LEN);
        e = get_cycles();
        total_cycles += CYCLE_DELTA(s, e);
    }

    p_cy_avg("   Derive:  ", total_cycles, RUNS_KDF);

    print_memory_report(type);
}

void run_kdf_benchmarks(void) {
    if (KDF_REGISTRY_COUNT > 0u) {
        platform_print_string("[Key Derivation (KDF)]\n");
        for (size_t i = 0u; i < KDF_REGISTRY_COUNT; i++)
            execute_kdf_benchmark(kdf_registry[i]->type);
    }
}