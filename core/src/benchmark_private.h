#ifndef BENCHMARK_PRIVATE_H
#define BENCHMARK_PRIVATE_H

#include <stdint.h>
#include "benchmark_metrics.h"
#include "benchmark_config.h"
#include "core/inc/crypto_api.h"

extern uint32_t get_cycles(void);
extern void     platform_print_string(const char *str);
extern void     platform_print_number(uint32_t num);

#define CYCLE_DELTA(s, e) \
    (((e) >= (s)) ? ((e) - (s)) : (0x00FFFFFFu - (s) + (e)))

static inline void p_cy(const char *label, uint32_t cy) {
    platform_print_string(label);
    platform_print_number(cy);
    platform_print_string(" cy\n");
}

// Prevents 32-bit accumulation overflows over hundreds of iterations
static inline void p_cy_avg(const char *label, uint64_t total_cycles, uint32_t runs) {
    if (runs == 0) return;
    uint32_t avg = (uint32_t)(total_cycles / runs);
    platform_print_string(label);
    platform_print_number(avg);
    platform_print_string(" cy (avg over ");
    platform_print_number(runs);
    platform_print_string(" runs)\n");
}

static inline void print_memory_report(crypto_type_t type) {
    platform_print_string("   [Memory]\n");
    platform_print_string("   Heap Peak:  "); platform_print_number(heap_peak_used()); platform_print_string(" B\n");
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used()); platform_print_string(" B\n");
    platform_print_string("   Static BSS: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n");
    platform_print_string("   Flash Code: "); platform_print_number(measure_algo_flash(type)); platform_print_string(" B\n\n");
}

#endif // BENCHMARK_PRIVATE_H