#ifndef BENCHMARK_PRIVATE_H
#define BENCHMARK_PRIVATE_H

#include <stdint.h>
#include "benchmark_metrics.h"
#include "core/inc/crypto_api.h"

// Forward declarations for Platform HAL (so individual suites can print)
extern uint32_t get_cycles(void);
extern void     platform_print_string(const char *str);
extern void     platform_print_number(uint32_t num);

// Shared Timing Macro
#define CYCLE_DELTA(s, e) \
    (((e) >= (s)) ? ((e) - (s)) : (0x00FFFFFFu - (s) + (e)))

// Shared Inline Print Helpers to prevent duplicate symbols across object files
static inline void p_cy(const char *label, uint32_t cy) {
    platform_print_string(label);
    platform_print_number(cy);
    platform_print_string(" cy\n");
}

static inline void p_bytes(const char *label, uint32_t b) {
    platform_print_string(label);
    platform_print_number(b);
    platform_print_string(" B\n");
}

static inline void print_memory_report(crypto_type_t type) {
    platform_print_string("   [Memory]\n");
    p_bytes("   Heap Peak:  ", heap_peak_used());
    p_bytes("   Stack HWM:  ", measure_stack_used());
    p_bytes("   Static BSS: ", measure_static_ram());
    p_bytes("   Flash Code: ", measure_algo_flash(type));
    platform_print_string("\n");
}

#endif // BENCHMARK_PRIVATE_H