#ifndef BENCHMARK_METRICS_H
#define BENCHMARK_METRICS_H

#include <stddef.h>
#include <stdint.h>
#include "core/inc/crypto_api.h"

void  heap_reset(void);
void *heap_malloc(size_t size);
uint32_t heap_peak_used(void);
uint32_t heap_current_used(void);
uint32_t heap_capacity(void);

uint32_t measure_algo_flash(crypto_type_t type);

void     fill_stack_watermark(void);
void     reset_stack_watermark(void);
uint32_t measure_stack_used(void);
uint32_t measure_static_ram(void);
uint32_t measure_stack_capacity(void);

#endif // BENCHMARK_METRICS_H