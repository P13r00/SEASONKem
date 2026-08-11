#include "benchmark_metrics.h"

extern uint32_t get_cycles(void);

extern uint32_t _sheap, _eheap;
static uint8_t *s_heap_base = NULL;
static uint8_t *s_heap_end  = NULL;
static uint8_t *s_heap_cur  = NULL;
static uint32_t s_heap_peak = 0u;

static void heap_init(void) {
    s_heap_base = (uint8_t *)&_sheap;
    s_heap_end  = (uint8_t *)&_eheap;
    s_heap_cur  = s_heap_base;
    s_heap_peak = 0u;
}

void heap_reset(void) {
    if (s_heap_base == NULL) heap_init();
    s_heap_cur  = s_heap_base;
    s_heap_peak = 0u;
}

void *heap_malloc(size_t size) {
    if (s_heap_base == NULL) heap_init();
    size = (size + 7u) & ~7u;
    if ((s_heap_cur + size) > s_heap_end) return NULL;

    void *p = (void *)s_heap_cur;
    s_heap_cur += size;

    volatile uint8_t *z = (volatile uint8_t *)p;
    for (size_t i = 0u; i < size; i++) z[i] = 0u;

    uint32_t used = (uint32_t)(s_heap_cur - s_heap_base);
    if (used > s_heap_peak) s_heap_peak = used;
    return p;
}

uint32_t heap_peak_used(void)     { return s_heap_peak; }
uint32_t heap_current_used(void)  { return (s_heap_base == NULL) ? 0u : (uint32_t)(s_heap_cur - s_heap_base); }
uint32_t heap_capacity(void)      { if (s_heap_base == NULL) heap_init(); return (uint32_t)(s_heap_end - s_heap_base); }


extern uint32_t _flash_region_start, _flash_region_end;

uint32_t measure_flash_used(void) {
    return (uint32_t)&_flash_region_end - (uint32_t)&_flash_region_start;
}

extern uint32_t _sbss, _ebss, _sstack, _estack;

void fill_stack_watermark(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    while (p < (volatile uint32_t *)&_estack) *p++ = 0xDEADBEEFu;
}

void reset_stack_watermark(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    volatile uint32_t sp;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    volatile uint32_t *fence = (volatile uint32_t *)sp;
    while (p < fence) *p++ = 0xDEADBEEFu;
}

uint32_t measure_stack_used(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    while (p < (volatile uint32_t *)&_estack && *p == 0xDEADBEEFu) p++;
    return (uint32_t)((uint8_t *)&_estack - (uint8_t *)p);
}

uint32_t measure_static_ram(void)      { return (uint32_t)((uint8_t *)&_ebss - (uint8_t *)&_sbss); }
uint32_t measure_stack_capacity(void)  { return (uint32_t)((uint8_t *)&_estack - (uint8_t *)&_sstack); }