#include "core/inc/crypto_api.h"

static volatile uint32_t * const RCC_APB2ENR = (volatile uint32_t *)0x40023844u;
static volatile uint32_t * const USART1_SR   = (volatile uint32_t *)0x40011000u;
static volatile uint32_t * const USART1_DR   = (volatile uint32_t *)0x40011004u;
static volatile uint32_t * const USART1_BRR  = (volatile uint32_t *)0x40011008u;
static volatile uint32_t * const USART1_CR1  = (volatile uint32_t *)0x4001100Cu;

static volatile uint32_t * const SYST_CSR    = (volatile uint32_t *)0xE000E010u;
static volatile uint32_t * const SYST_RVR    = (volatile uint32_t *)0xE000E014u;
static volatile uint32_t * const SYST_CVR    = (volatile uint32_t *)0xE000E018u;

// Coprocessor Access Control Register — needed to enable the FPU
static volatile uint32_t * const SCB_CPACR   = (volatile uint32_t *)0xE000ED88u;

extern uint32_t _sheap, _eheap;    // heap pool bounds (.heap NOLOAD)
extern uint32_t _sbss,  _ebss;     // BSS bounds (for static RAM size)


int  main(void);
void Reset_Handler(void);
extern void run_all_benchmarks(void);


void platform_print_string(const char *str) {
    while (*str) {
        while (!(*USART1_SR & (1U << 7)));
        *USART1_DR = (uint32_t)(*str++);
    }
}

void platform_print_number(uint32_t num) {
    char buf[11];
    int  i = 10;
    buf[i] = '\0';
    if (num == 0u) { platform_print_string("0"); return; }
    while (num > 0u && i > 0) {
        buf[--i] = (char)((num % 10u) + '0');
        num /= 10u;
    }
    platform_print_string(&buf[i]);
}

/*
 * platform_print_hex — prints val as "0xXXXXXXXX" (8 uppercase hex
 * digits).  Useful for logging linker-symbol addresses in the memory
 * map on startup, where decimal representations are hard to read.
 */
void platform_print_hex(uint32_t val) {
    static const char hex[] = "0123456789ABCDEF";
    char buf[11];           /* "0x" + 8 digits + '\0' */
    buf[0]  = '0';
    buf[1]  = 'x';
    for (int i = 9; i >= 2; i--) {
        buf[i] = hex[val & 0xFu];
        val >>= 4;
    }
    buf[10] = '\0';
    platform_print_string(buf);
}


uint32_t get_cycles(void) {
    return (0x00FFFFFFu - (*SYST_CVR & 0x00FFFFFFu));
}


void HardFault_Handler(void) {
    platform_print_string("\n!!! HARDWARE FAULT CAUGHT !!!\n");
    while (1);
}

__attribute__((section(".isr_vector")))
const void *Vectors[] = {
    (void *)0x20020000u,        /* 0: Initial SP (top of RAM)   */
    (void *)&Reset_Handler,     /* 1: Reset vector              */
    (void *)&HardFault_Handler, /* 2: NMI                       */
    (void *)&HardFault_Handler, /* 3: HardFault                 */
    (void *)&HardFault_Handler, /* 4: MemManage                 */
    (void *)&HardFault_Handler, /* 5: BusFault                  */
    (void *)&HardFault_Handler  /* 6: UsageFault                */
};

static void init_platform_hardware(void) {
    /* 1. Enable FPU — grant full access to CP10 and CP11 */
    *SCB_CPACR |= (0xFu << 20);

    /* 2. Enable USART1 clock on APB2, configure BRR and CR1 */
    *RCC_APB2ENR |= (1U << 4);
    *USART1_BRR   = 0x0683u;
    *USART1_CR1   = (1U << 13) | (1U << 3);

    /* 3. Configure SysTick as a free-running 24-bit down-counter */
    *SYST_CSR = 0u;
    *SYST_RVR = 0x00FFFFFFu;
    *SYST_CVR = 0u;
    *SYST_CSR = 0x00000005u;    /* CLKSOURCE=1 (core), ENABLE=1 */
}

/* ------------------------------------------------------------------ */
/* Memory map startup report                                          */
/*                                                                     */
/* Printed once on boot to give context for the per-algorithm         */
/* heap / stack / BSS / Flash numbers that follow.                    */
/* ------------------------------------------------------------------ */

static void print_memory_map(void) {
    uint32_t heap_sz  = heap_capacity();
    uint32_t stack_sz = measure_stack_capacity();
    uint32_t bss_sz   = measure_static_ram();

    platform_print_string("[Memory Map]\n");

    /* Flash — fixed STM32F407 values; adjust for other targets */
    platform_print_string("  Flash:  "); platform_print_hex(0x08000000u);
    platform_print_string("  1048576 B (1024 KB)\n");

    /* RAM */
    platform_print_string("  RAM:    "); platform_print_hex(0x20000000u);
    platform_print_string("   131072 B (128 KB)\n");

    /* Static BSS (adapters + benchmark runner) */
    platform_print_string("  BSS:              ");
    platform_print_number(bss_sz);
    platform_print_string(" B\n");

    /* Heap pool: address and capacity */
    platform_print_string("  Heap:   ");
    platform_print_hex((uint32_t)&_sheap);
    platform_print_string("   ");
    platform_print_number(heap_sz);
    platform_print_string(" B (bump allocator)\n");

    /* Stack: base address and available depth */
    platform_print_string("  Stack:  ");
    platform_print_hex((uint32_t)&_eheap);   /* stack base = heap top */
    platform_print_string("   ");
    platform_print_number(stack_sz);
    platform_print_string(" B (grows downward)\n");

    platform_print_string("\n");
}


/* Symbols provided by stm32_renode_linker.ld */
extern uint32_t _sidata, _sdata, _edata;

void Reset_Handler(void) {
    /* Copy .data initializers from Flash to RAM */
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;

    /* Zero .bss (uninitialised statics / globals) */
    dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0u;

    /* NOTE: .heap (NOLOAD) is NOT zeroed here intentionally.
     * heap_reset() initialises the bump-pointer on first use. */

    main();
    while (1);
}

int main(void) {
    /* 1. Hardware must be ready before any other operation */
    init_platform_hardware();

    /* 2. Initialise the heap allocator (sets bump pointer to _sheap,
     *    clears peak counter).  Must happen before fill_stack_watermark
     *    to ensure the heap region is not painted over. */
    heap_reset();

    /* 3. Paint the entire stack region with the watermark sentinel so
     *    measure_stack_used() can detect the high-water mark. */
    fill_stack_watermark();

    /* 4. Banner */
    platform_print_string("\n=========================================\n");
    platform_print_string("  Multi-Algorithm Heterogeneous Framework \n");
    platform_print_string("=========================================\n\n");

    heap_reset();              // called ONCE, before run_all_benchmarks()
    fill_stack_watermark();

    /* 5. Memory map (contextualises the per-algorithm numbers below) */
    print_memory_map();

    /* 6. Run all registered benchmarks */
    run_all_benchmarks();

    platform_print_string("Suite complete.\n");
    while (1);
    return 0;
}
