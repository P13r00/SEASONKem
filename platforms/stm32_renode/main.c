#include "core/inc/crypto_api.h"

static volatile uint32_t * const RCC_APB2ENR = (volatile uint32_t *)0x40023844u;
static volatile uint32_t * const USART1_SR   = (volatile uint32_t *)0x40011000u;
static volatile uint32_t * const USART1_DR   = (volatile uint32_t *)0x40011004u;
static volatile uint32_t * const USART1_BRR  = (volatile uint32_t *)0x40011008u;
static volatile uint32_t * const USART1_CR1  = (volatile uint32_t *)0x4001100Cu;

static volatile uint32_t * const SYST_CSR    = (volatile uint32_t *)0xE000E010u;
static volatile uint32_t * const SYST_RVR    = (volatile uint32_t *)0xE000E014u;
static volatile uint32_t * const SYST_CVR    = (volatile uint32_t *)0xE000E018u;

static volatile uint32_t * const SCB_CPACR   = (volatile uint32_t *)0xE000ED88u;

extern uint32_t _sheap, _eheap;    
extern uint32_t _sbss,  _ebss;


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

void platform_print_hex(uint32_t val) {
    static const char hex[] = "0123456789ABCDEF";
    char buf[11];           
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
    *SCB_CPACR |= (0xFu << 20);

    *RCC_APB2ENR |= (1U << 4);
    *USART1_BRR   = 0x0683u;
    *USART1_CR1   = (1U << 13) | (1U << 3);

    *SYST_CSR = 0u;
    *SYST_RVR = 0x00FFFFFFu;
    *SYST_CVR = 0u;
    *SYST_CSR = 0x00000005u;    /* CLKSOURCE=1 (core), ENABLE=1 */
}

static void print_memory_map(void) {
    uint32_t heap_sz  = heap_capacity();
    uint32_t stack_sz = measure_stack_capacity();
    uint32_t bss_sz   = measure_static_ram();

    platform_print_string("[Memory Map]\n");

    platform_print_string("  Flash:  "); platform_print_hex(0x08000000u);
    platform_print_string("  1048576 B (1024 KB)\n");

    platform_print_string("  RAM:    "); platform_print_hex(0x20000000u);
    platform_print_string("   131072 B (128 KB)\n");

    platform_print_string("  BSS:              ");
    platform_print_number(bss_sz);
    platform_print_string(" B\n");

    platform_print_string("  Heap:   ");
    platform_print_hex((uint32_t)&_sheap);
    platform_print_string("   ");
    platform_print_number(heap_sz);
    platform_print_string(" B (bump allocator)\n");

    platform_print_string("  Stack:  ");
    platform_print_hex((uint32_t)&_eheap);   /* stack base = heap top */
    platform_print_string("   ");
    platform_print_number(stack_sz);
    platform_print_string(" B (grows downward)\n");

    platform_print_string("\n");
}


extern uint32_t _sidata, _sdata, _edata;

void Reset_Handler(void) {
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;

    dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0u;

    main();
    while (1);
}

int main(void) {
    init_platform_hardware();

    heap_reset();

    fill_stack_watermark();

    platform_print_string("\n=========================================\n");
    platform_print_string("  Multi-Algorithm Heterogeneous Framework \n");
    platform_print_string("=========================================\n\n");

    heap_reset();              // called ONCE, before run_all_benchmarks()
    fill_stack_watermark();

    print_memory_map();

    run_all_benchmarks();

    platform_print_string("Suite complete.\n");
    while (1);
    return 0;
}
