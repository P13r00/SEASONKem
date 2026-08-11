#include "core/inc/crypto_api.h"

static volatile uint32_t * const RCC_CR      = (volatile uint32_t *)0x40023800u;
static volatile uint32_t * const RCC_PLLCFGR = (volatile uint32_t *)0x40023804u;
static volatile uint32_t * const RCC_CFGR    = (volatile uint32_t *)0x40023808u;
static volatile uint32_t * const RCC_AHB1ENR = (volatile uint32_t *)0x40023830u;
static volatile uint32_t * const RCC_APB1ENR = (volatile uint32_t *)0x40023840u;

static volatile uint32_t * const FLASH_ACR   = (volatile uint32_t *)0x40023C00u;

static volatile uint32_t * const GPIOA_MODER = (volatile uint32_t *)0x40020000u;
static volatile uint32_t * const GPIOA_AFRL  = (volatile uint32_t *)0x40020020u;

static volatile uint32_t * const USART2_SR   = (volatile uint32_t *)0x40004400u;
static volatile uint32_t * const USART2_DR   = (volatile uint32_t *)0x40004404u;
static volatile uint32_t * const USART2_BRR  = (volatile uint32_t *)0x40004408u;
static volatile uint32_t * const USART2_CR1  = (volatile uint32_t *)0x4000440Cu;

static volatile uint32_t * const SYST_CSR    = (volatile uint32_t *)0xE000E010u;
static volatile uint32_t * const SYST_RVR    = (volatile uint32_t *)0xE000E014u;
static volatile uint32_t * const SYST_CVR    = (volatile uint32_t *)0xE000E018u;

static volatile uint32_t * const SCB_CPACR   = (volatile uint32_t *)0xE000ED88u;

extern uint32_t _sheap, _eheap;    // heap pool bounds (.heap NOLOAD)
extern uint32_t _sbss,  _ebss;     // BSS bounds (for static RAM size)


int  main(void);
void Reset_Handler(void);
extern void run_all_benchmarks(void);


void platform_print_string(const char *str) {
    while (*str) {
        if (*str == '\n') {
            while (!(*USART2_SR & (1U << 7)));
            *USART2_DR = (uint32_t)'\r';
        }
        while (!(*USART2_SR & (1U << 7)));
        *USART2_DR = (uint32_t)(*str++);
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


static void SystemClock_Config(void) {
    *RCC_CR |= (1u << 0);                /* HSION */
    while (!(*RCC_CR & (1u << 1)));      /* wait HSIRDY */

    *FLASH_ACR = (1u << 8) | (1u << 9) | (1u << 10) | 0x0u;

    /* PLL config: source=HSI(0), M=8, N=96, P=8(11b), Q=4 (unused) */
    *RCC_PLLCFGR = (8u)        /* PLLM  [5:0]   */
                 | (96u  << 6) /* PLLN  [14:6]  */
                 | (3u   << 16)/* PLLP  [17:16] = 11 -> /8 */
                 | (0u   << 22)/* PLLSRC = 0 -> HSI */
                 | (4u   << 24);/* PLLQ [27:24] */

    *RCC_CR |= (1u << 24);                /* PLLON */
    while (!(*RCC_CR & (1u << 25)));      /* wait PLLRDY */

    /* Prescalers: AHB /1, APB1 /1 (PCLK1=24MHz), APB2 /1 (PCLK2=24MHz) */
    *RCC_CFGR = (*RCC_CFGR & ~((0xFu << 4) | (0x7u << 10) | (0x7u << 13)))
              | (0x0u << 4)
              | (0x0u << 10)   /* APB1 /1 */
              | (0x0u << 13);  /* APB2 /1 */

    /* Switch SYSCLK source to PLL and wait for confirmation */
    *RCC_CFGR = (*RCC_CFGR & ~0x3u) | 0x2u;
    while (((*RCC_CFGR >> 2) & 0x3u) != 0x2u);
}

static void init_usart2_gpio(void) {
    *RCC_AHB1ENR |= (1u << 0);   /* GPIOAEN */

    /* PA2 (TX), PA3 (RX) -> alternate function mode (10b) */
    *GPIOA_MODER &= ~((3u << (2 * 2)) | (3u << (3 * 2)));
    *GPIOA_MODER |=  ((2u << (2 * 2)) | (2u << (3 * 2)));

    /* AF7 (USART2) on PA2/PA3, both within AFRL (pins 0-7) */
    *GPIOA_AFRL &= ~((0xFu << (4 * 2)) | (0xFu << (4 * 3)));
    *GPIOA_AFRL |=  ((7u   << (4 * 2)) | (7u   << (4 * 3)));
}

static void init_platform_hardware(void) {
    *SCB_CPACR |= (0xFu << 20);

    SystemClock_Config();

    init_usart2_gpio();
    *RCC_APB1ENR |= (1u << 17);   /* USART2EN */
    *USART2_BRR   = 0x00D0u;
    *USART2_CR1   = (1U << 13) | (1U << 3);   /* UE, TE */

    for (volatile uint32_t settle = 0; settle < 1000000u; settle++) {
        __asm__ volatile ("nop");
    }

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

    /* Flash — STM32F411RET6: 512KB (differs from the 1024KB F407 target) */
    platform_print_string("  Flash:  "); platform_print_hex(0x08000000u);
    platform_print_string("   524288 B (512 KB)\n");

    /* RAM — same 128KB as the F407 target */
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
    platform_print_hex((uint32_t)&_eheap);
    platform_print_string("   ");
    platform_print_number(stack_sz);
    platform_print_string(" B (grows downward)\n");

    platform_print_string("\n");
}


/* Symbols provided by linker_f411.ld */
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
    platform_print_string("  (STM32F411 Nucleo — physical hardware)  \n");
    platform_print_string("=========================================\n\n");

    heap_reset();
    fill_stack_watermark();

    print_memory_map();

    run_all_benchmarks();

    platform_print_string("Suite complete.\n");
    while (1);
    return 0;
}