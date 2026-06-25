#include <stdint.h>
#include "core/inc/crypto_api.h"

/*
 * main.c — STM32F4 / Renode platform layer
 *
 * Responsibilities:
 * - Vector table and Reset_Handler
 * - Hardware initialisation (USART1, SysTick)
 * - Platform HAL (platform_print_string, platform_print_number, get_cycles)
 * - Top-level main() that sequences the benchmark suite
 *
 * NOT here: fill_stack_watermark / reset_stack_watermark / measure_*
 * Those are benchmarking utilities, not platform HAL.  They live in
 * core/src/benchmark_runner.c and are declared in core/inc/crypto_api.h.
 * Defining them in both files would cause a "multiple definition" link error.
 */

/*
 * STM32F4 register map (RM0090 reference manual)
 *
 * RCC
 * RCC_APB2ENR  0x40023844  bit4 = USART1EN
 *
 * USART1 (APB2, base 0x40011000)
 * USART_SR   +0x00  bit7=TXE (tx data-register empty)
 * USART_DR   +0x04  write byte to transmit
 * USART_BRR  +0x08  baud-rate divisor
 * USART_CR1  +0x0C  bit13=UE (USART enable), bit3=TE (transmitter enable)
 *
 * SysTick (Cortex-M4 core, always present)
 * SYST_CSR   0xE000E010  bit2=CLKSOURCE, bit0=ENABLE
 * SYST_RVR   0xE000E014  reload value
 * SYST_CVR   0xE000E018  current value (write any value to clear)
 */

/* ------------------------------------------------------------------ */
/* Register pointers                                                  */
/* ------------------------------------------------------------------ */

static volatile uint32_t * const RCC_APB2ENR = (volatile uint32_t *)0x40023844u;

static volatile uint32_t * const USART1_SR  = (volatile uint32_t *)0x40011000u;
static volatile uint32_t * const USART1_DR  = (volatile uint32_t *)0x40011004u;
static volatile uint32_t * const USART1_BRR = (volatile uint32_t *)0x40011008u;
static volatile uint32_t * const USART1_CR1 = (volatile uint32_t *)0x4001100Cu;

static volatile uint32_t * const SYST_CSR = (volatile uint32_t *)0xE000E010u;
static volatile uint32_t * const SYST_RVR = (volatile uint32_t *)0xE000E014u;
static volatile uint32_t * const SYST_CVR = (volatile uint32_t *)0xE000E018u;

/* ------------------------------------------------------------------ */
/* Forward declarations                                               */
/* ------------------------------------------------------------------ */

int  main(void);
void Reset_Handler(void);
extern void run_all_benchmarks(void);

/* ------------------------------------------------------------------ */
/* Minimal vector table                                               */
/* ------------------------------------------------------------------ */

__attribute__((section(".isr_vector")))
const void *Vectors[] = {
    (void *)0x20020000u,     /* Initial SP: top of 128 KiB RAM */
    (void *)&Reset_Handler   /* Reset vector                   */
};

/* ------------------------------------------------------------------ */
/* Platform I/O                                                       */
/* ------------------------------------------------------------------ */

void platform_print_string(const char *str) {
    while (*str) {
        /* Wait for TXE (bit 7) — real HW requires this; harmless in Renode */
        while (!(*USART1_SR & (1U << 7)));
        *USART1_DR = (uint32_t)(*str++);
    }
}

void platform_print_number(uint32_t num) {
    char buf[11]; /* max 10 decimal digits + NUL */
    int  i = 10;
    buf[i] = '\0';
    if (num == 0) { platform_print_string("0"); return; }
    while (num > 0 && i > 0) {
        buf[--i] = (char)((num % 10u) + '0');
        num /= 10u;
    }
    platform_print_string(&buf[i]);
}

/* ------------------------------------------------------------------ */
/* Cycle counter via SysTick                                          */
/* ------------------------------------------------------------------ */

uint32_t get_cycles(void) {
    /* SysTick counts DOWN from RVR to 0; we invert to get elapsed.
     * Masked to 24 bits to match the hardware register width. */
    return (0x00FFFFFFu - (*SYST_CVR & 0x00FFFFFFu));
}

/* ------------------------------------------------------------------ */
/* Hardware initialisation                                            */
/* ------------------------------------------------------------------ */

static void init_platform_hardware(void) {
    /* 1. Enable USART1 clock on APB2 (bit 4 = USART1EN). */
    *RCC_APB2ENR |= (1U << 4);

    /* 2. Configure USART1 for basic TX.
     * BRR: 16 MHz APB2 / 9600 baud → divisor ≈ 1667 = 0x683.
     * Renode doesn't enforce baud rate but the register must be non-zero. */
    *USART1_BRR = 0x0683u;
    *USART1_CR1 = (1U << 13) | (1U << 3); /* UE | TE */

    /* 3. Configure SysTick as a 24-bit free-running up-counter.
     * CLKSOURCE=1 (processor clock), TICKINT=0, ENABLE=1. */
    *SYST_CSR = 0;            /* stop while reconfiguring */
    *SYST_RVR = 0x00FFFFFFu;  /* maximum 24-bit reload    */
    *SYST_CVR = 0;            /* clear current value      */
    *SYST_CSR = 0x00000005u;  /* CLKSOURCE | ENABLE       */
}

/* ------------------------------------------------------------------ */
/* Startup / entry                                                    */
/* ------------------------------------------------------------------ */

void Reset_Handler(void) {
    main();
    while (1); /* trap if main returns */
}

int main(void) {
    /* Watermark the entire stack before any stack-disturbing work.
     * fill_stack_watermark() is defined in core/src/benchmark_runner.c. */
    fill_stack_watermark();
    init_platform_hardware();

    platform_print_string("\n=========================================\n");
    platform_print_string("  Multi-Algorithm Heterogeneous Framework \n");
    platform_print_string("=========================================\n\n");

    /* Run all enabled benchmarks dynamically managed by CMake switches */
    run_all_benchmarks();

    platform_print_string("Suite complete.\n");
    while (1);
    return 0;
}