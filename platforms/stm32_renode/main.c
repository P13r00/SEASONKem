#include <stdint.h>
#include "core/inc/crypto_api.h"

/*
 * STM32F4 register map (all addresses from RM0090 reference manual)
 *
 * RCC
 *   RCC_APB2ENR  0x40023844  bit4 = USART1EN
 *
 * USART1 (APB2, base 0x40011000)
 *   USART_SR   +0x00  bit7=TXE (tx data-register empty), bit6=TC
 *   USART_DR   +0x04  write byte here to transmit
 *   USART_BRR  +0x08  baud-rate divisor
 *   USART_CR1  +0x0C  bit13=UE (USART enable), bit3=TE (transmitter enable)
 *
 * SysTick (Cortex-M4 core, always present)
 *   SYST_CSR   0xE000E010  bit2=CLKSOURCE, bit0=ENABLE
 *   SYST_RVR   0xE000E014  reload value
 *   SYST_CVR   0xE000E018  current value (write any value to clear)
 */

/* ------------------------------------------------------------------ */
/*  Register pointers                                                   */
/* ------------------------------------------------------------------ */

/* RCC */
static volatile uint32_t * const RCC_APB2ENR = (volatile uint32_t *)0x40023844;

/* USART1 */
static volatile uint32_t * const USART1_SR  = (volatile uint32_t *)0x40011000;
static volatile uint32_t * const USART1_DR  = (volatile uint32_t *)0x40011004;
static volatile uint32_t * const USART1_BRR = (volatile uint32_t *)0x40011008;
static volatile uint32_t * const USART1_CR1 = (volatile uint32_t *)0x4001100C;

/* SysTick */
static volatile uint32_t * const SYST_CSR = (volatile uint32_t *)0xE000E010;
static volatile uint32_t * const SYST_RVR = (volatile uint32_t *)0xE000E014;
static volatile uint32_t * const SYST_CVR = (volatile uint32_t *)0xE000E018;

/* ------------------------------------------------------------------ */
/*  Forward declarations                                               */
/* ------------------------------------------------------------------ */

int main(void);
void Reset_Handler(void);

/* ------------------------------------------------------------------ */
/*  Minimal vector table (placed at the very start of FLASH)           */
/* ------------------------------------------------------------------ */
__attribute__((section(".isr_vector")))
const void *Vectors[] = {
    (void *)0x20020000,    /* Initial SP: top of 128K RAM (0x20000000 + 0x20000) */
    (void *)&Reset_Handler /* Reset vector                                        */
};

/* ------------------------------------------------------------------ */
/*  Platform I/O                                                       */
/* ------------------------------------------------------------------ */

void platform_print_string(const char *str) {
    while (*str) {
        /* Wait for TXE (bit 7) — transmit data register empty.
         * Required in real hardware; harmless in Renode where the model
         * always reports TXE ready, but keeps the code correct for both. */
        while (!(*USART1_SR & (1U << 7)));
        *USART1_DR = (uint32_t)(*str++);
    }
}

void platform_print_number(uint32_t num) {
    char buf[11]; /* max 10 decimal digits + NUL */
    int i = 10;
    buf[i] = '\0';
    if (num == 0) { platform_print_string("0"); return; }
    while (num > 0 && i > 0) {
        buf[--i] = (char)((num % 10) + '0');
        num /= 10;
    }
    platform_print_string(&buf[i]);
}

/* ------------------------------------------------------------------ */
/*  Cycle counter via SysTick                                          */
/* ------------------------------------------------------------------ */

uint32_t get_cycles(void) {
    /* SysTick counts DOWN from RVR to 0.
     * Elapsed = RVR - CVR, masked to 24 bits. */
    return (0x00FFFFFFu - (*SYST_CVR & 0x00FFFFFFu));
}

/* ------------------------------------------------------------------ */
/*  Hardware initialisation                                            */
/* ------------------------------------------------------------------ */

void init_platform_hardware(void) {
    /* 1. Enable USART1 clock on APB2 (bit 4 = USART1EN).
     *    Without this the USART registers are clock-gated and all writes
     *    are ignored on real silicon; Renode is more lenient but we keep
     *    the code correct for both environments. */
    *RCC_APB2ENR |= (1U << 4);

    /* 2. Configure USART1 for basic TX.
     *    Renode's STM32 UART model exposes the serial analyzer through
     *    showAnalyzer; we just need UE + TE set.
     *    BRR: for 16 MHz APB2 clock, 9600 baud → divisor = 1667 = 0x683.
     *    Renode does not enforce baud rate but the register must be non-zero
     *    so the peripheral considers itself configured. */
    *USART1_BRR = 0x0683u;
    *USART1_CR1 = (1U << 13) | (1U << 3); /* UE | TE — clean write, not OR */

    /* 3. Configure SysTick as a 24-bit free-running up-counter.
     *    CLKSOURCE=1 (processor clock), ENABLE=1, TICKINT=0 (no IRQ).
     *    Writing 0 to CVR clears it and resets the reload pipeline. */
    *SYST_CSR = 0;           /* stop while reconfiguring */
    *SYST_RVR = 0x00FFFFFFu; /* maximum 24-bit reload    */
    *SYST_CVR = 0;           /* clear current value      */
    *SYST_CSR = 0x00000005u; /* CLKSOURCE | ENABLE       */
}

/* ------------------------------------------------------------------ */
/*  Startup / entry                                                    */
/* ------------------------------------------------------------------ */

/* Reset_Handler is called directly by the vector table.
 * We skip .data/.bss init loops because:
 *   - The linker script places .data in FLASH (LMA) and RAM (VMA); Renode
 *     loads the ELF directly into RAM, so the VMA copy is already correct.
 *   - All globals here are 'const' or zero-initialised by default in C,
 *     so skipping the BSS zeroing loop is safe for this translation unit.
 */
void Reset_Handler(void) {
    main();
    while (1); /* unreachable — satisfy the no-return requirement */
}

int main(void) {
    fill_stack_watermark();
    init_platform_hardware();

    platform_print_string("\n=========================================\n");
    platform_print_string("   Multi-Algorithm Heterogeneous Framework\n");
    platform_print_string("=========================================\n\n");

    execute_signature_benchmark(ALG_CLASSICAL_ECC);

    execute_signature_benchmark(ALG_LIGHTWEIGHT_ASCON);

    platform_print_string("System Suite Run Finalized.\n");
    while (1);
    return 0;
}
