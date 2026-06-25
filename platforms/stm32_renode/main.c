#include <stdint.h>
#include "core/inc/crypto_api.h"

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

/* System Control Block - Coprocessor Access Control Register */
static volatile uint32_t * const SCB_CPACR  = (volatile uint32_t *)0xE000ED88u;

/* ------------------------------------------------------------------ */
/* Forward declarations                                               */
/* ------------------------------------------------------------------ */
int  main(void);
void Reset_Handler(void);
extern void run_all_benchmarks(void);

/* ------------------------------------------------------------------ */
/* Platform I/O                                                       */
/* ------------------------------------------------------------------ */
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
    if (num == 0) { platform_print_string("0"); return; }
    while (num > 0 && i > 0) {
        buf[--i] = (char)((num % 10u) + '0');
        num /= 10u;
    }
    platform_print_string(&buf[i]);
}

/* ------------------------------------------------------------------ */
/* Fault Handlers and Vector Table                                    */
/* ------------------------------------------------------------------ */

void HardFault_Handler(void) {
    platform_print_string("\n!!! HARDWARE FAULT CAUGHT !!!\n");
    while(1); /* Trap the CPU safely */
}

__attribute__((section(".isr_vector")))
const void *Vectors[] = {
    (void *)0x20020000u,        /* 0: Initial SP */
    (void *)&Reset_Handler,     /* 1: Reset vector */
    (void *)&HardFault_Handler, /* 2: NMI */
    (void *)&HardFault_Handler, /* 3: HardFault */
    (void *)&HardFault_Handler, /* 4: MemManage */
    (void *)&HardFault_Handler, /* 5: BusFault */
    (void *)&HardFault_Handler  /* 6: UsageFault */
};

/* ------------------------------------------------------------------ */
/* Cycle counter via SysTick                                          */
/* ------------------------------------------------------------------ */
uint32_t get_cycles(void) {
    return (0x00FFFFFFu - (*SYST_CVR & 0x00FFFFFFu));
}

/* ------------------------------------------------------------------ */
/* Hardware initialisation                                            */
/* ------------------------------------------------------------------ */
static void init_platform_hardware(void) {
    /* 1. ENABLE THE FPU: Grant full access to Coprocessors 10 and 11 */
    *SCB_CPACR |= (0xFu << 20); 

    /* 2. Enable USART1 clock on APB2 */
    *RCC_APB2ENR |= (1U << 4);
    *USART1_BRR = 0x0683u;
    *USART1_CR1 = (1U << 13) | (1U << 3); 

    /* 3. Configure SysTick */
    *SYST_CSR = 0;            
    *SYST_RVR = 0x00FFFFFFu;  
    *SYST_CVR = 0;            
    *SYST_CSR = 0x00000005u;  
}

/* ------------------------------------------------------------------ */
/* Startup / entry                                                    */
/* ------------------------------------------------------------------ */
void Reset_Handler(void) {
    main();
    while (1); 
}

int main(void) {
    /* Set up platform FIRST so the FPU is ready */
    init_platform_hardware();
    fill_stack_watermark();

    platform_print_string("\n=========================================\n");
    platform_print_string("  Multi-Algorithm Heterogeneous Framework \n");
    platform_print_string("=========================================\n\n");

    run_all_benchmarks();

    platform_print_string("Suite complete.\n");
    while (1);
    return 0;
}