#include <stddef.h>         /* NULL, size_t — required even in freestanding C99 */
#include "core/inc/crypto_api.h"

/* External operational structs defined in the adapter translation units */
extern const crypto_ops_t ecc_classical_ops;
extern const crypto_ops_t ascon_ops;

static const crypto_ops_t *crypto_registry[] = {
    &ecc_classical_ops,
    &ascon_ops
};
#define REGISTRY_COUNT (sizeof(crypto_registry) / sizeof(crypto_registry[0]))

/* Platform HAL — implemented in platforms/stm32_renode/main.c */
extern uint32_t get_cycles(void);
extern void platform_print_string(const char *str);
extern void platform_print_number(uint32_t num);

extern uint32_t _sbss, _ebss, _sstack, _estack;

void fill_stack_watermark(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    volatile uint32_t *top = (volatile uint32_t *)&_estack;
    while (p < top) *p++ = 0xDEADBEEF;
}

void reset_stack_watermark(void) {
    /* Refill from current SP downward to _sstack.
     * We must not clobber the active stack frame, so stop at current SP. */
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    volatile uint32_t sp;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    volatile uint32_t *top = (volatile uint32_t *)sp;
    while (p < top) *p++ = 0xDEADBEEF;
}

uint32_t measure_stack_used(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    volatile uint32_t *top = (volatile uint32_t *)&_estack;
    while (p < top && *p == 0xDEADBEEF) p++;
    return (uint32_t)((uint8_t *)top - (uint8_t *)p);
}

uint32_t measure_static_ram(void) {
    return (uint32_t)((uint8_t *)&_ebss - (uint8_t *)&_sbss);
}

void execute_signature_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    
    const crypto_ops_t *ops = NULL; /* NULL not bare 0 for pointer null */

    for (size_t i = 0; i < REGISTRY_COUNT; i++) {
        if (crypto_registry[i]->type == type) {
            ops = crypto_registry[i];
            break;
        }
    }

    if (!ops) {
        platform_print_string("!! Unregistered !!\n");
        return;
    }

    /* Fixed-size stack buffers.
     * Sized for the largest algorithm in this registry:
     *   pk  32 B  (Ed25519 public key)
     *   sk  64 B  (Ed25519 private key)
     *   sig 64 B  (Ed25519 / Ascon stub signature)
     * The Ascon stub does not actually touch these buffers, so sizes are safe. */
    uint8_t pk[32];
    uint8_t sk[64];
    uint8_t sig[64];
    size_t  siglen = 0;
    uint8_t msg[4] = {1, 2, 3, 4};

    platform_print_string("-> Benchmarking: ");
    platform_print_string(ops->name);
    platform_print_string("\n");

    uint32_t start, end, delta;

    /* 1. Key generation */
    start = get_cycles();
    ops->sign_keypair(pk, sk);
    end   = get_cycles();
    /* SysTick is a 24-bit counter; handle wrap-around */
    delta = (end >= start) ? (end - start) : (0x00FFFFFFu - start + end);
    platform_print_string("   Keygen: "); platform_print_number(delta); platform_print_string("\n");

    /* 2. Sign */
    start = get_cycles();
    ops->sign(sig, &siglen, msg, sizeof(msg), sk);
    end   = get_cycles();
    delta = (end >= start) ? (end - start) : (0x00FFFFFFu - start + end);
    platform_print_string("   Sign:   "); platform_print_number(delta); platform_print_string("\n");

    /* 3. Verify */
    start = get_cycles();
    ops->verify(sig, siglen, msg, sizeof(msg), pk);
    end   = get_cycles();
    delta = (end >= start) ? (end - start) : (0x00FFFFFFu - start + end);
    platform_print_string("   Verify: "); platform_print_number(delta); platform_print_string("\n\n");

    /* 4. Stack usage */
    platform_print_string("   Static RAM: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n");
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used());  platform_print_string(" B\n\n");
}
