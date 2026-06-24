#include <stddef.h>         /* NULL, size_t — required even in freestanding C99 */
#include "core/inc/crypto_api.h"

/* ------------------------------------------------------------------ */
/*  Signature registry                                                 */
/* ------------------------------------------------------------------ */

extern const crypto_ops_t ecc_classical_ops;
extern const crypto_ops_t ascon_ops;

static const crypto_ops_t *sign_registry[] = {
    &ecc_classical_ops,
    &ascon_ops,
};
#define SIGN_REGISTRY_COUNT (sizeof(sign_registry) / sizeof(sign_registry[0]))

/* ------------------------------------------------------------------ */
/*  AEAD registry                                                      */
/* ------------------------------------------------------------------ */

extern const crypto_aead_ops_t aes_gcm_ops;
extern const crypto_aead_ops_t chacha20_poly1305_ops;

static const crypto_aead_ops_t *aead_registry[] = {
    &aes_gcm_ops,
    &chacha20_poly1305_ops,
};
#define AEAD_REGISTRY_COUNT (sizeof(aead_registry) / sizeof(aead_registry[0]))

/* ------------------------------------------------------------------ */
/*  KDF registry                                                       */
/* ------------------------------------------------------------------ */

extern const crypto_kdf_ops_t hkdf_ops;

static const crypto_kdf_ops_t *kdf_registry[] = {
    &hkdf_ops,
};
#define KDF_REGISTRY_COUNT (sizeof(kdf_registry) / sizeof(kdf_registry[0]))

/* ------------------------------------------------------------------ */
/*  Platform HAL — implemented in platforms/stm32_renode/main.c       */
/* ------------------------------------------------------------------ */

extern uint32_t get_cycles(void);
extern void platform_print_string(const char *str);
extern void platform_print_number(uint32_t num);

/* ------------------------------------------------------------------ */
/*  Stack / RAM measurement utilities                                  */
/*                                                                     */
/*  These live here — not in main.c — because they are benchmarking   */
/*  infrastructure, not platform HAL.  main.c calls fill_stack_       */
/*  watermark() early in main(); the linker resolves it from here.    */
/*                                                                     */
/*  The linker symbols _sstack / _estack / _sbss / _ebss are not      */
/*  STM32-specific; every ARM bare-metal linker script exports them,   */
/*  so this translation unit stays platform-agnostic.                 */
/* ------------------------------------------------------------------ */

extern uint32_t _sbss, _ebss, _sstack, _estack;

/* Fill the entire stack region with a sentinel on first call.        */
/* Call once before any benchmark (from main, before init overhead).  */
void fill_stack_watermark(void) {
    volatile uint32_t *p   = (volatile uint32_t *)&_sstack;
    volatile uint32_t *top = (volatile uint32_t *)&_estack;
    while (p < top) *p++ = 0xDEADBEEFu;
}

/* Refill from _sstack up to (but not including) the current SP.     */
/* Call at the start of each benchmark to reset the high-water mark. */
void reset_stack_watermark(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    volatile uint32_t sp;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    volatile uint32_t *fence = (volatile uint32_t *)sp;
    while (p < fence) *p++ = 0xDEADBEEFu;
}

/* Walk from _sstack upward; the first non-sentinel word is the peak. */
uint32_t measure_stack_used(void) {
    volatile uint32_t *p   = (volatile uint32_t *)&_sstack;
    volatile uint32_t *top = (volatile uint32_t *)&_estack;
    while (p < top && *p == 0xDEADBEEFu) p++;
    return (uint32_t)((uint8_t *)top - (uint8_t *)p);
}

/* BSS span gives the combined size of zero-initialised static data. */
uint32_t measure_static_ram(void) {
    return (uint32_t)((uint8_t *)&_ebss - (uint8_t *)&_sbss);
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/* SysTick is a 24-bit down-counter; handle the single-wrap case.    */
#define CYCLE_DELTA(start, end) \
    (((end) >= (start)) ? ((end) - (start)) : (0x00FFFFFFu - (start) + (end)))

/* ------------------------------------------------------------------ */
/*  execute_signature_benchmark                                        */
/* ------------------------------------------------------------------ */

void execute_signature_benchmark(crypto_type_t type) {
    reset_stack_watermark();

    const crypto_ops_t *ops = NULL;
    for (size_t i = 0; i < SIGN_REGISTRY_COUNT; i++) {
        if (sign_registry[i]->type == type) {
            ops = sign_registry[i];
            break;
        }
    }

    if (!ops) {
        platform_print_string("!! Unregistered signature algorithm !!\n");
        return;
    }

    /* Fixed-size stack buffers, sized for the largest entry in the
     * signature registry:
     *   pk  32 B  (Ed25519 public key)
     *   sk  64 B  (Ed25519 private key / seed+pk)
     *   sig 64 B  (Ed25519 / Ascon stub) */
    uint8_t pk[32];
    uint8_t sk[64];
    uint8_t sig[64];
    size_t  siglen = 0;
    uint8_t msg[4] = {0x01, 0x02, 0x03, 0x04};

    platform_print_string("-> Benchmarking: ");
    platform_print_string(ops->name);
    platform_print_string("\n");

    uint32_t start, end;

    start = get_cycles();
    ops->sign_keypair(pk, sk);
    end = get_cycles();
    platform_print_string("   Keygen: "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    start = get_cycles();
    ops->sign(sig, &siglen, msg, sizeof(msg), sk);
    end = get_cycles();
    platform_print_string("   Sign:   "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    start = get_cycles();
    ops->verify(sig, siglen, msg, sizeof(msg), pk);
    end = get_cycles();
    platform_print_string("   Verify: "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    platform_print_string("   Static RAM: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n");
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used());  platform_print_string(" B\n\n");
}

/* ------------------------------------------------------------------ */
/*  execute_aead_benchmark                                             */
/*                                                                     */
/*  Exercises keygen → encrypt (64-byte plaintext, 16-byte AD) →      */
/*  decrypt with tag verification, then reports cycle counts and      */
/*  memory usage.                                                      */
/* ------------------------------------------------------------------ */

void execute_aead_benchmark(crypto_type_t type) {
    reset_stack_watermark();

    const crypto_aead_ops_t *ops = NULL;
    for (size_t i = 0; i < AEAD_REGISTRY_COUNT; i++) {
        if (aead_registry[i]->type == type) {
            ops = aead_registry[i];
            break;
        }
    }

    if (!ops) {
        platform_print_string("!! Unregistered AEAD algorithm !!\n");
        return;
    }

    /* Stack buffers sized for the worst case across the AEAD registry:
     *   key   32 B  (ChaCha20-Poly1305 / AES-256)
     *   nonce 12 B  (IETF nonce format)
     *   pt    64 B  (test plaintext)
     *   ad    16 B  (additional authenticated data)
     *   ct    80 B  (64 B ciphertext + 16 B tag max)
     *   pt2   64 B  (decrypted output for round-trip check) */
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t pt[64];
    uint8_t ad[16];
    uint8_t ct[80];
    uint8_t pt2[64];
    size_t  ctlen = 0;
    size_t  ptlen = 0;

    /* Known-pattern test data — avoids compiler optimising away loops */
    for (size_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(ad); i++) ad[i] = (uint8_t)(0xA0u | i);

    platform_print_string("-> Benchmarking: ");
    platform_print_string(ops->name);
    platform_print_string("\n");

    uint32_t start, end;

    /* 1. Key + nonce generation */
    start = get_cycles();
    ops->keygen(key, nonce);
    end = get_cycles();
    platform_print_string("   Keygen:  "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    /* 2. Authenticated encryption */
    start = get_cycles();
    ops->encrypt(ct, &ctlen, pt, sizeof(pt), ad, sizeof(ad), nonce, key);
    end = get_cycles();
    platform_print_string("   Encrypt: "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    /* 3. Authenticated decryption */
    start = get_cycles();
    int rc = ops->decrypt(pt2, &ptlen, ct, ctlen, ad, sizeof(ad), nonce, key);
    end = get_cycles();
    platform_print_string("   Decrypt: "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy");
    platform_print_string(rc == CRYPTO_SUCCESS ? " [OK]\n" : " [TAG FAIL]\n");

    platform_print_string("   Static RAM: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n");
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used());  platform_print_string(" B\n\n");
}

/* ------------------------------------------------------------------ */
/*  execute_kdf_benchmark                                              */
/*                                                                     */
/*  Derives 32 bytes of key material from a 32-byte IKM with a       */
/*  16-byte salt and an 8-byte context label, then reports cycles     */
/*  and memory usage.                                                  */
/* ------------------------------------------------------------------ */

void execute_kdf_benchmark(crypto_type_t type) {
    reset_stack_watermark();

    const crypto_kdf_ops_t *ops = NULL;
    for (size_t i = 0; i < KDF_REGISTRY_COUNT; i++) {
        if (kdf_registry[i]->type == type) {
            ops = kdf_registry[i];
            break;
        }
    }

    if (!ops) {
        platform_print_string("!! Unregistered KDF !!\n");
        return;
    }

    /* RFC 5869 §A.1 test-vector-inspired inputs */
    uint8_t ikm[32];        /* simulated shared secret / raw key material */
    uint8_t salt[16];       /* optional salt (non-secret randomness)       */
    uint8_t info[8];        /* application context label                   */
    uint8_t okm[32];        /* output key material                         */

    for (size_t i = 0; i < sizeof(ikm);  i++) ikm[i]  = 0x0Bu;
    for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)(0x00u + i);
    info[0]='b'; info[1]='e'; info[2]='n'; info[3]='c';
    info[4]='h'; info[5]='m'; info[6]='r'; info[7]='k';

    platform_print_string("-> Benchmarking: ");
    platform_print_string(ops->name);
    platform_print_string("\n");

    uint32_t start, end;

    /* Extract + expand — timed as a single atomic KDF invocation */
    start = get_cycles();
    ops->derive(okm, sizeof(okm),
                ikm,  sizeof(ikm),
                salt, sizeof(salt),
                info, sizeof(info));
    end = get_cycles();
    platform_print_string("   Derive:  "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    platform_print_string("   Static RAM: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n");
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used());  platform_print_string(" B\n\n");
}
