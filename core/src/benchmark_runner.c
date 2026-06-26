#include <stddef.h>         /* NULL, size_t — required even in freestanding C99 */
#include "core/inc/crypto_api.h"

/* ================================================================== */
/* GLOBAL ALGORITHM CONFIGURATION (1 = Compile & Run, 0 = Skip)       */
/* ================================================================== */
#define COMPILE_ED25519           1
#define COMPILE_ECDSAP256         1
#define COMPILE_AES_GCM           1
#define COMPILE_CHACHA20_POLY1305 1
#define COMPILE_HKDF_SHA256       1
#define COMPILE_ASCON80           0
#define COMPILE_ASCON_HASH        0
#define COMPILE_KYBER512          1
#define COMPILE_DILITHIUM2        1

/* ------------------------------------------------------------------ */
/* Signature registry                                                 */
/* ------------------------------------------------------------------ */

#if COMPILE_ED25519
extern const crypto_ops_t ed25519_ops; /* cite: x */
#endif

#if COMPILE_ECDSAP256
extern const crypto_ops_t ecdsap256_ops; /* cite: x */
#endif

#if COMPILE_DILITHIUM2
extern const crypto_ops_t dilithium2_ops; /* cite: x */
#endif

static const crypto_ops_t *sign_registry[] = {
#if COMPILE_ED25519
    &ed25519_ops, /* cite: x */
#endif
#if COMPILE_ECDSAP256
    &ecdsap256_ops, /* cite: x */
#endif
#if COMPILE_DILITHIUM2
    &dilithium2_ops, /* cite: x */
#endif
    NULL
};

#define SIGN_REGISTRY_COUNT ((sizeof(sign_registry) / sizeof(sign_registry[0])) - 1) /* cite: x */

/* ------------------------------------------------------------------ */
/* AEAD registry                                                      */
/* ------------------------------------------------------------------ */

#if COMPILE_AES_GCM
    extern const crypto_aead_ops_t aes_gcm_ops; /* cite: x */
#endif
#if COMPILE_CHACHA20_POLY1305
    extern const crypto_aead_ops_t chacha20_poly1305_ops; /* cite: x */
#endif
#if COMPILE_ASCON80
    extern const crypto_aead_ops_t ascon80pq_ops; /* cite: x */
#endif

static const crypto_aead_ops_t *aead_registry[] = {
#if COMPILE_AES_GCM
    &aes_gcm_ops, /* cite: x */
#endif
#if COMPILE_CHACHA20_POLY1305
    &chacha20_poly1305_ops, /* cite: x */
#endif
#if COMPILE_ASCON80
    &ascon80pq_ops, /* cite: x */
#endif
    NULL
};
#define AEAD_REGISTRY_COUNT ((sizeof(aead_registry) / sizeof(aead_registry[0])) - 1) /* cite: x */

/* ------------------------------------------------------------------ */
/* KDF registry                                                       */
/* ------------------------------------------------------------------ */

#if COMPILE_HKDF_SHA256
extern const crypto_kdf_ops_t hkdf_sha256_ops; /* cite: x */
#endif
#if COMPILE_ASCON_HASH
extern const crypto_aead_ops_t asconhash256_ops; /* cite: x */
#endif

static const crypto_kdf_ops_t *kdf_registry[] = {
#if COMPILE_HKDF_SHA256
    &hkdf_sha256_ops, /* cite: x */
#endif
#if COMPILE_ASCON_HASH
    (const crypto_kdf_ops_t *)&asconhash256_ops, /* cite: x */
#endif
    NULL
};
#define KDF_REGISTRY_COUNT ((sizeof(kdf_registry) / sizeof(kdf_registry[0])) - 1) /* cite: x */

/* ------------------------------------------------------------------ */
/* KEM registry (Key Encapsulation Mechanism)                         */
/* ------------------------------------------------------------------ */

#if COMPILE_KYBER512
extern const crypto_kem_ops_t kyber512_ops;
#endif

static const crypto_kem_ops_t *kem_registry[] = {
#if COMPILE_KYBER512
    &kyber512_ops,
#endif
    NULL
};
#define KEM_REGISTRY_COUNT ((sizeof(kem_registry) / sizeof(kem_registry[0])) - 1)

/* ------------------------------------------------------------------ */
/* Platform HAL — implemented in platforms/stm32_renode/main.c       */
/* ------------------------------------------------------------------ */

extern uint32_t get_cycles(void); /* cite: x */
extern void platform_print_string(const char *str); /* cite: x */
extern void platform_print_number(uint32_t num); /* cite: x */

/* ------------------------------------------------------------------ */
/* Stack / RAM measurement utilities                                  */
/* ------------------------------------------------------------------ */

extern uint32_t _sbss, _ebss, _sstack, _estack; /* cite: x */

void fill_stack_watermark(void) {
    volatile uint32_t *p   = (volatile uint32_t *)&_sstack; /* cite: x */
    volatile uint32_t *top = (volatile uint32_t *)&_estack; /* cite: x */
    while (p < top) *p++ = 0xDEADBEEFu; /* cite: x */
}

void reset_stack_watermark(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack; /* cite: x */
    volatile uint32_t sp; /* cite: x */
    __asm__ volatile ("mov %0, sp" : "=r"(sp)); /* cite: x */
    volatile uint32_t *fence = (volatile uint32_t *)sp; /* cite: x */
    while (p < fence) *p++ = 0xDEADBEEFu; /* cite: x */
}

uint32_t measure_stack_used(void) {
    volatile uint32_t *p   = (volatile uint32_t *)&_sstack; /* cite: x */
    volatile uint32_t *top = (volatile uint32_t *)&_estack; /* cite: x */
    while (p < top && *p == 0xDEADBEEFu) p++; /* cite: x */
    return (uint32_t)((uint8_t *)top - (uint8_t *)p); /* cite: x */
}

uint32_t measure_static_ram(void) {
    return (uint32_t)((uint8_t *)&_ebss - (uint8_t *)&_sbss); /* cite: x */
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

#define CYCLE_DELTA(start, end) \
    (((end) >= (start)) ? ((end) - (start)) : (0x00FFFFFFu - (start) + (end))) /* cite: x */

/* ------------------------------------------------------------------ */
/* Execution Framework                                                */
/* ------------------------------------------------------------------ */

void execute_signature_benchmark(crypto_type_t type) {
    reset_stack_watermark(); /* cite: x */

    const crypto_ops_t *ops = NULL; /* cite: x */
    for (size_t i = 0; i < SIGN_REGISTRY_COUNT; i++) {
        if (sign_registry[i]->type == type) { /* cite: x */
            ops = sign_registry[i]; /* cite: x */
            break; /* cite: x */
        }
    }

    if (!ops) {
        platform_print_string("!! Unregistered signature algorithm !!\n"); /* cite: x */
        return; /* cite: x */
    }

    /* Static: crypto_sign_ctx needs ~50 KB stack internally; keep local frames small */
    static uint8_t pk[1312];
    static uint8_t sk[2528];
    static uint8_t sig[2420];
    size_t  siglen = 0;
    uint8_t msg[4] = {0x01, 0x02, 0x03, 0x04};

    platform_print_string("-> Benchmarking: "); /* cite: x */
    platform_print_string(ops->name); /* cite: x */
    platform_print_string("\n"); /* cite: x */

    uint32_t start, end; /* cite: x */

    start = get_cycles(); /* cite: x */
    ops->sign_keypair(pk, sk); /* cite: x */
    end = get_cycles(); /* cite: x */
    platform_print_string("   Keygen: "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n"); /* cite: x */

    start = get_cycles(); /* cite: x */
    ops->sign(sig, &siglen, msg, sizeof(msg), sk); /* cite: x */
    end = get_cycles(); /* cite: x */
    platform_print_string("   Sign:   "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n"); /* cite: x */

    start = get_cycles(); /* cite: x */
    ops->verify(sig, siglen, msg, sizeof(msg), pk); /* cite: x */
    end = get_cycles(); /* cite: x */
    platform_print_string("   Verify: "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n"); /* cite: x */

    platform_print_string("   Static RAM: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n"); /* cite: x */
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used());  platform_print_string(" B\n\n"); /* cite: x */
}

void execute_aead_benchmark(crypto_type_t type) {
    reset_stack_watermark(); /* cite: x */

    const crypto_aead_ops_t *ops = NULL; /* cite: x */
    for (size_t i = 0; i < AEAD_REGISTRY_COUNT; i++) {
        if (aead_registry[i]->type == type) { /* cite: x */
            ops = aead_registry[i]; /* cite: x */
            break; /* cite: x */
        }
    }

    if (!ops) {
        platform_print_string("!! Unregistered AEAD algorithm !!\n"); /* cite: x */
        return; /* cite: x */
    }

    uint8_t key[32]; /* cite: x */
    uint8_t nonce[12]; /* cite: x */
    uint8_t pt[64]; /* cite: x */
    uint8_t ad[16]; /* cite: x */
    uint8_t ct[80]; /* cite: x */
    uint8_t pt2[64]; /* cite: x */
    size_t  ctlen = 0; /* cite: x */
    size_t  ptlen = 0; /* cite: x */

    for (size_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)i; /* cite: x */
    for (size_t i = 0; i < sizeof(ad); i++) ad[i] = (uint8_t)(0xA0u | i); /* cite: x */

    platform_print_string("-> Benchmarking: "); /* cite: x */
    platform_print_string(ops->name); /* cite: x */
    platform_print_string("\n"); /* cite: x */

    uint32_t start, end; /* cite: x */

    start = get_cycles(); /* cite: x */
    ops->keygen(key, nonce); /* cite: x */
    end = get_cycles(); /* cite: x */
    platform_print_string("   Keygen:  "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n"); /* cite: x */

    start = get_cycles(); /* cite: x */
    ops->encrypt(ct, &ctlen, pt, sizeof(pt), ad, sizeof(ad), nonce, key); /* cite: x */
    end = get_cycles(); /* cite: x */
    platform_print_string("   Encrypt: "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n"); /* cite: x */

    start = get_cycles(); /* cite: x */
    int rc = ops->decrypt(pt2, &ptlen, ct, ctlen, ad, sizeof(ad), nonce, key); /* cite: x */
    end = get_cycles(); /* cite: x */
    platform_print_string("   Decrypt: "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy"); /* cite: x */
    platform_print_string(rc == CRYPTO_SUCCESS ? " [OK]\n" : " [TAG FAIL]\n"); /* cite: x */

    platform_print_string("   Static RAM: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n"); /* cite: x */
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used());  platform_print_string(" B\n\n"); /* cite: x */
}

void execute_kdf_benchmark(crypto_type_t type) {
    reset_stack_watermark(); /* cite: x */

    const crypto_kdf_ops_t *ops = NULL; /* cite: x */
    for (size_t i = 0; i < KDF_REGISTRY_COUNT; i++) {
        if (kdf_registry[i]->type == type) { /* cite: x */
            ops = kdf_registry[i]; /* cite: x */
            break; /* cite: x */
        }
    }

    if (!ops) {
        platform_print_string("!! Unregistered KDF !!\n"); /* cite: x */
        return; /* cite: x */
    }

    uint8_t ikm[32];        /* cite: x */
    uint8_t salt[16];       /* cite: x */
    uint8_t info[8];        /* cite: x */
    uint8_t okm[32];        /* cite: x */

    for (size_t i = 0; i < sizeof(ikm);  i++) ikm[i]  = 0x0Bu; /* cite: x */
    for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)(0x00u + i); /* cite: x */
    info[0]='b'; info[1]='e'; info[2]='n'; info[3]='c'; /* cite: x */
    info[4]='h'; info[5]='m'; info[6]='r'; info[7]='k'; /* cite: x */

    platform_print_string("-> Benchmarking: "); /* cite: x */
    platform_print_string(ops->name); /* cite: x */
    platform_print_string("\n"); /* cite: x */

    uint32_t start, end; /* cite: x */

    start = get_cycles(); /* cite: x */
    ops->derive(okm, sizeof(okm), ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info)); /* cite: x */
    end = get_cycles(); /* cite: x */
    platform_print_string("   Derive:  "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n"); /* cite: x */

    platform_print_string("   Static RAM: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n"); /* cite: x */
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used());  platform_print_string(" B\n\n"); /* cite: x */
}

void execute_kem_benchmark(crypto_type_t type) {
    reset_stack_watermark();

    const crypto_kem_ops_t *ops = NULL;
    for (size_t i = 0; i < KEM_REGISTRY_COUNT; i++) {
        if (kem_registry[i]->type == type) {
            ops = kem_registry[i];
            break;
        }
    }

    if (!ops) {
        platform_print_string("!! Unregistered KEM algorithm !!\n");
        return;
    }

    /* Static: keeps stack free for pqm4 internal NTT temporaries */
    static uint8_t pk[800];
    static uint8_t sk[1632];
    static uint8_t ct[768];
    static uint8_t ss_enc[32];
    static uint8_t ss_dec[32];

    platform_print_string("-> Benchmarking: ");
    platform_print_string(ops->name);
    platform_print_string("\n");

    uint32_t start, end;

    start = get_cycles();
    ops->keygen(pk, sk);
    end = get_cycles();
    platform_print_string("   Keygen:  "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    start = get_cycles();
    ops->encaps(ct, ss_enc, pk);
    end = get_cycles();
    platform_print_string("   Encaps:  "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    start = get_cycles();
    ops->decaps(ss_dec, ct, sk);
    end = get_cycles();
    platform_print_string("   Decaps:  "); platform_print_number(CYCLE_DELTA(start, end)); platform_print_string(" cy\n");

    /* Verify correctness by comparing shared secrets */
    int matched = 1;
    for (size_t i = 0; i < 32; i++) {
        if (ss_enc[i] != ss_dec[i]) {
            matched = 0;
            break;
        }
    }
    platform_print_string("   Verify:  ");
    platform_print_string(matched ? "[OK]\n" : "[SHARED SECRET MISMATCH]\n");

    platform_print_string("   Static RAM: "); platform_print_number(measure_static_ram()); platform_print_string(" B\n");
    platform_print_string("   Stack HWM:  "); platform_print_number(measure_stack_used());  platform_print_string(" B\n\n");
}

/* ------------------------------------------------------------------ */
/* Master Suite Runner                                                */
/* ------------------------------------------------------------------ */
void run_all_benchmarks(void) {
    if (SIGN_REGISTRY_COUNT > 0) {
        platform_print_string("[Signature Schemes]\n"); /* cite: x */
        for (size_t i = 0; i < SIGN_REGISTRY_COUNT; i++) {
            execute_signature_benchmark(sign_registry[i]->type); /* cite: x */
        }
    }

    if (AEAD_REGISTRY_COUNT > 0) {
        platform_print_string("[Symmetric AEAD]\n"); /* cite: x */
        for (size_t i = 0; i < AEAD_REGISTRY_COUNT; i++) {
            execute_aead_benchmark(aead_registry[i]->type); /* cite: x */
        }
    }

    if (KDF_REGISTRY_COUNT > 0) {
        platform_print_string("[Key Derivation]\n"); /* cite: x */
        for (size_t i = 0; i < KDF_REGISTRY_COUNT; i++) {
            execute_kdf_benchmark(kdf_registry[i]->type); /* cite: x */
        }
    }

    if (KEM_REGISTRY_COUNT > 0) {
        platform_print_string("[Key Encapsulation Mechanisms (KEM)]\n");
        for (size_t i = 0; i < KEM_REGISTRY_COUNT; i++) {
            execute_kem_benchmark(kem_registry[i]->type);
        }
    }
}