#include <stddef.h>
#include "core/inc/crypto_api.h"

// Selection point for benchmark
#define COMPILE_ED25519            0
#define COMPILE_ECDSAP256          0
#define COMPILE_AES_GCM            0
#define COMPILE_CHACHA20_POLY1305  1
#define COMPILE_HKDF_SHA256        0
#define COMPILE_ASCON80            0
#define COMPILE_ASCON_AEAD128      0
#define COMPILE_ASCON_HASH256      0
#define COMPILE_ASCON_XOF          1
#define COMPILE_KYBER512           0
#define COMPILE_KYBER768           0
#define COMPILE_DILITHIUM2         1
#define COMPILE_FALCON512          0
#define COMPILE_X25519             0


#if COMPILE_ED25519
extern const crypto_ops_t ed25519_ops;
#endif
#if COMPILE_ECDSAP256
extern const crypto_ops_t ecdsap256_ops;
#endif
#if COMPILE_DILITHIUM2
extern const crypto_ops_t dilithium2_ops;
#endif
#if COMPILE_FALCON512
extern const crypto_ops_t falcon512_ops;
#endif

static const crypto_ops_t *sign_registry[] = {
#if COMPILE_ED25519
    &ed25519_ops,
#endif
#if COMPILE_ECDSAP256
    &ecdsap256_ops,
#endif
#if COMPILE_DILITHIUM2
    &dilithium2_ops,
#endif
#if COMPILE_FALCON512
    &falcon512_ops,
#endif
    NULL
};
#define SIGN_REGISTRY_COUNT \
    ((sizeof(sign_registry) / sizeof(sign_registry[0])) - 1u)

/* ================================================================== */
/* SYMMETRIC AEAD REGISTRY  (crypto_aead_ops_t)                       */
/* ================================================================== */

#if COMPILE_AES_GCM
extern const crypto_aead_ops_t aes_gcm_ops;
#endif
#if COMPILE_ASCON80
extern const crypto_aead_ops_t ascon80pq_ops;
#endif
#if COMPILE_ASCON_AEAD128
extern const crypto_aead_ops_t asconaead128_ops;
#endif
#if COMPILE_CHACHA20_POLY1305
extern const crypto_aead_ops_t chacha20_poly1305_ops;
#endif

static const crypto_aead_ops_t *aead_registry[] = {
#if COMPILE_AES_GCM
    &aes_gcm_ops,
#endif
#if COMPILE_ASCON80
    &ascon80pq_ops,
#endif
#if COMPILE_ASCON_AEAD128
    &asconaead128_ops,
#endif
#if COMPILE_CHACHA20_POLY1305
    &chacha20_poly1305_ops,
#endif
    NULL
};
#define AEAD_REGISTRY_COUNT \
    ((sizeof(aead_registry) / sizeof(aead_registry[0])) - 1u)

/* ================================================================== */
/* KEY DERIVATION REGISTRY  (crypto_kdf_ops_t)                        */
/* ================================================================== */

#if COMPILE_HKDF_SHA256
extern const crypto_kdf_ops_t hkdf_sha256_ops;
#endif
#if COMPILE_ASCON_XOF
extern const crypto_kdf_ops_t asconxof_ops;
#endif
#if COMPILE_ASCON_HASH256
extern const crypto_kdf_ops_t asconhash256_ops;
#endif

static const crypto_kdf_ops_t *kdf_registry[] = {
#if COMPILE_HKDF_SHA256
    &hkdf_sha256_ops,
#endif
#if COMPILE_ASCON_XOF
    &asconxof_ops,
#endif
#if COMPILE_ASCON_HASH256
    &asconhash256_ops,
#endif
    NULL
};
#define KDF_REGISTRY_COUNT \
    ((sizeof(kdf_registry) / sizeof(kdf_registry[0])) - 1u)

/* ================================================================== */
/* KEY ENCAPSULATION REGISTRY  (crypto_kem_ops_t)                     */
/* ================================================================== */

#if COMPILE_KYBER512
extern const crypto_kem_ops_t kyber512_ops;
#endif
#if COMPILE_KYBER768
extern const crypto_kem_ops_t kyber768_ops;
#endif

static const crypto_kem_ops_t *kem_registry[] = {
#if COMPILE_KYBER512
    &kyber512_ops,
#endif
#if COMPILE_KYBER768
    &kyber768_ops,
#endif
    NULL
};
#define KEM_REGISTRY_COUNT \
    ((sizeof(kem_registry) / sizeof(kem_registry[0])) - 1u)

/* ================================================================== */
/* KEY EXCHANGE REGISTRY  (crypto_kex_ops_t)                          */
/* ================================================================== */

#if COMPILE_X25519
extern const crypto_kex_ops_t x25519_ops;
#endif

static const crypto_kex_ops_t *kex_registry[] = {
#if COMPILE_X25519
    &x25519_ops,
#endif
    NULL
};
#define KEX_REGISTRY_COUNT \
    ((sizeof(kex_registry) / sizeof(kex_registry[0])) - 1u)

/* ================================================================== */
/* PLATFORM HAL FORWARD DECLARATIONS                                  */
/* ================================================================== */

extern uint32_t get_cycles(void);
extern void     platform_print_string(const char *str);
extern void     platform_print_number(uint32_t num);
extern void     platform_print_hex(uint32_t val);

/* ================================================================== */
/* HEAP BUMP ALLOCATOR                                                */
/*                                                                    */
/* _sheap / _eheap are placed by the linker script in the .heap      */
/* (NOLOAD) section, directly above .bss and below the stack.        */
/*                                                                    */
/* Allocation contract:                                               */
/*   • Aligned to 8 bytes (meets alignment for all key types)        */
/*   • Zero-initialised on every call (safe for key-material reuse)  */
/*   • All memory is reclaimed at once with heap_reset(); no         */
/*     individual free is provided (benchmark workload pattern).     */
/*   • heap_reset() also clears the peak counter, so each benchmark  */
/*     measures only its own working set.                            */
/*                                                                    */
/* Failure: returns NULL; callers must check and abort the run.      */
/* ================================================================== */

extern uint32_t _sheap, _eheap;    /* linker-defined section bounds  */

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

/* Public — called by main() for initialisation and before each run */
void heap_reset(void) {
    if (s_heap_base == NULL) heap_init();
    s_heap_cur  = s_heap_base;
    s_heap_peak = 0u;
}

/* Public — allocate `size` zero-initialised bytes; NULL on OOM */
void *heap_malloc(size_t size) {
    if (s_heap_base == NULL) heap_init();

    /* Round up to nearest 8-byte boundary */
    size = (size + 7u) & ~7u;

    if ((s_heap_cur + size) > s_heap_end) {
        return NULL;    /* heap exhausted */
    }

    void *p = (void *)s_heap_cur;
    s_heap_cur += size;

    /* Zero-initialise — safe default for key material */
    volatile uint8_t *z = (volatile uint8_t *)p;
    for (size_t i = 0u; i < size; i++) z[i] = 0u;

    /* Update peak high-water mark */
    uint32_t used = (uint32_t)(s_heap_cur - s_heap_base);
    if (used > s_heap_peak) s_heap_peak = used;

    return p;
}

/* Public — peak heap usage (bytes) since last heap_reset() */
uint32_t heap_peak_used(void) {
    return s_heap_peak;
}

/* Public — bytes currently live on the heap */
uint32_t heap_current_used(void) {
    if (s_heap_base == NULL) return 0u;
    return (uint32_t)(s_heap_cur - s_heap_base);
}

/* Public — total heap capacity in bytes */
uint32_t heap_capacity(void) {
    if (s_heap_base == NULL) heap_init();
    return (uint32_t)(s_heap_end - s_heap_base);
}

/* ================================================================== */
/* PER-ALGORITHM FLASH FOOTPRINT TABLE                               */
/*                                                                    */
/* The linker script wraps each adapter object's .text* and .rodata* */
/* between a pair of _flash_<algo>_start / _flash_<algo>_end labels. */
/* measure_algo_flash() returns (end - start) in bytes.              */
/*                                                                    */
/* An adapter that is not linked produces start == end → 0 B.        */
/* ================================================================== */

extern uint32_t _flash_aes_gcm_start,       _flash_aes_gcm_end;
extern uint32_t _flash_ascon80pq_start,     _flash_ascon80pq_end;
extern uint32_t _flash_asconaead128_start,  _flash_asconaead128_end;
extern uint32_t _flash_asconhash256_start,  _flash_asconhash256_end;
extern uint32_t _flash_asconxof_start,      _flash_asconxof_end;
extern uint32_t _flash_chacha_start,        _flash_chacha_end;
extern uint32_t _flash_ecdsap256_start,     _flash_ecdsap256_end;
extern uint32_t _flash_ed25519_start,       _flash_ed25519_end;
extern uint32_t _flash_hkdf_start,          _flash_hkdf_end;
extern uint32_t _flash_dilithium2_start,    _flash_dilithium2_end;
extern uint32_t _flash_falcon512_start,     _flash_falcon512_end;
extern uint32_t _flash_kyber512_start,      _flash_kyber512_end;
extern uint32_t _flash_kyber768_start,      _flash_kyber768_end;
extern uint32_t _flash_x25519_start,        _flash_x25519_end;

typedef struct {
    crypto_type_t   type;
    const uint32_t *flash_start;  /* address = &linker_symbol */
    const uint32_t *flash_end;
} flash_entry_t;

static const flash_entry_t s_flash_table[] = {
    { ALG_AES_GCM,           &_flash_aes_gcm_start,       &_flash_aes_gcm_end       },
    { ALG_ASCON80PQ,         &_flash_ascon80pq_start,     &_flash_ascon80pq_end     },
    { ALG_ASCON_AEAD128,     &_flash_asconaead128_start,  &_flash_asconaead128_end  },
    { ALG_ASCON_HASH256,     &_flash_asconhash256_start,  &_flash_asconhash256_end  },
    { ALG_ASCON_XOF,         &_flash_asconxof_start,      &_flash_asconxof_end      },
    { ALG_CHACHA20_POLY1305, &_flash_chacha_start,        &_flash_chacha_end        },
    { ALG_ECDSA_P256,        &_flash_ecdsap256_start,     &_flash_ecdsap256_end     },
    { ALG_ED25519,           &_flash_ed25519_start,       &_flash_ed25519_end       },
    { ALG_HKDF_SHA256,       &_flash_hkdf_start,          &_flash_hkdf_end          },
    { ALG_DILITHIUM2,        &_flash_dilithium2_start,    &_flash_dilithium2_end    },
    { ALG_FALCON,            &_flash_falcon512_start,     &_flash_falcon512_end     },
    { ALG_KYBER512,          &_flash_kyber512_start,      &_flash_kyber512_end      },
    { ALG_KYBER768,          &_flash_kyber768_start,      &_flash_kyber768_end      },
    { ALG_X25519,            &_flash_x25519_start,        &_flash_x25519_end        },
};
#define FLASH_TABLE_COUNT (sizeof(s_flash_table) / sizeof(s_flash_table[0]))

/* Exposed for use by external callers (declared in crypto_api.h) */
uint32_t measure_algo_flash(crypto_type_t type) {
    for (size_t i = 0u; i < FLASH_TABLE_COUNT; i++) {
        if (s_flash_table[i].type == type) {
            /* Cast pointer-to-symbol to uint32_t to get the address value */
            uint32_t start = (uint32_t)s_flash_table[i].flash_start;
            uint32_t end   = (uint32_t)s_flash_table[i].flash_end;
            return end - start;
        }
    }
    return 0u;
}

/* ================================================================== */
/* PER-ALGORITHM KEY / OUTPUT SIZE TABLES                             */
/*                                                                    */
/* Drives exact heap_malloc() sizes so heap_peak_used() reflects     */
/* each algorithm's actual key-material working set, not a padded    */
/* worst-case constant.                                              */
/* ================================================================== */

/* --- Signature / MAC -------------------------------------------- */
typedef struct {
    crypto_type_t type;
    uint16_t      pk_bytes;
    uint16_t      sk_bytes;
    uint16_t      sig_bytes;    /* worst-case or fixed output length */
} sign_size_t;

static const sign_size_t s_sign_sizes[] = {
    /*  type                pk     sk    sig                              */
    {  ALG_ED25519,          32,    64,    64  },  /* Ed25519             */
    {  ALG_ECDSA_P256,       65,    97,    72  },  /* DER r+s worst-case  */
    {  ALG_DILITHIUM2,     1312,  2560,  2420  },  /* ML-DSA-44           */
    {  ALG_FALCON,          897,  1281,   666  },  /* FN-DSA-512          */
};
#define SIGN_SIZE_COUNT (sizeof(s_sign_sizes) / sizeof(s_sign_sizes[0]))

static const sign_size_t *lookup_sign_sizes(crypto_type_t t) {
    for (size_t i = 0u; i < SIGN_SIZE_COUNT; i++)
        if (s_sign_sizes[i].type == t) return &s_sign_sizes[i];
    return NULL;
}

/* --- KEM --------------------------------------------------------- */
typedef struct {
    crypto_type_t type;
    uint16_t      pk_bytes;
    uint16_t      sk_bytes;
    uint16_t      ct_bytes;
    uint16_t      ss_bytes;
} kem_size_t;

static const kem_size_t s_kem_sizes[] = {
    /*  type          pk      sk      ct     ss  */
    {  ALG_KYBER512,   800,  1632,   768,   32  },
    {  ALG_KYBER768,  1184,  2400,  1088,   32  },
};
#define KEM_SIZE_COUNT (sizeof(s_kem_sizes) / sizeof(s_kem_sizes[0]))

static const kem_size_t *lookup_kem_sizes(crypto_type_t t) {
    for (size_t i = 0u; i < KEM_SIZE_COUNT; i++)
        if (s_kem_sizes[i].type == t) return &s_kem_sizes[i];
    return NULL;
}

/* --- KEX --------------------------------------------------------- */
typedef struct {
    crypto_type_t type;
    uint16_t      pk_bytes;
    uint16_t      sk_bytes;
    uint16_t      ss_bytes;
} kex_size_t;

static const kex_size_t s_kex_sizes[] = {
    /*  type          pk    sk    ss  */
    {  ALG_X25519,    32,   32,   32  },
    {  ALG_ECDH_P256, 65,   32,   32  },
};
#define KEX_SIZE_COUNT (sizeof(s_kex_sizes) / sizeof(s_kex_sizes[0]))

static const kex_size_t *lookup_kex_sizes(crypto_type_t t) {
    for (size_t i = 0u; i < KEX_SIZE_COUNT; i++)
        if (s_kex_sizes[i].type == t) return &s_kex_sizes[i];
    return NULL;
}

/* ================================================================== */
/* STACK / STATIC RAM MEASUREMENT UTILITIES                           */
/* ================================================================== */

extern uint32_t _sbss, _ebss, _sstack, _estack;

void fill_stack_watermark(void) {
    volatile uint32_t *p   = (volatile uint32_t *)&_sstack;
    volatile uint32_t *top = (volatile uint32_t *)&_estack;
    while (p < top) *p++ = 0xDEADBEEFu;
}

void reset_stack_watermark(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    volatile uint32_t  sp;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    volatile uint32_t *fence = (volatile uint32_t *)sp;
    while (p < fence) *p++ = 0xDEADBEEFu;
}

uint32_t measure_stack_used(void) {
    volatile uint32_t *p   = (volatile uint32_t *)&_sstack;
    volatile uint32_t *top = (volatile uint32_t *)&_estack;
    while (p < top && *p == 0xDEADBEEFu) p++;
    return (uint32_t)((uint8_t *)top - (uint8_t *)p);
}

uint32_t measure_static_ram(void) {
    return (uint32_t)((uint8_t *)&_ebss - (uint8_t *)&_sbss);
}

uint32_t measure_stack_capacity(void) {
    return (uint32_t)((uint8_t *)&_estack - (uint8_t *)&_sstack);
}

/* ================================================================== */
/* INTERNAL PRINT HELPERS                                             */
/* ================================================================== */

#define CYCLE_DELTA(s, e) \
    (((e) >= (s)) ? ((e) - (s)) : (0x00FFFFFFu - (s) + (e)))

static void p_cy(const char *label, uint32_t cy) {
    platform_print_string(label);
    platform_print_number(cy);
    platform_print_string(" cy\n");
}

static void p_bytes(const char *label, uint32_t b) {
    platform_print_string(label);
    platform_print_number(b);
    platform_print_string(" B\n");
}

/*
 * print_memory_report — emits the four-axis memory summary at the end
 * of every benchmark run.  Call AFTER timing loops so that the heap
 * peak, stack HWM, and BSS values are all fully settled.
 */
static void print_memory_report(crypto_type_t type) {
    platform_print_string("   [Memory]\n");
    p_bytes("   Heap Peak:  ", heap_peak_used());
    p_bytes("   Stack HWM:  ", measure_stack_used());
    p_bytes("   Static BSS: ", measure_static_ram());
    p_bytes("   Flash Code: ", measure_algo_flash(type));
    platform_print_string("\n");
}

/* ================================================================== */
/* EXECUTE: SIGNATURE / MAC BENCHMARK                                 */
/*                                                                    */
/* Key material is heap-allocated using the exact sizes from          */
/* s_sign_sizes[], so heap_peak_used() reflects the true working set  */
/* of this algorithm, not a padded worst-case constant.               */
/* ================================================================== */

void execute_signature_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    /* ---- locate ops ---- */
    const crypto_ops_t *ops = NULL;
    for (size_t i = 0u; i < SIGN_REGISTRY_COUNT; i++) {
        if (sign_registry[i]->type == type) { ops = sign_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered signature algorithm !!\n"); return; }

    /* ---- exact allocation sizes for this algorithm ---- */
    const sign_size_t *sz = lookup_sign_sizes(type);
    uint16_t pk_bytes  = sz ? sz->pk_bytes  : 1312u;  /* Dilithium2 max fallback */
    uint16_t sk_bytes  = sz ? sz->sk_bytes  : 2560u;
    uint16_t sig_bytes = sz ? sz->sig_bytes : 2420u;

    uint8_t *pk  = (uint8_t *)heap_malloc((size_t)pk_bytes);
    uint8_t *sk  = (uint8_t *)heap_malloc((size_t)sk_bytes);
    uint8_t *sig = (uint8_t *)heap_malloc((size_t)sig_bytes);

    if (!pk || !sk || !sig) {
        platform_print_string("!! Heap OOM in signature benchmark !!\n");
        return;
    }

    size_t  siglen = 0u;
    uint8_t msg[4] = {0x01u, 0x02u, 0x03u, 0x04u};

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    uint32_t s, e;

    s = get_cycles(); ops->sign_keypair(pk, sk);               e = get_cycles();
    p_cy("   Keygen: ", CYCLE_DELTA(s, e));

    s = get_cycles(); ops->sign(sig, &siglen, msg, 4u, sk);    e = get_cycles();
    p_cy("   Sign:   ", CYCLE_DELTA(s, e));

    s = get_cycles(); ops->verify(sig, siglen, msg, 4u, pk);   e = get_cycles();
    p_cy("   Verify: ", CYCLE_DELTA(s, e));

    print_memory_report(type);
}

/* ================================================================== */
/* EXECUTE: SYMMETRIC AEAD BENCHMARK                                  */
/*                                                                    */
/* Buffer sizes are taken directly from the ops struct fields         */
/* (key_bytes, nonce_bytes, tag_bytes) so no separate size table      */
/* is needed; the heap peak is exact for every AEAD algorithm.        */
/* ================================================================== */

#define AEAD_MSG_LEN  64u
#define AEAD_AD_LEN   16u

void execute_aead_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_aead_ops_t *ops = NULL;
    for (size_t i = 0u; i < AEAD_REGISTRY_COUNT; i++) {
        if (aead_registry[i]->type == type) { ops = aead_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered AEAD algorithm !!\n"); return; }

    /* Initialise the RNG before the timed section (exclude one-time cost) */
    if (ops->init && ops->init() != CRYPTO_SUCCESS) {
        platform_print_string("!! AEAD init failed !!\n");
        return;
    }

    /* Exact sizes come from the ops struct — no hardcoded constants */
    uint8_t *key   = (uint8_t *)heap_malloc(ops->key_bytes);
    uint8_t *nonce = (uint8_t *)heap_malloc(ops->nonce_bytes);
    uint8_t *pt    = (uint8_t *)heap_malloc(AEAD_MSG_LEN);
    uint8_t *ad    = (uint8_t *)heap_malloc(AEAD_AD_LEN);
    uint8_t *ct    = (uint8_t *)heap_malloc(AEAD_MSG_LEN + ops->tag_bytes);
    uint8_t *pt2   = (uint8_t *)heap_malloc(AEAD_MSG_LEN);

    if (!key || !nonce || !pt || !ad || !ct || !pt2) {
        platform_print_string("!! Heap OOM in AEAD benchmark !!\n");
        return;
    }

    /* Fill test vectors (heap_malloc zero-inits; overwrite with known pattern) */
    for (size_t i = 0u; i < AEAD_MSG_LEN; i++) pt[i] = (uint8_t)i;
    for (size_t i = 0u; i < AEAD_AD_LEN;  i++) ad[i] = (uint8_t)(0xA0u | i);

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    uint32_t s, e;
    size_t ctlen = 0u, ptlen = 0u;

    s = get_cycles(); ops->keygen(key, nonce);                                             e = get_cycles();
    p_cy("   Keygen:  ", CYCLE_DELTA(s, e));

    s = get_cycles(); ops->encrypt(ct, &ctlen, pt, AEAD_MSG_LEN, ad, AEAD_AD_LEN, nonce, key); e = get_cycles();
    p_cy("   Encrypt: ", CYCLE_DELTA(s, e));

    s = get_cycles();
    int rc = ops->decrypt(pt2, &ptlen, ct, ctlen, ad, AEAD_AD_LEN, nonce, key);
    e = get_cycles();
    platform_print_string("   Decrypt: ");
    platform_print_number(CYCLE_DELTA(s, e));
    platform_print_string(rc == CRYPTO_SUCCESS ? " cy [OK]\n" : " cy [TAG FAIL]\n");

    print_memory_report(type);
}

/* ================================================================== */
/* EXECUTE: KEY DERIVATION BENCHMARK                                  */
/* ================================================================== */

#define KDF_IKM_LEN   32u
#define KDF_SALT_LEN  16u
#define KDF_INFO_LEN   8u
#define KDF_OKM_LEN   32u

void execute_kdf_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_kdf_ops_t *ops = NULL;
    for (size_t i = 0u; i < KDF_REGISTRY_COUNT; i++) {
        if (kdf_registry[i]->type == type) { ops = kdf_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered KDF !!\n"); return; }

    uint8_t *ikm  = (uint8_t *)heap_malloc(KDF_IKM_LEN);
    uint8_t *salt = (uint8_t *)heap_malloc(KDF_SALT_LEN);
    uint8_t *info = (uint8_t *)heap_malloc(KDF_INFO_LEN);
    uint8_t *okm  = (uint8_t *)heap_malloc(KDF_OKM_LEN);

    if (!ikm || !salt || !info || !okm) {
        platform_print_string("!! Heap OOM in KDF benchmark !!\n");
        return;
    }

    for (size_t i = 0u; i < KDF_IKM_LEN;  i++) ikm[i]  = 0x0Bu;
    for (size_t i = 0u; i < KDF_SALT_LEN; i++) salt[i] = (uint8_t)i;
    info[0]='b'; info[1]='e'; info[2]='n'; info[3]='c';
    info[4]='h'; info[5]='m'; info[6]='r'; info[7]='k';

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    uint32_t s = get_cycles();
    ops->derive(okm, KDF_OKM_LEN, ikm, KDF_IKM_LEN, salt, KDF_SALT_LEN, info, KDF_INFO_LEN);
    uint32_t e = get_cycles();
    p_cy("   Derive:  ", CYCLE_DELTA(s, e));

    print_memory_report(type);
}

/* ================================================================== */
/* EXECUTE: KEY ENCAPSULATION BENCHMARK                               */
/* ================================================================== */

void execute_kem_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_kem_ops_t *ops = NULL;
    for (size_t i = 0u; i < KEM_REGISTRY_COUNT; i++) {
        if (kem_registry[i]->type == type) { ops = kem_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered KEM algorithm !!\n"); return; }

    const kem_size_t *sz = lookup_kem_sizes(type);
    uint16_t pk_bytes = sz ? sz->pk_bytes : 1184u;  /* Kyber-768 fallback */
    uint16_t sk_bytes = sz ? sz->sk_bytes : 2400u;
    uint16_t ct_bytes = sz ? sz->ct_bytes : 1088u;
    uint16_t ss_bytes = sz ? sz->ss_bytes :   32u;

    uint8_t *pk     = (uint8_t *)heap_malloc((size_t)pk_bytes);
    uint8_t *sk     = (uint8_t *)heap_malloc((size_t)sk_bytes);
    uint8_t *ct     = (uint8_t *)heap_malloc((size_t)ct_bytes);
    uint8_t *ss_enc = (uint8_t *)heap_malloc((size_t)ss_bytes);
    uint8_t *ss_dec = (uint8_t *)heap_malloc((size_t)ss_bytes);

    if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
        platform_print_string("!! Heap OOM in KEM benchmark !!\n");
        return;
    }

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    uint32_t s, e;

    s = get_cycles(); ops->keygen(pk, sk);          e = get_cycles();
    p_cy("   Keygen:  ", CYCLE_DELTA(s, e));

    s = get_cycles(); ops->encaps(ct, ss_enc, pk);  e = get_cycles();
    p_cy("   Encaps:  ", CYCLE_DELTA(s, e));

    s = get_cycles(); ops->decaps(ss_dec, ct, sk);  e = get_cycles();
    p_cy("   Decaps:  ", CYCLE_DELTA(s, e));

    /* Verify both sides derive the same shared secret */
    uint8_t diff = 0u;
    for (size_t i = 0u; i < (size_t)ss_bytes; i++) diff |= (ss_enc[i] ^ ss_dec[i]);
    platform_print_string("   SS Match: ");
    platform_print_string(diff == 0u ? "[OK]\n" : "[MISMATCH]\n");

    print_memory_report(type);
}

/* ================================================================== */
/* EXECUTE: KEY EXCHANGE BENCHMARK                                    */
/*                                                                    */
/* Allocates key material for both local and peer parties so the      */
/* heap peak captures the full two-party working set.                 */
/* Only local keygen and shared-secret derivation are timed; the      */
/* peer keypair is generated as untimed setup.                        */
/* ================================================================== */

void execute_kex_benchmark(crypto_type_t type) {
    reset_stack_watermark();
    heap_reset();

    const crypto_kex_ops_t *ops = NULL;
    for (size_t i = 0u; i < KEX_REGISTRY_COUNT; i++) {
        if (kex_registry[i]->type == type) { ops = kex_registry[i]; break; }
    }
    if (!ops) { platform_print_string("!! Unregistered KEX algorithm !!\n"); return; }

    const kex_size_t *sz = lookup_kex_sizes(type);
    uint16_t pk_bytes = sz ? sz->pk_bytes : 65u;
    uint16_t sk_bytes = sz ? sz->sk_bytes : 32u;
    uint16_t ss_bytes = sz ? sz->ss_bytes : 32u;

    /* Both parties' key material lives on the heap for peak accuracy */
    uint8_t *pk_a  = (uint8_t *)heap_malloc((size_t)pk_bytes);  /* local public  */
    uint8_t *sk_a  = (uint8_t *)heap_malloc((size_t)sk_bytes);  /* local private */
    uint8_t *pk_b  = (uint8_t *)heap_malloc((size_t)pk_bytes);  /* peer  public  */
    uint8_t *sk_b  = (uint8_t *)heap_malloc((size_t)sk_bytes);  /* peer  private */
    uint8_t *ss_a  = (uint8_t *)heap_malloc((size_t)ss_bytes);  /* shared secret (local side)  */
    uint8_t *ss_b  = (uint8_t *)heap_malloc((size_t)ss_bytes);  /* shared secret (peer  side)  */

    if (!pk_a || !sk_a || !pk_b || !sk_b || !ss_a || !ss_b) {
        platform_print_string("!! Heap OOM in KEX benchmark !!\n");
        return;
    }

    platform_print_string("-> ");
    platform_print_string(ops->name);
    platform_print_string("\n   [Timing]\n");

    /* Untimed: generate peer's keypair (setup only) */
    ops->keygen(pk_b, sk_b);

    uint32_t s, e;

    /* Timed: local key generation */
    s = get_cycles(); ops->keygen(pk_a, sk_a);               e = get_cycles();
    p_cy("   Keygen:        ", CYCLE_DELTA(s, e));

    /* Timed: local party derives shared secret from peer's public key */
    s = get_cycles(); ops->shared_secret(ss_a, pk_b, sk_a);  e = get_cycles();
    p_cy("   SharedSecret:  ", CYCLE_DELTA(s, e));

    /* Correctness: peer derives the same secret (untimed) */
    ops->shared_secret(ss_b, pk_a, sk_b);
    uint8_t diff = 0u;
    for (size_t i = 0u; i < (size_t)ss_bytes; i++) diff |= (ss_a[i] ^ ss_b[i]);
    platform_print_string("   SS Match:       ");
    platform_print_string(diff == 0u ? "[OK]\n" : "[MISMATCH]\n");

    print_memory_report(type);
}

/* ================================================================== */
/* MASTER SUITE RUNNER                                               */
/* ================================================================== */

void run_all_benchmarks(void) {
    if (SIGN_REGISTRY_COUNT > 0u) {
        platform_print_string("[Signature / MAC Schemes]\n");
        for (size_t i = 0u; i < SIGN_REGISTRY_COUNT; i++)
            execute_signature_benchmark(sign_registry[i]->type);
    }

    if (AEAD_REGISTRY_COUNT > 0u) {
        platform_print_string("[Symmetric AEAD]\n");
        for (size_t i = 0u; i < AEAD_REGISTRY_COUNT; i++)
            execute_aead_benchmark(aead_registry[i]->type);
    }

    if (KDF_REGISTRY_COUNT > 0u) {
        platform_print_string("[Key Derivation]\n");
        for (size_t i = 0u; i < KDF_REGISTRY_COUNT; i++)
            execute_kdf_benchmark(kdf_registry[i]->type);
    }

    if (KEM_REGISTRY_COUNT > 0u) {
        platform_print_string("[Key Encapsulation (KEM)]\n");
        for (size_t i = 0u; i < KEM_REGISTRY_COUNT; i++)
            execute_kem_benchmark(kem_registry[i]->type);
    }

    if (KEX_REGISTRY_COUNT > 0u) {
        platform_print_string("[Key Exchange (KEX)]\n");
        for (size_t i = 0u; i < KEX_REGISTRY_COUNT; i++)
            execute_kex_benchmark(kex_registry[i]->type);
    }
}
