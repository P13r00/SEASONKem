#include "benchmark_metrics.h"

extern uint32_t get_cycles(void);

extern uint32_t _sheap, _eheap;
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

void heap_reset(void) {
    if (s_heap_base == NULL) heap_init();
    s_heap_cur  = s_heap_base;
    s_heap_peak = 0u;
}

void *heap_malloc(size_t size) {
    if (s_heap_base == NULL) heap_init();
    size = (size + 7u) & ~7u;
    if ((s_heap_cur + size) > s_heap_end) return NULL;

    void *p = (void *)s_heap_cur;
    s_heap_cur += size;

    volatile uint8_t *z = (volatile uint8_t *)p;
    for (size_t i = 0u; i < size; i++) z[i] = 0u;

    uint32_t used = (uint32_t)(s_heap_cur - s_heap_base);
    if (used > s_heap_peak) s_heap_peak = used;
    return p;
}

uint32_t heap_peak_used(void)     { return s_heap_peak; }
uint32_t heap_current_used(void)  { return (s_heap_base == NULL) ? 0u : (uint32_t)(s_heap_cur - s_heap_base); }
uint32_t heap_capacity(void)      { if (s_heap_base == NULL) heap_init(); return (uint32_t)(s_heap_end - s_heap_base); }

extern uint32_t _flash_aes_gcm_start,            _flash_aes_gcm_end;
extern uint32_t _flash_ascon80pq_start,          _flash_ascon80pq_end;
extern uint32_t _flash_asconaead128_start,       _flash_asconaead128_end;
extern uint32_t _flash_asconhash256_start,       _flash_asconhash256_end;
extern uint32_t _flash_asconxof_start,           _flash_asconxof_end;
extern uint32_t _flash_chacha_start,             _flash_chacha_end;
extern uint32_t _flash_ecdsap256_start,          _flash_ecdsap256_end;
extern uint32_t _flash_wolf_ed25519_start,       _flash_wolf_ed25519_end;
extern uint32_t _flash_hkdf_start,               _flash_hkdf_end;
extern uint32_t _flash_pqm4_dilithium2_start,    _flash_pqm4_dilithium2_end;
extern uint32_t _flash_pqm4_falcon512_start,     _flash_pqm4_falcon512_end;
extern uint32_t _flash_pqm4_kyber512_start,      _flash_pqm4_kyber512_end;
extern uint32_t _flash_pqm4_kyber768_start,      _flash_pqm4_kyber768_end;
extern uint32_t _flash_pqm4_sha3_256_start,      _flash_pqm4_sha3_256_end;
extern uint32_t _flash_pqm4_shake256_start,      _flash_pqm4_shake256_end;
extern uint32_t _flash_wolf_x25519_start,        _flash_wolf_x25519_end;

typedef struct {
    crypto_type_t   type;
    const uint32_t *flash_start;
    const uint32_t *flash_end;
} flash_entry_t;

static const flash_entry_t s_flash_table[] = {
    { ALG_AES_GCM,           &_flash_aes_gcm_start,         &_flash_aes_gcm_end         },
    { ALG_ASCON80PQ,         &_flash_ascon80pq_start,       &_flash_ascon80pq_end       },
    { ALG_ASCON_AEAD128,     &_flash_asconaead128_start,    &_flash_asconaead128_end    },
    { ALG_ASCON_HASH256,     &_flash_asconhash256_start,    &_flash_asconhash256_end    },
    { ALG_ASCON_XOF,         &_flash_asconxof_start,        &_flash_asconxof_end        },
    { ALG_CHACHA20_POLY1305, &_flash_chacha_start,          &_flash_chacha_end          },
    { ALG_ECDSA_P256,        &_flash_ecdsap256_start,       &_flash_ecdsap256_end       },
    { ALG_WOLF_ED25519,      &_flash_wolf_ed25519_start,    &_flash_wolf_ed25519_end    },
    { ALG_HKDF_SHA256,       &_flash_hkdf_start,            &_flash_hkdf_end            },
    { ALG_PQM4_DILITHIUM2,   &_flash_pqm4_dilithium2_start, &_flash_pqm4_dilithium2_end },
    { ALG_PQM4_FALCON512,    &_flash_pqm4_falcon512_start,  &_flash_pqm4_falcon512_end  },
    { ALG_PQM4_KYBER512,     &_flash_pqm4_kyber512_start,   &_flash_pqm4_kyber512_end   },
    { ALG_PQM4_KYBER768,     &_flash_pqm4_kyber768_start,   &_flash_pqm4_kyber768_end   },
    { ALG_PQM4_SHA3_256,     &_flash_pqm4_sha3_256_start,   &_flash_pqm4_sha3_256_end   },
    { ALG_PQM4_SHAKE256,     &_flash_pqm4_shake256_start,   &_flash_pqm4_shake256_end   },
    { ALG_WOLF_X25519,       &_flash_wolf_x25519_start,     &_flash_wolf_x25519_end     },
};
#define FLASH_TABLE_COUNT (sizeof(s_flash_table) / sizeof(s_flash_table[0]))

uint32_t measure_algo_flash(crypto_type_t type) {
    for (size_t i = 0u; i < FLASH_TABLE_COUNT; i++) {
        if (s_flash_table[i].type == type) {
            return (uint32_t)s_flash_table[i].flash_end - (uint32_t)s_flash_table[i].flash_start;
        }
    }
    return 0u;
}

extern uint32_t _sbss, _ebss, _sstack, _estack;

void fill_stack_watermark(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    while (p < (volatile uint32_t *)&_estack) *p++ = 0xDEADBEEFu;
}

void reset_stack_watermark(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    volatile uint32_t sp;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    volatile uint32_t *fence = (volatile uint32_t *)sp;
    while (p < fence) *p++ = 0xDEADBEEFu;
}

uint32_t measure_stack_used(void) {
    volatile uint32_t *p = (volatile uint32_t *)&_sstack;
    while (p < (volatile uint32_t *)&_estack && *p == 0xDEADBEEFu) p++;
    return (uint32_t)((uint8_t *)&_estack - (uint8_t *)p);
}

uint32_t measure_static_ram(void)      { return (uint32_t)((uint8_t *)&_ebss - (uint8_t *)&_sbss); }
uint32_t measure_stack_capacity(void)  { return (uint32_t)((uint8_t *)&_estack - (uint8_t *)&_sstack); }