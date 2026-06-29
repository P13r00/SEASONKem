/*
 * stm32_renode_linker.ld
 *
 * RAM layout (128 KB, top-of-address-space stack):
 *
 *   0x20000000  ┌──────────────────────────┐  ← ORIGIN(RAM)
 *               │  .data  (initialised)    │
 *               ├──────────────────────────┤  ← _sdata / _edata
 *               │  .bss   (zeroed)         │  adapter RNG state,
 *               │                          │  pqm4 staging buffers
 *               ├──────────────────────────┤  ← _sbss / _ebss
 *               │  .heap  (NOLOAD, 16 KB)  │  bump-allocator pool
 *               │                          │  key material per run
 *               ├──────────────────────────┤  ← _sheap / _eheap / _sstack
 *               │  Stack  (grows ↓)        │
 *               │  ~96 KB available        │
 *               │  (≥ Dilithium2 50 KB need)│
 *   0x2001FFFF  └──────────────────────────┘  ← _estack
 *
 * Flash layout (1 MB):
 *
 *   0x08000000  ┌──────────────────────────┐
 *               │  .isr_vector             │
 *               ├──────────────────────────┤
 *               │  per-algo adapter code   │  each wrapped between
 *               │  (12 windows, see below) │  _flash_<algo>_{start,end}
 *               ├──────────────────────────┤
 *               │  all other .text* /      │
 *               │  .rodata* (catch-all)    │
 *               └──────────────────────────┘  ← _etext
 *
 * Flash footprint measurement:
 *   Each _flash_<algo>_start / _flash_<algo>_end pair encloses exactly
 *   the .text* and .rodata* sections from one adapter object file.
 *   measure_algo_flash() returns (end_addr - start_addr) in bytes.
 *   Unlinked adapters produce start == end → 0 B.
 *
 * The per-algo input-section patterns must appear BEFORE the catch-all
 * *(.text*) rule; GNU ld marks consumed sections as "already assigned"
 * so they will not be re-matched, giving exact, non-overlapping windows.
 */

ENTRY(Reset_Handler)

/* ================================================================== */
/* Memory map                                                          */
/* ================================================================== */

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
  RAM   (xrw) : ORIGIN = 0x20000000, LENGTH = 128K
}

/*
 * Heap size — 16 KB is sufficient for the largest single-run
 * working set:
 *   Dilithium2  pk(1312) + sk(2560) + sig(2420)          ≈  6.3 KB
 *   Kyber-768   pk(1184) + sk(2400) + ct(1088) + ss(64)  ≈  4.8 KB
 * 16 KB leaves 8+ KB of margin for alignment rounding and
 * future algorithm additions.
 */
HEAP_SIZE = 0x4000;     /* 16 384 B = 16 KB */

/* ================================================================== */
/* Sections                                                            */
/* ================================================================== */

SECTIONS
{
  /* ----------------------------------------------------------------
   * 1.  FLASH: interrupt vector table + code + constants
   * ---------------------------------------------------------------- */
  .text :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))    /* vector table must be the very first thing */

    /* ---------------------------------------------------------------
     * Per-algorithm Flash measurement windows.
     *
     * Pattern  *<stem>*(.text* .rodata*)  selects all code and
     * read-only data sections from the named adapter object.  Sections
     * captured here are NOT re-matched by the catch-all below.
     *
     * Build systems that use -ffunction-sections / -fdata-sections
     * produce input sections like .text.funcname and .rodata.varname —
     * the * suffix in (.text* .rodata*) covers all of these.
     *
     * Naming convention: the wildcard must match the stem of the C
     * source filename (e.g. adapters_crypto_aes_gcm.c → *crypto_aes_gcm*).
     * --------------------------------------------------------------- */

    _flash_aes_gcm_start        = .;
    *crypto_aes_gcm*            (.text* .rodata*)
    _flash_aes_gcm_end          = .;

    _flash_ascon80pq_start      = .;
    *crypto_ascon80pq*          (.text* .rodata*)
    _flash_ascon80pq_end        = .;

    _flash_asconhash_start      = .;
    *crypto_asconhash256*       (.text* .rodata*)
    _flash_asconhash_end        = .;

    _flash_chacha_start         = .;
    *crypto_chacha20_poly1305*  (.text* .rodata*)
    _flash_chacha_end           = .;

    _flash_ecdsap256_start      = .;
    *crypto_ecdsap256*          (.text* .rodata*)
    _flash_ecdsap256_end        = .;

    _flash_ed25519_start        = .;
    *crypto_ed25519*            (.text* .rodata*)
    _flash_ed25519_end          = .;

    _flash_hkdf_start           = .;
    *crypto_hkdfsha256*         (.text* .rodata*)
    _flash_hkdf_end             = .;

    _flash_dilithium2_start     = .;
    *crypto_dilithium2*         (.text* .rodata*)
    _flash_dilithium2_end       = .;

    _flash_falcon512_start      = .;
    *crypto_falcon512*          (.text* .rodata*)
    _flash_falcon512_end        = .;

    _flash_kyber512_start       = .;
    *crypto_kyber512*           (.text* .rodata*)
    _flash_kyber512_end         = .;

    _flash_kyber768_start       = .;
    *crypto_kyber768*           (.text* .rodata*)
    _flash_kyber768_end         = .;

    _flash_x25519_start         = .;
    *crypto_x25519*             (.text* .rodata*)
    _flash_x25519_end           = .;

    /* catch-all: benchmark_runner, platform HAL, wolfSSL, pqm4, libc stubs */
    *(.text)
    *(.text*)
    *(.rodata)
    *(.rodata*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  /* ----------------------------------------------------------------
   * 2.  Initialised global / static variables
   *     LMA (load address) in Flash; copied to VMA in RAM by Reset_Handler
   * ---------------------------------------------------------------- */
  _sidata = LOADADDR(.data);
  .data :
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data)
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM AT > FLASH

  /* ----------------------------------------------------------------
   * 3.  Uninitialised global / static variables
   *     Zeroed by Reset_Handler before main().
   *     Contains: adapter WC_RNG instances, pqm4 staging buffers
   *     (dilithium2 s_sm[2676], falcon512 s_sm[922], etc.)
   * ---------------------------------------------------------------- */
  .bss :
  {
    . = ALIGN(4);
    _sbss        = .;
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss        = .;
    __bss_end__  = _ebss;
  } > RAM

  /* ----------------------------------------------------------------
   * 4.  Heap — bump-allocator pool for per-benchmark key material.
   *
   *     NOLOAD: no image bytes allocated in the Flash binary.
   *     Reset_Handler does NOT zero this region (it only touches .bss).
   *     heap_reset() in benchmark_runner.c initialises the allocator
   *     pointer on first use and before every benchmark run.
   *
   *     Sits immediately above .bss; stack starts at _eheap so the
   *     full remaining RAM (≈96 KB) is available to the stack, which
   *     is enough for Dilithium2's ~50 KB internal NTT temporaries.
   * ---------------------------------------------------------------- */
  .heap (NOLOAD) :
  {
    . = ALIGN(8);       /* 8-byte aligned base for key-material safety */
    _sheap = .;
    . += HEAP_SIZE;
    _eheap = .;
  } > RAM

  /* ----------------------------------------------------------------
   * 5.  Stack — grows downward from top of RAM toward _eheap.
   *     _sstack marks the lowest valid address (painted with watermark).
   *     _estack is the initial SP value loaded from the vector table.
   * ---------------------------------------------------------------- */
  _sstack = _eheap;
  _estack = ORIGIN(RAM) + LENGTH(RAM);

  /* ----------------------------------------------------------------
   * 6.  Discard ARM exception-unwind and attribute sections.
   *     Do NOT list specific archives here (causes -nostdlib link errors).
   *     Section-name wildcards work without opening any archive.
   * ---------------------------------------------------------------- */
  /DISCARD/ :
  {
    *(.ARM.exidx*)
    *(.ARM.exidx)
    *(.ARM.attributes)
  }
}
