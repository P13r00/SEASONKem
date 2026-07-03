MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
  RAM   (xrw) : ORIGIN = 0x20000000, LENGTH = 128K
}

HEAP_SIZE = 0x4000; /* 16KB */

SECTIONS
{
  .text :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))    /* vector table must be the very first thing */
    
    /* Pattern  *<stem>*(.text* .rodata*)  selects all code and read-only data sections from the named adapter object. 
     * Naming: stem of the C filename (e.g. adapters_crypto_aes_gcm.c → *crypto_aes_gcm*).
     */

    _flash_aes_gcm_start        = .;
    *crypto_aes_gcm*            (.text* .rodata*)
    _flash_aes_gcm_end          = .;

    _flash_ascon80pq_start      = .;
    *crypto_ascon80pq*          (.text* .rodata*)
    _flash_ascon80pq_end        = .;

    _flash_asconaead128_start   = .;
    *crypto_asconaead128*       (.text* .rodata*)
    _flash_asconaead128_end     = .;

    _flash_asconhash256_start   = .;
    *crypto_asconhash256*       (.text* .rodata*)
    _flash_asconhash256_end     = .;

    _flash_asconxof_start       = .;
    *crypto_asconxof*           (.text* .rodata*)
    _flash_asconxof_end         = .;

    _flash_blake3_start         = .;
    *crypto_blake3*             (.text* .rodata*)
    _flash_blake3_end           = .;

    _flash_chacha_start         = .;
    *crypto_chacha20_poly1305*  (.text* .rodata*)
    _flash_chacha_end           = .;

    _flash_ecdhp256_start       = .;
    *crypto_ecdhp256*           (.text* .rodata*)
    _flash_ecdhp256_end         = .;

    _flash_ecdsap256_start      = .;
    *crypto_ecdsap256*          (.text* .rodata*)
    _flash_ecdsap256_end        = .;

    _flash_wolf_ed25519_start        = .;
    *crypto_wolf_ed25519*            (.text* .rodata*)
    _flash_wolf_ed25519_end          = .;

    _flash_hkdf_start           = .;
    *crypto_hkdfsha256*         (.text* .rodata*)
    _flash_hkdf_end             = .;

    _flash_pqm4_dilithium2_start     = .;
    *crypto_pqm4_dilithium2*         (.text* .rodata*)
    _flash_pqm4_dilithium2_end       = .;

    _flash_pqm4_falcon512_start      = .;
    *crypto_pqm4_falcon512*          (.text* .rodata*)
    _flash_pqm4_falcon512_end        = .;

    _flash_pqm4_kyber512_start       = .;
    *crypto_pqm4_kyber512*           (.text* .rodata*)
    _flash_pqm4_kyber512_end         = .;

    _flash_pqm4_kyber768_start       = .;
    *crypto_pqm4_kyber768*           (.text* .rodata*)
    _flash_pqm4_kyber768_end         = .;

    _flash_pqm4_sha3_256_start       = .;
    *crypto_pqm4_sha3_256*           (.text* .rodata*)
    _flash_pqm4_sha3_256_end         = .;

    _flash_pqm4_shake256_start       = .;
    *crypto_pqm4_shake256*           (.text* .rodata*)
    _flash_pqm4_shake256_end         = .;

    _flash_photonbeetle_start        = .;
    *crypto_photonbeetleaead*        (.text* .rodata*)
    _flash_photonbeetle_end          = .;

    _flash_wolf_x25519_start         = .;
    *crypto_wolf_x25519*             (.text* .rodata*)
    _flash_wolf_x25519_end           = .;

    _flash_lwc_sparkle_aead256_start = .;
    *crypto_lwc_sparkle_aead256*      (.text* .rodata*)
    _flash_lwc_sparkle_aead256_end   = .;

    _flash_lwc_sparkle_aead192_start = .;
    *crypto_lwc_sparkle_aead192*     (.text* .rodata*)
    _flash_lwc_sparkle_aead192_end   = .;
    
    _flash_lwc_sparkle_hashxof_start = .;
    *crypto_lwc_sparkle_hashxof*      (.text* .rodata*)
    _flash_lwc_sparkle_hashxof_end   = .;
    
    _flash_lwc_sparkle_hash256_start = .;
    *crypto_lwc_sparkle_hash256*      (.text* .rodata*)
    _flash_lwc_sparkle_hash256_end   = .;
    
    _flash_lwc_xoodyak_hash_start    = .;
    *crypto_lwc_xoodyak_hash*         (.text* .rodata*)
    _flash_lwc_xoodyak_hash_end      = .;

    _flash_lwc_ascon80pq_aead_start  = .;
    *crypto_lwc_ascon80pq_aead*         (.text* .rodata*)
    _flash_lwc_ascon80pq_aead_end    = .;


    /* catch-all: benchmark_runner, platform HAL, wolfSSL, pqm4, libc stubs */
    *(.text)
    *(.text*)
    *(.rodata)
    *(.rodata*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  /* Initialised global / static variables */
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

  /* Uninitialised global / static variables */
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

  /* Heap — bump-allocator */
  .heap (NOLOAD) :
  {
    . = ALIGN(8);
    _sheap = .;
    . += HEAP_SIZE;
    _eheap = .;
  } > RAM

  _sstack = _eheap;
  _estack = ORIGIN(RAM) + LENGTH(RAM);

  /DISCARD/ :
  {
    *(.ARM.exidx*)
    *(.ARM.exidx)
    *(.ARM.attributes)
  }
}
