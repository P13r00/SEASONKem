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

    _flash_region_start = .;

    *(.text)
    *(.text*)
    *(.rodata)
    *(.rodata*)
    KEEP(*(.keep_alive))

    . = ALIGN(4);
    _flash_region_end = .;
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
