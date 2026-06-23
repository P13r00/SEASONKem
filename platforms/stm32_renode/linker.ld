ENTRY(Reset_Handler)

MEMORY
{
  FLASH (rx)      : ORIGIN = 0x08000000, LENGTH = 1024K
  RAM (xrw)       : ORIGIN = 0x20000000, LENGTH = 128K
}

_sstack = _ebss;
_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
  /* 1. Vector table and execution code must go into FLASH */
  .text :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))   /* Keep the explicit vector layout first! */
    *(.text)
    *(.text*)
    *(.rodata)
    *(.rodata*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  /* 2. Global variable initializations (Loaded from Flash to RAM) */
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

  /* 3. Empty runtime data allocations (Must only exist in RAM) */
  .bss :
  {
    . = ALIGN(4);
    _sbss = .;
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
    __bss_end__ = _ebss;
  } > RAM

  /* 4. Discard ARM exception-unwind and attribute sections.
        Do NOT name archives (libc.a etc.) here — ld must open them to apply
        the rule, but -nostdlib removes them from the search path, causing
        "cannot find libc.a". Section-name wildcards work without opening any archive. */
  /DISCARD/ :
  {
    *(.ARM.exidx*)
    *(.ARM.exidx)
    *(.ARM.attributes)
  }
}