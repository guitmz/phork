ENTRY(_start)

PHDRS
{
  shelf   PT_LOAD    FILEHDR PHDRS FLAGS(7);
  dynamic PT_DYNAMIC FLAGS(6);
  tls     PT_TLS     FLAGS(4);
}

SECTIONS
{
  PROVIDE(__ehdr_start = 0);
  PROVIDE(__executable_start = 0);
  . = SIZEOF_HEADERS;

  .note.gnu.build-id : { *(.note.gnu.build-id) } :shelf
  .hash             : { *(.hash) } :shelf
  .gnu.hash         : { *(.gnu.hash) } :shelf
  .dynsym           : { *(.dynsym) } :shelf
  .dynstr           : { *(.dynstr) } :shelf
  .gnu.version      : { *(.gnu.version) } :shelf
  .gnu.version_d    : { *(.gnu.version_d) } :shelf
  .gnu.version_r    : { *(.gnu.version_r) } :shelf
  .rela.dyn         : { *(.rela.dyn) } :shelf
  .rela.plt         : { *(.rela.plt) } :shelf

  .init             : { *(.init) } :shelf
  .plt              : { *(.plt*) } :shelf
  .text             : { *(.text*) } :shelf
  .fini             : { *(.fini) } :shelf

  .rodata           : { *(.rodata*) } :shelf
  .eh_frame_hdr     : { *(.eh_frame_hdr) } :shelf
  .eh_frame         : { KEEP(*(.eh_frame)) *(.eh_frame*) } :shelf
  .gcc_except_table : { *(.gcc_except_table*) } :shelf

  .preinit_array :
  {
    PROVIDE_HIDDEN(__preinit_array_start = .);
    KEEP(*(.preinit_array*))
    PROVIDE_HIDDEN(__preinit_array_end = .);
  } :shelf

  .init_array :
  {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
    KEEP(*(.init_array EXCLUDE_FILE(*crtbegin.o *crtbeginS.o *crtbeginT.o) .ctors))
    PROVIDE_HIDDEN(__init_array_end = .);
  } :shelf

  .fini_array :
  {
    PROVIDE_HIDDEN(__fini_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
    KEEP(*(.fini_array EXCLUDE_FILE(*crtbegin.o *crtbeginS.o *crtbeginT.o) .dtors))
    PROVIDE_HIDDEN(__fini_array_end = .);
  } :shelf

  .dynamic : { *(.dynamic) } :shelf :dynamic
  .got     : { *(.got*) } :shelf
  .data.rel.ro : { *(.data.rel.ro*) } :shelf
  .data    : { *(.data*) } :shelf
  .bss     : { *(.bss*) *(COMMON) } :shelf

  .tdata : { *(.tdata*) } :shelf :tls
  .tbss  : { *(.tbss*) *(.tcommon) } :shelf :tls

  /DISCARD/ :
  {
    *(.interp)
  }
}
