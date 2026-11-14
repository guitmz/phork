O_WRONLY = 1
O_CREAT  = 64
O_TRUNC  = 512
MODE_0755 = 493                 ; octal 0755 rwxr-xr-x
MODE_0644 = 420                 ; octal 0644 rw-r--r--
SYS_LSEEK = 8    
SEEK_END = 0x2               
SPACK_FOOTER_SIZE = 48          ; magic(8) + meta_off/meta_len/payload_off/payload_len/flags, 5 u64 fields(40)
SHELF_META_FIXED_SIZE = 144     ; 8 byte magic + the 17 fixed u64 fields mkpack writes before the raw PHDR blob
; The runtime's phdr scratch buffer (phork.asm's phdrBlob) is 4096 bytes, so
; that is the largest raw PHDR blob a pack can legally carry. Total metadata
; size is therefore bounded by the fixed header plus that same 4096 byte cap
SHELF_META_MAX_PHDR_BLOB = 4096
SHELF_META_MAX_SIZE = SHELF_META_FIXED_SIZE + SHELF_META_MAX_PHDR_BLOB

macro WRITE_AND_EXIT msgSym, lenSym
{
    mov rdi, STDOUT
    lea rsi, [msgSym]
    mov rdx, lenSym
    call writeBuf
    mov edi, 1
    mov eax, SYS_EXIT
    syscall
}