format binary
use64
; Minimal FASM payload example for the packer.
;
; Why this file is handwritten as a raw binary instead of using FASM's normal
; ELF executable output:
;
; - the packer expects a very narrow SHELF payload
; - in particular, it wants ET_DYN with one PT_LOAD at file offset 0 and
;   virtual address 0
; - FASM's "format ELF64 executable" output produces ET_EXEC instead
; - You might be fine with another assembler though, but I haven't tested it
;
; So this sample builds the ELF header and the single PT_LOAD header directly.
; That keeps the final file exactly in the shape the packer expects while still
; being a normal ELF64 image the strip and pack stages can parse
SYS_WRITE = 1
SYS_EXIT  = 60
STDOUT    = 1

PT_LOAD   = 1
PF_X      = 1
PF_W      = 2
PF_R      = 4

ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ELFOSABI_GNU = 3
ET_DYN = 3
EM_X86_64 = 62

PAGE_ALIGN = 0x1000

org 0

; ELF header
db 0x7f, 'E', 'L', 'F'          ; ELF magic
db ELFCLASS64                   ; 64 bit ELF
db ELFDATA2LSB                  ; little-endian
db EV_CURRENT                   ; ELF version
db ELFOSABI_GNU                 ; GNU/Linux ABI tag
db 0                            ; ABI version
times 7 db 0                    ; unused e_ident padding

dw ET_DYN                       ; e_type = ET_DYN so the payload is relocatable
dw EM_X86_64                    ; x86_64 machine type
dd EV_CURRENT                   ; ELF version field
dq _start                       ; e_entry = offset of the first instruction inside the image
dq phdr - $$                    ; e_phoff = file offset of the program header table
dq 0                            ; e_shoff = no section headers in this tiny payload
dd 0                            ; e_flags = none
dw ehdr_size                    ; e_ehsize
dw phdr_size                    ; e_phentsize
dw 1                            ; e_phnum = exactly one PT_LOAD
dw 0                            ; e_shentsize = no section headers
dw 0                            ; e_shnum = no section headers
dw 0                            ; e_shstrndx = no section string table

ehdr_size = $ - $$

; Single PT_LOAD
phdr:
dd PT_LOAD                      ; p_type = one loadable segment
dd PF_R or PF_W or PF_X         ; p_flags = keep the tiny sample R/W/X for simplicity
dq 0                            ; p_offset = segment begins at file offset 0
dq 0                            ; p_vaddr = segment runtime offset 0, as expected by the packer
dq 0                            ; p_paddr = unused on Linux
dq file_end - $$                ; p_filesz = full file size
dq file_end - $$                ; p_memsz = no .bss here, so memsz == filesz
dq PAGE_ALIGN                   ; p_align = normal page alignment

phdr_size = $ - phdr

; Actual payload code
_start:
    ; TMZ explains: the call/pop trick is a fun compact way to materialize a RIP
    ; relative pointer without needing relocations or extra ELF machinery. 
    ; "call get_msg" pushes the address of the following byte, which is exactly 
    ; where msg starts, and then jumps forward to get_msg. Puters are neat!
call get_msg
msg db "hello from asm", 10
msg_len = $ - msg

get_msg:
    pop rsi                         ; runtime pointer to msg thanks to the call/pop trick above
    mov eax, SYS_WRITE              
    mov edi, STDOUT                 
    mov edx, msg_len                
    syscall

    mov eax, SYS_EXIT               
    mov edi, 7                      ; use exit code 7 
    syscall

file_end:
