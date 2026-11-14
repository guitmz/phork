format ELF64 executable 3

include "../utils.inc"
include "tools.inc"

segment readable executable
entry $ 

; Usage:
;   mkpack <stub-elf> <input-shelf-elf> <output-packed> [--xor-meta] [--xor-payload]
;
; The output layout is:
;   [stub ELF][SHELFBN1 metadata][stripped payload][SPACK footer]
    mov rcx, [rsp]                               ; rcx = argc
    cmp rcx, 4                                   ; expect argv[0] + 3 user supplied paths, plus optional flags
    jl usage

    mov rax, [rsp + 16]                          ; argv[1] = existing stub ELF
    mov [stubPath], rax
    mov rax, [rsp + 24]                          ; argv[2] = input SHELF payload
    mov [inputPath], rax
    mov rax, [rsp + 32]                          ; argv[3] = packed output path
    mov [outputPath], rax

    ; Optional transform flags, in any order, after the three required paths.
    ; This has to run before any call/push disturbs rsp, since it still
    ; addresses argv straight off the original entry stack
    mov qword [packFlagsValue], 0
    mov rdx, rcx                                 ; rdx = argc
    sub rdx, 4                                   ; rdx = number of optional flag args
    jz .flagsDone
    lea rbx, [rsp + 40]                          ; argv[4] address
    .flagLoop:
        mov rdi, [rbx]                           ; rdi = this flag string
        lea rsi, [flagXorMetaStr]
        call strEquals
        test al, al
        jz .notXorMeta
        or qword [packFlagsValue], SPACK_FLAG_META_XOR
        jmp .nextFlag
        .notXorMeta:
        mov rdi, [rbx]
        lea rsi, [flagXorPayloadStr]
        call strEquals
        test al, al
        jz .notXorPayload
        or qword [packFlagsValue], SPACK_FLAG_PAYLOAD_XOR
        jmp .nextFlag
        .notXorPayload:
        jmp usage                                ; unrecognized flag
        .nextFlag:
        add rbx, 8
        dec rdx
        jnz .flagLoop
    .flagsDone:

    ; Stage the stub ELF
    mov rdi, [stubPath]                          
    mov rsi, O_RDONLY                            
    xor rdx, rdx                                 
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [stubFd], rax                            ; remember the stub fd for the subsequent read

    mov rdi, rax                                 
    lea rsi, [stubStat]                          
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed

    cmp qword [stubStat.st_size], BUFFER_SIZE    ; reject anything too big for the fixed staging buffer
    jg fileTooLarge

    mov rdi, [stubFd]                            
    lea rsi, [stubBuf]                           
    mov rdx, [stubStat.st_size]                  
    mov rax, SYS_READ
    syscall
    cmp rax, [stubStat.st_size]                  ; this builder expects a full one shot read
    jne fileReadFailed

    ; Stage and parse the input SHELF ELF
    mov rdi, [inputPath]                         
    mov rsi, O_RDONLY                            
    xor rdx, rdx                                
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [inputFd], rax
    mov r12, rax                                  ; r12 keeps the payload fd across the rax clobbering reads below

    mov rdi, r12                                 ; payload fd
    lea rsi, [fileStat]                          ; struct stat for the payload file
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed

    cmp qword [fileStat.st_size], BUFFER_SIZE    ; same fixed buffer limit as the stub above
    jg fileTooLarge

    mov rdi, r12                                 ; payload fd
    lea rsi, [buf]                               ; staging buffer for the payload ELF
    mov rdx, [fileStat.st_size]                  ; input ELF byte count
    mov rax, SYS_READ
    syscall
    test rax, rax
    jle fileReadFailed

    cmp dword [buf + EHDR.magic], 0x464c457f      ; require ELF magic
    jne invalidElf
    cmp byte [buf + EHDR.class], ELFCLASS64       ; packer payloads are ELF64 only
    jne invalidElf
    cmp byte [buf + EHDR.data], ELFDATA2LSB       ; packer payloads are little-endian only
    jne invalidElf
    cmp word [buf + EHDR.type], ET_DYN            ; the payload must be ET_DYN
    jne invalidElf
    cmp word [buf + EHDR.phentsize], sizeof.PHDR  ; require native ELF64 PHDR size
    jne invalidElf

    mov rax, qword [buf + EHDR.entry]            ; get the OEP
    mov [entryValue], rax
    mov rax, qword [buf + EHDR.phoff]            ; capture where the original PHDR table begins in the file
    mov [phoffValue], rax
    movzx eax, word [buf + EHDR.phnum]           ; number of PHDR entries
    mov [phnumValue], rax
    movzx eax, word [buf + EHDR.phentsize]       ; bytes per PHDR entry
    mov [phentsizeValue], rax

    mov rax, [phoffValue]                            ; start with the PHDR table file offset
    mov rdx, [phnumValue]                            ; number of PHDR entries
    mov rcx, [phentsizeValue]                        ; size of each PHDR entry
    imul rdx, rcx                                    ; total PHDR table byte size
    add rax, rdx                                     ; first byte after the stripped ELF front matter
    mov [headerSpan], rax                            ; header_span is exactly what the payload strip stage removes

    lea rbx, [buf]                               ; staged ELF base
    add rbx, [phoffValue]                        ; first PHDR
    mov rcx, [phnumValue]                        ; PHDRs left to inspect
    .scanPhdrs:
        test rcx, rcx
        jz .scanDone
        cmp dword [rbx + PHDR.type], PT_LOAD     ; does this PHDR describe the one loadable segment?
        jne .notLoad
        inc qword [loadCount]                    ; count PT_LOAD entries so we can reject multi segment payloads
        cmp qword [loadCount], 1
        jne invalidShelf
        mov eax, dword [rbx + PHDR.flags]        ; preserve the original ELF PF_* bits for later translation
        mov dword [loadFlagsValue], eax
        mov rax, qword [rbx + PHDR.offset]       ; capture PT_LOAD.p_offset
        mov [loadOffsetValue], rax
        mov rax, qword [rbx + PHDR.vaddr]        ; capture PT_LOAD.p_vaddr
        mov [loadVaddrValue], rax
        mov rax, qword [rbx + PHDR.filesz]       ; capture PT_LOAD.p_filesz
        mov [loadFileszValue], rax
        mov rax, qword [rbx + PHDR.memsz]        ; capture PT_LOAD.p_memsz
        mov [loadMemszValue], rax
        jmp .nextPhdr
        .notLoad:
        cmp dword [rbx + PHDR.type], PT_DYNAMIC  ; optional PT_DYNAMIC metadata for relocations
        jne .notDynamic
        mov rax, qword [rbx + PHDR.vaddr]        ; capture PT_DYNAMIC.p_vaddr
        mov [dynamicVaddrValue], rax
        mov rax, qword [rbx + PHDR.memsz]        ; capture PT_DYNAMIC.p_memsz
        mov [dynamicMemszValue], rax
        jmp .nextPhdr
        .notDynamic:
        cmp dword [rbx + PHDR.type], PT_TLS      ; optional PT_TLS metadata for direct entry TLS setup
        jne .nextPhdr
        mov rax, qword [rbx + PHDR.vaddr]        ; capture PT_TLS.p_vaddr
        mov [tlsVaddrValue], rax
        mov rax, qword [rbx + PHDR.filesz]       ; capture PT_TLS.p_filesz
        mov [tlsFileszValue], rax
        mov rax, qword [rbx + PHDR.memsz]        ; capture PT_TLS.p_memsz
        mov [tlsMemszValue], rax
        mov rax, qword [rbx + PHDR.align]        ; capture PT_TLS.p_align
        mov [tlsAlignValue], rax
        .nextPhdr:
        add rbx, sizeof.PHDR
        dec rcx
        jmp .scanPhdrs
    .scanDone:

    ; SHELF payloads are restricted to a single PT_LOAD sitting at file offset 0
    ; and vaddr 0, which is what lets the runtime loader map the stripped
    ; payload straight in without any relocation of its own
    cmp qword [loadCount], 1
    jne invalidShelf
    cmp qword [loadOffsetValue], 0
    jne invalidShelf
    cmp qword [loadVaddrValue], 0
    jne invalidShelf

    mov rax, [loadFileszValue]
    cmp rax, [headerSpan]                        ; header_span bytes are sliced out of this same PT_LOAD, so
    jb invalidShelf                               ; p_filesz - header_span must never be allowed to underflow
    sub rax, [headerSpan]
    mov [payloadSize], rax

    mov rax, [phnumValue]                        ; PHDR count
    imul rax, [phentsizeValue]                   ; PHDR blob byte size we will copy into SHELFBN1
    mov [phdrBlobSize], rax
    cmp qword [phdrBlobSize], SHELF_META_MAX_PHDR_BLOB  ; matches the runtime loader's own phdr scratch limit
    ja phdrBlobTooLarge

    ; Open packed output and write all regions in order
    mov rdi, [outputPath]                        ; final packed output path
    mov rsi, O_WRONLY or O_CREAT or O_TRUNC      ; create/truncate the packed output
    mov rdx, MODE_0755                           ; leave the resulting file executable
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [outputFd], rax                          ; remember output fd for every write call below

    ; Write the stub bytes first so the packed file remains directly exec-able (is that a word?)
    mov rdi, rax
    lea rsi, [stubBuf]
    mov rdx, [stubStat.st_size]
    call writeBuf

    ; Metadata starts immediately after the stub
    mov rax, [stubStat.st_size]
    mov [metaOffValue], rax

    ; Build SHELFBN1 metadata in memory first so a single optional XOR pass
    ; can cover the whole record (magic included) exactly like the runtime
    ; decoder expects
    lea rdi, [metaBuf]
    lea rsi, [metaBinMagic]
    mov rcx, metaBinMagicLen
    rep movsb                                    ; metaBuf + 8
    mov rax, [entryValue]                        ; SHELFBN1+8: OEP
    mov [rdi], rax
    add rdi, 8
    mov rax, [phoffValue]                        ; SHELFBN1+16: original phoff
    mov [rdi], rax
    add rdi, 8
    mov rax, [phnumValue]                        ; SHELFBN1+24: phnum, read back by spack_tool as is
    mov [rdi], rax
    add rdi, 8
    mov rax, [phentsizeValue]                     ; SHELFBN1+32: phentsize
    mov [rdi], rax
    add rdi, 8
    mov rax, [headerSpan]                         ; SHELFBN1+40: header_span, stripped from the front of the payload
    mov [rdi], rax
    add rdi, 8
    mov rax, [loadOffsetValue]                    ; SHELFBN1+48: load_offset, always 0 per the single PT_LOAD invariant above
    mov [rdi], rax
    add rdi, 8
    mov rax, [loadVaddrValue]                    ; SHELFBN1+56: load_vaddr, always 0 for the same reason
    mov [rdi], rax
    add rdi, 8
    mov rax, [loadFileszValue]                   ; SHELFBN1+64: load_filesz, header_span + payload bytes still to come
    mov [rdi], rax
    add rdi, 8
    mov rax, [loadMemszValue]                    ; SHELFBN1+72: load_memsz
    mov [rdi], rax
    add rdi, 8
    mov rax, [loadFlagsValue]                    ; SHELFBN1+80: load_flags, PF_* bits from the source PHDR
    mov [rdi], rax
    add rdi, 8
    mov rax, [dynamicVaddrValue]                 ; SHELFBN1+88: dynamic_vaddr, 0 if no PT_DYNAMIC was found
    mov [rdi], rax
    add rdi, 8
    mov rax, [dynamicMemszValue]                 ; SHELFBN1+96: dynamic_memsz
    mov [rdi], rax
    add rdi, 8
    mov rax, [tlsVaddrValue]                     ; SHELFBN1+104: tls_vaddr, 0 if no PT_TLS was found
    mov [rdi], rax
    add rdi, 8
    mov rax, [tlsFileszValue]                    ; SHELFBN1+112: tls_filesz
    mov [rdi], rax
    add rdi, 8
    mov rax, [tlsMemszValue]                     ; SHELFBN1+120: tls_memsz
    mov [rdi], rax
    add rdi, 8
    mov rax, [tlsAlignValue]                     ; SHELFBN1+128: tls_align
    mov [rdi], rax
    add rdi, 8
    mov rax, [phdrBlobSize]                      ; SHELFBN1+136: phdr_blob_size, byte count of the raw PHDR copy that follows
    mov [rdi], rax
    add rdi, 8
    lea rsi, [buf]                                ; append the raw PHDR bytes after the fixed SHELFBN1 fields
    add rsi, [phoffValue]
    mov rcx, [phdrBlobSize]
    rep movsb

    mov rax, metaBinMagicLen                     ; start with 8 byte "SHELFBN1"
    add rax, (17 * 8)                            ; add the fixed 17 u64 metadata fields
    add rax, [phdrBlobSize]                      ; add the raw PHDR blob size
    mov [metaSizeValue], rax

    test qword [packFlagsValue], SPACK_FLAG_META_XOR
    jz .metaXorDone
    lea rsi, [metaBuf]
    mov rcx, [metaSizeValue]
    call xorBuf
    .metaXorDone:

    mov rdi, [outputFd]                          ; write the whole SHELFBN1 record in one go
    lea rsi, [metaBuf]
    mov rdx, [metaSizeValue]
    call writeBuf

    ; Payload follows metadata immediately
    mov rax, [metaOffValue]
    add rax, [metaSizeValue]
    mov [payloadOffValue], rax

    test qword [packFlagsValue], SPACK_FLAG_PAYLOAD_XOR
    jz .payloadXorDone
    lea rsi, [buf]
    add rsi, [headerSpan]
    mov rcx, [payloadSize]
    call xorBuf
    .payloadXorDone:

    mov rdi, [outputFd]                          ; append the stripped payload body after the metadata
    lea rsi, [buf]
    add rsi, [headerSpan]
    mov rdx, [payloadSize]
    call writeBuf

    ; Footer is the last structure in the packed file, fixed at SPACK_FOOTER_SIZE
    ; bytes so spack_tool can find it by seeking back from EOF without reading
    ; anything else first
    mov rdi, [outputFd]
    lea rsi, [packMagic]                         ; footer+0: "SPACK01!" magic
    mov rdx, packMagicLen
    call writeBuf
    mov rdi, [outputFd]
    mov rax, [metaOffValue]                      ; footer+8: meta_off
    call writeU64Le
    mov rdi, [outputFd]
    mov rax, [metaSizeValue]                     ; footer+16: meta_len
    call writeU64Le
    mov rdi, [outputFd]
    mov rax, [payloadOffValue]                   ; footer+24: payload_off
    call writeU64Le
    mov rdi, [outputFd]
    mov rax, [payloadSize]                       ; footer+32: payload_len
    call writeU64Le
    mov rdi, [outputFd]
    mov rax, [packFlagsValue]                    ; footer+40: flags
    call writeU64Le

    mov rdi, [outputFd]
    mov rax, SYS_CLOSE
    syscall
    test rax, rax                                ; a failed close can still mean the output never made it to disk
    js closeFailed

    mov edi, 0                                   ; exit code 0, packing succeeded
    mov eax, SYS_EXIT
    syscall

writeU64Le:
    ; rdi = output fd
    ; rax = 64 bit value to emit
    ;
    ; The packer format uses little-endian u64 fields throughout, and because
    ; this code runs on little-endian x64 already, writing the raw 8 byte
    ; register image from a temporary slot produces the correct on disk order.
    mov [u64Tmp], rax
    lea rsi, [u64Tmp]
    mov rdx, 8
    call writeBuf
    ret

writeBuf:
    ; rdi = destination fd
    ; rsi = source bytes
    ; rdx = byte count
    mov rax, SYS_WRITE
    syscall
    cmp rax, rdx                                 ; treat short writes as fatal so the packed file is never partial/silent
    jne fileWriteFailed
    ret

xorBuf:
    ; rsi = buffer, rcx = byte count. XORs the buffer in place with the fixed
    ; SPACK key, matching the runtime decoder's xorBufferInPlace exactly
    push rax
    push rsi
    push rcx
    .loop:
        test rcx, rcx
        jz .done
        xor byte [rsi], SPACK_XOR_KEY
        inc rsi
        dec rcx
        jmp .loop
    .done:
    pop rcx
    pop rsi
    pop rax
    ret

strEquals:
    ; rdi = argv string (arbitrary length), rsi = literal null terminated
    ; string. Returns al = 1 if equal, else 0. Leaves rdi/rsi clobbered but
    ; must not touch rbx/rcx/rdx: the flag loop keeps its remaining-count
    ; counter in rdx across this call
    .cmpLoop:
        mov al, [rdi]
        mov r10b, [rsi]
        cmp al, r10b
        jne .notEqual
        test al, al
        jz .isEqual
        inc rdi
        inc rsi
        jmp .cmpLoop
    .notEqual:
    xor al, al
    ret
    .isEqual:
    mov al, 1
    ret

usage:
    mov rdi, STDOUT
    lea rsi, [usageMsg]
    mov rdx, usageMsgLen
    call writeBuf
    mov edi, 1                                   ; exit code 1, bad usage
    mov eax, SYS_EXIT
    syscall

openFailed:
    WRITE_AND_EXIT openFailedMsg, openFailedMsgLen
fstatFailed:
    WRITE_AND_EXIT fstatFailedMsg, fstatFailedMsgLen
fileTooLarge:
    WRITE_AND_EXIT fileTooLargeMsg, fileTooLargeMsgLen
fileReadFailed:
    WRITE_AND_EXIT fileReadFailedMsg, fileReadFailedMsgLen
fileWriteFailed:
    WRITE_AND_EXIT fileWriteFailedMsg, fileWriteFailedMsgLen
invalidElf:
    WRITE_AND_EXIT invalidElfMsg, invalidElfMsgLen
invalidShelf:
    WRITE_AND_EXIT invalidShelfMsg, invalidShelfMsgLen
phdrBlobTooLarge:
    WRITE_AND_EXIT phdrBlobTooLargeMsg, phdrBlobTooLargeMsgLen
closeFailed:
    WRITE_AND_EXIT closeFailedMsg, closeFailedMsgLen

segment readable
usageMsg            db "Usage: mkpack <stub-elf> <input-shelf-elf> <output-packed> [--xor-meta] [--xor-payload]", 0xa
usageMsgLen         = $ - usageMsg
metaBinMagic        db "SHELFBN1"               ; also the string the runtime loader validates on load
metaBinMagicLen     = $ - metaBinMagic
packMagic           db "SPACK01!"                ; checked by spack_tool's footer validation
packMagicLen        = $ - packMagic
flagXorMetaStr      db "--xor-meta", 0           ; literals matched by strEquals in the flag parsing loop above
flagXorPayloadStr   db "--xor-payload", 0

openFailedMsg       db "Failed to open file", 0xa
openFailedMsgLen    = $ - openFailedMsg
fstatFailedMsg      db "Failed to stat file", 0xa
fstatFailedMsgLen   = $ - fstatFailedMsg
fileTooLargeMsg     db "Input ELF is larger than the tool buffer", 0xa
fileTooLargeMsgLen  = $ - fileTooLargeMsg
fileReadFailedMsg   db "Failed to read input file", 0xa
fileReadFailedMsgLen = $ - fileReadFailedMsg
fileWriteFailedMsg  db "Failed to write output file", 0xa
fileWriteFailedMsgLen = $ - fileWriteFailedMsg
invalidElfMsg       db "Input is not a supported ET_DYN ELF64 image", 0xa
invalidElfMsgLen    = $ - invalidElfMsg
invalidShelfMsg     db "Input ELF is not shaped like a one PT_LOAD SHELF image", 0xa
invalidShelfMsgLen  = $ - invalidShelfMsg
phdrBlobTooLargeMsg db "Input ELF has more PHDR bytes than the runtime loader accepts", 0xa
phdrBlobTooLargeMsgLen = $ - phdrBlobTooLargeMsg
closeFailedMsg      db "Failed to close output file", 0xa
closeFailedMsgLen   = $ - closeFailedMsg

segment readable writeable
stubStat         STAT
fileStat         STAT
stubFd           rq 1
inputFd          rq 1
outputFd         rq 1
stubPath         rq 1
inputPath        rq 1
outputPath       rq 1
entryValue       rq 1
phoffValue       rq 1
phnumValue       rq 1
phentsizeValue   rq 1
headerSpan       rq 1
loadOffsetValue  rq 1
loadVaddrValue   rq 1
loadFileszValue  rq 1
loadMemszValue   rq 1
loadFlagsValue   rq 1
dynamicVaddrValue rq 1
dynamicMemszValue rq 1
tlsVaddrValue    rq 1
tlsFileszValue   rq 1
tlsMemszValue    rq 1
tlsAlignValue    rq 1
phdrBlobSize     rq 1
payloadSize      rq 1
loadCount        rq 1
metaOffValue     rq 1
metaSizeValue    rq 1
payloadOffValue  rq 1
packFlagsValue   rq 1
u64Tmp           rq 1
stubBuf          rb BUFFER_SIZE
buf              rb BUFFER_SIZE
metaBuf          rb SHELF_META_MAX_SIZE ; fixed header + max phdr blob, see tools.inc
