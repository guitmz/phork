format ELF64 executable 3

include "utils.inc"                          
; This is the self loading SHELF packer stub.
;
; The packed file is still a normal ELF executable at the front, so Linux can
; start it directly. After the stub bytes, mkpack appends:
;
;   [binary SHELF metadata blob]
;   [stripped payload blob]
;   [SPACK footer]
;
; At runtime the stub reopens /proc/self/exe, reads the footer from the very
; end of the file, uses that footer to locate the embedded metadata/payload
; blobs, reconstructs synthetic ELF header state in memory, and then reuses the
; same direct entry relocation/TLS/stack path as the headless SHELF loader

PACK_MAGIC_LEN   = 8                             ; length of "SPACK01!"
PACK_FOOTER_SIZE = 48                            ; magic + 5 u64 fields (meta off/len, payload off/len, flags)

segment readable executable                      ; the packed stub's own code
entry $                                          ; entry point is just the first byte of this segment, no named label needed
    ; Capture the original process entry view.
    ;
    ; The packed stub does not need to drop any metadata path from argv.
    ; The target program should observe the exact same argc/argv that the kernel
    ; gave the packed file itself
    mov rcx, [rsp]                               ; argc sits at the very top of the initial stack 
    mov [targetArgc], rcx                        ; preserve that argc so the target sees it unchanged
    lea rax, [rsp + 8]                           ; address of argv[] itself, not argv[0]'s value
    mov [targetArgv], rax
    mov rax, [rsp + 8]                           ; argv[0] itself: the packed file's pathname as the kernel invoked it
    mov [targetPath], rax                        ; kept for AT_EXECFN rewriting later
    lea rax, [rsp + rcx * 8 + 16]                ; skip argc + argv[] + argv NULL to reach envp[0]
    mov [targetEnvp], rax                        ; kept only long enough to scan for PHORK_DEBUG below, then the target builds its own envp

    ; Optional debug activation
    mov byte [debugEnabled], 0
    mov rbx, [targetEnvp]                        ; walks envp[] one pointer at a time
    .scanDebugEnv:
        mov rdi, [rbx]
        test rdi, rdi                            ; NULL terminates envp[]
        jz .debugEnvDone
        lea rsi, [packDebugEnvPrefix]
        mov rdx, packDebugEnvPrefixLen
        .debugEnvCmp:
            test rdx, rdx                            ; reaching zero means the whole prefix matched
            jz .debugEnvMatched
            mov al, [rdi]
            mov cl, [rsi]
            cmp al, cl                              ; mismatch means this env var is not the debug switch
            jne .debugEnvNext
            inc rdi
            inc rsi
            dec rdx
            jmp .debugEnvCmp
        .debugEnvMatched:
            mov al, [rdi]                        ; load the byte immediately after the matched prefix
            test al, al                          ; empty value does not enable tracing
            jz .debugEnvNext
            cmp al, '0'                          ; explicit zero also means tracing disabled
            je .debugEnvNext
            mov byte [debugEnabled], 1           ; any other non empty value enables tracing
            lea rsi, [packVersionMsg]
            mov rdx, packVersionMsgLen
            call debugWrite
            lea rsi, [dbgEnabledMsg]
            mov rdx, dbgEnabledMsgLen
            call debugWrite
            jmp .debugEnvDone
        .debugEnvNext:
        add rbx, 8
        jmp .scanDebugEnv
    .debugEnvDone:

    ; Open our own image on disk through /proc/self/exe.
    ;
    ; The kernel ignores the appended packer blobs when it maps the stub, but
    ; they are still present at the end of the executable file. Reopening the
    ; file lets the stub recover those bytes without needing any extra files
    lea rdi, [selfExePath]
    mov rsi, O_RDONLY                            
    xor rdx, rdx                                 
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [targetFd], rax                          ; keep the self fd open until stack.inc closes it at handoff time

    mov rdi, rax
    lea rsi, [fstat]                             
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed

    cmp qword [fstat.st_size], PACK_FOOTER_SIZE     ; packed files must at least be large enough to hold the footer
    jb invalidFooterTooSmall

    ; Read and validate the SPACK footer at EOF.
    ;
    ; Layout:
    ;   magic[8] = "SPACK01!"
    ;   meta_off   u64
    ;   meta_len   u64
    ;   payload_off u64
    ;   payload_len u64
    ;   flags      u64
    mov r10, [fstat.st_size]                     ; anchor point for locating the footer at the very EOF
    sub r10, PACK_FOOTER_SIZE                    ; file offset where the footer begins
    mov [footerOff], r10                         ; remember the first footer byte for later embedded range validation
    mov rdi, [targetFd]
    lea rsi, [footerBuf]
    mov rdx, PACK_FOOTER_SIZE
    mov rax, SYS_PREAD64
    syscall
    cmp rax, PACK_FOOTER_SIZE                   ; short footer reads are treated as malformed packs
    jne invalidFooterRead

    lea rsi, [footerBuf]
    lea rdi, [packMagic]
    mov rcx, PACK_MAGIC_LEN
    .checkPackMagic:
        test rcx, rcx                            ; finishing the loop means the full footer magic matched
        jz .packMagicDone
        mov al, [rsi]
        mov dl, [rdi]
        cmp al, dl                              ; mismatch means the executable is not a packed SPACK file
        jne invalidFooterMagic
        inc rsi
        inc rdi
        dec rcx
        jmp .checkPackMagic
    .packMagicDone:

    mov rax, qword [footerBuf + 8]               ; offset of the embedded binary metadata blob
    mov [packMetaOff], rax
    mov rax, qword [footerBuf + 16]              ; byte size of the embedded metadata blob
    mov [packMetaLen], rax
    mov rax, qword [footerBuf + 24]              ; offset of the embedded stripped payload blob
    mov [packPayloadOff], rax
    mov rax, qword [footerBuf + 32]              ; byte size of the embedded stripped payload blob
    mov [packPayloadLen], rax
    mov rax, qword [footerBuf + 40]              ; footer flags describing optional transforms on the embedded blobs
    mov [packFlags], rax
    ; Reject unknown flag bits early so the stub never tries to best effort
    ; decode a format revision it does not actually understand
    test rax, not (SPACK_FLAG_META_XOR or SPACK_FLAG_PAYLOAD_XOR or SPACK_FLAG_PAYLOAD_RLE)
    jnz invalidPackFlags

    ; Validate the embedded ranges so obviously malformed packs fail early
    mov rax, [packMetaLen]                       ; metadata must fit in the fixed metadata staging buffer
    cmp rax, BUFFER_SIZE
    ja invalidMetaTooLarge
    mov rax, [packPayloadLen]                    ; payload must fit in the fixed payload staging buffer
    cmp rax, BUFFER_SIZE
    ja invalidPayloadTooLarge
    mov r11, [footerOff]                              ; first footer byte, so embedded ranges must end before it
    mov rax, [packMetaOff]
    cmp rax, r11
    jae invalidMetaRange
    add rax, [packMetaLen]                           ; first byte after the metadata blob
    jc invalidMetaRange                              ; unsigned wrap is never a valid in-file range
    cmp rax, r11                                     ; metadata must be fully contained before the footer
    ja invalidMetaRange
    mov rax, [packPayloadOff]
    cmp rax, r11
    jae invalidPayloadRange
    add rax, [packPayloadLen]                    ; first byte after the stripped payload blob
    jc invalidPayloadRange                       ; reject offset + length overflow before comparing bounds
    cmp rax, r11                                 ; payload must also be fully contained before the footer
    ja invalidPayloadRange
    ; metadata and payload need not appear in file order, so this checks
    ; containment from both sides before ruling out an overlap
    mov rax, [packMetaOff]
    add rax, [packMetaLen]                       ;  metadata end
    jc invalidMetaRange                          ; overflow here would only reopen a case already rejected by the containment check above
    cmp rax, [packPayloadOff]                    ; if metadata ends at or before payload starts, they cannot overlap
    jbe .rangesSeparate
    mov rax, [packPayloadOff]
    add rax, [packPayloadLen]                    ; payload end
    jc invalidPayloadRange                       ; overflow guard for the payload end computed just above
    cmp rax, [packMetaOff]                       ; if payload ends at or before metadata starts, they cannot overlap either
    jbe .rangesSeparate
    jmp invalidPackOverlap
    .rangesSeparate:

    ; Load the embedded binary metadata blob.
    ;
    ; The packer uses the compact binary sidecar format unconditionally because
    ; it is smaller and easier to append than the textual flavor
    mov rdi, [targetFd]
    lea rsi, [interpBuffer]                      ; reusing the loader's interp scratch buffer here, no PT_INTERP handling happens this early
    mov rdx, [packMetaLen]
    mov rax, SYS_PREAD64
    mov r10, [packMetaOff]
    syscall
    cmp rax, [packMetaLen]
    jne metaReadFailed
    mov rax, [packMetaLen]
    mov [interpStat.st_size], rax                ; synthesize the size field the binary metadata parser expects
    mov rax, [packFlags]                         ; check whether the metadata blob was XORed by the builder
    test rax, SPACK_FLAG_META_XOR
    jz .metaReady
    lea rsi, [interpBuffer]
    mov rcx, [packMetaLen]
    call xorBufferInPlace
    .metaReady:
    call parseMetaBin

    ; Load the embedded stripped payload blob.
    ;
    ; These are the original single PT_LOAD bytes after mkpack stripped the
    ; ELF header/program header prefix away from the original SHELF image
    mov rdi, [targetFd]
    lea rsi, [buffer]                            ; plain payloads can be staged directly into their final buffer
    mov rax, [packFlags]                         ; transformed payloads may need a temporary decode staging area first
    test rax, SPACK_FLAG_PAYLOAD_RLE
    jz .payloadDstReady
    lea rsi, [interpBuffer]                      ; RLE payloads are staged here first, then expanded into buffer
    .payloadDstReady:
    mov rdx, [packPayloadLen]                    ; encoded payload byte count exactly as stored on disk
    mov rax, SYS_PREAD64
    mov r10, [packPayloadOff]
    syscall
    cmp rax, [packPayloadLen]
    jne fileReadFailed
    mov rax, [packFlags]                            ; the builder may have XORed the payload blob too
    test rax, SPACK_FLAG_PAYLOAD_XOR
    jz .payloadDecoded
    mov rax, [packFlags]                            ; RLE payloads were staged in interpBuffer, plain payloads in buffer
    test rax, SPACK_FLAG_PAYLOAD_RLE
    jz .xorPlainPayload
    lea rsi, [interpBuffer]                      ; de-XOR the encoded payload in place before running the RLE decoder
    mov rcx, [packPayloadLen]
    call xorBufferInPlace
    jmp .payloadDecoded
    .xorPlainPayload:
    lea rsi, [buffer]                              ; plain payloads were staged directly in their final destination buffer
    mov rcx, [packPayloadLen]
    call xorBufferInPlace
    .payloadDecoded:

    ; The embedded stripped payload must match the metadata derived expectation
    mov rax, [loadFilesz]                        ; original PT_LOAD file size
    sub rax, [headerSpan]                        ; stripped payload size = PT_LOAD.filesz - stripped header span
    mov [expectedPayloadSize], rax               ; remember the size the decoded payload must expand to
    mov r11, [packFlags]                         ; flags rechecked here to decide whether the RLE expansion path runs next
    test r11, SPACK_FLAG_PAYLOAD_RLE
    jz .plainPayload
    lea rsi, [interpBuffer]                   ; encoded RLE stream, feeds decodeRlePayload
    mov rdx, [packPayloadLen]
    lea rdi, [buffer]                         ; destination for the fully decoded stripped payload
    mov rcx, [expectedPayloadSize]            ; exact decoded byte count the RLE stream must expand to
    call decodeRlePayload
    mov rax, [expectedPayloadSize]
    mov [fstat.st_size], rax                     ; from here on fstat.st_size tracks the decoded payload length, not the packed file size
    jmp .payloadReady
    .plainPayload:
    mov rax, [packPayloadLen]
    mov [fstat.st_size], rax                    ; the rest of the load path only cares about the stripped payload byte count
    cmp rax, [expectedPayloadSize]
    jne invalidPayloadSize
    .payloadReady:

    ; Reserve, synthesize, populate, and protect the one SHELF PT_LOAD span
    mov rax, [loadMemsz]                         ; memsz, not filesz, since the mapping must cover any bss beyond the file backed bytes
    add rax, PAGE_SIZE - 1                       ; bias upward so we can round to whole pages
    and rax, -PAGE_SIZE                          ; page align the anonymous mapping length
    mov [imageSpanSize], rax

    lea rsi, [dbgReserveDynMsg]
    mov rdx, dbgReserveDynMsgLen
    call debugWrite

    xor rdi, rdi                                 
    mov rsi, [imageSpanSize]
    mov rdx, PROT_READ or PROT_WRITE             ; start writable so we can synthesize headers and copy payload bytes
    mov r10, MAP_PRIVATE or MAP_ANON             ; copy on write and unbacked, matching a scratch mapping we own outright
    mov r8, -1                                   ; MAP_ANON ignores the fd slot
    xor r9, r9                                   ; ditto, anonymous ignores the offset arg
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov [baseAddr], rax

    lea rsi, [dbgLoadBiasMsg]
    mov rdx, dbgLoadBiasMsgLen
    mov rax, [baseAddr]
    call debugPrintHexLine

    lea rsi, [dbgMapMainMsg]
    mov rdx, dbgMapMainMsgLen
    mov rax, [baseAddr]
    call debugPrintHexLine

    mov rdi, [baseAddr]
    call synthesizeHeaders                       ; rebuild EHDR + PHDR bytes that were stripped by the packer
    mov rdi, [baseAddr]
    add rdi, [headerSpan]                         ; copy stripped payload bytes immediately after the synthesized header prefix
    lea rsi, [buffer]
    mov rcx, [fstat.st_size]                      ; still the stripped payload length via the repurposed fstat.st_size
    rep movsb

    mov r8d, dword [loadFlags]                   ; raw PF_* bits parsed from the metadata, translated to PROT_* next
    ELF_FLAGS_TO_PROT r8d, edx                   ; translated Linux PROT_* mask
    mov rdi, [baseAddr]
    mov rsi, [imageSpanSize]
    mov rax, SYS_MPROTECT
    syscall
    test rax, rax
    js mprotectFailed

    mov byte [hasInterp], 0                      ; packed SHELF direct entry images never carry PT_INTERP in this first pass
    lea rax, [phdrBlob]
    mov [phdrBlobAddr], rax                      ; the local scratch copy's address, distinct from where the PHDRs end up at phdrRuntime
    mov rax, [baseAddr]
    add rax, [phoffValue]                         ; AT_PHDR should point into the synthetic in-memory PHDR table we rebuilt
    mov [phdrRuntime], rax
    ; hasDynamic/hasTls mirror whether the parsed sizes above actually carry a dynamic segment or TLS
    mov byte [hasDynamic], 0
    cmp qword [dynamicSize], 0
    je .noDynamic
    mov byte [hasDynamic], 1
    .noDynamic:
    mov byte [hasTls], 0
    cmp qword [tlsMemsz], 0
    je .noTls
    mov byte [hasTls], 1
    .noTls:
    mov byte [stackProt], PROT_READ or PROT_WRITE ; initial protection for the synthetic stack mapped just below

allocateStack:
    ; Build a fresh synthetic initial stack for the embedded program. This
    ; keeps the packed stub's own argv/envp/auxv manipulation separate from the
    ; target's eventual view of process startup state
    xor rdi, rdi
    mov rsi, STACK_SIZE
    mov rdx, PROT_READ or PROT_WRITE
    mov r10, MAP_PRIVATE or MAP_ANON
    mov r8, -1                                   ; MAP_ANON ignores the fd slot
    xor r9, r9                                   ; ditto, anonymous ignores the offset arg
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov [stackAddr], rax
    lea rsi, [dbgStackMsg]
    mov rdx, dbgStackMsgLen
    mov rax, [stackAddr]
    call debugPrintHexLine
    jmp interp

include "loader/reloc.inc"
loadInterp:
    ; packed images are always direct entry with no PT_INTERP, so this path is unreachable in practice
    jmp unsupportedInterp

include "loader/stack.inc"
forkTransformExec:
    ; packing built around a fork plus exec transform is not supported by this stub yet
    jmp unsupportedType

parseMetaBin:
    ; Parse the compact SHELFBN1 metadata record that mkpack embeds
    ;
    ; Format:
    ;   "SHELFBN1"
    ;   17 x u64 fields
    ;   raw phdr bytes
    mov rax, [interpStat.st_size]
    cmp rax, metaBinFixedSize                    ; the fixed binary header must be present before any raw phdr bytes follow
    jb invalidMetaFormat
    lea rsi, [interpBuffer]
    lea rdi, [metaBinMagic]
    mov rcx, metaBinMagicLen
    .checkMetaMagic:
        test rcx, rcx                            ; finishing the loop means the SHELFBN1 magic matched
        jz .metaMagicDone
        mov al, [rsi]
        mov dl, [rdi]
        cmp al, dl
        jne invalidMetaFormat
        inc rsi
        inc rdi
        dec rcx
        jmp .checkMetaMagic
    .metaMagicDone:

    mov rax, [rsi]                               ; entry = original ET_DYN entry point
    mov [ehdr.entry], rax
    add rsi, 8
    mov rax, [rsi]                               ; phoff
    mov [phoffValue], rax
    mov [ehdr.phoff], rax
    add rsi, 8
    mov rax, [rsi]                               ; phnum
    cmp rax, 0xffff                              ; EHDR stores this value in a 16 bit field
    ja invalidMetaFormat
    mov word [ehdr.phnum], ax
    add rsi, 8
    mov rax, [rsi]                               ; phentsize
    cmp rax, sizeof.PHDR                         ; always embeds native ELF64 program headers
    jne invalidMetaFormat
    mov word [ehdr.phentsize], ax
    add rsi, 8
    mov rax, [rsi]                               ; header span stripped by the packer
    mov [headerSpan], rax
    add rsi, 8
    mov rax, [rsi]                               ; one PT_LOAD SHELF pack format requires load_offset == 0
    test rax, rax
    jne invalidMetaFormat
    add rsi, 8
    mov rax, [rsi]                               ; one PT_LOAD SHELF pack format requires load_vaddr == 0
    test rax, rax
    jne invalidMetaFormat
    add rsi, 8
    mov rax, [rsi]                               ; load_filesz = original PT_LOAD.p_filesz
    mov [loadFilesz], rax
    cmp rax, [headerSpan]                        ; header_span bytes are sliced out of this same PT_LOAD, so
    jb invalidMetaFormat                          ; load_filesz - header_span must never be allowed to underflow
    add rsi, 8
    mov rax, [rsi]                               ; load_memsz = original PT_LOAD.p_memsz
    mov [loadMemsz], rax
    cmp rax, [loadFilesz]                        ; memsz must never be smaller than filesz for a sane PT_LOAD
    jb invalidMetaFormat
    add rsi, 8
    mov eax, [rsi]                               ; load_flags = compact PROT_* bits stored by the packer
    mov dword [loadFlags], eax
    add rsi, 8
    ; remaining fields (dynamic segment and TLS descriptors) land in destinations
    ; already named for what they hold, so no per field comment follows
    mov rax, [rsi]
    mov [dynamicVaddr], rax
    add rsi, 8
    mov rax, [rsi]
    mov [dynamicSize], rax
    add rsi, 8
    mov rax, [rsi]
    mov [tlsVaddr], rax
    add rsi, 8
    mov rax, [rsi]
    mov [tlsFilesz], rax
    add rsi, 8
    mov rax, [rsi]
    mov [tlsMemsz], rax
    add rsi, 8
    mov rax, [rsi]
    mov [tlsAlign], rax
    add rsi, 8
    mov r8, [rsi]                                 ; declared raw PHDR byte count stored after the fixed metadata fields
    cmp r8, 4096                                 ; the shared phdr scratch buffer is 4096 bytes large
    ja invalidMetaFormat
    movzx rax, word [ehdr.phnum]                 ; recompute phnum * phentsize and require an exact match
    movzx rcx, word [ehdr.phentsize]
    imul rax, rcx
    cmp r8, rax
    jne invalidMetaFormat
    mov rax, [interpStat.st_size]                ; metadata file size must cover the fixed header plus the raw phdr bytes
    sub rax, metaBinFixedSize
    cmp rax, r8                                  ; permits no trailing metadata extensions
    jne invalidMetaFormat
    lea rsi, [interpBuffer + metaBinFixedSize]
    lea rdi, [phdrBlob]
    mov rcx, r8
    rep movsb

    ; Rebuild the minimal synthetic EHDR image the runtime and auxv logic want
    ; to observe once the payload is mapped
    mov word [ehdr.type], ET_DYN                 ; packed SHELF payloads are direct entry ET_DYN images
    ; fixed values for a normal little endian x64 ELF64 image, only entry/phoff/phnum/phentsize actually come from the metadata
    mov dword [ehdr.magic], 0x464c457f
    mov byte [ehdr.class], ELFCLASS64
    mov byte [ehdr.data], ELFDATA2LSB
    mov byte [ehdr.elfversion], 1
    mov byte [ehdr.os], 3
    mov byte [ehdr.abiversion], 0
    mov word [ehdr.machine], EM_X86_64
    mov dword [ehdr.version], EV_CURRENT
    mov word [ehdr.ehsize], sizeof.EHDR
    mov qword [baseAddr], 0                      ;  placeholder until the real mapping sets this further below
    ret

synthesizeHeaders:
    ; Recreate the stripped ELF header and PHDR table at the front of the
    ; mapped image so the loaded program still has a believable in-memory ELF
    ; view and a sane AT_PHDR target
    ; preserves rdi/rsi/rcx since this is invoked with a plain call, not a fixed calling convention, and the caller still needs them
    push rdi
    push rsi
    push rcx
    lea rsi, [ehdr]                              ; src = synthetic EHDR bytes we just rebuilt from metadata
    mov rcx, sizeof.EHDR
    rep movsb
    mov rdi, [baseAddr]                          ; restart at the mapped image base
    add rdi, [phoffValue]                        ; dst = where the PHDR table should live in memory
    lea rsi, [phdrBlob]                          ; src = decoded raw PHDR bytes from the metadata sidecar
    movzx rcx, word [ehdr.phnum]
    ; total PHDR table bytes = phnum * phentsize
    movzx rax, word [ehdr.phentsize]
    imul rcx, rax
    rep movsb
    pop rcx
    pop rsi
    pop rdi
    ret

xorBufferInPlace:
    ; rsi = buffer start, rcx = byte count to XOR with the fixed SPACK key
    ;
    ; Both metadata and payload use the same rule:
    ;   byte ^= key
    ;
    ; Keeping the transform tiny means the runtime decoder can stay equally
    ; tiny and obvious
    push rax
    .loop:
        test rcx, rcx
        jz .done
        xor byte [rsi], SPACK_XOR_KEY ; this is the key right here yall
        inc rsi
        dec rcx
        jmp .loop
    .done:
    pop rax
    ret

decodeRlePayload:
    ; rsi = encoded source, rdx = encoded byte count
    ; rdi = decoded destination, rcx = expected decoded byte count
    ;
    ; Token format:
    ;   high bit clear -> literal block, count = low7 + 1, next <count> bytes copied as is
    ;   high bit set   -> run block,     count = low7 + 1, next 1 byte repeated <count> times
    ;
    ; Any malformed token stream or size mismatch is treated as a hard format 
    ; error rather than a best effort decode
    ; preserves every register this function touches since it is called from more than one site
    push rax
    push rbx
    push r8
    push r9
    push r10
    push r11
    xor r8, r8                                   ; encoded input offset
    xor r9, r9                                   ; decoded output offset
    .nextToken:
        cmp r8, rdx
        je .done
        mov al, [rsi + r8]                       ; current RLE control byte
        inc r8                                   ; consume the control byte
        movzx r10, al
        and r10, 0x7f                            ; lower 7 bits encode (count - 1)
        inc r10                                  ; number of output bytes for this token
        mov r11, r9
        add r11, r10                             ; decoded offset after this token
        cmp r11, rcx
        ja invalidPayloadEncoding
        test al, 0x80                            ; high bit distinguishes run tokens from literal tokens
        jz .literal
        cmp r8, rdx                              ; run tokens need one more source byte for the repeated value
        jae invalidPayloadEncoding
        mov bl, [rsi + r8]                       ; repeated byte value
        inc r8
        .runLoop:
            mov [rdi + r9], bl
            inc r9
            dec r10
            jnz .runLoop
        jmp .nextToken
        .literal:
        mov r11, r8
        add r11, r10                             ; literal token consumes count literal bytes from the encoded stream
        cmp r11, rdx
        ja invalidPayloadEncoding
        .litLoop:
            mov bl, [rsi + r8]
            mov [rdi + r9], bl
            inc r8
            inc r9
            dec r10
            jnz .litLoop
        jmp .nextToken
    .done:
    cmp r9, rcx                                  ; the decoded payload must expand to exactly the metadata described size
    jne invalidPayloadEncoding
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbx
    pop rax
    ret

invalidFooterTooSmall:
    lea rsi, [invalidFooterTooSmallMsg]
    mov rdx, invalidFooterTooSmallMsgLen
    jmp writeError

invalidFooterRead:
    lea rsi, [invalidFooterReadMsg]
    mov rdx, invalidFooterReadMsgLen
    jmp writeError

invalidFooterMagic:
    lea rsi, [invalidFooterMagicMsg]
    mov rdx, invalidFooterMagicMsgLen
    jmp writeError

invalidMetaTooLarge:
    lea rsi, [invalidMetaTooLargeMsg]
    mov rdx, invalidMetaTooLargeMsgLen
    jmp writeError

invalidPayloadTooLarge:
    lea rsi, [invalidPayloadTooLargeMsg]
    mov rdx, invalidPayloadTooLargeMsgLen
    jmp writeError

invalidMetaRange:
    lea rsi, [invalidMetaRangeMsg]
    mov rdx, invalidMetaRangeMsgLen
    jmp writeError

invalidPayloadRange:
    lea rsi, [invalidPayloadRangeMsg]
    mov rdx, invalidPayloadRangeMsgLen
    jmp writeError

invalidPackOverlap:
    lea rsi, [invalidPackOverlapMsg]
    mov rdx, invalidPackOverlapMsgLen
    jmp writeError

invalidMetaFormat:
    lea rsi, [invalidMetaFormatMsg]
    mov rdx, invalidMetaFormatMsgLen
    jmp writeError

invalidPayloadSize:
    lea rsi, [invalidPayloadSizeMsg]
    mov rdx, invalidPayloadSizeMsgLen
    jmp writeError

invalidPayloadEncoding:
    lea rsi, [invalidPayloadEncodingMsg]
    mov rdx, invalidPayloadEncodingMsgLen
    jmp writeError

invalidPackFlags:
    lea rsi, [invalidPackFlagsMsg]
    mov rdx, invalidPackFlagsMsgLen
    jmp writeError

unsupportedType:
    lea rsi, [unsupportedTypeMsg]
    mov rdx, unsupportedTypeMsgLen
    jmp writeError

unsupportedInterp:
    lea rsi, [unsupportedInterpMsg]
    mov rdx, unsupportedInterpMsgLen
    jmp writeError

unsupportedReloc:                                
    lea rsi, [unsupportedRelocMsg]
    mov rdx, unsupportedRelocMsgLen
    jmp writeError

stackStorageTooSmall:                            
    lea rsi, [stackStorageTooSmallMsg]
    mov rdx, stackStorageTooSmallMsgLen
    jmp writeError

openFailed:
    lea rsi, [openFailedMsg]
    mov rdx, openFailedMsgLen
    jmp writeError

fstatFailed:
    lea rsi, [fstatFailedMsg]
    mov rdx, fstatFailedMsgLen
    jmp writeError

fileReadFailed:
    lea rsi, [fileReadFailedMsg]
    mov rdx, fileReadFailedMsgLen
    jmp writeError

metaReadFailed:
    lea rsi, [metaReadFailedMsg]
    mov rdx, metaReadFailedMsgLen
    jmp writeError

closeFailed:                                     
    lea rsi, [closeFailedMsg]
    mov rdx, closeFailedMsgLen
    jmp writeError

mmapFailed:
    lea rsi, [mmapFailedMsg]
    mov rdx, mmapFailedMsgLen
    jmp writeError

mprotectFailed:
    lea rsi, [mprotectFailedMsg]
    mov rdx, mprotectFailedMsgLen
    jmp writeError

archPrctlFailed:                                 
    lea rsi, [archPrctlFailedMsg]
    mov rdx, archPrctlFailedMsgLen
    jmp writeError

writeError:
    mov rdi, STDERR                              
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1
    jmp exit

debugWrite:
    cmp byte [debugEnabled], 0
    je .done
    push rax
    push rdi
    push rcx
    push r11
    mov rdi, STDERR
    mov rax, SYS_WRITE
    syscall
    pop r11
    pop rcx
    pop rdi
    pop rax
    .done:
    ret

debugPrintHexLine:
    cmp byte [debugEnabled], 0
    je .done
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r11
    ; writes the label text directly rather than calling debugWrite, since the enabled check already happened above
    mov rdi, STDERR
    mov rax, SYS_WRITE
    syscall
    pop r11
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r11
    lea rdi, [debugHexBuf]
    ; builds "0xXXXXXXXXXXXXXXXX\n" into a scratch buffer before the single write below
    mov byte [rdi], '0'
    mov byte [rdi + 1], 'x'
    lea rsi, [hexDigits]
    mov rbx, rax
    lea rdi, [debugHexBuf + 2]
    mov rcx, 16
    .hexLoop:
        ; walk the value one nibble at a time from the top, shifting the next nibble into the high bits each round
        mov r8, rbx
        shr r8, 60
        mov dl, [rsi + r8]
        mov [rdi], dl
        inc rdi
        shl rbx, 4
        dec rcx
        jnz .hexLoop
    mov byte [rdi], 0xa
    mov rdi, STDERR
    lea rsi, [debugHexBuf]
    mov rdx, 19                                  ; 2 ("0x") + 16 hex digits + 1 newline
    mov rax, SYS_WRITE
    syscall
    pop r11
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    .done:
    ret

exit:
    mov dil, byte [exitStatus]                   
    mov rax, SYS_EXIT
    syscall

segment readable                             
include "loader/rodata.inc"                  

packVersionMsg          db "spack: self loading SHELF packer stub", 0xa
packVersionMsgLen       = $ - packVersionMsg
packDebugEnvPrefix      db "PHORK_DEBUG="
packDebugEnvPrefixLen   = $ - packDebugEnvPrefix 
packMagic               db "SPACK01!"            
metaBinMagic            db "SHELFBN1"            
metaBinMagicLen         = $ - metaBinMagic
metaBinFixedSize        = metaBinMagicLen + (17 * 8) ; matches the 17 u64 fields walked through in parseMetaBin above
selfExePath             db "/proc/self/exe", 0

invalidFooterTooSmallMsg db "Packed file is smaller than a SPACK footer", 0xa
invalidFooterTooSmallMsgLen = $ - invalidFooterTooSmallMsg
invalidFooterReadMsg    db "Failed to read full SPACK footer from packed file", 0xa
invalidFooterReadMsgLen = $ - invalidFooterReadMsg
invalidFooterMagicMsg   db "Packed file does not end with a valid SPACK footer", 0xa
invalidFooterMagicMsgLen = $ - invalidFooterMagicMsg

invalidMetaTooLargeMsg  db "Embedded SHELF metadata is larger than the stub buffer", 0xa
invalidMetaTooLargeMsgLen = $ - invalidMetaTooLargeMsg
invalidPayloadTooLargeMsg db "Embedded payload is larger than the stub buffer", 0xa
invalidPayloadTooLargeMsgLen = $ - invalidPayloadTooLargeMsg
invalidMetaRangeMsg     db "Embedded metadata range overlaps or extends into the SPACK footer", 0xa
invalidMetaRangeMsgLen  = $ - invalidMetaRangeMsg
invalidPayloadRangeMsg  db "Embedded payload range overlaps or extends into the SPACK footer", 0xa
invalidPayloadRangeMsgLen = $ - invalidPayloadRangeMsg
invalidPackOverlapMsg   db "Embedded metadata and payload ranges overlap", 0xa
invalidPackOverlapMsgLen = $ - invalidPackOverlapMsg

invalidMetaFormatMsg    db "Embedded SHELFBN1 metadata is malformed or unsupported", 0xa
invalidMetaFormatMsgLen = $ - invalidMetaFormatMsg
invalidPayloadSizeMsg   db "Embedded payload size does not match the size described by SHELFBN1", 0xa
invalidPayloadSizeMsgLen = $ - invalidPayloadSizeMsg
invalidPayloadEncodingMsg db "Embedded payload RLE stream is malformed or expands to the wrong size", 0xa
invalidPayloadEncodingMsgLen = $ - invalidPayloadEncodingMsg
invalidPackFlagsMsg     db "Packed file uses unknown SPACK footer flags", 0xa
invalidPackFlagsMsgLen  = $ - invalidPackFlagsMsg

segment readable writeable                    
include "loader/rwdata.inc"                   

footerBuf       rb PACK_FOOTER_SIZE
footerOff       rq 1
packMetaOff     rq 1
packMetaLen     rq 1
packPayloadOff  rq 1
packPayloadLen  rq 1
packFlags       rq 1
expectedPayloadSize rq 1
