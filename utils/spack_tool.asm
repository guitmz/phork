format ELF64 executable 3

include "../utils.inc"                       
include "tools.inc"                          

segment readable executable
entry $ 

    mov rcx, [rsp]                               ; rcx = argc
    cmp rcx, 3                                   ; all modes need at least argv[0], mode, and packed file path
    jb usage

    mov rax, [rsp + 16]                          ; argv[1] = mode string
    mov [modeArg], rax                           ; stashed for the dispatch comparisons below
    mov rax, [rsp + 24]                          ; argv[2] = packed file path
    mov [inputPath], rax                         ; stashed for every open() call further down

    ; Manual mode dispatch.
    mov rsi, [modeArg]                           ; rsi = user supplied mode string
    lea rdi, [inspectCmd]                        ; rdi/rcx = literal + length pair, cmpStringExact's convention
    mov rcx, inspectCmdLen
    call cmpStringExact
    cmp rax, 1                                   ; cmpStringExact only returns 1 on an exact, null terminated match
    je .inspectMode

    mov rsi, [modeArg]
    lea rdi, [extractCmd]
    mov rcx, extractCmdLen
    call cmpStringExact
    cmp rax, 1
    je .extractMode

    mov rsi, [modeArg]                           ; last remaining possibility, must be "validate" or it's an error
    lea rdi, [validateCmd]
    mov rcx, validateCmdLen
    call cmpStringExact
    cmp rax, 1
    jne usage                                    ; none of the three literals matched, argv[1] is garbage
    mov byte [modeValidate], 1                   ; reached only once "validate" matched exactly
    mov byte [modeExtract], 0
    jmp .modeReady

    .extractMode:
    cmp qword [rsp], 5                           ; extract needs argv0, mode, packed path, meta out, payload out
    jne usage                                     ; wrong argc: missing or extra output paths
    mov rax, [rsp + 32]                           ; argv[3] = extracted metadata output path
    mov [metaOutPath], rax
    mov rax, [rsp + 40]                           ; argv[4] = extracted payload output path
    mov [payloadOutPath], rax
    mov byte [modeExtract], 1
    jmp .modeReady

    .inspectMode:
    mov byte [modeExtract], 0                    ; inspect just prints a report, no output files to open
    mov byte [modeValidate], 0

    .modeReady:
    mov rdi, [inputPath]                         
    mov rsi, O_RDONLY                            
    xor rdx, rdx                                 
    mov rax, SYS_OPEN
    syscall                                      
    test rax, rax
    js openFailed
    mov [inputFd], rax

    mov rdi, [inputFd]                           ; packed file fd
    xor rsi, rsi                                 ; offset 0
    mov rdx, SEEK_END
    mov rax, SYS_LSEEK
    syscall
    test rax, rax
    js readFailed
    mov [fileSize], rax                          ; seeking to offset 0 from SEEK_END lands exactly at EOF, giving the file size

    cmp qword [fileSize], SPACK_FOOTER_SIZE      ; a file smaller than the footer can't be a valid pack at all
    jb invalidFooterTooSmall

    mov r10, [fileSize]                           ; total packed file byte count
    sub r10, SPACK_FOOTER_SIZE
    mov [footerOff], r10                            ; remember where the last 48 byte SPACK footer begins
    mov rdi, [inputFd]                              ; seek to the footer before reading it
    mov rsi, r10
    xor rdx, rdx                                  ; whence = SEEK_SET
    mov rax, SYS_LSEEK
    syscall
    test rax, rax
    js readFailed
    mov rdi, [inputFd]
    lea rsi, [footerBuf]                         ; destination for the raw footer bytes
    mov rdx, SPACK_FOOTER_SIZE
    mov rax, SYS_READ
    syscall
    cmp rax, SPACK_FOOTER_SIZE                   ; a short read here means a truncated or corrupt file
    jne readFailed

    lea rsi, [footerBuf]
    lea rdi, [packMagic]                         ; compare the footer's first 8 bytes against the expected magic
    mov rcx, packMagicLen
    call cmpMemExact
    cmp rax, 1
    jne invalidFooterMagic

    mov rax, qword [footerBuf + 8]               ; footer.meta_off
    mov [metaOff], rax
    mov rax, qword [footerBuf + 16]              ; footer.meta_len
    mov [metaLen], rax
    mov rax, qword [footerBuf + 24]              ; footer.payload_off
    mov [payloadOff], rax
    mov rax, qword [footerBuf + 32]              ; footer.payload_len
    mov [payloadLen], rax
    mov rax, qword [footerBuf + 40]              ; footer.flags
    mov [flagsValue], rax

    ; Range validation.
    ;
    ; Both embedded blobs must live entirely before the footer and must not
    ; overlap each other
    mov rax, [metaOff]
    cmp rax, [footerOff]                         ; meta_off itself must sit before the footer
    jae invalidMetaRange
    add rax, [metaLen]
    cmp rax, [footerOff]                         ; meta_off + meta_len must not run into the footer either
    ja invalidMetaRange

    mov rax, [payloadOff]
    cmp rax, [footerOff]                         ; same two sided check for the payload range
    jae invalidPayloadRange
    add rax, [payloadLen]
    cmp rax, [footerOff]                         ; payload_off + payload_len must not run into the footer either
    ja invalidPayloadRange

    ; meta and payload don't overlap as long as one of them fully precedes
    ; the other, in either order
    mov rax, [metaOff]
    add rax, [metaLen]
    cmp rax, [payloadOff]                        ; does metadata fully precede the payload?
    jbe .rangesOk
    mov rax, [payloadOff]
    add rax, [payloadLen]
    cmp rax, [metaOff]                           ; or does the payload fully precede the metadata instead?
    jbe .rangesOk
    jmp invalidOverlap
    .rangesOk:      ; both ranges are sane, safe to proceed to whichever mode was requested

    cmp byte [modeValidate], 0
    jne .validate
    cmp byte [modeExtract], 0
    jne .extract

    ; Every field below reuses printKeyU64: rsi/rdx point at the label string
    ; that names it, rax holds the decimal value to print
    lea rsi, [inspectMagicMsg]
    mov rdx, inspectMagicMsgLen
    call writeStdout
    lea rsi, [fileSizeMsg]
    mov rdx, fileSizeMsgLen
    mov rax, [fileSize]
    call printKeyU64
    lea rsi, [footerOffMsg]
    mov rdx, footerOffMsgLen
    mov rax, [footerOff]
    call printKeyU64
    lea rsi, [metaOffMsg]
    mov rdx, metaOffMsgLen
    mov rax, [metaOff]
    call printKeyU64
    lea rsi, [metaLenMsg]
    mov rdx, metaLenMsgLen
    mov rax, [metaLen]
    call printKeyU64
    lea rsi, [payloadOffMsg]
    mov rdx, payloadOffMsgLen
    mov rax, [payloadOff]
    call printKeyU64
    lea rsi, [payloadLenMsg]
    mov rdx, payloadLenMsgLen
    mov rax, [payloadLen]
    call printKeyU64
    lea rsi, [flagsMsg]
    mov rdx, flagsMsgLen
    mov rax, [flagsValue]                    ; raw flag bits, not decoded into names here
    call printKeyU64
    jmp .success

    .validate:
    mov rax, [flagsValue]                       ; reject future/unknown flags this validator does not understand
    test rax, not (SPACK_FLAG_META_XOR or SPACK_FLAG_PAYLOAD_XOR or SPACK_FLAG_PAYLOAD_RLE) ; any bit outside the three known flags is unknown/future
    jnz invalidFlags
    ; Bound against this tool's own copyBuf scratch size, which is sized to
    ; match the runtime's real ceiling: a fixed 144 byte header plus up to a
    ; 4096 byte raw PHDR blob (SHELF_META_MAX_SIZE = 4240). A pack near that
    ; ceiling is unusual but legal, and the runtime would happily load it, so
    ; this must not reject anything the runtime accepts
    cmp qword [metaLen], SHELF_META_MAX_SIZE
    ja invalidMetaRange
    cmp qword [metaLen], SHELF_META_FIXED_SIZE   ; must be at least the fixed 144 byte header
    jb invalidMetaFormat

    mov rdi, [inputFd]                           ; seek to the metadata blob so validation can inspect its fields
    mov rsi, [metaOff]
    xor rdx, rdx                                  ; whence = SEEK_SET
    mov rax, SYS_LSEEK
    syscall
    test rax, rax
    js readFailed
    mov rdi, [inputFd]
    lea rsi, [copyBuf]                           ; copyBuf will hold the raw (possibly XOR'd) metadata bytes
    mov rdx, [metaLen]
    mov rax, SYS_READ
    syscall
    cmp rax, [metaLen]
    jne readFailed

    mov rax, [flagsValue]                        ; metadata may be XOR obfuscated
    test rax, SPACK_FLAG_META_XOR
    jz .metaReady
    lea rsi, [copyBuf]                           ; XOR every byte of the freshly read metadata in place
    mov rcx, [metaLen]
    .xorMetaLoop:                                ; one byte per iteration until rcx counts down to zero
        test rcx, rcx
        jz .metaReady
        xor byte [rsi], SPACK_XOR_KEY
        inc rsi
        dec rcx
        jmp .xorMetaLoop
    .metaReady:         ; reached directly with no XOR flag, or after the loop above finishes
    lea rsi, [copyBuf]
    lea rdi, [metaMagic]                         ; confirm the blob starts with SHELFBN1 before trusting its fields
    mov rcx, metaMagicLen
    call cmpMemExact
    cmp rax, 1
    jne invalidMetaFormat
    mov rax, qword [copyBuf + 40]                ; header_span
    mov [expectedPayloadLen], rax
    mov rax, qword [copyBuf + 64]                ; load_filesz
    cmp rax, [expectedPayloadLen]
    jb invalidMetaFormat                         ; load_filesz can't be smaller than the header span it's meant to include
    sub rax, [expectedPayloadLen]
    mov [expectedPayloadLen], rax                ; expected decoded payload bytes = load_filesz - header_span
    mov rax, qword [copyBuf + 136]               ; declared PHDR blob byte count
    mov [phdrBlobSize], rax
    mov rax, qword [copyBuf + 24]                ; phnum
    mov rcx, qword [copyBuf + 32]                ; phentsize
    imul rax, rcx                                ;  phnum * phentsize, the expected trailing PHDR blob size
    cmp rax, [phdrBlobSize]                      ; must match the declared blob size exactly
    jne invalidMetaFormat
    mov rax, SHELF_META_FIXED_SIZE
    add rax, [phdrBlobSize]                      ; total meta_len must equal the fixed header plus that blob
    cmp rax, [metaLen]
    jne invalidMetaFormat
    mov rax, [flagsValue]                        ; if the payload is RLE compressed, length equality alone is not meaningful
    test rax, SPACK_FLAG_PAYLOAD_RLE
    jnz .validateOk
    mov rax, [payloadLen]
    cmp rax, [expectedPayloadLen]
    jne invalidPayloadSize
    .validateOk:        ; reached either because RLE makes length equality meaningless, or because the check above already passed
    lea rsi, [validateOkMsg]
    mov rdx, validateOkMsgLen
    call writeStdout
    jmp .success

    .extract:
    mov rdi, [metaOutPath]                       
    mov rsi, O_WRONLY or O_CREAT or O_TRUNC
    mov rdx, MODE_0644                           ; -rw-r--r--
    mov rax, SYS_OPEN
    syscall                                      
    test rax, rax
    js openFailed
    mov [metaFd], rax
    mov rdi, [metaFd]
    mov r8, [metaOff]
    mov r9, [metaLen]
    call copyRange                               ; streams metaLen bytes from the packed input starting at metaOff
    mov rdi, [metaFd]
    mov rax, SYS_CLOSE
    syscall
    test rax, rax
    js closeFailed

    mov rdi, [payloadOutPath]                    
    mov rsi, O_WRONLY or O_CREAT or O_TRUNC
    mov rdx, MODE_0644                           
    mov rax, SYS_OPEN
    syscall                                      
    test rax, rax
    js openFailed
    mov [payloadFd], rax
    mov rdi, [payloadFd]
    mov r8, [payloadOff]
    mov r9, [payloadLen]
    call copyRange                               ; same streaming copy, this time for the payload range
    mov rdi, [payloadFd]
    mov rax, SYS_CLOSE
    syscall
    test rax, rax
    js closeFailed

    .success:
    mov rdi, [inputFd]                           ; close the packed input now that every mode is done reading it
    mov rax, SYS_CLOSE
    syscall                                      ; unlike the extraction closes above, this result is never checked
    mov edi, 0                                   ; exit code 0, beautiful!
    mov eax, SYS_EXIT
    syscall

copyRange:
    ; rdi = output fd, r8 = input offset, r9 = remaining bytes
    ;
    ; The function keeps the output fd parked in rbx while rdi is reused for
    ; lseek/read on the packed input fd during each chunk copy
    push rbx
    push rdi
    push r8
    push r9
    mov rbx, rdi
    .loop:
        cmp r9, 0
        je .done
        mov r10, 4096                            ; default chunk size = size of the copy scratch buffer
        cmp r9, r10                              ; does the remaining count still fill a whole chunk?
        jae .sizeReady
        mov r10, r9                              ; last chunk may be smaller than the scratch buffer
        .sizeReady:
        mov rdi, [inputFd]                        ; seek to this chunk's offset in the packed input
        mov rsi, r8                               ; r8 tracks how far into the range we've copied so far
        xor rdx, rdx                              ; whence = SEEK_SET
        mov rax, SYS_LSEEK
        syscall
        test rax, rax
        js readFailed
        mov rdi, [inputFd]
        lea rsi, [copyBuf]
        mov rdx, r10
        mov rax, SYS_READ
        syscall
        cmp rax, r10                              ; a short read mid copy counts as failure too
        jne readFailed
        mov rdi, rbx                              ; the real output fd, restored after rdi was reused above
        lea rsi, [copyBuf]
        mov rdx, r10
        call writeBuf
        add r8, r10
        sub r9, r10
        jmp .loop
    .done:          ; reached once r9 counts all the way down to zero
    pop r9
    pop r8
    pop rdi
    pop rbx
    ret

printKeyU64:
    ; rsi = key string, rdx = key len, rax = value
    push rax
    call writeStdout
    pop rax
    call printU64Line
    ret

printU64Line:
    ; Convert the unsigned value in rax into decimal ASCII followed by '\n'.
    ; The digits are produced backwards into the tail of u64Buf, then emitted
    ; as one contiguous line
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    lea rdi, [u64Buf + 31]
    mov byte [rdi], 0xa
    dec rdi
    mov rcx, 1                                   ; tracks emitted length, starting at 1 for the trailing newline
    mov rbx, 0xa                                  ; decimal divisor for each digit
    cmp rax, 0
    jne .loop
    mov byte [rdi], '0'                          ; special case zero: the division loop below would never run
    dec rdi
    inc rcx
    jmp .emit
    .loop:
        xor rdx, rdx
        div rbx                                  ; rax = quotient, rdx = next decimal digit (0-9)
        add dl, '0'
        mov [rdi], dl
        dec rdi
        inc rcx
        test rax, rax
        jnz .loop
    .emit:
    inc rdi                                      ; back up onto the first digit actually written
    mov rsi, rdi                                 ; rsi/rdx now point at the finished digit string plus newline
    mov rdx, rcx
    call writeStdout
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

writeStdout:
    mov rdi, STDOUT                              ; falls through into writeBuf with the fd already set
writeBuf:
    ; Shared write helper used by both stdout printing and extraction writes
    mov rax, SYS_WRITE
    syscall
    cmp rax, rdx                                 ; treat short writes as fatal, same rule mkpack's writeBuf uses
    jne writeFailed
    ret

cmpMemExact:
    ; Compare rcx bytes from [rsi] and [rdi]. Return rax = 1 on exact match
    xor rax, rax
    .loop:
        test rcx, rcx
        jz .match
        mov dl, [rsi]
        mov bl, [rdi]
        cmp dl, bl
        jne .done
        inc rsi
        inc rdi
        dec rcx
        jmp .loop
    .match:
    mov rax, 1
    .done:
    ret

cmpStringExact:
    ; Compare an argument string against a literal of known length and also
    ; require the input to terminate exactly at that length
    xor rax, rax
    .loop:
        test rcx, rcx
        jz .checkTerm
        mov dl, [rsi]
        mov bl, [rdi]
        cmp dl, bl
        jne .done
        inc rsi
        inc rdi
        dec rcx
        jmp .loop
    .checkTerm:
    cmp byte [rsi], 0
    jne .done
    mov rax, 1
    .done:
    ret


usage:
    WRITE_AND_EXIT usageMsg, usageMsgLen
openFailed:
    WRITE_AND_EXIT openFailedMsg, openFailedMsgLen
readFailed:
    WRITE_AND_EXIT readFailedMsg, readFailedMsgLen
writeFailed:
    WRITE_AND_EXIT writeFailedMsg, writeFailedMsgLen
closeFailed:
    WRITE_AND_EXIT closeFailedMsg, closeFailedMsgLen
invalidFooterTooSmall:
    WRITE_AND_EXIT invalidFooterTooSmallMsg, invalidFooterTooSmallMsgLen
invalidFooterMagic:
    WRITE_AND_EXIT invalidFooterMagicMsg, invalidFooterMagicMsgLen
invalidMetaRange:
    WRITE_AND_EXIT invalidMetaRangeMsg, invalidMetaRangeMsgLen
invalidPayloadRange:
    WRITE_AND_EXIT invalidPayloadRangeMsg, invalidPayloadRangeMsgLen
invalidOverlap:
    WRITE_AND_EXIT invalidOverlapMsg, invalidOverlapMsgLen
invalidFlags:
    WRITE_AND_EXIT invalidFlagsMsg, invalidFlagsMsgLen
invalidMetaFormat:
    WRITE_AND_EXIT invalidMetaFormatMsg, invalidMetaFormatMsgLen
invalidPayloadSize:
    WRITE_AND_EXIT invalidPayloadSizeMsg, invalidPayloadSizeMsgLen

segment readable
usageMsg db "Usage: spack_tool inspect <packed-file>",0xa,\
            "   or: spack_tool extract <packed-file> <out-meta> <out-payload>",0xa,\
            "   or: spack_tool validate <packed-file>",0xa
usageMsgLen = $ - usageMsg
inspectCmd db "inspect",0
inspectCmdLen = 7                                 ; excludes the null terminator, matches cmpStringExact's rcx convention
extractCmd db "extract",0
extractCmdLen = 7
validateCmd db "validate",0
validateCmdLen = 8
packMagic db "SPACK01!"                            
packMagicLen = $ - packMagic
metaMagic db "SHELFBN1"                            
metaMagicLen = $ - metaMagic
inspectMagicMsg db "spack magic: SPACK01!",0xa
inspectMagicMsgLen = $ - inspectMagicMsg
fileSizeMsg db "file_size: "
fileSizeMsgLen = $ - fileSizeMsg
footerOffMsg db "footer_off: "
footerOffMsgLen = $ - footerOffMsg
metaOffMsg db "meta_off: "
metaOffMsgLen = $ - metaOffMsg
metaLenMsg db "meta_len: "
metaLenMsgLen = $ - metaLenMsg
payloadOffMsg db "payload_off: "
payloadOffMsgLen = $ - payloadOffMsg
payloadLenMsg db "payload_len: "
payloadLenMsgLen = $ - payloadLenMsg
flagsMsg db "flags: "
flagsMsgLen = $ - flagsMsg

openFailedMsg db "Failed to open packed file",0xa
openFailedMsgLen = $ - openFailedMsg
readFailedMsg db "Failed to read packed file",0xa
readFailedMsgLen = $ - readFailedMsg
writeFailedMsg db "Failed to write output file",0xa
writeFailedMsgLen = $ - writeFailedMsg
closeFailedMsg db "Failed to close output file",0xa
closeFailedMsgLen = $ - closeFailedMsg
invalidFooterTooSmallMsg db "Packed file is smaller than a SPACK footer",0xa
invalidFooterTooSmallMsgLen = $ - invalidFooterTooSmallMsg
invalidFooterMagicMsg db "Packed file does not end with a valid SPACK footer",0xa
invalidFooterMagicMsgLen = $ - invalidFooterMagicMsg
invalidMetaRangeMsg db "SPACK metadata range overlaps or extends into the footer",0xa
invalidMetaRangeMsgLen = $ - invalidMetaRangeMsg
invalidPayloadRangeMsg db "SPACK payload range overlaps or extends into the footer",0xa
invalidPayloadRangeMsgLen = $ - invalidPayloadRangeMsg
invalidOverlapMsg db "SPACK metadata and payload ranges overlap",0xa
invalidOverlapMsgLen = $ - invalidOverlapMsg
invalidFlagsMsg db "Packed file uses unknown SPACK footer flags",0xa
invalidFlagsMsgLen = $ - invalidFlagsMsg
invalidMetaFormatMsg db "Embedded SHELFBN1 metadata is malformed or unsupported",0xa
invalidMetaFormatMsgLen = $ - invalidMetaFormatMsg
invalidPayloadSizeMsg db "Embedded payload size does not match the size described by SHELFBN1",0xa
invalidPayloadSizeMsgLen = $ - invalidPayloadSizeMsg
validateOkMsg db "spack validate: ok",0xa
validateOkMsgLen = $ - validateOkMsg

segment readable writeable 
fileSize rq 1              
inputFd rq 1               
metaFd rq 1                
payloadFd rq 1             
modeArg rq 1               
inputPath rq 1             
metaOutPath rq 1           
payloadOutPath rq 1        
modeExtract rb 1           
modeValidate rb 1          
footerOff rq 1             
metaOff rq 1               
metaLen rq 1               
payloadOff rq 1            
payloadLen rq 1            
flagsValue rq 1            
expectedPayloadLen rq 1    
phdrBlobSize rq 1          
footerBuf rb SPACK_FOOTER_SIZE 
copyBuf rb SHELF_META_MAX_SIZE  
u64Buf rb 32                    
