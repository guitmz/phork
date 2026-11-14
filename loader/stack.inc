; Direct entry TLS setup (I hated this very much, took me like 1 year of work).
;
; This file owns the two ABI sensitive chores nobody really gets for free here:
;   * fake just enough TLS for direct entry PT_TLS binaries
;   * rebuild a kernel like initial stack with patched auxv values

prepareTlsAndStack:
    ; If PT_INTERP is in charge, ld-linux will sort TLS out later. The manual
    ; bootstrap below is only for the direct entry paths where we jmp in
    ; ourselves
    cmp byte [hasInterp], 0
    jne prepareStackImage
    cmp byte [hasTls], 0
    je prepareStackImage
    lea rsi, [dbgTlsMsg]
    mov rdx, dbgTlsMsgLen
    call debugWrite
    ; PT_TLS alignment can be zero or just plain tiny. We normalize it here so
    ; the synthetic layout has a sane x64 baseline
    mov rax, [tlsAlign]
    test rax, rax
    jnz .tlsAlignReady
    mov rax, 1                                    ; zero = no special alignment beyond byte granularity
    .tlsAlignReady:
    cmp rax, 16                                   ; keep the alignment at least 16 bytes for sane x64 startup state
    jae .tlsAlignSized
    mov rax, 16
    .tlsAlignSized:
    ; Layout is:
    ;   [TLS block][TCB][small DTV]
    ;
    ; Then FS points at the TCB. Minimal, yes, but enough for the direct entry
    ; cases we care about here
    mov [tlsAlignWork], rax                       ; remember the normalized alignment for the address arithmetic below
    mov rcx, [tlsMemsz]                           ; start from the TLS block size, before the TCB/DTV padding below
    add rcx, TLS_TCB_SIZE + TLS_DTV_SIZE
    add rcx, rax                                  ; add enough slack to round the TCB up to its required alignment
    add rcx, 15
    and rcx, -16                                   ; final anonymous mapping length for the TLS area
    mov rdi, 0                                     ; 0 lets the kernel choose the mapping address
    mov rsi, rcx
    mov rdx, PROT_READ or PROT_WRITE              ; TLS storage only ever needs to be read and written, never executed
    mov r10, MAP_PRIVATE or MAP_ANON              ; anonymous private memory is enough for synthetic TLS
    mov r8, -1                                    ; -1 is required for an anonymous mapping, there is no backing fd
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    ; Place the TCB right after the TLS block, align it up, and keep the block
    ; itself immediately before it. That matches the x64 model glibc and
    ; static PIE startup code expect closely enough for our needs
    mov rdi, rax                                  ; start from the base of the anonymous TLS mapping
    add rdi, [tlsMemsz]                           ; move past the TLS block to where the TCB will begin
    mov rax, [tlsAlignWork]
    dec rax                                       ; convert alignment into a low bits mask helper
    add rdi, rax                                  ; bias upward before masking so the result rounds up
    not rax                                       ; invert the mask so aligned low bits become zero
    and rdi, rax
    mov [tlsTcb], rdi
    mov rax, rdi
    sub rax, [tlsMemsz]                           ; step backward by tlsMemsz to recover the TLS block base
    mov [tlsBlock], rax
    mov rdi, rax
    cmp word [ehdr.type], ET_EXEC
    jne .tlsCopyFromMapped
    ; ET_EXEC has not been remapped yet at this point, so its TLS initializer
    ; still has to come from the staged file buffer
    lea rsi, [buffer]
    add rsi, [tlsOffset]
    jmp .tlsCopyReady
    .tlsCopyFromMapped:
    mov rsi, [baseAddr]
    add rsi, [tlsVaddr]
    .tlsCopyReady:
    ; Copy the initializer bytes, then zero the tail if there is one
    mov rcx, [tlsFilesz]
    rep movsb
    mov rcx, [tlsMemsz]
    sub rcx, [tlsFilesz]
    xor eax, eax
    rep stosb
    mov rdi, [tlsTcb]
    mov rax, rdi                                  ; the TCB must point at itself, that's the x64 TLS FS:0 convention
    mov [rdi], rax
    lea rax, [rdi + TLS_TCB_SIZE + 16]
    mov [rdi + 8], rax
    mov [rdi + 16], rdi                           ; these two fields round out the minimal tcbhead_t glibc expects to find here
    ; Seed a tiny DTV that describes one TLS module starting at tlsBlock
    lea rsi, [rdi + TLS_TCB_SIZE]
    mov qword [rsi], 1
    mov qword [rsi + 8], 0
    mov qword [rsi + 16], 1
    mov qword [rsi + 24], 0
    mov rax, [tlsBlock]
    mov [rsi + 32], rax
    mov qword [rsi + 40], 0
    mov rdi, ARCH_SET_FS                          ; arch_prctl subcommand selecting FS base installation
    mov rsi, [tlsTcb]                             ; FS base becomes our synthetic TCB from here on
    mov rax, SYS_ARCH_PRCTL
    syscall
    test rax, rax
    js archPrctlFailed

prepareStackImage:
    ; Rebuild a kernel-like initial stack in loader memory:
    ;   argc
    ;   argv[]
    ;   NULL
    ;   envp[]
    ;   NULL
    ;   auxv[]
    ;
    ; We also duplicate the pointed to strings and aux payloads so the loaded
    ; program does not keep pointers into the loader's own stack by accident
    lea rsi, [dbgStackBuildMsg]
    mov rdx, dbgStackBuildMsgLen
    call debugWrite
    mov rbx, [targetArgv]                         ; pointer to argv[0] in the loader's own original startup stack
    mov rcx, [targetArgc]                         ; number of target argv entries, including argv[0]
    lea rdx, [rbx + rcx * 8 + 8]                  ; skip argv[] plus its trailing NULL to reach envp[0]
    mov [targetEnvp], rdx
    mov rsi, rdx                                  ; walk the original envp vector looking for where auxv begins
    .findAuxv:
        mov rax, [rsi]
        add rsi, 8
        test rax, rax                     ; envp is NULL terminated, and auxv begins right after that NULL
        jnz .findAuxv
    mov [targetAuxv], rsi
    mov rdx, [targetEnvp]
    xor rcx, rcx
    .countEnvp:
        mov rax, [rdx]
        add rdx, 8
        inc rcx
        test rax, rax
        jnz .countEnvp
    dec rcx                                       ; the loop above also counted the terminating NULL, drop it back out here
    mov [targetEnvc], rcx
    mov rsi, [targetAuxv]
    xor rcx, rcx
    .countAuxv:
        mov rax, [rsi]
        add rsi, 16                               ; auxv entries are a_type/a_val pairs, 16 bytes each
        inc rcx                                   ; unlike targetEnvc, this count intentionally keeps the AT_NULL terminator in it
        test rax, rax                             ; AT_NULL is type 0 and marks the end of the auxv vector
        jnz .countAuxv
    mov [targetAuxc], rcx
    xor rcx, rcx
    ; First count how many string bytes we are about to duplicate. If the
    ; reserved stack storage is too small, bail out now instead of half
    ; building a stack
    mov rsi, [targetArgv]
    mov rdx, [targetArgc]
    .countArgStrings:
        test rdx, rdx
        jz .countEnvStrings
        mov rdi, [rsi]
        .countArgStringBytes:
            inc rcx                               ; rcx is a running total shared with the env string count below
            mov al, [rdi]
            inc rdi
            test al, al
            jnz .countArgStringBytes
        add rsi, 8
        dec rdx
        jmp .countArgStrings
    .countEnvStrings:
    mov rsi, [targetEnvp]
    mov rdx, [targetEnvc]
    .countEnvStringsLoop:
        test rdx, rdx
        jz .countStringsDone
        mov rdi, [rsi]
        .countEnvStringBytes:
            inc rcx
            mov al, [rdi]
            inc rdi
            test al, al
            jnz .countEnvStringBytes
        add rsi, 8
        dec rdx
        jmp .countEnvStringsLoop
    .countStringsDone:
    mov [totalStringBytes], rcx
    cmp rcx, STACK_STRING_SIZE
    jg stackStorageTooSmall                       ; better to refuse outright than build a stack with truncated strings
    mov rax, [stackAddr]
    add rax, STACK_STORAGE_SIZE                   ; string storage sits right after the region reserved for pointer tables
    mov [stringWritePtr], rax
    mov rax, [stackAddr]
    add rax, STACK_SIZE
    and rax, -16                                  ; top of the mapping, 16 byte aligned as the ABI expects at process entry
    mov rcx, [targetEnvc]
    add rcx, [targetArgc]

    ; The stack is built downward from the top of the mapping. The exact top
    ; alignment differs a little between direct entry and PT_INTERP paths, so
    ; we settle that before laying out the tables.
    cmp byte [hasInterp], 0
    jne .stackTopInterp
    test rcx, 1
    jz .stackTopReady
    sub rax, 8                                    ; nudge the top so the final table count still leaves rsp 16 byte aligned
    jmp .stackTopReady
    .stackTopInterp:
    test rcx, 1
    jnz .stackTopReady
    sub rax, 8
    .stackTopReady:
    mov [newStackPtr], rax
    ; Pointer tables go downward from the top:
    ;   auxv, then envp, then argv, then argc
    ;
    ; Copied strings and aux payloads grow upward from stringWritePtr.
    ; That split keeps ownership obvious and avoids leaving target pointers
    ; aimed at the loader's original entry stack.
    mov rdi, [newStackPtr]
    mov rcx, [targetAuxc]
    shl rcx, 4
    sub rdi, rcx
    mov [auxvDst], rdi
    mov rsi, [targetAuxv]
    mov rcx, [targetAuxc]
    .copyAuxv:
        ; Auxv copy/patch pass.
        ;
        ; Most entries survive unchanged, but some values must be rewritten
        ; because the loader changed image placement, entry routing, or the
        ; storage backing the strings/payloads they point at
        mov rax, [rsi]
        mov r8, [rsi + 8]
        cmp rax, AT_PHDR
        jne .auxNotPhdr
        mov r8, [phdrRuntime]
        jmp .auxStore
        .auxNotPhdr:
        cmp rax, AT_PHENT
        jne .auxNotPhent
        movzx r8, word [ehdr.phentsize]
        jmp .auxStore
        .auxNotPhent:
        cmp rax, AT_PHNUM
        jne .auxNotPhnum
        movzx r8, word [ehdr.phnum]               ; reports the main executable's phdr count, not the interpreter's
        jmp .auxStore
        .auxNotPhnum:
        cmp rax, AT_BASE                          ; AT_BASE points at the interpreter's base, when PT_INTERP exists
        jne .auxNotBase
        mov r8, [interpBaseAddr]                  ; the mapped ld-linux base address, or 0 for a direct entry binary
        jmp .auxStore
        .auxNotBase:
        cmp rax, AT_ENTRY                         ; AT_ENTRY always describes the main program's entry point, never the interpreter's
        jne .auxNotEntry
        mov r8, [baseAddr]                        ; the main image's load bias, 0 for ET_EXEC
        add r8, [ehdr.entry]
        jmp .auxStore
        .auxNotEntry:
        cmp rax, AT_EXECFN                        ; AT_EXECFN should reference the executable's pathname string
        jne .auxNotExecfn
        mov r8, [targetPath]                      ; a placeholder for now, patched later to point at the copied argv[0] instead
        jmp .auxStore
        .auxNotExecfn:
        cmp rax, AT_RANDOM
        jne .auxNotRandom
        ; AT_RANDOM points at 16 random bytes, not a C string, so copy the
        ; payload as is and then patch the auxv value to the copied address
        push rcx
        push rax
        mov r9, [stringWritePtr]                  ; stringWritePtr is a simple bump allocator into the copied string/payload area
        mov [rdi + 8], r9                         ; stashed here temporarily, .auxStore below overwrites it with the real r8
        mov r10, [rsi + 8]
        mov rcx, 16                               ; AT_RANDOM's payload is always exactly 16 bytes, per the kernel ABI
        .copyAuxRandom:
            mov dl, [r10]
            mov [r9], dl
            inc r9
            inc r10
            loop .copyAuxRandom
        mov [stringWritePtr], r9                  ; commit the bump allocator forward past what we just copied
        pop rax
        pop rcx
        mov r8, [rdi + 8]                         ; reload the copied payload pointer stashed above, now the real auxv value
        jmp .auxStore
        .auxNotRandom:
        cmp rax, AT_PLATFORM
        je .copyAuxString
        cmp rax, AT_BASE_PLATFORM
        jne .auxStore
        .copyAuxString:
        ; These auxv entries point at NUL terminated strings that also need to
        ; move onto the target stack image
        push rcx
        push rax
        mov r9, [stringWritePtr]
        mov [rdi + 8], r9
        mov r10, [rsi + 8]
        .copyAuxCString:
            mov dl, [r10]                         ; copy until NUL also used again below for the env and argv strings
            mov [r9], dl
            inc r9
            inc r10
            test dl, dl
            jnz .copyAuxCString
        mov [stringWritePtr], r9
        pop rax
        pop rcx
        mov r8, [rdi + 8]
        .auxStore:
        mov [rdi], rax
        mov [rdi + 8], r8
        add rsi, 16
        add rdi, 16
        dec rcx
        jnz .copyAuxv
    mov rdi, [auxvDst]
    mov rax, [targetEnvc]
    inc rax                                       ; ++ slot for the terminating envp NULL
    shl rax, 3
    sub rdi, rax                                  ; carve out room for envp immediately below auxv, same downward layout as before
    mov [envpDst], rdi
    mov rdi, [envpDst]
    mov rsi, [targetEnvp]
    mov rcx, [targetEnvc]
    .copyEnvStrings:
        ; Environment vector rewrite.
        ;
        ; Each envp[i] pointer is rewritten to point at a copied string owned
        ; by the synthetic stack mapping instead of the loader's original
        ; startup stack
        test rcx, rcx
        jz .copyEnvStringsDone
        mov r8, [stringWritePtr]
        mov [rdi], r8
        mov r9, [rsi]
        .copyOneEnvString:
            mov al, [r9]
            mov [r8], al
            inc r8
            inc r9
            test al, al
            jnz .copyOneEnvString
        mov [stringWritePtr], r8
        add rdi, 8
        add rsi, 8
        dec rcx
        jmp .copyEnvStrings
    .copyEnvStringsDone:
    mov qword [rdi], 0                            ; the envp table is NULL terminated, same as the loader's own startup stack
    mov rdi, [envpDst]
    mov rax, [targetArgc]
    inc rax
    shl rax, 3
    sub rdi, rax
    mov [argvDst], rdi
    mov rdi, [argvDst]
    mov rsi, [targetArgv]
    mov rcx, [targetArgc]
    .copyArgStrings:
        ; Argument vector rewrite.
        ;
        ; argv is treated exactly like envp: rewrite pointer slots downward,
        ; copy actual string bytes upward into target storage
        test rcx, rcx
        jz .copyArgStringsDone
        mov r8, [stringWritePtr]                  ; same bump allocator as the aux and env string copies above
        mov [rdi], r8
        mov r9, [rsi]
        .copyOneArgString:
            mov al, [r9]
            mov [r8], al
            inc r8
            inc r9
            test al, al
            jnz .copyOneArgString
        mov [stringWritePtr], r8
        add rdi, 8
        add rsi, 8
        dec rcx
        jmp .copyArgStrings
    .copyArgStringsDone:
    mov qword [rdi], 0                            ; argv table gets the same NULL terminator as envp did
    mov rax, [argvDst]
    mov rax, [rax]                                ; argvDst pointed at the argv[0] slot, this dereferences it to the string itself
    mov [targetPathNew], rax                      ; the copied executable path, used below for the AT_EXECFN patch
    mov rsi, [auxvDst]
    mov rcx, [targetAuxc]
    .patchExecfnAuxv:
        ; AT_EXECFN should reference the copied argv[0] string, not the old
        ; pointer into the loader's original stack
        test rcx, rcx
        jz .patchExecfnDone
        mov rax, [rsi]
        cmp rax, AT_EXECFN                        ; only this one rebuilt entry needs the second patching pass
        jne .nextExecfnAuxv
        mov rax, [targetPathNew]
        mov [rsi + 8], rax                         ; now the target sees an AT_EXECFN pointer it actually owns
        jmp .patchExecfnDone
        .nextExecfnAuxv:
        add rsi, 16
        dec rcx
        jmp .patchExecfnAuxv
    .patchExecfnDone:
    ; After argv/envp/auxv are laid out, prepend argc immediately below them.
    ; That final pointer is what the target entry code will observe in rsp
    mov rdi, [argvDst]
    sub rdi, 8                                     ; one machine word below argv[0], reserved for argc
    mov rax, [targetArgc]
    mov [rdi], rax
    mov [newStackPtr], rdi                         ; this is the exact rsp value that gets installed at handoff

    ; Final handoff selection.
    ;
    ; After this point the stack image is complete. We can close the staged
    ; file and choose the final entry mechanism:
    ;   * ET_EXEC -> fork + scratch trampoline
    ;   * PT_INTERP -> jump into ld-linux
    ;   * otherwise -> jump directly to the main executable entry point
    ; From this point on the staged file descriptor is no longer needed. All
    ; target bytes that matter have already been copied into anonymous mappings
    mov rdi, [targetFd]
    mov rax, SYS_CLOSE
    syscall
    test rax, rax
    js closeFailed

    ; ET_EXEC targets must switch through the child trampoline so they can
    ; claim fixed virtual addresses without destroying the running loader
    cmp word [ehdr.type], ET_EXEC
    je forkTransformExec
    cmp byte [hasInterp], 0                       ; PT_INTERP means jumping into ld-linux instead of the main entry point
    jne .jumpInterp
    mov r11, [baseAddr]
    add r11, [ehdr.entry]                         ; direct entry runtime address of the main executable's entry point
    lea rsi, [dbgJumpMainMsg]
    mov rdx, dbgJumpMainMsgLen
    mov rax, r11
    call debugPrintHexLine
    ENTER_PREPARED_IMAGE newStackPtr, r11
    .jumpInterp:
    mov r11, [interpBaseAddr]
    add r11, [interpEhdr.entry]
    lea rsi, [dbgJumpInterpMsg]
    mov rdx, dbgJumpInterpMsgLen
    mov rax, r11
    call debugPrintHexLine
    ENTER_PREPARED_IMAGE newStackPtr, r11
