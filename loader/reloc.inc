; Direct entry relocation handling for ET_DYN. It just knows specific kinds of
; relocations that we actually need and nothing else
interp:
    cmp byte [hasInterp], 0
    jne loadInterp
    cmp byte [hasDynamic], 0
    je prepareTlsAndStack                         ; static binaries carry no PT_DYNAMIC and need no relocation pass at all
    lea rsi, [dbgRelocMsg]
    mov rdx, dbgRelocMsgLen
    call debugWrite
    ; Read PT_DYNAMIC once to find the RELA/JMPREL tables and their sizes.
    ; If the target wants more than RELATIVE/IRELATIVE world, let's bail
    mov rsi, [baseAddr]
    add rsi, [dynamicVaddr]
    mov rcx, [dynamicSize]
    shr rcx, 4                                    ; DYN entries are tag+val pairs, 16 bytes each, so this turns bytes into a count
    .parseDynamic:
        test rcx, rcx
        jz .dynamicParsed
        mov rax, [rsi + DYN.tag]                    ; only the tags below matter for RELA/JMPREL, everything else in PT_DYNAMIC is ignored
        mov rdx, [rsi + DYN.val]
        cmp rax, DT_NULL                            ; DT_NULL terminates the dynamic table early, before dynamicSize is exhausted
        je .dynamicParsed
        cmp rax, DT_RELA
        jne .notDtRela
        mov [relaAddr], rdx                       ; stored as a raw vaddr, baseAddr gets folded in wherever this is read back
        jmp .nextDynamic
        .notDtRela:
        cmp rax, DT_RELASZ
        jne .notDtRelaSz
        mov [relaSize], rdx                       ; total byte size, paired with relaEnt below to get a record count
        jmp .nextDynamic
        .notDtRelaSz:
        cmp rax, DT_RELAENT
        jne .notDtRelaEnt
        mov [relaEnt], rdx                        ; recorded so the sizeof.RELA sanity check further down has something to compare against
        jmp .nextDynamic
        .notDtRelaEnt:
        cmp rax, DT_JMPREL
        jne .notDtJmpRel
        mov [jmprelAddr], rdx                     ; JMPREL is the PLT's own RELA table, same vaddr caveat as relaAddr above
        jmp .nextDynamic
        .notDtJmpRel:
        cmp rax, DT_PLTRELSZ
        jne .notDtPltRelSz
        mov [jmprelSize], rdx                     ; same byte-size role as DT_RELASZ, but for the PLT/JMPREL table
        jmp .nextDynamic
        .notDtPltRelSz:
        cmp rax, DT_PLTREL
        jne .notDtPltRel
        mov [pltrelType], rdx                     ; DT_PLTREL tells us whether JMPREL uses REL or RELA layout, we only support RELA
        jmp .nextDynamic
        .notDtPltRel:
        .nextDynamic:
        add rsi, sizeof.DYN
        dec rcx
        jmp .parseDynamic
    .dynamicParsed:

    ; No RELA table means nothing for us to do here
    cmp qword [relaEnt], 0
    je prepareTlsAndStack
    cmp qword [relaEnt], sizeof.RELA              ; an unexpected entry size means an ELF layout we don't understand, bail rather than misparse
    jne unsupportedReloc
    cmp qword [pltrelType], 0
    je .applyRelaRelative                         ; no PLT table at all, nothing further to validate before the RELATIVE pass
    cmp qword [pltrelType], DT_RELA
    jne unsupportedReloc                          ; a REL style PLT layout isn't something this loader knows how to apply

    ; Pass 1: plain RELATIVE relocations.
    ;
    ; Write (base + addend) into (base + offset) and continue. Do this first so
    ; later passes operate against a simpler image
    .applyRelaRelative:
    mov rsi, [baseAddr]
    add rsi, [relaAddr]                            ; relaAddr was stored as a raw vaddr, this is where baseAddr finally gets folded in
    mov rcx, [relaSize]
    xor rdx, rdx                                  ; div takes rdx:rax as a 128 bit dividend, zero the high half or the quotient is garbage
    mov rax, [relaEnt]
    test rax, rax
    jz unsupportedReloc                           ; a zero entry size would turn the loop below into an infinite one
    div rax                                       ; RELA has no entry count field, only a byte range, so recover the count this way
    mov rcx, rax                                  ; rcx now counts whole RELA records rather than bytes
    .relaRelativeLoop:
        test rcx, rcx
        jz .applyJmpRelRelative
        mov rax, [rsi + RELA.info]                ; r_info packs the symbol index in the high 32 bits, the type in the low 32
        and eax, 0xffffffff
        cmp eax, R_X86_64_RELATIVE
        jne .nextRelaRelative
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]               ; offset is a vaddr too, this is where the fixup actually lands at runtime
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]               ; RELATIVE carries no symbol, the value is just base + addend
        mov [rdi], rax
        .nextRelaRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .relaRelativeLoop

    .applyJmpRelRelative:
    ; Some static PIEs also sneak RELATIVE relocations into JMPREL
    cmp qword [jmprelSize], 0
    je .applyRelaIRelative                        ; no PLT relocations present, nothing more to do in this pass
    mov rsi, [baseAddr]
    add rsi, [jmprelAddr]                          ; jmprelAddr is a vaddr too, fixed up against baseAddr here just like relaAddr
    mov rcx, [jmprelSize]
    xor rdx, rdx                                  ; same rdx:rax caveat as the RELATIVE pass above
    mov rax, [relaEnt]                            ; JMPREL shares the RELA record layout, guaranteed by the DT_PLTREL check earlier
    test rax, rax                                 ; a zero here would mean DT_RELAENT was never set, bail rather than divide by it
    jz unsupportedReloc
    div rax                                       ; byte range becomes a JMPREL record count the same way as the main table
    mov rcx, rax
    .jmprelRelativeLoop:
        test rcx, rcx
        jz .applyRelaIRelative
        mov rax, [rsi + RELA.info]                ; JMPREL entries use the same r_info layout as the main RELA table
        and eax, 0xffffffff
        cmp eax, R_X86_64_RELATIVE                ; this table can carry RELATIVE entries too on some binaries, handled the same way
        jne .nextJmpRelRelative
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]               ; still base + addend, no symbol lookup needed for RELATIVE
        mov [rdi], rax
        .nextJmpRelRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .jmprelRelativeLoop

    .applyRelaIRelative:
    ; Pass 2: IRELATIVE relocations.
    ;
    ; These call back into resolver code inside the image, after the plain
    ; RELATIVE pointers are already fixed
    mov rsi, [baseAddr]
    add rsi, [relaAddr]
    mov rcx, [relaSize]
    xor rdx, rdx                                  ; clearing rdx again before the divide, same reason as before
    mov rax, [relaEnt]
    test rax, rax
    jz unsupportedReloc                           ; refuse rather than loop forever on a zero sized RELA entry
    div rax
    mov rcx, rax
    .relaIRelativeLoop:
        test rcx, rcx
        jz .applyJmpRelIRelative
        mov rax, [rsi + RELA.info]                ; still the same info word layout, now filtering for IRELATIVE instead
        and eax, 0xffffffff
        cmp eax, R_X86_64_IRELATIVE
        jne .checkUnsupportedRela
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]               ; same dest address math as the RELATIVE passes above
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]               ; here the addend is the resolver's address, not the final value
        push rcx                                  ; the resolver is arbitrary code and may clobber these, save loop state before calling it
        push rsi
        push rdi
        call rax                                  ; execute the resolver to compute the real target
        pop rdi
        pop rsi
        pop rcx
        mov [rdi], rax
        jmp .nextRelaIRelative
        .checkUnsupportedRela:
        cmp eax, R_X86_64_RELATIVE                 ; plain RELATIVE entries are legal here too, just already handled in pass 1
        je .nextRelaIRelative
        jmp unsupportedReloc                      ; anything else is a relocation kind this loader doesn't know how to apply safely
        .nextRelaIRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .relaIRelativeLoop

    .applyJmpRelIRelative:
    ; Same idea again for the PLT relocation table, because some binaries stash
    ; IRELATIVE entries there instead of in the main RELA table (if I understood
    ; correctly, but seems to work?)
    cmp qword [jmprelSize], 0
    je prepareTlsAndStack                         ; no PLT table left to check, relocation is done
    mov rsi, [baseAddr]
    add rsi, [jmprelAddr]
    mov rcx, [jmprelSize]
    xor rdx, rdx
    mov rax, [relaEnt]                            ; JMPREL's PLT entries share the RELA layout too, per the same DT_PLTREL guarantee
    test rax, rax
    jz unsupportedReloc
    div rax                                       ; and again here, for the PLT/JMPREL table
    mov rcx, rax
    .jmprelIRelativeLoop:
        test rcx, rcx
        jz prepareTlsAndStack
        mov rax, [rsi + RELA.info]                ; PLT/JMPREL info word, same layout, same mask
        and eax, 0xffffffff
        cmp eax, R_X86_64_IRELATIVE                ; PLT ifuncs get identical resolver treatment to the main table pass above
        jne .checkUnsupportedJmpRel
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]               ; same destination math, now for a PLT slot
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]               ; addend here is the resolver address again, not a final pointer
        push rcx                                  ; same resolver-clobber concern as the main table pass above
        push rsi
        push rdi
        call rax                                  ; PLT ifuncs resolve the exact same way
        pop rdi
        pop rsi
        pop rcx
        mov [rdi], rax
        jmp .nextJmpRelIRelative
        .checkUnsupportedJmpRel:
        cmp eax, R_X86_64_RELATIVE                 ; tolerated here too, the RELATIVE pass over JMPREL already applied it
        je .nextJmpRelIRelative
        jmp unsupportedReloc
        .nextJmpRelIRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .jmprelIRelativeLoop
