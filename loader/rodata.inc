hexDigits         db "0123456789abcdef"

dbgEnabledMsg       db "phork: debug tracing enabled", 0xa
dbgEnabledMsgLen    = $ - dbgEnabledMsg
dbgReserveDynMsg    db "phork: reserving SHELF load window", 0xa
dbgReserveDynMsgLen = $ - dbgReserveDynMsg
dbgLoadBiasMsg      db "phork: load bias = "
dbgLoadBiasMsgLen   = $ - dbgLoadBiasMsg
dbgStackMsg         db "phork: synthetic stack base = "
dbgStackMsgLen      = $ - dbgStackMsg
dbgMapMainMsg       db "phork: mapping SHELF PT_LOAD at "
dbgMapMainMsgLen    = $ - dbgMapMainMsg
dbgRelocMsg         db "phork: applying direct entry relocations", 0xa
dbgRelocMsgLen      = $ - dbgRelocMsg
dbgTlsMsg           db "phork: preparing PT_TLS runtime state", 0xa
dbgTlsMsgLen        = $ - dbgTlsMsg
dbgStackBuildMsg    db "phork: rebuilding argc/argv/envp/auxv", 0xa
dbgStackBuildMsgLen = $ - dbgStackBuildMsg
dbgJumpMainMsg      db "phork: jumping to SHELF entry = "
dbgJumpMainMsgLen   = $ - dbgJumpMainMsg
dbgJumpInterpMsg    db "phork: PT_INTERP path is not part of this variant"
dbgJumpInterpMsgLen = $ - dbgJumpInterpMsg

unsupportedTypeMsg    db "phork: this runtime only accepts ET_DYN SHELF payloads", 0xa
unsupportedTypeMsgLen = $ - unsupportedTypeMsg
unsupportedInterpMsg  db "phork: PT_INTERP would defeat the direct entry packer model", 0xa
unsupportedInterpMsgLen = $ - unsupportedInterpMsg
unsupportedRelocMsg   db "phork: relocation set is larger than this packed runtime handles", 0xa
unsupportedRelocMsgLen = $ - unsupportedRelocMsg
stackStorageTooSmallMsg    db "phork: copied argv/env strings do not fit in the synthetic stack arena", 0xa
stackStorageTooSmallMsgLen = $ - stackStorageTooSmallMsg
openFailedMsg              db "phork: could not reopen the packed file", 0xa
openFailedMsgLen           = $ - openFailedMsg
fstatFailedMsg             db "phork: could not stat the packed file", 0xa
fstatFailedMsgLen          = $ - fstatFailedMsg
fileReadFailedMsg          db "phork: could not read the embedded payload bytes", 0xa
fileReadFailedMsgLen       = $ - fileReadFailedMsg
metaReadFailedMsg          db "phork: could not read the embedded SHELFBN1 metadata blob", 0xa
metaReadFailedMsgLen       = $ - metaReadFailedMsg
closeFailedMsg             db "phork: finished unpacking, but close(2) on the packed file failed", 0xa
closeFailedMsgLen          = $ - closeFailedMsg
mmapFailedMsg              db "phork: mmap(2) failed while laying out the unpacked image", 0xa
mmapFailedMsgLen           = $ - mmapFailedMsg
mprotectFailedMsg          db "phork: mprotect(2) rejected the final segment permissions", 0xa
mprotectFailedMsgLen       = $ - mprotectFailedMsg
archPrctlFailedMsg         db "phork: arch_prctl(2) failed while installing PT_TLS state", 0xa
archPrctlFailedMsgLen      = $ - archPrctlFailedMsg
