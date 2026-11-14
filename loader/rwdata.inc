fstat       STAT    
ehdr        EHDR    
phdr        PHDR    
interpStat  STAT    
interpEhdr  EHDR    

targetFd        rq 1   
exitStatus      rb 1   
hasInterp       rb 1   
hasDynamic      rb 1   
hasTls          rb 1   
debugEnabled    rb 1   

targetArgc          rq 1   
targetArgv          rq 1   
targetEnvp          rq 1   
targetEnvc          rq 1   
targetAuxv          rq 1   
targetAuxc          rq 1   
targetPath          rq 1   
targetPathNew       rq 1   
newStackPtr         rq 1   
argvDst             rq 1   
envpDst             rq 1   
auxvDst             rq 1   
stringWritePtr      rq 1   
totalStringBytes    rq 1   

stackAddr       rq 1    
baseAddr        rq 1    
interpBaseAddr  rq 1    
phdrRuntime     rq 1    
headerSpan      rq 1    
phoffValue      rq 1    
loadFilesz      rq 1    
loadMemsz       rq 1    
loadFlags       rq 1    
phdrBlobAddr    rq 1    

dynamicVaddr    rq 1   
dynamicSize     rq 1   
tlsVaddr        rq 1   
tlsOffset       rq 1   
tlsFilesz       rq 1   
tlsMemsz        rq 1   
tlsAlign        rq 1   
tlsAlignWork    rq 1   
tlsBlock        rq 1   
tlsTcb          rq 1   

relaAddr    rq 1  
relaSize    rq 1  
relaEnt     rq 1  
jmprelAddr  rq 1  
jmprelSize  rq 1  
pltrelType  rq 1  

imageSpanSize       rq 1    

stackProt       db PROT_READ or PROT_WRITE  
debugHexBuf     rb 19                       
buffer          rb BUFFER_SIZE              
interpBuffer    rb BUFFER_SIZE              
phdrBlob        rb 4096                     
