.686
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data

.code

EXTERN SW2_GetSyscallNumber: PROC

WhisperMain PROC
    pop eax                        ; Remove return address from CALL instruction
    call SW2_GetSyscallNumber      ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, fs:[0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword ptr fs:[0c0h]
    ret
WhisperMain ENDP

NtOpenProcess PROC
    push 0633B2AE6h
    call WhisperMain
NtOpenProcess ENDP

NtAllocateVirtualMemory PROC
    push 00B901715h
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
    push 0F75FEFCFh
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
    push 074AF4416h
    call WhisperMain
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
    push 026BA3C17h
    call WhisperMain
NtWaitForSingleObject ENDP

NtClose PROC
    push 034ECACD1h
    call WhisperMain
NtClose ENDP

NtFreeVirtualMemory PROC
    push 087957DD7h
    call WhisperMain
NtFreeVirtualMemory ENDP

end