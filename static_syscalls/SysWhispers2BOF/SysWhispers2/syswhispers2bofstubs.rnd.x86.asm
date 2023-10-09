.686
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data
stubReturn      dd 0
returnAddress   dd 0
espBookmark     dd 0
syscallNumber   dd 0
syscallAddress  dd 0

.code

EXTERN SW2_GetSyscallNumber: PROC
EXTERN SW2_GetRandomSyscallAddress: PROC

WhisperMain PROC
    pop eax                                 ; Remove return address from CALL instruction
    mov dword ptr [stubReturn], eax         ; Save the return address to the stub
    push esp
    pop eax
    add eax, 04h
    push dword ptr [eax]
    pop returnAddress                       ; Save the original return address
    add eax, 04h
    push eax
    pop espBookmark                         ; Save original ESP
    call SW2_GetSyscallNumber               ; Resolve function hash into syscall number
    add esp, 4                              ; Restore ESP
    mov dword ptr [syscallNumber], eax      ; Save the syscall number
    xor eax, eax
    mov ecx, fs:[0c0h]
    test ecx, ecx
    je _x86
    inc eax
_x86: 
    push eax                                ; Push 0 for x86, 1 for Wow64
    lea edx, dword ptr [esp+04h]
    call SW2_GetRandomSyscallAddress        ; Get a memory address of random syscall
    mov dword ptr [syscallAddress], eax     ; Save the address
    mov esp, dword ptr [espBookmark]        ; Restore ESP
    mov eax, dword ptr [syscallNumber]      ; Restore the syscall number
    call dword ptr syscallAddress           ; Call the random syscall
    mov esp, dword ptr [espBookmark]        ; Restore ESP
    push dword ptr [returnAddress]          ; Restore the return address
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