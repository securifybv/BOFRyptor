.intel_syntax noprefix
.data
currentHash:    .long   0

.text
.global NtOpenProcess
.global NtAllocateVirtualMemory
.global NtWriteVirtualMemory
.global NtCreateThreadEx
.global NtWaitForSingleObject
.global NtClose
.global NtFreeVirtualMemory

.global WhisperMain
.extern SW2_GetSyscallNumber
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx              # Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 0x28
    mov ecx, dword ptr [currentHash + RIP]
    call SW2_GetSyscallNumber
    add rsp, 0x28
    mov rcx, [rsp+ 8]              # Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        # Issue syscall
    ret

NtOpenProcess:
    mov dword ptr [currentHash + RIP], 0x0633B2AE6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x00B901715   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x0F75FEFCF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThreadEx:
    mov dword ptr [currentHash + RIP], 0x074AF4416   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForSingleObject:
    mov dword ptr [currentHash + RIP], 0x026BA3C17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClose:
    mov dword ptr [currentHash + RIP], 0x034ECACD1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x087957DD7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


