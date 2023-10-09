[SECTION .data]

global _NtOpenProcess
global _NtAllocateVirtualMemory
global _NtWriteVirtualMemory
global _NtCreateThreadEx
global _NtWaitForSingleObject
global _NtClose
global _NtFreeVirtualMemory

global _WhisperMain
extern _SW2_GetSyscallNumber

[SECTION .text]

BITS 32
DEFAULT REL

_WhisperMain:
    pop eax                        ; Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, [fs:0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword [fs:0c0h]
    ret

_NtOpenProcess:
    push 0633B2AE6h
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 00B901715h
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0F75FEFCFh
    call _WhisperMain

_NtCreateThreadEx:
    push 074AF4416h
    call _WhisperMain

_NtWaitForSingleObject:
    push 026BA3C17h
    call _WhisperMain

_NtClose:
    push 034ECACD1h
    call _WhisperMain

_NtFreeVirtualMemory:
    push 087957DD7h
    call _WhisperMain

