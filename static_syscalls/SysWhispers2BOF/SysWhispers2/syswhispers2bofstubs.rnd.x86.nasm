[SECTION .data align=4]
stubReturn:     dd  0
returnAddress:  dd  0
espBookmark:    dd  0
syscallNumber:  dd  0
syscallAddress: dd  0

[SECTION .text]

BITS 32
DEFAULT REL

global _NtOpenProcess
global _NtAllocateVirtualMemory
global _NtWriteVirtualMemory
global _NtCreateThreadEx
global _NtWaitForSingleObject
global _NtClose
global _NtFreeVirtualMemory

global _WhisperMain
extern _SW2_GetSyscallNumber
extern _SW2_GetRandomSyscallAddress

_WhisperMain:
    pop eax                                  
    mov dword [stubReturn], eax             ; Save the return address to the stub
    push esp
    pop eax
    add eax, 4h
    push dword [eax]
    pop dword [returnAddress]               ; Save original return address
    add eax, 4h
    push eax
    pop dword [espBookmark]                 ; Save original ESP
    call _SW2_GetSyscallNumber              ; Resolve function hash into syscall number
    add esp, 4h                             ; Restore ESP
    mov dword [syscallNumber], eax          ; Save the syscall number
    xor eax, eax
    mov ecx, dword [fs:0c0h]
    test ecx, ecx
    je _x86
    inc eax                                 ; Inc EAX to 1 for Wow64
_x86:
    push eax                                ; Push 0 for x86, 1 for Wow64
    lea edx, dword [esp+4h]
    call _SW2_GetRandomSyscallAddress       ; Get a random 0x02E address
    mov dword [syscallAddress], eax         ; Save the address
    mov esp, dword [espBookmark]            ; Restore ESP
    mov eax, dword [syscallNumber]          ; Restore the syscall number
    call dword [syscallAddress]             ; Call the random syscall location
    mov esp, dword [espBookmark]            ; Restore ESP
    push dword [returnAddress]              ; Restore the return address
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

