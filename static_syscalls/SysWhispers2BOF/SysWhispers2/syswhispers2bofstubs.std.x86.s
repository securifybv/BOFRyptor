.intel_syntax noprefix

.text
.global _NtOpenProcess
.global _NtAllocateVirtualMemory
.global _NtWriteVirtualMemory
.global _NtCreateThreadEx
.global _NtWaitForSingleObject
.global _NtClose
.global _NtFreeVirtualMemory

.global _WhisperMain

_WhisperMain:
    pop eax                        # Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     # Resolve function hash into syscall number
    add esp, 4                     # Restore ESP
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    jne _wow64
    lea edx, dword ptr [esp+0x04]
    INT 0x02e
    ret
_wow64:
    xor ecx, ecx
    lea edx, dword ptr [esp+0x04]
    call dword ptr fs:0xc0
    ret

_NtOpenProcess:
    push 0x633B2AE6
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0x0B901715
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0xF75FEFCF
    call _WhisperMain

_NtCreateThreadEx:
    push 0x74AF4416
    call _WhisperMain

_NtWaitForSingleObject:
    push 0x26BA3C17
    call _WhisperMain

_NtClose:
    push 0x34ECACD1
    call _WhisperMain

_NtFreeVirtualMemory:
    push 0x87957DD7
    call _WhisperMain

