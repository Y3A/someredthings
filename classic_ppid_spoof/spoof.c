#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

DWORD get_pid_from_name(char *name);

#define warn(x) printf("%s : 0x%08X\n", x, GetLastError())

int main(void)
{
    STARTUPINFOEXA                  si = { 0 };
    PROCESS_INFORMATION             pi = { 0 };
    LPPROC_THREAD_ATTRIBUTE_LIST    pl = NULL;
    SIZE_T                          pl_sz;
    DWORD                           explorer_pid;
    HANDLE                          explorer;
    
    explorer_pid = get_pid_from_name(L"explorer.exe");
    if (!explorer_pid) {
        warn("get_pid_from_name fail");
        return 0;
    }

    explorer = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorer_pid);
    if (!explorer) {
        warn("OpenProcess fail");
        return 0;
    }

    InitializeProcThreadAttributeList(NULL, 1, 0, &pl_sz);
    if (!pl_sz) {
        warn("InitializeProcThreadAttributeList fail");
        return 0;
    }

    pl = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, pl_sz);
    if (!pl) {
        warn("HeapAlloc fail");
        return 0;
    }

    if (!InitializeProcThreadAttributeList(pl, 1, 0, &pl_sz)) {
        warn("InitializeProcThreadAttributeList fail");
        return 0;
    }

    if (!UpdateProcThreadAttribute(pl, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &explorer, sizeof(HANDLE), NULL, NULL)) {
        warn("UpdateProcThreadAttributeList fail");
        return 0;
    }
    
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.lpAttributeList = pl;

    // launch new process with different parent
    CreateProcessA(NULL,
        (LPSTR)"notepad.exe",
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi);

    DeleteProcThreadAttributeList(pl);
    HeapFree(GetProcessHeap(), 0, pl);
    CloseHandle(explorer);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}

DWORD get_pid_from_name(char *name)
{
    PROCESSENTRY32  pe;
    HANDLE          snapshot;

    pe.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(snapshot, &pe) == TRUE) {
        while (Process32Next(snapshot, &pe) == TRUE) {
            if (_stricmp(pe.szExeFile, name) == 0) {
                return pe.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}