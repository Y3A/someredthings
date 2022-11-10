#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define warn(x, y) printf("%s : 0x%08X\n", x, y)

#define CMD L"notepad.exe C:\\Users\\User\\Desktop\\recon.txt\0"

typedef struct _PEB64
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB64, *PPEB64;

INT create_notepad(PHANDLE notepad_thread);

typedef NTSTATUS(NTAPI *NQIP) (
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );

int main(void)
{
    PROCESS_BASIC_INFORMATION       pbi = { 0 };
    INT                             notepad_pid;
    HANDLE                          notepad_handle = 0, notepad_thread = 0;
    NTSTATUS                        status;
    NQIP                            NtQueryInformationProcess;
    PPEB64                          peb_data = NULL;
    SIZE_T                          read;
    BOOL                            bstatus;
    PRTL_USER_PROCESS_PARAMETERS    parameter_data = NULL;
    char                            nulls[4] = { 0 };

    NtQueryInformationProcess = (NQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        warn("GetProcAddress fail", GetLastError());
        goto out;
    }

    notepad_pid = create_notepad(&notepad_thread);
    if (notepad_pid < 0) {
        warn("create_notepad fail", -notepad_pid);
        goto out;
    }

    notepad_handle = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE,
        notepad_pid
    );
    if (!notepad_handle) {
        warn("OpenProcess fail", GetLastError());
        goto out;
    }

    status = NtQueryInformationProcess(
        notepad_handle,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL
    );
    if (!NT_SUCCESS(status)) {
        warn("NtQueryInformationProcess fail", status);
        goto out;
    }

    peb_data = HeapAlloc(GetProcessHeap(), 0, sizeof(PEB64));
    if (!peb_data) {
        warn("HeapAlloc fail", GetLastError());
        goto out;
    }

    parameter_data = HeapAlloc(GetProcessHeap(), 0, sizeof(RTL_USER_PROCESS_PARAMETERS));
    if (!parameter_data) {
        warn("HeapAlloc fail", GetLastError());
        goto out;
    }

    bstatus = ReadProcessMemory(notepad_handle, pbi.PebBaseAddress, peb_data, sizeof(PEB64), &read);
    if (!bstatus) {
        warn("ReadProcessMemory fail", GetLastError());
        goto out;
    }

    bstatus = ReadProcessMemory(notepad_handle, peb_data->ProcessParameters, parameter_data, sizeof(RTL_USER_PROCESS_PARAMETERS), &read);
    if (!bstatus) {
        warn("ReadProcessMemory fail", GetLastError());
        goto out;
    }

    // write 0 for UNICODE_STRING.length and max length, since it is not used by loader
    // can fool some apps like process hacker
    bstatus = WriteProcessMemory(notepad_handle, (ULONG_PTR)peb_data->ProcessParameters + (ULONG_PTR)&((PRTL_USER_PROCESS_PARAMETERS)0)->CommandLine, nulls, sizeof(nulls), &read);
    if (!bstatus) {
        warn("WriteProcessMemory fail", GetLastError());
        goto out;
    }

    // write in the changed argument
    // note if the argument is too much longer than the initial dummy argument, will overflow important data and crash
   bstatus = WriteProcessMemory(notepad_handle, parameter_data->CommandLine.Buffer, CMD, wcslen(CMD) * 2 + 2, &read);
   if (!bstatus) {
       warn("WriteProcessMemory fail", GetLastError());
       goto out;
   }

    if (ResumeThread(notepad_thread) < 0)
        warn("ResumeThread fail", GetLastError());

out:
    if (notepad_handle)
        CloseHandle(notepad_handle);
    if (notepad_thread)
        CloseHandle(notepad_thread);
    if (peb_data)
        HeapFree(GetProcessHeap(), 0, peb_data);
    return 0;
}

INT create_notepad(PHANDLE notepad_thread)
{
    char                    appl[] = "C:\\Windows\\System32\\notepad.exe";
    char                    cmdl[] = "notepad.exe C:\\Windows\\System32\\kernel32.dll";
    char                    startup[] = "C:\\Windows\\System32\\";
    STARTUPINFOA            si = { 0 };
    PROCESS_INFORMATION     pi = { 0 };
    BOOL                    res;

    si.cb = sizeof(STARTUPINFOA);

    res = CreateProcessA(
        appl, cmdl, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, startup,
        &si, &pi
    );

    if (!res) {
        puts("[-] Create notepad fail.");
        return -(INT)GetLastError();
    }

    CloseHandle(pi.hProcess);

    *notepad_thread = pi.hThread;

    return pi.dwProcessId;
}