#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#pragma warning(disable : 4996)

void get_protection(void);

int main(void)
{
    get_protection();
    return 0;
}

void get_protection(void)
{
    HANDLE                                      snapshot;
    PROCESSENTRY32                              entry = { 0 };
    HANDLE                                      hProc;
    PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY p;
    BOOL                                        status;

    entry.dwSize = sizeof(PROCESSENTRY32);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        puts("[-] Snapshot fail.");
        return 0;
    }

    while (Process32Next(snapshot, &entry)) {
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
        if (!hProc)
            continue;

        status = GetProcessMitigationPolicy(hProc, ProcessRedirectionTrustPolicy, &p, sizeof(p));
        if (status)
            wprintf(L"%s -- Audit: %d , Enforce: %d\n", entry.szExeFile, p.AuditRedirectionTrust, p.EnforceRedirectionTrust);
        CloseHandle(hProc);
    }

    CloseHandle(snapshot);
    return;
}