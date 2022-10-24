#include <Windows.h>

#define DLLEXPORT __declspec(dllexport)

void WINAPI HookFunction(const ULONG_PTR origfunc_addr, const ULONG_PTR newfunc_addr);
void DLLEXPORT HookMessageBox(void);
int HijackedBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

char g_orig_bytes[14];

/*
    * Replaces the first few bytes with a jmp
    * to our rogue function
*/

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

void DLLEXPORT HookMessageBox(void)
{
    HookFunction(&MessageBoxA, &HijackedBox);
}

void WINAPI HookFunction(const ULONG_PTR origfunc_addr, const ULONG_PTR newfunc_addr)
{
    DWORD out;

    // src: https://www.ragestorm.net/blogs/?p=107
    // create a patch <14 bytes> with JMP [RIP+0]; <ADDR64>
    // \xFF\x25\x00\x00\x00\x00
    // \x00\x11\x22\x33\x44\0x55\x66\x77

    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)MessageBoxA, g_orig_bytes, sizeof(g_orig_bytes), &out);
    char patch[14] = { 0 };
    memcpy(patch, "\xFF\x25", 2);
    *(PULONG_PTR)(patch + 6) = newfunc_addr;
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)MessageBoxA, patch, sizeof(patch), &out);

    return;
}

int HijackedBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    DWORD out;
    int ret;

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)MessageBoxA, g_orig_bytes, sizeof(g_orig_bytes), &out);
    ret = MessageBoxA(hWnd, lpText, "pwned", uType);
    HookMessageBox(&MessageBoxA, &HijackedBox);

    return ret;
}