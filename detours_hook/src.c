#include <Windows.h>

#include "detours.h"

#define DLLEXPORT __declspec(dllexport)
#pragma comment(lib, "detours.lib")

DLLEXPORT void WINAPI HookDecreaseHitpoints(void);
void GodMode(DWORD unused);

/*
    * Detours hooks functions by replacing the first few bytes of that function
    * with a jmp to our specified new function. These few bytes are copied to our other
    * specified function known as the trampoline function, which is a essentially a saved copy
    * of the original function. The trampoline function contains the first few overwritten bytes
    * of the original function, and a jmp to the offset in the original function after those bytes.
    * In this example I'll hook an arbitrary function called DecreaseHitpoints, simulating a game cheat.
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

DLLEXPORT void WINAPI HookDecreaseHitpoints(void)
{
    const ULONG_PTR offset = 0x1550; // arbitrary offset of the DecreaseHitpoints function from the exe base;
    ULONG_PTR       base = GetModuleHandle(NULL);

    void (*DecreaseHitpoints)(DWORD) = base + offset;
    DetourTransactionBegin(); // initialize a detours transaction
    DetourUpdateThread(GetCurrentThread()); // this is ignored for current thread, but we should do this for other threads if we want to hook them
    DetourAttach(&(PVOID)DecreaseHitpoints, GodMode); // hook function
    DetourTransactionCommit(); // commit transaction!
}

void GodMode(DWORD unused)
{
    const ULONG_PTR g_hp_off = 0x3010; // arbitrary offset of the global hitpoints variable
    ULONG_PTR       base = GetModuleHandle(NULL);

    DWORD *g_hp = (DWORD *)(g_hp_off + base);

    if (*g_hp < 100)
        *g_hp = (DWORD)100;
}

/*
    * testing program
    * you can use my shellcode rdi project to inject :)

#include <stdio.h>

int g_hp = 100;

void DecreaseHitpoints(int by);

void DecreaseHitpoints(int by)
{
	g_hp -= by;
}

int main(void)
{
	printf("[*] Your hitpoints is %d\n", g_hp);
	puts("[-] Monster attacks!");
	getchar();
	DecreaseHitpoints(10);
	printf("[*] Your hitpoints is %d\n", g_hp);
	puts("[-] Monster attacks!");
	getchar();
	DecreaseHitpoints(10);
	printf("[*] Your hitpoints is %d\n", g_hp);
	puts("[-] Monster attacks!");
	getchar();
	DecreaseHitpoints(10);
	printf("[*] Your hitpoints is %d\n", g_hp);
	puts("[-] Monster attacks!");
	getchar();
	DecreaseHitpoints(10);
	printf("[*] Game over, your hitpoints is %d\n", g_hp);
	printf("[*] You %s!\n", g_hp == 100 ? "win" : "lose");
		

	return 0;
}

*/