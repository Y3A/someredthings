#include <Windows.h>
#include <DbgHelp.h>

#define DLLEXPORT __declspec(dllexport)

void WINAPI HookIAT(const char *dllname, const char *functionname, const ULONG_PTR newfunc_addr);
void DLLEXPORT HookMessageBox(void);
int HijackedBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

/*
    * This just replaces the IAT thunk entry(already resolved address) of an imported function
    * with the address of our desired function.
    * In this example I hook MessageBoxA and change the caption.
*/

int (*OrigMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) = MessageBoxA;

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
    HookIAT("User32.dll", "MessageBoxA", HijackedBox);
}

void WINAPI HookIAT(const char *dllname, const char *functionname, const ULONG_PTR newfunc_addr)
{
    HMODULE                         pebase = NULL;
    PIMAGE_IMPORT_DESCRIPTOR        desc = NULL;
    ULONG                           sz = 0;
    char                            *import_name = NULL;
    ULONG_PTR                       origfunc_addr, cur;
    PIMAGE_THUNK_DATA               thunk = NULL;
    DWORD                           oldprot;

    pebase = GetModuleHandle(NULL);
    /*
        * Resolve this function from DbgHelp.dll
        * And get the first entry of the image import descriptor
    */
    PVOID (WINAPI *ImageDirectoryEntryToDataEx)(PVOID, BOOLEAN, USHORT, PULONG, PIMAGE_SECTION_HEADER *) = (PVOID(WINAPI *)(PVOID, BOOLEAN, USHORT, PULONG, PIMAGE_SECTION_HEADER *))GetProcAddress(LoadLibraryA("DbgHelp.dll"), "ImageDirectoryEntryToDataEx");
    desc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(pebase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &sz, NULL);
    
    for (int i = 0; i < sz; i++) {
        import_name = (char *)((UINT64)pebase + (UINT64)(desc[i].Name));
        if (_stricmp(import_name, dllname) == 0) { // cmp name until we find the dll
            origfunc_addr = (ULONG_PTR)GetProcAddress(GetModuleHandleA(dllname), functionname);
            thunk = (char *)((UINT64)pebase + (UINT64)(desc[i].FirstThunk)); // parse dll's imports, compare to find the function we want
            while (thunk->u1.Function) {
                cur = (ULONG_PTR)&(thunk->u1.Function);
                if (*(ULONG_PTR *)cur == origfunc_addr) {
                    VirtualProtect((LPVOID)cur, 0x1000, PAGE_READWRITE, &oldprot);
                    // set the hook
                    *(ULONG_PTR *)cur = (ULONG_PTR)newfunc_addr;
                    // revert protection setting back
                    VirtualProtect((LPVOID)cur, 0x1000, oldprot, &oldprot);
                    return;
                }
                thunk++;
            }
        }
    }

}

int HijackedBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    return OrigMessageBoxA(hWnd, lpText, "pwned", uType);
}