#include <Windows.h>

UINT64 _GetHash(const char *name);
UINT64 _GetModuleHandle(const wchar_t *name);
UINT64 _GetProcAddress(UINT64 module_base, UINT64 hash);

typedef HMODULE(*LLA)(LPCSTR lpLibFileName);
typedef int(*MBA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

int main(void)
{
    UINT64 kernel32_base =  _GetModuleHandle(TEXT("KERNEL32.DLL"));
    LLA _LoadLibraryA = _GetProcAddress(kernel32_base, _GetHash("LoadLibraryA"));
    HMODULE user32_base = _LoadLibraryA("user32.dll");
    if (!user32_base)
        return 1;
    MBA _MessageBoxA = _GetProcAddress(user32_base, _GetHash("MessageBoxA"));
    _MessageBoxA(NULL, "Message Box From No Imports!", NULL, MB_OK);
    return 0;
}