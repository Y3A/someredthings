#include <Windows.h>
#include <stdio.h>

extern void invoke_dotnet(void);

int main(void)
{
    DWORD old;
    LPVOID addr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    VirtualProtect(addr, 0x1000, PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
    VirtualProtect(addr, 0x1000, PAGE_EXECUTE_READ, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, 0x1000);

    invoke_dotnet();

    return 0;
}