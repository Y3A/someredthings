#ifndef REF_LDR_H
#define REF_LDR_H

#define DLLEXPORT __declspec(dllexport)

#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

typedef struct _IMAGE_RELOC
{
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING, **PPUNICODE_STRING;

typedef NTSTATUS (NTAPI *LLD) (
	IN OPTIONAL PWSTR DllPath,
	IN OPTIONAL PULONG DllCharacteristics,
	IN PUNICODE_STRING DllName,
	OUT PVOID *DllHandle
);

typedef NTSTATUS (NTAPI *NAVM) (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

typedef NTSTATUS (NTAPI *NPVM) (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

typedef NTSTATUS (NTAPI *NFVM) (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
);

typedef struct
{

    LLD LdrLoadDll;
    NAVM NtAllocateVirtualMemory;
    NPVM NtProtectVirtualMemory;

} _NtFuncs;

typedef struct
{

    PVOID *OldBase;
    NFVM NtFreeVirtualMemory;

} _EntryArgs, *_PEntryArgs;

#define LDRLOADDLL_HASH                  0x84901F412C0870A3
#define NTALLOCATEVIRTUALMEMORY_HASH     0x36AF31F19C8C98CC
#define NTPROTECTVIRTUALMEMORY_HASH      0xE6AD30B9A58C1CCF
#define NTFREEVIRTUALMEMORY_HASH         0x465830E1950B84CA

HMODULE _GetBase(void);
UINT64 _GetHash(char *name);
UINT64 _GetModuleHandle(wchar_t *name);
UINT64 _GetProcAddress(ULONG_PTR module_base, UINT64 hash);
SIZE_T CharStringToWCharString(PWCHAR Dest, PCHAR Src, SIZE_T MaximumAllowed);
SIZE_T StringLengthW(LPCWSTR String);
void *_memcpy(void *dest, const void *src, size_t len);
void *_memset(void *dest, int val, size_t len);

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(void);

#endif