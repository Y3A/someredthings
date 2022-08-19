#ifndef SRC_H
#define SRC_H

#include <Windows.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define kill(...) return printf(__VA_ARGS__), 0

#define IN
#define OUT
#define OPTIONAL

typedef NTSTATUS (NTAPI *__BCryptOpenAlgorithmProvider) (
    OUT BCRYPT_ALG_HANDLE *phAlgorithm,
    IN  LPCWSTR           pszAlgId,
    IN  LPCWSTR           pszImplementation,
    IN  ULONG             dwFlags
);

typedef NTSTATUS (NTAPI *__BCryptGetProperty) (
    IN  BCRYPT_HANDLE hObject,
    IN  LPCWSTR       pszProperty,
    OUT PUCHAR        pbOutput,
    IN  ULONG         cbOutput,
    OUT ULONG         *pcbResult,
    IN  ULONG         dwFlags
);

typedef NTSTATUS (NTAPI *__BCryptGenerateSymmetricKey) (
    IN OUT        BCRYPT_ALG_HANDLE hAlgorithm,
    OUT           BCRYPT_KEY_HANDLE *phKey,
    OUT OPTIONAL  PUCHAR            pbKeyObject,
    IN            ULONG             cbKeyObject,
    IN            PUCHAR            pbSecret,
    IN            ULONG             cbSecret,
    IN            ULONG             dwFlags
);

typedef NTSTATUS (NTAPI *__BCryptEncrypt) (
    IN OUT            BCRYPT_KEY_HANDLE hKey,
    IN                PUCHAR            pbInput,
    IN                ULONG             cbInput,
    IN OPTIONAL       VOID              *pPaddingInfo,
    IN OUT OPTIONAL   PUCHAR            pbIV,
    IN                ULONG             cbIV,
    OUT OPTIONAL      PUCHAR            pbOutput,
    IN                ULONG             cbOutput,
    OUT               ULONG             *pcbResult,
    IN                ULONG             dwFlags
);

typedef NTSTATUS (NTAPI *__BCryptDecrypt) (
    IN OUT            BCRYPT_KEY_HANDLE hKey,
    IN                PUCHAR            pbInput,
    IN                ULONG             cbInput,
    IN OPTIONAL       VOID              *pPaddingInfo,
    IN OUT OPTIONAL   PUCHAR            pbIV,
    IN                ULONG             cbIV,
    OUT OPTIONAL      PUCHAR            pbOutput,
    IN                ULONG             cbOutput,
    OUT               ULONG             *pcbResult,
    IN                ULONG             dwFlags
);

typedef NTSTATUS (NTAPI *__BCryptDestroyKey) (
    IN OUT BCRYPT_KEY_HANDLE hKey
);

NTSTATUS initialize_funcs(void);
NTSTATUS encrypt(unsigned char *input, size_t input_sz, unsigned char **output, size_t *output_sz);
NTSTATUS decrypt(unsigned char *input, size_t input_sz, unsigned char **output, size_t *output_sz);

#endif