#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>

#include "src.h"

const unsigned char key[] =
{
    0x91, 0x98, 0x22, 0x07, 0x50, 0x55, 0x06, 0xF2,
    0x6F, 0xF6, 0x21, 0xB1, 0xD2, 0xD0, 0xEE, 0x37
};

__BCryptOpenAlgorithmProvider _BCryptOpenAlgorithmProvider = NULL;
__BCryptGetProperty _BCryptGetProperty = NULL;
__BCryptGenerateSymmetricKey _BCryptGenerateSymmetricKey = NULL;
__BCryptEncrypt _BCryptEncrypt = NULL;
__BCryptDecrypt _BCryptDecrypt = NULL;
__BCryptDestroyKey _BCryptDestroyKey = NULL;

NTSTATUS initialize_funcs(void)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HMODULE  bcrypt = NULL;

    bcrypt = LoadLibraryA("bcrypt.dll");
    if (!bcrypt)
        goto out;

    _BCryptOpenAlgorithmProvider = GetProcAddress(bcrypt, "BCryptOpenAlgorithmProvider");
    _BCryptGetProperty = GetProcAddress(bcrypt, "BCryptGetProperty");
    _BCryptGenerateSymmetricKey = GetProcAddress(bcrypt, "BCryptGenerateSymmetricKey");
    _BCryptEncrypt = GetProcAddress(bcrypt, "BCryptEncrypt");
    _BCryptDecrypt = GetProcAddress(bcrypt, "BCryptDecrypt");
    _BCryptDestroyKey = GetProcAddress(bcrypt, "BCryptDestroyKey");

    if (!_BCryptOpenAlgorithmProvider || !_BCryptGetProperty || !_BCryptGenerateSymmetricKey
        || !_BCryptEncrypt || !_BCryptDecrypt || !_BCryptDestroyKey)
        goto out;

    status = STATUS_SUCCESS;

out:
    return status;
}

NTSTATUS encrypt(unsigned char *input, size_t input_sz, unsigned char **output, size_t *output_sz)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE   algo;
    BCRYPT_KEY_HANDLE   hkey;
    DWORD               sz = 0;
    ULONG               api_out;
    unsigned char       *real_key = NULL, *temp_output = NULL;
    
    // Open an algorithm handle.
    if (!NT_SUCCESS(status = _BCryptOpenAlgorithmProvider(&algo, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto out;

    // Get size of key to allocate
    if (!NT_SUCCESS(_BCryptGetProperty(algo, BCRYPT_OBJECT_LENGTH, &sz, sizeof(sz), &api_out, 0)));

    real_key = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    if (!real_key)
        goto out;

    // Generate key object
    if (!NT_SUCCESS(_BCryptGenerateSymmetricKey(algo, &hkey, real_key, sz, key, sizeof(key), 0)))
        goto out;

    // Get size of ciphertext to allocate
    if (!NT_SUCCESS(_BCryptEncrypt(hkey, input, input_sz, NULL, NULL, 0, NULL, 0, &api_out, BCRYPT_BLOCK_PADDING)))
        goto out;

    temp_output = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, api_out);
    if (!temp_output)
        goto out;

    // Encrypt plaintext
    if (!NT_SUCCESS(_BCryptEncrypt(hkey, input, input_sz, NULL, NULL, 0, temp_output, api_out, &api_out, BCRYPT_BLOCK_PADDING)))
        goto out;

    status = STATUS_SUCCESS;
    *output = temp_output;
    *output_sz = api_out;

    _BCryptDestroyKey(hkey);

out:
    if (real_key)
        HeapFree(GetProcessHeap(), 0, real_key);

    if (temp_output && !NT_SUCCESS(status))
        HeapFree(GetProcessHeap(), 0, temp_output);

    return status;
}

NTSTATUS decrypt(unsigned char *input, size_t input_sz, unsigned char **output, size_t *output_sz)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE   algo;
    BCRYPT_KEY_HANDLE   hkey;
    DWORD               sz = 0;
    ULONG               api_out;
    unsigned char       *real_key = NULL, *temp_output = NULL;

    // Open an algorithm handle.
    if (!NT_SUCCESS(status = _BCryptOpenAlgorithmProvider(&algo, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto out;

    // Get size of key to allocate
    if (!NT_SUCCESS(_BCryptGetProperty(algo, BCRYPT_OBJECT_LENGTH, &sz, sizeof(sz), &api_out, 0)));

    real_key = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    if (!real_key)
        goto out;

    // Generate key object
    if (!NT_SUCCESS(_BCryptGenerateSymmetricKey(algo, &hkey, real_key, sz, key, sizeof(key), 0)))
        goto out;

    // Get size of plaintext to allocate
    if (!NT_SUCCESS(_BCryptDecrypt(hkey, input, input_sz, NULL, NULL, 0, NULL, 0, &api_out, BCRYPT_BLOCK_PADDING)))
        goto out;

    temp_output = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, api_out);
    if (!temp_output)
        goto out;

    // Decrypt ciphertext
    if (!NT_SUCCESS(_BCryptDecrypt(hkey, input, input_sz, NULL, NULL, 0, temp_output, api_out, &api_out, BCRYPT_BLOCK_PADDING)))
        goto out;

    status = STATUS_SUCCESS;
    *output = temp_output;
    *output_sz = api_out;

    _BCryptDestroyKey(hkey);

out:
    if (real_key)
        HeapFree(GetProcessHeap(), 0, real_key);

    if (temp_output && !NT_SUCCESS(status))
        HeapFree(GetProcessHeap(), 0, temp_output);

    return status;
}

int main(void)
{
    unsigned char plaintext[] = "This is a secure and important message. Must be encrypted!";
    unsigned char *output;
    ULONG sz;

    if (!NT_SUCCESS(initialize_funcs()))
        kill("[-] Initialize functions fail.");

    if (!NT_SUCCESS(encrypt(plaintext, sizeof(plaintext), &output, &sz)))
        kill("[-] Encryption fail.");

    for (int i = 0; i < sz; i++)
        printf("0x%x\n", output[i]);

    if (!NT_SUCCESS(decrypt(output, sz, &output, &sz)))
        kill("[-] Decryption fail.");

    printf("%s\n", output);

    return 0;
}