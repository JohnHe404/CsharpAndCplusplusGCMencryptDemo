#pragma once
#include <iostream>
#include <vector>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <Windows.h> // <- Added this
#include <bcrypt.h>
#pragma comment (lib, "bcrypt.lib")
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
//https://docs.microsoft.com/en-us/windows/win32/seccng/encrypting-data-with-cng
int gcm_encrypt_Second(unsigned char* plaintext, int plaintext_len,
    unsigned char* nonce, int nonce_len,
    unsigned char* key,
    int key_len,
    //const unsigned char* iv, int iv_len,
    unsigned char* ciphertext,
    unsigned char* tag, int tag_len)
{
    NTSTATUS bcryptResult = 0;
    DWORD bytesDone = 0;
    NTSTATUS status = 0;
    BCRYPT_ALG_HANDLE algHandle = 0;
    bcryptResult = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_AES_ALGORITHM, 0, 0);
    if (!BCRYPT_SUCCESS(bcryptResult))
        return -1;

    bcryptResult = BCryptSetProperty(algHandle, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(bcryptResult))
        return -1;

    BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
    bcryptResult = BCryptGetProperty(algHandle, BCRYPT_AUTH_TAG_LENGTH, (BYTE*)&authTagLengths, sizeof(authTagLengths), &bytesDone, 0);
    if (!BCRYPT_SUCCESS(bcryptResult))
        return -1;

    DWORD blockLength = 0;
    bcryptResult = BCryptGetProperty(algHandle, BCRYPT_BLOCK_LENGTH, (BYTE*)&blockLength, sizeof(blockLength), &bytesDone, 0);
    if (!BCRYPT_SUCCESS(bcryptResult))
        return -1;

    BCRYPT_KEY_HANDLE keyHandle = 0;

    bcryptResult = BCryptGenerateSymmetricKey(algHandle, &keyHandle, 0, 0, key, key_len, 0);
    if (!BCRYPT_SUCCESS(bcryptResult))
        return -1;
    ULONG cbBlob;
    if (!NT_SUCCESS(status = BCryptExportKey(
        keyHandle,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        NULL,
        0,
        &cbBlob,
        0)))
        return -1;
    
    PBYTE pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    if (!NT_SUCCESS(status = BCryptExportKey(
        keyHandle,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        pbBlob,
        cbBlob,
        &cbBlob,
        0)))
        return -1;

    bcryptResult = BCryptImportKey(algHandle, NULL, BCRYPT_KEY_DATA_BLOB, &keyHandle, NULL, 0, pbBlob, cbBlob, 0);
    if (!BCRYPT_SUCCESS(bcryptResult))
        return -1;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = nonce_len;
    authInfo.pbTag = tag;
    authInfo.cbTag = tag_len;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    ULONG result_len = 0;
    status = BCryptEncrypt(keyHandle, plaintext, plaintext_len, &authInfo, NULL, 0, ciphertext, plaintext_len, &result_len, 0);
    if (NT_SUCCESS(status))
        return 1;

    return -1;
}

//int gcm_decrypt(const unsigned char* ciphertext, int ciphertext_len,
//    unsigned char* aad, int aad_len,
//    unsigned char* tag,
//    unsigned char* key,
//    const unsigned char* iv, int iv_len,
//    unsigned char* plaintext)
//{
//    BCryptDecrypt();
//}