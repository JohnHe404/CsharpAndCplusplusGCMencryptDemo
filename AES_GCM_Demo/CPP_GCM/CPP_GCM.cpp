// CPP_GCM.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#include "GCM_01.h"
#include <sstream>
using namespace std;
int gcm_encrypt(const unsigned char* plaintext, int plaintext_len,
    unsigned char* aad, int aad_len,
    unsigned char* key,
    const unsigned char* iv, int iv_len,
    unsigned char* ciphertext,
    unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        return -1;

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return -1;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
int gcm_decrypt(const unsigned char* ciphertext, int ciphertext_len,
    unsigned char* aad, int aad_len,
    unsigned char* tag,
    unsigned char* key,
    const unsigned char* iv, int iv_len,
    unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        return -1;

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        return -1;

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else {
        /* Verify failed */
        return -1;
    }
}

shared_ptr<vector<unsigned char>> InputToBytes(string& input)
{
    auto result = make_shared<vector<unsigned char>>(input.length());
    unique_ptr<vector<char>> temp = make_unique<vector<char>>(input.length() + 1);
    strncpy_s(temp->data(), temp->size(), input.c_str(), input.length());

    char* p = strtok(temp->data(), "-");   //strtok() func. with delimeter " "
    int i = 0;
    while (p)
    {
        //cout << p << endl;     //printing each token
        unsigned int val;
        //std::istringstream str(p);
        std::stringstream str;
        str << std::hex << p;
       // string str(p);
       // val = stoi(p);
        if (!(str >> val))
        {
            throw runtime_error("get input byte error");
        }
        result->at(i++) = val;
        cout << hex << val << "-";
        p = strtok(NULL, "-");
    }
    result->resize(i);
    cout << endl;
    return result;
}
void ShowBytes(shared_ptr<vector<unsigned char>> bytes)
{
    for (auto start = bytes->begin(); start != bytes->end(); ++start)
    {
        cout << hex << (int)(*start) << "-";
    }
    cout << endl;
}
void ShowBytes(vector<unsigned char>& bytes)
{
    for (auto start = bytes.begin(); start != bytes.end(); ++start)
    {
        cout << hex << (int)(*start) << "-";
    }
    cout << endl;
}
int main()
{
    char text[] = "This is Test Message 01\n";
    vector<unsigned char> EncryptData(strnlen(text, 1000));
    vector<unsigned char>  DecryptData(strnlen(text, 1000));
    unsigned char tagData[16] = { 0 };

    string inputStr;
    cout << "Please input key" << endl;
    cin >> inputStr;
    auto key = InputToBytes(inputStr);
    ShowBytes(key);
    cout << "Please input nonceBytes" << endl;
    cin >> inputStr;
    auto nonceBytes = InputToBytes(inputStr);
    ShowBytes(nonceBytes);

    cout << "Please input timeBytes" << endl;
    cin >> inputStr;
    auto timeBytes = InputToBytes(inputStr);
    ShowBytes(timeBytes);

    int result = gcm_encrypt(
        reinterpret_cast<const unsigned char*>(text),
        (int)(strnlen(text, 1000)),
        timeBytes->data(),
        timeBytes->size(),
        key->data(),
        nonceBytes->data(),
        nonceBytes->size(),
        EncryptData.data(),
        tagData
    );

    if (result == -1)
    {
        cout << "failed gcm_encrypt" << endl;
        return 0;
    }
    ShowBytes(EncryptData);

    gcm_decrypt(
        EncryptData.data(),
        (int)(strnlen(text, 1000)),
        timeBytes->data(),
        timeBytes->size(),
        tagData,
        key->data(),
        nonceBytes->data(),
        nonceBytes->size(),
        DecryptData.data()
    );
    if (result == -1)
    {
        cout << "failed gcm_decrypt" << endl;
        return 0;
    }
    ShowBytes(DecryptData);
    string lastMessage(reinterpret_cast<char *>(DecryptData.data()));

    cout << lastMessage << endl;
    cin.ignore();
}
//int main()
int Testmain()
{
    std::cout << "Start test c++ openssl ase gcm!\n";
    static const unsigned char gcm_iv_First[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
    };
    static const unsigned char gcm_iv_Second[] = {
    0x98, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
    };
    char password[] = "18EB38984D82477B992F3F6BF27E8B67";
    char text[] = "This is Test Message 01\n";
    unsigned char tagData[16] = { 0 };
    char* EncryptData = new char[strnlen(text, 1000)];
    char* DecryptData = new char[strnlen(text, 1000)];
    unsigned char nonceBytes[12] = { 0 };
   //vector<unsigned char> nonceBytes(12);
    cout << text << endl;
    strncpy(reinterpret_cast<char *>(nonceBytes), password, 12);

    //int result = gcm_encrypt_Second(
    //    reinterpret_cast<unsigned char*>(text),
    //    (int)(strnlen(text, 1000)),
    //    nonceBytes,
    //    12,
    //    reinterpret_cast<unsigned char*>(password),
    //    strnlen(password, 1000),
    //    reinterpret_cast<unsigned char*>(EncryptData),
    //    tagData,
    //    16
    //    );
    int result = gcm_encrypt(
        reinterpret_cast<const unsigned char*>(text),  
        (int)(strnlen(text, 1000)),
        nonceBytes,
        //12,
        sizeof(nonceBytes),
        reinterpret_cast<unsigned char*>(password),
        gcm_iv_First,
        sizeof(gcm_iv_First),
        reinterpret_cast<unsigned char*>(EncryptData),
        tagData
        );

    if (result == -1)
    {
        cout << "failed gcm_encrypt" << endl;
        return 0;
    }

    gcm_decrypt(
        reinterpret_cast<unsigned char*>(EncryptData),
        (int)(strnlen(text, 1000)),
        nonceBytes,
        12,
        tagData,
        reinterpret_cast<unsigned char*>(password),
        gcm_iv_First,
        sizeof(gcm_iv_First),
        //gcm_iv_Second,
        //sizeof(gcm_iv_Second),
        reinterpret_cast<unsigned char*>(DecryptData)
        );
    if (result == -1)
    {
        cout << "failed gcm_decrypt" << endl;
        return 0;
    }
    cout << EncryptData << endl;
    cout << DecryptData << endl;

    delete[] EncryptData;
    delete[] DecryptData;

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
