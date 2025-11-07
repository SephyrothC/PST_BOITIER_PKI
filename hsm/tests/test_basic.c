/*
 * Basic PKCS#11 Library Test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11/pkcs11.h"

#define CHECK_RV(func, rv) do { \
    if ((rv) != CKR_OK) { \
        fprintf(stderr, "ERROR: %s failed with code 0x%08lX\n", (func), (unsigned long)(rv)); \
        return 1; \
    } else { \
        printf("SUCCESS: %s\n", (func)); \
    } \
} while(0)

int main(void)
{
    CK_RV rv;
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_SLOT_ID slotID = 0;
    CK_SESSION_HANDLE hSession;
    CK_INFO info;
    CK_TOKEN_INFO tokenInfo;

    printf("===========================================\n");
    printf("PST HSM PKCS#11 Library - Basic Test\n");
    printf("===========================================\n\n");

    /* Get function list */
    printf("1. Getting function list...\n");
    rv = C_GetFunctionList(&pFunctionList);
    CHECK_RV("C_GetFunctionList", rv);

    /* Initialize library */
    printf("\n2. Initializing Cryptoki...\n");
    rv = pFunctionList->C_Initialize(NULL);
    CHECK_RV("C_Initialize", rv);

    /* Get library info */
    printf("\n3. Getting library information...\n");
    rv = pFunctionList->C_GetInfo(&info);
    CHECK_RV("C_GetInfo", rv);

    printf("   Cryptoki Version: %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    printf("   Manufacturer ID: %.32s\n", info.manufacturerID);
    printf("   Library Description: %.32s\n", info.libraryDescription);
    printf("   Library Version: %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);

    /* Get slot list */
    printf("\n4. Getting slot list...\n");
    CK_ULONG slotCount;
    rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL, &slotCount);
    CHECK_RV("C_GetSlotList", rv);
    printf("   Number of slots: %lu\n", (unsigned long)slotCount);

    CK_SLOT_ID slots[10];
    CK_ULONG count = 10;
    rv = pFunctionList->C_GetSlotList(CK_FALSE, slots, &count);
    CHECK_RV("C_GetSlotList (with buffer)", rv);

    /* Initialize token */
    printf("\n5. Initializing token...\n");
    CK_UTF8CHAR soPin[] = "1234567890";
    CK_UTF8CHAR label[] = "PST HSM Token";
    rv = pFunctionList->C_InitToken(slotID, soPin, sizeof(soPin) - 1, label);
    CHECK_RV("C_InitToken", rv);

    /* Get token info */
    printf("\n6. Getting token information...\n");
    rv = pFunctionList->C_GetTokenInfo(slotID, &tokenInfo);
    CHECK_RV("C_GetTokenInfo", rv);

    printf("   Token Label: %.32s\n", tokenInfo.label);
    printf("   Manufacturer ID: %.32s\n", tokenInfo.manufacturerID);
    printf("   Model: %.16s\n", tokenInfo.model);
    printf("   Serial Number: %.16s\n", tokenInfo.serialNumber);

    /* Get mechanism list */
    printf("\n7. Getting mechanism list...\n");
    CK_ULONG mechCount;
    rv = pFunctionList->C_GetMechanismList(slotID, NULL, &mechCount);
    CHECK_RV("C_GetMechanismList", rv);
    printf("   Number of mechanisms: %lu\n", (unsigned long)mechCount);

    /* Open session */
    printf("\n8. Opening session...\n");
    rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                      NULL, NULL, &hSession);
    CHECK_RV("C_OpenSession", rv);
    printf("   Session handle: 0x%08lX\n", (unsigned long)hSession);

    /* Initialize user PIN */
    printf("\n9. Initializing user PIN...\n");
    rv = pFunctionList->C_Login(hSession, CKU_SO, soPin, sizeof(soPin) - 1);
    CHECK_RV("C_Login (SO)", rv);

    CK_UTF8CHAR userPin[] = "user1234";
    rv = pFunctionList->C_InitPIN(hSession, userPin, sizeof(userPin) - 1);
    CHECK_RV("C_InitPIN", rv);

    rv = pFunctionList->C_Logout(hSession);
    CHECK_RV("C_Logout", rv);

    /* Login as user */
    printf("\n10. Logging in as user...\n");
    rv = pFunctionList->C_Login(hSession, CKU_USER, userPin, sizeof(userPin) - 1);
    CHECK_RV("C_Login (USER)", rv);

    /* Generate RSA key pair */
    printf("\n11. Generating RSA-2048 key pair...\n");

    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};  /* 65537 */

    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_ENCRYPT, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL)},
        {CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
        {CKA_WRAP, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
        {CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
        {CKA_LABEL, "Test RSA Public Key", 19}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_DECRYPT, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL)},
        {CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
        {CKA_UNWRAP, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL)},
        {CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL)},
        {CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
        {CKA_PRIVATE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
        {CKA_LABEL, "Test RSA Private Key", 20}
    };

    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;

    rv = pFunctionList->C_GenerateKeyPair(
        hSession,
        &mechanism,
        publicKeyTemplate, sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
        privateKeyTemplate, sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
        &hPublicKey,
        &hPrivateKey
    );
    CHECK_RV("C_GenerateKeyPair", rv);

    printf("   Public key handle:  0x%08lX\n", (unsigned long)hPublicKey);
    printf("   Private key handle: 0x%08lX\n", (unsigned long)hPrivateKey);

    /* Sign some data */
    printf("\n12. Signing test data...\n");

    CK_MECHANISM signMechanism = {CKM_SHA256_RSA_PKCS, NULL, 0};
    CK_BYTE data[] = "Hello, PST HSM!";
    CK_BYTE signature[512];
    CK_ULONG signatureLen = sizeof(signature);

    rv = pFunctionList->C_SignInit(hSession, &signMechanism, hPrivateKey);
    CHECK_RV("C_SignInit", rv);

    rv = pFunctionList->C_Sign(hSession, data, sizeof(data) - 1, signature, &signatureLen);
    CHECK_RV("C_Sign", rv);

    printf("   Data: %s\n", data);
    printf("   Signature length: %lu bytes\n", (unsigned long)signatureLen);
    printf("   Signature (first 32 bytes): ");
    for (CK_ULONG i = 0; i < 32 && i < signatureLen; i++) {
        printf("%02X", signature[i]);
    }
    printf("...\n");

    /* Generate random data */
    printf("\n13. Generating random data...\n");
    CK_BYTE randomData[32];
    rv = pFunctionList->C_GenerateRandom(hSession, randomData, sizeof(randomData));
    CHECK_RV("C_GenerateRandom", rv);

    printf("   Random data: ");
    for (size_t i = 0; i < sizeof(randomData); i++) {
        printf("%02X", randomData[i]);
    }
    printf("\n");

    /* Cleanup */
    printf("\n14. Cleaning up...\n");

    rv = pFunctionList->C_Logout(hSession);
    CHECK_RV("C_Logout", rv);

    rv = pFunctionList->C_CloseSession(hSession);
    CHECK_RV("C_CloseSession", rv);

    rv = pFunctionList->C_Finalize(NULL);
    CHECK_RV("C_Finalize", rv);

    printf("\n===========================================\n");
    printf("All tests completed successfully!\n");
    printf("===========================================\n");

    return 0;
}
