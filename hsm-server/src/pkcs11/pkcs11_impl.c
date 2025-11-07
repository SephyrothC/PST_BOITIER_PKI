/*
 * PKCS#11 Implementation - Main Functions
 *
 * This file implements the core PKCS#11 Cryptoki API
 */

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

/* Global HSM context */
hsm_context_t g_hsm_context = {
    .initialized = false,
    .global_lock = PTHREAD_MUTEX_INITIALIZER,
    .slots = NULL,
    .slot_count = 0,
    .max_sessions = HSM_MAX_SESSIONS,
    .max_objects = HSM_MAX_OBJECTS,
    .enforce_timeouts = true,
    .session_timeout = HSM_SESSION_TIMEOUT,
    .log_func = NULL
};

/* Static function list */
static CK_FUNCTION_LIST functionList;

/*
 * C_Initialize - Initialize the Cryptoki library
 */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
    CK_RV rv;

    hsm_log(HSM_LOG_INFO, "C_Initialize called");

    HSM_LOCK(g_hsm_context.global_lock);

    if (g_hsm_context.initialized) {
        HSM_UNLOCK(g_hsm_context.global_lock);
        hsm_log(HSM_LOG_ERROR, "Cryptoki already initialized");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    /* Initialize context */
    rv = hsm_init_context();
    if (rv != CKR_OK) {
        HSM_UNLOCK(g_hsm_context.global_lock);
        hsm_log(HSM_LOG_ERROR, "Failed to initialize HSM context");
        return rv;
    }

    /* Initialize storage */
    rv = hsm_storage_init();
    if (rv != CKR_OK) {
        hsm_cleanup_context();
        HSM_UNLOCK(g_hsm_context.global_lock);
        hsm_log(HSM_LOG_ERROR, "Failed to initialize storage");
        return rv;
    }

    /* Create default slot (slot 0) */
    g_hsm_context.slot_count = 1;
    g_hsm_context.slots = calloc(1, sizeof(hsm_slot_t));
    if (!g_hsm_context.slots) {
        hsm_cleanup_context();
        HSM_UNLOCK(g_hsm_context.global_lock);
        return CKR_HOST_MEMORY;
    }

    rv = hsm_init_slot(0);
    if (rv != CKR_OK) {
        free(g_hsm_context.slots);
        g_hsm_context.slots = NULL;
        hsm_cleanup_context();
        HSM_UNLOCK(g_hsm_context.global_lock);
        hsm_log(HSM_LOG_ERROR, "Failed to initialize slot 0");
        return rv;
    }

    g_hsm_context.initialized = true;

    HSM_UNLOCK(g_hsm_context.global_lock);

    hsm_log(HSM_LOG_INFO, "Cryptoki initialized successfully");
    return CKR_OK;
}

/*
 * C_Finalize - Cleanup and shut down the Cryptoki library
 */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    hsm_log(HSM_LOG_INFO, "C_Finalize called");

    if (pReserved != NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    HSM_LOCK(g_hsm_context.global_lock);

    if (!g_hsm_context.initialized) {
        HSM_UNLOCK(g_hsm_context.global_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    /* Cleanup all slots */
    for (uint32_t i = 0; i < g_hsm_context.slot_count; i++) {
        hsm_cleanup_slot(i);
    }

    if (g_hsm_context.slots) {
        free(g_hsm_context.slots);
        g_hsm_context.slots = NULL;
    }

    g_hsm_context.slot_count = 0;
    g_hsm_context.initialized = false;

    HSM_UNLOCK(g_hsm_context.global_lock);

    hsm_log(HSM_LOG_INFO, "Cryptoki finalized successfully");
    return CKR_OK;
}

/*
 * C_GetInfo - Get general information about Cryptoki
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    memset(pInfo, 0, sizeof(CK_INFO));

    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;

    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, "PST Cryptographic Systems",
           strlen("PST Cryptographic Systems"));

    pInfo->flags = 0;

    memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
    memcpy(pInfo->libraryDescription, "PST HSM PKCS#11 Library",
           strlen("PST HSM PKCS#11 Library"));

    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;

    return CKR_OK;
}

/*
 * C_GetFunctionList - Get function pointer list
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(struct CK_FUNCTION_LIST **ppFunctionList)
{
    if (ppFunctionList == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    /* Initialize function list if not already done */
    static bool initialized = false;
    if (!initialized) {
        functionList.version.major = 2;
        functionList.version.minor = 40;

        functionList.C_Initialize = C_Initialize;
        functionList.C_Finalize = C_Finalize;
        functionList.C_GetInfo = C_GetInfo;
        functionList.C_GetFunctionList = C_GetFunctionList;
        functionList.C_GetSlotList = C_GetSlotList;
        functionList.C_GetSlotInfo = C_GetSlotInfo;
        functionList.C_GetTokenInfo = C_GetTokenInfo;
        functionList.C_GetMechanismList = C_GetMechanismList;
        functionList.C_GetMechanismInfo = C_GetMechanismInfo;
        functionList.C_InitToken = C_InitToken;
        functionList.C_InitPIN = C_InitPIN;
        functionList.C_SetPIN = C_SetPIN;
        functionList.C_OpenSession = C_OpenSession;
        functionList.C_CloseSession = C_CloseSession;
        functionList.C_CloseAllSessions = C_CloseAllSessions;
        functionList.C_GetSessionInfo = C_GetSessionInfo;
        functionList.C_Login = C_Login;
        functionList.C_Logout = C_Logout;
        functionList.C_CreateObject = C_CreateObject;
        functionList.C_DestroyObject = C_DestroyObject;
        functionList.C_GetAttributeValue = C_GetAttributeValue;
        functionList.C_SetAttributeValue = C_SetAttributeValue;
        functionList.C_FindObjectsInit = C_FindObjectsInit;
        functionList.C_FindObjects = C_FindObjects;
        functionList.C_FindObjectsFinal = C_FindObjectsFinal;
        functionList.C_SignInit = C_SignInit;
        functionList.C_Sign = C_Sign;
        functionList.C_VerifyInit = C_VerifyInit;
        functionList.C_Verify = C_Verify;
        functionList.C_GenerateKeyPair = C_GenerateKeyPair;
        functionList.C_GenerateRandom = C_GenerateRandom;

        /* Stub out unimplemented functions */
        functionList.C_GetOperationState = C_GetOperationState;
        functionList.C_SetOperationState = C_SetOperationState;
        functionList.C_CopyObject = C_CopyObject;
        functionList.C_GetObjectSize = C_GetObjectSize;
        functionList.C_EncryptInit = C_EncryptInit;
        functionList.C_Encrypt = C_Encrypt;
        functionList.C_EncryptUpdate = C_EncryptUpdate;
        functionList.C_EncryptFinal = C_EncryptFinal;
        functionList.C_DecryptInit = C_DecryptInit;
        functionList.C_Decrypt = C_Decrypt;
        functionList.C_DecryptUpdate = C_DecryptUpdate;
        functionList.C_DecryptFinal = C_DecryptFinal;
        functionList.C_DigestInit = C_DigestInit;
        functionList.C_Digest = C_Digest;
        functionList.C_DigestUpdate = C_DigestUpdate;
        functionList.C_DigestKey = C_DigestKey;
        functionList.C_DigestFinal = C_DigestFinal;
        functionList.C_SignUpdate = C_SignUpdate;
        functionList.C_SignFinal = C_SignFinal;
        functionList.C_SignRecoverInit = C_SignRecoverInit;
        functionList.C_SignRecover = C_SignRecover;
        functionList.C_VerifyUpdate = C_VerifyUpdate;
        functionList.C_VerifyFinal = C_VerifyFinal;
        functionList.C_VerifyRecoverInit = C_VerifyRecoverInit;
        functionList.C_VerifyRecover = C_VerifyRecover;
        functionList.C_DigestEncryptUpdate = C_DigestEncryptUpdate;
        functionList.C_DecryptDigestUpdate = C_DecryptDigestUpdate;
        functionList.C_SignEncryptUpdate = C_SignEncryptUpdate;
        functionList.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
        functionList.C_GenerateKey = C_GenerateKey;
        functionList.C_WrapKey = C_WrapKey;
        functionList.C_UnwrapKey = C_UnwrapKey;
        functionList.C_DeriveKey = C_DeriveKey;
        functionList.C_SeedRandom = C_SeedRandom;
        functionList.C_GetFunctionStatus = C_GetFunctionStatus;
        functionList.C_CancelFunction = C_CancelFunction;
        functionList.C_WaitForSlotEvent = C_WaitForSlotEvent;

        initialized = true;
    }

    *ppFunctionList = &functionList;
    return CKR_OK;
}

/*
 * C_GetSlotList - Get list of available slots
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
    CK_BBOOL tokenPresent,
    CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount)
{
    if (pulCount == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    CK_ULONG count = 0;

    /* Count slots with tokens present if requested */
    if (tokenPresent) {
        for (uint32_t i = 0; i < g_hsm_context.slot_count; i++) {
            if (g_hsm_context.slots[i].token_present) {
                count++;
            }
        }
    } else {
        count = g_hsm_context.slot_count;
    }

    /* If pSlotList is NULL, just return the count */
    if (pSlotList == NULL_PTR) {
        *pulCount = count;
        return CKR_OK;
    }

    /* Check if buffer is large enough */
    if (*pulCount < count) {
        *pulCount = count;
        return CKR_BUFFER_TOO_SMALL;
    }

    /* Fill slot list */
    CK_ULONG idx = 0;
    for (uint32_t i = 0; i < g_hsm_context.slot_count && idx < count; i++) {
        if (!tokenPresent || g_hsm_context.slots[i].token_present) {
            pSlotList[idx++] = i;
        }
    }

    *pulCount = count;
    return CKR_OK;
}

/*
 * C_GetSlotInfo - Get information about a slot
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
    CK_SLOT_ID slotID,
    CK_SLOT_INFO_PTR pInfo)
{
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[slotID];

    memset(pInfo, 0, sizeof(CK_SLOT_INFO));

    memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
    snprintf((char *)pInfo->slotDescription, sizeof(pInfo->slotDescription),
             "PST HSM Slot %lu", (unsigned long)slotID);

    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, "PST Cryptographic Systems",
           strlen("PST Cryptographic Systems"));

    pInfo->flags = CKF_HW_SLOT;
    if (slot->token_present) {
        pInfo->flags |= CKF_TOKEN_PRESENT;
    }

    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

/*
 * C_GetTokenInfo - Get information about a token
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
    CK_SLOT_ID slotID,
    CK_TOKEN_INFO_PTR pInfo)
{
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[slotID];

    if (!slot->token_present) {
        return CKR_TOKEN_NOT_PRESENT;
    }

    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));

    memset(pInfo->label, ' ', sizeof(pInfo->label));
    if (strlen(slot->token_label) > 0) {
        memcpy(pInfo->label, slot->token_label,
               strlen(slot->token_label) < sizeof(pInfo->label) ?
               strlen(slot->token_label) : sizeof(pInfo->label));
    } else {
        memcpy(pInfo->label, "PST HSM Token", strlen("PST HSM Token"));
    }

    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, "PST Cryptographic Systems",
           strlen("PST Cryptographic Systems"));

    memset(pInfo->model, ' ', sizeof(pInfo->model));
    memcpy(pInfo->model, "PST-HSM-001", strlen("PST-HSM-001"));

    memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
    snprintf((char *)pInfo->serialNumber, sizeof(pInfo->serialNumber),
             "%016lX", (unsigned long)time(NULL));

    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED;
    if (slot->token_initialized) {
        pInfo->flags |= CKF_TOKEN_INITIALIZED;
    }
    if (slot->user_pin_initialized) {
        pInfo->flags |= CKF_USER_PIN_INITIALIZED;
    }
    if (slot->user_pin_locked) {
        pInfo->flags |= CKF_USER_PIN_LOCKED;
    }

    pInfo->ulMaxSessionCount = HSM_MAX_SESSIONS;
    pInfo->ulSessionCount = slot->session_count;
    pInfo->ulMaxRwSessionCount = HSM_MAX_SESSIONS;
    pInfo->ulRwSessionCount = slot->session_count;
    pInfo->ulMaxPinLen = HSM_MAX_PIN_LEN;
    pInfo->ulMinPinLen = HSM_MIN_PIN_LEN;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

    return CKR_OK;
}

/*
 * C_GetMechanismList - Get list of supported mechanisms
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
    CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount)
{
    if (pulCount == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    /* List of supported mechanisms */
    static const CK_MECHANISM_TYPE mechanisms[] = {
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_RSA_PKCS,
        CKM_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
        CKM_EC_KEY_PAIR_GEN,
        CKM_ECDSA,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
        CKM_SHA256,
        CKM_SHA384,
        CKM_SHA512
    };
    static const CK_ULONG mechanism_count = sizeof(mechanisms) / sizeof(mechanisms[0]);

    if (pMechanismList == NULL_PTR) {
        *pulCount = mechanism_count;
        return CKR_OK;
    }

    if (*pulCount < mechanism_count) {
        *pulCount = mechanism_count;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pMechanismList, mechanisms, sizeof(mechanisms));
    *pulCount = mechanism_count;

    return CKR_OK;
}

/*
 * C_GetMechanismInfo - Get information about a mechanism
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
    CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    CK_RV rv = hsm_check_mechanism_supported(type);
    if (rv != CKR_OK) {
        return rv;
    }

    memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));
    pInfo->flags = CKF_HW;

    switch (type) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            pInfo->ulMinKeySize = 2048;
            pInfo->ulMaxKeySize = 4096;
            pInfo->flags |= CKF_GENERATE_KEY_PAIR;
            break;

        case CKM_RSA_PKCS:
        case CKM_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            pInfo->ulMinKeySize = 2048;
            pInfo->ulMaxKeySize = 4096;
            pInfo->flags |= CKF_SIGN | CKF_VERIFY;
            break;

        case CKM_EC_KEY_PAIR_GEN:
            pInfo->ulMinKeySize = 256;
            pInfo->ulMaxKeySize = 521;
            pInfo->flags |= CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE;
            break;

        case CKM_ECDSA:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            pInfo->ulMinKeySize = 256;
            pInfo->ulMaxKeySize = 521;
            pInfo->flags |= CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE;
            break;

        case CKM_SHA256:
        case CKM_SHA384:
        case CKM_SHA512:
            pInfo->ulMinKeySize = 0;
            pInfo->ulMaxKeySize = 0;
            pInfo->flags |= CKF_DIGEST;
            break;

        default:
            return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/* Forward declarations for unimplemented stubs */
CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    /* OpenSSL automatically seeds, so this is a no-op */
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession) {
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession) {
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
