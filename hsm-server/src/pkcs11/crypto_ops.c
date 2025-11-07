/*
 * PKCS#11 Cryptographic Operations
 */

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"
#include <string.h>
#include <openssl/objects.h>

/*
 * C_GenerateKeyPair - Generate a key pair
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    if (pMechanism == NULL_PTR || phPublicKey == NULL_PTR || phPrivateKey == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (!session->user_logged_in) {
        HSM_UNLOCK(session->lock);
        return CKR_USER_NOT_LOGGED_IN;
    }

    HSM_UNLOCK(session->lock);

    hsm_log(HSM_LOG_INFO, "Generating key pair: mechanism=%s",
            hsm_mechanism_to_string(pMechanism->mechanism));

    /* Create object structures */
    hsm_object_t *pub_obj = calloc(1, sizeof(hsm_object_t));
    hsm_object_t *priv_obj = calloc(1, sizeof(hsm_object_t));

    if (!pub_obj || !priv_obj) {
        free(pub_obj);
        free(priv_obj);
        return CKR_HOST_MEMORY;
    }

    /* Initialize objects */
    pub_obj->type = OBJ_TYPE_PUBLIC_KEY;
    pub_obj->is_private = false;
    pub_obj->is_sensitive = false;
    pub_obj->is_extractable = true;
    pub_obj->can_verify = true;

    priv_obj->type = OBJ_TYPE_PRIVATE_KEY;
    priv_obj->is_private = true;
    priv_obj->is_sensitive = true;
    priv_obj->is_extractable = false;
    priv_obj->can_sign = true;

    /* Parse templates */
    hsm_parse_template(pPublicKeyTemplate, ulPublicKeyAttributeCount, pub_obj);
    hsm_parse_template(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, priv_obj);

    /* Generate key pair based on mechanism */
    if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
        /* Get key size from template */
        CK_ULONG key_bits = 2048;  /* Default */
        for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
            if (pPublicKeyTemplate[i].type == CKA_MODULUS_BITS) {
                key_bits = *(CK_ULONG *)pPublicKeyTemplate[i].pValue;
                break;
            }
        }

        rv = hsm_generate_key_pair_rsa(key_bits, pub_obj, priv_obj);

    } else if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
        /* Get curve from template */
        int curve_nid = NID_X9_62_prime256v1;  /* Default P-256 */
        for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
            if (pPublicKeyTemplate[i].type == CKA_EC_PARAMS) {
                /* Parse EC params to get curve */
                const uint8_t *params = pPublicKeyTemplate[i].pValue;
                size_t params_len = pPublicKeyTemplate[i].ulValueLen;

                /* Check for P-256 */
                static const uint8_t p256_oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
                /* Check for P-384 */
                static const uint8_t p384_oid[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
                /* Check for P-521 */
                static const uint8_t p521_oid[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

                if (params_len == sizeof(p256_oid) && memcmp(params, p256_oid, sizeof(p256_oid)) == 0) {
                    curve_nid = NID_X9_62_prime256v1;
                } else if (params_len == sizeof(p384_oid) && memcmp(params, p384_oid, sizeof(p384_oid)) == 0) {
                    curve_nid = NID_secp384r1;
                } else if (params_len == sizeof(p521_oid) && memcmp(params, p521_oid, sizeof(p521_oid)) == 0) {
                    curve_nid = NID_secp521r1;
                }
                break;
            }
        }

        rv = hsm_generate_key_pair_ec(curve_nid, pub_obj, priv_obj);

    } else {
        free(pub_obj);
        free(priv_obj);
        return CKR_MECHANISM_INVALID;
    }

    if (rv != CKR_OK) {
        free(pub_obj);
        free(priv_obj);
        return rv;
    }

    /* Add objects to slot */
    hsm_slot_t *slot = &g_hsm_context.slots[session->slot_id];
    HSM_LOCK(slot->lock);

    /* Find free slots */
    uint32_t pub_idx = HSM_MAX_OBJECTS, priv_idx = HSM_MAX_OBJECTS;
    for (uint32_t i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (slot->objects[i] == NULL) {
            if (pub_idx == HSM_MAX_OBJECTS) {
                pub_idx = i;
            } else if (priv_idx == HSM_MAX_OBJECTS) {
                priv_idx = i;
                break;
            }
        }
    }

    if (pub_idx == HSM_MAX_OBJECTS || priv_idx == HSM_MAX_OBJECTS) {
        HSM_UNLOCK(slot->lock);
        free(pub_obj);
        free(priv_obj);
        return CKR_HOST_MEMORY;
    }

    /* Generate handles */
    pub_obj->handle = hsm_generate_object_handle(OBJ_TYPE_PUBLIC_KEY);
    priv_obj->handle = hsm_generate_object_handle(OBJ_TYPE_PRIVATE_KEY);

    slot->objects[pub_idx] = pub_obj;
    slot->objects[priv_idx] = priv_obj;
    slot->object_count += 2;

    *phPublicKey = pub_obj->handle;
    *phPrivateKey = priv_obj->handle;

    /* Save to storage if token objects */
    if (pub_obj->is_token) {
        hsm_storage_save_object(pub_obj);
    }
    if (priv_obj->is_token) {
        hsm_storage_save_object(priv_obj);
    }

    HSM_UNLOCK(slot->lock);

    hsm_log(HSM_LOG_INFO, "Key pair generated: pub=0x%08lx, priv=0x%08lx",
            (unsigned long)*phPublicKey, (unsigned long)*phPrivateKey);

    return CKR_OK;
}

/*
 * C_SignInit - Initialize signing operation
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
    if (pMechanism == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (session->operation.active) {
        HSM_UNLOCK(session->lock);
        return CKR_OPERATION_ACTIVE;
    }

    /* Verify key exists and is a private key */
    hsm_object_t *key;
    rv = hsm_get_object(session->slot_id, hKey, &key);
    if (rv != CKR_OK) {
        HSM_UNLOCK(session->lock);
        return rv;
    }

    if (key->type != OBJ_TYPE_PRIVATE_KEY) {
        HSM_UNLOCK(session->lock);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (!key->can_sign) {
        HSM_UNLOCK(session->lock);
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    /* Check mechanism */
    rv = hsm_check_mechanism_supported(pMechanism->mechanism);
    if (rv != CKR_OK) {
        HSM_UNLOCK(session->lock);
        return rv;
    }

    /* Initialize operation */
    session->operation.type = OP_SIGN;
    session->operation.mechanism = pMechanism->mechanism;
    session->operation.key_handle = hKey;
    session->operation.active = true;
    session->operation.context = NULL;

    HSM_UNLOCK(session->lock);

    hsm_log(HSM_LOG_DEBUG, "Sign operation initialized: mechanism=%s",
            hsm_mechanism_to_string(pMechanism->mechanism));

    return CKR_OK;
}

/*
 * C_Sign - Sign data
 */
CK_DEFINE_FUNCTION(CK_RV, C_Sign)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
    if (pData == NULL_PTR || pulSignatureLen == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (!session->operation.active || session->operation.type != OP_SIGN) {
        HSM_UNLOCK(session->lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    /* Get private key */
    hsm_object_t *priv_key;
    rv = hsm_get_object(session->slot_id, session->operation.key_handle, &priv_key);
    if (rv != CKR_OK) {
        session->operation.active = false;
        HSM_UNLOCK(session->lock);
        return rv;
    }

    /* Perform signature */
    size_t sig_len = *pulSignatureLen;
    rv = hsm_sign_data(priv_key, session->operation.mechanism,
                       pData, ulDataLen, pSignature, &sig_len);

    *pulSignatureLen = sig_len;

    /* Clear operation */
    session->operation.active = false;
    session->operation.type = OP_NONE;

    HSM_UNLOCK(session->lock);

    if (rv == CKR_OK) {
        hsm_log(HSM_LOG_INFO, "Data signed: %lu bytes -> %lu bytes signature",
                (unsigned long)ulDataLen, (unsigned long)sig_len);
    }

    return rv;
}

/*
 * C_SignUpdate - Continue signing operation
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
    /* TODO: Implement multi-part signing */
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * C_SignFinal - Finalize signing operation
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
    /* TODO: Implement multi-part signing */
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * C_VerifyInit - Initialize verification operation
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
    if (pMechanism == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (session->operation.active) {
        HSM_UNLOCK(session->lock);
        return CKR_OPERATION_ACTIVE;
    }

    /* Verify key exists and is a public key */
    hsm_object_t *key;
    rv = hsm_get_object(session->slot_id, hKey, &key);
    if (rv != CKR_OK) {
        HSM_UNLOCK(session->lock);
        return rv;
    }

    if (key->type != OBJ_TYPE_PUBLIC_KEY) {
        HSM_UNLOCK(session->lock);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Initialize operation */
    session->operation.type = OP_VERIFY;
    session->operation.mechanism = pMechanism->mechanism;
    session->operation.key_handle = hKey;
    session->operation.active = true;

    HSM_UNLOCK(session->lock);

    return CKR_OK;
}

/*
 * C_Verify - Verify signature
 */
CK_DEFINE_FUNCTION(CK_RV, C_Verify)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
    if (pData == NULL_PTR || pSignature == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (!session->operation.active || session->operation.type != OP_VERIFY) {
        HSM_UNLOCK(session->lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    /* Get public key */
    hsm_object_t *pub_key;
    rv = hsm_get_object(session->slot_id, session->operation.key_handle, &pub_key);
    if (rv != CKR_OK) {
        session->operation.active = false;
        HSM_UNLOCK(session->lock);
        return rv;
    }

    /* Perform verification */
    rv = hsm_verify_signature(pub_key, session->operation.mechanism,
                              pData, ulDataLen, pSignature, ulSignatureLen);

    /* Clear operation */
    session->operation.active = false;
    session->operation.type = OP_NONE;

    HSM_UNLOCK(session->lock);

    return rv;
}

/*
 * C_VerifyUpdate - Continue verification operation
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * C_VerifyFinal - Finalize verification operation
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Digest operations stubs */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Encryption operations stubs */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Decryption operations stubs */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
