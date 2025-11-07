/*
 * PKCS#11 Object Management
 */

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"
#include <string.h>
#include <stdlib.h>

/*
 * Get object from slot
 */
CK_RV hsm_get_object(CK_SLOT_ID slot_id, CK_OBJECT_HANDLE hObject, hsm_object_t **ppObject)
{
    if (slot_id >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[slot_id];

    for (uint32_t i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (slot->objects[i] && slot->objects[i]->handle == hObject) {
            *ppObject = slot->objects[i];
            return CKR_OK;
        }
    }

    return CKR_OBJECT_HANDLE_INVALID;
}

/*
 * C_CreateObject - Create a new object
 */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject)
{
    if (pTemplate == NULL_PTR || phObject == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    /* Create object through internal function */
    rv = hsm_create_object(session, pTemplate, ulCount, phObject);

    return rv;
}

/*
 * C_DestroyObject - Destroy an object
 */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject)
{
    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    return hsm_destroy_object(session, hObject);
}

/*
 * C_GetAttributeValue - Get object attributes
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
    if (pTemplate == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    hsm_object_t *object;
    rv = hsm_get_object(session->slot_id, hObject, &object);
    if (rv != CKR_OK) {
        return rv;
    }

    return hsm_get_attribute_value(object, pTemplate, ulCount);
}

/*
 * C_SetAttributeValue - Set object attributes
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
    if (pTemplate == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    hsm_object_t *object;
    rv = hsm_get_object(session->slot_id, hObject, &object);
    if (rv != CKR_OK) {
        return rv;
    }

    return hsm_set_attribute_value(object, pTemplate, ulCount);
}

/*
 * C_FindObjectsInit - Initialize object search
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (session->find_active) {
        HSM_UNLOCK(session->lock);
        return CKR_OPERATION_ACTIVE;
    }

    rv = hsm_find_objects(session, pTemplate, ulCount);
    if (rv == CKR_OK) {
        session->find_active = true;
        session->find_index = 0;
    }

    HSM_UNLOCK(session->lock);

    return rv;
}

/*
 * C_FindObjects - Find objects
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount)
{
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (!session->find_active) {
        HSM_UNLOCK(session->lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    CK_ULONG count = 0;
    while (session->find_index < session->find_count && count < ulMaxObjectCount) {
        phObject[count++] = session->find_results[session->find_index++];
    }

    *pulObjectCount = count;

    HSM_UNLOCK(session->lock);

    return CKR_OK;
}

/*
 * C_FindObjectsFinal - Finalize object search
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (!session->find_active) {
        HSM_UNLOCK(session->lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    session->find_active = false;
    session->find_count = 0;
    session->find_index = 0;

    HSM_UNLOCK(session->lock);

    return CKR_OK;
}

/*
 * Internal: Create object
 */
CK_RV hsm_create_object(hsm_session_t *session, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount, CK_OBJECT_HANDLE *phObject)
{
    hsm_slot_t *slot = &g_hsm_context.slots[session->slot_id];

    HSM_LOCK(slot->lock);

    if (slot->object_count >= HSM_MAX_OBJECTS) {
        HSM_UNLOCK(slot->lock);
        return CKR_HOST_MEMORY;
    }

    /* Find free object slot */
    uint32_t idx = 0;
    for (; idx < HSM_MAX_OBJECTS; idx++) {
        if (slot->objects[idx] == NULL) {
            break;
        }
    }

    /* Allocate object */
    hsm_object_t *object = calloc(1, sizeof(hsm_object_t));
    if (!object) {
        HSM_UNLOCK(slot->lock);
        return CKR_HOST_MEMORY;
    }

    /* Parse template and set attributes */
    CK_RV rv = hsm_parse_template(pTemplate, ulCount, object);
    if (rv != CKR_OK) {
        free(object);
        HSM_UNLOCK(slot->lock);
        return rv;
    }

    /* Generate handle */
    object->handle = hsm_generate_object_handle(object->type);
    object->created = time(NULL);
    object->modified = time(NULL);
    object->ref_count = 1;

    slot->objects[idx] = object;
    slot->object_count++;

    *phObject = object->handle;

    /* Save to storage if token object */
    if (object->is_token) {
        hsm_storage_save_object(object);
    }

    HSM_UNLOCK(slot->lock);

    hsm_log(HSM_LOG_INFO, "Object created: handle=0x%08lx", (unsigned long)object->handle);
    return CKR_OK;
}

/*
 * Internal: Destroy object
 */
CK_RV hsm_destroy_object(hsm_session_t *session, CK_OBJECT_HANDLE hObject)
{
    hsm_slot_t *slot = &g_hsm_context.slots[session->slot_id];

    HSM_LOCK(slot->lock);

    /* Find object */
    uint32_t idx = 0;
    hsm_object_t *object = NULL;
    for (; idx < HSM_MAX_OBJECTS; idx++) {
        if (slot->objects[idx] && slot->objects[idx]->handle == hObject) {
            object = slot->objects[idx];
            break;
        }
    }

    if (!object) {
        HSM_UNLOCK(slot->lock);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    /* Delete from storage if token object */
    if (object->is_token) {
        hsm_storage_delete_object(hObject);
    }

    /* Free object data */
    /* TODO: Properly free all allocated memory in object */

    free(object);
    slot->objects[idx] = NULL;
    slot->object_count--;

    HSM_UNLOCK(slot->lock);

    hsm_log(HSM_LOG_INFO, "Object destroyed: handle=0x%08lx", (unsigned long)hObject);
    return CKR_OK;
}

/*
 * Internal: Find objects matching template
 */
CK_RV hsm_find_objects(hsm_session_t *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    hsm_slot_t *slot = &g_hsm_context.slots[session->slot_id];

    session->find_count = 0;

    for (uint32_t i = 0; i < HSM_MAX_OBJECTS && session->find_count < HSM_MAX_FIND_OBJECTS; i++) {
        if (slot->objects[i]) {
            /* Check if object matches template */
            bool matches = true;
            for (CK_ULONG j = 0; j < ulCount; j++) {
                /* TODO: Implement proper attribute matching */
                /* For now, add all objects */
            }

            if (matches) {
                session->find_results[session->find_count++] = slot->objects[i]->handle;
            }
        }
    }

    return CKR_OK;
}

/*
 * Internal: Get attribute value
 */
CK_RV hsm_get_attribute_value(hsm_object_t *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_RV rv = CKR_OK;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_CLASS:
                if (pTemplate[i].pValue) {
                    *(CK_OBJECT_CLASS *)pTemplate[i].pValue = object->type;
                }
                pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
                break;

            case CKA_TOKEN:
                if (pTemplate[i].pValue) {
                    *(CK_BBOOL *)pTemplate[i].pValue = object->is_token ? CK_TRUE : CK_FALSE;
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;

            case CKA_PRIVATE:
                if (pTemplate[i].pValue) {
                    *(CK_BBOOL *)pTemplate[i].pValue = object->is_private ? CK_TRUE : CK_FALSE;
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;

            case CKA_LABEL:
                if (pTemplate[i].pValue) {
                    size_t len = strlen(object->label);
                    if (pTemplate[i].ulValueLen >= len) {
                        memcpy(pTemplate[i].pValue, object->label, len);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = strlen(object->label);
                break;

            case CKA_ID:
                if (pTemplate[i].pValue) {
                    if (pTemplate[i].ulValueLen >= object->id_len) {
                        memcpy(pTemplate[i].pValue, object->id, object->id_len);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = object->id_len;
                break;

            case CKA_KEY_TYPE:
                if (pTemplate[i].pValue) {
                    *(CK_KEY_TYPE *)pTemplate[i].pValue =
                        (object->key_type == KEY_TYPE_RSA) ? CKK_RSA : CKK_EC;
                }
                pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
                break;

            /* TODO: Add more attributes */

            default:
                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
                break;
        }
    }

    return rv;
}

/*
 * Internal: Set attribute value
 */
CK_RV hsm_set_attribute_value(hsm_object_t *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_LABEL:
                if (pTemplate[i].ulValueLen < sizeof(object->label)) {
                    memcpy(object->label, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    object->label[pTemplate[i].ulValueLen] = '\0';
                }
                break;

            /* Most attributes are read-only */
            default:
                return CKR_ATTRIBUTE_READ_ONLY;
        }
    }

    return CKR_OK;
}

/*
 * Internal: Parse template and populate object
 */
CK_RV hsm_parse_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, hsm_object_t *object)
{
    /* Set defaults */
    object->is_token = false;
    object->is_private = true;
    object->is_sensitive = true;
    object->is_extractable = false;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_CLASS:
                object->type = *(CK_OBJECT_CLASS *)pTemplate[i].pValue;
                break;

            case CKA_TOKEN:
                object->is_token = (*(CK_BBOOL *)pTemplate[i].pValue == CK_TRUE);
                break;

            case CKA_PRIVATE:
                object->is_private = (*(CK_BBOOL *)pTemplate[i].pValue == CK_TRUE);
                break;

            case CKA_LABEL:
                if (pTemplate[i].ulValueLen < sizeof(object->label)) {
                    memcpy(object->label, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    object->label[pTemplate[i].ulValueLen] = '\0';
                }
                break;

            case CKA_ID:
                if (pTemplate[i].ulValueLen <= sizeof(object->id)) {
                    memcpy(object->id, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    object->id_len = pTemplate[i].ulValueLen;
                }
                break;

            /* TODO: Handle more attributes */
        }
    }

    return CKR_OK;
}
