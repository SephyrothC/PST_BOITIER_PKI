/*
 * PKCS#11 Session Management
 */

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Session handle counter */
static CK_SESSION_HANDLE g_next_session_handle = 1;
static pthread_mutex_t g_session_handle_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * C_InitToken - Initialize a token
 */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(
    CK_SLOT_ID slotID,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen,
    CK_UTF8CHAR_PTR pLabel)
{
    if (pPin == NULL_PTR || pLabel == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (ulPinLen < HSM_MIN_PIN_LEN || ulPinLen > HSM_MAX_PIN_LEN) {
        return CKR_PIN_LEN_RANGE;
    }

    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[slotID];
    HSM_LOCK(slot->lock);

    /* Close all sessions */
    for (uint32_t i = 0; i < HSM_MAX_SESSIONS; i++) {
        if (slot->sessions[i]) {
            hsm_destroy_session(slot->sessions[i]->handle);
        }
    }

    /* Set SO PIN */
    CK_RV rv = hsm_set_pin(slot, CKU_SO, pPin, ulPinLen);
    if (rv != CKR_OK) {
        HSM_UNLOCK(slot->lock);
        return rv;
    }

    /* Set token label */
    memset(slot->token_label, ' ', sizeof(slot->token_label));
    size_t label_len = ulPinLen < sizeof(slot->token_label) ? ulPinLen : sizeof(slot->token_label);
    memcpy(slot->token_label, pLabel, label_len);

    slot->token_initialized = true;
    slot->token_present = true;
    slot->so_pin_initialized = true;
    slot->user_pin_initialized = false;
    slot->user_pin_locked = false;
    slot->so_pin_locked = false;
    slot->user_pin_retry_count = HSM_PIN_RETRY_COUNT;
    slot->so_pin_retry_count = HSM_PIN_RETRY_COUNT;

    /* Save token info */
    hsm_storage_save_token_info(slot);

    HSM_UNLOCK(slot->lock);

    hsm_log(HSM_LOG_INFO, "Token initialized on slot %lu", (unsigned long)slotID);
    return CKR_OK;
}

/*
 * C_InitPIN - Initialize user PIN
 */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(
    CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{
    if (pPin == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (ulPinLen < HSM_MIN_PIN_LEN || ulPinLen > HSM_MAX_PIN_LEN) {
        return CKR_PIN_LEN_RANGE;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    /* Must be logged in as SO */
    if (!session->so_logged_in) {
        HSM_UNLOCK(session->lock);
        return CKR_USER_NOT_LOGGED_IN;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[session->slot_id];
    HSM_LOCK(slot->lock);

    rv = hsm_set_pin(slot, CKU_USER, pPin, ulPinLen);
    if (rv == CKR_OK) {
        slot->user_pin_initialized = true;
        slot->user_pin_locked = false;
        slot->user_pin_retry_count = HSM_PIN_RETRY_COUNT;
        hsm_storage_save_token_info(slot);
    }

    HSM_UNLOCK(slot->lock);
    HSM_UNLOCK(session->lock);

    hsm_log(HSM_LOG_INFO, "User PIN initialized");
    return rv;
}

/*
 * C_SetPIN - Change PIN
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(
    CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldLen,
    CK_UTF8CHAR_PTR pNewPin,
    CK_ULONG ulNewLen)
{
    if (pOldPin == NULL_PTR || pNewPin == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (ulNewLen < HSM_MIN_PIN_LEN || ulNewLen > HSM_MAX_PIN_LEN) {
        return CKR_PIN_LEN_RANGE;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (!session->user_logged_in && !session->so_logged_in) {
        HSM_UNLOCK(session->lock);
        return CKR_USER_NOT_LOGGED_IN;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[session->slot_id];
    HSM_LOCK(slot->lock);

    CK_USER_TYPE user_type = session->user_logged_in ? CKU_USER : CKU_SO;

    /* Verify old PIN */
    rv = hsm_verify_pin(slot, user_type, pOldPin, ulOldLen);
    if (rv != CKR_OK) {
        HSM_UNLOCK(slot->lock);
        HSM_UNLOCK(session->lock);
        return rv;
    }

    /* Set new PIN */
    rv = hsm_set_pin(slot, user_type, pNewPin, ulNewLen);
    if (rv == CKR_OK) {
        if (user_type == CKU_USER) {
            slot->user_pin_retry_count = HSM_PIN_RETRY_COUNT;
        } else {
            slot->so_pin_retry_count = HSM_PIN_RETRY_COUNT;
        }
        hsm_storage_save_token_info(slot);
    }

    HSM_UNLOCK(slot->lock);
    HSM_UNLOCK(session->lock);

    hsm_log(HSM_LOG_INFO, "PIN changed");
    return rv;
}

/*
 * C_OpenSession - Open a session
 */
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(
    CK_SLOT_ID slotID,
    CK_FLAGS flags,
    CK_VOID_PTR pApplication,
    CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession)
{
    if (phSession == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    if (!(flags & CKF_SERIAL_SESSION)) {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    CK_RV rv = hsm_create_session(slotID, flags, phSession);
    if (rv == CKR_OK) {
        hsm_log(HSM_LOG_INFO, "Session opened: handle=0x%lx", (unsigned long)*phSession);
    }

    return rv;
}

/*
 * C_CloseSession - Close a session
 */
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = hsm_destroy_session(hSession);
    if (rv == CKR_OK) {
        hsm_log(HSM_LOG_INFO, "Session closed: handle=0x%lx", (unsigned long)hSession);
    }
    return rv;
}

/*
 * C_CloseAllSessions - Close all sessions on a slot
 */
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[slotID];
    HSM_LOCK(slot->lock);

    for (uint32_t i = 0; i < HSM_MAX_SESSIONS; i++) {
        if (slot->sessions[i]) {
            hsm_destroy_session(slot->sessions[i]->handle);
        }
    }

    HSM_UNLOCK(slot->lock);

    hsm_log(HSM_LOG_INFO, "All sessions closed on slot %lu", (unsigned long)slotID);
    return CKR_OK;
}

/*
 * C_GetSessionInfo - Get session information
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
    CK_SESSION_HANDLE hSession,
    CK_SESSION_INFO_PTR pInfo)
{
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    pInfo->slotID = session->slot_id;
    pInfo->flags = CKF_SERIAL_SESSION;
    if (session->is_read_write) {
        pInfo->flags |= CKF_RW_SESSION;
    }

    switch (session->state) {
        case SESSION_STATE_RO_PUBLIC:
            pInfo->state = CKS_RO_PUBLIC_SESSION;
            break;
        case SESSION_STATE_RO_USER:
            pInfo->state = CKS_RO_USER_FUNCTIONS;
            break;
        case SESSION_STATE_RW_PUBLIC:
            pInfo->state = CKS_RW_PUBLIC_SESSION;
            break;
        case SESSION_STATE_RW_USER:
            pInfo->state = CKS_RW_USER_FUNCTIONS;
            break;
        case SESSION_STATE_RW_SO:
            pInfo->state = CKS_RW_SO_FUNCTIONS;
            break;
        default:
            pInfo->state = CKS_RW_PUBLIC_SESSION;
            break;
    }

    pInfo->ulDeviceError = 0;

    HSM_UNLOCK(session->lock);

    return CKR_OK;
}

/*
 * C_Login - Login to a session
 */
CK_DEFINE_FUNCTION(CK_RV, C_Login)(
    CK_SESSION_HANDLE hSession,
    CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{
    if (pPin == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (userType != CKU_SO && userType != CKU_USER) {
        return CKR_USER_TYPE_INVALID;
    }

    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    /* Check if already logged in */
    if (session->user_logged_in || session->so_logged_in) {
        HSM_UNLOCK(session->lock);
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    /* SO can only login on RW sessions */
    if (userType == CKU_SO && !session->is_read_write) {
        HSM_UNLOCK(session->lock);
        return CKR_SESSION_READ_ONLY;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[session->slot_id];
    HSM_LOCK(slot->lock);

    /* Verify PIN */
    rv = hsm_verify_pin(slot, userType, pPin, ulPinLen);
    if (rv != CKR_OK) {
        HSM_UNLOCK(slot->lock);
        HSM_UNLOCK(session->lock);
        return rv;
    }

    /* Update session state */
    if (userType == CKU_SO) {
        session->so_logged_in = true;
        session->state = SESSION_STATE_RW_SO;
    } else {
        session->user_logged_in = true;
        session->state = session->is_read_write ?
                         SESSION_STATE_RW_USER : SESSION_STATE_RO_USER;
    }

    session->last_activity = time(NULL);

    HSM_UNLOCK(slot->lock);
    HSM_UNLOCK(session->lock);

    hsm_log(HSM_LOG_INFO, "User logged in: type=%s",
            userType == CKU_SO ? "SO" : "USER");
    return CKR_OK;
}

/*
 * C_Logout - Logout from a session
 */
CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
    hsm_session_t *session;
    CK_RV rv = hsm_get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    HSM_LOCK(session->lock);

    if (!session->user_logged_in && !session->so_logged_in) {
        HSM_UNLOCK(session->lock);
        return CKR_USER_NOT_LOGGED_IN;
    }

    /* Update session state */
    session->user_logged_in = false;
    session->so_logged_in = false;
    session->state = session->is_read_write ?
                     SESSION_STATE_RW_PUBLIC : SESSION_STATE_RO_PUBLIC;

    HSM_UNLOCK(session->lock);

    hsm_log(HSM_LOG_INFO, "User logged out");
    return CKR_OK;
}

/*
 * Internal: Create a new session
 */
CK_RV hsm_create_session(CK_SLOT_ID slot_id, CK_FLAGS flags, CK_SESSION_HANDLE *phSession)
{
    hsm_slot_t *slot = &g_hsm_context.slots[slot_id];

    HSM_LOCK(slot->lock);

    /* Check session count */
    if (slot->session_count >= HSM_MAX_SESSIONS) {
        HSM_UNLOCK(slot->lock);
        return CKR_SESSION_COUNT;
    }

    /* Find free session slot */
    uint32_t idx = 0;
    for (; idx < HSM_MAX_SESSIONS; idx++) {
        if (slot->sessions[idx] == NULL) {
            break;
        }
    }

    if (idx >= HSM_MAX_SESSIONS) {
        HSM_UNLOCK(slot->lock);
        return CKR_SESSION_COUNT;
    }

    /* Allocate session */
    hsm_session_t *session = calloc(1, sizeof(hsm_session_t));
    if (!session) {
        HSM_UNLOCK(slot->lock);
        return CKR_HOST_MEMORY;
    }

    /* Generate handle */
    HSM_LOCK(g_session_handle_lock);
    session->handle = g_next_session_handle++;
    HSM_UNLOCK(g_session_handle_lock);

    session->slot_id = slot_id;
    session->is_read_write = (flags & CKF_RW_SESSION) != 0;
    session->state = session->is_read_write ?
                     SESSION_STATE_RW_PUBLIC : SESSION_STATE_RO_PUBLIC;
    session->user_logged_in = false;
    session->so_logged_in = false;
    session->find_active = false;
    session->find_count = 0;
    session->find_index = 0;
    session->created = time(NULL);
    session->last_activity = time(NULL);
    session->operation.active = false;
    session->operation.type = OP_NONE;

    pthread_mutex_init(&session->lock, NULL);

    slot->sessions[idx] = session;
    slot->session_count++;

    *phSession = session->handle;

    HSM_UNLOCK(slot->lock);

    return CKR_OK;
}

/*
 * Internal: Destroy a session
 */
CK_RV hsm_destroy_session(CK_SESSION_HANDLE hSession)
{
    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    /* Find session */
    hsm_session_t *session = NULL;
    hsm_slot_t *slot = NULL;
    uint32_t idx = 0;

    for (uint32_t s = 0; s < g_hsm_context.slot_count; s++) {
        slot = &g_hsm_context.slots[s];
        HSM_LOCK(slot->lock);
        for (idx = 0; idx < HSM_MAX_SESSIONS; idx++) {
            if (slot->sessions[idx] && slot->sessions[idx]->handle == hSession) {
                session = slot->sessions[idx];
                break;
            }
        }
        if (session) {
            break;
        }
        HSM_UNLOCK(slot->lock);
    }

    if (!session) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* Cleanup operation context if any */
    if (session->operation.active && session->operation.context) {
        /* TODO: Free OpenSSL contexts properly */
        free(session->operation.context);
    }

    pthread_mutex_destroy(&session->lock);
    free(session);

    slot->sessions[idx] = NULL;
    slot->session_count--;

    HSM_UNLOCK(slot->lock);

    return CKR_OK;
}

/*
 * Internal: Get session by handle
 */
CK_RV hsm_get_session(CK_SESSION_HANDLE hSession, hsm_session_t **ppSession)
{
    if (!g_hsm_context.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    /* Find session */
    for (uint32_t s = 0; s < g_hsm_context.slot_count; s++) {
        hsm_slot_t *slot = &g_hsm_context.slots[s];
        for (uint32_t i = 0; i < HSM_MAX_SESSIONS; i++) {
            if (slot->sessions[i] && slot->sessions[i]->handle == hSession) {
                *ppSession = slot->sessions[i];
                return CKR_OK;
            }
        }
    }

    return CKR_SESSION_HANDLE_INVALID;
}

/*
 * Internal: Verify session is valid
 */
CK_RV hsm_verify_session(CK_SESSION_HANDLE hSession)
{
    hsm_session_t *session;
    return hsm_get_session(hSession, &session);
}
