/*
 * Utility Functions
 */

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

/*
 * Logging function
 */
void hsm_log(int level, const char *format, ...)
{
    if (!g_hsm_context.initialized && level != HSM_LOG_ERROR) {
        return;
    }

    const char *level_str[] = {"ERROR", "WARN", "INFO", "DEBUG"};

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(stderr, "[%s] [%s] ", time_buf, level_str[level]);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
}

/*
 * Secure memory allocation
 */
void *hsm_secure_alloc(size_t size)
{
    void *ptr = calloc(1, size);
    if (ptr) {
        /* Lock memory to prevent swapping (requires root) */
        /* mlock(ptr, size); */
    }
    return ptr;
}

/*
 * Secure memory deallocation
 */
void hsm_secure_free(void *ptr, size_t size)
{
    if (ptr) {
        hsm_secure_zero(ptr, size);
        /* munlock(ptr, size); */
        free(ptr);
    }
}

/*
 * Securely zero memory
 */
void hsm_secure_zero(void *ptr, size_t size)
{
    if (ptr) {
        volatile uint8_t *p = ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}

/*
 * Check if mechanism is supported
 */
CK_RV hsm_check_mechanism_supported(CK_MECHANISM_TYPE mechanism)
{
    static const CK_MECHANISM_TYPE supported[] = {
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

    for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
        if (supported[i] == mechanism) {
            return CKR_OK;
        }
    }

    return CKR_MECHANISM_INVALID;
}

/*
 * Convert mechanism to string
 */
const char *hsm_mechanism_to_string(CK_MECHANISM_TYPE mechanism)
{
    switch (mechanism) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN";
        case CKM_RSA_PKCS: return "CKM_RSA_PKCS";
        case CKM_RSA_PKCS_PSS: return "CKM_RSA_PKCS_PSS";
        case CKM_SHA256_RSA_PKCS: return "CKM_SHA256_RSA_PKCS";
        case CKM_SHA384_RSA_PKCS: return "CKM_SHA384_RSA_PKCS";
        case CKM_SHA512_RSA_PKCS: return "CKM_SHA512_RSA_PKCS";
        case CKM_EC_KEY_PAIR_GEN: return "CKM_EC_KEY_PAIR_GEN";
        case CKM_ECDSA: return "CKM_ECDSA";
        case CKM_ECDSA_SHA256: return "CKM_ECDSA_SHA256";
        case CKM_ECDSA_SHA384: return "CKM_ECDSA_SHA384";
        case CKM_ECDSA_SHA512: return "CKM_ECDSA_SHA512";
        default: return "UNKNOWN";
    }
}

/*
 * Convert return value to string
 */
const char *hsm_rv_to_string(CK_RV rv)
{
    switch (rv) {
        case CKR_OK: return "CKR_OK";
        case CKR_CANCEL: return "CKR_CANCEL";
        case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
        case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
        case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
        case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
        case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
        case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
        case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
        case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
        case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
        case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        default: return "UNKNOWN";
    }
}

/*
 * Initialize HSM context
 */
CK_RV hsm_init_context(void)
{
    memset(&g_hsm_context, 0, sizeof(g_hsm_context));
    pthread_mutex_init(&g_hsm_context.global_lock, NULL);
    g_hsm_context.max_sessions = HSM_MAX_SESSIONS;
    g_hsm_context.max_objects = HSM_MAX_OBJECTS;
    g_hsm_context.enforce_timeouts = true;
    g_hsm_context.session_timeout = HSM_SESSION_TIMEOUT;
    g_hsm_context.initialized = false;

    return CKR_OK;
}

/*
 * Cleanup HSM context
 */
CK_RV hsm_cleanup_context(void)
{
    pthread_mutex_destroy(&g_hsm_context.global_lock);
    return CKR_OK;
}

/*
 * Initialize slot
 */
CK_RV hsm_init_slot(CK_SLOT_ID slot_id)
{
    if (slot_id >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[slot_id];
    memset(slot, 0, sizeof(hsm_slot_t));

    slot->slot_id = slot_id;
    slot->token_present = true;
    slot->token_initialized = false;
    slot->user_pin_initialized = false;
    slot->so_pin_initialized = false;
    slot->user_pin_locked = false;
    slot->so_pin_locked = false;
    slot->user_pin_retry_count = HSM_PIN_RETRY_COUNT;
    slot->so_pin_retry_count = HSM_PIN_RETRY_COUNT;
    slot->session_count = 0;
    slot->object_count = 0;

    pthread_mutex_init(&slot->lock, NULL);

    /* Try to load token info from storage */
    hsm_storage_load_token_info(slot);

    return CKR_OK;
}

/*
 * Cleanup slot
 */
CK_RV hsm_cleanup_slot(CK_SLOT_ID slot_id)
{
    if (slot_id >= g_hsm_context.slot_count) {
        return CKR_SLOT_ID_INVALID;
    }

    hsm_slot_t *slot = &g_hsm_context.slots[slot_id];

    /* Close all sessions */
    for (uint32_t i = 0; i < HSM_MAX_SESSIONS; i++) {
        if (slot->sessions[i]) {
            hsm_destroy_session(slot->sessions[i]->handle);
        }
    }

    /* Free all objects */
    for (uint32_t i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (slot->objects[i]) {
            /* TODO: Free object data properly */
            free(slot->objects[i]);
            slot->objects[i] = NULL;
        }
    }

    pthread_mutex_destroy(&slot->lock);

    return CKR_OK;
}

/*
 * Hash PIN using SHA-256
 */
CK_RV hsm_hash_pin(const uint8_t *pin, size_t pin_len, uint8_t *hash_out)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return CKR_HOST_MEMORY;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, pin, pin_len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash_out, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return CKR_FUNCTION_FAILED;
    }

    EVP_MD_CTX_free(ctx);
    return CKR_OK;
}

/*
 * Set PIN
 */
CK_RV hsm_set_pin(hsm_slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if (ulPinLen < HSM_MIN_PIN_LEN || ulPinLen > HSM_MAX_PIN_LEN) {
        return CKR_PIN_LEN_RANGE;
    }

    uint8_t pin_hash[32];
    hsm_hash_pin(pPin, ulPinLen, pin_hash);

    if (userType == CKU_SO) {
        memcpy(slot->so_pin_hash, pin_hash, 32);
    } else {
        memcpy(slot->user_pin_hash, pin_hash, 32);
    }

    return CKR_OK;
}

/*
 * Verify PIN
 */
CK_RV hsm_verify_pin(hsm_slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    uint8_t *stored_hash;
    uint32_t *retry_count;
    bool *locked;

    if (userType == CKU_SO) {
        if (!slot->so_pin_initialized) {
            return CKR_USER_PIN_NOT_INITIALIZED;
        }
        stored_hash = slot->so_pin_hash;
        retry_count = &slot->so_pin_retry_count;
        locked = &slot->so_pin_locked;
    } else {
        if (!slot->user_pin_initialized) {
            return CKR_USER_PIN_NOT_INITIALIZED;
        }
        stored_hash = slot->user_pin_hash;
        retry_count = &slot->user_pin_retry_count;
        locked = &slot->user_pin_locked;
    }

    if (*locked) {
        return CKR_PIN_LOCKED;
    }

    uint8_t pin_hash[32];
    hsm_hash_pin(pPin, ulPinLen, pin_hash);

    if (memcmp(pin_hash, stored_hash, 32) != 0) {
        if (*retry_count > 0) {
            (*retry_count)--;
        }
        if (*retry_count == 0) {
            *locked = true;
            return CKR_PIN_LOCKED;
        }
        return CKR_PIN_INCORRECT;
    }

    /* PIN correct, reset retry count */
    *retry_count = HSM_PIN_RETRY_COUNT;

    return CKR_OK;
}

/*
 * Generate object handle
 */
CK_OBJECT_HANDLE hsm_generate_object_handle(hsm_object_type_t type)
{
    static uint32_t counter = 1;
    static pthread_mutex_t handle_lock = PTHREAD_MUTEX_INITIALIZER;

    HSM_LOCK(handle_lock);
    uint32_t handle_counter = counter++;
    HSM_UNLOCK(handle_lock);

    CK_OBJECT_HANDLE base = 0;
    switch (type) {
        case OBJ_TYPE_PUBLIC_KEY:
            base = OBJECT_HANDLE_PUBLIC_KEY_BASE;
            break;
        case OBJ_TYPE_PRIVATE_KEY:
            base = OBJECT_HANDLE_PRIVATE_KEY_BASE;
            break;
        case OBJ_TYPE_CERTIFICATE:
            base = OBJECT_HANDLE_CERT_BASE;
            break;
        case OBJ_TYPE_DATA:
            base = OBJECT_HANDLE_DATA_BASE;
            break;
    }

    return base + handle_counter;
}
