/*
 * PKCS#11 Internal Types and Structures
 *
 * This file contains internal structures and definitions for our PKCS#11 implementation
 */

#ifndef PKCS11_INTERNAL_H
#define PKCS11_INTERNAL_H

#include "pkcs11.h"
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Configuration constants */
#define HSM_MAX_SESSIONS 64
#define HSM_MAX_OBJECTS 1024
#define HSM_MAX_PIN_LEN 32
#define HSM_MIN_PIN_LEN 4
#define HSM_MAX_FIND_OBJECTS 100
#define HSM_PIN_RETRY_COUNT 3
#define HSM_SESSION_TIMEOUT 300  /* 5 minutes */

/* Storage paths */
#define HSM_STORAGE_DIR "/var/lib/hsm"
#define HSM_KEY_STORAGE_DIR HSM_STORAGE_DIR "/keys"
#define HSM_TOKEN_FILE HSM_STORAGE_DIR "/token.dat"
#define HSM_CONFIG_FILE HSM_STORAGE_DIR "/config.conf"

/* Object handle generation */
#define OBJECT_HANDLE_PUBLIC_KEY_BASE  0x10000000
#define OBJECT_HANDLE_PRIVATE_KEY_BASE 0x20000000
#define OBJECT_HANDLE_CERT_BASE        0x30000000
#define OBJECT_HANDLE_DATA_BASE        0x40000000

/* Internal object types */
typedef enum {
    OBJ_TYPE_DATA = 0,
    OBJ_TYPE_CERTIFICATE,
    OBJ_TYPE_PUBLIC_KEY,
    OBJ_TYPE_PRIVATE_KEY
} hsm_object_type_t;

typedef enum {
    KEY_TYPE_RSA = 0,
    KEY_TYPE_EC
} hsm_key_type_t;

/* RSA key structure */
typedef struct {
    uint32_t bits;              /* Key size in bits */
    uint8_t *modulus;           /* n */
    size_t modulus_len;
    uint8_t *public_exponent;   /* e */
    size_t public_exponent_len;
    uint8_t *private_exponent;  /* d (private only) */
    size_t private_exponent_len;
    uint8_t *prime1;            /* p (private only) */
    size_t prime1_len;
    uint8_t *prime2;            /* q (private only) */
    size_t prime2_len;
    uint8_t *exponent1;         /* d mod (p-1) (private only) */
    size_t exponent1_len;
    uint8_t *exponent2;         /* d mod (q-1) (private only) */
    size_t exponent2_len;
    uint8_t *coefficient;       /* q^-1 mod p (private only) */
    size_t coefficient_len;
} hsm_rsa_key_t;

/* EC key structure */
typedef struct {
    uint8_t *ec_params;         /* DER-encoded curve OID */
    size_t ec_params_len;
    uint8_t *ec_point;          /* Public key point */
    size_t ec_point_len;
    uint8_t *ec_private;        /* Private key (private only) */
    size_t ec_private_len;
    int curve_nid;              /* OpenSSL curve NID */
} hsm_ec_key_t;

/* Generic key union */
typedef union {
    hsm_rsa_key_t rsa;
    hsm_ec_key_t ec;
} hsm_key_data_t;

/* Object structure */
typedef struct {
    CK_OBJECT_HANDLE handle;
    hsm_object_type_t type;
    bool is_token;              /* Persistent token object */
    bool is_private;            /* Requires login */
    bool is_sensitive;          /* Cannot be read */
    bool is_extractable;        /* Can be exported */

    /* Label and ID */
    char label[256];
    uint8_t id[64];
    size_t id_len;

    /* Key-specific data */
    hsm_key_type_t key_type;
    hsm_key_data_t key_data;

    /* Capabilities */
    bool can_sign;
    bool can_verify;
    bool can_encrypt;
    bool can_decrypt;
    bool can_wrap;
    bool can_unwrap;
    bool can_derive;

    /* Metadata */
    time_t created;
    time_t modified;

    /* Reference count for object lifecycle */
    uint32_t ref_count;

    /* Storage information */
    char storage_path[512];
    bool is_loaded;
} hsm_object_t;

/* Session state */
typedef enum {
    SESSION_STATE_INVALID = 0,
    SESSION_STATE_RO_PUBLIC,
    SESSION_STATE_RO_USER,
    SESSION_STATE_RW_PUBLIC,
    SESSION_STATE_RW_USER,
    SESSION_STATE_RW_SO
} hsm_session_state_t;

/* Cryptographic operation context */
typedef enum {
    OP_NONE = 0,
    OP_SIGN,
    OP_VERIFY,
    OP_ENCRYPT,
    OP_DECRYPT,
    OP_DIGEST
} hsm_operation_type_t;

typedef struct {
    hsm_operation_type_t type;
    CK_MECHANISM_TYPE mechanism;
    CK_OBJECT_HANDLE key_handle;
    void *context;              /* OpenSSL context (EVP_MD_CTX, etc.) */
    bool active;
} hsm_operation_t;

/* Session structure */
typedef struct {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
    hsm_session_state_t state;
    bool is_read_write;

    /* Authentication */
    bool user_logged_in;
    bool so_logged_in;

    /* Operation contexts */
    hsm_operation_t operation;

    /* Find operation state */
    bool find_active;
    CK_OBJECT_HANDLE find_results[HSM_MAX_FIND_OBJECTS];
    uint32_t find_count;
    uint32_t find_index;

    /* Timestamps */
    time_t created;
    time_t last_activity;

    /* Thread safety */
    pthread_mutex_t lock;
} hsm_session_t;

/* Slot/Token structure */
typedef struct {
    CK_SLOT_ID slot_id;
    bool token_present;

    /* Token info */
    char token_label[32];
    bool token_initialized;
    bool user_pin_initialized;
    bool so_pin_initialized;

    /* PIN management */
    uint8_t user_pin_hash[32];
    uint8_t so_pin_hash[32];
    uint32_t user_pin_retry_count;
    uint32_t so_pin_retry_count;
    bool user_pin_locked;
    bool so_pin_locked;

    /* Sessions */
    hsm_session_t *sessions[HSM_MAX_SESSIONS];
    uint32_t session_count;

    /* Objects */
    hsm_object_t *objects[HSM_MAX_OBJECTS];
    uint32_t object_count;

    /* Thread safety */
    pthread_mutex_t lock;
} hsm_slot_t;

/* Global HSM state */
typedef struct {
    bool initialized;
    pthread_mutex_t global_lock;

    /* Slots */
    hsm_slot_t *slots;
    uint32_t slot_count;

    /* Configuration */
    uint32_t max_sessions;
    uint32_t max_objects;
    bool enforce_timeouts;
    uint32_t session_timeout;

    /* Logging */
    void (*log_func)(int level, const char *message);
} hsm_context_t;

/* Global context - defined in pkcs11_impl.c */
extern hsm_context_t g_hsm_context;

/* Internal function prototypes */

/* Initialization and finalization */
CK_RV hsm_init_context(void);
CK_RV hsm_cleanup_context(void);
CK_RV hsm_init_slot(CK_SLOT_ID slot_id);
CK_RV hsm_cleanup_slot(CK_SLOT_ID slot_id);

/* Session management */
CK_RV hsm_create_session(CK_SLOT_ID slot_id, CK_FLAGS flags, CK_SESSION_HANDLE *phSession);
CK_RV hsm_destroy_session(CK_SESSION_HANDLE hSession);
CK_RV hsm_get_session(CK_SESSION_HANDLE hSession, hsm_session_t **ppSession);
CK_RV hsm_verify_session(CK_SESSION_HANDLE hSession);
CK_RV hsm_check_session_timeout(hsm_session_t *session);

/* Object management */
CK_RV hsm_create_object(hsm_session_t *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE *phObject);
CK_RV hsm_destroy_object(hsm_session_t *session, CK_OBJECT_HANDLE hObject);
CK_RV hsm_get_object(CK_SLOT_ID slot_id, CK_OBJECT_HANDLE hObject, hsm_object_t **ppObject);
CK_RV hsm_find_objects(hsm_session_t *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_OBJECT_HANDLE hsm_generate_object_handle(hsm_object_type_t type);

/* Attribute handling */
CK_RV hsm_get_attribute_value(hsm_object_t *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV hsm_set_attribute_value(hsm_object_t *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV hsm_parse_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, hsm_object_t *object);

/* PIN management */
CK_RV hsm_verify_pin(hsm_slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV hsm_set_pin(hsm_slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV hsm_hash_pin(const uint8_t *pin, size_t pin_len, uint8_t *hash_out);

/* Crypto operations - defined in crypto module */
CK_RV hsm_generate_key_pair_rsa(CK_ULONG key_bits, hsm_object_t *pub_key, hsm_object_t *priv_key);
CK_RV hsm_generate_key_pair_ec(int curve_nid, hsm_object_t *pub_key, hsm_object_t *priv_key);
CK_RV hsm_sign_data(hsm_object_t *priv_key, CK_MECHANISM_TYPE mechanism, const uint8_t *data, size_t data_len, uint8_t *signature, size_t *signature_len);
CK_RV hsm_verify_signature(hsm_object_t *pub_key, CK_MECHANISM_TYPE mechanism, const uint8_t *data, size_t data_len, const uint8_t *signature, size_t signature_len);

/* Storage operations - defined in storage module */
CK_RV hsm_storage_init(void);
CK_RV hsm_storage_save_object(hsm_object_t *object);
CK_RV hsm_storage_load_object(CK_OBJECT_HANDLE handle, hsm_object_t *object);
CK_RV hsm_storage_delete_object(CK_OBJECT_HANDLE handle);
CK_RV hsm_storage_list_objects(CK_OBJECT_HANDLE *handles, uint32_t *count);
CK_RV hsm_storage_save_token_info(hsm_slot_t *slot);
CK_RV hsm_storage_load_token_info(hsm_slot_t *slot);

/* Utility functions */
void hsm_log(int level, const char *format, ...);
void *hsm_secure_alloc(size_t size);
void hsm_secure_free(void *ptr, size_t size);
void hsm_secure_zero(void *ptr, size_t size);
CK_RV hsm_check_mechanism_supported(CK_MECHANISM_TYPE mechanism);
const char *hsm_mechanism_to_string(CK_MECHANISM_TYPE mechanism);
const char *hsm_rv_to_string(CK_RV rv);

/* Lock helpers */
#define HSM_LOCK(mutex) pthread_mutex_lock(&(mutex))
#define HSM_UNLOCK(mutex) pthread_mutex_unlock(&(mutex))
#define HSM_TRYLOCK(mutex) pthread_mutex_trylock(&(mutex))

/* Logging levels */
#define HSM_LOG_ERROR   0
#define HSM_LOG_WARN    1
#define HSM_LOG_INFO    2
#define HSM_LOG_DEBUG   3

#ifdef __cplusplus
}
#endif

#endif /* PKCS11_INTERNAL_H */
