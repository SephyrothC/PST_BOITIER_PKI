/*
 * Encrypted Key Storage
 *
 * Provides secure storage for cryptographic keys with AES-256-GCM encryption.
 * Keys are encrypted with a master key derived from the HSM PIN.
 */

#ifndef KEY_STORAGE_H
#define KEY_STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "pkcs11/pkcs11.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Storage configuration */
#define KEY_STORAGE_DIR "/var/lib/pki-hsm/keys"
#define KEY_STORAGE_CONFIG "/var/lib/pki-hsm/config/storage.conf"

/* Encryption algorithm */
#define KEY_STORAGE_CIPHER "AES-256-GCM"
#define KEY_STORAGE_KEY_SIZE 32     /* 256 bits */
#define KEY_STORAGE_IV_SIZE 12      /* 96 bits for GCM */
#define KEY_STORAGE_TAG_SIZE 16     /* 128 bits auth tag */
#define KEY_STORAGE_SALT_SIZE 32    /* Salt for PBKDF2 */
#define KEY_STORAGE_PBKDF2_ITERATIONS 600000

/* Storage backend types */
typedef enum {
    STORAGE_BACKEND_FILE = 0,       /* File-based storage */
    STORAGE_BACKEND_DATABASE = 1,   /* SQLite database */
    STORAGE_BACKEND_HSM = 2         /* Hardware HSM (future) */
} storage_backend_t;

/* Key metadata */
typedef struct {
    CK_OBJECT_HANDLE handle;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE key_type;
    char label[256];
    uint8_t id[64];
    size_t id_len;
    bool is_token;
    bool is_private;
    bool is_sensitive;
    bool is_extractable;
    time_t created;
    time_t modified;
    size_t key_size;            /* Key size in bytes */
    uint32_t usage_count;       /* Number of times used */
} key_metadata_t;

/* Storage context */
typedef struct key_storage_ctx key_storage_ctx_t;

/*
 * Initialize key storage
 *
 * Parameters:
 *   backend: Storage backend to use
 *   pin: Master PIN for key encryption (min 8 characters)
 *   pin_len: Length of PIN
 *
 * Returns: Storage context on success, NULL on error
 */
key_storage_ctx_t *key_storage_init(
    storage_backend_t backend,
    const uint8_t *pin,
    size_t pin_len
);

/*
 * Change master PIN
 *
 * Re-encrypts all stored keys with new PIN-derived key.
 *
 * Returns: 0 on success, -1 on error
 */
int key_storage_change_pin(
    key_storage_ctx_t *ctx,
    const uint8_t *old_pin,
    size_t old_pin_len,
    const uint8_t *new_pin,
    size_t new_pin_len
);

/*
 * Store key
 *
 * Encrypts and stores the key material with metadata.
 *
 * Parameters:
 *   ctx: Storage context
 *   handle: PKCS#11 object handle
 *   key_data: Raw key material
 *   key_len: Length of key material
 *   metadata: Key metadata
 *
 * Returns: 0 on success, -1 on error
 */
int key_storage_store(
    key_storage_ctx_t *ctx,
    CK_OBJECT_HANDLE handle,
    const uint8_t *key_data,
    size_t key_len,
    const key_metadata_t *metadata
);

/*
 * Load key
 *
 * Decrypts and loads key material.
 *
 * Parameters:
 *   ctx: Storage context
 *   handle: PKCS#11 object handle
 *   key_data: Buffer for key material (allocated by function)
 *   key_len: Length of loaded key material
 *   metadata: Key metadata (optional, can be NULL)
 *
 * Returns: 0 on success, -1 on error
 *          key_data must be freed with key_storage_free_key()
 */
int key_storage_load(
    key_storage_ctx_t *ctx,
    CK_OBJECT_HANDLE handle,
    uint8_t **key_data,
    size_t *key_len,
    key_metadata_t *metadata
);

/*
 * Delete key
 *
 * Securely deletes key from storage.
 *
 * Returns: 0 on success, -1 on error
 */
int key_storage_delete(
    key_storage_ctx_t *ctx,
    CK_OBJECT_HANDLE handle
);

/*
 * List all keys
 *
 * Returns array of key handles.
 *
 * Parameters:
 *   ctx: Storage context
 *   handles: Array of handles (allocated by function)
 *   count: Number of handles
 *
 * Returns: 0 on success, -1 on error
 *          handles must be freed with free()
 */
int key_storage_list(
    key_storage_ctx_t *ctx,
    CK_OBJECT_HANDLE **handles,
    size_t *count
);

/*
 * Get key metadata
 *
 * Returns: 0 on success, -1 on error
 */
int key_storage_get_metadata(
    key_storage_ctx_t *ctx,
    CK_OBJECT_HANDLE handle,
    key_metadata_t *metadata
);

/*
 * Update key metadata
 *
 * Returns: 0 on success, -1 on error
 */
int key_storage_update_metadata(
    key_storage_ctx_t *ctx,
    CK_OBJECT_HANDLE handle,
    const key_metadata_t *metadata
);

/*
 * Check if key exists
 *
 * Returns: true if exists, false otherwise
 */
bool key_storage_exists(
    key_storage_ctx_t *ctx,
    CK_OBJECT_HANDLE handle
);

/*
 * Get storage statistics
 */
typedef struct {
    size_t total_keys;
    size_t token_keys;
    size_t session_keys;
    size_t storage_size_bytes;
    time_t oldest_key;
    time_t newest_key;
} storage_stats_t;

int key_storage_get_stats(
    key_storage_ctx_t *ctx,
    storage_stats_t *stats
);

/*
 * Backup storage
 *
 * Creates encrypted backup of all keys.
 *
 * Returns: 0 on success, -1 on error
 */
int key_storage_backup(
    key_storage_ctx_t *ctx,
    const char *backup_path
);

/*
 * Restore from backup
 *
 * Returns: 0 on success, -1 on error
 */
int key_storage_restore(
    key_storage_ctx_t *ctx,
    const char *backup_path
);

/*
 * Verify storage integrity
 *
 * Checks all stored keys for corruption.
 *
 * Returns: 0 if all keys valid, -1 if corruption detected
 */
int key_storage_verify_integrity(key_storage_ctx_t *ctx);

/*
 * Free key data
 *
 * Securely wipes and frees key material.
 */
void key_storage_free_key(uint8_t *key_data, size_t key_len);

/*
 * Cleanup storage context
 */
void key_storage_cleanup(key_storage_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* KEY_STORAGE_H */
