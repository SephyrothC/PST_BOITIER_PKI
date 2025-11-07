/*
 * Secure Storage Implementation
 */

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

/*
 * Initialize storage system
 */
CK_RV hsm_storage_init(void)
{
    /* Create storage directories if they don't exist */
    struct stat st = {0};

    if (stat(HSM_STORAGE_DIR, &st) == -1) {
        if (mkdir(HSM_STORAGE_DIR, 0700) != 0) {
            hsm_log(HSM_LOG_ERROR, "Failed to create storage directory: %s", strerror(errno));
            return CKR_DEVICE_ERROR;
        }
    }

    if (stat(HSM_KEY_STORAGE_DIR, &st) == -1) {
        if (mkdir(HSM_KEY_STORAGE_DIR, 0700) != 0) {
            hsm_log(HSM_LOG_ERROR, "Failed to create key storage directory: %s", strerror(errno));
            return CKR_DEVICE_ERROR;
        }
    }

    hsm_log(HSM_LOG_INFO, "Storage initialized at %s", HSM_STORAGE_DIR);
    return CKR_OK;
}

/*
 * Save token information to storage
 */
CK_RV hsm_storage_save_token_info(hsm_slot_t *slot)
{
    FILE *fp = fopen(HSM_TOKEN_FILE, "wb");
    if (!fp) {
        hsm_log(HSM_LOG_ERROR, "Failed to open token file for writing: %s", strerror(errno));
        return CKR_DEVICE_ERROR;
    }

    /* Write token info */
    fwrite(&slot->token_initialized, sizeof(bool), 1, fp);
    fwrite(&slot->user_pin_initialized, sizeof(bool), 1, fp);
    fwrite(&slot->so_pin_initialized, sizeof(bool), 1, fp);
    fwrite(slot->token_label, sizeof(slot->token_label), 1, fp);
    fwrite(slot->user_pin_hash, sizeof(slot->user_pin_hash), 1, fp);
    fwrite(slot->so_pin_hash, sizeof(slot->so_pin_hash), 1, fp);

    fclose(fp);
    chmod(HSM_TOKEN_FILE, 0600);

    hsm_log(HSM_LOG_DEBUG, "Token info saved");
    return CKR_OK;
}

/*
 * Load token information from storage
 */
CK_RV hsm_storage_load_token_info(hsm_slot_t *slot)
{
    FILE *fp = fopen(HSM_TOKEN_FILE, "rb");
    if (!fp) {
        /* File doesn't exist yet, that's OK */
        return CKR_OK;
    }

    /* Read token info */
    fread(&slot->token_initialized, sizeof(bool), 1, fp);
    fread(&slot->user_pin_initialized, sizeof(bool), 1, fp);
    fread(&slot->so_pin_initialized, sizeof(bool), 1, fp);
    fread(slot->token_label, sizeof(slot->token_label), 1, fp);
    fread(slot->user_pin_hash, sizeof(slot->user_pin_hash), 1, fp);
    fread(slot->so_pin_hash, sizeof(slot->so_pin_hash), 1, fp);

    fclose(fp);

    hsm_log(HSM_LOG_INFO, "Token info loaded");
    return CKR_OK;
}

/*
 * Save object to storage
 */
CK_RV hsm_storage_save_object(hsm_object_t *object)
{
    if (!object->is_token) {
        /* Session objects are not persisted */
        return CKR_OK;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/obj_%08lx.dat", HSM_KEY_STORAGE_DIR, (unsigned long)object->handle);

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        hsm_log(HSM_LOG_ERROR, "Failed to save object: %s", strerror(errno));
        return CKR_DEVICE_ERROR;
    }

    /* Write object metadata */
    fwrite(&object->handle, sizeof(CK_OBJECT_HANDLE), 1, fp);
    fwrite(&object->type, sizeof(hsm_object_type_t), 1, fp);
    fwrite(&object->is_token, sizeof(bool), 1, fp);
    fwrite(&object->is_private, sizeof(bool), 1, fp);
    fwrite(&object->is_sensitive, sizeof(bool), 1, fp);
    fwrite(&object->is_extractable, sizeof(bool), 1, fp);
    fwrite(object->label, sizeof(object->label), 1, fp);
    fwrite(object->id, sizeof(object->id), 1, fp);
    fwrite(&object->id_len, sizeof(size_t), 1, fp);
    fwrite(&object->key_type, sizeof(hsm_key_type_t), 1, fp);

    /* Write key-specific data */
    if (object->key_type == KEY_TYPE_RSA) {
        /* Write RSA key data */
        hsm_rsa_key_t *rsa = &object->key_data.rsa;
        fwrite(&rsa->bits, sizeof(uint32_t), 1, fp);
        fwrite(&rsa->modulus_len, sizeof(size_t), 1, fp);
        if (rsa->modulus_len > 0) fwrite(rsa->modulus, rsa->modulus_len, 1, fp);
        fwrite(&rsa->public_exponent_len, sizeof(size_t), 1, fp);
        if (rsa->public_exponent_len > 0) fwrite(rsa->public_exponent, rsa->public_exponent_len, 1, fp);

        /* For private keys, save private components (encrypted in production!) */
        if (object->type == OBJ_TYPE_PRIVATE_KEY) {
            fwrite(&rsa->private_exponent_len, sizeof(size_t), 1, fp);
            if (rsa->private_exponent_len > 0) fwrite(rsa->private_exponent, rsa->private_exponent_len, 1, fp);
            fwrite(&rsa->prime1_len, sizeof(size_t), 1, fp);
            if (rsa->prime1_len > 0) fwrite(rsa->prime1, rsa->prime1_len, 1, fp);
            fwrite(&rsa->prime2_len, sizeof(size_t), 1, fp);
            if (rsa->prime2_len > 0) fwrite(rsa->prime2, rsa->prime2_len, 1, fp);
            fwrite(&rsa->exponent1_len, sizeof(size_t), 1, fp);
            if (rsa->exponent1_len > 0) fwrite(rsa->exponent1, rsa->exponent1_len, 1, fp);
            fwrite(&rsa->exponent2_len, sizeof(size_t), 1, fp);
            if (rsa->exponent2_len > 0) fwrite(rsa->exponent2, rsa->exponent2_len, 1, fp);
            fwrite(&rsa->coefficient_len, sizeof(size_t), 1, fp);
            if (rsa->coefficient_len > 0) fwrite(rsa->coefficient, rsa->coefficient_len, 1, fp);
        }
    } else if (object->key_type == KEY_TYPE_EC) {
        /* Write EC key data */
        hsm_ec_key_t *ec = &object->key_data.ec;
        fwrite(&ec->curve_nid, sizeof(int), 1, fp);
        fwrite(&ec->ec_params_len, sizeof(size_t), 1, fp);
        if (ec->ec_params_len > 0) fwrite(ec->ec_params, ec->ec_params_len, 1, fp);
        fwrite(&ec->ec_point_len, sizeof(size_t), 1, fp);
        if (ec->ec_point_len > 0) fwrite(ec->ec_point, ec->ec_point_len, 1, fp);

        if (object->type == OBJ_TYPE_PRIVATE_KEY) {
            fwrite(&ec->ec_private_len, sizeof(size_t), 1, fp);
            if (ec->ec_private_len > 0) fwrite(ec->ec_private, ec->ec_private_len, 1, fp);
        }
    }

    fclose(fp);
    chmod(path, 0600);

    strcpy(object->storage_path, path);
    object->is_loaded = true;

    hsm_log(HSM_LOG_DEBUG, "Object 0x%08lx saved to %s", (unsigned long)object->handle, path);
    return CKR_OK;
}

/*
 * Load object from storage
 */
CK_RV hsm_storage_load_object(CK_OBJECT_HANDLE handle, hsm_object_t *object)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/obj_%08lx.dat", HSM_KEY_STORAGE_DIR, (unsigned long)handle);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    /* Read object metadata */
    fread(&object->handle, sizeof(CK_OBJECT_HANDLE), 1, fp);
    fread(&object->type, sizeof(hsm_object_type_t), 1, fp);
    fread(&object->is_token, sizeof(bool), 1, fp);
    fread(&object->is_private, sizeof(bool), 1, fp);
    fread(&object->is_sensitive, sizeof(bool), 1, fp);
    fread(&object->is_extractable, sizeof(bool), 1, fp);
    fread(object->label, sizeof(object->label), 1, fp);
    fread(object->id, sizeof(object->id), 1, fp);
    fread(&object->id_len, sizeof(size_t), 1, fp);
    fread(&object->key_type, sizeof(hsm_key_type_t), 1, fp);

    /* Read key-specific data (simplified - needs full implementation) */
    /* TODO: Implement full loading logic */

    fclose(fp);

    strcpy(object->storage_path, path);
    object->is_loaded = true;

    return CKR_OK;
}

/*
 * Delete object from storage
 */
CK_RV hsm_storage_delete_object(CK_OBJECT_HANDLE handle)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/obj_%08lx.dat", HSM_KEY_STORAGE_DIR, (unsigned long)handle);

    if (unlink(path) != 0 && errno != ENOENT) {
        hsm_log(HSM_LOG_ERROR, "Failed to delete object: %s", strerror(errno));
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

/*
 * List all stored objects
 */
CK_RV hsm_storage_list_objects(CK_OBJECT_HANDLE *handles, uint32_t *count)
{
    DIR *dir = opendir(HSM_KEY_STORAGE_DIR);
    if (!dir) {
        *count = 0;
        return CKR_OK;
    }

    uint32_t n = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && n < HSM_MAX_OBJECTS) {
        if (strncmp(entry->d_name, "obj_", 4) == 0) {
            unsigned long handle;
            if (sscanf(entry->d_name, "obj_%08lx.dat", &handle) == 1) {
                if (handles) {
                    handles[n] = (CK_OBJECT_HANDLE)handle;
                }
                n++;
            }
        }
    }

    closedir(dir);
    *count = n;

    return CKR_OK;
}
