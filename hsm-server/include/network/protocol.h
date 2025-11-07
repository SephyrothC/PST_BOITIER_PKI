/*
 * PKCS#11 Network Protocol
 *
 * Defines the protocol for PKCS#11 operations over TLS network.
 */

#ifndef PKCS11_PROTOCOL_H
#define PKCS11_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include "pkcs11/pkcs11.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol version */
#define PKCS11_PROTO_VERSION_MAJOR 1
#define PKCS11_PROTO_VERSION_MINOR 0

/* Message types */
typedef enum {
    /* Control messages */
    MSG_HELLO = 0x01,
    MSG_GOODBYE = 0x02,
    MSG_PING = 0x03,
    MSG_PONG = 0x04,

    /* PKCS#11 function codes (0x10 - 0xFF) */
    MSG_C_INITIALIZE = 0x10,
    MSG_C_FINALIZE = 0x11,
    MSG_C_GET_INFO = 0x12,
    MSG_C_GET_SLOT_LIST = 0x13,
    MSG_C_GET_SLOT_INFO = 0x14,
    MSG_C_GET_TOKEN_INFO = 0x15,
    MSG_C_GET_MECHANISM_LIST = 0x16,
    MSG_C_GET_MECHANISM_INFO = 0x17,
    MSG_C_INIT_TOKEN = 0x18,
    MSG_C_INIT_PIN = 0x19,
    MSG_C_SET_PIN = 0x1A,

    MSG_C_OPEN_SESSION = 0x20,
    MSG_C_CLOSE_SESSION = 0x21,
    MSG_C_CLOSE_ALL_SESSIONS = 0x22,
    MSG_C_GET_SESSION_INFO = 0x23,
    MSG_C_LOGIN = 0x24,
    MSG_C_LOGOUT = 0x25,

    MSG_C_CREATE_OBJECT = 0x30,
    MSG_C_DESTROY_OBJECT = 0x31,
    MSG_C_GET_ATTRIBUTE_VALUE = 0x32,
    MSG_C_SET_ATTRIBUTE_VALUE = 0x33,
    MSG_C_FIND_OBJECTS_INIT = 0x34,
    MSG_C_FIND_OBJECTS = 0x35,
    MSG_C_FIND_OBJECTS_FINAL = 0x36,

    MSG_C_GENERATE_KEY_PAIR = 0x40,
    MSG_C_GENERATE_KEY = 0x41,
    MSG_C_GENERATE_RANDOM = 0x42,

    MSG_C_SIGN_INIT = 0x50,
    MSG_C_SIGN = 0x51,
    MSG_C_SIGN_UPDATE = 0x52,
    MSG_C_SIGN_FINAL = 0x53,

    MSG_C_VERIFY_INIT = 0x60,
    MSG_C_VERIFY = 0x61,
    MSG_C_VERIFY_UPDATE = 0x62,
    MSG_C_VERIFY_FINAL = 0x63,

    /* Response */
    MSG_RESPONSE = 0xF0,
    MSG_ERROR = 0xFF
} pkcs11_msg_type_t;

/* Message flags */
#define MSG_FLAG_REQUEST  0x01
#define MSG_FLAG_RESPONSE 0x02
#define MSG_FLAG_ERROR    0x04
#define MSG_FLAG_MORE     0x08  /* More data follows */

/* Message header (fixed size: 16 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t version_major;      /* Protocol version major */
    uint8_t version_minor;      /* Protocol version minor */
    uint8_t msg_type;           /* Message type */
    uint8_t flags;              /* Message flags */
    uint32_t msg_id;            /* Message ID (for request/response matching) */
    uint32_t session_handle;    /* PKCS#11 session handle */
    uint32_t data_length;       /* Length of data following header */
} pkcs11_msg_header_t;

/* Maximum message size (16 MB) */
#define PKCS11_MSG_MAX_SIZE (16 * 1024 * 1024)

/* Hello message payload */
typedef struct __attribute__((packed)) {
    uint8_t client_version_major;
    uint8_t client_version_minor;
    char client_name[64];
} pkcs11_hello_t;

/* Response message payload */
typedef struct __attribute__((packed)) {
    CK_RV rv;                   /* PKCS#11 return value */
    uint32_t data_length;       /* Length of response data */
    uint8_t data[];             /* Response data */
} pkcs11_response_t;

/* Protocol context */
typedef struct pkcs11_protocol_ctx pkcs11_protocol_ctx_t;

/*
 * Initialize protocol context
 */
pkcs11_protocol_ctx_t *pkcs11_protocol_init(void);

/*
 * Cleanup protocol context
 */
void pkcs11_protocol_cleanup(pkcs11_protocol_ctx_t *ctx);

/*
 * Create message header
 */
void pkcs11_msg_create_header(
    pkcs11_msg_header_t *header,
    uint8_t msg_type,
    uint8_t flags,
    uint32_t msg_id,
    uint32_t session_handle,
    uint32_t data_length
);

/*
 * Validate message header
 *
 * Returns: true if valid, false otherwise
 */
bool pkcs11_msg_validate_header(const pkcs11_msg_header_t *header);

/*
 * Send message
 *
 * Returns: 0 on success, -1 on error
 */
int pkcs11_msg_send(
    int socket_fd,
    const pkcs11_msg_header_t *header,
    const void *data
);

/*
 * Receive message
 *
 * Returns: 0 on success, -1 on error
 */
int pkcs11_msg_recv(
    int socket_fd,
    pkcs11_msg_header_t *header,
    void **data  /* Allocated buffer, must be freed by caller */
);

/*
 * Send response
 */
int pkcs11_msg_send_response(
    int socket_fd,
    uint32_t msg_id,
    CK_RV rv,
    const void *data,
    uint32_t data_len
);

/*
 * Send error
 */
int pkcs11_msg_send_error(
    int socket_fd,
    uint32_t msg_id,
    CK_RV rv,
    const char *error_message
);

/*
 * Serialize PKCS#11 attribute array
 *
 * Returns: Serialized buffer (must be freed by caller), NULL on error
 *          *out_len contains the serialized length
 */
uint8_t *pkcs11_serialize_attributes(
    const CK_ATTRIBUTE *attributes,
    CK_ULONG count,
    size_t *out_len
);

/*
 * Deserialize PKCS#11 attribute array
 *
 * Returns: Attribute array (must be freed by caller), NULL on error
 *          *out_count contains the number of attributes
 */
CK_ATTRIBUTE *pkcs11_deserialize_attributes(
    const uint8_t *data,
    size_t data_len,
    CK_ULONG *out_count
);

/*
 * Free deserialized attributes
 */
void pkcs11_free_attributes(CK_ATTRIBUTE *attributes, CK_ULONG count);

#ifdef __cplusplus
}
#endif

#endif /* PKCS11_PROTOCOL_H */
