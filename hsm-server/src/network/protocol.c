/**
 * PKCS#11 Protocol - Stub Implementation
 *
 * This file provides stub implementations for the PKCS#11 network protocol.
 * TODO: Implement actual protocol handlers.
 */

#include "network/protocol.h"
#include <stdio.h>
#include <string.h>

// Stub implementation
int protocol_handle_message(const pkcs11_msg_header_t *header,
                           const uint8_t *data,
                           uint8_t **response,
                           size_t *response_len) {
    fprintf(stderr, "protocol_handle_message: Stub implementation\n");
    fprintf(stderr, "  Message type: 0x%02x\n", header->msg_type);
    fprintf(stderr, "  Message ID: %u\n", header->msg_id);
    fprintf(stderr, "  Data length: %u\n", header->data_length);

    (void)data;
    *response = NULL;
    *response_len = 0;

    return -1; // Not implemented
}

// Stub implementation
int protocol_send_response(int sock, const pkcs11_msg_header_t *header,
                          const uint8_t *data, size_t data_len) {
    fprintf(stderr, "protocol_send_response: Stub implementation (%zu bytes)\n", data_len);
    (void)sock;
    (void)header;
    (void)data;
    return -1; // Not implemented
}
