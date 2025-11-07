/*
 * TLS Server - mTLS Server Implementation
 *
 * Provides secure TLS server with mutual authentication (mTLS)
 * for PKCS#11 over network communication.
 */

#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TLS Configuration */
typedef struct {
    const char *cert_file;      /* Server certificate file */
    const char *key_file;       /* Server private key file */
    const char *ca_file;        /* CA certificate for client verification */
    const char *ciphers;        /* Allowed cipher suites */
    uint16_t port;              /* Listen port */
    const char *bind_address;   /* Bind address (NULL = all interfaces) */
    bool require_client_cert;   /* Require client certificate (mTLS) */
    bool verify_client_cert;    /* Verify client certificate against CA */
    int max_clients;            /* Maximum number of concurrent clients */
    int session_timeout;        /* Session timeout in seconds */
} tls_server_config_t;

/* TLS Server Context */
typedef struct tls_server_ctx tls_server_ctx_t;

/* TLS Client Connection */
typedef struct {
    SSL *ssl;
    int socket_fd;
    char client_ip[46];         /* IPv4 or IPv6 address */
    uint16_t client_port;
    bool authenticated;
    void *user_data;            /* Application-specific data */
} tls_client_t;

/* Callback function types */
typedef int (*tls_client_handler_t)(tls_client_t *client, void *user_data);
typedef void (*tls_client_disconnect_t)(tls_client_t *client, void *user_data);
typedef bool (*tls_client_authorize_t)(tls_client_t *client, const char *subject_dn, void *user_data);

/*
 * Initialize TLS server context
 *
 * Returns: TLS server context on success, NULL on error
 */
tls_server_ctx_t *tls_server_init(const tls_server_config_t *config);

/*
 * Set client connection handler
 *
 * The handler is called when a new client connects and completes the TLS handshake.
 * Return 0 to accept the connection, non-zero to reject.
 */
void tls_server_set_client_handler(
    tls_server_ctx_t *ctx,
    tls_client_handler_t handler,
    void *user_data
);

/*
 * Set client disconnection handler
 *
 * Called when a client disconnects (gracefully or forcibly).
 */
void tls_server_set_disconnect_handler(
    tls_server_ctx_t *ctx,
    tls_client_disconnect_t handler,
    void *user_data
);

/*
 * Set client authorization callback
 *
 * Called after TLS handshake to authorize the client based on certificate DN.
 * Return true to accept, false to reject.
 */
void tls_server_set_authorize_handler(
    tls_server_ctx_t *ctx,
    tls_client_authorize_t handler,
    void *user_data
);

/*
 * Start TLS server (blocking)
 *
 * Starts listening for connections and handling clients.
 * This function blocks until tls_server_stop() is called from another thread.
 *
 * Returns: 0 on success, -1 on error
 */
int tls_server_start(tls_server_ctx_t *ctx);

/*
 * Stop TLS server
 *
 * Gracefully stops the server and closes all client connections.
 */
void tls_server_stop(tls_server_ctx_t *ctx);

/*
 * Cleanup TLS server context
 *
 * Frees all resources associated with the server.
 */
void tls_server_cleanup(tls_server_ctx_t *ctx);

/*
 * Send data to client
 *
 * Returns: Number of bytes sent, or -1 on error
 */
ssize_t tls_server_send(tls_client_t *client, const void *data, size_t len);

/*
 * Receive data from client
 *
 * Returns: Number of bytes received, 0 on EOF, or -1 on error
 */
ssize_t tls_server_recv(tls_client_t *client, void *buffer, size_t len);

/*
 * Get client certificate subject DN
 *
 * Returns: Subject DN string (must be freed by caller), or NULL on error
 */
char *tls_server_get_client_dn(tls_client_t *client);

/*
 * Check if client is authenticated
 */
bool tls_server_is_authenticated(tls_client_t *client);

/*
 * Get TLS version string
 */
const char *tls_server_get_version(tls_client_t *client);

/*
 * Get current cipher suite
 */
const char *tls_server_get_cipher(tls_client_t *client);

/*
 * Get last OpenSSL error as string
 */
const char *tls_server_get_error(void);

#ifdef __cplusplus
}
#endif

#endif /* TLS_SERVER_H */
