/*
 * PST PKI HSM Server - Main Entry Point
 *
 * Docker-ready PKCS#11 HSM server with TLS support
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"
#include "network/tls_server.h"
#include "network/protocol.h"

/* Server configuration */
typedef struct {
    char *config_file;
    char *cert_file;
    char *key_file;
    char *ca_file;
    uint16_t port;
    char *bind_address;
    char *pin;
    bool foreground;
} server_config_t;

/* Global server state */
static bool g_running = true;
static tls_server_ctx_t *g_tls_server = NULL;

/*
 * Signal handler for graceful shutdown
 */
static void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM) {
        fprintf(stderr, "\nReceived shutdown signal, stopping server...\n");
        g_running = false;
        if (g_tls_server) {
            tls_server_stop(g_tls_server);
        }
    }
}

/*
 * Print usage information
 */
static void print_usage(const char *prog_name)
{
    printf("PST PKI HSM Server - PKCS#11 over TLS\n");
    printf("\n");
    printf("Usage: %s [options]\n", prog_name);
    printf("\n");
    printf("Options:\n");
    printf("  -c, --config FILE    Configuration file (default: /etc/pki-hsm/server.conf)\n");
    printf("  -p, --port PORT      Listen port (default: 8443)\n");
    printf("  -b, --bind ADDR      Bind address (default: 0.0.0.0)\n");
    printf("  --cert FILE          Server certificate file\n");
    printf("  --key FILE           Server private key file\n");
    printf("  --ca FILE            CA certificate file for client verification\n");
    printf("  --pin PIN            HSM PIN (or use HSM_PIN env var)\n");
    printf("  -f, --foreground     Run in foreground (don't daemonize)\n");
    printf("  -v, --verbose        Verbose logging\n");
    printf("  -h, --help           Show this help\n");
    printf("\n");
    printf("Environment variables:\n");
    printf("  HSM_PIN              HSM PIN for key encryption\n");
    printf("  TLS_CERT             Server certificate file\n");
    printf("  TLS_KEY              Server private key file\n");
    printf("  TLS_CA               CA certificate file\n");
    printf("  LOG_LEVEL            Logging level (ERROR, WARN, INFO, DEBUG)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --cert /opt/certs/server.crt --key /opt/certs/server.key --ca /opt/certs/ca.crt\n", prog_name);
    printf("  HSM_PIN=secret123 %s --port 8443\n", prog_name);
    printf("\n");
}

/*
 * Parse command line arguments
 */
static int parse_arguments(int argc, char **argv, server_config_t *config)
{
    static struct option long_options[] = {
        {"config",     required_argument, 0, 'c'},
        {"port",       required_argument, 0, 'p'},
        {"bind",       required_argument, 0, 'b'},
        {"cert",       required_argument, 0, 1},
        {"key",        required_argument, 0, 2},
        {"ca",         required_argument, 0, 3},
        {"pin",        required_argument, 0, 4},
        {"foreground", no_argument,       0, 'f'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Set defaults */
    config->config_file = strdup("/etc/pki-hsm/server.conf");
    config->port = 8443;
    config->bind_address = strdup("0.0.0.0");
    config->foreground = true;  /* Default to foreground in Docker */
    config->cert_file = NULL;
    config->key_file = NULL;
    config->ca_file = NULL;
    config->pin = NULL;

    /* Check environment variables */
    char *env_cert = getenv("TLS_CERT");
    char *env_key = getenv("TLS_KEY");
    char *env_ca = getenv("TLS_CA");
    char *env_pin = getenv("HSM_PIN");

    if (env_cert) config->cert_file = strdup(env_cert);
    if (env_key) config->key_file = strdup(env_key);
    if (env_ca) config->ca_file = strdup(env_ca);
    if (env_pin) config->pin = strdup(env_pin);

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "c:p:b:fvh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                free(config->config_file);
                config->config_file = strdup(optarg);
                break;
            case 'p':
                config->port = atoi(optarg);
                break;
            case 'b':
                free(config->bind_address);
                config->bind_address = strdup(optarg);
                break;
            case 1:  /* --cert */
                if (config->cert_file) free(config->cert_file);
                config->cert_file = strdup(optarg);
                break;
            case 2:  /* --key */
                if (config->key_file) free(config->key_file);
                config->key_file = strdup(optarg);
                break;
            case 3:  /* --ca */
                if (config->ca_file) free(config->ca_file);
                config->ca_file = strdup(optarg);
                break;
            case 4:  /* --pin */
                if (config->pin) free(config->pin);
                config->pin = strdup(optarg);
                break;
            case 'f':
                config->foreground = true;
                break;
            case 'v':
                /* Set verbose logging */
                setenv("LOG_LEVEL", "DEBUG", 1);
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    /* Validate required options */
    if (!config->cert_file || !config->key_file || !config->ca_file) {
        fprintf(stderr, "Error: TLS certificates required (--cert, --key, --ca)\n");
        fprintf(stderr, "Or set environment variables: TLS_CERT, TLS_KEY, TLS_CA\n");
        return -1;
    }

    if (!config->pin) {
        fprintf(stderr, "Error: HSM PIN required (--pin or HSM_PIN environment variable)\n");
        return -1;
    }

    return 0;
}

/*
 * Main function
 */
int main(int argc, char **argv)
{
    server_config_t config;
    CK_RV rv;

    printf("========================================\n");
    printf("PST PKI HSM Server v1.0.0\n");
    printf("PKCS#11 v2.40 over TLS\n");
    printf("========================================\n\n");

    /* Parse arguments */
    if (parse_arguments(argc, argv, &config) != 0) {
        return 1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Initialize PKCS#11 library */
    printf("[1/3] Initializing PKCS#11 library...\n");
    CK_FUNCTION_LIST_PTR pFunctionList;
    rv = C_GetFunctionList(&pFunctionList);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error: Failed to get PKCS#11 function list: 0x%08lX\n", (unsigned long)rv);
        return 1;
    }

    rv = pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error: Failed to initialize PKCS#11: 0x%08lX\n", (unsigned long)rv);
        return 1;
    }
    printf("✓ PKCS#11 initialized\n\n");

    /* Initialize TLS server */
    printf("[2/3] Initializing TLS server...\n");
    printf("  Certificate: %s\n", config.cert_file);
    printf("  Private key: %s\n", config.key_file);
    printf("  CA cert: %s\n", config.ca_file);
    printf("  Port: %u\n", config.port);
    printf("  Bind: %s\n", config.bind_address);

    tls_server_config_t tls_config = {
        .cert_file = config.cert_file,
        .key_file = config.key_file,
        .ca_file = config.ca_file,
        .ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
        .port = config.port,
        .bind_address = config.bind_address,
        .require_client_cert = true,
        .verify_client_cert = true,
        .max_clients = 10,
        .session_timeout = 300
    };

    g_tls_server = tls_server_init(&tls_config);
    if (!g_tls_server) {
        fprintf(stderr, "Error: Failed to initialize TLS server\n");
        pFunctionList->C_Finalize(NULL);
        return 1;
    }
    printf("✓ TLS server initialized\n\n");

    /* Start server */
    printf("[3/3] Starting server...\n");
    printf("  Listening on %s:%u\n", config.bind_address, config.port);
    printf("  mTLS enabled (client certificates required)\n");
    printf("  Press Ctrl+C to stop\n\n");

    printf("========================================\n");
    printf("Server ready! Waiting for connections...\n");
    printf("========================================\n\n");

    /* Run server (blocking) */
    int ret = tls_server_start(g_tls_server);

    /* Cleanup */
    printf("\nShutting down...\n");
    tls_server_cleanup(g_tls_server);

    rv = pFunctionList->C_Finalize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "Warning: C_Finalize failed: 0x%08lX\n", (unsigned long)rv);
    }

    /* Free config */
    free(config.config_file);
    free(config.bind_address);
    if (config.cert_file) free(config.cert_file);
    if (config.key_file) free(config.key_file);
    if (config.ca_file) free(config.ca_file);
    if (config.pin) free(config.pin);

    printf("Server stopped.\n");

    return ret == 0 ? 0 : 1;
}
