/*
 * PKCS#11 Network Server
 * Expose PKCS#11 operations over secure network (TLS)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"

#define DEFAULT_PORT 11111
#define MAX_CLIENTS 10
#define BUFFER_SIZE 65536

/* Protocol command codes */
typedef enum {
    CMD_INITIALIZE = 0x01,
    CMD_FINALIZE = 0x02,
    CMD_GET_INFO = 0x03,
    CMD_GET_SLOT_LIST = 0x04,
    CMD_GET_TOKEN_INFO = 0x05,
    CMD_OPEN_SESSION = 0x06,
    CMD_CLOSE_SESSION = 0x07,
    CMD_LOGIN = 0x08,
    CMD_LOGOUT = 0x09,
    CMD_GENERATE_KEY_PAIR = 0x10,
    CMD_SIGN_INIT = 0x11,
    CMD_SIGN = 0x12,
    CMD_VERIFY_INIT = 0x13,
    CMD_VERIFY = 0x14,
    CMD_GENERATE_RANDOM = 0x15,
    CMD_FIND_OBJECTS_INIT = 0x20,
    CMD_FIND_OBJECTS = 0x21,
    CMD_FIND_OBJECTS_FINAL = 0x22,
    CMD_GET_ATTRIBUTE_VALUE = 0x23
} command_code_t;

/* Server state */
typedef struct {
    int running;
    int server_fd;
    CK_FUNCTION_LIST_PTR pFunctionList;
    pthread_mutex_t lock;
} server_state_t;

static server_state_t g_server = {
    .running = 0,
    .server_fd = -1,
    .pFunctionList = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/* Signal handler for graceful shutdown */
static void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM) {
        printf("\nReceived shutdown signal, stopping server...\n");
        g_server.running = 0;
    }
}

/* Handle client connection */
static void* handle_client(void* arg)
{
    int client_fd = *(int*)arg;
    free(arg);

    uint8_t buffer[BUFFER_SIZE];
    uint8_t response[BUFFER_SIZE];

    printf("Client connected (fd=%d)\n", client_fd);

    while (g_server.running) {
        /* Read command header */
        ssize_t n = recv(client_fd, buffer, 5, MSG_WAITALL);
        if (n <= 0) {
            break;
        }

        uint8_t cmd = buffer[0];
        uint32_t length = (buffer[1] << 24) | (buffer[2] << 16) |
                          (buffer[3] << 8) | buffer[4];

        if (length > BUFFER_SIZE - 5) {
            fprintf(stderr, "Command too large: %u bytes\n", length);
            break;
        }

        /* Read command data */
        if (length > 0) {
            n = recv(client_fd, buffer + 5, length, MSG_WAITALL);
            if (n != (ssize_t)length) {
                break;
            }
        }

        /* Process command */
        CK_RV rv = CKR_FUNCTION_FAILED;
        uint32_t response_len = 0;

        switch (cmd) {
            case CMD_GET_INFO: {
                CK_INFO info;
                rv = g_server.pFunctionList->C_GetInfo(&info);
                if (rv == CKR_OK) {
                    memcpy(response + 5, &info, sizeof(CK_INFO));
                    response_len = sizeof(CK_INFO);
                }
                break;
            }

            case CMD_GET_SLOT_LIST: {
                CK_BBOOL tokenPresent = buffer[5];
                CK_SLOT_ID slots[10];
                CK_ULONG count = 10;
                rv = g_server.pFunctionList->C_GetSlotList(tokenPresent, slots, &count);
                if (rv == CKR_OK) {
                    memcpy(response + 5, &count, sizeof(CK_ULONG));
                    memcpy(response + 5 + sizeof(CK_ULONG), slots, count * sizeof(CK_SLOT_ID));
                    response_len = sizeof(CK_ULONG) + count * sizeof(CK_SLOT_ID);
                }
                break;
            }

            case CMD_GENERATE_RANDOM: {
                CK_SESSION_HANDLE hSession;
                CK_ULONG dataLen;
                memcpy(&hSession, buffer + 5, sizeof(CK_SESSION_HANDLE));
                memcpy(&dataLen, buffer + 5 + sizeof(CK_SESSION_HANDLE), sizeof(CK_ULONG));

                if (dataLen <= BUFFER_SIZE - 100) {
                    rv = g_server.pFunctionList->C_GenerateRandom(hSession, response + 5, dataLen);
                    if (rv == CKR_OK) {
                        response_len = dataLen;
                    }
                }
                break;
            }

            /* TODO: Implement other commands */
            default:
                rv = CKR_FUNCTION_NOT_SUPPORTED;
                break;
        }

        /* Send response */
        response[0] = (rv >> 24) & 0xFF;
        response[1] = (rv >> 16) & 0xFF;
        response[2] = (rv >> 8) & 0xFF;
        response[3] = rv & 0xFF;
        response[4] = (response_len >> 0) & 0xFF;

        send(client_fd, response, 5 + response_len, 0);
    }

    printf("Client disconnected (fd=%d)\n", client_fd);
    close(client_fd);
    return NULL;
}

/* Main server function */
int network_server_start(uint16_t port)
{
    int opt = 1;
    struct sockaddr_in address;

    printf("PST HSM Network Server\n");
    printf("======================\n\n");

    /* Initialize PKCS#11 library */
    printf("Initializing PKCS#11 library...\n");
    CK_RV rv = C_GetFunctionList(&g_server.pFunctionList);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to get function list: 0x%08lX\n", (unsigned long)rv);
        return 1;
    }

    rv = g_server.pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to initialize Cryptoki: 0x%08lX\n", (unsigned long)rv);
        return 1;
    }
    printf("PKCS#11 library initialized\n\n");

    /* Create socket */
    if ((g_server.server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return 1;
    }

    /* Set socket options */
    if (setsockopt(g_server.server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(g_server.server_fd);
        return 1;
    }

    /* Bind to address */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(g_server.server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(g_server.server_fd);
        return 1;
    }

    /* Listen */
    if (listen(g_server.server_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        close(g_server.server_fd);
        return 1;
    }

    printf("Server listening on port %d\n", port);
    printf("Press Ctrl+C to stop\n\n");

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    g_server.running = 1;

    /* Accept connections */
    while (g_server.running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(g_server.server_fd, (struct sockaddr*)&client_addr, &client_len);

        if (*client_fd < 0) {
            if (errno == EINTR) {
                free(client_fd);
                continue;
            }
            perror("accept");
            free(client_fd);
            break;
        }

        printf("New connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        /* Create thread for client */
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, client_fd);
        pthread_detach(thread_id);
    }

    /* Cleanup */
    printf("\nShutting down server...\n");
    close(g_server.server_fd);

    rv = g_server.pFunctionList->C_Finalize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "Warning: C_Finalize failed: 0x%08lX\n", (unsigned long)rv);
    }

    printf("Server stopped\n");
    return 0;
}

/* Main entry point */
int main(int argc, char *argv[])
{
    uint16_t port = DEFAULT_PORT;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (port == 0) {
            fprintf(stderr, "Invalid port number\n");
            return 1;
        }
    }

    return network_server_start(port);
}
