cmake_minimum_required(VERSION 3.16)
project(pki-hsm VERSION 1.0.0 LANGUAGES C)

# C Standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror=implicit-function-declaration")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# Find required packages
find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Source files for PKCS#11 library
set(PKCS11_SOURCES
    src/pkcs11/pkcs11_impl.c
    src/pkcs11/session.c
    src/pkcs11/objects.c
    src/pkcs11/crypto_ops.c
    src/crypto/crypto_engine.c
    src/storage/key_storage.c
    src/utils/utils.c
)

# Source files for network server
set(SERVER_SOURCES
    src/network/network_server.c
    src/network/tls_server.c
    src/network/protocol.c
    src/main.c
)

# Build shared library for PKCS#11
add_library(pki-pkcs11 SHARED ${PKCS11_SOURCES})
target_link_libraries(pki-pkcs11
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Set library version
set_target_properties(pki-pkcs11 PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "include/pkcs11/pkcs11.h"
)

# Build server executable
add_executable(pki-hsm-server ${SERVER_SOURCES})
target_link_libraries(pki-hsm-server
    pki-pkcs11
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    m
)

# Installation
install(TARGETS pki-pkcs11 pki-hsm-server
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/pkcs11
)

# Install additional headers
install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Tests (optional)
option(BUILD_TESTS "Build test programs" ON)
if(BUILD_TESTS)
    enable_testing()

    add_executable(test_crypto tests/test_crypto.c)
    target_link_libraries(test_crypto pki-pkcs11)
    add_test(NAME test_crypto COMMAND test_crypto)

    add_executable(test_pkcs11 tests/test_pkcs11.c)
    target_link_libraries(test_pkcs11 pki-pkcs11)
    add_test(NAME test_pkcs11 COMMAND test_pkcs11)
endif()

# Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
endif()

# Print configuration summary
message(STATUS "=== PST PKI HSM Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C Flags: ${CMAKE_C_FLAGS}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Build tests: ${BUILD_TESTS}")
message(STATUS "================================")
