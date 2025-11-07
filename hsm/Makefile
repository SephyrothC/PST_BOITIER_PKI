# Makefile for PST HSM PKCS#11 Library

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -std=c11 -D_GNU_SOURCE
CFLAGS += -Iinclude
LDFLAGS = -shared
LIBS = -lssl -lcrypto -lpthread

# Directories
SRC_DIR = src
BUILD_DIR = build
LIB_DIR = lib
BIN_DIR = bin

# Source files
PKCS11_SRCS = $(SRC_DIR)/pkcs11/pkcs11_impl.c \
              $(SRC_DIR)/pkcs11/session.c \
              $(SRC_DIR)/pkcs11/objects.c \
              $(SRC_DIR)/pkcs11/crypto_ops.c

CRYPTO_SRCS = $(SRC_DIR)/crypto/crypto_ops.c

STORAGE_SRCS = $(SRC_DIR)/storage/storage.c

UTILS_SRCS = $(SRC_DIR)/utils/utils.c

ALL_SRCS = $(PKCS11_SRCS) $(CRYPTO_SRCS) $(STORAGE_SRCS) $(UTILS_SRCS)

# Object files
OBJS = $(ALL_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Output library
LIBRARY = $(LIB_DIR)/libpst-pkcs11.so

# Targets
.PHONY: all clean install test directories

all: directories $(LIBRARY)

directories:
	@mkdir -p $(BUILD_DIR)/pkcs11
	@mkdir -p $(BUILD_DIR)/crypto
	@mkdir -p $(BUILD_DIR)/storage
	@mkdir -p $(BUILD_DIR)/utils
	@mkdir -p $(LIB_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p /var/lib/hsm/keys

$(LIBRARY): $(OBJS)
	@echo "Linking $@..."
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Library built successfully: $@"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(LIB_DIR) $(BIN_DIR)
	@echo "Clean complete."

install: $(LIBRARY)
	@echo "Installing library..."
	install -d /usr/local/lib/pkcs11
	install -m 755 $(LIBRARY) /usr/local/lib/pkcs11/
	ldconfig
	@echo "Installation complete."

uninstall:
	@echo "Uninstalling library..."
	rm -f /usr/local/lib/pkcs11/libpst-pkcs11.so
	ldconfig
	@echo "Uninstall complete."

# Build test program
test: directories $(LIBRARY) tests/test_basic.c
	@echo "Building test program..."
	$(CC) $(CFLAGS) -o $(BIN_DIR)/test_basic tests/test_basic.c -L$(LIB_DIR) -lpst-pkcs11 $(LIBS)
	@echo "Test program built: $(BIN_DIR)/test_basic"

# Show build info
info:
	@echo "PST HSM PKCS#11 Library Build Information"
	@echo "=========================================="
	@echo "CC:        $(CC)"
	@echo "CFLAGS:    $(CFLAGS)"
	@echo "LDFLAGS:   $(LDFLAGS)"
	@echo "LIBS:      $(LIBS)"
	@echo "SOURCES:   $(words $(ALL_SRCS)) files"
	@echo "OBJECTS:   $(words $(OBJS)) files"
	@echo "LIBRARY:   $(LIBRARY)"
	@echo ""

help:
	@echo "PST HSM PKCS#11 Library - Makefile Targets"
	@echo "==========================================="
	@echo ""
	@echo "  make                - Build the library"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make install        - Install library system-wide"
	@echo "  make uninstall      - Uninstall library"
	@echo "  make test           - Build and run tests"
	@echo "  make info           - Show build information"
	@echo "  make help           - Show this help message"
	@echo ""
