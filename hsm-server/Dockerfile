FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    openssl \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source code
COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/
COPY tests/ ./tests/

# Build
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) && \
    make install

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /usr/local/bin/pki-hsm-server /usr/local/bin/
COPY --from=builder /usr/local/lib/libpki-pkcs11.so /usr/local/lib/

# Run ldconfig to update library cache
RUN ldconfig

# Create directories
RUN mkdir -p /var/lib/pki-hsm/keys \
             /var/lib/pki-hsm/config \
             /var/log/pki-hsm

# Create non-root user
RUN useradd -r -s /bin/false -d /var/lib/pki-hsm hsm-user && \
    chown -R hsm-user:hsm-user /var/lib/pki-hsm /var/log/pki-hsm

# Switch to non-root user
USER hsm-user

# Expose TLS port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD timeout 2 sh -c 'echo > /dev/tcp/localhost/8443' 2>/dev/null || exit 1

WORKDIR /var/lib/pki-hsm

CMD ["/usr/local/bin/pki-hsm-server", \
     "--config", "/etc/pki-hsm/server.conf", \
     "--cert", "/opt/certs/server.crt", \
     "--key", "/opt/certs/server.key", \
     "--ca", "/opt/certs/ca.crt", \
     "--port", "8443"]
