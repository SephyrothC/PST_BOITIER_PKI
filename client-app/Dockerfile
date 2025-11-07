# Multi-stage Dockerfile for PKI HSM Client Application
#
# This Dockerfile creates a development environment for the client application
# that communicates with the HSM server via TLS/mTLS.

FROM node:20-bookworm-slim AS base

# Install development tools and OpenSSL
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    openssl \
    ca-certificates \
    curl \
    git && \
    rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy package files (will create them next)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application source
COPY . .

# Development stage
FROM base AS development

# Set environment variables
ENV NODE_ENV=development
ENV HSM_HOST=pki-hsm
ENV HSM_PORT=8443

# Expose port for development server (if GUI is added later)
EXPOSE 3000

# Default command for development
CMD ["npm", "run", "dev"]

# Production stage
FROM base AS production

# Install production dependencies only
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application
COPY --from=base /app /app

# Create non-root user
RUN useradd -r -u 1001 -g root pki-client && \
    chown -R pki-client:root /app

USER pki-client

ENV NODE_ENV=production

# Default command
CMD ["node", "src/index.js"]
