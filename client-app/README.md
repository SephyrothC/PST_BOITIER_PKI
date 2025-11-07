# PKI HSM Client Application

Client application for the PST PKI HSM system. Communicates with the HSM server via TLS/mTLS using the PKCS#11 protocol over a secure network connection.

## Features

- **TLS 1.3 with mTLS**: Secure communication with client certificate authentication
- **PKCS#11 Protocol**: Standard cryptographic token interface
- **Interactive CLI**: User-friendly command-line interface
- **Key Management**: Generate, list, and manage cryptographic keys
- **Signing Operations**: Sign and verify documents using HSM keys

## Quick Start

### Using Docker (Recommended)

```bash
# From project root
make shell-client

# Inside container
pki-client info
pki-client test
```

### Local Development

```bash
cd client-app

# Install dependencies
npm install

# Set environment variables
export HSM_HOST=172.20.0.10
export HSM_PORT=8443
export TLS_CERT=/opt/certs/client.crt
export TLS_KEY=/opt/certs/client.key
export TLS_CA=/opt/certs/ca.crt

# Run client
npm start info
npm start test
```

## Commands

### Connection Testing

```bash
# Display server configuration
pki-client info

# Test TLS connection
pki-client test
```

### Key Management (Coming Soon)

```bash
# Generate RSA key pair
pki-client generate-rsa --bits 2048 --label "MySigningKey"

# Generate EC key pair
pki-client generate-ec --curve P-256 --label "MyAuthKey"

# List all keys
pki-client list-keys
```

### Signing Operations (Coming Soon)

```bash
# Sign a file
pki-client sign --key "MySigningKey" --file document.pdf

# Verify signature
pki-client verify --key "MySigningKey" --file document.pdf --signature document.pdf.sig
```

## Configuration

Environment variables:

- `HSM_HOST`: HSM server hostname (default: `pki-hsm`)
- `HSM_PORT`: HSM server port (default: `8443`)
- `TLS_CERT`: Client certificate path
- `TLS_KEY`: Client private key path
- `TLS_CA`: CA certificate path

## Development

### Project Structure

```
client-app/
├── src/
│   ├── index.js          # Main entry point
│   ├── components/       # UI components
│   ├── services/         # PKCS#11 client services
│   └── utils/            # Utility functions
├── tests/                # Test files
├── package.json          # Dependencies
└── Dockerfile            # Docker image
```

### Adding New Commands

Edit `src/index.js` and add a new command using Commander.js:

```javascript
program
  .command('my-command')
  .description('My command description')
  .option('--param <value>', 'Parameter description')
  .action((options) => {
    // Implementation here
  });
```

### Testing

```bash
npm test
```

## Roadmap

- [ ] PKCS#11 protocol client implementation
- [ ] Key generation operations
- [ ] Signing and verification
- [ ] Certificate management
- [ ] Interactive mode with Inquirer
- [ ] GUI (Electron/Tauri)

## License

See root LICENSE file.
