#!/usr/bin/env node

/**
 * PST PKI HSM Client Application
 *
 * This is the main entry point for the client application that communicates
 * with the HSM server via TLS/mTLS using the PKCS#11 protocol.
 */

const { program } = require('commander');
const chalk = require('chalk');
const fs = require('fs');
const tls = require('tls');
require('dotenv').config();

// Configuration
const config = {
  hsmHost: process.env.HSM_HOST || 'pki-hsm',
  hsmPort: parseInt(process.env.HSM_PORT || '8443'),
  tlsCert: process.env.TLS_CERT || '/opt/certs/client.crt',
  tlsKey: process.env.TLS_KEY || '/opt/certs/client.key',
  tlsCa: process.env.TLS_CA || '/opt/certs/ca.crt',
};

// Display banner
console.log(chalk.blue.bold('\n╔════════════════════════════════════════╗'));
console.log(chalk.blue.bold('║   PST PKI HSM Client Application      ║'));
console.log(chalk.blue.bold('║   PKCS#11 Client over TLS             ║'));
console.log(chalk.blue.bold('╚════════════════════════════════════════╝\n'));

// Test TLS connection to HSM server
function testConnection() {
  console.log(chalk.yellow('Testing connection to HSM server...'));
  console.log(chalk.gray(`Host: ${config.hsmHost}:${config.hsmPort}`));

  // Check if certificates exist
  const certsExist = fs.existsSync(config.tlsCert) &&
                     fs.existsSync(config.tlsKey) &&
                     fs.existsSync(config.tlsCa);

  if (!certsExist) {
    console.log(chalk.red('✗ TLS certificates not found'));
    console.log(chalk.gray('  Expected locations:'));
    console.log(chalk.gray(`    - Client cert: ${config.tlsCert}`));
    console.log(chalk.gray(`    - Client key:  ${config.tlsKey}`));
    console.log(chalk.gray(`    - CA cert:     ${config.tlsCa}`));
    console.log(chalk.yellow('\n  Run: make certs (from project root)\n'));
    process.exit(1);
  }

  const options = {
    host: config.hsmHost,
    port: config.hsmPort,
    cert: fs.readFileSync(config.tlsCert),
    key: fs.readFileSync(config.tlsKey),
    ca: fs.readFileSync(config.tlsCa),
    rejectUnauthorized: true,
  };

  const socket = tls.connect(options, () => {
    if (socket.authorized) {
      console.log(chalk.green('✓ TLS connection established'));
      console.log(chalk.gray(`  Protocol: ${socket.getProtocol()}`));
      console.log(chalk.gray(`  Cipher:   ${socket.getCipher().name}`));
      socket.end();
      process.exit(0);
    } else {
      console.log(chalk.red('✗ TLS authorization failed'));
      console.log(chalk.red(`  Reason: ${socket.authorizationError}`));
      socket.destroy();
      process.exit(1);
    }
  });

  socket.on('error', (error) => {
    console.log(chalk.red('✗ Connection failed'));
    console.log(chalk.red(`  Error: ${error.message}`));
    process.exit(1);
  });

  socket.setTimeout(5000, () => {
    console.log(chalk.red('✗ Connection timeout'));
    socket.destroy();
    process.exit(1);
  });
}

// Display server information
function showInfo() {
  console.log(chalk.cyan('HSM Server Configuration:'));
  console.log(chalk.gray(`  Host:        ${config.hsmHost}`));
  console.log(chalk.gray(`  Port:        ${config.hsmPort}`));
  console.log(chalk.gray(`  Client Cert: ${config.tlsCert}`));
  console.log(chalk.gray(`  Client Key:  ${config.tlsKey}`));
  console.log(chalk.gray(`  CA Cert:     ${config.tlsCa}`));
  console.log();
}

// CLI commands
program
  .name('pki-client')
  .description('PKI HSM Client Application - PKCS#11 over TLS')
  .version('1.0.0');

program
  .command('info')
  .description('Display HSM server configuration')
  .action(showInfo);

program
  .command('test')
  .description('Test TLS connection to HSM server')
  .action(testConnection);

program
  .command('generate-rsa')
  .description('Generate RSA key pair on HSM')
  .option('--bits <size>', 'Key size in bits (2048, 4096)', '2048')
  .option('--label <label>', 'Key label', 'RSAKey')
  .action((options) => {
    console.log(chalk.yellow('⚠️  RSA key generation not yet implemented'));
    console.log(chalk.gray(`  Requested: ${options.bits}-bit RSA key with label "${options.label}"`));
    console.log(chalk.gray('  Status: Awaiting PKCS#11 protocol implementation\n'));
  });

program
  .command('generate-ec')
  .description('Generate EC key pair on HSM')
  .option('--curve <name>', 'Curve name (P-256, P-384, P-521)', 'P-256')
  .option('--label <label>', 'Key label', 'ECKey')
  .action((options) => {
    console.log(chalk.yellow('⚠️  EC key generation not yet implemented'));
    console.log(chalk.gray(`  Requested: ${options.curve} key with label "${options.label}"`));
    console.log(chalk.gray('  Status: Awaiting PKCS#11 protocol implementation\n'));
  });

program
  .command('list-keys')
  .description('List all keys on HSM')
  .action(() => {
    console.log(chalk.yellow('⚠️  Key listing not yet implemented'));
    console.log(chalk.gray('  Status: Awaiting PKCS#11 protocol implementation\n'));
  });

program
  .command('sign')
  .description('Sign a file with a key on HSM')
  .requiredOption('--key <label>', 'Key label')
  .requiredOption('--file <path>', 'File to sign')
  .option('--algorithm <alg>', 'Signature algorithm', 'RSA-PKCS')
  .action((options) => {
    console.log(chalk.yellow('⚠️  Signing not yet implemented'));
    console.log(chalk.gray(`  Key:       ${options.key}`));
    console.log(chalk.gray(`  File:      ${options.file}`));
    console.log(chalk.gray(`  Algorithm: ${options.algorithm}`));
    console.log(chalk.gray('  Status: Awaiting PKCS#11 protocol implementation\n'));
  });

program
  .command('verify')
  .description('Verify a signature')
  .requiredOption('--key <label>', 'Key label')
  .requiredOption('--file <path>', 'Original file')
  .requiredOption('--signature <path>', 'Signature file')
  .action((options) => {
    console.log(chalk.yellow('⚠️  Verification not yet implemented'));
    console.log(chalk.gray(`  Key:       ${options.key}`));
    console.log(chalk.gray(`  File:      ${options.file}`));
    console.log(chalk.gray(`  Signature: ${options.signature}`));
    console.log(chalk.gray('  Status: Awaiting PKCS#11 protocol implementation\n'));
  });

// Parse command line arguments
program.parse(process.argv);

// If no command provided, show help
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
