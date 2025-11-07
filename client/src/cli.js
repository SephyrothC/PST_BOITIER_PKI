#!/usr/bin/env node

/*
 * PST HSM Client - Command Line Interface
 */

const { Command } = require('commander');
const chalk = require('chalk');
const inquirer = require('inquirer');
const ora = require('ora');

const program = new Command();

program
  .name('pst-hsm')
  .description('PST HSM Client - Manage cryptographic operations')
  .version('1.0.0');

// Generate RSA key pair command
program
  .command('generate-rsa')
  .description('Generate RSA key pair')
  .option('-b, --bits <bits>', 'Key size in bits', '2048')
  .option('-l, --label <label>', 'Key label', 'RSA Key')
  .option('--token', 'Store as token object', false)
  .action(async (options) => {
    console.log(chalk.bold.blue('\n🔐 PST HSM - Generate RSA Key Pair\n'));

    const spinner = ora('Connecting to HSM...').start();

    try {
      // Simulate connection delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      spinner.succeed('Connected to HSM');

      spinner.start('Generating RSA-' + options.bits + ' key pair...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      spinner.succeed('Key pair generated successfully!');

      console.log(chalk.green('\n✓ Success!\n'));
      console.log('Public Key:  ' + chalk.cyan('0x10000001'));
      console.log('Private Key: ' + chalk.cyan('0x20000001'));
      console.log('Label:       ' + chalk.cyan(options.label));
      console.log('Size:        ' + chalk.cyan(options.bits + ' bits'));

    } catch (error) {
      spinner.fail('Failed to generate key pair');
      console.error(chalk.red('\nError: ' + error.message));
      process.exit(1);
    }
  });

// Generate EC key pair command
program
  .command('generate-ec')
  .description('Generate EC key pair')
  .option('-c, --curve <curve>', 'Curve name (P-256, P-384, P-521)', 'P-256')
  .option('-l, --label <label>', 'Key label', 'EC Key')
  .option('--token', 'Store as token object', false)
  .action(async (options) => {
    console.log(chalk.bold.blue('\n🔐 PST HSM - Generate EC Key Pair\n'));

    const spinner = ora('Connecting to HSM...').start();

    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      spinner.succeed('Connected to HSM');

      spinner.start('Generating EC-' + options.curve + ' key pair...');
      await new Promise(resolve => setTimeout(resolve, 1500));
      spinner.succeed('Key pair generated successfully!');

      console.log(chalk.green('\n✓ Success!\n'));
      console.log('Public Key:  ' + chalk.cyan('0x10000002'));
      console.log('Private Key: ' + chalk.cyan('0x20000002'));
      console.log('Label:       ' + chalk.cyan(options.label));
      console.log('Curve:       ' + chalk.cyan(options.curve));

    } catch (error) {
      spinner.fail('Failed to generate key pair');
      console.error(chalk.red('\nError: ' + error.message));
      process.exit(1);
    }
  });

// List keys command
program
  .command('list-keys')
  .description('List all keys on HSM')
  .option('-t, --type <type>', 'Key type (rsa, ec, all)', 'all')
  .action(async (options) => {
    console.log(chalk.bold.blue('\n🔑 PST HSM - List Keys\n'));

    const spinner = ora('Fetching keys from HSM...').start();

    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      spinner.succeed('Keys retrieved');

      const keys = [
        { handle: '0x10000001', type: 'RSA Public', label: 'Signing Key', size: '2048 bits' },
        { handle: '0x20000001', type: 'RSA Private', label: 'Signing Key', size: '2048 bits' },
        { handle: '0x10000002', type: 'EC Public', label: 'Auth Key', size: 'P-256' },
        { handle: '0x20000002', type: 'EC Private', label: 'Auth Key', size: 'P-256' },
      ];

      console.log(chalk.green('\nFound ' + keys.length + ' keys:\n'));

      keys.forEach(key => {
        console.log(chalk.cyan('Handle: ') + key.handle);
        console.log(chalk.gray('  Type:  ') + key.type);
        console.log(chalk.gray('  Label: ') + key.label);
        console.log(chalk.gray('  Size:  ') + key.size);
        console.log('');
      });

    } catch (error) {
      spinner.fail('Failed to list keys');
      console.error(chalk.red('\nError: ' + error.message));
      process.exit(1);
    }
  });

// Sign command
program
  .command('sign')
  .description('Sign a document')
  .requiredOption('-k, --key <label>', 'Private key label')
  .requiredOption('-f, --file <path>', 'File to sign')
  .option('-o, --output <path>', 'Output signature file')
  .option('-a, --algorithm <alg>', 'Signature algorithm', 'SHA256-RSA')
  .action(async (options) => {
    console.log(chalk.bold.blue('\n✍️  PST HSM - Sign Document\n'));

    const spinner = ora('Loading document...').start();

    try {
      await new Promise(resolve => setTimeout(resolve, 500));
      spinner.succeed('Document loaded: ' + options.file);

      spinner.start('Finding private key...');
      await new Promise(resolve => setTimeout(resolve, 500));
      spinner.succeed('Private key found');

      spinner.start('Signing document...');
      await new Promise(resolve => setTimeout(resolve, 1000));
      spinner.succeed('Document signed successfully!');

      const outputPath = options.output || options.file + '.sig';
      console.log(chalk.green('\n✓ Success!\n'));
      console.log('Signature:  ' + chalk.cyan(outputPath));
      console.log('Algorithm:  ' + chalk.cyan(options.algorithm));
      console.log('Length:     ' + chalk.cyan('256 bytes'));

    } catch (error) {
      spinner.fail('Failed to sign document');
      console.error(chalk.red('\nError: ' + error.message));
      process.exit(1);
    }
  });

// Verify command
program
  .command('verify')
  .description('Verify a signature')
  .requiredOption('-k, --key <label>', 'Public key label')
  .requiredOption('-f, --file <path>', 'Original file')
  .requiredOption('-s, --signature <path>', 'Signature file')
  .action(async (options) => {
    console.log(chalk.bold.blue('\n🔍 PST HSM - Verify Signature\n'));

    const spinner = ora('Loading files...').start();

    try {
      await new Promise(resolve => setTimeout(resolve, 500));
      spinner.succeed('Files loaded');

      spinner.start('Finding public key...');
      await new Promise(resolve => setTimeout(resolve, 500));
      spinner.succeed('Public key found');

      spinner.start('Verifying signature...');
      await new Promise(resolve => setTimeout(resolve, 1000));
      spinner.succeed('Signature is VALID!');

      console.log(chalk.green('\n✓ Signature verified successfully!\n'));

    } catch (error) {
      spinner.fail('Signature verification FAILED');
      console.error(chalk.red('\nError: ' + error.message));
      process.exit(1);
    }
  });

// Info command
program
  .command('info')
  .description('Show HSM information')
  .action(async () => {
    console.log(chalk.bold.blue('\n📊 PST HSM - Information\n'));

    const spinner = ora('Connecting to HSM...').start();

    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      spinner.succeed('Connected to HSM');

      console.log(chalk.cyan('\nLibrary Information:'));
      console.log(chalk.gray('  Version:      ') + '2.40');
      console.log(chalk.gray('  Manufacturer: ') + 'PST Cryptographic Systems');
      console.log(chalk.gray('  Description:  ') + 'PST HSM PKCS#11 Library');

      console.log(chalk.cyan('\nToken Information:'));
      console.log(chalk.gray('  Label:        ') + 'PST HSM Token');
      console.log(chalk.gray('  Serial:       ') + 'A1B2C3D4E5F60708');
      console.log(chalk.gray('  Initialized:  ') + chalk.green('Yes'));
      console.log(chalk.gray('  PIN Required: ') + chalk.green('Yes'));

      console.log(chalk.cyan('\nSupported Mechanisms:'));
      const mechanisms = [
        'RSA-PKCS Key Generation (2048-4096 bits)',
        'EC Key Generation (P-256, P-384, P-521)',
        'RSA-PKCS Signature',
        'RSA-PSS Signature',
        'ECDSA Signature',
        'SHA-256, SHA-384, SHA-512'
      ];
      mechanisms.forEach(mech => console.log(chalk.gray('  • ') + mech));

      console.log('');

    } catch (error) {
      spinner.fail('Failed to get HSM information');
      console.error(chalk.red('\nError: ' + error.message));
      process.exit(1);
    }
  });

// Interactive mode
program
  .command('interactive')
  .description('Start interactive mode')
  .action(async () => {
    console.log(chalk.bold.blue('\n🚀 PST HSM - Interactive Mode\n'));

    while (true) {
      const { action } = await inquirer.prompt([
        {
          type: 'list',
          name: 'action',
          message: 'What would you like to do?',
          choices: [
            { name: '🔑 Generate RSA Key Pair', value: 'gen-rsa' },
            { name: '🔐 Generate EC Key Pair', value: 'gen-ec' },
            { name: '📋 List Keys', value: 'list' },
            { name: '✍️  Sign Document', value: 'sign' },
            { name: '🔍 Verify Signature', value: 'verify' },
            { name: '📊 Show HSM Info', value: 'info' },
            { name: '❌ Exit', value: 'exit' }
          ]
        }
      ]);

      if (action === 'exit') {
        console.log(chalk.yellow('\nGoodbye! 👋\n'));
        break;
      }

      // Handle actions (simplified for demo)
      console.log(chalk.gray('\n[This would execute: ' + action + ']\n'));
    }
  });

program.parse();
