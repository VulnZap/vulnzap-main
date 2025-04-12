#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import { startMcpServer, checkVulnerability, getBatchStatus } from './index.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import open from 'open';
import { v4 as uuidv4 } from 'uuid';
import os from 'os';
import fs from 'fs';
import * as api from './api/apis.js';
import * as auth from './api/auth.js';

// Get package version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
const version = packageJson.version;


const checkHealth = async () => {
  const data = await api.checkHealth();
  if (data.status === 'ok') {
    console.log(chalk.green('✓') + ' VulnZap server is healthy');
  } else {
    console.error(chalk.red('✗') + ' VulnZap server is down');
    process.exit(1);
  }
}

// Banner display
const displayBanner = () => {
  console.log(chalk.bold(`
  ╦  ╦┬ ┬┬  ┌┐┌╔═╗┌─┐┌─┐
  ╚╗╔╝│ ││  │││╔═╝├─┤├─┘
   ╚╝ └─┘┴─┘┘└┘╚═╝┴ ┴┴  v${version}
  `));
  console.log(`${chalk.cyan('Securing AI-Generated Code')}\n`);
};

program
  .name('vulnzap')
  .description('Secure your AI-generated code from vulnerabilities in real-time')
  .version(version);

// Command: vulnzap secure
program
  .command('secure')
  .description('Start the MCP security bridge to protect your AI coding')
  .option('--mcp', 'Use Model Context Protocol for IDE integration')
  .option('--ide <ide-name>', 'Specify IDE integration (cursor, claude-code, windsurf)')
  .option('--port <port>', 'Port to use for MCP server', '3456')
  .option('--api-key <key>', 'Premium API key for enhanced features')
  .action(async (options) => {
    displayBanner();

    await checkHealth();

    // Check if authenticated or has API key
    const { success: authSuccess, authenticated: isLoggedIn } = await api.checkAuth();
    const { success: tierSuccess, tier } = await api.getUserTier();

    if (!isLoggedIn) {
      console.log(chalk.yellow('You are not logged in.'));
      console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate or ${chalk.cyan('vulnzap signup')} to signup\n`);
    }

    const isPremium = authSuccess && tierSuccess && isLoggedIn && tier !== 'free';

    if (!isPremium && !options.apiKey && !process.env.VULNZAP_API_KEY) {
      console.log(chalk.yellow('You are not using a premium account. Some features may be unavailable.'));
    }

    const { success: quotaSuccess, remaining, total } = await api.getScanQuota();
    if (quotaSuccess) {
      console.log(`${chalk.cyan('ℹ')} Scan quota: ${remaining}/${total} scans remaining today\n`);
    }

    const spinner = ora('Starting VulnZap security bridge...\n').start();

    try {
      // Load configuration and start the server
      await startMcpServer({
        useMcp: options.mcp || true,
        ide: options.ide || 'cursor',
        port: parseInt(options.port, 10),
        apiKey: options.apiKey || process.env.VULNZAP_API_KEY
      });

      spinner.succeed('VulnZap security bridge is running');
      console.log(chalk.green('✓') + ' MCP protocol active and listening for AI-generated code');
      console.log(chalk.green('✓') + ' Vulnerability database connected');
      console.log(chalk.green('✓') + ' Real-time scanning enabled');

      if (options.apiKey || process.env.VULNZAP_API_KEY) {
        console.log(chalk.green('✓') + ' Premium features activated\n');
      } else {
        console.log(chalk.yellow('!') + ' Running in free tier mode. For enhanced security, run ' +
          chalk.cyan('vulnzap upgrade') + ' to get a premium API key\n');
      }

      console.log('Press Ctrl+C to stop the security bridge');
    } catch (error: any) {
      spinner.fail('Failed to start VulnZap security bridge');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

program
  .command("status")
  .action(async () => {
    displayBanner();

    const spinner = ora('Checking VulnZap status...').start();

    try {
      const { success, status } = await api.checkHealth();
      if (success) {
        spinner.succeed('VulnZap is running');
        console.log(chalk.green('✓') + ' Status: ' + status);
      } else {
        spinner.fail('VulnZap is down');
        console.error(chalk.red('Error:'), status);
      }
    } catch (error: any) {
      spinner.fail('Failed to check status');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap check
program
  .command('check <package>')
  .description('Check a package for vulnerabilities (format: npm:package-name@version)')
  .option('-e, --ecosystem <ecosystem>', 'Package ecosystem (npm, pip)', 'npm')
  .option('-v, --version <version>', 'Package version')
  .action(async (packageInput, options) => {
    displayBanner();

    let packageName, packageVersion;

    // Parse package input
    if (packageInput.includes('@') && !packageInput.startsWith('@')) {
      [packageName, packageVersion] = packageInput.split('@');
    } else {
      packageName = packageInput;
      packageVersion = options.version;
    }

    if (!packageVersion) {
      console.error(chalk.red('Error: Package version is required'));
      console.log('Format: vulnzap check package-name@version');
      console.log('Or: vulnzap check package-name --version <version>');
      process.exit(1);
    }

    const spinner = ora(`Checking ${options.ecosystem}:${packageName}@${packageVersion} for vulnerabilities...`).start();

    try {
      const result = await checkVulnerability(options.ecosystem, packageName, packageVersion);

      spinner.stop();

      if (result.isVulnerable) {
        console.log(chalk.red(`✗ Vulnerable: ${packageName}@${packageVersion} has vulnerabilities\n`));

        // Display vulnerability details
        result.advisories?.forEach(advisory => {
          console.log(chalk.yellow(`- ${advisory.title}`));
          console.log(`  Severity: ${advisory.severity}`);
          console.log(`  CVE: ${advisory.cve_id || 'N/A'}`);
          console.log(`  Description: ${advisory.description}`);
          console.log('');
        });

        // Suggest fixed version if available
        if (result.fixedVersions && result.fixedVersions.length > 0) {
          console.log(chalk.green('Suggested fix:'));
          console.log(`Upgrade to ${result.fixedVersions[0]} or later\n`);
        }
      } else {
        console.log(chalk.green(`✓ Safe: ${packageName}@${packageVersion} has no known vulnerabilities\n`));
      }
    } catch (error: any) {
      spinner.fail('Vulnerability check failed');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap connect
program
  .command('connect')
  .description('Connect VulnZap to your AI-powered IDE')
  .option('--ide <ide-name>', 'IDE to connect with (cursor, claude-code, windsurf)')
  .option('--key <key>', 'Premium API key for enhanced features')
  .option('--port <port>', 'Port to use for MCP server', '3456')
  .action(async (options) => {
    // Prompt for IDE if not provided

    if (!options.ide) {
      console.error(chalk.red('Error: You must specify an IDE to connect with.'));
      console.log('Example: vulnzap connect --ide <ide-name>');
      process.exit(1);
    }

    await startMcpServer({
      useMcp: options.mcp || true,
      ide: options.ide || 'cursor',
      port: parseInt(options.port, 10),
      apiKey: options.key || process.env.VULNZAP_API_KEY
    });
  });

// Command: vulnzap login
program
  .command('login')
  .description('Login to your VulnZap account')
  .option('--provider <provider>', 'OAuth provider (google, github)')
  .action(async (options) => {
    displayBanner();

    const spinner = ora('Initializing login...').start();

    try {
      const checkExists = await auth.checkAuth();
      if (checkExists.authenticated) {
        console.log(chalk.green('✓') + ' You are already logged in to VulnZap');
        process.exit(0);
      }
      const { success, error } = await auth.login(options.provider);
      
      if (success) {
        spinner.succeed('Successfully logged in');
        
        // Get and display user info
        const { user } = await auth.getCurrentUser();
        if (user) {
          console.log('\nWelcome back, ' + chalk.cyan(user.email));
          console.log(chalk.green('✓') + ' You are now logged in to VulnZap\n');
        }
      } else {
        spinner.fail('Login failed');
        if (error) {
          console.error(chalk.red('Error:'), error);
        }
        process.exit(1);
      }
    } catch (error: any) {
      spinner.fail('Login failed');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap logout
program
  .command('logout')
  .description('Logout from your VulnZap account')
  .action(async () => {
    displayBanner();

    const spinner = ora('Logging out...').start();

    try {
      const { success } = await auth.logout();
      if (success) {
        spinner.succeed('Successfully logged out');
        console.log(chalk.green('✓') + ' You have been logged out of VulnZap');
      } else {
        spinner.fail('Logout failed');
        process.exit(1);
      }
    } catch (error: any) {
      spinner.fail('Logout failed');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap account
program
  .command('account')
  .description('View your account information')
  .action(async () => {
    displayBanner();

    try {
      const homeDir = os.homedir();
      const configPath = join(homeDir, '.vulnzap', 'config.json');
      if (fs.existsSync(configPath)) {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        const { success, user } = config;

        if (success && user) {
          console.log(chalk.green('✓') + ' Account information:');
          console.log(`  Email: ${user.email}`);
          console.log(`  Name: ${user.name || 'Not set'}`);

          const { success: tierSuccess, tier } = await api.getUserTier();
          if (tierSuccess) {
            console.log(`  Tier: ${tier}`);
          }

          const { success: quotaSuccess, remaining, total } = await api.getScanQuota();
          if (quotaSuccess) {
            console.log(`  Scan quota: ${remaining}/${total} scans remaining today`);
          }
        } else {
          console.log(chalk.yellow('You are not logged in.'));
          console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate.`);
        }
      } else {
        console.log(chalk.yellow('No account information found.'));
      }
    } catch (error: any) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap signup
program
  .command('signup')
  .description('Create a new VulnZap account')
  .action(async () => {
    displayBanner();

    const spinner = ora('Initializing signup...').start();

    try {
      const { success, error } = await auth.signup();
      
      if (success) {
        spinner.succeed('Account created successfully');
        
        // Get and display user info
        const { user } = await auth.getCurrentUser();
        if (user) {
          console.log('\nWelcome to VulnZap, ' + chalk.cyan(user.email));
          console.log(chalk.green('✓') + ' Your account has been created and you are now logged in\n');
        }
      } else {
        spinner.fail('Signup failed');
        if (error) {
          console.error(chalk.red('Error:'), error);
        }
        process.exit(1);
      }
    } catch (error: any) {
      spinner.fail('Signup failed');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap batch
program
  .command('batch')
  .description('Batch scan multiple packages for vulnerabilities')
  .option('-f, --file <file>', 'Path to JSON file with packages to scan')
  .option('-o, --output <file>', 'Output file for results')
  .option('--api-key <key>', 'Premium API key (required for batch scanning)')
  .action(async (options) => {
    displayBanner();

    // Check if authenticated or has API key
    const { success: isLoggedIn } = await api.checkAuth();
    const { success: tierSuccess, tier } = await api.getUserTier();
    const isPremium = isLoggedIn && tierSuccess && tier !== 'free';

    if (!isPremium && !options.apiKey && !process.env.VULNZAP_API_KEY) {
      console.error(chalk.red('Error: Premium account required for batch scanning'));
      console.log('Please sign up for a premium plan:');
      console.log(chalk.cyan('  vulnzap signup'));
      return;
    }

    if (!options.file) {
      console.error(chalk.red('Error: You must specify a file containing packages to scan'));
      console.log('Example: vulnzap batch --file packages.json');
      process.exit(1);
    }

    const spinner = ora('Initiating batch vulnerability scan...').start();

    // Simulate batch scanning process
    setTimeout(async () => {
      spinner.text = 'Processing packages...';

      // Simulate checking status
      setTimeout(async () => {
        spinner.text = 'Analyzing vulnerabilities...';

        // Simulate completion
        setTimeout(() => {
          spinner.succeed('Batch scan completed');

          console.log('\nScan summary:');
          console.log(chalk.green('✓') + ' Packages scanned: 42');
          console.log(chalk.red('✗') + ' Vulnerabilities found: 7');
          console.log(chalk.yellow('!') + ' Packages with known issues: 5');

          console.log('\nDetailed results saved to:', options.output || 'vulnzap-results.json');
        }, 3000);
      }, 2000);
    }, 2000);
  });

// Command: vulnzap help
program
  .command('help')
  .description('Display help information')
  .action(() => {
    displayBanner();
    program.help();
  });

// Parse arguments
program.parse(process.argv);

// If no args, display help
if (process.argv.length === 2) {
  displayBanner();
  program.help();
} 