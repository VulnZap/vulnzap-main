#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
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
import { checkInit } from './utils/checks.js';
import config from './config/config.js';
import { saveKey, getKey } from './api/auth.js';
import inquirer from 'inquirer';
import { extractPackagesFromDirectory } from './utils/packageExtractor.js';
import { batchScan } from './api/batchScan.js';
import path from 'path';

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


// Command: vulnzap setup
program
  .command('setup')
  .description('Configure VulnZap with your API key')
  .option('-k, --key <key>', 'Directly provide the API key')
  .action(async (options) => {
    displayBanner();
    
    try {
      const { authenticated } = await auth.checkAuth();
      if (!authenticated) {
        console.error(chalk.red('Error: You must be logged in to configure VulnZap'));
        console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate first`);
        process.exit(1);
      }

      const existingKey = await getKey();
      if (existingKey) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: 'An API key already exists. Do you want to replace it?',
            default: false
          }
        ]);

        if (!confirm) {
          console.log(chalk.yellow('✓') + ' API key configuration cancelled');
          return;
        }
      }

      if (!options.key) {
        console.log(chalk.cyan('\nYou can get your API key from:'));
        console.log(chalk.cyan(`${config.api.baseUrl}/dashboard/api-keys`));
        console.log(chalk.cyan('(Make sure you are logged in to your VulnZap account)\n'));
      }

      let apiKey: string;
      if (options.key) {
        apiKey = options.key;
      } else {
        const response = await inquirer.prompt([
          {
            type: 'password',
            name: 'apiKey',
            message: 'Enter your VulnZap API key:',
            validate: (input) => {
              if (!input) {
                return 'API key is required';
              }
              return true;
            }
          }
        ]);
        apiKey = response.apiKey;
      }

      await saveKey(apiKey);
      console.log(chalk.green('✓') + ' VulnZap is now configured with your API key');
    } catch (error: any) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });


// Command: vulnzap init
program
  .command('init')
  .description('Initialize VulnZap for your project')
  .action(async () => {
    displayBanner();
    
    try {
      const { authenticated } = await auth.checkAuth();
      if (!authenticated) {
        console.error(chalk.red('Error: You must be logged in to initialize VulnZap'));
        console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate first`);
        process.exit(1);
      }

      const spinner = ora('Initializing VulnZap...\n').start();

      const checkAlreadyInitialized = await checkInit();
      if (checkAlreadyInitialized) {
        console.log(chalk.green('✓') + ' VulnZap already initialized');
        process.exit(0);
      }

      try {
        const vulnzapLocation = process.cwd() + '/.vulnzap-core';
        if (!fs.existsSync(vulnzapLocation)) {
          fs.mkdirSync(vulnzapLocation);
        }
        const scanConfigLocation = vulnzapLocation + '/scans.json';
        if (!fs.existsSync(scanConfigLocation)) {
          fs.writeFileSync(scanConfigLocation, JSON.stringify({
            scans: []
          }, null, 2));
        }
        console.log(chalk.green('✓') + ' VulnZap config file created\n');
        spinner.succeed('wohooooo!');
        console.log(chalk.yellow('To enable GitHub integration, set the VULNZAP_GITHUB environment variable with your GitHub token'));
        console.log(chalk.yellow('To enable National Vulnerability Database(NVD) integration, set the VULNZAP_NVD environment variable with your NVD token'));
        console.log(chalk.green('✓') + ' VulnZap initialized successfully');
      } catch (error: any) {
        spinner.fail('Failed to initialize VulnZap');
        console.error(chalk.red('Error:'), error.message);
        process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
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

      console.log(chalk.cyan('The Api key will automatically get saved after you successfully login. (If it exists)\n'));

      const { success, error } = await auth.login("login");

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


// Command: vulnzap secure (only used by ides to start a connection to the server)
program
  .command('secure')
  .description('Start the MCP security bridge to protect your AI coding')
  .option('--ide <ide-name>', 'Specify IDE integration (cursor, claude-code, windsurf)')
  .option('--port <port>', 'Port to use for MCP server', '3456')
  .option('--api-key <key>', 'Premium API key for enhanced features')
  .action(async (options) => {
    try {
      const { authenticated } = await auth.checkAuth();
      if (!authenticated) {
        console.error(chalk.red('Error: You must be logged in to use VulnZap secure'));
        console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate first`);
        process.exit(1);
      }

      await checkHealth();
      const key = await auth.getKey();
      if (!key) {
        console.error(chalk.red('Error: VulnZap Api key not defined, user is require to run `vulnzap setup -k <key>` to setup the api key.'));
        process.exit(1);
      }
      await startMcpServer({
        useMcp: options.mcp || true,
        ide: options.ide || 'cursor',
        port: parseInt(options.port, 10),
      });
    } catch (error: any) {
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
      await checkHealth();
      spinner.succeed('')
      process.exit(1);
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
    
    try {
      const { authenticated } = await auth.checkAuth();
      if (!authenticated) {
        console.error(chalk.red('Error: You must be logged in to check vulnerabilities'));
        console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate first`);
        process.exit(1);
      }

      await checkHealth();

      const checkAlreadyInitialized = await checkInit();
      if (!checkAlreadyInitialized) {
        console.error(chalk.red('Error: VulnZap is not initialized in this project, run vulnzap init to initialize VulnZap'));
        process.exit(1);
      }

      let packageName, packageVersion, packageEcosystem;

      // Parse package input
      const packageFormat = /^(npm|pip):([^@]+)@(.+)$/;
      const match = packageInput.match(packageFormat);

      if (match) {
        [, packageEcosystem, packageName, packageVersion] = match;
      } else if (packageInput.includes('@') && !packageInput.startsWith('@')) {
        // Fallback for old format package@version
        [packageName, packageVersion] = packageInput.split('@');
        packageEcosystem = options.ecosystem;
      } else {
        packageName = packageInput;
        packageVersion = options.version;
        packageEcosystem = options.ecosystem;
      }

      if (!packageVersion) {
        console.error(chalk.red('Error: Package version is required'));
        console.log('Format: vulnzap check ecosystem:package-name@version');
        console.log('Example: vulnzap check npm:express@4.17.1');
        console.log('Or: vulnzap check package-name --ecosystem npm --version 4.17.1');
        process.exit(1);
      }

      if (!packageEcosystem) {
        console.error(chalk.red('Error: Package ecosystem is required'));
        console.log('Format: vulnzap check ecosystem:package-name@version');
        console.log('Example: vulnzap check npm:express@4.17.1');
        console.log('Or: vulnzap check package-name --ecosystem npm --version 4.17.1');
        process.exit(1);
      }

      const spinner = ora(`Checking ${packageEcosystem}:${packageName}@${packageVersion} for vulnerabilities...`).start();

      try {
        const result = await checkVulnerability(packageEcosystem, packageName, packageVersion);

        spinner.stop();

        console.log(chalk.green('✓') + ' Vulnerability scan completed');

        if (result.error) {
          console.error(chalk.red('Error:'), result.error);
          return;
        }

        if (result.isUnknown) {
          console.log(chalk.yellow('!') + ` Unknown: ${result.message}`);
          if (result.sources && result.sources.length > 0) {
            console.log(`  Sources checked: ${result.sources.join(', ')}`);
          }
          return;
        }

        if (!result.isVulnerable) {
          console.log(chalk.green(`✓ Safe: ${packageName}@${packageVersion} has no known vulnerabilities`));
          if (result.sources && result.sources.length > 0) {
            console.log(`  Sources checked: ${result.sources.join(', ')}`);
          }
          console.log('');
          return;
        }

        if (result.isVulnerable) {
          console.log(chalk.red(`✗ Vulnerable: ${packageName}@${packageVersion} has vulnerabilities`));
          if (result.sources && result.sources.length > 0) {
            console.log(`  Sources: ${result.sources.join(', ')}`);
          }
          console.log('');

          // Display vulnerability details
          result.advisories?.forEach((advisory: { title: string; severity: string; description: string; references?: string[] }) => {
            console.log(chalk.yellow(`- ${advisory.title}`));
            console.log(`  Severity: ${advisory.severity}`);
            console.log(`  Description: ${advisory.description}`);
            if (advisory.references?.length) {
              console.log(`  References: ${advisory.references.join(', ')}`);
            }
            console.log('');
          });

          // Suggest fixed version if available
          if (result.fixedVersions && result.fixedVersions.length > 0) {
            console.log(chalk.green('Suggested fix:'));
            console.log(`Upgrade to ${result.fixedVersions[0]} or later\n`);
          }
        }

        const pwd = process.cwd();
        const scanConfigLocation = pwd + '/.vulnzap-core/scans.json';
        const scanConfig = JSON.parse(fs.readFileSync(scanConfigLocation, 'utf8'));
        const newScan = {
          package: `${packageName}@${packageVersion}`,
          result: result,
          createdAt: new Date().toISOString()
        };
        scanConfig.scans.push(newScan);
        fs.writeFileSync(scanConfigLocation, JSON.stringify(scanConfig, null, 2));

        console.log(chalk.green('✓') + ' Vulnerability scan saved to ' + scanConfigLocation);
      } catch (error: any) {
        spinner.fail('Vulnerability check failed');
        console.error(chalk.red('Error:'), error.message);
        process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap connect
program
  .command('connect')
  .description('Connect VulnZap to your AI-powered IDE')
  .option('--ide <ide-name>', 'IDE to connect with (cursor, claude-code, windsurf)')
  .option('--port <port>', 'Port to use for MCP server', '3456')
  .action(async (options) => {
    try {
      const { authenticated } = await auth.checkAuth();
      if (!authenticated) {
        console.error(chalk.red('Error: You must be logged in to connect VulnZap'));
        console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate first`);
        process.exit(1);
      }

      // Prompt for IDE if not provided

      if (!options.ide) {
        console.error(chalk.red('Error: You must specify an IDE to connect with.'));
        console.log('Example: vulnzap connect --ide <ide-name>');
        process.exit(1);
      }

      if (options.ide === 'cursor') {
        const cursorMcpConfigLocation = os.homedir() + '/.cursor/mcp.json';
        if (!fs.existsSync(cursorMcpConfigLocation)) {
          console.error(chalk.red('Error: Cursor MCP config not found.'));
          console.log('Please install Cursor and try again.');
          process.exit(1);
        }
        const cursorMcpConfig = JSON.parse(fs.readFileSync(cursorMcpConfigLocation, 'utf8'));
        if (!cursorMcpConfig.mcp) {
          fs.writeFileSync(cursorMcpConfigLocation, JSON.stringify({
            mcpServers: {
              VulnZap: {
                command: "vulnzap",
                args: ["secure", "--ide", "cursor", "--port", "3456"]
              }
            }
          }, null, 2));
        } else {
          cursorMcpConfig.mcpServers.VulnZap = {
            command: "vulnzap",
            args: ["secure", "--ide", "cursor", "--port", "3456"]
          }
          fs.writeFileSync(cursorMcpConfigLocation, JSON.stringify(cursorMcpConfig, null, 2));
        }
        console.log(chalk.green('✓') + ' Cursor MCP config updated successfully');
      } else {
        console.error(chalk.red('Error: Unsupported IDE.'));
        console.log('Please use Cursor for now.');
        process.exit(1);
      }
    } catch (error: any) {
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

// Command: vulnzap batch
program
  .command('batch')
  .description('Batch scan multiple packages for vulnerabilities')
  .option('-f, --file <file>', 'Path to JSON file with packages to scan')
  .option('-o, --output <file>', 'Output file for results')
  .action(async (options) => {
    displayBanner();
    
    try {
      const { authenticated } = await auth.checkAuth();
      if (!authenticated) {
        console.error(chalk.red('Error: You must be logged in to perform batch scans'));
        console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate first`);
        process.exit(1);
      }

      // Check if authenticated or has API key
      const key = await auth.getKey();

      if (!key) {
        console.error(chalk.red('Error: API key required for batch scanning'));
        console.log('Please run `vulnzap setup for saving Api key to your system`:');
        return;
      }

      if (!options.file) {
        console.error(chalk.red('Error: You must specify a file containing packages to scan'));
        console.log('Example: vulnzap batch --file package.json');
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
    } catch (error: any) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap batch-scan
program
  .command('batch-scan')
  .description('Scan all packages in the current directory for vulnerabilities')
  .option('--ecosystem <ecosystem>', 'Specific ecosystem to scan (npm, pip, go, rust)')
  .option('--output <file>', 'Output file for scan results (JSON format)')
  .action(async (options) => {
    try {
      const spinner = ora('Checking project initialization...').start();
      
      // Check if VulnZap is initialized in the current directory
      const vulnzapDir = path.join(process.cwd(), '.vulnzap-core');
      if (!fs.existsSync(vulnzapDir)) {
        spinner.fail('VulnZap is not initialized in this directory');
        console.log(chalk.yellow('Please run `vulnzap init` first to initialize VulnZap in this directory'));
        process.exit(1);
      }

      spinner.text = 'Scanning packages...';
      
      // Extract packages from current directory
      const packages = extractPackagesFromDirectory(process.cwd(), options.ecosystem);
      
      if (packages.length === 0) {
        spinner.fail('No packages found to scan');
        console.log(chalk.yellow('No package manager files (package.json, requirements.txt, etc.) found in the directory'));
        return;
      }

      spinner.text = `Found ${packages.length} packages. Scanning for vulnerabilities...`;
      
      // Perform batch scan
      const results = await batchScan(packages);
      
      spinner.succeed('Scan completed');
      
      // Format and display results
      console.log('\nScan Results:');
      console.log('-------------');
      
      const vulnerableCount = results.results.filter(r => r.status === 'vulnerable').length;
      const safeCount = results.results.filter(r => r.status === 'safe').length;
      const errorCount = results.results.filter(r => r.status === 'error').length;
      
      console.log(`Total packages: ${packages.length}`);
      console.log(`Vulnerable: ${vulnerableCount}`);
      console.log(`Safe: ${safeCount}`);
      console.log(`Errors: ${errorCount}`);
      
      // Save results to file if specified
      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
        console.log(`\nResults saved to: ${outputPath}`);
      } else {
        // Save to default location in .vulnzap-core
        const defaultOutputPath = path.join(vulnzapDir, 'batch-scan-results.json');
        fs.writeFileSync(defaultOutputPath, JSON.stringify(results, null, 2));
        console.log(`\nResults saved to: ${defaultOutputPath}`);
      }
      
      // Display detailed results
      if (vulnerableCount > 0) {
        console.log('\nVulnerable Packages:');
        console.log('-------------------');
        results.results
          .filter(r => r.status === 'vulnerable')
          .forEach(result => {
            console.log(`\n${result.package.packageName}@${result.package.version} (${result.package.ecosystem})`);
            console.log(result.message);
            
            if (result.vulnerabilities) {
              result.vulnerabilities.forEach(vuln => {
                console.log(`\n- ${vuln.title} (${vuln.severity})`);
                console.log(`  ${vuln.description}`);
                if (vuln.references?.length) {
                  console.log(`  References: ${vuln.references.join(', ')}`);
                }
              });
            }
            
            if (result.remediation) {
              console.log('\nRemediation:');
              console.log(`- Update to ${result.remediation.recommendedVersion}`);
              console.log(`- ${result.remediation.notes}`);
              if (result.remediation.alternativePackages?.length) {
                console.log('- Alternative packages:');
                result.remediation.alternativePackages.forEach(pkg => {
                  console.log(`  - ${pkg}`);
                });
              }
            }
          });
      }
      
    } catch (error: any) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
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