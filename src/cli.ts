#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { startMcpServer, checkVulnerability, checkBatch } from './index.js';
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
import { execSync } from 'child_process';
import { cacheService } from './services/cache.js';

// Get package version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
const version = packageJson.version;

const checkHealth = async () => {
  try {
    const data = await api.checkHealth();
    if (data.status === 'ok') {
      return true;
    } else {
      throw new Error('SERVER_DOWN');
    }
  } catch (err) {
    throw new Error('SERVER_DOWN');
  }
}

// Ensure .vulnzap folder exists in the user's home directory
const ensureVulnzapFolder = () => {
  const vulnzapHomeDir = join(os.homedir(), '.vulnzap');
  if (!fs.existsSync(vulnzapHomeDir)) {
    fs.mkdirSync(vulnzapHomeDir, { recursive: true });
  }
};
ensureVulnzapFolder();

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
  .option('--ide <ide-name>', 'Specify IDE integration (cursor, windsurf, cline)')
  .action(async (options) => {
    displayBanner();
    
    try {
      // Check if API key already exists
      let existingKey;
      try {
        existingKey = await getKey();
      } catch (error) {
        // API key doesn't exist, which is fine
        existingKey = null;
      }

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
          
          // If user doesn't want to replace API key but provided --ide flag, still proceed with IDE connection
          if (options.ide) {
            console.log(chalk.cyan('\nProceeding with IDE connection...'));
            await connectIDE(options.ide);
          }
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

      // If IDE flag is provided, proceed with IDE connection
      if (options.ide) {
        console.log(chalk.cyan('\nConnecting to IDE...'));
        await connectIDE(options.ide);
      }

    } catch (error: any) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap init
program
  .command('init')
  .description('Complete VulnZap onboarding - setup authentication and IDE integration')
  .action(async () => {
    // Handle Ctrl+C gracefully
    const handleExit = () => {
      console.log(chalk.yellow('\n\nSetup cancelled by user. You can run `vulnzap init` again anytime.'));
      process.exit(0);
    };
    
    process.on('SIGINT', handleExit);
    process.on('SIGTERM', handleExit);

    try {
      displayBanner();
      console.log(chalk.cyan('Welcome to VulnZap! Let\'s get you set up.\n'));

      // Step 1: Welcome and options
      const { welcomeChoice } = await inquirer.prompt([
        {
          type: 'list',
          name: 'welcomeChoice',
          message: 'How would you like to proceed?',
          choices: [
            { name: '🌐 Visit vulnzap.com to learn more', value: 'visit' },
            { name: '🚀 Continue with setup here', value: 'proceed' }
          ],
          default: 'proceed'
        }
      ]);

      if (welcomeChoice === 'visit') {
        console.log(chalk.cyan('\n🌐 Visit vulnzap.com to learn more'));
        process.exit(0);
      }

      // Step 2: Check if already authenticated
      let existingKey;
      try {
        existingKey = await getKey();
      } catch (error) {
        existingKey = null;
      }

      if (existingKey) {
        console.log(chalk.green('✓ API key already configured'));
        
        const { replaceKey } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'replaceKey',
            message: 'Would you like to re-authenticate with a new account?',
            default: false
          }
        ]);

        if (!replaceKey) {
          console.log(chalk.cyan('Using existing authentication...'));
        } else {
          existingKey = null; // Force re-authentication
        }
      }

      // Step 3: Authentication flow
      if (!existingKey) {
        console.log(chalk.cyan('\n🔐 Setting up authentication...'));
        console.log(chalk.gray('You\'ll be redirected to your browser for secure login.'));
        
        const spinner = ora('Initializing authentication...').start();

        try {
          spinner.text = 'Opening browser for authentication...';
          
          const { success, error } = await auth.login("login");

          if (success) {
            spinner.succeed(chalk.green('✓ Authentication successful!'));
          } else {
            spinner.fail('Authentication failed');
            if (error) {
              console.error(chalk.red('Error:'), error);
            }
            console.log(chalk.yellow('\nYou can also manually set up your API key:'));
            console.log(chalk.cyan('1. Visit https://vulnzap.com/dashboard/api-keys'));
            console.log(chalk.cyan('2. Copy your API key'));
            console.log(chalk.cyan('3. Run: vulnzap setup -k <your-api-key>'));
            process.exit(1);
          }
        } catch (error: any) {
          spinner.fail('Authentication failed');
          console.error(chalk.red('Error:'), error.message);
          console.log(chalk.yellow('\nFallback: You can manually set up your API key:'));
          console.log(chalk.cyan('1. Visit https://vulnzap.com/dashboard/api-keys'));
          console.log(chalk.cyan('2. Copy your API key'));
          console.log(chalk.cyan('3. Run: vulnzap setup -k <your-api-key>'));
          process.exit(1);
        }
      }

      // Step 4: IDE Selection and Configuration
      console.log(chalk.cyan('\n🔧 Setting up IDE integration...'));
      
      const { selectedIde } = await inquirer.prompt([
        {
          type: 'list',
          name: 'selectedIde',
          message: 'Which IDE are you using?',
          choices: [
            { name: '🎯 Cursor IDE', value: 'cursor' },
            { name: '🌊 Windsurf IDE', value: 'windsurf' },
            { name: '🤖 Cline (VS Code Extension)', value: 'cline' },
            { name: '🔍 Other (Manual Configuration)', value: 'other' }
          ],
          default: 'cursor'
        }
      ]);

      const ideSpinner = ora(`Configuring ${selectedIde} integration...`).start();
      
      try {
        await connectIDE(selectedIde);
        ideSpinner.succeed(`✓ ${selectedIde} integration configured successfully!`);

        // Step 5: Success and next steps
        console.log(chalk.green('\n🎉 VulnZap setup completed successfully!\n'));
        console.log(chalk.cyan('What\'s next?'));
        console.log('• VulnZap is now protecting your AI-generated code');
        console.log('• Start coding in your IDE - vulnerabilities will be caught automatically');
        console.log('• Check detailed logs and analytics at: https://vulnzap.com/dashboard/logs');
        console.log('• Run `vulnzap check <package>` to manually scan packages');
        console.log('• Run `vulnzap status` to verify everything is working\n');
        
        console.log(chalk.gray('Need help? Visit https://vulnzap.com/docs or run `vulnzap help`'));
      } catch (error: any) {
        ideSpinner.fail(`Failed to configure ${selectedIde} integration`);
        console.error(chalk.red('Error:'), error.message);
        console.log(chalk.yellow(`\nYou can manually configure ${selectedIde} later by running:`));
        console.log(chalk.cyan(`vulnzap connect --ide ${selectedIde}`));
      }

    } catch (error: any) {
      console.error(chalk.red('\nSetup failed:'), error.message);
      console.log(chalk.yellow('\nYou can:'));
      console.log('• Run `vulnzap init` again to retry');
      console.log('• Run `vulnzap setup` for manual configuration');
      console.log('• Visit https://vulnzap.com/support for help');
      process.exit(1);
    } finally {
      // Remove signal handlers
      process.removeListener('SIGINT', handleExit);
      process.removeListener('SIGTERM', handleExit);
    }
  });

// Command: vulnzap login (Disabled for now)
// program
//   .command('login')
//   .description('Login to your VulnZap account')
//   .option('--provider <provider>', 'OAuth provider (google, github)')
//   .action(async (options) => {
//     displayBanner();

//     const spinner = ora('Initializing login...').start();

//     try {
//       const checkExists = await auth.checkAuth();
//       if (checkExists.authenticated) {
//         console.log(chalk.green('✓') + ' You are already logged in to VulnZap');
//         process.exit(0);
//       }

//       console.log(chalk.cyan('The Api key will automatically get saved after you successfully login. (If it exists)\n'));

//       const { success, error } = await auth.login("login");

//       if (success) {
//         spinner.succeed(chalk.green('✓') + ' You are now logged in to VulnZap\n');
//       } else {
//         spinner.fail('Login failed');
//         if (error) {
//           console.error(chalk.red('Error:'), error);
//         }
//         process.exit(1);
//       }
//     } catch (error: any) {
//       spinner.fail('Login failed');
//       console.error(chalk.red('Error:'), error.message);
//       process.exit(1);
//     }
//   });

// Command: vulnzap secure (only used by ides to start a connection to the server)
program
  .command('secure')
  .description('Start the MCP security bridge to protect your AI coding')
  .option('--ide <ide-name>', 'Specify IDE integration (cursor, claude-code, windsurf)')
  .option('--port <port>', 'Port to use for MCP server', '3456')
  .option('--api-key <key>', 'Premium API key for enhanced features')
  .action(async (options) => {
    try {
      let serverIsDown = false;
      try {
        await checkHealth();
      } catch (err) {
        serverIsDown = true;
        console.log(chalk.yellow('Warning: VulnZap API server is down. MCP server will serve from local cache only.'));
      }
      const key = await auth.getKey();
      if (!key) {
        console.error(chalk.red('Error: VulnZap Api key not defined, user is require to run `vulnzap setup -k <key>` to setup the api key.'));
        process.exit(1);
      }
      await startMcpServer();
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
      spinner.succeed(chalk.green('✓') + ' VulnZap server is healthy');
      process.exit(0);
    } catch (error: any) {
      spinner.fail('Failed to check server status');
      console.error(chalk.red('Error:'), "VulnZap server is down. Local cache will be used if available.");
      process.exit(1);
    }
  });

// Command: vulnzap check
program
  .command('check <package>')
  .description('Check a package for vulnerabilities (format: npm:package-name@version)')
  .option('-e, --ecosystem <ecosystem>', 'Package ecosystem (npm, pip, go, rust, etc.)')
  .option('-v, --version <version>', 'Package version')
  .action(async (packageInput, options) => {
    displayBanner();
    let packageName, packageVersion, packageEcosystem;
    
    // Parse package input with improved logic
    const packageFormat = /^(npm|pip|go|rust|maven|gradle|composer|nuget|pypi):([^@]+)@(.+)$/;
    const match = packageInput.match(packageFormat);
    
    if (match) {
      // Format: ecosystem:package-name@version (preferred format)
      [, packageEcosystem, packageName, packageVersion] = match;
    } else if (packageInput.includes('@') && !packageInput.startsWith('@')) {
      // Fallback for old format package@version
      const parts = packageInput.split('@');
      if (parts.length === 2) {
        [packageName, packageVersion] = parts;
        packageEcosystem = options.ecosystem;
      } else {
        packageName = packageInput;
        packageVersion = options.version;
        packageEcosystem = options.ecosystem;
      }
    } else {
      // No @ symbol, use package name as-is
      packageName = packageInput;
      packageVersion = options.version;
      packageEcosystem = options.ecosystem;
    }

    // Validate that we have all required components
    const missingComponents = [];
    
    if (!packageName || packageName.trim() === '') {
      missingComponents.push('package name');
    }
    
    if (!packageVersion || packageVersion.trim() === '') {
      missingComponents.push('package version');
    }
    
    if (!packageEcosystem || packageEcosystem.trim() === '') {
      missingComponents.push('package ecosystem');
    }

    // If any components are missing, show specific error messages
    if (missingComponents.length > 0) {
      console.error(chalk.red(`Error: Missing required ${missingComponents.join(', ')}`));
      console.log('');
      console.log(chalk.cyan('Supported formats:'));
      console.log('  1. ecosystem:package-name@version (recommended)');
      console.log('     Example: vulnzap check npm:express@4.17.1');
      console.log('');
      console.log('  2. package-name@version with --ecosystem flag');
      console.log('     Example: vulnzap check express@4.17.1 --ecosystem npm');
      console.log('');
      console.log('  3. package-name with --ecosystem and --version flags');
      console.log('     Example: vulnzap check express --ecosystem npm --version 4.17.1');
      console.log('');
      console.log(chalk.yellow('Supported ecosystems: npm, pip, go, rust, maven, gradle, composer, nuget, pypi'));
      process.exit(1);
    }

    // Validate ecosystem
    const supportedEcosystems = ['npm', 'pip', 'go', 'rust', 'maven', 'gradle', 'composer', 'nuget', 'pypi'];
    if (!supportedEcosystems.includes(packageEcosystem.toLowerCase())) {
      console.error(chalk.red(`Error: Unsupported ecosystem '${packageEcosystem}'`));
      console.log(chalk.yellow(`Supported ecosystems: ${supportedEcosystems.join(', ')}`));
      process.exit(1);
    }

    const spinner = ora(`Checking ${packageEcosystem}:${packageName}@${packageVersion} for vulnerabilities...\n`).start();

    try {
      await checkHealth();
      const result = await checkVulnerability(packageEcosystem, packageName, packageVersion, {
        useCache: options.cache,
        useAi: options.ai
      });
      spinner.stop();

      if (result.fromCache) {
        console.log(chalk.yellow('Note: Using cached result (may be up to 5 days old)'));
      }

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
        if (result.processedVulnerabilities && result.processedVulnerabilities.summary) {
          console.log(chalk.green(`✓ LLM Processed: `));
          console.log('');
          console.log(`1. Summary: `);
          console.log(`- ${result.processedVulnerabilities.summary}`);
          console.log(`2. Impact: `);
          console.log(`- ${result.processedVulnerabilities.impact}`);
          console.log(`3. Recommendations: `);
          result.processedVulnerabilities.recommendations.forEach((recommendation: string) => {
            console.log(`- ${recommendation}`);
          });
        }
        if (result.sources && result.sources.length > 0) {
          console.log(`  Sources: ${result.sources.join(', ')}`);
        }
        console.log('');
        console.log(chalk.green(`✓ Raw Vulnerabilities: `));
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
      spinner.succeed('Vulnerability check completed');
      process.exit(0);
    } catch (error: any) {
      if (error.message === 'SERVER_DOWN') {
        spinner.stop();
        console.log(chalk.yellow('Warning: VulnZap server is down. Using local cache if available.'));
        const cached = cacheService.readCache(packageName, packageVersion, packageEcosystem);
        if (cached) {
          console.log(chalk.green('✓') + ' Found cached scan result (from local cache, may be outdated):');
          // Print cached result in a user-friendly way
          if (cached.error) {
            console.error(chalk.red('Error:'), cached.error);
            return;
          }
          if (cached.isUnknown) {
            console.log(chalk.yellow('!') + ` Unknown: ${cached.message}`);
            if (cached.sources && cached.sources.length > 0) {
              console.log(`  Sources checked: ${cached.sources.join(', ')}`);
            }
            return;
          }
          if (!cached.isVulnerable) {
            console.log(chalk.green(`✓ Safe: ${packageName}@${packageVersion} has no known vulnerabilities`));
            if (cached.sources && cached.sources.length > 0) {
              console.log(`  Sources checked: ${cached.sources.join(', ')}`);
            }
            console.log('');
            return;
          }
          if (cached.isVulnerable) {
            console.log(chalk.red(`✗ Vulnerable: ${packageName}@${packageVersion} has vulnerabilities`));
            if (cached.processedVulnerabilities && cached.processedVulnerabilities.summary) {
              console.log(chalk.green(`✓ LLM Processed: `));
              console.log('');
              console.log(`1. Summary: `);
              console.log(`- ${cached.processedVulnerabilities.summary}`);
              console.log(`2. Impact: `);
              console.log(`- ${cached.processedVulnerabilities.impact}`);
              console.log(`3. Recommendations: `);
              cached.processedVulnerabilities.recommendations.forEach((recommendation: string) => {
                console.log(`- ${recommendation}`);
              });
            }
            
            if (cached.sources && cached.sources.length > 0) {
              console.log(`  Sources: ${cached.sources.join(', ')}`);
            }
            console.log('');
            cached.advisories?.forEach((advisory: { title: string; severity: string; description: string; references?: string[] }) => {
              console.log(chalk.yellow(`- ${advisory.title}`));
              console.log(`  Severity: ${advisory.severity}`);
              console.log(`  Description: ${advisory.description}`);
              if (advisory.references?.length) {
                console.log(`  References: ${advisory.references.join(', ')}`);
              }
              console.log('');
            });
            if (cached.fixedVersions && cached.fixedVersions.length > 0) {
              console.log(chalk.green('Suggested fix:'));
              console.log(`Upgrade to ${cached.fixedVersions[0]} or later\n`);
            }
          }
        } else {
          console.log(chalk.red('No valid local cache found for this package/version (older than 5 days or never scanned).'));
        }
        process.exit(1);
      } else {
        spinner.fail('Vulnerability check failed');
        console.error(chalk.red('Error:'), error.message);
        process.exit(1);
      }
    }
  });

program
  .command('connect')
  .description('Connect VulnZap to your AI-powered IDE')
  .option('--ide <ide-name>', 'IDE to connect with (cursor, cline, windsurf)', 'cursor')
  .action(async (options) => {
    // Prompt for IDE if not provided
    if (!options.ide) {
      const { ide } = await inquirer.prompt([{
        type: 'list',
        name: 'ide',
        message: 'Which IDE would you like to connect with?',
        choices: [
          { name: 'Cursor IDE', value: 'cursor' },
          { name: 'Cline', value: 'cline' },
          { name: 'Windsurf IDE', value: 'windsurf' }
        ],
        default: 'cursor'
      }]);
      options.ide = ide;
    }

    await connectIDE(options.ide);
    process.exit(0);
  });

// Command: vulnzap account
program
  .command('account')
  .description('View your account information')
  .action(async () => {
    displayBanner();

    try {
      console.log('\nAccount Details:');
      console.log('----------------');
      console.log('Please visit https://vulnzap.com/dashboard to view your account details');
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
      const vulnzapDir = path.join(process.cwd(), '.vulnzap');
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
      const results = await batchScan(packages, {
        useCache: true,
        useAi: true
      });
      
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
        // Save to default location in .vulnzap
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
    
    console.log(chalk.cyan('Quick Start:'));
    console.log('  npx vulnzap init          Complete onboarding (recommended for new users)');
    console.log('');
    console.log(chalk.cyan('Available Commands:'));
    console.log('  init                      Complete VulnZap setup with authentication and IDE integration');
    console.log('  setup                     Configure VulnZap with your API key');
    console.log('  connect                   Connect VulnZap to your AI-powered IDE');
    console.log('  check <package>           Check a package for vulnerabilities');
    console.log('  batch-scan                Scan all packages in current directory');
    console.log('  status                    Check VulnZap server health');
    console.log('  account                   View account information');
    console.log('  help                      Display this help information');
    console.log('');
    console.log(chalk.cyan('Examples:'));
    console.log('  vulnzap init                                    # Complete setup (recommended)');
    console.log('  vulnzap check npm:express@4.17.1               # Check specific package');
    console.log('  vulnzap setup -k your-api-key                  # Manual API key setup');
    console.log('  vulnzap connect --ide cursor                   # Connect to Cursor IDE');
    console.log('');
    console.log(chalk.cyan('Need Help?'));
    console.log('  Documentation: https://vulnzap.com/docs');
    console.log('  Support: https://vulnzap.com/support');
    console.log('  Dashboard: https://vulnzap.com/dashboard');
    console.log('');
    
    // Also show the default commander help for detailed options
    console.log(chalk.gray('Detailed command options:'));
    program.help();
  });

// Parse arguments
program.parse(process.argv);

// If no args, display help
if (process.argv.length === 2) {
  displayBanner();
  console.log(chalk.cyan('🚀 Get started with VulnZap:'));
  console.log('');
  console.log(chalk.green('  npx vulnzap init') + '          Complete setup (recommended for new users)');
  console.log('  vulnzap help                Show all available commands');
  console.log('');
}

// Helper function to handle IDE connection logic
async function connectIDE(ide: string) {
  // Log the event
  const logFile = join(os.homedir(), '.vulnzap', 'info.log');
  const logStream = fs.createWriteStream(logFile, { flags: 'a' });
  logStream.write(`VulnZap connect command executed for ${ide} at ${new Date().toISOString()}\n`);
  logStream.end();

  if (ide === 'cursor') {
    // Ensure the .cursor directory exists
    const cursorDir = path.join(os.homedir(), '.cursor');
    if (!fs.existsSync(cursorDir)) {
      fs.mkdirSync(cursorDir, { recursive: true });
      console.log(chalk.yellow('Created .cursor directory'));
    }
    
    // Define the MCP config file path
    const cursorMcpConfigLocation = path.join(cursorDir, 'mcp.json');
    
    // Read existing config or create empty object
    let cursorMcpConfig: { mcpServers?: any; [key: string]: any } = {};
    if (fs.existsSync(cursorMcpConfigLocation)) {
      try {
        const configData = fs.readFileSync(cursorMcpConfigLocation, 'utf8');
        cursorMcpConfig = JSON.parse(configData);
      } catch (parseError) {
        console.warn(chalk.yellow('Warning: Could not parse existing mcp.json, creating new one'));
        cursorMcpConfig = {};
      }
    } else {
      console.log(chalk.yellow('Creating new mcp.json file'));
    }

    // Initialize mcpServers if it doesn't exist
    if (!cursorMcpConfig.mcpServers) {
      cursorMcpConfig.mcpServers = {};
    }

    // Add VulnZap configuration
    cursorMcpConfig.mcpServers.VulnZap = {
      command: "vulnzap",
      args: ["secure", "--ide", "cursor", "--port", "3456"]
    };

    // Write the config file with proper permissions
    const configContent = JSON.stringify(cursorMcpConfig, null, 2);
    fs.writeFileSync(cursorMcpConfigLocation, configContent, { 
      encoding: 'utf8'
    });
    
    console.log(chalk.green('✓') + ' Cursor MCP config updated successfully');

    // Display helpful information
    console.log('\nConfiguration Summary:');
    console.log('- MCP Server Name: VulnZap');
    console.log('- Transport Type: STDIO');
    console.log('- Auto-approved Tools: auto-vulnerability-scan');
    console.log('- Network Timeout: 60 seconds');
    console.log('\nTo manage this server in Cursor:');
    console.log('1. Click the "MCP Servers" icon in Cursor');
    console.log('2. Find "VulnZap" in the server list');
    console.log('3. Use the toggle switch to enable/disable');
    console.log('4. Click on server name to access additional settings');

  } else if (ide === 'windsurf') {
    // Windsurf MCP config location and structure
    const windsurfDir = path.join(os.homedir(), '.codeium', 'windsurf');
    const windsurfMcpConfigLocation = path.join(windsurfDir, 'mcp_config.json');
    // Ensure parent directory exists
    if (!fs.existsSync(windsurfDir)) {
      fs.mkdirSync(windsurfDir, { recursive: true });
    }
    let windsurfMcpConfig: any = {};
    if (fs.existsSync(windsurfMcpConfigLocation)) {
      try {
        windsurfMcpConfig = JSON.parse(fs.readFileSync(windsurfMcpConfigLocation, 'utf8'));
      } catch (e) {
        console.error(chalk.red('Error: Failed to parse existing Windsurf MCP config.'));
        return;
      }
    } else {
      // If file does not exist, create with empty structure
      windsurfMcpConfig = { mcpServers: {} };
    }
    if (!windsurfMcpConfig.mcpServers) {
      windsurfMcpConfig.mcpServers = {};
    }
    windsurfMcpConfig.mcpServers.VulnZap = {
      command: 'vulnzap',
      args: ['secure', '--ide', 'windsurf', '--port', '3456']
    };
    fs.writeFileSync(windsurfMcpConfigLocation, JSON.stringify(windsurfMcpConfig, null, 2));
    console.log(chalk.green('✓') + ' Windsurf MCP config updated successfully with API keys');
    
    // Display helpful information
    console.log('\nConfiguration Summary:');
    console.log('- MCP Server Name: VulnZap');
    console.log('- Transport Type: STDIO');
    console.log('- Auto-approved Tools: auto-vulnerability-scan');
    console.log('- Network Timeout: 60 seconds');
    console.log('\nTo manage this server in Windsurf:');
    console.log('1. Click the "MCP Servers" icon in Windsurf');
    console.log('2. Find "VulnZap" in the server list');
    console.log('3. Use the toggle switch to enable/disable');
    console.log('4. Click on server name to access additional settings');
    
  } else if (ide === 'cline') {
    // Cline MCP config location and structure
    const clineDir = path.join(os.homedir(), 'AppData', 'Roaming', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings');
    const clineMcpConfigLocation = path.join(clineDir, 'cline_mcp_settings.json');
    
    // Ensure parent directory exists
    if (!fs.existsSync(clineDir)) {
      fs.mkdirSync(clineDir, { recursive: true });
    }

    let clineMcpConfig: any = {};
    if (fs.existsSync(clineMcpConfigLocation)) {
      try {
        clineMcpConfig = JSON.parse(fs.readFileSync(clineMcpConfigLocation, 'utf8'));
      } catch (e) {
        console.error(chalk.red('Error: Failed to parse existing Cline MCP config.'));
        return;
      }
    }

    // Initialize mcpServers if it doesn't exist
    if (!clineMcpConfig.mcpServers) {
      clineMcpConfig.mcpServers = {};
    }

    // Configure VulnZap MCP server with STDIO transport
    clineMcpConfig.mcpServers.VulnZap = {
      command: "vulnzap",
      args: ["secure", "--ide", "cline", "--port", "3456"],
      alwaysAllow: ["auto-vulnerability-scan"], // Auto-approve vulnerability scanning
      disabled: false,
      networkTimeout: 60000 // 1 minute default timeout
    };

    fs.writeFileSync(clineMcpConfigLocation, JSON.stringify(clineMcpConfig, null, 2));
    console.log(chalk.green('✓') + ' Cline MCP config updated successfully with API keys');
    
    // Display helpful information
    console.log('\nConfiguration Summary:');
    console.log('- MCP Server Name: VulnZap');
    console.log('- Transport Type: STDIO');
    console.log('- Auto-approved Tools: auto-vulnerability-scan');
    console.log('- Network Timeout: 60 seconds');
    console.log('\nTo manage this server in Cline:');
    console.log('1. Click the "MCP Servers" icon in Cline');
    console.log('2. Find "VulnZap" in the server list');
    console.log('3. Use the toggle switch to enable/disable');
    console.log('4. Click on server name to access additional settings');
    
  } else {
    console.error(chalk.cyan('Add this to your IDE\'s mcp config:'));
    console.log(chalk.cyan(`{
      "mcpServers": {
        "VulnZap": {
          "command": "vulnzap",
          "args": ["secure", "--ide", "${ide}", "--port", "3456"]
        }
      }
    }`));
  }
} 