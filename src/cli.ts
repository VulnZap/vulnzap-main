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
import { displayUserWelcome, displayUserStatus } from './utils/userDisplay.js';
import { getMockProfile } from './utils/mockUser.js';

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

// Enhanced banner display with Apple-inspired design
const displayBanner = () => {
  console.log(chalk.gray(`
              _       _____            
 /\\   /\\_   _| |_ __ / _  / __ _ _ __  
 \\ \\ / | | | | | '_ \\\\// / / _\` | '_ \\ 
  \\ V /| |_| | | | | |/ //| (_| | |_) |
   \\_/  \\__,_|_|_| |_/____/\\__,_| .__/ 
                                |_|    
  `));
  console.log(chalk.white(`  Security-first AI development`));
  console.log(chalk.gray(`  Version ${version}\n`));
};

// Enhanced typography helpers
const typography = {
  title: (text: string) => chalk.white.bold(text),
  subtitle: (text: string) => chalk.gray(text),
  success: (text: string) => chalk.green(text),
  warning: (text: string) => chalk.yellow(text),
  error: (text: string) => chalk.red(text),
  info: (text: string) => chalk.blue(text),
  muted: (text: string) => chalk.gray.dim(text),
  accent: (text: string) => chalk.cyan(text),
  code: (text: string) => chalk.gray.bgBlack(` ${text} `),
};

// Enhanced spacing helpers
const spacing = {
  line: () => console.log(''),
  section: () => console.log('\n'),
  block: () => console.log('\n\n'),
};

// Enhanced progress indicators
const createSpinner = (text: string) => {
  return ora({
    text: chalk.gray(text),
    spinner: 'dots2',
    color: 'gray',
  });
};

// Enhanced inquirer themes
const customPrompts = {
  ...inquirer,
  prompt: (questions: any) => inquirer.prompt(questions.map((q: any) => ({
    ...q,
    prefix: chalk.gray('›'),
  }))),
};

program
  .name('vulnzap')
  .description('Security-first AI development platform')
  .version(version);


// Command: vulnzap setup
program
  .command('setup')
  .description('Configure authentication and settings')
  .option('-k, --key <key>', 'Provide API key directly')
  .option('--ide <ide-name>', 'Configure IDE integration (cursor, windsurf, cline)')
  .action(async (options) => {
    displayBanner();
    console.log(typography.title('Setup Configuration'));
    spacing.line();
    
    try {
      // Check if API key already exists
      let existingKey;
      try {
        existingKey = await getKey();
      } catch (error) {
        existingKey = null;
      }

      if (existingKey) {
        console.log(typography.muted('  An API key is already configured'));
        spacing.line();
        
        const { confirm } = await customPrompts.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: 'Replace existing configuration?',
            default: false
          }
        ]);

        if (!confirm) {
          console.log(typography.muted('  Configuration unchanged'));
          
          if (options.ide) {
            spacing.section();
            console.log(typography.info('Configuring IDE integration...'));
            await connectIDE(options.ide);
          }
          return;
        }
      }

      if (!options.key) {
        spacing.line();
        console.log(typography.muted('  Get your API key from:'));
        console.log(typography.accent(`  ${config.api.baseUrl}/dashboard/api-keys`));
        console.log(typography.muted('  (Ensure you are signed in to your account)'));
        spacing.section();
      }

      let apiKey: string;
      if (options.key) {
        apiKey = options.key;
      } else {
        const response = await customPrompts.prompt([
          {
            type: 'password',
            name: 'apiKey',
            message: 'API key',
            validate: (input: string) => {
              if (!input) {
                return 'API key is required';
              }
              return true;
            }
          }
        ]);
        apiKey = response.apiKey;
      }

      const spinner = createSpinner('Configuring authentication...');
      spinner.start();
      
      await saveKey(apiKey);
      spinner.succeed(typography.success('Authentication configured'));
      
      // Show personalized welcome message
      await displayUserWelcome();

      if (options.ide) {
        spacing.line();
        const ideSpinner = createSpinner('Configuring IDE integration...');
        ideSpinner.start();
        await connectIDE(options.ide);
        ideSpinner.succeed(typography.success('IDE integration configured'));
      }

    } catch (error: any) {
      console.error(typography.error('Configuration failed:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap init
program
  .command('init')
  .description('Complete onboarding and configuration')
  .action(async () => {
    // Handle Ctrl+C gracefully
    const handleExit = () => {
      spacing.line();
      console.log(typography.muted('Setup cancelled. Run `vulnzap init` again anytime.'));
      process.exit(0);
    };
    
    process.on('SIGINT', handleExit);
    process.on('SIGTERM', handleExit);

    try {
      displayBanner();
      console.log(typography.title('Welcome to VulnZap'));
      console.log(typography.subtitle('Let\'s configure your security-first development environment.'));
      spacing.section();

      // Step 1: Welcome and options
      const { welcomeChoice } = await customPrompts.prompt([
        {
          type: 'list',
          name: 'welcomeChoice',
          message: 'How would you like to proceed?',
          choices: [
            { name: 'Learn more about VulnZap', value: 'visit' },
            { name: 'Continue with setup', value: 'proceed' }
          ],
          default: 'proceed'
        }
      ]);

      if (welcomeChoice === 'visit') {
        spacing.line();
        console.log(typography.info('Visit vulnzap.com to learn more'));
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
        console.log(typography.success('Authentication configured'));
        spacing.line();
        
        const { replaceKey } = await customPrompts.prompt([
          {
            type: 'confirm',
            name: 'replaceKey',
            message: 'Re-authenticate with a different account?',
            default: false
          }
        ]);

        if (!replaceKey) {
          console.log(typography.muted('  Using existing authentication'));
        } else {
          existingKey = null;
        }
      }

      // Step 3: Authentication flow
      if (!existingKey) {
        spacing.section();
        console.log(typography.info('Setting up authentication'));
        console.log(typography.muted('  You will be redirected to your browser for secure login'));
        spacing.line();
        
        const spinner = createSpinner('Initializing authentication...');
        spinner.start();

        try {
          spinner.text = 'Opening browser for authentication...';
          
          const { success, error } = await auth.login("login");

          if (success) {
            spinner.succeed(typography.success('Authentication successful'));
            
            // Show personalized welcome message
            await displayUserWelcome();
          } else {
            spinner.fail('Authentication failed');
            if (error) {
              console.error(typography.error('Error:'), error);
            }
            spacing.line();
            console.log(typography.muted('Manual setup alternative:'));
            console.log(typography.muted('  1. Visit https://vulnzap.com/dashboard/api-keys'));
            console.log(typography.muted('  2. Copy your API key'));
            console.log(typography.code('vulnzap setup -k <your-api-key>'));
            process.exit(1);
          }
        } catch (error: any) {
          spinner.fail('Authentication failed');
          console.error(typography.error('Error:'), error.message);
          spacing.line();
          console.log(typography.muted('Manual setup alternative:'));
          console.log(typography.muted('  1. Visit https://vulnzap.com/dashboard/api-keys'));
          console.log(typography.muted('  2. Copy your API key'));
          console.log(typography.code('vulnzap setup -k <your-api-key>'));
          process.exit(1);
        }
      }

      // Step 4: IDE Selection and Configuration
      spacing.section();
      console.log(typography.info('Setting up IDE integration'));
      spacing.line();
      
      const { selectedIde } = await customPrompts.prompt([
        {
          type: 'list',
          name: 'selectedIde',
          message: 'Which development environment are you using?',
          choices: [
            { name: 'Cursor IDE', value: 'cursor' },
            { name: 'Windsurf IDE', value: 'windsurf' },
            { name: 'Cline (VS Code Extension)', value: 'cline' },
            { name: 'Other (Manual Configuration)', value: 'other' }
          ],
          default: 'cursor'
        }
      ]);

      const ideSpinner = createSpinner(`Configuring ${selectedIde} integration...`);
      ideSpinner.start();
      
      try {
        await connectIDE(selectedIde);
        ideSpinner.succeed(typography.success(`${selectedIde} integration configured`));

        // Step 5: Success and next steps
        spacing.section();
        console.log(typography.title('Setup Complete'));
        console.log(typography.subtitle('VulnZap is now protecting your AI-generated code'));
        spacing.section();
        
        console.log(typography.info('What\'s next:'));
        console.log(typography.muted('  • Start coding - vulnerabilities will be caught automatically'));
        console.log(typography.muted('  • View detailed logs at vulnzap.com/dashboard/logs'));
        console.log(typography.muted('  • Run `vulnzap check <package>` to manually scan packages'));
        console.log(typography.muted('  • Run `vulnzap status` to verify everything is working'));
        spacing.section();
        
        console.log(typography.muted('Need help? Visit vulnzap.com/docs or run `vulnzap help`'));
      } catch (error: any) {
        ideSpinner.fail(`Failed to configure ${selectedIde} integration`);
        console.error(typography.error('Error:'), error.message);
        spacing.line();
        console.log(typography.muted(`Manual configuration available:`));
        console.log(typography.code(`vulnzap connect --ide ${selectedIde}`));
      }

    } catch (error: any) {
      spacing.section();
      console.error(typography.error('Setup failed:'), error.message);
      spacing.line();
      console.log(typography.muted('Recovery options:'));
      console.log(typography.muted('  • Run `vulnzap init` again to retry'));
      console.log(typography.muted('  • Run `vulnzap setup` for manual configuration'));
      console.log(typography.muted('  • Visit vulnzap.com/support for help'));
      process.exit(1);
    } finally {
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
  .description('Check system health and configuration')
  .action(async () => {
    displayBanner();
    console.log(typography.title('System Status'));
    spacing.line();

    const spinner = createSpinner('Checking server health...');
    spinner.start();

    try {
      await checkHealth();
      spinner.succeed(typography.success('Server is healthy'));
      
      // Check authentication
      spacing.line();
      const authSpinner = createSpinner('Checking authentication...');
      authSpinner.start();
      
      try {
        await getKey();
        authSpinner.succeed(typography.success('Authentication configured'));
        
        // Show user profile information
        spacing.section();
        await displayUserStatus();
        
      } catch (error) {
        authSpinner.fail(typography.warning('Authentication not configured'));
        spacing.line();
        console.log(typography.muted('Run `vulnzap setup` to configure authentication'));
      }
      
      spacing.section();
      console.log(typography.info('System ready for secure development'));
      
    } catch (error: any) {
      spinner.fail(typography.warning('Server is offline'));
      spacing.line();
      console.log(typography.muted('Local cache will be used when available'));
      console.log(typography.muted('Some features may be limited'));
    }
  });

// Command: vulnzap check
program
  .command('check <package>')
  .description('Analyze package for security vulnerabilities')
  .option('-e, --ecosystem <ecosystem>', 'Package ecosystem (npm, pip, go, rust, etc.)')
  .option('-v, --version <version>', 'Package version')
  .action(async (packageInput, options) => {
    displayBanner();
    console.log(typography.title('Security Analysis'));
    spacing.line();
    
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
      console.error(typography.error(`Missing required ${missingComponents.join(', ')}`));
      spacing.section();
      console.log(typography.info('Supported formats:'));
      console.log(typography.muted('  1. ecosystem:package-name@version (recommended)'));
      console.log(typography.code('vulnzap check npm:express@4.17.1'));
      spacing.line();
      console.log(typography.muted('  2. package-name@version with --ecosystem flag'));
      console.log(typography.code('vulnzap check express@4.17.1 --ecosystem npm'));
      spacing.line();
      console.log(typography.muted('  3. package-name with --ecosystem and --version flags'));
      console.log(typography.code('vulnzap check express --ecosystem npm --version 4.17.1'));
      spacing.section();
      console.log(typography.muted('Supported ecosystems: npm, pip, go, rust, maven, gradle, composer, nuget, pypi'));
      process.exit(1);
    }

    // Validate ecosystem
    const supportedEcosystems = ['npm', 'pip', 'go', 'rust', 'maven', 'gradle', 'composer', 'nuget', 'pypi'];
    if (!supportedEcosystems.includes(packageEcosystem.toLowerCase())) {
      console.error(typography.error(`Unsupported ecosystem '${packageEcosystem}'`));
      console.log(typography.muted(`Supported ecosystems: ${supportedEcosystems.join(', ')}`));
      process.exit(1);
    }

    console.log(typography.muted(`  Analyzing ${packageEcosystem}:${packageName}@${packageVersion}`));
    spacing.line();
    
    const spinner = createSpinner('Scanning for vulnerabilities...');
    spinner.start();

          try {
        await checkHealth();
        const result = await checkVulnerability(packageEcosystem, packageName, packageVersion, {
          useCache: options.cache,
          useAi: options.ai
        });
        
        if (result.fromCache) {
          spinner.succeed(typography.warning('Analysis complete (using cached result)'));
          console.log(typography.muted('  Result may be up to 5 days old'));
        } else {
          spinner.succeed(typography.success('Analysis complete'));
          
          // Show usage info after successful scan (but not for cached results)
          await displayUserWelcome();
        }
        
        spacing.line();

        if (result.error) {
          console.error(typography.error('Analysis failed:'), result.error);
          return;
        }
        
        if (result.isUnknown) {
          console.log(typography.warning('Result: Unknown'));
          console.log(typography.muted(`  ${result.message}`));
          if (result.sources && result.sources.length > 0) {
            console.log(typography.muted(`  Sources checked: ${result.sources.join(', ')}`));
          }
          return;
        }
        
        if (!result.isVulnerable) {
          console.log(typography.success('Result: Secure'));
          console.log(typography.muted(`  ${packageName}@${packageVersion} has no known vulnerabilities`));
          if (result.sources && result.sources.length > 0) {
            console.log(typography.muted(`  Sources: ${result.sources.join(', ')}`));
          }
          spacing.line();
          return;
        }
              if (result.isVulnerable) {
          console.log(typography.error('Result: Vulnerable'));
          console.log(typography.muted(`  ${packageName}@${packageVersion} has security vulnerabilities`));
          spacing.section();
          
          if (result.processedVulnerabilities && result.processedVulnerabilities.summary) {
            console.log(typography.info('AI Analysis'));
            spacing.line();
            console.log(typography.subtitle('Summary'));
            console.log(typography.muted(`  ${result.processedVulnerabilities.summary}`));
            spacing.line();
            console.log(typography.subtitle('Impact'));
            console.log(typography.muted(`  ${result.processedVulnerabilities.impact}`));
            spacing.line();
            console.log(typography.subtitle('Recommendations'));
            result.processedVulnerabilities.recommendations.forEach((recommendation: string) => {
              console.log(typography.muted(`  • ${recommendation}`));
            });
            spacing.section();
          }
          
          if (result.sources && result.sources.length > 0) {
            console.log(typography.muted(`Sources: ${result.sources.join(', ')}`));
            spacing.line();
          }
          
          console.log(typography.info('Vulnerability Details'));
          spacing.line();
          // Display vulnerability details
          result.advisories?.forEach((advisory: { title: string; severity: string; description: string; references?: string[] }) => {
            console.log(typography.warning(`• ${advisory.title}`));
            console.log(typography.muted(`  Severity: ${advisory.severity}`));
            console.log(typography.muted(`  ${advisory.description}`));
            if (advisory.references?.length) {
              console.log(typography.muted(`  References: ${advisory.references.join(', ')}`));
            }
            spacing.line();
          });
          
          // Suggest fixed version if available
          if (result.fixedVersions && result.fixedVersions.length > 0) {
            console.log(typography.info('Recommended Fix'));
            console.log(typography.accent(`  Upgrade to ${result.fixedVersions[0]} or later`));
            spacing.line();
          }
                }
    } catch (error: any) {
      if (error.message === 'SERVER_DOWN') {
        spinner.stop();
        console.log(typography.warning('VulnZap server is offline. Using local cache if available.'));
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
  .description('Configure IDE integration')
  .option('--ide <ide-name>', 'IDE to connect with (cursor, cline, windsurf)', 'cursor')
  .action(async (options) => {
    displayBanner();
    console.log(typography.title('IDE Integration'));
    spacing.line();
    
    // Prompt for IDE if not provided
    if (!options.ide) {
      const { ide } = await customPrompts.prompt([{
        type: 'list',
        name: 'ide',
        message: 'Which development environment are you using?',
        choices: [
          { name: 'Cursor IDE', value: 'cursor' },
          { name: 'Cline', value: 'cline' },
          { name: 'Windsurf IDE', value: 'windsurf' }
        ],
        default: 'cursor'
      }]);
      options.ide = ide;
    }

    const spinner = createSpinner(`Configuring ${options.ide} integration...`);
    spinner.start();
    
    try {
      await connectIDE(options.ide);
      spinner.succeed(typography.success('IDE integration configured'));
      spacing.line();
      console.log(typography.muted('Your development environment is now secured with VulnZap'));
    } catch (error: any) {
      spinner.fail(typography.error('Configuration failed'));
      console.error(typography.error('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap account
program
  .command('account')
  .description('View account information and settings')
  .action(async () => {
    displayBanner();
    console.log(typography.title('Account Information'));
    spacing.section();
    
    try {
      // Show detailed user status
      await displayUserStatus();
      
      spacing.section();
      console.log(typography.info('Dashboard Access'));
      console.log(typography.muted('  Visit your dashboard to manage account settings:'));
      console.log(typography.accent('  https://vulnzap.com/dashboard'));
      spacing.section();
      
      console.log(typography.info('Available Features'));
      console.log(typography.muted('  • API key management'));
      console.log(typography.muted('  • Scan history and analytics'));
      console.log(typography.muted('  • Team collaboration tools'));
      console.log(typography.muted('  • Integration settings'));
      
    } catch (error: any) {
      console.error(typography.error('Error:'), error.message);
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

// Command: vulnzap demo (for testing personalized features)
program
  .command('demo')
  .description('Demo personalized CLI features (development only)')
  .option('--tier <tier>', 'User tier to demo (free, pro, enterprise)', 'free')
  .action(async (options) => {
    displayBanner();
    console.log(typography.title('Personalized CLI Demo'));
    spacing.section();
    
    // Create mock profile for demo
    const mockProfile = getMockProfile(options.tier as 'free' | 'pro' | 'enterprise');
    
    try {
      console.log(typography.info(`Demonstrating ${options.tier} tier experience:`));
      spacing.line();
      
      // Manually create the displays with mock data
      const firstName = mockProfile.name.split(' ')[0];
      console.log(typography.subtitle(`Welcome back, ${firstName}`));
      
      // Tier and usage display
      const tierDisplay = mockProfile.tier === 'free' ? typography.muted('Free') :
                         mockProfile.tier === 'pro' ? typography.accent('Pro') :
                         typography.success('Enterprise');
      
      const remaining = mockProfile.usage.limit - mockProfile.usage.current;
      const percentage = (mockProfile.usage.current / mockProfile.usage.limit) * 100;
      
      let usageDisplay;
      if (percentage >= 90) {
        usageDisplay = typography.error(`${remaining} scans remaining this ${mockProfile.usage.period}`);
      } else if (percentage >= 75) {
        usageDisplay = typography.warning(`${remaining} scans remaining this ${mockProfile.usage.period}`);
      } else {
        usageDisplay = typography.muted(`${remaining} scans remaining this ${mockProfile.usage.period}`);
      }
      
      console.log(`${tierDisplay} • ${usageDisplay}`);
      
      // FOMO message
      if (mockProfile.tier === 'free' && percentage >= 75) {
        spacing.line();
        if (percentage >= 90) {
          console.log(typography.warning('Upgrade to Pro for unlimited scans and advanced features'));
        } else {
          console.log(typography.muted('Consider upgrading to Pro to avoid hitting limits'));
        }
      }
      
      spacing.section();
      console.log(typography.subtitle('Full Status View:'));
      spacing.line();
      
      console.log(typography.info('Account Information'));
      spacing.line();
      console.log(typography.muted(`  Name: ${mockProfile.name}`));
      console.log(typography.muted(`  Email: ${mockProfile.email}`));
      console.log(typography.muted(`  Tier: ${mockProfile.tier.charAt(0).toUpperCase() + mockProfile.tier.slice(1)}`));
      
      spacing.line();
      console.log(typography.info('Usage This Month'));
      spacing.line();
      
      const percentageRounded = Math.round(percentage);
      console.log(typography.muted(`  Scans used: ${mockProfile.usage.current} of ${mockProfile.usage.limit} (${percentageRounded}%)`));
      console.log(typography.muted(`  Remaining: ${remaining} scans`));
      
      // Progress bar
      const barLength = 20;
      const filledLength = Math.round((mockProfile.usage.current / mockProfile.usage.limit) * barLength);
      const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);
      
      let barColor;
      if (percentage >= 90) barColor = chalk.red;
      else if (percentage >= 75) barColor = chalk.yellow;
      else if (percentage >= 50) barColor = chalk.cyan;
      else barColor = chalk.green;
      
      console.log(typography.muted(`  Progress: ${barColor(bar)} ${percentageRounded}%`));
      
      if (mockProfile.tier === 'free' && percentage >= 75) {
        spacing.section();
        if (percentage >= 90) {
          console.log(typography.warning('Upgrade to Pro for unlimited scans and advanced features'));
        } else {
          console.log(typography.muted('Consider upgrading to Pro to avoid hitting limits'));
        }
        console.log(typography.muted('Visit vulnzap.com/pricing to upgrade'));
      }
      
    } catch (error: any) {
      console.error(typography.error('Demo failed:'), error.message);
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
  console.log(typography.title('Get started with VulnZap'));
  spacing.section();
  console.log(typography.accent('  npx vulnzap init') + typography.muted('          Complete setup (recommended for new users)'));
  console.log(typography.muted('  vulnzap help                Show all available commands'));
  spacing.section();
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
        console.log(typography.warning('Warning: Could not parse existing mcp.json, creating new one'));
        cursorMcpConfig = {};
      }
    } else {
      console.log(typography.info('Creating new mcp.json file'));
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
    
    console.log(typography.success('Configuration updated successfully'));

    // Display helpful information
    spacing.section();
    console.log(typography.info('Configuration Summary'));
    console.log(typography.muted('  MCP Server Name: VulnZap'));
    console.log(typography.muted('  Transport Type: STDIO'));
    console.log(typography.muted('  Auto-approved Tools: auto-vulnerability-scan'));
    console.log(typography.muted('  Network Timeout: 60 seconds'));
    spacing.section();
    console.log(typography.info('To manage this server in Cursor:'));
    console.log(typography.muted('  1. Click the "MCP Servers" icon in Cursor'));
    console.log(typography.muted('  2. Find "VulnZap" in the server list'));
    console.log(typography.muted('  3. Use the toggle switch to enable/disable'));
    console.log(typography.muted('  4. Click on server name to access additional settings'));

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
        console.error(typography.error('Failed to parse existing Windsurf MCP config.'));
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
    console.log(typography.success('Configuration updated successfully'));
    
    // Display helpful information
    spacing.section();
    console.log(typography.info('Configuration Summary'));
    console.log(typography.muted('  MCP Server Name: VulnZap'));
    console.log(typography.muted('  Transport Type: STDIO'));
    console.log(typography.muted('  Auto-approved Tools: auto-vulnerability-scan'));
    console.log(typography.muted('  Network Timeout: 60 seconds'));
    spacing.section();
    console.log(typography.info('To manage this server in Windsurf:'));
    console.log(typography.muted('  1. Click the "MCP Servers" icon in Windsurf'));
    console.log(typography.muted('  2. Find "VulnZap" in the server list'));
    console.log(typography.muted('  3. Use the toggle switch to enable/disable'));
    console.log(typography.muted('  4. Click on server name to access additional settings'));
    
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
        console.error(typography.error('Failed to parse existing Cline MCP config.'));
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
    console.log(typography.success('Configuration updated successfully'));
    
    // Display helpful information
    spacing.section();
    console.log(typography.info('Configuration Summary'));
    console.log(typography.muted('  MCP Server Name: VulnZap'));
    console.log(typography.muted('  Transport Type: STDIO'));
    console.log(typography.muted('  Auto-approved Tools: auto-vulnerability-scan'));
    console.log(typography.muted('  Network Timeout: 60 seconds'));
    spacing.section();
    console.log(typography.info('To manage this server in Cline:'));
    console.log(typography.muted('  1. Click the "MCP Servers" icon in Cline'));
    console.log(typography.muted('  2. Find "VulnZap" in the server list'));
    console.log(typography.muted('  3. Use the toggle switch to enable/disable'));
    console.log(typography.muted('  4. Click on server name to access additional settings'));
    
  } else {
    console.log(typography.info('Manual Configuration Required'));
    spacing.line();
    console.log(typography.muted('Add this to your IDE\'s MCP configuration:'));
    spacing.line();
    console.log(typography.code(`{
  "mcpServers": {
    "VulnZap": {
      "command": "vulnzap",
      "args": ["secure", "--ide", "${ide}", "--port", "3456"]
    }
  }
}`));
  }
} 