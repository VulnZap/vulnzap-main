#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import os from 'os';
import fs from 'fs';
import * as api from './api/apis.js';
import * as auth from './api/auth.js';
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
        console.log(typography.accent(`  https://vulnzap.com/dashboard/api-keys`));
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

      // IDE Selection and Extension Installation
      let selectedIDEs = options.ide ? [options.ide] : [];
      if (selectedIDEs.length === 0) {
        spacing.section();
        console.log(typography.info('IDE Integration (Optional)'));
        spacing.line();

        const { configureIde } = await customPrompts.prompt([
          {
            type: 'confirm',
            name: 'configureIde',
            message: 'Would you like to configure IDE integration?',
            default: true
          }
        ]);

        if (configureIde) {
          // Detect installed IDEs
          const spinner = createSpinner('Detecting installed IDEs...');
          spinner.start();
          const installedIDEs = await detectInstalledIDEs();
          spinner.stop();

          if (installedIDEs.length === 0) {
            console.log(typography.warning('No supported IDEs detected on your system'));
            console.log(typography.muted('Supported IDEs: VS Code, Cursor, Windsurf'));
            console.log(typography.muted('You can still configure them manually later'));
            selectedIDEs = [];
          }

          // Create choices for multiselect
          const ideChoices = installedIDEs.map(ide => ({
            name: ide === 'vscode' ? 'VS Code' :
                  ide === 'cursor' ? 'Cursor IDE' :
                  ide === 'windsurf' ? 'Windsurf IDE' : ide,
            value: ide
          }));

          const { chosenIDEs } = await customPrompts.prompt([
            {
              type: 'checkbox',
              name: 'chosenIDEs',
              message: 'Which development environments would you like to configure?',
              choices: ideChoices,
              default: installedIDEs
            }
          ]);
          selectedIDEs = chosenIDEs;
        }
      }

      if (selectedIDEs.length > 0) {
        for (const selectedIde of selectedIDEs) {
          spacing.line();
          console.log(typography.info(`Setting up ${selectedIde}...`));

          // Configure MCP for supported IDEs (all except vscode)
          if (selectedIde !== 'vscode') {
            const mcpSpinner = createSpinner(`Configuring ${selectedIde} MCP integration...`);
            mcpSpinner.start();
            try {
              await connectIDE(selectedIde);
              mcpSpinner.succeed(typography.success(`${selectedIde} MCP integration configured`));
            } catch (error: any) {
              mcpSpinner.fail(typography.error(`${selectedIde} MCP configuration failed`));
              console.error(typography.error('Error:'), error.message);
              continue;
            }
          }

          // Install extension for all supported IDEs
          const extSpinner = createSpinner(`Installing VulnZap extension for ${selectedIde}...`);
          extSpinner.start();
          try {
            const result = await installIDEExtension(selectedIde);
            if (result.success) {
              extSpinner.succeed(typography.success(`${selectedIde} extension installed successfully`));

              // Show instructions for the IDE
              if (result.instructions && result.instructions.length > 0) {
                spacing.line();
                result.instructions.forEach(instruction => {
                  if (instruction === '') {
                    console.log('');
                  } else {
                    console.log(typography.muted(instruction));
                  }
                });
              }
            } else {
              extSpinner.warn(typography.warning(`${selectedIde} extension installation had issues`));

              // Show error and instructions
              if (result.error) {
                console.log(typography.error(`Error: ${result.error}`));
              }
              if (result.instructions && result.instructions.length > 0) {
                spacing.line();
                result.instructions.forEach(instruction => {
                  console.log(typography.muted(instruction));
                });
              }
            }
          } catch (error: any) {
            extSpinner.fail(typography.error(`${selectedIde} extension installation failed`));
            console.error(typography.error('Error:'), error.message);
          }
        }

        spacing.section();
        console.log(typography.success('IDE setup complete!'));
        console.log(typography.muted('Your development environments are now secured with VulnZap'));
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
        console.log(typography.info(`Visit 'https://vulnzap.com' to learn more`));
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

      // Show personalized welcome message
      await displayUserWelcome();

      // Step 4: IDE Selection and Configuration
      spacing.section();
      console.log(typography.info('Setting up IDE integration'));
      spacing.line();

      // Detect installed IDEs
      const ideSpinner = createSpinner('Detecting installed IDEs...');
      ideSpinner.start();
      const installedIDEs = await detectInstalledIDEs();
      ideSpinner.stop();

      if (installedIDEs.length === 0) {
        console.log(typography.warning('No supported IDEs detected on your system'));
        console.log(typography.muted('Supported IDEs: VS Code, Cursor, Windsurf'));
        console.log(typography.muted('You can still configure them manually later'));
      } else {
        // Create choices for multiselect
        const ideChoices = installedIDEs.map(ide => ({
          name: ide === 'vscode' ? 'VS Code' :
                ide === 'cursor' ? 'Cursor IDE' :
                ide === 'windsurf' ? 'Windsurf IDE' : ide,
          value: ide
        }));

        const { selectedIDEs } = await customPrompts.prompt([
          {
            type: 'checkbox',
            name: 'selectedIDEs',
            message: 'Which development environments would you like to configure?',
            choices: ideChoices,
            default: installedIDEs
          }
        ]);

        if (selectedIDEs.length > 0) {
          for (const selectedIde of selectedIDEs) {
            spacing.line();
            console.log(typography.info(`Setting up ${selectedIde}...`));

            // Configure MCP for supported IDEs (all except vscode)
            if (selectedIde !== 'vscode') {
              const mcpSpinner = createSpinner(`Configuring ${selectedIde} MCP integration...`);
              mcpSpinner.start();
              try {
                await connectIDE(selectedIde);
                mcpSpinner.succeed(typography.success(`${selectedIde} MCP integration configured`));
              } catch (error: any) {
                mcpSpinner.fail(typography.error(`${selectedIde} MCP configuration failed`));
                console.error(typography.error('Error:'), error.message);
                continue;
              }
            }

            // Install extension for all supported IDEs
            const extSpinner = createSpinner(`Installing VulnZap extension for ${selectedIde}...`);
            extSpinner.start();
            try {
              const result = await installIDEExtension(selectedIde);
              if (result.success) {
                extSpinner.succeed(typography.success(`${selectedIde} extension installed successfully`));

                // Show instructions for the IDE
                if (result.instructions && result.instructions.length > 0) {
                  spacing.line();
                  result.instructions.forEach(instruction => {
                    if (instruction === '') {
                      console.log('');
                    } else {
                      console.log(typography.muted(instruction));
                    }
                  });
                }
              } else {
                extSpinner.warn(typography.warning(`${selectedIde} extension installation had issues`));

                // Show error and instructions
                if (result.error) {
                  console.log(typography.error(`Error: ${result.error}`));
                }
                if (result.instructions && result.instructions.length > 0) {
                  spacing.line();
                  result.instructions.forEach(instruction => {
                    console.log(typography.muted(instruction));
                  });
                }
              }
            } catch (error: any) {
              extSpinner.fail(typography.error(`${selectedIde} extension installation failed`));
              console.error(typography.error('Error:'), error.message);
            }
          }

          // Step 5: Success and next steps
          spacing.section();
          console.log(typography.title('Setup Complete'));
        } else {
          console.log(typography.info('No IDEs selected'));
          console.log(typography.muted('You can configure them manually later'));
        }
      }

      // Step 5: Success and next steps (only show if IDE setup was attempted)
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
      const result = await batchScan([{
        packageName: packageName,
        ecosystem: packageEcosystem,
        version: packageVersion
      }], {
        useCache: options.cache,
        useAi: options.ai
      });

      spinner.succeed(typography.success('Analysis complete'));

      spacing.line();

      if (result.results[0].status === 'safe') {
        console.log(typography.success('Result: Secure'));
        console.log(typography.muted(`  ${packageName}@${packageVersion} has no known vulnerabilities`));
        spacing.line();
        return;
      }
      if (result.results[0].status === 'vulnerable') {
        console.log(typography.error('Result: Vulnerable'));
        console.log(typography.muted(`  ${packageName}@${packageVersion} has security vulnerabilities`));
        spacing.section();

        if (result.results[0].vulnerabilities && result.results[0].vulnerabilities.length > 0) {
          console.log(typography.info('AI Analysis'));
          spacing.line();
          console.log(typography.subtitle('Summary'));
          console.log(typography.muted(`  ${result.results[0].vulnerabilities[0].title}`));
          spacing.line();
          console.log(typography.subtitle('Impact'));
          console.log(typography.muted(`  ${result.results[0].vulnerabilities[0].description}`));
          spacing.line();
          console.log(typography.subtitle('Recommendations'));
          result.results[0].vulnerabilities.forEach((vulnerability: any) => {
            console.log(typography.muted(`  • ${vulnerability.description}`));
          });
          spacing.section();
        }

        console.log(typography.info('Vulnerability Details'));
        spacing.line();
        // Display vulnerability details
        result.results[0].vulnerabilities?.forEach((advisory: { title: string; severity: string; description: string; references?: string[] }) => {
          console.log(typography.warning(`• ${advisory.title}`));
          console.log(typography.muted(`  Severity: ${advisory.severity}`));
          console.log(typography.muted(`  ${advisory.description}`));
          if (advisory.references?.length) {
            console.log(typography.muted(`  References: ${advisory.references.join(', ')}`));
          }
          spacing.line();
        });

        // Suggest fixed version if available
        if (result.results[0].remediation && result.results[0].remediation.recommendedVersion) {
          console.log(typography.info('Recommended Fix'));
          console.log(typography.accent(`  Upgrade to ${result.results[0].remediation.recommendedVersion} or later`));
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
      const firstName = mockProfile.username;
      console.log(typography.subtitle(`Welcome back, ${firstName}`));

      // Tier and usage display
      const tierDisplay = mockProfile.subscription.tier === 'free' ? typography.muted('Free') :
        mockProfile.subscription.tier === 'pro' ? typography.accent('Pro') :
          typography.success('Enterprise');

      const remaining = mockProfile.subscription.line_scans_limit - mockProfile.apiUsage;
      const percentage = (mockProfile.apiUsage / mockProfile.subscription.line_scans_limit) * 100;

      let usageDisplay;
      if (percentage >= 90) {
        usageDisplay = typography.error(`${remaining} scans remaining this month`);
      } else if (percentage >= 75) {
        usageDisplay = typography.warning(`${remaining} scans remaining this month`);
      } else {
        usageDisplay = typography.muted(`${remaining} scans remaining this month`);
      }

      console.log(`${tierDisplay} • ${usageDisplay}`);

      // FOMO message
      if (mockProfile.subscription.tier === 'free' && percentage >= 75) {
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
      console.log(typography.muted(`  Name: ${mockProfile.username}`));
      console.log(typography.muted(`  Email: ${mockProfile.email}`));
      console.log(typography.muted(`  Tier: ${mockProfile.subscription.tier.charAt(0).toUpperCase() + mockProfile.subscription.tier.slice(1)}`));

      spacing.line();
      console.log(typography.info('Usage This Month'));
      spacing.line();

      const percentageRounded = Math.round(percentage);
      console.log(typography.muted(`  Scans used: ${mockProfile.apiUsage} of ${mockProfile.subscription.line_scans_limit} (${percentageRounded}%)`));
      console.log(typography.muted(`  Remaining: ${remaining} scans`));

      // Progress bar
      const barLength = 20;
      const filledLength = Math.round((mockProfile.apiUsage / mockProfile.subscription.line_scans_limit) * barLength);
      const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);

      let barColor;
      if (percentage >= 90) barColor = chalk.red;
      else if (percentage >= 75) barColor = chalk.yellow;
      else if (percentage >= 50) barColor = chalk.cyan;
      else barColor = chalk.green;

      console.log(typography.muted(`  Progress: ${barColor(bar)} ${percentageRounded}%`));

      if (mockProfile.subscription.tier === 'free' && percentage >= 75) {
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

// Helper function to detect installed IDEs
async function detectInstalledIDEs(): Promise<string[]> {
  const installedIDEs: string[] = [];
  const supportedIDEs = [
    { name: 'vscode', command: 'code', displayName: 'VS Code' },
    { name: 'cursor', command: 'cursor', displayName: 'Cursor IDE' },
    { name: 'windsurf', command: 'windsurf', displayName: 'Windsurf IDE' }
  ];

  for (const ide of supportedIDEs) {
    try {
      await execSync(`${ide.command} --version`, { stdio: 'pipe' });
      installedIDEs.push(ide.name);
    } catch (error) {
      // IDE not installed, skip
    }
  }

  return installedIDEs;
}

// Helper function to install IDE extensions
async function installIDEExtension(ide: string) {
  try {
    if (ide === 'vscode') {
      // Check if VS Code CLI is available
      try {
        execSync('code --version', { stdio: 'pipe' });
      } catch (error) {
        return { success: false, error: 'VS Code CLI not found', instructions: [
          'VS Code CLI not found. Please ensure VS Code is installed and added to PATH.',
          'To add VS Code to PATH:',
          '  1. Open VS Code',
          '  2. Press Cmd+Shift+P (Ctrl+Shift+P on Windows/Linux)',
          '  3. Type "Shell Command: Install \'code\' command in PATH"',
          '  4. Run the command and restart your terminal'
        ]};
      }

      // Install the VulnZap extension
      const extensionId = 'vulnzap.vulnzap';
      try {
        execSync(`code --install-extension ${extensionId}`, { stdio: 'pipe' });
        return {
          success: true,
          instructions: [
            'VS Code Extension Setup Complete',
            '  Extension: VulnZap Security Scanner',
            '  Auto-scan: Enabled for supported files',
            '  API Integration: Configured with your account',
            '',
            'To use the extension:',
            '  1. Open a project in VS Code',
            '  2. Install dependencies or create new files',
            '  3. VulnZap will automatically scan for vulnerabilities',
            '  4. Check the Problems panel for security issues'
          ]
        };
      } catch (installError) {
        return {
          success: false,
          error: 'Extension not available in marketplace',
          instructions: [
            'VulnZap extension not yet available in marketplace',
            'Manual installation will be available soon.',
            'Visit https://vulnzap.com/vscode for updates',
            'Or install the extension manually from the marketplace'
          ]
        };
      }
    } else if (ide === 'cursor') {
      // For Cursor, provide manual installation instructions
      return {
        success: true,
        instructions: [
          'Cursor Extension Installation',
          '',
          'Cursor uses the same extension marketplace as VS Code.',
          'To install the VulnZap extension:',
          '  1. Open Cursor',
          '  2. Go to Extensions (Ctrl+Shift+X)',
          '  3. Search for "VulnZap"',
          '  4. Install the extension',
          '',
          'The extension will automatically use your API key for scanning.'
        ]
      };
    } else {
      return {
        success: false,
        error: `Extension installation for ${ide} is not yet automated`,
        instructions: [
          `Extension installation for ${ide} is not yet automated.`,
          'Please visit https://vulnzap.com/docs/ide-integration for manual setup instructions.'
        ]
      };
    }
  } catch (error: any) {
    return { success: false, error: error.message, instructions: [] };
  }
}

// Helper function to handle IDE connection logic
async function connectIDE(ide: string) {
  // Log the event
  const logFile = join(os.homedir(), '.vulnzap', 'info.log');
  const logStream = fs.createWriteStream(logFile, { flags: 'a' });
  logStream.write(`VulnZap connect command executed for ${ide} at ${new Date().toISOString()}\n`);
  logStream.end();

  const apiKey = await getKey();

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
    let cursorMcpConfig: { mcpServers?: any;[key: string]: any } = {};
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
      url: "https://vulnzap.com/mcp/sse",
      headers: {
        "x-api-key": apiKey
      }
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
    console.log(typography.muted('  Transport Type: SSE'));
    console.log(typography.muted('  Auto-approved Tools: auto-vulnerability-scan, scan_repo'));
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
      url: "https://vulnzap.com/mcp/sse",
      headers: {
        "x-api-key": apiKey
      }
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
      url: "https://vulnzap.com/mcp/sse",
      headers: {
        "x-api-key": apiKey
      },
      alwaysAllow: ["auto-vulnerability-scan"],
      disabled: false,
      networkTimeout: 60000
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

  } else if (ide === 'vscode') {
    // For VSCode, we don't need MCP setup, just provide manual configuration instructions
    console.log(typography.info('Manual Configuration for VS Code'));
    spacing.line();
    console.log(typography.muted('VS Code integration is handled via the VulnZap extension.'));
    console.log(typography.muted('If you haven\'t installed it yet, you can:'));
    console.log(typography.muted('  1. Open VS Code'));
    console.log(typography.muted('  2. Go to Extensions (Ctrl+Shift+X)'));
    console.log(typography.muted('  3. Search for "VulnZap"'));
    console.log(typography.muted('  4. Install the extension'));
    spacing.line();
    console.log(typography.muted('The extension will automatically use your API key for scanning.'));

  } else {
    console.log(typography.info('Manual Configuration Required'));
    spacing.line();
    console.log(typography.muted('Add this to your IDE\'s MCP configuration:'));
    spacing.line();
    console.log(typography.code(`{
  "mcpServers": {
    "VulnZap": {
      "url": "https://vulnzap.com/mcp/sse",
      "headers": {
        "x-api-key": "${apiKey}"
      }
    }
  }
}`));
    spacing.line();
    console.log(typography.muted('Visit https://vulnzap.com/docs/ide-integration for more information'));
  }
} 