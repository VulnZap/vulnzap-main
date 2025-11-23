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
// Lazy import for MCP server - only loaded when 'mcp' command is executed
import { startRepoScan, getRepoScanStatus, getScanResults, streamScanEvents, ScanEvent } from './api/repoScan.js';
import { v4 as uuidv4 } from 'uuid';
import { VulnzapClient } from '@vulnzap/client';

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

import { typography, layout } from './utils/typography.js';

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
    layout.banner(version);
    console.log(typography.header('Setup Configuration'));
    layout.spacer();
    console.log(typography.header('Setup Configuration'));
    layout.spacer();

    try {
      // Check if API key already exists
      let existingKey;
      try {
        existingKey = await getKey();
      } catch (error) {
        existingKey = null;
      }

      if (existingKey) {
        console.log(typography.dim('  An API key is already configured'));
        layout.spacer();

        const { confirm } = await customPrompts.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: 'Replace existing configuration?',
            default: false
          }
        ]);

        if (!confirm) {
          console.log(typography.dim('  Configuration unchanged'));

          if (options.ide) {
            layout.section();
            console.log(typography.accent('Configuring IDE integration...'));
            await connectIDE(options.ide);
          }
          return;
        }
      }

      if (!options.key) {
        layout.spacer();
        console.log(typography.dim('  Get your API key from:'));
        console.log(typography.accent(`  https://vulnzap.com/dashboard/api-keys`));
        console.log(typography.dim('  (Ensure you are signed in to your account)'));
        layout.section();
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
        layout.section();
        console.log(typography.accent('IDE Integration (Optional)'));
        layout.spacer();

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
            console.log(typography.dim('Supported: GitHub Copilot (VS Code, Cursor, Windsurf, JetBrains), Antigravity, Claude Code'));
            console.log(typography.dim('You can configure them manually with: vulnzap connect'));
            selectedIDEs = [];
          } else {
            // Step 1: Ask what category they want to configure
            const { ideCategory } = await customPrompts.prompt([
              {
                type: 'list',
                name: 'ideCategory',
                message: 'What would you like to configure?',
                choices: [
                  {
                    name: 'Standalone (Cursor IDE, Windsurf IDE, Antigravity, Claude Code)',
                    value: 'standalone'
                  },
                  {
                    name: 'GitHub Copilot (works with VS Code, Cursor, Windsurf, JetBrains)',
                    value: 'copilot'
                  },
                  {
                    name: 'Skip for now',
                    value: 'skip'
                  }
                ]
              }
            ]);

            if (ideCategory === 'skip') {
              selectedIDEs = [];
            } else if (ideCategory === 'standalone') {
              // Filter for standalone IDEs (includes Cursor and Windsurf as standalone)
              const standaloneIDEs = installedIDEs.filter(ide =>
                ['cursor', 'windsurf', 'antigravity', 'claude'].includes(ide)
              );

              if (standaloneIDEs.length === 0) {
                console.log(typography.warning('No standalone IDEs detected'));
                console.log(typography.dim('Install Cursor, Windsurf, Antigravity, or Claude Code to continue'));
                selectedIDEs = [];
              } else {
                const standaloneChoices = standaloneIDEs.map(ide => {
                  const isInstalled = isMcpInstalled(ide);
                  const installedTag = isInstalled ? chalk.green(' (Configured)') : '';

                  let name = '';
                  if (ide === 'cursor') name = 'Cursor IDE';
                  else if (ide === 'windsurf') name = 'Windsurf IDE';
                  else if (ide === 'antigravity') name = 'Antigravity';
                  else if (ide === 'claude') name = 'Claude Code';
                  else name = ide;

                  return {
                    name: `${name}${installedTag}`,
                    value: ide,
                    checked: !isInstalled
                  };
                });

                const { chosenIDEs } = await customPrompts.prompt([
                  {
                    type: 'checkbox',
                    name: 'chosenIDEs',
                    message: 'Which standalone IDEs would you like to configure?',
                    choices: standaloneChoices
                  }
                ]);

                selectedIDEs = chosenIDEs;
              }
            } else if (ideCategory === 'copilot') {
              // Filter for Copilot-compatible IDEs
              const copilotIDEs = installedIDEs.filter(ide =>
                ['vscode', 'cursor', 'windsurf', 'jetbrains'].includes(ide)
              );

              if (copilotIDEs.length === 0) {
                console.log(typography.warning('No GitHub Copilot-compatible IDEs detected'));
                console.log(typography.dim('Install VS Code, Cursor, Windsurf, or a JetBrains IDE to continue'));
                selectedIDEs = [];
              } else {
                const copilotChoices = copilotIDEs.map(ide => {
                  const isInstalled = isMcpInstalled(ide);
                  const installedTag = isInstalled ? chalk.green(' (Configured)') : '';

                  let name = '';
                  if (ide === 'vscode') name = 'VS Code';
                  else if (ide === 'cursor') name = 'Cursor';
                  else if (ide === 'windsurf') name = 'Windsurf';
                  else if (ide === 'jetbrains') name = 'JetBrains (IntelliJ/WebStorm/etc)';
                  else name = ide;

                  return {
                    name: `${name}${installedTag}`,
                    value: ide,
                    checked: !isInstalled
                  };
                });

                const { chosenIDEs } = await customPrompts.prompt([
                  {
                    type: 'checkbox',
                    name: 'chosenIDEs',
                    message: 'Which IDEs do you use with GitHub Copilot?',
                    choices: copilotChoices
                  }
                ]);

                selectedIDEs = chosenIDEs;
              }
            }
          }
        }
      }

      if (selectedIDEs.length > 0) {
        for (const selectedIde of selectedIDEs) {
          layout.spacer();
          console.log(typography.accent(`Setting up ${selectedIde}...`));

          // Configure MCP for all supported IDEs
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

        layout.section();
        console.log(typography.success('IDE setup complete!'));
        console.log(typography.dim('Your development environments are now secured with VulnZap'));
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
      layout.spacer();
      console.log(typography.dim('Setup cancelled. Run `vulnzap init` again anytime.'));
      process.exit(0);
    };

    process.on('SIGINT', handleExit);
    process.on('SIGTERM', handleExit);

    try {
      layout.banner(version);
      console.log(typography.header('Welcome to VulnZap'));
      console.log(typography.subheader('Let\'s configure your security-first development environment.'));
      layout.section();

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
        layout.spacer();
        console.log(typography.accent(`Visit 'https://vulnzap.com' to learn more`));
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
        layout.spacer();

        const { replaceKey } = await customPrompts.prompt([
          {
            type: 'confirm',
            name: 'replaceKey',
            message: 'Re-authenticate with a different account?',
            default: false
          }
        ]);

        if (!replaceKey) {
          console.log(typography.dim('  Using existing authentication'));
        } else {
          existingKey = null;
        }
      }

      // Step 3: Magic Auth Flow
      if (!existingKey) {
        const { displayMagicAuth, displayAuthWaiting, displayAuthSuccess, displayAuthError } = await import('./utils/magicAuth.js');

        await displayMagicAuth();

        try {
          const { success, error } = await auth.login("login");

          if (success) {
            await displayAuthSuccess();
            await displayUserWelcome();
          } else {
            displayAuthError(error);
            process.exit(1);
          }
        } catch (error: any) {
          displayAuthError(error.message);
          process.exit(1);
        }
      } else {
        // Show personalized welcome message for existing users
        await displayUserWelcome();
      }

      // Step 4: IDE Selection and Configuration
      layout.section();
      console.log(typography.accent('Setting up IDE integration'));
      layout.spacer();

      // Detect installed IDEs
      const ideSpinner = createSpinner('Detecting installed IDEs...');
      ideSpinner.start();
      const installedIDEs = await detectInstalledIDEs();
      ideSpinner.stop();

      let selectedIDEs: string[] = [];

      if (installedIDEs.length === 0) {
        console.log(typography.warning('No supported IDEs detected on your system'));
        console.log(typography.dim('Supported: GitHub Copilot (VS Code, Cursor, Windsurf, JetBrains), Antigravity, Claude Code'));
        console.log(typography.dim('You can configure them manually later with: vulnzap connect'));
      } else {
        // Step 1: Ask what category they want to configure
        const { ideCategory } = await customPrompts.prompt([
          {
            type: 'list',
            name: 'ideCategory',
            message: 'What would you like to configure?',
            choices: [
              {
                name: 'Standalone (Cursor IDE, Windsurf IDE, Antigravity, Claude Code)',
                value: 'standalone'
              },
              {
                name: 'GitHub Copilot (works with VS Code, Cursor, Windsurf, JetBrains)',
                value: 'copilot'
              },
              {
                name: 'Skip for now',
                value: 'skip'
              }
            ]
          }
        ]);

        if (ideCategory === 'skip') {
          console.log(typography.dim('You can set this up later with: vulnzap connect'));
        } else if (ideCategory === 'standalone') {
          // Filter for standalone IDEs (includes Cursor and Windsurf as standalone)
          const standaloneIDEs = installedIDEs.filter(ide =>
            ['cursor', 'windsurf', 'antigravity', 'claude'].includes(ide)
          );

          if (standaloneIDEs.length === 0) {
            console.log(typography.warning('No standalone IDEs detected'));
            console.log(typography.dim('Install Cursor, Windsurf, Antigravity, or Claude Code to continue'));
          } else {
            const standaloneChoices = standaloneIDEs.map(ide => {
              const isInstalled = isMcpInstalled(ide);
              const installedTag = isInstalled ? chalk.green(' (Configured)') : '';

              let name = '';
              if (ide === 'cursor') name = 'Cursor IDE';
              else if (ide === 'windsurf') name = 'Windsurf IDE';
              else if (ide === 'antigravity') name = 'Antigravity';
              else if (ide === 'claude') name = 'Claude Code';
              else name = ide;

              return {
                name: `${name}${installedTag}`,
                value: ide,
                checked: !isInstalled
              };
            });

            const { selectedStandaloneIDEs } = await customPrompts.prompt([
              {
                type: 'checkbox',
                name: 'selectedStandaloneIDEs',
                message: 'Which standalone IDEs would you like to configure?',
                choices: standaloneChoices
              }
            ]);

            selectedIDEs = selectedStandaloneIDEs;
          }
        } else if (ideCategory === 'copilot') {
          // Filter for Copilot-compatible IDEs
          const copilotIDEs = installedIDEs.filter(ide =>
            ['vscode', 'cursor', 'windsurf', 'jetbrains'].includes(ide)
          );

          if (copilotIDEs.length === 0) {
            console.log(typography.warning('No GitHub Copilot-compatible IDEs detected'));
            console.log(typography.dim('Install VS Code, Cursor, Windsurf, or a JetBrains IDE to continue'));
          } else {
            const copilotChoices = copilotIDEs.map(ide => {
              const isInstalled = isMcpInstalled(ide);
              const installedTag = isInstalled ? chalk.green(' (Configured)') : '';

              let name = '';
              if (ide === 'vscode') name = 'VS Code';
              else if (ide === 'cursor') name = 'Cursor';
              else if (ide === 'windsurf') name = 'Windsurf';
              else if (ide === 'jetbrains') name = 'JetBrains (IntelliJ/WebStorm/etc)';
              else name = ide;

              return {
                name: `${name}${installedTag}`,
                value: ide,
                checked: !isInstalled
              };
            });

            const { selectedCopilotIDEs } = await customPrompts.prompt([
              {
                type: 'checkbox',
                name: 'selectedCopilotIDEs',
                message: 'Which IDEs do you use with GitHub Copilot?',
                choices: copilotChoices
              }
            ]);

            selectedIDEs = selectedCopilotIDEs;
          }
        }

        if (selectedIDEs.length > 0) {
          for (const selectedIde of selectedIDEs) {
            layout.spacer();
            console.log(typography.accent(`Setting up ${selectedIde}...`));

            // Configure MCP for all supported IDEs
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
        }
      }

      // Step 5: Tool Spotlight - Show users what they just unlocked
      if (selectedIDEs.length > 0) {
        layout.section();
        const { wantSpotlight } = await customPrompts.prompt([
          {
            type: 'confirm',
            name: 'wantSpotlight',
            message: 'Would you like a quick tour of the security tools now available to your AI?',
            default: true
          }
        ]);

        if (wantSpotlight) {
          const { displayToolSpotlight } = await import('./utils/toolSpotlight.js');
          await displayToolSpotlight();
        } else {
          const { displayToolSummary } = await import('./utils/toolSpotlight.js');
          displayToolSummary();
        }
      }

      // Final: Premium completion screen
      layout.clear();
      layout.section();

      // Success Banner
      console.log(typography.header('  🎉 Setup Complete'));
      layout.spacer();
      console.log(typography.subheader('  VulnZap is now protecting your AI-powered development'));
      layout.section();

      // Quick actions
      console.log(typography.accent('  Quick Start:'));
      console.log(typography.body('  • Open your IDE and start coding'));
      console.log(typography.body('  • Your AI now has security superpowers'));
      console.log(typography.body('  • Vulnerabilities will be caught automatically'));
      layout.section();

      // Additional resources
      console.log(typography.dim('  📖 Documentation: vulnzap.com/docs'));
      console.log(typography.dim('  🔧 Run `vulnzap status` to verify setup'));
      console.log(typography.dim('  💬 Need help? vulnzap.com/support'));
      layout.section();

    } catch (error: any) {
      layout.section();
      console.error(typography.error('Setup failed:'), error.message);
      layout.spacer();
      console.log(typography.dim('Recovery options:'));
      console.log(typography.dim('  • Run `vulnzap init` again to retry'));
      console.log(typography.dim('  • Run `vulnzap setup` for manual configuration'));
      console.log(typography.dim('  • Visit vulnzap.com/support for help'));
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
    layout.banner(version);
    console.log(typography.header('System Status'));
    layout.spacer();

    const spinner = createSpinner('Checking server health...');
    spinner.start();

    try {
      await checkHealth();
      spinner.succeed(typography.success('Server is healthy'));

      // Check authentication
      layout.spacer();
      const authSpinner = createSpinner('Checking authentication...');
      authSpinner.start();

      try {
        await getKey();
        authSpinner.succeed(typography.success('Authentication configured'));

        // Show user profile information
        layout.section();
        await displayUserStatus();

      } catch (error) {
        authSpinner.fail(typography.warning('Authentication not configured'));
        layout.spacer();
        console.log(typography.dim('Run `vulnzap setup` to configure authentication'));
      }

      layout.section();
      console.log(typography.accent('System ready for secure development'));

    } catch (error: any) {
      spinner.fail(typography.warning('Server is offline'));
      layout.spacer();
      console.log(typography.dim('Local cache will be used when available'));
      console.log(typography.dim('Some features may be limited'));
    }
  });

// Command: vulnzap check
program
  .command('check <package>')
  .description('Analyze package for security vulnerabilities')
  .option('-e, --ecosystem <ecosystem>', 'Package ecosystem (npm, pip, go, rust, etc.)')
  .action(async (packageInput, options) => {
    layout.banner(version);
    console.log(typography.header('Vulnerability Scan'));
    layout.spacer();

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
      layout.section();
      console.log(typography.accent('Supported formats:'));
      console.log(typography.dim('  1. ecosystem:package-name@version (recommended)'));
      console.log(typography.code('vulnzap check npm:express@4.17.1'));
      layout.spacer();
      console.log(typography.dim('  2. package-name@version with --ecosystem flag'));
      console.log(typography.code('vulnzap check express@4.17.1 --ecosystem npm'));
      layout.spacer();
      console.log(typography.dim('Supported ecosystems: npm, pip, go, rust, maven, gradle, composer, nuget, pypi'));
      process.exit(1);
    }

    // Validate ecosystem
    const supportedEcosystems = ['npm', 'pip', 'go', 'rust', 'maven', 'gradle', 'composer', 'nuget', 'pypi'];
    if (!supportedEcosystems.includes(packageEcosystem.toLowerCase())) {
      console.error(typography.error(`Unsupported ecosystem '${packageEcosystem}'`));
      console.log(typography.dim(`Supported ecosystems: ${supportedEcosystems.join(', ')}`));
      process.exit(1);
    }

    console.log(typography.dim(`  Analyzing ${packageEcosystem}:${packageName}@${packageVersion}`));
    layout.spacer();

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

      layout.spacer();

      if (result.results[0].status === 'safe') {
        console.log(typography.success('Result: Secure'));
        console.log(typography.dim(`  ${packageName}@${packageVersion} has no known vulnerabilities`));
        layout.spacer();
        return;
      }
      if (result.results[0].status === 'vulnerable') {
        console.log(typography.error('Result: Vulnerable'));
        console.log(typography.dim(`  ${packageName}@${packageVersion} has security vulnerabilities`));
        layout.section();

        if (result.results[0].vulnerabilities && result.results[0].vulnerabilities.length > 0) {
          console.log(typography.accent('AI Analysis'));
          layout.spacer();
          console.log(typography.subheader('Summary'));
          console.log(typography.dim(`  ${result.results[0].vulnerabilities[0].title}`));
          layout.spacer();
          console.log(typography.subheader('Impact'));
          console.log(typography.dim(`  ${result.results[0].vulnerabilities[0].description}`));
          layout.spacer();
          console.log(typography.subheader('Recommendations'));
          result.results[0].vulnerabilities.forEach((vulnerability: any) => {
            console.log(typography.dim(`  • ${vulnerability.description}`));
          });
          layout.section();
        }

        console.log(typography.accent('Vulnerability Details'));
        layout.spacer();
        // Display vulnerability details
        result.results[0].vulnerabilities?.forEach((advisory: { title: string; severity: string; description: string; references?: string[] }) => {
          console.log(typography.warning(`• ${advisory.title}`));
          console.log(typography.dim(`  Severity: ${advisory.severity}`));
          console.log(typography.dim(`  ${advisory.description}`));
          if (advisory.references?.length) {
            console.log(typography.dim(`  References: ${advisory.references.join(', ')}`));
          }
          layout.spacer();
        });

        // Suggest fixed version if available
        if (result.results[0].remediation && result.results[0].remediation.recommendedVersion) {
          console.log(typography.accent('Recommended Fix'));
          console.log(typography.accent(`  Upgrade to ${result.results[0].remediation.recommendedVersion} or later`));
          layout.spacer();
        }
      }
    } catch (error: any) {
      if (error.message === 'SERVER_DOWN') {
        spinner.stop();
        console.log(typography.warning('VulnZap server is offline. Using local cache if available.'));
        const cached = cacheService.readCache(packageName, packageVersion, packageEcosystem);
        if (cached) {
          console.log(typography.success('Found cached scan result (from local cache, may be outdated)'));
          layout.spacer();

          // Print cached result in a user-friendly way
          if (cached.error) {
            console.error(typography.error(cached.error));
            return;
          }
          if (cached.isUnknown) {
            console.log(typography.warning(`Unknown: ${cached.message}`));
            if (cached.sources && cached.sources.length > 0) {
              console.log(typography.dim(`  Sources checked: ${cached.sources.join(', ')}`));
            }
            return;
          }
          if (!cached.isVulnerable) {
            console.log(typography.success(`Safe: ${packageName}@${packageVersion} has no known vulnerabilities`));
            if (cached.sources && cached.sources.length > 0) {
              console.log(typography.dim(`  Sources checked: ${cached.sources.join(', ')}`));
            }
            layout.spacer();
            return;
          }
          if (cached.isVulnerable) {
            console.log(typography.error(`Vulnerable: ${packageName}@${packageVersion} has vulnerabilities`));
            layout.spacer();

            if (cached.processedVulnerabilities && cached.processedVulnerabilities.summary) {
              console.log(typography.accent('AI Analysis:'));
              console.log(typography.body(cached.processedVulnerabilities.summary));
              layout.spacer();

              console.log(typography.accent('Impact:'));
              console.log(typography.body(cached.processedVulnerabilities.impact));
              layout.spacer();

              console.log(typography.accent('Recommendations:'));
              cached.processedVulnerabilities.recommendations.forEach((recommendation: string) => {
                console.log(typography.body(`• ${recommendation}`));
              });
              layout.spacer();
            }

            if (cached.sources && cached.sources.length > 0) {
              console.log(typography.dim(`Sources: ${cached.sources.join(', ')}`));
              layout.spacer();
            }

            console.log(typography.subheader('Advisories'));
            cached.advisories?.forEach((advisory: { title: string; severity: string; description: string; references?: string[] }) => {
              console.log(typography.accent(`• ${advisory.title}`));
              console.log(typography.dim(`  Severity: ${advisory.severity}`));
              console.log(typography.dim(`  Description: ${advisory.description}`));
              if (advisory.references?.length) {
                console.log(typography.dim(`  References: ${advisory.references.join(', ')}`));
              }
              layout.spacer();
            });

            if (cached.fixedVersions && cached.fixedVersions.length > 0) {
              console.log(typography.success('Suggested fix:'));
              console.log(typography.body(`Upgrade to ${cached.fixedVersions[0]} or later`));
              layout.spacer();
            }
          }
        } else {
          console.log(typography.error('No valid local cache found for this package/version (older than 5 days or never scanned).'));
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
    layout.banner(version);
    console.log(typography.header('MCP Server'));
    layout.spacer();

    // Prompt for IDE if not provided
    if (!options.ide) {
      const { ide } = await customPrompts.prompt([{
        type: 'list',
        name: 'ide',
        message: 'Which development environment are you using?',
        choices: [
          { name: `Cursor IDE${isMcpInstalled('cursor') ? chalk.green(' (Installed)') : ''}`, value: 'cursor' },
          { name: `Windsurf IDE${isMcpInstalled('windsurf') ? chalk.green(' (Installed)') : ''}`, value: 'windsurf' },
          { name: `Antigravity (New)${isMcpInstalled('antigravity') ? chalk.green(' (Installed)') : ''}`, value: 'antigravity' },
          { name: `Claude Code${isMcpInstalled('claude') ? chalk.green(' (Installed)') : ''}`, value: 'claude' }
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
      layout.spacer();
      console.log(typography.dim('Your development environment is now secured with VulnZap'));
    } catch (error: any) {
      spinner.fail(typography.error('Configuration failed'));
      console.error(typography.error('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap tools
program
  .command('tools')
  .description('Learn about the security tools available to your AI')
  .action(async () => {
    const { displayToolSpotlight } = await import('./utils/toolSpotlight.js');
    await displayToolSpotlight();
  });

// Command: vulnzap account
program
  .command('account')
  .description('View account information and settings')
  .action(async () => {
    layout.banner(version);
    console.log(typography.header('Account Information'));
    layout.section();

    try {
      // Show detailed user status
      await displayUserStatus();

      layout.section();
      console.log(typography.accent('Dashboard Access'));
      console.log(typography.dim('  Visit your dashboard to manage account settings:'));
      console.log(typography.accent('  https://vulnzap.com/dashboard'));
      layout.section();

      console.log(typography.accent('Available Features'));
      console.log(typography.dim('  • API key management'));
      console.log(typography.dim('  • Scan history and analytics'));
      console.log(typography.dim('  • Team collaboration tools'));
      console.log(typography.dim('  • Integration settings'));

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
      layout.section();
      console.log(typography.header('Scan Results'));
      layout.spacer();

      const vulnerableCount = results.results.filter(r => r.status === 'vulnerable').length;
      const safeCount = results.results.filter(r => r.status === 'safe').length;
      const errorCount = results.results.filter(r => r.status === 'error').length;

      console.log(typography.body(`Total packages: ${packages.length}`));
      console.log(typography.error(`Vulnerable:     ${vulnerableCount}`));
      console.log(typography.success(`Safe:           ${safeCount}`));
      if (errorCount > 0) {
        console.log(typography.warning(`Errors:         ${errorCount}`));
      }
      layout.spacer();

      // Save results to file if specified
      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
        console.log(typography.dim(`Results saved to: ${outputPath}`));
      } else {
        // Save to default location in .vulnzap
        const defaultOutputPath = path.join(vulnzapDir, 'batch-scan-results.json');
        fs.writeFileSync(defaultOutputPath, JSON.stringify(results, null, 2));
        console.log(typography.dim(`Results saved to: ${defaultOutputPath}`));
      }

      // Display detailed results
      if (vulnerableCount > 0) {
        layout.section();
        console.log(typography.subheader('Vulnerable Packages'));

        results.results
          .filter(r => r.status === 'vulnerable')
          .forEach(result => {
            layout.spacer();
            console.log(typography.error(`${result.package.packageName}@${result.package.version}`));
            console.log(typography.dim(`(${result.package.ecosystem})`));
            console.log(typography.body(result.message));

            if (result.vulnerabilities) {
              result.vulnerabilities.forEach(vuln => {
                layout.spacer();
                console.log(typography.accent(`• ${vuln.title}`));
                console.log(typography.dim(`  Severity: ${vuln.severity}`));
                console.log(typography.dim(`  ${vuln.description}`));
                if (vuln.references?.length) {
                  console.log(typography.dim(`  References: ${vuln.references.join(', ')}`));
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
    layout.banner(version);
    console.log(typography.header('Personalized CLI Demo'));
    layout.section();

    // Create mock profile for demo
    const mockProfile = getMockProfile(options.tier as 'free' | 'pro' | 'enterprise');

    try {
      console.log(typography.accent(`Demonstrating ${options.tier} tier experience:`));
      layout.spacer();

      // Manually create the displays with mock data
      const firstName = mockProfile.username;
      console.log(typography.subheader(`Welcome back, ${firstName}`));

      // Tier and usage display
      const tierDisplay = mockProfile.subscription.tier === 'free' ? typography.dim('Free') :
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
        usageDisplay = typography.dim(`${remaining} scans remaining this month`);
      }

      console.log(`${tierDisplay} • ${usageDisplay}`);

      // FOMO message
      if (mockProfile.subscription.tier === 'free' && percentage >= 75) {
        layout.spacer();
        if (percentage >= 90) {
          console.log(typography.warning('Upgrade to Pro for unlimited scans and advanced features'));
        } else {
          console.log(typography.dim('Consider upgrading to Pro to avoid hitting limits'));
        }
      }

      layout.section();
      console.log(typography.subheader('Full Status View:'));
      layout.spacer();

      console.log(typography.accent('Account Information'));
      layout.spacer();
      console.log(typography.dim(`  Name: ${mockProfile.username}`));
      console.log(typography.dim(`  Email: ${mockProfile.email}`));
      console.log(typography.dim(`  Tier: ${mockProfile.subscription.tier.charAt(0).toUpperCase() + mockProfile.subscription.tier.slice(1)}`));

      layout.spacer();
      console.log(typography.accent('Usage This Month'));
      layout.spacer();

      const percentageRounded = Math.round(percentage);
      console.log(typography.dim(`  Scans used: ${mockProfile.apiUsage} of ${mockProfile.subscription.line_scans_limit} (${percentageRounded}%)`));
      console.log(typography.dim(`  Remaining: ${remaining} scans`));

      // Progress bar
      const barLength = 20;
      const filledLength = Math.round((mockProfile.apiUsage / mockProfile.subscription.line_scans_limit) * barLength);
      const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);

      let barColor;
      if (percentage >= 90) barColor = chalk.red;
      else if (percentage >= 75) barColor = chalk.yellow;
      else if (percentage >= 50) barColor = chalk.cyan;
      else barColor = chalk.green;

      console.log(typography.dim(`  Progress: ${barColor(bar)} ${percentageRounded}%`));

      if (mockProfile.subscription.tier === 'free' && percentage >= 75) {
        layout.section();
        if (percentage >= 90) {
          console.log(typography.warning('Upgrade to Pro for unlimited scans and advanced features'));
        } else {
          console.log(typography.dim('Consider upgrading to Pro to avoid hitting limits'));
        }
        console.log(typography.dim('Visit vulnzap.com/pricing to upgrade'));
      }

    } catch (error: any) {
      console.error(typography.error('Demo failed:'), error.message);
    }
  });

// Command: vulnzap mcp
program
  .command('mcp')
  .description('Start the VulnZap MCP server for IDE integration')
  .action(async () => {
    try {
      // Lazy import MCP server to avoid loading @vulnzap/client when not needed
      const { startMcpServer } = await import('./mcp/server.js');
      // Start the MCP server
      await startMcpServer();
    } catch (error: any) {
      process.exit(1);
    }
  });

// Command: vulnzap watch
program
  .command('watch')
  .description('Watch a directory for changes and run security analysis')
  .option('-t, --timeout <milliseconds>', 'Timeout for the watcher in milliseconds', '120000') // 2 minutes default
  .option('-o, --output <dir>', 'Output directory for scan results')
  .action(async (options) => {
    layout.banner(version);
    console.log(typography.header('Security Assistant'));
    layout.spacer();

    const spinner = createSpinner('Initializing security assistant...');
    spinner.start();

    try {
      const apiKey = await getKey();
      const vulnzapClient = new VulnzapClient({ apiKey });
      const dirPath = process.cwd();
      const timeout = parseInt(options.timeout, 10);
      const sessionId = uuidv4();

      spinner.text = `Starting security assistant on "${dirPath}"...`;

      const watcher = vulnzapClient.securityAssistant({
        dirPath: dirPath,
        sessionId: sessionId,
        timeout: timeout,
      });

      const saveResults = async (res: any) => {
        const outputDir = options.output ? path.resolve(options.output) : path.join(dirPath, '.vulnzap', 'incremental');
        if (!options.output) {
          const vulnzapCwdDir = path.join(dirPath, '.vulnzap');
          if (!fs.existsSync(vulnzapCwdDir)) {
            fs.mkdirSync(vulnzapCwdDir, { recursive: true });
          }
        }
        
        spinner.start('Saving scan results...');
        try {
          if (res.success && res.data) {
            if (!fs.existsSync(outputDir)) {
              fs.mkdirSync(outputDir, { recursive: true });
            }
            const outputFile = path.join(outputDir, `vulnzap-results-${sessionId}.json`);
            fs.writeFileSync(outputFile, JSON.stringify(res.data, null, 2));
            spinner.succeed(`\nScan results saved to: ${outputFile}`);
          } else {
            spinner.warn(`\nCould not retrieve scan results: ${res.error || 'No data returned.'}`);
          }
        } catch (error: any) {
          spinner.fail('Failed to save results');
          console.error(typography.error(error.message));
        }
      };

      if (watcher) {
        spinner.succeed('Security assistant is running.');
        console.log(typography.dim(`  Watching for file changes in: ${dirPath}`));
        console.log(typography.dim(`  Session ID: ${sessionId}`));
        console.log(typography.dim(`  Timeout: ${timeout / 1000} seconds`));
        console.log(typography.accent('  Press Ctrl+C to stop the watcher and save results.'));
        layout.spacer();
        console.log(typography.dim('  To prevent logs and results from being committed, add ".vulnzap" to your .gitignore file.'));
        layout.spacer();
        
        vulnzapClient.on("update", (update: any) => {
          console.log(typography.dim(`  Update: ${update.message}`));
        });

        vulnzapClient.on('error', (error: any) => {
          console.error(typography.error(`\nWatcher error: ${error.message}`));
        });

        vulnzapClient.on('completed', async (completed: any) => {
          console.log(typography.success(`\nWatcher completed: ${completed.message}`));
          const res = await vulnzapClient.stopSecurityAssistant(sessionId);
          if (res.success) {
            await saveResults(res.data);
          }
          process.exit(0);
        });

        const timeoutHandle = setTimeout(async () => {
          console.log(typography.dim('\nWatcher session timed out.'));
          const res = await vulnzapClient.stopSecurityAssistant(sessionId);
          if (res.success) {
            await saveResults(res.data);
          }
          process.exit(0);
        }, timeout);
  
        process.on('SIGINT', async () => {
          console.log(typography.dim('\nWatcher stopped manually.'));
          clearTimeout(timeoutHandle);
          const res = await vulnzapClient.stopSecurityAssistant(sessionId);
          if (res.success) {
            await saveResults(res.data);
          }
          process.exit(0);
        });

      } else {
        spinner.fail('Failed to start the security assistant.');
        process.exit(1);
      }
    } catch (error: any) {
      spinner.fail('Failed to start security assistant');
      console.error(typography.error(error.message));
      if (error.code === 'MODULE_NOT_FOUND') {
          console.error(typography.dim('Could not load the Vulnzap client library. This might be a dependency issue.'));
      }
      process.exit(1);
    }
  });

// Command: vulnzap scan
program
  .command('scan <repoUrl>')
  .description('Start a vulnerability scan for a GitHub repository')
  .option('-b, --branch <branch>', 'Repository branch to scan', 'main')
  .option('--wait', 'Wait for scan completion and show results')
  .option('-o, --output <file>', 'Save scan results to a JSON file')
  .option('--key <key>', 'Use a specific API key')
  .action(async (repoUrl, options) => {
    layout.banner(version);
    console.log(typography.header('Setup Configuration'));
    console.log(typography.subheader('Configure your development environment'));
    layout.spacer();

    try {
      const spinner = createSpinner('Initiating repository scan...');
      spinner.start();

      const result = await startRepoScan({
        repoUrl,
        branch: options.branch,
        key: options.key
      });

      spinner.succeed(typography.success('Scan initiated successfully'));

      layout.spacer();
      console.log(typography.accent('Initializing VulnZap...'));
      console.log(typography.dim(`  Job ID: ${result.data.jobId}`));
      console.log(typography.dim(`  Project ID: ${result.data.projectId}`));
      console.log(typography.dim(`  Repository: ${result.data.repository}`));
      console.log(typography.dim(`  Branch: ${result.data.branch}`));
      console.log(typography.dim(`  Status: ${result.data.status}`));
      console.log(typography.dim(`  Remaining line quota: ${result.data.remaining}`));
      console.log(typography.dim(`  View Results at: https://vulnzap.com/dashboard/projects/${result.data.projectId}/${result.data.jobId}`));
      // Save initial scan result to file if output option is provided
      if (options.output) {
        const scanResultData = {
          jobId: result.data.jobId,
          projectId: result.data.projectId,
          repository: result.data.repository,
          branch: result.data.branch,
          status: result.data.status,
          remaining: result.data.remaining,
          message: result.data.message
        };

        try {
          fs.writeFileSync(options.output, JSON.stringify(scanResultData, null, 2));
          console.log(typography.dim(`  Results saved to: ${options.output}`));
        } catch (error) {
          console.log(typography.warning(`  Failed to save results to file: ${error instanceof Error ? error.message : 'Unknown error'}`));
        }
      }

      layout.section();

      if (options.wait) {
        console.log(typography.accent('Waiting for scan completion...'));
        console.log(typography.dim('Connecting to real-time event stream...'));

        let scanCompleted = false;

        // Try Server-Sent Events first
        try {
          await streamScanEvents(
            result.data.jobId,
            async (event: ScanEvent) => {
              switch (event.type) {
                case 'connected':
                  console.log(typography.success('  🔗 Connected to scan progress stream'));
                  if (event.data.jobStatus) {
                    console.log(typography.dim(`     Status: ${event.data.jobStatus}`));
                  }
                  layout.spacer();
                  break;

                case 'progress':
                  if (event.data.message) {
                    // Handle different types of progress messages
                    const message = event.data.message;

                    if (message.includes('Scan started for')) {
                      console.log(typography.accent(`  📁 ${message}`));
                    } else if (message.includes('Analyzing dependencies')) {
                      console.log(typography.dim(`  🔍 ${message}`));
                    } else if (message.includes('Magic tree built')) {
                      console.log(typography.dim(`  🌳 ${message}`));
                    } else if (message.includes('Generating comprehensive')) {
                      console.log(typography.dim(`  📊 ${message}`));
                    } else if (message.includes('Total lines scanned')) {
                      console.log(typography.accent(`  📈 ${message}`));
                    } else if (message.includes('Scan completed for') && message.includes('vulnerabilities found')) {
                      console.log(typography.subheader(`  📋 ${message}`));
                    } else {
                      console.log(typography.dim(`  ℹ️  ${message}`));
                    }
                  }
                  break;

                case 'vulnerability':
                  if (event.data) {
                    const vuln = event.data;
                    const severityColor = vuln.severity === 'critical' ? typography.error :
                      vuln.severity === 'high' ? typography.warning :
                        vuln.severity === 'medium' ? typography.accent : typography.dim;

                    console.log(severityColor(`  🚨 ${vuln.severity}: ${vuln.title}`));
                    console.log(typography.dim(`     File: ${vuln.file}`));
                    console.log(typography.dim(`     Line: ${vuln.line}`));
                    console.log(typography.dim(`     Description: ${vuln.description}`));
                    layout.spacer();
                  }
                  break;

                case 'completed':
                  console.log(typography.success('  ✅ Scan completed!'));
                  console.log(typography.dim('  📥 Fetching detailed results...'));

                  try {
                    // Fetch detailed results from jobs endpoint
                    const detailedResults = await getScanResults(result.data.jobId);

                    // Save detailed results to file if output option is provided
                    if (options.output) {
                      const finalResultData = {
                        jobId: result.data.jobId,
                        projectId: result.data.projectId,
                        repository: result.data.repository,
                        branch: result.data.branch,
                        status: 'completed',
                        completedAt: new Date().toISOString(),
                        message: event.data.message,
                        detailedResults: detailedResults
                      };

                      try {
                        fs.writeFileSync(options.output, JSON.stringify(finalResultData, null, 2));
                        console.log(typography.success(`  💾 Results saved to: ${options.output}`));
                      } catch (error) {
                        console.log(typography.warning(`  ⚠️  Failed to save results to file: ${error instanceof Error ? error.message : 'Unknown error'}`));
                      }
                    }
                  } catch (error) {
                    console.log(typography.warning(`  ⚠️  Could not fetch detailed results: ${error instanceof Error ? error.message : 'Unknown error'}`));
                  }

                  scanCompleted = true;
                  // Exit immediately after completion
                  process.exit(0);
                  break;

                case 'failed':
                  console.log(typography.error('  ❌ Scan failed'));
                  if (event.data.message) {
                    console.log(typography.dim(`     ${event.data.message}`));
                  }
                  scanCompleted = true;
                  // Exit with error code on failure
                  process.exit(1);
                  break;
              }
            },
            async (error) => {
              console.log(typography.warning(`  Event stream error: ${error.message}`));
              console.log(typography.dim('  Falling back to polling...'));

              // Fallback to polling
              await fallbackToPolling(result.data.jobId);
              scanCompleted = true;
            }
          );
        } catch (error) {
          console.log(typography.warning(`  Could not connect to event stream: ${error instanceof Error ? error.message : 'Unknown error'}`));
          console.log(typography.dim('  Falling back to polling...'));

          // Fallback to polling
          await fallbackToPolling(result.data.jobId);
          scanCompleted = true;
        }

        // Wait for completion if still running
        while (!scanCompleted) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Get final status for file saving
        try {
          const finalStatus = await getRepoScanStatus(result.data.jobId);

          if (finalStatus.data.status === 'completed') {
            console.log(typography.success('Scan completed!'));
            console.log(typography.dim('View detailed results at: https://vulnzap.com/dashboard/scans'));
          } else if (finalStatus.data.status === 'failed') {
            console.log(typography.error('Scan failed'));
            console.log(typography.dim(finalStatus.data.message || 'Unknown error occurred'));
          }

          // Save final results to file if output option is provided
          if (options.output) {
            const finalResultData = {
              jobId: finalStatus.data.jobId,
              projectId: finalStatus.data.projectId,
              repository: finalStatus.data.repository,
              branch: finalStatus.data.branch,
              status: finalStatus.data.status,
              completedAt: new Date().toISOString(),
              message: finalStatus.data.message,
              remaining: finalStatus.data.remaining
            };

            try {
              fs.writeFileSync(options.output, JSON.stringify(finalResultData, null, 2));
              console.log(typography.dim(`  Final results saved to: ${options.output}`));
            } catch (error) {
              console.log(typography.warning(`  Failed to save final results to file: ${error instanceof Error ? error.message : 'Unknown error'}`));
            }
          }
        } catch (error) {
          console.log(typography.warning(`  Could not get final status: ${error instanceof Error ? error.message : 'Unknown error'}`));
        }
      } else {
        console.log(typography.accent('Next Steps:'));
        console.log(typography.dim('  • Monitor progress at https://vulnzap.com/dashboard/scans'));
        console.log(typography.dim('  • Use --wait flag to wait for completion'));
        console.log(typography.dim(`  • Job ID: ${result.data.jobId}`));
      }

    } catch (error: any) {
      console.error(typography.error('Scan failed:'), error.message);
      layout.spacer();
      console.log(typography.accent('Troubleshooting:'));
      console.log(typography.dim('  • Ensure the repository URL is correct (https://github.com/owner/repo)'));
      console.log(typography.dim('  • Check your API key with: vulnzap status'));
      console.log(typography.dim('  • Verify repository is public or you have access'));
      process.exit(1);
    }
  });

// Helper function for fallback polling when SSE is not available
async function fallbackToPolling(scanId: string): Promise<void> {
  const maxAttempts = 120; // 10 minutes with 5-second intervals
  let attempts = 0;

  while (attempts < maxAttempts) {
    attempts++;
    await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds

    try {
      const scanStatus = await getRepoScanStatus(scanId);
      console.log(typography.dim(`  Status: ${scanStatus.data.status} (${attempts}/${maxAttempts})`));

      if (scanStatus.data.status === 'completed' || scanStatus.data.status === 'failed') {
        if (scanStatus.data.status === 'completed') {
          console.log(typography.success('  ✅ Scan completed!'));
        } else {
          console.log(typography.error('  ❌ Scan failed'));
          if (scanStatus.data.message) {
            console.log(typography.dim(`     ${scanStatus.data.message}`));
          }
        }
        return;
      }
    } catch (error) {
      console.log(typography.warning(`  Failed to check status: ${error instanceof Error ? error.message : 'Unknown error'}`));
    }
  }

  console.log(typography.warning('  Scan is still processing...'));
  console.log(typography.dim('  Check progress at: https://vulnzap.com/dashboard/scans'));
}

// Command: vulnzap help
program
  .command('help')
  .description('Display help information')
  .action(() => {
    layout.banner(version);

    console.log(typography.header('Quick Start'));
    console.log(typography.body('  npx vulnzap init          Complete onboarding (recommended for new users)'));
    layout.spacer();

    console.log(typography.header('Available Commands'));
    console.log(typography.accent('  init                      ') + typography.dim('Complete VulnZap setup with authentication and IDE integration'));
    console.log(typography.accent('  setup                     ') + typography.dim('Configure VulnZap with your API key'));
    console.log(typography.accent('  connect                   ') + typography.dim('Connect VulnZap to your AI-powered IDE'));
    console.log(typography.accent('  check <package>           ') + typography.dim('Check a package for vulnerabilities'));
    console.log(typography.accent('  batch-scan                ') + typography.dim('Scan all packages in current directory'));
    console.log(typography.accent('  scan <repo>               ') + typography.dim('Start repository vulnerability scan'));
    console.log(typography.accent('  mcp                       ') + typography.dim('Start MCP server for IDE integration'));
    console.log(typography.accent('  tools                     ') + typography.dim('Interactive tour of VulnZap MCP tools'));
    console.log(typography.accent('  status                    ') + typography.dim('Check VulnZap server health'));
    console.log(typography.accent('  account                   ') + typography.dim('View account information'));
    console.log(typography.accent('  help                      ') + typography.dim('Display this help information'));
    layout.spacer();

    console.log(typography.header('Examples'));
    console.log(typography.body('  vulnzap init                                    # Complete setup (recommended)'));
    console.log(typography.body('  vulnzap check npm:express@4.17.1               # Check specific package'));
    console.log(typography.body('  vulnzap setup -k your-api-key                  # Manual API key setup'));
    console.log(typography.body('  vulnzap connect --ide cursor                   # Connect to Cursor IDE'));
    console.log(typography.body('  vulnzap scan https://github.com/user/repo      # Scan a GitHub repository'));
    console.log(typography.body('  vulnzap mcp                                    # Start MCP server for IDE integration'));
    layout.spacer();

    console.log(typography.header('Need Help?'));
    console.log(typography.dim('  Documentation: https://vulnzap.com/docs'));
    console.log(typography.dim('  Support: https://vulnzap.com/support'));
    console.log(typography.dim('  Dashboard: https://vulnzap.com/dashboard'));
    layout.spacer();

    // Also show the default commander help for detailed options
    console.log(chalk.gray('Detailed command options:'));
    program.help();
  });

// Parse arguments
program.parse(process.argv);

// If no args, display help
if (process.argv.length === 2) {
  layout.banner(version);
  console.log(typography.header('Get started with VulnZap'));
  layout.section();
  console.log(typography.accent('  npx vulnzap init') + typography.dim('          Complete setup (recommended for new users)'));
  console.log(typography.dim('  vulnzap help                Show all available commands'));
  layout.section();
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
      // Fallback detection when CLI is not on PATH
      const resolved = resolveIDECLIPath(ide.name);
      if (resolved) {
        installedIDEs.push(ide.name);
      }
    }
  }

  // Always add JetBrains as an option (if .idea folder exists, likely a JetBrains project)
  if (fs.existsSync(path.join(process.cwd(), '.idea'))) {
    if (!installedIDEs.includes('jetbrains')) {
      installedIDEs.push('jetbrains');
    }
  }

  // Always add these as options even if not auto-detected
  const alwaysAvailable = ['antigravity', 'claude', 'jetbrains'];
  for (const ide of alwaysAvailable) {
    if (!installedIDEs.includes(ide)) {
      installedIDEs.push(ide);
    }
  }

  return installedIDEs;
}

// Resolve VS Code CLI path when 'code' is not on PATH
function resolveVSCodeCLIPath(): string | null {
  const platform = os.platform();
  const candidates: string[] = [];

  if (platform === 'darwin') {
    candidates.push('/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code');
    candidates.push('/Applications/Visual Studio Code - Insiders.app/Contents/Resources/app/bin/code');
    candidates.push(join(os.homedir(), 'Applications', 'Visual Studio Code.app', 'Contents', 'Resources', 'app', 'bin', 'code'));
    candidates.push(join(os.homedir(), 'Applications', 'Visual Studio Code - Insiders.app', 'Contents', 'Resources', 'app', 'bin', 'code'));
    candidates.push('/usr/local/bin/code');
    candidates.push('/opt/homebrew/bin/code');
  } else if (platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || join(os.homedir(), 'AppData', 'Local');
    candidates.push(join(localAppData, 'Programs', 'Microsoft VS Code', 'bin', 'code.cmd'));
    candidates.push('C\\\:\\\Program Files\\\Microsoft VS Code\\\bin\\\code.cmd');
    candidates.push('C\\\:\\\Program Files (x86)\\\Microsoft VS Code\\\bin\\\code.cmd');
  } else {
    candidates.push('/usr/bin/code');
    candidates.push('/snap/bin/code');
  }

  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) {
        return p;
      }
    } catch { }
  }
  return null;
}

function resolveIDECLIPath(ide: string): string | null {
  if (ide === 'vscode') return resolveVSCodeCLIPath();
  const platform = os.platform();
  const candidates: string[] = [];
  if (ide === 'cursor') {
    if (platform === 'darwin') {
      candidates.push('/Applications/Cursor.app/Contents/Resources/app/bin/cursor');
      candidates.push(join(os.homedir(), 'Applications', 'Cursor.app', 'Contents', 'Resources', 'app', 'bin', 'cursor'));
    } else if (platform === 'win32') {
      const localAppData = process.env.LOCALAPPDATA || join(os.homedir(), 'AppData', 'Local');
      candidates.push(join(localAppData, 'Programs', 'Cursor', 'bin', 'cursor.exe'));
    } else {
      candidates.push('/usr/bin/cursor');
      candidates.push('/snap/bin/cursor');
    }
  } else if (ide === 'windsurf') {
    if (platform === 'darwin') {
      candidates.push('/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf');
      candidates.push(join(os.homedir(), 'Applications', 'Windsurf.app', 'Contents', 'Resources', 'app', 'bin', 'windsurf'));
    } else if (platform === 'win32') {
      const localAppData = process.env.LOCALAPPDATA || join(os.homedir(), 'AppData', 'Local');
      candidates.push(join(localAppData, 'Programs', 'Windsurf', 'bin', 'windsurf.exe'));
    } else {
      candidates.push('/usr/bin/windsurf');
      candidates.push('/snap/bin/windsurf');
    }
  }
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch { }
  }
  return null;
}

function quoteCmdIfNeeded(cmd: string): string {
  if (!cmd) return cmd;
  return cmd.includes(' ') ? `"${cmd}"` : cmd;
}

// Best-effort symlink for VS Code CLI on macOS/Linux
function tryEnsureVSCodeSymlink(codePath: string): void {
  try {
    const platform = os.platform();
    if (platform === 'darwin' || platform === 'linux') {
      const binTargets = platform === 'darwin'
        ? ['/usr/local/bin/code', '/opt/homebrew/bin/code']
        : ['/usr/local/bin/code'];

      for (const target of binTargets) {
        try {
          const targetDir = path.dirname(target);
          if (!fs.existsSync(target) && fs.existsSync(targetDir)) {
            fs.symlinkSync(codePath, target);
          }
        } catch { }
      }
    }
  } catch { }
}

// Helper to get MCP config path for a given IDE
// Helper to get MCP config path for a given IDE
// Returns primary path (workspace if in project, else global)
function getMcpConfigPath(ide: string, options?: { workspace?: boolean }): string | null {
  const homeDir = os.homedir();
  const cwd = process.cwd();

  if (ide === 'vscode') {
    // Workspace-scoped (preferred for teams)
    if (options?.workspace) {
      return path.join(cwd, '.vscode', 'mcp.json');
    }
    // Global user settings - VS Code uses settings.json with "mcp" section
    // We'll handle this separately in connectIDE
    return null; // Signal to use settings.json approach
  }

  if (ide === 'cursor') {
    // Project-scoped (if in workspace)
    if (options?.workspace && fs.existsSync(path.join(cwd, '.cursor'))) {
      return path.join(cwd, '.cursor', 'mcp.json');
    }
    // Global fallback
    return path.join(homeDir, '.cursor', 'mcp.json');
  }

  if (ide === 'windsurf') {
    return path.join(homeDir, '.codeium', 'windsurf', 'mcp_config.json');
  }

  if (ide === 'jetbrains') {
    // Project-scoped - JetBrains uses mcp.json in project root
    if (options?.workspace) {
      return path.join(cwd, 'mcp.json');
    }
    // Fallback to .idea folder if it exists
    if (fs.existsSync(path.join(cwd, '.idea'))) {
      return path.join(cwd, '.idea', 'mcp.json');
    }
    return path.join(cwd, 'mcp.json');
  }

  if (ide === 'antigravity') {
    return path.join(homeDir, '.gemini', 'antigravity', 'mcp_config.json');
  }

  if (ide === 'claude') {
    const platform = os.platform();
    if (platform === 'darwin') {
      return path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    } else if (platform === 'win32') {
      return path.join(process.env.APPDATA || path.join(homeDir, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json');
    } else {
      return path.join(homeDir, '.claude.json');
    }
  }

  return null;
}

// Helper to check if VulnZap MCP is already installed
function isMcpInstalled(ide: string): boolean {
  const configPath = getMcpConfigPath(ide);
  if (!configPath || !fs.existsSync(configPath)) {
    return false;
  }

  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    // Check both schemas: "servers" (VS Code/Cursor) and "mcpServers" (Windsurf/JetBrains)
    return !!(config.mcpServers?.VulnZap || config.servers?.VulnZap);
  } catch (e) {
    return false;
  }
}

// Helper function to handle IDE connection logic
async function connectIDE(ide: string) {
  const { mergeVulnZapConfig, readConfigFile, writeConfigFile } = await import('./utils/mcpConfig.js');

  // Log the event
  const logFile = join(os.homedir(), '.vulnzap', 'info.log');
  const logStream = fs.createWriteStream(logFile, { flags: 'a' });
  logStream.write(`VulnZap connect command executed for ${ide} at ${new Date().toISOString()}\n`);
  logStream.end();

  const apiKey = await getKey();

  // VS Code special handling - ask about workspace vs global
  if (ide === 'vscode') {
    layout.section();
    console.log(typography.header('VS Code + GitHub Copilot MCP Configuration'));
    layout.spacer();
    console.log(typography.body('Choose where to install VulnZap MCP server:'));
    layout.spacer();

    const { scope } = await customPrompts.prompt([
      {
        type: 'list',
        name: 'scope',
        message: 'Installation scope:',
        choices: [
          {
            name: 'Workspace (this project only) - Recommended for teams',
            value: 'workspace'
          },
          {
            name: 'Global (all VS Code projects) - Recommended for personal use',
            value: 'global'
          }
        ],
        default: 'workspace'
      }
    ]);

    let configPath: string;
    let configDescription: string;

    if (scope === 'workspace') {
      configPath = path.join(process.cwd(), '.vscode', 'mcp.json');
      configDescription = 'Workspace-scoped (this project only)';

      // Ensure .vscode directory exists
      const workspaceDir = path.dirname(configPath);
      if (!fs.existsSync(workspaceDir)) {
        fs.mkdirSync(workspaceDir, { recursive: true });
      }
    } else {
      // Global user settings - we'll use settings.json approach
      const homeDir = os.homedir();
      const platform = os.platform();

      if (platform === 'darwin') {
        configPath = path.join(homeDir, 'Library', 'Application Support', 'Code', 'User', 'settings.json');
      } else if (platform === 'win32') {
        configPath = path.join(process.env.APPDATA || path.join(homeDir, 'AppData', 'Roaming'), 'Code', 'User', 'settings.json');
      } else {
        configPath = path.join(homeDir, '.config', 'Code', 'User', 'settings.json');
      }

      configDescription = 'Global (all VS Code projects)';
    }

    // Read existing config
    let config = readConfigFile(configPath);

    // For global settings.json, we need to nest under "mcp" key
    if (scope === 'global') {
      if (!config) config = {};
      if (!config.mcp) config.mcp = {};

      // Merge into mcp.servers
      if (!config.mcp.servers) config.mcp.servers = {};
      config.mcp.servers.VulnZap = {
        command: 'npx',
        args: ['vulnzap', 'mcp'],
        env: {
          VULNZAP_API_KEY: '${env:VULNZAP_API_KEY}' // Use environment variable for security
        }
      };

      // Inform user about environment variable
      layout.spacer();
      console.log(typography.accent('Important: Set environment variable'));
      console.log(typography.dim('  Add to your shell profile (~/.zshrc or ~/.bashrc):'));
      console.log(typography.code(`export VULNZAP_API_KEY="${apiKey}"`));
      layout.spacer();
    } else {
      // Workspace: use standard merge
      config = mergeVulnZapConfig(config, apiKey, ide);
    }

    // Write configuration
    writeConfigFile(configPath, config);
    console.log(typography.success('Configuration updated successfully'));

    // Display helpful information
    layout.section();
    console.log(typography.accent('Configuration Summary'));
    console.log(typography.dim('  MCP Server Name: VulnZap'));
    console.log(typography.dim(`  Scope: ${configDescription}`));
    console.log(typography.dim(`  Config Path: ${configPath}`));
    console.log(typography.dim('  Schema: servers (GitHub Copilot MCP)'));
    layout.section();
    console.log(typography.accent('Next Steps:'));
    console.log(typography.dim('  1. Restart VS Code'));
    console.log(typography.dim('  2. Open GitHub Copilot Chat'));
    console.log(typography.dim('  3. VulnZap security tools are now available'));
    layout.section();
    return;
  }

  // JetBrains special handling - ask about location
  if (ide === 'jetbrains') {
    layout.section();
    console.log(typography.header('JetBrains + GitHub Copilot MCP Configuration'));
    layout.spacer();
    console.log(typography.body('Choose where to place the MCP configuration:'));
    layout.spacer();

    const hasIdeaFolder = fs.existsSync(path.join(process.cwd(), '.idea'));
    const choices = [
      {
        name: 'Project root (mcp.json) - Recommended, visible to team',
        value: 'root'
      }
    ];

    if (hasIdeaFolder) {
      choices.push({
        name: '.idea folder (.idea/mcp.json) - Hidden from version control',
        value: 'idea'
      });
    }

    const { location } = await customPrompts.prompt([
      {
        type: 'list',
        name: 'location',
        message: 'Configuration location:',
        choices,
        default: 'root'
      }
    ]);

    let configPath: string;
    let configDescription: string;

    if (location === 'idea') {
      configPath = path.join(process.cwd(), '.idea', 'mcp.json');
      configDescription = 'Project .idea folder (hidden from VCS)';
    } else {
      configPath = path.join(process.cwd(), 'mcp.json');
      configDescription = 'Project root (visible to team)';
    }

    // Read existing config
    let config = readConfigFile(configPath);

    // Merge VulnZap configuration (uses "mcpServers" schema)
    config = mergeVulnZapConfig(config, apiKey, ide);

    // Write configuration
    writeConfigFile(configPath, config);
    console.log(typography.success('Configuration updated successfully'));

    // Display helpful information
    layout.section();
    console.log(typography.accent('Configuration Summary'));
    console.log(typography.dim('  MCP Server Name: VulnZap'));
    console.log(typography.dim(`  Location: ${configDescription}`));
    console.log(typography.dim(`  Config Path: ${configPath}`));
    console.log(typography.dim('  Schema: mcpServers (GitHub Copilot Agent)'));
    layout.section();
    console.log(typography.accent('Next Steps:'));
    console.log(typography.dim('  1. Open Copilot Chat in JetBrains'));
    console.log(typography.dim('  2. Switch to Agent mode'));
    console.log(typography.dim('  3. Click MCP tools icon to verify VulnZap appears'));
    console.log(typography.dim('  4. Enable VulnZap from the MCP server list'));
    layout.section();
    console.log(typography.dim('Note: Org admins must enable "MCP servers in Copilot" for Copilot Business/Enterprise'));
    layout.section();
    return;
  }

  // Cursor special handling - ask about workspace vs global
  if (ide === 'cursor') {
    layout.section();
    console.log(typography.header('Cursor + GitHub Copilot MCP Configuration'));
    layout.spacer();
    console.log(typography.body('Choose where to install VulnZap MCP server:'));
    layout.spacer();

    const { scope } = await customPrompts.prompt([
      {
        type: 'list',
        name: 'scope',
        message: 'Installation scope:',
        choices: [
          {
            name: 'Workspace (this project only) - Recommended for teams',
            value: 'workspace'
          },
          {
            name: 'Global (all Cursor projects) - Recommended for personal use',
            value: 'global'
          }
        ],
        default: 'global'
      }
    ]);

    let configPath: string;
    let configDescription: string;

    if (scope === 'workspace') {
      configPath = path.join(process.cwd(), '.cursor', 'mcp.json');
      configDescription = 'Workspace-scoped (this project only)';

      // Add rules for cursor for agent to call the mcp tools 
      const agentRulesFilePath = path.join(process.cwd(), 'AGENTS.md');
      const agentRulesFileContent = `\n\n### VulnZap MCP Guidelines

## Overview
Use VulnZap's tools to proactively identify and report security vulnerabilities within the codebase.

## Workflow
Your primary workflow consists of the following steps:

1. **Start the security assistant**: Call the \`vulnzap_security_assistant\` tool with the path to the directory you intend to work on. This tool will continuously monitor the specified directory for any file changes and automatically trigger security scans.

2. **Retrieve Scan Results**: Once you have completed your changes, call the \`vulnzap_security_assistant_results\` tool to obtain the scan results. This tool also accepts a 'wait' parameter in seconds. If the scan is still in progress, you can re-run the tool with an increased wait time.

3. **Address Vulnerabilities**: Analyze the scan results to identify any vulnerabilities. Use the provided information to implement the necessary fixes. If no vulnerabilities are found, the tool will indicate that the code is secure.
`;
      if (!fs.existsSync(agentRulesFilePath)) {
        fs.writeFileSync(agentRulesFilePath, agentRulesFileContent);
      } else {
        // Check if rules already exist, if not, add them
        const agentRulesFileContent = fs.readFileSync(agentRulesFilePath, 'utf8');
        if (!agentRulesFileContent.includes("## Rules for using VulnZap and its tools.")) {
          fs.appendFileSync(agentRulesFilePath, agentRulesFileContent);
        }
      }

      // Ensure .cursor directory exists
      const workspaceDir = path.dirname(configPath);
      if (!fs.existsSync(workspaceDir)) {
        fs.mkdirSync(workspaceDir, { recursive: true });
      }
    } else {
      configPath = path.join(os.homedir(), '.cursor', 'mcp.json');
      configDescription = 'Global (all Cursor projects)';
    }

    // Read existing config
    let config = readConfigFile(configPath);

    // Merge VulnZap configuration (uses "servers" schema)
    config = mergeVulnZapConfig(config, apiKey, ide);

    // Write configuration
    writeConfigFile(configPath, config);
    console.log(typography.success('Configuration updated successfully'));

    // Display helpful information
    layout.section();
    console.log(typography.accent('Configuration Summary'));
    console.log(typography.dim('  MCP Server Name: VulnZap'));
    console.log(typography.dim(`  Scope: ${configDescription}`));
    console.log(typography.dim(`  Config Path: ${configPath}`));
    console.log(typography.dim('  Schema: servers (GitHub Copilot MCP)'));
    console.log(typography.dim('  Transport Type: STDIO'));
    console.log(typography.dim('  Auto-approved Tools: auto-vulnerability-scan, scan_repo'));
    layout.section();
    console.log(typography.accent('To manage this server in Cursor:'));
    console.log(typography.dim('  1. Click the "MCP Servers" icon in Cursor'));
    console.log(typography.dim('  2. Find "VulnZap" in the server list'));
    console.log(typography.dim('  3. Use the toggle switch to enable/disable'));
    console.log(typography.dim('  4. Works with GitHub Copilot in Cursor'));
    layout.section();
    return;
  }

  // Standard handling for Windsurf, Antigravity, Claude
  const configPath = getMcpConfigPath(ide);

  if (!configPath) {
    console.log(typography.error(`Could not determine configuration path for ${ide}`));
    return;
  }

  // Read existing config
  let config = readConfigFile(configPath);

  // Merge VulnZap configuration
  config = mergeVulnZapConfig(config, apiKey, ide);

  // Write configuration
  writeConfigFile(configPath, config);
  console.log(typography.success('Configuration updated successfully'));

  // Display helpful information
  layout.section();
  console.log(typography.accent('Configuration Summary'));
  console.log(typography.dim('  MCP Server Name: VulnZap'));
  console.log(typography.dim(`  Config Path: ${configPath}`));

  const schemaKey = 'mcpServers';
  console.log(typography.dim(`  Schema: ${schemaKey}`));

  if (ide === 'windsurf') {
    layout.section();
    console.log(typography.accent('To manage this server in Windsurf:'));
    console.log(typography.dim('  1. Click the "MCP Servers" icon in Windsurf'));
    console.log(typography.dim('  2. Find "VulnZap" in the server list'));
    console.log(typography.dim('  3. Use the toggle switch to enable/disable'));
    console.log(typography.dim('  4. Works with GitHub Copilot in Windsurf'));
  } else if (ide === 'claude') {
    layout.section();
    console.log(typography.accent('Next Steps:'));
    console.log(typography.dim('  1. Restart Claude Code Desktop'));
    console.log(typography.dim('  2. Type /mcp in chat or check Settings > Integrations > MCP Servers'));
    console.log(typography.dim('  3. Verify VulnZap appears in the MCP server list'));
  } else if (ide === 'antigravity') {
    layout.section();
    console.log(typography.accent('Next Steps:'));
    console.log(typography.dim('  1. Restart Antigravity'));
    console.log(typography.dim('  2. VulnZap tools are now available'));
  }

  layout.section();
}