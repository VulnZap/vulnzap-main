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
  .action(async (options) => {
    // Import MCP setup utilities
    const { configureMcpInteractive } = await import('./utils/mcpSetup.js');

    layout.banner(version);
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
        console.log(typography.success('✓ API key is already configured'));
        layout.spacer();

        const { confirm } = await customPrompts.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: 'Replace existing API key?',
            default: false
          }
        ]);

        if (!confirm) {
          console.log(typography.dim('  Configuration unchanged'));

          // Still offer MCP configuration
          layout.section();
          const { configureMcp } = await customPrompts.prompt([
            {
              type: 'confirm',
              name: 'configureMcp',
              message: 'Would you like to configure IDE integration?',
              default: true
            }
          ]);

          if (configureMcp) {
            await configureMcpInteractive();
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

      // Ask about IDE integration
      layout.section();
      const { configureIde } = await customPrompts.prompt([
        {
          type: 'confirm',
          name: 'configureIde',
          message: 'Would you like to configure IDE integration?',
          default: true
        }
      ]);

      if (configureIde) {
        const result = await configureMcpInteractive();

        if (result.configured > 0) {
          layout.section();
          console.log(typography.success('Setup complete!'));
          console.log(typography.dim('Your development environment is now secured with VulnZap'));
        }
      } else {
        console.log(typography.dim('You can configure IDE integration later with: vulnzap connect'));
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
    // Import MCP setup utilities
    const { configureMcpInteractive } = await import('./utils/mcpSetup.js');

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
        console.log(typography.success('✓ Authentication configured'));
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

      // Step 3: Magic Auth Flow (if needed)
      if (!existingKey) {
        const { displayMagicAuth, displayAuthSuccess, displayAuthError } = await import('./utils/magicAuth.js');

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

      // Step 4: Ask about MCP configuration
      layout.section();
      const { configureMcp } = await customPrompts.prompt([
        {
          type: 'confirm',
          name: 'configureMcp',
          message: 'Would you like to configure IDE integration now?',
          default: true
        }
      ]);

      let mcpConfigured = false;
      if (configureMcp) {
        const result = await configureMcpInteractive();
        mcpConfigured = result.configured > 0;
      } else {
        console.log(typography.dim('You can configure IDE integration later with: vulnzap connect'));
      }

      // Step 5: Tool Spotlight (if MCP was configured)
      if (mcpConfigured) {
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
      if (mcpConfigured) {
        console.log(typography.body('  • Your AI now has security superpowers'));
        console.log(typography.body('  • Vulnerabilities will be caught automatically'));
      } else {
        console.log(typography.body('  • Run `vulnzap connect` to configure IDE integration'));
      }
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
  .action(async () => {
    // Import MCP setup utilities
    const { configureMcpInteractive } = await import('./utils/mcpSetup.js');

    layout.banner(version);
    console.log(typography.header('IDE Integration'));
    layout.spacer();

    // Check authentication
    try {
      await getKey();
      console.log(typography.success('✓ Authentication verified'));
      layout.spacer();
    } catch (error) {
      console.log(typography.error('Authentication required'));
      layout.spacer();
      console.log(typography.dim('Please run `vulnzap init` or `vulnzap setup` first to authenticate'));
      process.exit(1);
    }

    try {
      // Run interactive MCP configuration
      const result = await configureMcpInteractive();

      if (result.configured > 0) {
        layout.spacer();
        console.log(typography.success('IDE integration complete!'));
        console.log(typography.dim('Your development environment is now secured with VulnZap'));
      } else if (result.skipped) {
        layout.spacer();
        console.log(typography.dim('Configuration skipped. You can run this command again anytime.'));
      }
    } catch (error: any) {
      layout.spacer();
      console.error(typography.error('Configuration failed:'), error.message);
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
          if (res && typeof res === 'object') {
            if (!fs.existsSync(outputDir)) {
              fs.mkdirSync(outputDir, { recursive: true });
            }
            const outputFile = path.join(outputDir, `vulnzap-results-${sessionId}.json`);
            fs.writeFileSync(outputFile, JSON.stringify(res, null, 2));
            spinner.succeed(`\nScan results saved to: ${outputFile}`);
          } else {
            spinner.warn(`\nCould not retrieve scan results: ${res || 'No data returned.'}`);
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
