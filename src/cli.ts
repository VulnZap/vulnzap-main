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
      console.log(chalk.green('✓') + ' VulnZap server is healthy');
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
        const vulnzapLocation = process.cwd() + '/.vulnzap';
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
        spinner.succeed(chalk.green('✓') + ' You are now logged in to VulnZap\n');
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
      await startMcpServer({
        useMcp: options.mcp || true,
        ide: options.ide || 'cursor',
        port: parseInt(options.port, 10),
        serverIsDown: serverIsDown
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
      spinner.fail('Failed to check server status');
      console.error(chalk.red('Error:'), "VulnZap server is down. Local cache will be used if available.");
      process.exit(1);
    }
  });

// Command: vulnzap check
program
  .command('check <package>')
  .description('Check a package for vulnerabilities (format: npm:package-name@version)')
  .option('-e, --ecosystem <ecosystem>', 'Package ecosystem (npm, pip)', 'npm')
  .option('-v, --version <version>', 'Package version')
  .option('-C, --cache', 'Use cached results')
  .option('-A, --ai', 'Use AI to get the summary of the vulnerabilities')
  .action(async (packageInput, options) => {
    displayBanner();
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

// Unavailable feature for now (will be added in future updates)
// program
//   .command('sbom')
//   .description('Scan the current directory for SBOM (Software Bill of Materials)')
//   .option('--ecosystem <ecosystem>', 'Specific ecosystem to scan (npm, pip, go, rust)')
//   .option('--output <file>', 'Output file for SBOM results (JSON format)')
//   .action(async (options) => {
//     displayBanner();
//     try {
//       const { authenticated } = await auth.checkAuth();
//       if (!authenticated) {
//         console.error(chalk.red('Error: You must be logged in to scan for SBOM'));
//         console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate first`);
//         process.exit(1);
//       }

//       const checkAlreadyInitialized = await checkInit();
//       if (!checkAlreadyInitialized) {
//         console.error(chalk.red('Error: VulnZap is not initialized in this project, run vulnzap init to initialize VulnZap'));
//         process.exit(1);
//       }

//       const spinner = ora('Scanning for SBOM...').start();

//       // Check if cyclonedx-bom is installed
//       try {
//         execSync('cdxgen --version', { stdio: 'ignore' });
//       } catch {
//         console.log(chalk.yellow('CycloneDX CLI not found. Installing globally...'));
//         try {
//           execSync('npm install -g @cyclonedx/cdxgen', { stdio: 'inherit' });
//         } catch (error: any) {
//           console.error(chalk.red('Error installing CycloneDX CLI (you can install it manually using `npm install -g @cyclonedx/cdxgen`):'), error.message);
//           process.exit(1);
//         }
//       }

//       // Run CycloneDX to generate SBOM
//       try {
//         const sbomFile = path.join(process.cwd(), options.output || 'sbom.json');
//         execSync(`cdxgen -o ${sbomFile}`, { stdio: 'inherit' });
//         console.log(chalk.green('✓') + ` SBOM generated at ${sbomFile}`);

//         // Read and parse the SBOM file
//         const sbomData = JSON.parse(fs.readFileSync(sbomFile, 'utf8'));
//         const packages = sbomData.components.map((component: any) => ({
//           packageName: component.name,
//           version: component.version,
//           ecosystem: component.type || 'unknown',
//         }));

//         spinner.succeed('SBOM scan completed');
//         console.log(chalk.green('✓') + ' SBOM scan completed successfully');
//         console.log(chalk.green('✓') + ` Found ${packages.length} packages in the SBOM`);
//         console.log(chalk.green('✓') + ' Packages:');
//         packages.forEach((pkg: any) => {
//           console.log(`- ${pkg.packageName}@${pkg.version} (${pkg.ecosystem})`);
//         });
//         console.log(chalk.green('✓') + ' SBOM results saved to ' + sbomFile);
//         console.log(chalk.green('✓') + ' Sending SBOM results to VulnZap server...');
//         const sbomResults = {
//           id: uuidv4(),
//           packages: packages,
//           createdAt: new Date().toISOString(),
//         };
//         const response = await api.sendSbomResults(sbomResults);
//         if (response.status === 'success') {
//           console.log(chalk.green('✓') + ' SBOM results sent successfully');
//           console.log(chalk.green('✓') + ` The scan is added to the queue and you can view the results on this url: ${config.api.baseUrl}/dashboard/scans/${response.traceId}`);
//         } else {
//           console.log(chalk.red('Error: Failed to send SBOM results to VulnZap server'));
//         }
//         process.exit(0);
//       } catch (error: any) {
//         console.error(chalk.red('Error generating SBOM:'), error.message);
//         process.exit(1);
//       }
//     } catch (error) {
//       console.log(error)
//       process.exit(1)
//     }
//   });

// Command: vulnzap connect
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

    // Log the event
    const logFile = join(os.homedir(), '.vulnzap', 'info.log');
    const logStream = fs.createWriteStream(logFile, { flags: 'a' });
    logStream.write(`VulnZap connect command executed for ${options.ide} at ${new Date().toISOString()}\n`);
    logStream.end();
    
    // Display info about API keys and ask if user has both
    console.log(chalk.cyan('To use the connect command, you need both a GitHub token and an NVD API key.'));
    console.log(chalk.yellow('GitHub token: https://github.com/settings/tokens'));
    console.log(chalk.yellow('NVD API key: https://nvd.nist.gov/developers/request-an-api-key'));
    console.log('\nBoth keys are required for full functionality.');
    const { hasKeys } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'hasKeys',
        message: 'Do you have both the GitHub token and NVD API key?',
        default: false,
      },
    ]);
    if (!hasKeys) {
      console.log(chalk.red('Please obtain both API keys before proceeding.'));
      process.exit(1);
    }

    // Prompt for GitHub and NVD API keys
    const answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'githubToken',
        message: 'Enter your GitHub token:',
      },
      {
        type: 'input',
        name: 'nvdApiKey',
        message: 'Enter your NVD API key:',
      },
    ]);

    let missing = false;
    if (!answers.githubToken) {
      console.log(chalk.yellow('You can generate a GitHub token at: https://github.com/settings/tokens'));
      missing = true;
    }
    if (!answers.nvdApiKey) {
      console.log(chalk.yellow('You can request an NVD API key at: https://nvd.nist.gov/developers/request-an-api-key'));
      missing = true;
    }
    if (missing) {
      console.error(chalk.red('Error: Both API keys are required to proceed.'));
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

      // Save tokens in mcp.json
      if (!cursorMcpConfig.mcp) {
        cursorMcpConfig.mcpServers = {
          VulnZap: {
            command: "vulnzap",
            args: ["secure", "--ide", "cursor", "--port", "3456"],
            env: {
              VULNZAP_GITHUB_TOKEN: answers.githubToken,
              VULNZAP_NVD_API_KEY: answers.nvdApiKey
            }
          }
        };
      } else {
        cursorMcpConfig.mcpServers.VulnZap = {
          command: "vulnzap",
          args: ["secure", "--ide", "cursor", "--port", "3456"],
          env: {
            VULNZAP_GITHUB_TOKEN: answers.githubToken,
            VULNZAP_NVD_API_KEY: answers.nvdApiKey
          }
        };
      }
      fs.writeFileSync(cursorMcpConfigLocation, JSON.stringify(cursorMcpConfig, null, 2));
      console.log(chalk.green('✓') + ' Cursor MCP config updated successfully with API keys');

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
      
      process.exit(0);
    } else if (options.ide === 'windsurf') {
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
          process.exit(1);
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
        args: ['secure', '--ide', 'windsurf', '--port', '3456'],
        env: {
          VULNZAP_GITHUB_TOKEN: answers.githubToken,
          VULNZAP_NVD_API_KEY: answers.nvdApiKey,
        },
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
      
      process.exit(0);
    } else if (options.ide === 'cline') {
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
          process.exit(1);
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
        env: {
          VULNZAP_GITHUB_TOKEN: answers.githubToken,
          VULNZAP_NVD_API_KEY: answers.nvdApiKey
        },
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
      
      process.exit(0);
    } else {
      console.error(chalk.red('Error: Unsupported IDE.'));
      console.log('Please use Cursor or Windsurf for now.');
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
    program.help();
  });

// Parse arguments
program.parse(process.argv);

// If no args, display help
if (process.argv.length === 2) {
  displayBanner();
  program.help();
} 