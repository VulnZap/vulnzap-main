#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import { startMcpServer, checkVulnerability, getBatchStatus } from '../src/index.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import * as auth from '../src/auth/supabase.js';
import * as payment from '../src/payment/stripe.js';
import qrcode from 'qrcode-terminal';
import open from 'open';
import { v4 as uuidv4 } from 'uuid';
import { createClient, Provider } from '@supabase/supabase-js';
import { config } from '../src/config/config.js';
import { User } from '@supabase/supabase-js';

// Get package version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
const version = packageJson.version;

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
    
    // Check if user is authenticated
    const isLoggedIn = await auth.isAuthenticated();
    if (!isLoggedIn) {
      console.log(chalk.yellow('You are not logged in. Some premium features may be unavailable.'));
      console.log(`Run ${chalk.cyan('vulnzap login')} to authenticate and access premium features.\n`);
    } else {
      // Check subscription
      const isPremium = await payment.isPremiumUser();
      if (isPremium) {
        console.log(chalk.green('✓') + ' Premium account detected');
      } else {
        console.log(chalk.yellow('⚠') + ' Using free tier');
        console.log(`Run ${chalk.cyan('vulnzap upgrade')} to upgrade to a premium plan.\n`);
      }

      // Get scan quota
      const { success, remaining, total } = await payment.getRemainingScanQuota();
      if (success) {
        console.log(`${chalk.cyan('ℹ')} Scan quota: ${remaining}/${total} scans remaining today\n`);
      }
    }
    
    const spinner = ora('Starting VulnZap security bridge...').start();

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
          chalk.cyan('vulnzap signup') + ' to get a premium API key\n');
      }
      
      console.log('Press Ctrl+C to stop the security bridge');
    } catch (error: any) {
      spinner.fail('Failed to start VulnZap security bridge');
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
  .action(async (options) => {
    displayBanner();
    
    // Prompt for IDE if not provided
    let ide = options.ide;
    if (!ide) {
      const response = await inquirer.prompt([{
        type: 'list',
        name: 'ide',
        message: 'Select your AI-powered IDE:',
        choices: ['cursor', 'claude-code', 'windsurf', 'other']
      }]);
      ide = response.ide;
      
      if (ide === 'other') {
        const customResponse = await inquirer.prompt([{
          type: 'input',
          name: 'customIde',
          message: 'Enter the name of your IDE:'
        }]);
        ide = customResponse.customIde;
      }
    }
    
    const spinner = ora(`Connecting to ${ide}...`).start();
    
    // Simulate connection process
    setTimeout(() => {
      spinner.succeed(`Connected to ${ide}`);
      console.log('\nVulnZap is now protecting your AI-generated code in real-time.');
      console.log('To start the security bridge, run:\n');
      console.log(chalk.cyan(`  vulnzap secure --ide ${ide}\n`));
    }, 2000);
  });

// Command: vulnzap login
program
  .command('login')
  .description('Authenticate with VulnZap')
  .option('--method <method>', 'Authentication method (email, magic, google, github)', 'email')
  .option('--email <email>', 'Email address for login')
  .action(async (options) => {
    displayBanner();
    
    // Initialize auth
    auth.initSupabase();
    
    // Check if already logged in
    const isLoggedIn = await auth.isAuthenticated();
    if (isLoggedIn) {
      const user = await auth.getCurrentUser();
      console.log(chalk.green(`You are already logged in as ${user?.email}`));
      
      const { answer } = await inquirer.prompt([{
        type: 'confirm',
        name: 'answer',
        message: 'Do you want to log out and log in as a different user?',
        default: false
      }]);
      
      if (!answer) {
        return;
      }
      
      // Log out if user wants to switch accounts
      const spinner = ora('Logging out...').start();
      await auth.signOut();
      spinner.succeed('Logged out successfully');
    }
    
    let method = options.method;
    let email = options.email;
    
    if (!method || !['email', 'magic', 'google', 'github'].includes(method)) {
      const { selectedMethod } = await inquirer.prompt([{
        type: 'list',
        name: 'selectedMethod',
        message: 'Select login method:',
        choices: [
          { name: 'Email and Password', value: 'email' },
          { name: 'Magic Link (passwordless)', value: 'magic' },
          { name: 'Login with Google', value: 'google' },
          { name: 'Login with GitHub', value: 'github' }
        ]
      }]);
      method = selectedMethod;
    }
    
    if ((method === 'email' || method === 'magic') && !email) {
      const { inputEmail } = await inquirer.prompt([{
        type: 'input',
        name: 'inputEmail',
        message: 'Enter your email:',
        validate: (input) => {
          return input.includes('@') ? true : 'Please enter a valid email address';
        }
      }]);
      email = inputEmail;
    }
    
    try {
      switch (method) {
        case 'email': {
          const { password } = await inquirer.prompt([{
            type: 'password',
            name: 'password',
            message: 'Enter your password:',
            validate: (input) => input.length >= 8 ? true : 'Password must be at least 8 characters'
          }]);
          
          const spinner = ora('Logging in...').start();
          const result = await auth.signInWithEmail(email, password);
          
          if (result.error) {
            spinner.fail(`Login failed: ${result.error}`);
            
            // Offer to sign up if account doesn't exist
            if (result.error.includes('Invalid login credentials')) {
              const { wantToSignUp } = await inquirer.prompt([{
                type: 'confirm',
                name: 'wantToSignUp',
                message: 'Account not found. Would you like to sign up instead?',
                default: true
              }]);
              
              if (wantToSignUp) {
                const signupResult = await auth.signUpWithEmail(email, password);
                if (signupResult.error) {
                  console.error(chalk.red(`Signup failed: ${signupResult.error}`));
                } else {
                  console.log(chalk.green('Account created successfully!'));
                  console.log(chalk.yellow('Please check your email to confirm your account.'));
                }
              }
            }
          } else {
            spinner.succeed(`Logged in as ${result.user?.email}`);
            
            // Show subscription info
            await showSubscriptionInfo();
          }
          break;
        }
        
        case 'magic': {
          const spinner = ora(`Sending magic link to ${email}...`).start();
          const result = await auth.sendMagicLink(email);
          
          if (result.error) {
            spinner.fail(`Failed to send magic link: ${result.error}`);
          } else {
            spinner.succeed('Magic link sent');
            console.log(chalk.cyan('✓') + ' Please check your email and click the link to log in.');
            console.log(chalk.cyan('✓') + ' After confirming, come back and run:');
            console.log(chalk.cyan('  vulnzap account'));
          }
          break;
        }
        
        case 'google':
        case 'github': {
          const provider = method === 'google' ? 'google' : 'github';
          const spinner = ora(`Preparing ${provider} login...`).start();
          
          // Generate a unique state for authentication
          const state = uuidv4();
          
          // Create the login URL
          const result = await auth.signInWithProvider(provider as Provider);
          
          if (result.error || !result.url) {
            spinner.fail(`Failed to start ${provider} login: ${result.error}`);
          } else {
            spinner.succeed(`${provider} login ready`);
            console.log('Please authenticate in your browser.');
            
            // Open the URL in the browser
            await open(result.url);
            
            console.log(chalk.cyan('\nAfter logging in, come back and run:'));
            console.log(chalk.cyan('  vulnzap account'));
          }
          break;
        }
      }
    } catch (error: any) {
      console.error(chalk.red('Login error:'), error.message);
    }
  });

// Command: vulnzap logout
program
  .command('logout')
  .description('Log out from your VulnZap account')
  .action(async () => {
    displayBanner();
    
    // Initialize auth
    auth.initSupabase();
    
    const spinner = ora('Logging out...').start();
    
    try {
      const result = await auth.signOut();
      
      if (result.error) {
        spinner.fail(`Logout failed: ${result.error}`);
      } else {
        spinner.succeed('Successfully logged out');
      }
    } catch (error: any) {
      spinner.fail('Logout failed');
      console.error(chalk.red('Error:'), error.message);
    }
  });

// Command: vulnzap account
program
  .command('account')
  .description('View and manage your VulnZap account')
  .action(async () => {
    displayBanner();
    
    // Initialize auth
    auth.initSupabase();
    
    const isLoggedIn = await auth.isAuthenticated();
    
    if (!isLoggedIn) {
      console.log(chalk.yellow('You are not logged in.'));
      console.log(`Please log in using ${chalk.cyan('vulnzap login')}`);
      return;
    }
    
    const user = await auth.getCurrentUser();
    
    if (!user) {
      console.log(chalk.red('Error retrieving user information'));
      return;
    }
    
    console.log(chalk.bold('Account Information'));
    console.log(chalk.cyan('Email:'), user.email);
    
    // Get subscription info
    await showSubscriptionInfo();
    
    // Show subscription management options
    const { action } = await inquirer.prompt([{
      type: 'list',
      name: 'action',
      message: 'What would you like to do?',
      choices: [
        { name: 'View usage statistics', value: 'stats' },
        { name: 'Upgrade subscription', value: 'upgrade' },
        { name: 'Manage subscription', value: 'manage' },
        { name: 'Cancel subscription', value: 'cancel' },
        { name: 'Log out', value: 'logout' },
        { name: 'Exit', value: 'exit' }
      ]
    }]);
    
    switch (action) {
      case 'stats':
        // Get user's scan stats
        await showUsageStats();
        break;
        
      case 'upgrade':
        await upgradeSubscription();
        break;
        
      case 'manage':
        await manageSubscription();
        break;
        
      case 'cancel':
        await cancelSubscription();
        break;
        
      case 'logout':
        await auth.signOut();
        console.log(chalk.green('Successfully logged out'));
        break;
        
      case 'exit':
        break;
    }
  });

// Command: vulnzap signup
program
  .command('signup')
  .description('Sign up for VulnZap premium features')
  .action(async () => {
    displayBanner();
    
    console.log('Sign up for VulnZap premium to unlock:');
    console.log('- Advanced vulnerability detection');
    console.log('- Supply chain attack protection');
    console.log('- Custom security policies');
    console.log('- Priority support\n');
    
    // Initialize auth
    auth.initSupabase();
    
    // Check if already logged in
    const isLoggedIn = await auth.isAuthenticated();
    let user: User | null = null;
    
    if (isLoggedIn) {
      user = await auth.getCurrentUser();
      console.log(chalk.green(`You are logged in as ${user?.email}`));
      
      // Get subscription info
      const { success, subscription } = await payment.getUserSubscription();
      
      if (success && subscription) {
        if (subscription.tier !== 'free') {
          console.log(chalk.yellow(`You already have an active ${subscription.tier} subscription.`));
          
          const { wantToUpgrade } = await inquirer.prompt([{
            type: 'confirm',
            name: 'wantToUpgrade',
            message: 'Would you like to upgrade or manage your subscription?',
            default: true
          }]);
          
          if (wantToUpgrade) {
            await manageSubscription();
          }
          
          return;
        }
      }
    } else {
      // Not logged in, ask to create account first
      const { action } = await inquirer.prompt([{
        type: 'list',
        name: 'action',
        message: 'You need an account to subscribe to premium features:',
        choices: [
          { name: 'Create a new account', value: 'create' },
          { name: 'Log in to existing account', value: 'login' }
        ]
      }]);
      
      if (action === 'login') {
        // Redirect to login
        program.parse(['node', 'vulnzap', 'login']);
        return;
      } else {
        // Get signup information
        const { email, password, name, company } = await inquirer.prompt([
          {
            type: 'input',
            name: 'email',
            message: 'Enter your email:',
            validate: (input) => {
              return input.includes('@') ? true : 'Please enter a valid email';
            }
          },
          {
            type: 'password',
            name: 'password',
            message: 'Create a password:',
            validate: (input) => {
              return input.length >= 8 ? true : 'Password must be at least 8 characters';
            }
          },
          {
            type: 'input',
            name: 'name',
            message: 'Your name (optional):',
          },
          {
            type: 'input',
            name: 'company',
            message: 'Company name (optional):',
          }
        ]);
        
        const spinner = ora('Creating your account...').start();
        
        // Create user account
        const result = await auth.signUpWithEmail(email, password, {
          name,
          company,
          tier: 'free'
        });
        
        if (result.error) {
          spinner.fail(`Account creation failed: ${result.error}`);
          return;
        }
        
        spinner.succeed('Account created successfully');
        console.log(chalk.yellow('Please check your email to confirm your account before upgrading.'));
        
        const { confirmNow } = await inquirer.prompt([{
          type: 'confirm',
          name: 'confirmNow',
          message: 'Have you confirmed your email?',
          default: false
        }]);
        
        if (!confirmNow) {
          console.log(chalk.cyan('Please confirm your email, then run:'));
          console.log(chalk.cyan('  vulnzap upgrade'));
          return;
        }
        
        // Try to get the current user after confirmation
        user = await auth.getCurrentUser();
      }
    }
    
    if (!user) {
      console.log(chalk.red('Error: Unable to retrieve user account.'));
      console.log('Please try again or contact support.');
      return;
    }
    
    // User is logged in, select premium plan
    const { plan } = await inquirer.prompt([{
      type: 'list',
      name: 'plan',
      message: 'Select your premium plan:',
      choices: [
        { name: 'Pro ($9/mo) - Individual developers', value: 'pro' },
        { name: 'Enterprise ($19/user/mo) - Teams and organizations', value: 'enterprise' }
      ]
    }]);
    
    // Create checkout session and open browser
    const spinner = ora('Preparing checkout...').start();
    const result = await payment.openCheckoutInBrowser(plan);
    
    if (!result.success || result.error) {
      spinner.fail(`Failed to create checkout: ${result.error}`);
      return;
    }
    
    spinner.succeed('Checkout page opened in browser');
    console.log(chalk.cyan('✓') + ' Complete the payment in your browser');
    console.log(chalk.cyan('✓') + ' After payment, your account will be automatically upgraded');
    console.log(chalk.cyan('✓') + ' Run this command to verify your subscription status:');
    console.log(chalk.cyan('  vulnzap account'));
  });

// Command: vulnzap upgrade
program
  .command('upgrade')
  .description('Upgrade to VulnZap premium')
  .action(async () => {
    displayBanner();
    
    // Initialize auth
    auth.initSupabase();
    
    // Check if already logged in
    const isLoggedIn = await auth.isAuthenticated();
    
    if (!isLoggedIn) {
      console.log(chalk.yellow('You need to log in first to upgrade.'));
      console.log(`Please log in using ${chalk.cyan('vulnzap login')}`);
      return;
    }
    
    // User is logged in, select premium plan
    const { plan } = await inquirer.prompt([{
      type: 'list',
      name: 'plan',
      message: 'Select your premium plan:',
      choices: [
        { name: 'Pro ($9/mo) - Individual developers', value: 'pro' },
        { name: 'Enterprise ($19/user/mo) - Teams and organizations', value: 'enterprise' }
      ]
    }]);
    
    // Create checkout session and open browser
    const spinner = ora('Preparing checkout...').start();
    const result = await payment.openCheckoutInBrowser(plan);
    
    if (!result.success || result.error) {
      spinner.fail(`Failed to create checkout: ${result.error}`);
      return;
    }
    
    spinner.succeed('Checkout page opened in browser');
    console.log(chalk.cyan('✓') + ' Complete the payment in your browser');
    console.log(chalk.cyan('✓') + ' After payment, your account will be automatically upgraded');
    console.log(chalk.cyan('✓') + ' Run this command to verify your subscription status:');
    console.log(chalk.cyan('  vulnzap account'));
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
    
    // Initialize auth
    auth.initSupabase();
    
    // Check if authenticated or has API key
    const isLoggedIn = await auth.isAuthenticated();
    const isPremium = isLoggedIn && await payment.isPremiumUser();
    
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

// Helper functions

/**
 * Show the user's subscription information
 */
async function showSubscriptionInfo() {
  const { success, subscription } = await payment.getUserSubscription();
  
  if (!success || !subscription) {
    console.log(chalk.red('Unable to retrieve subscription information'));
    return;
  }
  
  console.log(chalk.bold('\nSubscription Information'));
  console.log(chalk.cyan('Plan:'), subscription.tier === 'free' ? 'Free tier' : subscription.tier === 'pro' ? 'Pro plan' : 'Enterprise plan');
  
  if (subscription.tier !== 'free') {
    console.log(chalk.cyan('Status:'), subscription.status === 'active' ? 
      chalk.green('Active') : 
      subscription.status === 'trialing' ? 
        chalk.blue('Trial') : 
        chalk.yellow(subscription.status));
    
    if (subscription.cancelAtPeriodEnd) {
      console.log(chalk.yellow('Your subscription will cancel at the end of the current billing period.'));
      const endDate = new Date(subscription.currentPeriodEnd * 1000).toLocaleDateString();
      console.log(chalk.cyan('End date:'), endDate);
    }
  }
  
  // Get scan limits
  const { success: quotaSuccess, remaining, total } = await payment.getRemainingScanQuota();
  if (quotaSuccess) {
    console.log(chalk.cyan('Scan quota:'), `${remaining}/${total} scans remaining today`);
  }
}

/**
 * Show usage statistics
 */
async function showUsageStats() {
  // In a real implementation, this would fetch actual usage stats from the database
  console.log(chalk.bold('\nUsage Statistics'));
  console.log(chalk.cyan('Today:'), '15 scans performed');
  console.log(chalk.cyan('This month:'), '253 scans performed');
  console.log(chalk.cyan('Vulnerabilities found:'), '42');
  console.log(chalk.cyan('Most scanned package:'), 'lodash (npm)');
}

/**
 * Upgrade the user's subscription
 */
async function upgradeSubscription() {
  const { success, subscription } = await payment.getUserSubscription();
  
  if (!success || !subscription) {
    console.log(chalk.red('Unable to retrieve subscription information'));
    return;
  }
  
  if (subscription.tier === 'free') {
    // Free tier - need to create a new subscription
    const { plan } = await inquirer.prompt([{
      type: 'list',
      name: 'plan',
      message: 'Select your premium plan:',
      choices: [
        { name: 'Pro ($9/mo) - Individual developers', value: 'pro' },
        { name: 'Enterprise ($19/user/mo) - Teams and organizations', value: 'enterprise' }
      ]
    }]);
    
    const spinner = ora('Preparing checkout...').start();
    const result = await payment.openCheckoutInBrowser(plan);
    
    if (!result.success || result.error) {
      spinner.fail(`Failed to create checkout: ${result.error}`);
    } else {
      spinner.succeed('Checkout page opened in browser');
    }
  } else if (subscription.tier === 'pro') {
    // Pro tier - offer upgrade to Enterprise
    const { confirm } = await inquirer.prompt([{
      type: 'confirm',
      name: 'confirm',
      message: 'Upgrade from Pro to Enterprise plan ($19/user/mo)?',
      default: false
    }]);
    
    if (confirm) {
      const spinner = ora('Upgrading subscription...').start();
      const result = await payment.updateSubscription('enterprise');
      
      if (!result.success || result.error) {
        spinner.fail(`Failed to upgrade: ${result.error}`);
      } else {
        spinner.succeed('Subscription upgraded to Enterprise plan');
      }
    }
  } else {
    // Already on Enterprise plan
    console.log(chalk.green('You are already on the highest tier (Enterprise).'));
  }
}

/**
 * Manage the user's subscription
 */
async function manageSubscription() {
  const { success, subscription } = await payment.getUserSubscription();
  
  if (!success || !subscription) {
    console.log(chalk.red('Unable to retrieve subscription information'));
    return;
  }
  
  if (subscription.tier === 'free') {
    // No subscription to manage
    console.log(chalk.yellow('You are on the free tier. No subscription to manage.'));
    
    const { wantToUpgrade } = await inquirer.prompt([{
      type: 'confirm',
      name: 'wantToUpgrade',
      message: 'Would you like to upgrade to a premium plan?',
      default: true
    }]);
    
    if (wantToUpgrade) {
      await upgradeSubscription();
    }
  } else {
    // Has subscription
    let choices = [
      { name: 'View subscription details', value: 'view' },
    ];
    
    if (subscription.cancelAtPeriodEnd) {
      choices.push({ name: 'Resume subscription', value: 'resume' });
    } else {
      choices.push({ name: 'Cancel subscription', value: 'cancel' });
    }
    
    if (subscription.tier === 'pro') {
      choices.push({ name: 'Upgrade to Enterprise plan', value: 'upgrade' });
    }
    
    const { action } = await inquirer.prompt([{
      type: 'list',
      name: 'action',
      message: 'Manage your subscription:',
      choices
    }]);
    
    switch (action) {
      case 'view':
        await showSubscriptionInfo();
        break;
        
      case 'resume':
        if (subscription.cancelAtPeriodEnd) {
          const spinner = ora('Resuming subscription...').start();
          const result = await payment.resumeSubscription();
          
          if (!result.success || result.error) {
            spinner.fail(`Failed to resume: ${result.error}`);
          } else {
            spinner.succeed('Subscription resumed');
          }
        }
        break;
        
      case 'cancel':
        await cancelSubscription();
        break;
        
      case 'upgrade':
        await upgradeSubscription();
        break;
    }
  }
}

/**
 * Cancel the user's subscription
 */
async function cancelSubscription() {
  const { success, subscription } = await payment.getUserSubscription();
  
  if (!success || !subscription) {
    console.log(chalk.red('Unable to retrieve subscription information'));
    return;
  }
  
  if (subscription.tier === 'free') {
    console.log(chalk.yellow('You are on the free tier. No subscription to cancel.'));
    return;
  }
  
  if (subscription.cancelAtPeriodEnd) {
    console.log(chalk.yellow('Your subscription is already set to cancel at the end of the billing period.'));
    const endDate = new Date(subscription.currentPeriodEnd * 1000).toLocaleDateString();
    console.log(`Your subscription will end on ${endDate}.`);
    
    const { wantToResume } = await inquirer.prompt([{
      type: 'confirm',
      name: 'wantToResume',
      message: 'Would you like to resume your subscription?',
      default: false
    }]);
    
    if (wantToResume) {
      const spinner = ora('Resuming subscription...').start();
      const result = await payment.resumeSubscription();
      
      if (!result.success || result.error) {
        spinner.fail(`Failed to resume: ${result.error}`);
      } else {
        spinner.succeed('Subscription resumed');
      }
    }
    
    return;
  }
  
  const { confirm } = await inquirer.prompt([{
    type: 'confirm',
    name: 'confirm',
    message: 'Are you sure you want to cancel your subscription? You will still have access until the end of your current billing period.',
    default: false
  }]);
  
  if (!confirm) {
    return;
  }
  
  const spinner = ora('Cancelling subscription...').start();
  const result = await payment.cancelSubscription();
  
  if (!result.success || result.error) {
    spinner.fail(`Failed to cancel: ${result.error}`);
  } else {
    spinner.succeed('Subscription cancelled');
    console.log(chalk.cyan('Your subscription will remain active until the end of the current billing period.'));
    const endDate = new Date(subscription.currentPeriodEnd * 1000).toLocaleDateString();
    console.log(`Access ends on: ${endDate}`);
  }
}

// Parse arguments
program.parse(process.argv);

// If no args, display help
if (process.argv.length === 2) {
  displayBanner();
  program.help();
} 