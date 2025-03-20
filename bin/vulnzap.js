#!/usr/bin/env node

/**
 * VulnZap MCP - CLI interface
 * 
 * This script provides a command-line interface for starting the VulnZap MCP server.
 * It allows easy connection to LLM clients like Cursor, Claude Code, and Windsurf.
 */

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Get the current directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const packagePath = path.resolve(__dirname, '..');

// Parse command-line arguments
const args = process.argv.slice(2);
const flags = {};

for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith('--')) {
    const flag = args[i].slice(2);
    const nextArg = args[i + 1];
    if (nextArg && !nextArg.startsWith('--')) {
      flags[flag] = nextArg;
      i++;
    } else {
      flags[flag] = true;
    }
  }
}

// Display help if requested
if (flags.help || flags.h) {
  console.log(`
VulnZap MCP - Vulnerability scanning server for LLM integration

USAGE:
  vulnzap [options]

OPTIONS:
  --help, -h            Show this help message
  --port PORT           Set the server port (default: 3000)
  --nvd-key KEY         Set the NVD API key
  --github-token TOKEN  Set the GitHub API token
  --data-path PATH      Set the path to the advisories file
  --premium-key KEY     Set the premium API key
  --verbose             Enable verbose logging
  --version, -v         Show version information

EXAMPLES:
  vulnzap                                  # Start the server with default settings
  vulnzap --nvd-key YOUR_KEY               # Start with NVD integration
  vulnzap --github-token YOUR_TOKEN        # Start with GitHub integration
  vulnzap --nvd-key KEY --github-token KEY # Start with both NVD and GitHub
  `);
  process.exit(0);
}

// Display version if requested
if (flags.version || flags.v) {
  const packageJsonPath = path.join(packagePath, 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  console.log(`VulnZap MCP v${packageJson.version}`);
  process.exit(0);
}

// Set environment variables based on provided flags
const env = { ...process.env };

if (flags.port) {
  env.PORT = flags.port;
}

if (flags['nvd-key']) {
  env.NVD_API_KEY = flags['nvd-key'];
  env.USE_NVD = 'true';
  console.log('NVD integration enabled');
}

if (flags['github-token']) {
  env.GITHUB_TOKEN = flags['github-token'];
  console.log('GitHub Advisory Database integration enabled');
}

if (flags['data-path']) {
  env.DATA_PATH = flags['data-path'];
}

if (flags['premium-key']) {
  env.PREMIUM_API_KEY = flags['premium-key'];
}

// Start the server
console.log('Starting VulnZap MCP server...');
const serverProcess = spawn('node', [path.join(packagePath, 'index.js')], {
  env,
  stdio: 'inherit'
});

// Handle server lifecycle
serverProcess.on('error', (error) => {
  console.error(`Failed to start server: ${error.message}`);
  process.exit(1);
});

process.on('SIGINT', () => {
  console.log('\nShutting down VulnZap MCP server...');
  serverProcess.kill('SIGINT');
});

process.on('SIGTERM', () => {
  console.log('\nShutting down VulnZap MCP server...');
  serverProcess.kill('SIGTERM');
});

serverProcess.on('exit', (code) => {
  console.log(`VulnZap MCP server exited with code ${code}`);
  process.exit(code);
}); 