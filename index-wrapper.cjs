#!/usr/bin/env node

/**
 * This is a wrapper script for vulnzap-mcp that handles the SDK module path issues
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Get the current directory
const packagePath = __dirname;

// Process command line arguments
const args = process.argv.slice(2);

// Set up environment variables
const env = { ...process.env };

// Extract NVD key and GitHub token from arguments
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--nvd-key' && i + 1 < args.length) {
    env.NVD_API_KEY = args[i + 1];
    env.USE_NVD = 'true';
    console.log('NVD integration enabled');
  }
  
  if (args[i] === '--github-token' && i + 1 < args.length) {
    env.GITHUB_TOKEN = args[i + 1];
    console.log('GitHub Advisory Database integration enabled');
  }
  
  if (args[i] === '--data-path' && i + 1 < args.length) {
    env.DATA_PATH = args[i + 1];
  }
  
  if (args[i] === '--premium-key' && i + 1 < args.length) {
    env.PREMIUM_API_KEY = args[i + 1];
  }
  
  if (args[i] === '--port' && i + 1 < args.length) {
    env.PORT = args[i + 1];
  }
}

// Create patch script that fixes the import issue
const patchScriptPath = path.join(packagePath, '_patch-imports.js');
const patchScript = `
// This is a dynamically generated patch script
// that correctly loads the MCP SDK modules
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Use require.resolve to find the exact location
const sdkPath = require.resolve('@modelcontextprotocol/sdk/package.json');
const sdkDir = sdkPath.replace(/package\\.json$/, '');

// Import MCP SDK modules with dynamically resolved paths
const serverModule = await import(sdkDir + 'dist/server/index.js');
const stdioModule = await import(sdkDir + 'dist/server/stdio.js');

export const McpServer = serverModule.Server;
export const StdioServerTransport = stdioModule.StdioServerTransport;

// Import the rest of the app
import './index.js';
`;

// Write the patch script
fs.writeFileSync(patchScriptPath, patchScript);

// Start the MCP server process
console.log('Starting VulnZap MCP server...');
const serverProcess = spawn('node', ['--experimental-modules', patchScriptPath], {
  env,
  stdio: 'inherit'
});

// Handle server lifecycle
serverProcess.on('error', (error) => {
  console.error(`Failed to start server: ${error.message}`);
  try {
    fs.unlinkSync(patchScriptPath);
  } catch (e) {
    // Ignore cleanup errors
  }
  process.exit(1);
});

process.on('SIGINT', () => {
  console.log('\nShutting down VulnZap MCP server...');
  serverProcess.kill('SIGINT');
  try {
    fs.unlinkSync(patchScriptPath);
  } catch (e) {
    // Ignore cleanup errors
  }
});

process.on('SIGTERM', () => {
  console.log('\nShutting down VulnZap MCP server...');
  serverProcess.kill('SIGTERM');
  try {
    fs.unlinkSync(patchScriptPath);
  } catch (e) {
    // Ignore cleanup errors
  }
});

serverProcess.on('exit', (code) => {
  console.log(`VulnZap MCP server exited with code ${code}`);
  try {
    fs.unlinkSync(patchScriptPath);
  } catch (e) {
    // Ignore cleanup errors
  }
  process.exit(code);
}); 