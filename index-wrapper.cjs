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
  
  if (args[i] === '--version' || args[i] === '-v') {
    const packageJsonPath = path.join(packagePath, 'package.json');
    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      console.log(`VulnZap MCP v${packageJson.version}`);
    } catch (error) {
      console.log('VulnZap MCP (version unknown)');
    }
    process.exit(0);
  }
  
  if (args[i] === '--help' || args[i] === '-h') {
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
}

// Create a temporary file with a simple wrapper to handle import issues
const tempIndexPath = path.join(packagePath, '_temp_index.js');
const tempContent = `
// This is a dynamically generated file to handle import issues
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Find the SDK module path
let sdkPath;
try {
  sdkPath = require.resolve('@modelcontextprotocol/sdk/package.json');
} catch (error) {
  console.error('Error: Could not find @modelcontextprotocol/sdk package.');
  console.error('Please make sure you have installed the package correctly.');
  process.exit(1);
}

// Get the base directory of the SDK
const sdkBaseDir = sdkPath.replace(/package\\.json$/, '');

// Import the required modules directly from the SDK package
async function startServer() {
  try {
    // Import the MCP SDK server modules
    const { Server } = await import(sdkBaseDir + 'dist/server/index.js');
    const { StdioServerTransport } = await import(sdkBaseDir + 'dist/server/stdio.js');
    
    // Start the application with the dynamically loaded modules
    await startVulnZapServer(Server, StdioServerTransport);
  } catch (error) {
    console.error('Error importing MCP SDK modules:', error);
    process.exit(1);
  }
}

// Load the application code and start the server
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import semver from 'semver';
import dotenv from 'dotenv';
import { initNvdClient, checkNvdVulnerability } from './nvd-client.js';
import { initGithubClient, checkGithubVulnerability, fetchAllAdvisories } from './github-client.js';

// Load environment variables first thing, before any other code
dotenv.config();

// Verify environment variables loaded correctly
console.log(\`Environment loaded - NVD API Key: \${process.env.NVD_API_KEY ? 'Yes (hidden)' : 'No'}\`);
console.log(\`Environment loaded - GitHub Token: \${process.env.GITHUB_TOKEN ? 'Yes (hidden)' : 'No'}\`);
console.log(\`Environment loaded - USE_NVD: \${process.env.USE_NVD}\`);

// Get __dirname equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
let nvdConfig = null;
let githubConfig = null;

// In-memory vulnerability database
const vulnerabilityDatabase = new Map();

// Load vulnerability functions from index.js
import * as indexFunctions from './index.js';

// Function to start the server with imported modules
async function startVulnZapServer(Server, StdioTransport) {
  try {
    // Initialize NVD client if API key is available
    if (process.env.NVD_API_KEY && process.env.USE_NVD === 'true') {
      try {
        console.log(\`Using NVD API key: \${process.env.NVD_API_KEY.substring(0, 5)}...\`);
        nvdConfig = {
          apiKey: process.env.NVD_API_KEY,
          refreshInterval: parseInt(process.env.NVD_REFRESH_INTERVAL || '86400000', 10)
        };
        initNvdClient(nvdConfig);
      } catch (error) {
        console.error('Failed to initialize NVD client:', error);
      }
    } else {
      console.warn(\`NVD integration disabled or API key not provided: USE_NVD=\${process.env.USE_NVD}, API key exists: \${Boolean(process.env.NVD_API_KEY)}\`);
    }
    
    // Initialize GitHub client if token is available
    if (process.env.GITHUB_TOKEN) {
      try {
        githubConfig = {
          githubToken: process.env.GITHUB_TOKEN,
          refreshInterval: parseInt(process.env.GITHUB_REFRESH_INTERVAL || '86400000', 10)
        };
        
        initGithubClient(githubConfig);
        
        // Refresh GitHub advisories if configured
        setTimeout(async () => {
          try {
            await fetchAllAdvisories();
          } catch (error) {
            console.error('Error refreshing advisories:', error);
          }
        }, 5000);
      } catch (error) {
        console.error('Failed to initialize GitHub client:', error);
      }
    } else {
      console.warn('GitHub token not provided. Continuing with limited functionality.');
    }
    
    // Initialize MCP server
    const transport = new StdioTransport(process.stdin, process.stdout);
    const server = new Server(transport);
    
    // Configure server with all the handlers
    
    // Register URL protocol handler
    server.registerUrlProtocolHandler("vuln", async (url) => {
      const parsedUrl = new URL(url);
      const [ecosystem, packageName, packageVersion] = parsedUrl.pathname.split('/').filter(Boolean);
      
      if (!ecosystem || !packageName || !packageVersion) {
        return {
          contents: [{
            type: "text",
            text: "Invalid URL format. Use vuln://ecosystem/package/version"
          }]
        };
      }
      
      console.log(\`Checking vulnerability for \${ecosystem}/\${packageName}@\${packageVersion}\`);
      
      const vulnerabilities = await indexFunctions.checkVulnerability(ecosystem, packageName, packageVersion);
      
      if (!vulnerabilities) {
        return {
          contents: [{
            type: "text",
            text: \`✅ No known vulnerabilities found for \${packageName}@\${packageVersion}.\`
          }]
        };
      }
      
      // Format the results
      const vulnCount = vulnerabilities.length;
      let responseText = \`⚠️ Found \${vulnCount} \${vulnCount === 1 ? 'vulnerability' : 'vulnerabilities'} for \${packageName}@\${packageVersion}:\\n\\n\`;
      
      for (const vuln of vulnerabilities) {
        responseText += \`* \${vuln.title || 'Unnamed vulnerability'}\\n\`;
        responseText += \`  Severity: \${vuln.severity || 'Unknown'}\\n\`;
        
        if (vuln.cve_id) {
          responseText += \`  CVE: \${vuln.cve_id}\\n\`;
        }
        
        if (vuln.description) {
          responseText += \`  Description: \${vuln.description.substring(0, 150)}\${vuln.description.length > 150 ? '...' : ''}\\n\`;
        }
        
        if (vuln.references && vuln.references.length > 0) {
          responseText += \`  Reference: \${vuln.references[0]}\\n\`;
        }
        
        if (vuln.patched_versions) {
          responseText += \`  Fixed in: \${vuln.patched_versions}\\n\`;
        }
        
        responseText += '\\n';
      }
      
      return {
        contents: [{
          type: "text",
          text: responseText
        }]
      };
    });
    
    // Start the server
    console.log('Server starting. Waiting for connections...');
    await server.start();
    
    // Keep the process running until interrupted
    console.log('MCP server is running and ready to handle requests.');
    console.log('Press Ctrl+C to stop the server.');
    
    // Keep the process alive
    process.stdin.resume();
  } catch (error) {
    console.error('Error starting VulnZap MCP server:', error);
    process.exit(1);
  }
}

// Start the server
startServer().catch(error => {
  console.error('Unhandled error:', error);
  process.exit(1);
}); 
`;

try {
  // Write the temporary index file
  fs.writeFileSync(tempIndexPath, tempContent);
  
  // Start the MCP server process
  console.log('Starting VulnZap MCP server...');
  const serverProcess = spawn('node', ['--experimental-modules', tempIndexPath], {
    env,
    stdio: 'inherit'
  });
  
  // Handle server lifecycle
  serverProcess.on('error', (error) => {
    console.error(`Failed to start server: ${error.message}`);
    try {
      fs.unlinkSync(tempIndexPath);
    } catch (e) {
      // Ignore cleanup errors
    }
    process.exit(1);
  });
  
  process.on('SIGINT', () => {
    console.log('\nShutting down VulnZap MCP server...');
    serverProcess.kill('SIGINT');
    try {
      fs.unlinkSync(tempIndexPath);
    } catch (e) {
      // Ignore cleanup errors
    }
  });
  
  process.on('SIGTERM', () => {
    console.log('\nShutting down VulnZap MCP server...');
    serverProcess.kill('SIGTERM');
    try {
      fs.unlinkSync(tempIndexPath);
    } catch (e) {
      // Ignore cleanup errors
    }
  });
  
  serverProcess.on('exit', (code) => {
    console.log(`VulnZap MCP server exited with code ${code}`);
    try {
      fs.unlinkSync(tempIndexPath);
    } catch (e) {
      // Ignore cleanup errors
    }
    process.exit(code);
  });
} catch (error) {
  console.error('Error starting VulnZap MCP server:', error);
  process.exit(1);
} 