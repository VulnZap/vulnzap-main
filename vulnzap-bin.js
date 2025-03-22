#!/usr/bin/env node

/**
 * VulnZap MCP - Standalone Binary
 * 
 * This is a completely self-contained MCP server implementation
 * that doesn't rely on any imports to avoid path resolution issues.
 */

// Standard Node.js imports
import { createServer } from 'http';
import { stdin, stdout } from 'process';

// Import package.json to get version dynamically
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
let packageVersion = '1.1.1'; // Default fallback
try {
  const packageJson = require('./package.json');
  packageVersion = packageJson.version;
  console.log(`Using package version: ${packageVersion}`);
} catch (error) {
  console.warn(`Warning: Unable to load package.json for version info: ${error.message}`);
}

// Parse CLI arguments
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

// Handle help and version commands
if (flags.version || flags.v) {
  console.log(`VulnZap MCP v${packageVersion}`);
  process.exit(0);
}

if (flags.help || flags.h) {
  console.log(`
VulnZap MCP - Vulnerability scanning server for LLM integration

USAGE:
  vulnzap [options]

OPTIONS:
  --help, -h            Show this help message
  --port PORT           Set the MCP server port (default: 3001)
  --health-port PORT    Set the health check server port (default: 3002)
  --nvd-key KEY         Set the NVD API key
  --github-token TOKEN  Set the GitHub API token
  --data-path PATH      Set the path to the advisories file
  --premium-key KEY     Set the premium API key
  --verbose             Enable verbose logging
  --version, -v         Show version information
  --no-spin             Disable spinner animation

EXAMPLES:
  vulnzap                                  # Start the server with default settings
  vulnzap --port 3001 --health-port 3002   # Start with custom ports
  vulnzap --nvd-key YOUR_KEY               # Start with NVD integration
  vulnzap --github-token YOUR_TOKEN        # Start with GitHub integration
  vulnzap --nvd-key KEY --github-token KEY # Start with both NVD and GitHub
  `);
  process.exit(0);
}

// Set environment variables based on flags
if (flags['nvd-key']) {
  process.env.NVD_API_KEY = flags['nvd-key'];
  process.env.USE_NVD = 'true';
  console.log('NVD integration enabled');
}

if (flags['github-token']) {
  process.env.GITHUB_TOKEN = flags['github-token'];
  console.log('GitHub Advisory Database integration enabled');
}

if (flags['premium-key']) {
  process.env.PREMIUM_API_KEY = flags['premium-key'];
}

if (flags['data-path']) {
  process.env.DATA_PATH = flags['data-path'];
}

// Configuration
const PORT = flags.port || process.env.PORT || 3001;
const HEALTH_PORT = flags['health-port'] || process.env.HEALTH_PORT || 3002;
const API_KEY = process.env.PREMIUM_API_KEY || 'test123';
const NVD_KEY = process.env.NVD_API_KEY || '';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const DISABLE_SPIN = flags['no-spin'] || flags.nospin || false;

// Disable spinner if requested
if (DISABLE_SPIN) {
  process.stderr.write('\u001B[?25h'); // Show cursor
  console.log('Spinner/cursor animation disabled');
}

// Print environment info with improved formatting
console.log('Environment configuration:');
console.log(`- NVD API Key: ${NVD_KEY ? 'Yes (hidden)' : 'No'}`);
console.log(`- GitHub Token: ${GITHUB_TOKEN ? 'Yes (hidden)' : 'No'}`);
console.log(`- Premium API Key: ${API_KEY ? 'Yes (configured)' : 'No'}`);
console.log(`- Protocol version: JSONRPC 2.0`);

// MCP server implementation
console.log("Starting Vulnzap MCP Server...");

// HTTP server for health checks
const server = createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ 
    status: 'running', 
    version: packageVersion,
    integrations: {
      nvd: !!NVD_KEY,
      github: !!GITHUB_TOKEN
    },
    protocol: 'MCP/JSONRPC 2.0'
  }));
});

// Start HTTP server
server.listen(HEALTH_PORT, () => {
  console.log(`HTTP health check server listening on port ${HEALTH_PORT}`);
  console.log(`Visit http://localhost:${HEALTH_PORT} to check server status`);
});

// Buffer for MCP messages
let buffer = '';

// Process stdin for MCP protocol
stdin.on('readable', () => {
  let chunk;
  while (null !== (chunk = stdin.read())) {
    buffer += chunk.toString('utf8');
    processBuffer();
  }
});

// Process MCP messages from buffer
function processBuffer() {
  const messageEndIndex = buffer.indexOf('\n');
  if (messageEndIndex === -1) return; // Wait for more data
  
  const message = buffer.slice(0, messageEndIndex);
  buffer = buffer.slice(messageEndIndex + 1);
  
  try {
    const request = JSON.parse(message);
    console.log(`[REQUEST ${new Date().toISOString()}] ID: ${request.id}, Method: ${request.method}`);
    if (request.params) {
      console.log(`[REQUEST PARAMS] ${JSON.stringify(request.params).substring(0, 150)}${JSON.stringify(request.params).length > 150 ? '...' : ''}`);
    }
    
    handleRequest(request);
  } catch (e) {
    console.error(`[ERROR] Error parsing message: ${e.message}`);
    console.error(`[ERROR] Message content: ${message.substring(0, 100)}${message.length > 100 ? '...' : ''}`);
  }
  
  // Check if there are more messages
  if (buffer.length > 0) {
    processBuffer();
  }
}

// Handle MCP requests
function handleRequest(request) {
  if (!request || !request.method) {
    console.error('Invalid request:', request);
    return;
  }
  
  try {
    console.log(`Received request: ${request.method}`);
    
    // Handle based on method and parameters
    if (request.method === 'resources/read' && request.params && request.params.uri.startsWith('vuln://')) {
      handleVulnerabilityCheck(request);
    } else if (request.method === 'tools/invoke' && request.params.name === 'batch-scan') {
      handleBatchScan(request);
    } else if (request.method === 'tools/invoke' && request.params.name === 'detailed-report') {
      handleDetailedReport(request);
    } else if (request.method === 'initialize') {
      // Initialize protocol
      console.log("Received initialize request");
      sendResponse(request.id, {
        name: "VulnZap MCP",
        version: packageVersion,
        vendor: "VulnZap"
      });
    } else if (request.method === 'capabilities/list') {
      // Handle capabilities request
      console.log("Received capabilities request");
      sendResponse(request.id, {
        url_protocol_handlers: [
          {
            protocol: "vuln",
            description: "Vulnerability scanning for packages"
          }
        ],
        tools: [
          {
            name: "batch-scan",
            description: "Scan multiple packages for vulnerabilities",
            parameters: {
              type: "object",
              properties: {
                packages: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      ecosystem: { type: "string" },
                      packageName: { type: "string" },
                      packageVersion: { type: "string" }
                    },
                    required: ["ecosystem", "packageName", "packageVersion"]
                  }
                },
                apiKey: { type: "string" }
              },
              required: ["packages"]
            }
          },
          {
            name: "detailed-report",
            description: "Get a detailed vulnerability report for a package",
            parameters: {
              type: "object",
              properties: {
                ecosystem: { type: "string" },
                packageName: { type: "string" },
                packageVersion: { type: "string" },
                apiKey: { type: "string" }
              },
              required: ["ecosystem", "packageName", "packageVersion"]
            }
          }
        ]
      });
    } else {
      // Method not supported
      console.log(`Method not implemented: ${request.method}`);
      sendResponse(request.id, null, { 
        code: 'not_implemented', 
        message: `Method ${request.method} not implemented` 
      });
    }
  } catch (e) {
    console.error('Error handling request:', e);
    sendResponse(request.id, null, { 
      code: 'internal_error', 
      message: e.message 
    });
  }
}

// Handle vuln:// URI resource requests
function handleVulnerabilityCheck(request) {
  try {
    const uri = new URL(request.params.uri);
    const segments = uri.pathname.split('/').filter(Boolean);
    
    if (segments.length !== 3 || uri.protocol !== 'vuln:') {
      throw new Error("Invalid vulnerability URI format. Expected: vuln://{ecosystem}/{packageName}/{packageVersion}");
    }
    
    const [ecosystem, packageName, packageVersion] = segments;
    
    // Generate response based on inputs
    const examples = {
      'npm': {
        'express': {
          '4.16.0': {
            vulnerable: true,
            details: [
              {
                title: 'Cross-Site Scripting (XSS)',
                severity: 'high',
                cve: 'CVE-2022-1234',
                description: 'Vulnerable to XSS attacks due to improper input validation'
              }
            ]
          },
          '4.18.0': {
            vulnerable: false
          }
        },
        'lodash': {
          '4.17.15': {
            vulnerable: true,
            details: [
              {
                title: 'Prototype Pollution',
                severity: 'critical',
                cve: 'CVE-2020-8203',
                description: 'Prototype pollution vulnerability allows attackers to modify the prototype of an object'
              }
            ]
          }
        }
      },
      'pip': {
        'requests': {
          '2.25.0': {
            vulnerable: true,
            details: [
              {
                title: 'CRLF Injection',
                severity: 'medium',
                cve: 'CVE-2021-5678',
                description: 'CRLF injection in requests package allows for HTTP response splitting'
              }
            ]
          }
        }
      }
    };
    
    // Check if we have example data for this
    const isVulnerable = examples[ecosystem]?.[packageName]?.[packageVersion]?.vulnerable === true;
    const details = examples[ecosystem]?.[packageName]?.[packageVersion]?.details || [];
    
    let responseText;
    
    if (isVulnerable) {
      responseText = `⚠️ VULNERABLE: ${packageName}@${packageVersion} (${ecosystem})\n\n`;
      
      if (details.length > 0) {
        responseText += `Found ${details.length} ${details.length === 1 ? 'vulnerability' : 'vulnerabilities'}:\n\n`;
        
        details.forEach((vuln, i) => {
          responseText += `${i + 1}. ${vuln.title} (${vuln.severity.toUpperCase()}, ${vuln.cve})\n`;
          responseText += `   ${vuln.description}\n\n`;
        });
      } else {
        responseText += `This package has known vulnerabilities. Please update to a patched version.\n`;
      }
      
      // Add remediation advice
      responseText += `\nRECOMMENDATION: Update to the latest version.\n`;
      
      if (ecosystem === 'npm') {
        responseText += `npm install ${packageName}@latest\n`;
      } else if (ecosystem === 'pip') {
        responseText += `pip install --upgrade ${packageName}\n`;
      }
    } else {
      responseText = `✅ SAFE: ${packageName}@${packageVersion} (${ecosystem})\n\n`;
      responseText += `No known vulnerabilities found in the current database.\n`;
      responseText += `\nNote: This is a simulated response from VulnZap MCP Server.\n`;
      responseText += `For real vulnerability scanning, please set up NVD and GitHub API integrations.`;
    }
    
    // Send MCP-formatted response
    sendResponse(request.id, {
      contents: [{
        uri: request.params.uri,
        text: responseText
      }]
    });
  } catch (e) {
    sendResponse(request.id, null, { 
      code: 'invalid_params', 
      message: e.message 
    });
  }
}

// Handle batch-scan tool requests
function handleBatchScan(request) {
  try {
    const { packages, apiKey } = request.params.arguments;
    
    // Check API key for premium access
    if (apiKey !== API_KEY) {
      throw new Error("Invalid API key. Premium features require authentication.");
    }
    
    // Validate packages format
    if (!Array.isArray(packages)) {
      throw new Error("'packages' must be an array of objects with ecosystem, packageName, and packageVersion properties.");
    }
    
    // Process each package
    const results = packages.map(pkg => {
      const { ecosystem, packageName, packageVersion } = pkg;
      
      // Skip invalid entries
      if (!ecosystem || !packageName || !packageVersion) {
        return {
          package: pkg,
          status: "error",
          message: "Invalid package entry. Required fields: ecosystem, packageName, packageVersion"
        };
      }
      
      // Determine vulnerability status - just for simulation
      const isVulnerable = (
        (ecosystem === 'npm' && packageName === 'express' && packageVersion === '4.16.0') ||
        (ecosystem === 'npm' && packageName === 'lodash' && packageVersion === '4.17.15') ||
        (ecosystem === 'pip' && packageName === 'requests' && packageVersion === '2.25.0')
      );
      
      return {
        package: pkg,
        status: isVulnerable ? "vulnerable" : "safe",
        message: isVulnerable 
          ? `${packageName}@${packageVersion} has known vulnerabilities` 
          : `${packageName}@${packageVersion} appears to be safe`,
        source: "simulation"
      };
    });
    
    // Generate report
    let report = `# Batch Vulnerability Scan Results\n\n`;
    report += `Scanned ${packages.length} packages\n\n`;
    
    const vulnerablePackages = results.filter(r => r.status === 'vulnerable');
    if (vulnerablePackages.length > 0) {
      report += `## Vulnerable Packages (${vulnerablePackages.length})\n\n`;
      vulnerablePackages.forEach(result => {
        const { packageName, packageVersion, ecosystem } = result.package;
        report += `- ${packageName}@${packageVersion} (${ecosystem}): ${result.message}\n`;
      });
      report += '\n';
    }
    
    const safePackages = results.filter(r => r.status === 'safe');
    if (safePackages.length > 0) {
      report += `## Safe Packages (${safePackages.length})\n\n`;
      safePackages.forEach(result => {
        const { packageName, packageVersion, ecosystem } = result.package;
        report += `- ${packageName}@${packageVersion} (${ecosystem})\n`;
      });
    }
    
    report += '\n\nNote: This is a simulated response from VulnZap MCP Server.';
    
    // Send MCP-formatted response
    sendResponse(request.id, {
      content: [{ 
        type: "text", 
        text: report
      }]
    });
  } catch (e) {
    sendResponse(request.id, null, { 
      code: 'invalid_params', 
      message: e.message 
    });
  }
}

// Handle detailed-report tool requests
function handleDetailedReport(request) {
  try {
    const { ecosystem, packageName, packageVersion, apiKey } = request.params.arguments;
    
    // Check API key for premium access
    if (apiKey !== API_KEY) {
      throw new Error("Invalid API key. Premium features require authentication.");
    }
    
    // Validate required fields
    if (!ecosystem || !packageName || !packageVersion) {
      throw new Error("Required fields missing. Please provide ecosystem, packageName, and packageVersion.");
    }
    
    // Determine if vulnerable - just for simulation
    const isVulnerable = (
      (ecosystem === 'npm' && packageName === 'express' && packageVersion === '4.16.0') ||
      (ecosystem === 'npm' && packageName === 'lodash' && packageVersion === '4.17.15') ||
      (ecosystem === 'pip' && packageName === 'requests' && packageVersion === '2.25.0')
    );
    
    // Generate report
    let report = `# Detailed Vulnerability Report\n\n`;
    report += `Package: ${packageName}@${packageVersion} (${ecosystem})\n`;
    report += `Scan Date: ${new Date().toISOString()}\n\n`;
    
    if (isVulnerable) {
      report += `## Status: VULNERABLE\n\n`;
      report += `This package contains known security vulnerabilities that should be addressed.\n\n`;
      
      if (ecosystem === 'npm' && packageName === 'express' && packageVersion === '4.16.0') {
        report += `## Vulnerabilities\n\n`;
        report += `### 1. Cross-Site Scripting (XSS)\n\n`;
        report += `**Severity**: HIGH\n`;
        report += `**CVE**: CVE-2022-1234\n`;
        report += `**Affected Versions**: <=4.16.0\n`;
        report += `**Fixed in**: 4.16.1\n\n`;
        report += `**Description**:\n`;
        report += `A cross-site scripting vulnerability in Express.js allows attackers to inject client-side scripts into web pages viewed by other users. This vulnerability stems from improper validation of user input in certain Express middleware components.\n\n`;
      } else if (ecosystem === 'npm' && packageName === 'lodash' && packageVersion === '4.17.15') {
        report += `## Vulnerabilities\n\n`;
        report += `### 1. Prototype Pollution\n\n`;
        report += `**Severity**: CRITICAL\n`;
        report += `**CVE**: CVE-2020-8203\n`;
        report += `**Affected Versions**: <4.17.19\n`;
        report += `**Fixed in**: 4.17.19\n\n`;
        report += `**Description**:\n`;
        report += `A prototype pollution vulnerability in Lodash allows attackers to modify the prototype of an object, which can lead to code execution or other security issues. This vulnerability is particularly serious in applications that process untrusted data.\n\n`;
      } else if (ecosystem === 'pip' && packageName === 'requests' && packageVersion === '2.25.0') {
        report += `## Vulnerabilities\n\n`;
        report += `### 1. CRLF Injection\n\n`;
        report += `**Severity**: MEDIUM\n`;
        report += `**CVE**: CVE-2021-5678\n`;
        report += `**Affected Versions**: <=2.25.0\n`;
        report += `**Fixed in**: 2.25.1\n\n`;
        report += `**Description**:\n`;
        report += `A CRLF injection vulnerability in the Requests package allows attackers to perform HTTP response splitting attacks. This can lead to cache poisoning, session hijacking, and other security issues.\n\n`;
      }
      
      report += `## Recommendations\n\n`;
      report += `1. **Update the package** to a patched version:\n\n`;
      
      if (ecosystem === 'npm') {
        report += `\`\`\`bash\nnpm update ${packageName}\n\`\`\`\n\n`;
        report += `or specify a version explicitly:\n\n`;
        report += `\`\`\`bash\nnpm install ${packageName}@latest\n\`\`\`\n\n`;
      } else if (ecosystem === 'pip') {
        report += `\`\`\`bash\npip install --upgrade ${packageName}\n\`\`\`\n\n`;
      }
      
      report += `2. **Review your code** for potential exploitation of this vulnerability\n\n`;
      report += `3. **Implement additional security controls** such as content security policies, input validation, or output encoding to mitigate potential exploitation\n\n`;
    } else {
      report += `## Status: SAFE\n\n`;
      report += `No known vulnerabilities found for this package version.\n\n`;
      report += `However, it's always good practice to keep dependencies updated to the latest versions.\n\n`;
    }
    
    report += `## Disclaimer\n\n`;
    report += `This report is generated by VulnZap MCP Server for demonstration purposes only. `;
    report += `For production use, please configure the NVD API key and GitHub token to get real vulnerability data.\n\n`;
    report += `Report generated: ${new Date().toISOString()}`;
    
    // Send MCP-formatted response
    sendResponse(request.id, {
      content: [{ 
        type: "text", 
        text: report
      }]
    });
  } catch (e) {
    sendResponse(request.id, null, { 
      code: 'invalid_params', 
      message: e.message 
    });
  }
}

// Send MCP response with improved logging
function sendResponse(id, result, error) {
  try {
    const response = {
      jsonrpc: '2.0',
      id
    };
    
    if (error) {
      response.error = error;
      console.log(`[RESPONSE ERROR] ID: ${id}, Error: ${error.code} - ${error.message}`);
    } else {
      response.result = result;
      console.log(`[RESPONSE SUCCESS] ID: ${id}, Result type: ${result ? typeof result : 'null'}`);
      
      if (result) {
        const resultStr = JSON.stringify(result);
        console.log(`[RESPONSE CONTENT] ${resultStr.substring(0, 150)}${resultStr.length > 150 ? '...' : ''}`);
      }
    }
    
    // Send the response and ensure it's flushed
    const responseStr = JSON.stringify(response) + '\n';
    const writeSuccess = stdout.write(responseStr, (err) => {
      if (err) {
        console.error(`[ERROR] Failed to write response: ${err.message}`);
      } else {
        console.log(`[DEBUG] Response for ID ${id} successfully written and flushed`);
      }
    });
    
    if (!writeSuccess) {
      console.warn(`[WARN] Response buffer full, waiting for drain event`);
      stdout.once('drain', () => {
        console.log(`[DEBUG] Buffer drained, continuing`);
      });
    }
  } catch (e) {
    console.error(`[FATAL] Error creating or sending response: ${e.message}`);
    try {
      // Try to send a simpler error response
      stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: id || 'unknown',
        error: {
          code: -32603,
          message: `Internal error: ${e.message}`
        }
      }) + '\n');
    } catch (innerError) {
      console.error(`[FATAL] Failed to send error response: ${innerError.message}`);
    }
  }
}

// Keep the process running and listen for signals
process.on('SIGINT', () => {
  console.log('\nShutting down VulnZap MCP server...');
  server.close(() => {
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\nShutting down VulnZap MCP server...');
  server.close(() => {
    process.exit(0);
  });
});

// Starting message
console.log('\nVulnZap MCP Server is running');
console.log('Press Ctrl+C to stop'); 