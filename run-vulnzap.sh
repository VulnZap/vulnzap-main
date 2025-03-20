#!/bin/bash

# Simple shell script wrapper for vulnzap-mcp
# This bypasses issues with dynamic module imports

# Get directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Parse arguments and set environment variables
while [[ $# -gt 0 ]]; do
  case $1 in
    --nvd-key)
      export NVD_API_KEY="$2"
      export USE_NVD=true
      echo "NVD integration enabled"
      shift 2
      ;;
    --github-token)
      export GITHUB_TOKEN="$2"
      echo "GitHub Advisory Database integration enabled"
      shift 2
      ;;
    --data-path)
      export DATA_PATH="$2"
      shift 2
      ;;
    --premium-key)
      export PREMIUM_API_KEY="$2"
      shift 2
      ;;
    --port)
      export PORT="$2"
      shift 2
      ;;
    --version|-v)
      echo "VulnZap MCP v1.0.8"
      exit 0
      ;;
    --help|-h)
      cat << EOF
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
EOF
      exit 0
      ;;
    *)
      # Unknown option
      shift
      ;;
  esac
done

# Create a temporary file with a simple MCP server implementation
TMP_FILE=$(mktemp /tmp/vulnzap-server.XXXXXX.js)

cat > "$TMP_FILE" << 'EOF'
import { createServer } from 'http';
import { readFileSync } from 'fs';
import { stdin, stdout } from 'process';

// Simple MCP server implementation
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.PREMIUM_API_KEY || 'test123';
const NVD_KEY = process.env.NVD_API_KEY || '';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';

console.log("Environment loaded - NVD API Key:", NVD_KEY ? 'Yes (hidden)' : 'No');
console.log("Environment loaded - GitHub Token:", GITHUB_TOKEN ? 'Yes (hidden)' : 'No');
console.log("Premium API Key:", API_KEY ? 'Yes (configured)' : 'No');

// MCP server implementation
console.log("Starting Vulnzap MCP Server...");

// HTTP server for health checks
const server = createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ 
    status: 'running', 
    version: '1.0.8',
    integrations: {
      nvd: !!NVD_KEY,
      github: !!GITHUB_TOKEN
    }
  }));
});

server.listen(PORT, () => {
  console.log(`HTTP health check server listening on port ${PORT}`);
});

// Simple MCP protocol implementation
const INPUT_BUFFER_SIZE = 1024 * 1024; // 1MB
let buffer = '';

stdin.on('readable', () => {
  let chunk;
  while (null !== (chunk = stdin.read())) {
    buffer += chunk.toString('utf8');
    processBuffer();
  }
});

// Process messages from stdin
function processBuffer() {
  const messageEndIndex = buffer.indexOf('\n');
  if (messageEndIndex === -1) return; // Wait for more data
  
  const message = buffer.slice(0, messageEndIndex);
  buffer = buffer.slice(messageEndIndex + 1);
  
  try {
    const request = JSON.parse(message);
    handleRequest(request);
  } catch (e) {
    console.error('Error parsing message:', e);
  }
  
  // Check if there are more messages
  if (buffer.length > 0) {
    processBuffer();
  }
}

// Handle MCP requests
function handleRequest(request) {
  try {
    if (request.method === 'resources/read' && request.params.uri.startsWith('vuln://')) {
      handleVulnerabilityCheck(request);
    } else if (request.method === 'tools/invoke' && request.params.name === 'batch-scan') {
      handleBatchScan(request);
    } else if (request.method === 'tools/invoke' && request.params.name === 'detailed-report') {
      handleDetailedReport(request);
    } else if (request.method === 'initialize' || request.method === 'capabilities') {
      // Handle initialization
      sendResponse(request.id, { 
        capabilities: {
          url_protocol_handlers: ['vuln'],
          tools: ['batch-scan', 'detailed-report']
        }
      });
    } else {
      sendResponse(request.id, null, { code: 'not_implemented', message: `Method ${request.method} not implemented` });
    }
  } catch (e) {
    console.error('Error handling request:', e);
    sendResponse(request.id, null, { code: 'internal_error', message: e.message });
  }
}

// Vulnerability check handler
function handleVulnerabilityCheck(request) {
  try {
    const uri = new URL(request.params.uri);
    const segments = uri.pathname.split('/').filter(Boolean);
    
    if (segments.length !== 3 || uri.protocol !== 'vuln:') {
      throw new Error("Invalid vulnerability URI format. Expected: vuln://{ecosystem}/{packageName}/{packageVersion}");
    }
    
    const [ecosystem, packageName, packageVersion] = segments;
    
    // Simulated response
    const response = {
      contents: [{
        uri: request.params.uri,
        text: `Package: ${packageName}@${packageVersion} (${ecosystem})\n\nThis is a test MCP server. To perform actual vulnerability scanning, you need to set up the NVD and GitHub API integrations.`
      }]
    };
    
    sendResponse(request.id, response);
  } catch (e) {
    sendResponse(request.id, null, { code: 'invalid_params', message: e.message });
  }
}

// Batch scan handler
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
    
    // Simulated response
    const response = {
      content: [{ 
        type: "text", 
        text: JSON.stringify({ 
          results: packages.map(pkg => ({
            package: pkg,
            status: "simulated",
            message: "This is a test MCP server response"
          }))
        }, null, 2) 
      }]
    };
    
    sendResponse(request.id, response);
  } catch (e) {
    sendResponse(request.id, null, { code: 'invalid_params', message: e.message });
  }
}

// Detailed report handler
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
    
    // Simulated response
    const response = {
      content: [{ 
        type: "text", 
        text: `# Vulnerability Report for ${packageName}@${packageVersion} (${ecosystem})\n\nThis is a test MCP server. To perform actual vulnerability scanning, you need to set up the NVD and GitHub API integrations.`
      }]
    };
    
    sendResponse(request.id, response);
  } catch (e) {
    sendResponse(request.id, null, { code: 'invalid_params', message: e.message });
  }
}

// Send response back to client
function sendResponse(id, result, error) {
  const response = {
    jsonrpc: '2.0',
    id
  };
  
  if (error) {
    response.error = error;
  } else {
    response.result = result;
  }
  
  stdout.write(JSON.stringify(response) + '\n');
}

// Keep process running
console.log("MCP Server running. Press Ctrl+C to stop.");
EOF

# Run our simplified server
node "$TMP_FILE"

# Clean up temp file
rm "$TMP_FILE" 