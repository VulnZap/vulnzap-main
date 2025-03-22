# VulnZap MCP

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![npm](https://img.shields.io/npm/v/vulnzap-mcp)

VulnZap is a multi-ecosystem vulnerability scanning service with Model Context Protocol (MCP) integration for AI coding assistants. It detects vulnerabilities in dependencies across multiple package ecosystems, protecting your codebase from AI-introduced security issues.

## Features

- **MCP Integration**: Connect directly to AI coding assistants like Cursor, Claude Code, and Windsurf
- **Multi-Ecosystem Support**: Scans 12+ package ecosystems including npm, pip, gem, cargo, go, and more
- **Multiple Data Sources**: Combines vulnerability data from GitHub Advisory Database and National Vulnerability Database
- **Code Analysis**: Automatically detects dependencies in code snippets and checks for vulnerabilities
- **Detailed Reports**: Provides comprehensive vulnerability information with remediation advice

## Installation

```bash
# Install globally
npm install -g vulnzap-mcp

# Or run with npx
npx vulnzap-mcp
```

## Usage

### Basic Usage

```bash
# Start the server with default settings
vulnzap

# Show help
vulnzap --help

# Start with NVD integration
vulnzap --nvd-key YOUR_NVD_API_KEY

# Start with GitHub integration
vulnzap --github-token YOUR_GITHUB_TOKEN

# Start with both integrations for comprehensive scanning
vulnzap --nvd-key YOUR_NVD_API_KEY --github-token YOUR_GITHUB_TOKEN

# Use custom ports to avoid conflicts
vulnzap --port 3001 --health-port 3002
```

### Port Configuration

VulnZap uses two ports:
- **MCP Server Port**: Default is 3001 (used for the main MCP communication)
- **Health Check Port**: Default is 3002 (used for the HTTP health check endpoint)

If you encounter port conflicts (EADDRINUSE errors), you can:

1. **Configure through command line arguments**:
   ```bash
   vulnzap --port 3001 --health-port 3002
   ```

2. **Set environment variables**:
   ```bash
   export PORT=3001
   export HEALTH_PORT=3002
   vulnzap
   ```

3. **Create a .env file** in your project directory:
   ```
   PORT=3001
   HEALTH_PORT=3002
   ```

### Using with MCP Inspector

When using the MCP Inspector with VulnZap, you need to specify the server port:

```bash
# Start VulnZap first
vulnzap --port 3001 --health-port 3002

# In another terminal, run MCP Inspector with the correct server port
npx @modelcontextprotocol/inspector vulnzap --server-port 3001
```

The inspector will typically use port 5173 for its web interface. If that port is in use:

```bash
# Find and kill the process using port 5173
lsof -i :5173
kill -9 <PID>

# Or specify a different inspector port
npx @modelcontextprotocol/inspector vulnzap --server-port 3001 --inspector-port 5174
```

### Connecting to LLM Clients

#### Cursor

1. Install VulnZap MCP globally:
   ```bash
   npm install -g vulnzap-mcp
   ```

2. Start the server:
   ```bash
   vulnzap
   ```

3. Configure Cursor settings:
   - Open Cursor Settings
   - Go to AI > Context > Context Providers
   - Add a new Context Provider:
     - Name: VulnZap
     - Type: Model Context Protocol
     - Command: vulnzap
   - Save settings

4. When using Cursor, it will now check for vulnerabilities in dependencies being added.

#### Claude Code

1. Start VulnZap MCP:
   ```bash
   vulnzap
   ```

2. In Claude Code settings:
   - Navigate to Extensions
   - Add External Tool
   - Configure with:
     - Name: VulnZap
     - Type: MCP
     - Command: vulnzap

3. Claude will now have access to vulnerability scanning through MCP.

#### Windsurf

1. Run VulnZap:
   ```bash
   vulnzap
   ```

2. In Windsurf configuration:
   - Add to MCP providers list:
     ```json
     {
       "mcpProviders": [
         {
           "name": "VulnZap",
           "command": "vulnzap"
         }
       ]
     }
     ```

## API Usage

VulnZap MCP provides several tools via the MCP protocol:

### Resource Query

Check if a specific package is vulnerable:

```
vuln://{ecosystem}/{packageName}/{packageVersion}
```

Example: `vuln://npm/express/4.16.0`

### Tool: batch-scan

Scan multiple packages at once:

```json
{
  "apiKey": "test123",
  "packages": [
    { "ecosystem": "npm", "packageName": "express", "packageVersion": "4.16.0" },
    { "ecosystem": "npm", "packageName": "lodash", "packageVersion": "4.17.15" }
  ]
}
```

### Tool: detailed-report

Generate a comprehensive vulnerability report:

```json
{
  "apiKey": "test123",
  "ecosystem": "npm",
  "packageName": "lodash",
  "packageVersion": "4.17.15"
}
```

### Tool: scan-code

Detect dependencies in code snippets and scan for vulnerabilities:

```json
{
  "apiKey": "test123",
  "code": "import express from 'express';\nimport lodash from 'lodash';",
  "language": "javascript"
}
```

## API Keys

For enhanced scanning capabilities, you can use these API keys:

- **NVD API Key**: Get from [NVD](https://nvd.nist.gov/developers/request-an-api-key)
- **GitHub Token**: Generate at [GitHub Settings](https://github.com/settings/tokens)

## GitHub Repository

[https://github.com/yecelebisanli/vulnzap-mcp](https://github.com/plawlost/vulnzap-mcp)

## License

MIT 