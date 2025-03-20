# Integrating VulnZap with Cursor

This guide explains how to integrate VulnZap MCP with the Cursor AI coding assistant for real-time vulnerability detection in your code.

## Prerequisites

- Node.js 16 or higher installed
- npm or yarn package manager
- Cursor AI editor installed ([cursor.sh](https://cursor.sh))

## Installation

Install VulnZap MCP globally:

```bash
npm install -g vulnzap-mcp
```

Or use it without installation via npx:

```bash
npx vulnzap-mcp
```

## Basic Setup

1. Start the VulnZap MCP server:

```bash
vulnzap
```

You should see output similar to:

```
Starting VulnZap MCP server...
Loaded 6 package vulnerability records from GitHub Advisory Database
Last updated: 2023-08-15T00:00:00Z
Vulnzap MCP server started successfully
Ready to process MCP requests

Active Data Sources:
- Local database

Supported Ecosystems:
npm, pip, gem, cargo, composer, go, maven, nuget, debian, ubuntu, alpine, centos, rhel, pypi

Available Tools:
- vulnerability-check: Check individual packages (vuln://npm/express/4.16.0)
- batch-scan: Scan multiple packages at once
- detailed-report: Generate comprehensive vulnerability reports
- scan-code: Detect and scan dependencies in code snippets
- scan-repository: Check entire repositories (placeholder)
- refresh-database: Update vulnerability database
```

2. Keep this terminal window open. The server needs to remain running for Cursor to connect to it.

## Configuring Cursor

1. Open Cursor AI Editor
2. Go to **Settings** (gear icon in the bottom left)
3. Navigate to **AI > Context > Context Providers**
4. Click **Add Context Provider**
5. Configure as follows:
   - **Name**: VulnZap
   - **Type**: Model Context Protocol
   - **Command**: vulnzap
   - **Enabled**: Checked ✓
6. Click **Save**

![Cursor Configuration](cursor-config.png)

## Enhanced Setup with NVD and GitHub

For comprehensive vulnerability detection, use the NVD API and GitHub Advisory Database:

```bash
vulnzap --nvd-key YOUR_NVD_API_KEY --github-token YOUR_GITHUB_TOKEN
```

To get these keys:
- NVD API Key: Register at [NVD Developer Portal](https://nvd.nist.gov/developers/request-an-api-key)
- GitHub Token: Generate at [GitHub Settings > Developer Settings > Personal Access Tokens](https://github.com/settings/tokens) with `public_repo` scope

## Testing the Integration

1. In Cursor, open or create a new JavaScript file
2. Type or paste the following code:

```javascript
const express = require('express');
const axios = require('axios');
const lodash = require('lodash');

const app = express();
app.use(express.json());

app.get('/api/data', async (req, res) => {
  try {
    const response = await axios.get('https://api.example.com/data');
    res.json(response.data);
  } catch (error) {
    res.status(500).send('Error');
  }
});

app.listen(3000);
```

3. Ask Cursor about vulnerabilities in this code:
   - "Are there any security vulnerabilities in these dependencies?"

Cursor should respond by checking with VulnZap and providing information about potential vulnerabilities in express, axios, and lodash.

## Troubleshooting

### Common Issues

1. **"Cannot connect to server"**
   - Ensure the VulnZap server is running
   - Check if any firewall is blocking the connection

2. **"Command not found"**
   - Make sure VulnZap is installed globally
   - Try using the full path to the binary

3. **"No vulnerabilities detected"**
   - Check if you're using an older version of VulnZap
   - Update your vulnerability database with `vulnzap --refresh`

4. **"Permission denied"**
   - Run `chmod +x bin/vulnzap.js` in the installation directory
   - Try running with sudo (not recommended for regular use)

### Debug Mode

Run VulnZap with verbose logging for more details:

```bash
vulnzap --verbose
```

## Advanced Configuration

### Custom Port

```bash
vulnzap --port 4000
```

Then update the Cursor configuration to use:
```
vulnzap --port 4000
```

### Custom Data Path

If you have your own vulnerability database file:

```bash
vulnzap --data-path /path/to/your/advisories.json
```

## Getting Help

Run the help command for all available options:

```bash
vulnzap --help
```

## Using with Cursor AI Features

VulnZap works best with the following Cursor features:

1. **Chat**: Ask about vulnerabilities in your code
2. **Code Completion**: Suggests secure alternatives
3. **Code Actions**: When adding new dependencies

## Best Practices

1. Always run VulnZap before starting Cursor
2. Use both NVD and GitHub data sources for comprehensive scanning
3. Keep your databases updated regularly
4. Pin dependency versions in your projects
5. Update dependencies when vulnerabilities are detected 