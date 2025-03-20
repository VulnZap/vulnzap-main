# Integrating VulnZap with Claude Code

This guide explains how to set up VulnZap MCP with Claude Code editor for real-time vulnerability detection during AI-assisted coding.

## Prerequisites

- Node.js 16 or higher
- npm or yarn
- Claude Code access

## Installation

Install VulnZap MCP globally:

```bash
npm install -g vulnzap-mcp
```

Alternatively, use it without installation:

```bash
npx vulnzap-mcp
```

## Starting the VulnZap Server

1. Open a terminal and start the VulnZap MCP server:

```bash
vulnzap
```

2. For enhanced vulnerability detection, use both the NVD and GitHub APIs:

```bash
vulnzap --nvd-key YOUR_NVD_API_KEY --github-token YOUR_GITHUB_TOKEN
```

3. Keep this terminal window open during your coding session.

## Configuring Claude Code

1. Open Claude Code editor
2. Navigate to **Settings** > **Extensions**
3. Click on **Add External Tool**
4. Configure with the following settings:
   - **Name**: VulnZap
   - **Type**: MCP
   - **Command**: vulnzap
   - **Arguments**: (leave blank unless you need custom options)
   - **Enabled**: Yes
5. Click **Save**

## Verifying the Integration

1. In Claude Code, create or open a project
2. Create a new file with some dependencies, e.g., create a `package.json` with:

```json
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.15",
    "axios": "0.21.0"
  }
}
```

3. Ask Claude:
   - "Can you check if these dependencies have vulnerabilities?"
   - "Is there anything concerning in the dependencies I'm using?"

Claude should respond with information about vulnerabilities in these packages that it receives from VulnZap.

## Scanning Code Snippets

Claude can also analyze code snippets for potential vulnerabilities with VulnZap. Try asking:

"Can you scan this code for vulnerable dependencies?"

```javascript
import express from 'express';
import lodash from 'lodash';
import axios from 'axios';

const app = express();
app.use(express.json());

app.get('/api/data', async (req, res) => {
  try {
    const response = await axios.get('https://api.example.com/data');
    const processed = lodash.merge({}, response.data, req.query);
    res.json(processed);
  } catch (error) {
    res.status(500).send('Error retrieving data');
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## Troubleshooting

### Common Issues

1. **Connection Errors**
   - Make sure VulnZap is running
   - Check that the port isn't being used by another application
   - Verify there are no firewall restrictions

2. **VulnZap Not Found**
   - Ensure global installation was successful
   - Try using full path to the binary

3. **Claude Not Using VulnZap**
   - Check that the extension configuration is correct
   - Restart Claude Code
   - Make sure your question references security or vulnerabilities

### Debug Logging

For more detailed output:

```bash
vulnzap --verbose
```

## Advanced Configuration

### Custom Port

If you need to run VulnZap on a different port:

```bash
vulnzap --port 5000
```

Then update the Claude Code extension configuration with:
```
vulnzap --port 5000
```

### Custom API Key

If you're in an organization with a custom premium key:

```bash
vulnzap --premium-key YOUR_PREMIUM_KEY
```

## Best Practices for Using with Claude Code

1. **Be Specific in Queries**:
   - Ask specific questions about security concerns
   - Mention "vulnerability scanning" or "dependency security" in your prompts

2. **Update Regularly**:
   - Keep VulnZap updated with the latest vulnerability database
   - Run VulnZap with external data sources when possible

3. **Code Reviews**:
   - Ask Claude to review dependencies before adding them
   - Request security audits of existing code

4. **Follow Remediation Advice**:
   - When vulnerabilities are found, ask Claude for mitigation steps
   - Request help upgrading to safer versions

## Example Queries for Claude

- "Can you scan my package.json for vulnerable dependencies?"
- "Is this version of express secure?"
- "What vulnerabilities exist in lodash 4.17.15?"
- "Help me upgrade my dependencies to secure versions"
- "Check my code for any security issues in the dependencies"
- "What are the CVSS scores for the vulnerabilities in my project?"

## Additional Resources

- [VulnZap GitHub Repository](https://github.com/yourusername/vulnzap-mcp)
- [Claude Code Documentation](https://claude.ai/docs)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [GitHub Advisory Database](https://github.com/advisories) 