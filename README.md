# VulnZap

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue)](https://opensource.org/licenses/BUSL-1.1)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8.3-blue)](https://www.typescriptlang.org/)
[![MCP Protocol](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple)](https://modelcontextprotocol.io/)

## Overview

VulnZap is a security-first development tool that provides real-time vulnerability scanning for AI-generated code. It integrates with AI-powered development environments through the Model Context Protocol (MCP) and provides comprehensive CLI tooling for security analysis.

The platform supports multi-ecosystem vulnerability detection across npm, pip, go, rust, maven, gradle, composer, nuget, and pypi packages, with intelligent caching and offline fallback capabilities.

## Installation

### Prerequisites
- Node.js >= 16.0.0
- npm or yarn package manager

### Global Installation
```bash
npm install -g vulnzap
```

### Build from Source
```bash
git clone https://github.com/VulnZap/vulnzap-main.git
cd vulnzap
npm install
npm run build
npm link
```

## CLI Commands

### Authentication and Configuration

#### `vulnzap init`
Complete onboarding workflow with interactive setup.

```bash
vulnzap init
```

Features:
- Magic authentication flow with QR code support
- Automatic IDE detection (VS Code, Cursor, Windsurf, JetBrains)
- Multi-IDE configuration support
- MCP server setup for compatible IDEs

#### `vulnzap setup`
Manual authentication and IDE configuration.

```bash
vulnzap setup -k <api-key>
vulnzap setup -k <api-key> --ide <cursor|windsurf|cline|vscode>
```

Options:
- `-k, --key <key>`: API key for authentication
- `--ide <ide-name>`: Target IDE for integration

#### `vulnzap account`
Display account information and usage statistics.

```bash
vulnzap account
```

Displays:
- User profile information
- Current subscription tier
- API usage metrics
- Remaining scan quota

#### `vulnzap status`
System health check and configuration verification.

```bash
vulnzap status
```

Validates:
- Server connectivity
- Authentication status
- User profile data
- System configuration

### Security Scanning

#### `vulnzap check`
Analyze individual packages for vulnerabilities.

```bash
# Recommended format
vulnzap check <ecosystem:package@version>
vulnzap check npm:express@4.17.1
vulnzap check pip:requests@2.25.1

# Alternative format
vulnzap check <package@version> --ecosystem <ecosystem>
vulnzap check express@4.17.1 --ecosystem npm
```

Supported ecosystems: `npm`, `pip`, `go`, `rust`, `maven`, `gradle`, `composer`, `nuget`, `pypi`

#### `vulnzap batch-scan`
Scan all dependencies in the current project directory.

```bash
vulnzap batch-scan
vulnzap batch-scan --ecosystem npm
vulnzap batch-scan --output results.json
```

Options:
- `--ecosystem <ecosystem>`: Filter by specific package ecosystem
- `--output <file>`: Save results to JSON file (default: `.vulnzap/batch-scan-results.json`)

Automatically detects and parses:
- `package.json` (npm)
- `requirements.txt` (pip)
- `go.mod` (go)
- `Cargo.toml` (rust)
- `pom.xml` (maven)
- `build.gradle` (gradle)
- `composer.json` (composer)
- `*.csproj` (nuget)

#### `vulnzap scan`
Initiate repository-wide vulnerability scan for GitHub repositories.

```bash
vulnzap scan <repository-url>
vulnzap scan https://github.com/owner/repo --branch main
vulnzap scan https://github.com/owner/repo --wait --output scan-results.json
```

Options:
- `-b, --branch <branch>`: Target branch (default: `main`)
- `--wait`: Block until scan completion
- `-o, --output <file>`: Save results to JSON file
- `--key <api-key>`: Override default API key

Returns:
- Job ID for tracking
- Project ID for dashboard access
- Real-time scan progress (with `--wait`)
- Remaining line quota

#### `vulnzap watch`
Monitor directory for file changes and perform incremental security analysis.

```bash
vulnzap watch
vulnzap watch --timeout 120000
vulnzap watch --output ./scan-results
```

Options:
- `-t, --timeout <ms>`: Session timeout in milliseconds (default: 120000)
- `-o, --output <dir>`: Output directory for results (default: `.vulnzap/incremental`)

Features:
- Real-time file change detection
- Incremental vulnerability scanning
- Session-based result tracking
- Automatic timeout handling
- Manual stop with Ctrl+C

### IDE Integration

#### `vulnzap connect`
Configure MCP integration for supported IDEs.

```bash
vulnzap connect
vulnzap connect --ide cursor
vulnzap connect --ide windsurf
```

Supported IDEs:
- `cursor`: Cursor IDE
- `windsurf`: Windsurf IDE
- `antigravity`: Antigravity IDE
- `claude`: Claude Code
- `cline`: Cline (VS Code extension)
- `vscode`: VS Code (extension only)
- `jetbrains`: JetBrains IDEs (IntelliJ, WebStorm, etc.)

Configuration locations:
- Cursor: `.cursor/mcp.json`
- Windsurf: `.codeium/windsurf/mcp_config.json`
- Cline: Platform-specific MCP settings

#### `vulnzap mcp`
Start the MCP server for IDE integration.

```bash
vulnzap mcp
```

Environment variables:
- `VULNZAP_API_KEY`: API key for authentication
- `VULNZAP_DEBUG`: Enable verbose logging

This command is typically invoked automatically by IDE MCP configurations.

### Utility Commands

#### `vulnzap tools`
Display interactive guide to available MCP tools.

```bash
vulnzap tools
```

#### `vulnzap help`
Display comprehensive help information.

```bash
vulnzap help
```

## MCP Tools Reference

VulnZap exposes seven MCP tools for AI agent integration. These tools enable autonomous security scanning during development workflows.

### Tool 1: `vulnzap_scan_diff`

Performs fast, non-blocking incremental scan on git diff.

**Purpose**: Scan only changed files since a specific commit reference. Designed for frequent use during active development.

**Input Schema**:
```typescript
{
  repo: string;              // Repository path (default: ".")
  since?: string;            // Commit/ref to diff against (default: "HEAD")
  paths?: string[];          // Optional glob patterns to limit scope
}
```

**Response**:
```typescript
{
  scan_id: string;           // Unique scan identifier
  queued: boolean;           // Scan queued status
  eta_ms: number;            // Estimated completion time
  next_hint: string;         // Suggested next action
  summary: {
    files_considered: number;
    mode: "diff";
  }
}
```

**Error Responses**:
- Not a git repository
- Could not determine commit hash
- Could not determine repository URL
- No files changed in diff

**Usage Pattern**:
```
1. Make code changes
2. Call vulnzap_scan_diff
3. Continue coding (non-blocking)
4. Poll vulnzap_status before next commit
```

### Tool 2: `vulnzap_status`

Retrieve scan results for a specific scan ID or latest scan.

**Purpose**: Check completion status and retrieve vulnerability findings. Primary mechanism for agents to discover security issues.

**Input Schema**:
```typescript
{
  repo: string;              // Repository path
  scan_id?: string;          // Specific scan to check
  latest?: boolean;          // Get latest scan for repo
}
```

**Response (Completed)**:
```typescript
{
  ready: true;
  findings: Array<{
    id: string;
    severity: "critical" | "high" | "medium" | "low";
    path: string;
    range: {
      start: { line: number; col: number; }
    };
    description: string;
  }>;
  next_hint: string;
}
```

**Response (In Progress)**:
```typescript
{
  ready: false;
  poll_after_ms: number;     // Suggested polling interval
}
```

**Polling Strategy**:
- Initial poll: 5 seconds
- Subsequent polls: 5-30 seconds with exponential backoff
- Do not poll continuously

### Tool 3: `vulnzap_full_scan`

Comprehensive repository-wide security scan.

**Purpose**: Baseline security analysis of entire codebase. Reserved for pre-deployment or pre-push workflows.

**Input Schema**:
```typescript
{
  repo: string;              // Repository path (default: ".")
}
```

**Response**:
```typescript
{
  scan_id: string;           // Unique scan identifier
  queued: boolean;           // Scan queued status
  eta_ms: number;            // Estimated completion (typically 180000ms)
}
```

**Performance Characteristics**:
- Significantly slower than diff scans
- Scans entire repository history
- Use sparingly (pre-push, pre-deploy only)
- Poll results via `vulnzap_status`

### Tool 4: `vulnzap_report`

Generate human-readable scan report in markdown format.

**Purpose**: Create formatted vulnerability reports for PR descriptions, documentation, or audit logs.

**Input Schema**:
```typescript
{
  repo: string;              // Repository path
  scan_id: string;           // Scan to generate report for
}
```

**Response**:
```typescript
{
  report: string;            // Markdown-formatted report
}
```

**Report Contents**:
- Vulnerability summary
- Severity breakdown
- Affected files and line numbers
- Remediation recommendations
- Reference links

### Tool 5: `vulnzap_security_assistant`

Start file watcher for incremental security analysis.

**Purpose**: Monitor directory for changes and perform continuous security scanning. Designed for active development sessions.

**Input Schema**:
```typescript
{
  path: string;              // Directory path to monitor
}
```

**Response**:
```typescript
{
  message: string;
  nextSteps: string;         // Instructions for retrieving results
  sessionId: string;         // Session identifier (in nextSteps)
}
```

**Workflow**:
```
1. Call vulnzap_security_assistant with target directory
2. Receive session ID
3. Make code changes
4. Wait 10+ seconds for analysis
5. Call vulnzap_security_assistant_results with session ID
```

**Session Management**:
- Automatic timeout: 60 seconds of inactivity
- Timeout resets on each file change
- Session data cached in `.vulnzap/client/sessions/`

### Tool 6: `vulnzap_security_assistant_results`

Retrieve results from active security assistant session.

**Purpose**: Fetch vulnerability findings from incremental scan session.

**Input Schema**:
```typescript
{
  session: string;           // Session ID from security_assistant
  wait?: number;             // Optional wait time in seconds
}
```

**Response (Success)**:
```typescript
{
  response: {
    findings: Array<Vulnerability>;
    summary: string;
    scannedFiles: string[];
  }
}
```

**Response (Error)**:
```typescript
{
  error: string;             // Error description
}
```

**Best Practices**:
- Wait 10+ seconds after code changes before calling
- Use `wait` parameter to add additional delay if needed
- Session must be active (not timed out)

### Tool 7: `vulnzap_security_assistant_stop`

Terminate security assistant session and retrieve final results.

**Purpose**: Explicitly stop file watching and get final scan results.

**Input Schema**:
```typescript
{
  session: string;           // Session ID to stop
}
```

**Response (Success)**:
```typescript
{
  message: string;
  nextSteps: string;
  response: {
    findings: Array<Vulnerability>;
    summary: string;
  }
}
```

**Response (Error)**:
```typescript
{
  error: string;
}
```

**Use Cases**:
- Manual session termination
- Retrieve final results before timeout
- Clean up resources after development session

## MCP Agent Workflow

Recommended integration pattern for AI agents:

### Initialization Phase
```
1. Call vulnzap_status with {latest: true, repo: "."}
2. Review any existing vulnerabilities
3. Fix critical issues before proceeding
```

### Active Development Phase
```
1. Make code changes
2. Call vulnzap_scan_diff with {repo: ".", since: "HEAD"}
3. Continue development (non-blocking)
4. Periodically call vulnzap_status to check results
5. If vulnerabilities found:
   a. Fix issues
   b. Call vulnzap_scan_diff again
   c. Verify fixes with vulnzap_status
```

### Pre-Commit Phase
```
1. Call vulnzap_status to ensure no pending issues
2. If clean, proceed with commit
3. If issues found, fix and rescan
```

### Pre-Push Phase
```
1. Call vulnzap_full_scan with {repo: "."}
2. Poll vulnzap_status until ready: true
3. Review all findings
4. Fix critical and high severity issues
5. Call vulnzap_report for documentation
6. Attach report to PR description
```

### Continuous Monitoring (Alternative)
```
1. Call vulnzap_security_assistant with {path: "./src"}
2. Save session ID
3. Make code changes
4. Wait 10+ seconds
5. Call vulnzap_security_assistant_results
6. Review findings and fix issues
7. Call vulnzap_security_assistant_stop when done
```

## Configuration

### IDE MCP Configuration

#### Cursor IDE
File: `.cursor/mcp.json`
```json
{
  "mcpServers": {
    "VulnZap": {
      "command": "npx",
      "args": ["vulnzap", "mcp"],
      "env": {
        "VULNZAP_API_KEY": "your_api_key"
      }
    }
  }
}
```

#### Windsurf IDE
File: `.codeium/windsurf/mcp_config.json`
```json
{
  "mcpServers": {
    "VulnZap": {
      "command": "npx",
      "args": ["vulnzap", "mcp"],
      "env": {
        "VULNZAP_API_KEY": "your_api_key"
      }
    }
  }
}
```

#### Cline
Configured via `vulnzap connect --ide cline`. Manual configuration requires setting MCP server command to `npx vulnzap mcp` with `VULNZAP_API_KEY` environment variable.

### Environment Variables

- `VULNZAP_API_KEY`: Authentication key for API access
- `VULNZAP_DEBUG`: Enable debug logging for MCP server

### Cache Configuration

VulnZap maintains a local cache in `~/.vulnzap/` with the following structure:
- `cache/`: Vulnerability scan results (5-day TTL)
- `config/`: User configuration and API keys
- `logs/`: MCP server logs (when debug enabled)
- `client/sessions/`: Security assistant session data


## Project Structure

```
vulnzap/
├── src/
│   ├── api/                    # API integration layer
│   │   ├── auth.ts             # Authentication & OAuth
│   │   ├── batchScan.ts        # Batch scanning functionality
│   │   ├── repoScan.ts         # Repository scanning (jobs & SSE)
│   │   └── apis.ts             # API utilities
│   ├── config/                 # Configuration management
│   │   └── config.ts           # Application configuration
│   ├── services/               # Core services
│   │   └── cache.ts            # Caching service (5-day TTL)
│   ├── types/                  # TypeScript type definitions
│   │   └── response.ts         # API response types
│   ├── utils/                  # Utility functions
│   │   ├── packageExtractor.ts # Package file parsing
│   │   ├── apiClient.ts        # HTTP client wrapper
│   │   ├── checks.ts           # Project validation
│   │   ├── gitUtils.ts         # Git operations
│   │   └── mcpConfig.ts        # MCP configuration utilities
│   ├── mcp/                    # MCP server implementation
│   │   ├── server.ts           # MCP server entry & tool definitions
│   │   └── scanState.ts        # In-memory scan state management
│   ├── cli.ts                  # Command-line interface
│   └── tui.ts                  # Terminal UI components
├── tests/                      # Test suite
├── dist/                       # Compiled JavaScript output
├── package.json                # Project dependencies
├── tsconfig.json               # TypeScript configuration
└── README.md                   # Documentation
```

## Development

### Building from Source

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Development server with hot reload
npm run dev

# CLI in watch mode
npm run cli
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage

# Lint code
npm run lint

# Fix linting issues
npm run lint:fix
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/feature-name`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `npm test`
6. Commit your changes: `git commit -m 'Add feature'`
7. Push to the branch: `git push origin feature/feature-name`
8. Open a Pull Request

## Troubleshooting

### Authentication Issues

**Error: "API key not configured"**
```bash
# Solution: Configure API key
vulnzap setup -k your_api_key_here
```

### Server Connectivity

**Error: "VulnZap server is down"**
```bash
# Check server status
vulnzap status

# VulnZap automatically uses local cache in offline mode
```

### Package Detection

**Error: "No packages found to scan"**

Ensure your project contains supported package files:
- `package.json` (npm)
- `requirements.txt` (pip)
- `go.mod` (go)
- `Cargo.toml` (rust)
- `pom.xml` (maven)
- `build.gradle` (gradle)
- `composer.json` (composer)
- `*.csproj` (nuget)

### MCP Connection Issues

1. Verify IDE MCP configuration file exists
2. Check that `vulnzap` is in your PATH: `which vulnzap`
3. Restart your IDE after configuration changes
4. Verify API key is set in MCP configuration

### Debug Mode

```bash
# Enable verbose logging
VULNZAP_DEBUG=true vulnzap mcp

# Check MCP server logs
tail -f ~/.vulnzap/logs/mcp-server.log
```

## Technical Specifications

### Supported Ecosystems

| Ecosystem | Package File | Version Format |
|-----------|--------------|----------------|
| npm | package.json | semver |
| pip | requirements.txt | PEP 440 |
| go | go.mod | semver |
| rust | Cargo.toml | semver |
| maven | pom.xml | Maven versioning |
| gradle | build.gradle | Maven versioning |
| composer | composer.json | semver |
| nuget | *.csproj | semver |

### Cache Behavior

- **TTL**: 5 days
- **Location**: `~/.vulnzap/cache/`
- **Invalidation**: Automatic on expiry
- **Offline Mode**: Automatic fallback when API unavailable

### API Rate Limits

Rate limits vary by subscription tier:
- **Free**: 1,000 scans/month
- **Pro**: Unlimited scans
- **Enterprise**: Unlimited scans + priority support

## Security

### Vulnerability Reporting

To report security vulnerabilities, please email: security@plawlabs.com

Do not create public GitHub issues for security vulnerabilities.

### API Key Storage

API keys are stored securely using the system keychain:
- **macOS**: Keychain Access
- **Linux**: libsecret
- **Windows**: Credential Manager

## Support

- **Documentation**: [https://vulnzap.com/docs](https://vulnzap.com/docs)
- **Issues**: [GitHub Issues](https://github.com/vulnzap/vulnzap/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vulnzap/vulnzap/discussions)
- **Email**: support@plawlabs.com

## License

This project is licensed under the Business Source License 1.1 (BUSL-1.1) - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Model Context Protocol**: For enabling seamless AI integration
- **OWASP**: For security best practices and vulnerability guidelines
- **Security Community**: For vulnerability data and research
- **Open Source Contributors**: For making this project possible

---

**Developed by Plaw Inc**

*Securing the future of AI-generated code.*
 