# VulnZap 🔒

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.2.2-blue)](https://www.typescriptlang.org/)
[![MCP Protocol](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple)](https://modelcontextprotocol.io/)

**The Missing Security Layer for AI-Generated Code**

VulnZap is a real-time vulnerability scanning tool that integrates seamlessly with AI-powered IDEs like Cursor, Cline, and Windsurf. It automatically intercepts package installation commands and scans for known vulnerabilities before they enter your codebase, ensuring your AI-generated code remains secure.

## 🚀 Features

### Core Security Features
- **Real-time Vulnerability Scanning**: Automatically scans packages before installation
- **Multi-Ecosystem Support**: npm, pip, go, rust, maven, gradle, composer, nuget, pypi
- **MCP Protocol Integration**: Native support for Model Context Protocol
- **Smart Caching**: 5-day cache with automatic invalidation for performance
- **Offline Mode**: Local vulnerability database fallback when API is unavailable

### AI-Enhanced Features
- **Amplified Security Prompts**: Transform feature requests into security-hardened implementations
- **Smart Documentation**: Context-aware package documentation and security guidelines  
- **Latest Toolset Recommendations**: Up-to-date package recommendations with security scoring
- **OWASP Top 10 Compliance**: Built-in security guidance following OWASP standards

### IDE Integrations
- **Cursor IDE**: Native MCP server integration
- **Cline (Claude Dev)**: Full compatibility with Claude-based development
- **Windsurf IDE**: Seamless integration with Codeium's AI IDE
- **Generic MCP Support**: Compatible with any MCP-enabled environment

## 📦 Installation

### Prerequisites
- Node.js 16.0.0 or higher
- npm or yarn package manager

### Global Installation
```bash
npm install -g vulnzap
```

### From Source
```bash
git clone https://github.com/vulnzap/vulnzap.git
cd vulnzap
npm install
npm run build
npm link
```

## 🛠️ Quick Start

### 1. Setup API Key
```bash
# Configure your API key (get it from https://vulnzap.com/dashboard/api-keys)
vulnzap setup -k <your-api-key>

# Setup API key with IDE connection in one step
vulnzap setup -k <your-api-key> --ide cursor
vulnzap setup -k <your-api-key> --ide windsurf
vulnzap setup -k <your-api-key> --ide cline
```

### 2. Connect to Your IDE (if not done in step 1)
```bash
# Connect to Cursor IDE
vulnzap connect --ide cursor

# Connect to Windsurf IDE  
vulnzap connect --ide windsurf

# Connect to Cline
vulnzap connect --ide cline
```

### 3. Start Scanning
Once connected, VulnZap automatically scans packages when your AI assistant tries to install them.

## 🔧 CLI Commands

### Setup & Configuration
```bash
# Setup API key
vulnzap setup -k <api-key>

# Setup API key and connect to IDE in one step
vulnzap setup -k <api-key> --ide <cursor|windsurf|cline>

# Check account information
vulnzap account
```

### Project Management
```bash
# Check server status
vulnzap status

# View help
vulnzap help
```

### Security Scanning
```bash
# Check individual package
vulnzap check <ecosystem:package@version>
vulnzap check npm:express@4.17.1
vulnzap check pip:requests@2.25.1

# Alternative syntax
vulnzap check <package> --ecosystem <eco> --version <ver>
vulnzap check express --ecosystem npm --version 4.17.1

# Batch scan current directory
vulnzap batch-scan [--ecosystem <ecosystem>] [--output <file>]

# Options
--cache, -C     Use cached results
--ai, -A        Use AI for vulnerability summaries
```

### IDE Integration
```bash
# Connect to IDE (sets up MCP configuration)
vulnzap connect [--ide cursor|cline|windsurf]

# Start MCP server manually (for debugging)
vulnzap secure [--ide <ide>] [--port <port>]
```

## 🔌 MCP Tools Reference

VulnZap provides several Model Context Protocol tools that integrate with your AI assistant:

### 1. auto-vulnerability-scan
**Purpose**: Automatically scans packages before installation
**Usage**: Called automatically when AI suggests package installation
```json
{
  "command": "npm install",
  "ecosystem": "npm", 
  "packageName": "express",
  "version": "4.17.1"
}
```

### 2. batch-scan
**Purpose**: Scans all packages in a directory
**Parameters**:
- `directory`: Full path to scan
- `ecosystem` (optional): Specific ecosystem filter

### 3. amplify-feature-prompt
**Purpose**: Enhances feature requests with security best practices
**Parameters**:
- `user_prompt`: The feature request
- `project_type`: web_app, api, cli, library, etc.
- `security_level`: high, medium, low
- `tech_stack`: Array of technologies
- `compliance_requirements`: GDPR, SOX, etc.

### 4. get_docs
**Purpose**: Retrieves security-focused documentation
**Parameters**:
- `package_name`: Package to document
- `skill_level`: beginner, intermediate, advanced
- `project_context`: Context for documentation
- `learning_goals`: Array of learning objectives

### 5. latest_toolset
**Purpose**: Recommends up-to-date, secure packages
**Parameters**:
- `user_prompt`: Project description
- `user_tools`: User's preferred tools
- `agent_tools`: AI's suggested tools
- `security_requirements`: Include security features
- `performance_requirements`: Include performance optimizations

## 📂 Project Structure

```
vulnzap/
├── src/
│   ├── api/                 # API integration layer
│   │   ├── auth.ts         # Authentication & OAuth
│   │   ├── batchScan.ts    # Batch scanning functionality
│   │   └── apis.ts         # API utilities
│   ├── config/             # Configuration management
│   │   └── config.ts       # App configuration
│   ├── services/           # Core services
│   │   └── cache.ts        # Caching service
│   ├── types/              # TypeScript definitions
│   │   └── response.ts     # API response types
│   ├── utils/              # Utility functions
│   │   ├── packageExtractor.ts  # Package file parsing
│   │   ├── apiClient.ts    # HTTP client wrapper
│   │   └── checks.ts       # Project validation
│   ├── cli.ts              # Command-line interface
│   └── index.ts            # MCP server implementation
├── tests/                  # Test suite
├── dist/                   # Compiled JavaScript
├── package.json            # Project dependencies
├── tsconfig.json           # TypeScript configuration
└── README.md              # This file
```

## 🔒 Security Features

### OWASP Top 10 Coverage
VulnZap automatically checks for and provides guidance on:
- **A01:2021 – Broken Access Control**
- **A02:2021 – Cryptographic Failures**  
- **A03:2021 – Injection**
- **A04:2021 – Insecure Design**
- **A05:2021 – Security Misconfiguration**
- **A06:2021 – Vulnerable and Outdated Components**
- **A07:2021 – Identification and Authentication Failures**
- **A08:2021 – Software and Data Integrity Failures**
- **A09:2021 – Security Logging and Monitoring Failures**
- **A10:2021 – Server-Side Request Forgery (SSRF)**

### Vulnerability Data Sources
- **GitHub Security Advisory Database**
- **National Vulnerability Database (NVD)**
- **OSV Database**
- **Local vulnerability database**

### Security Best Practices
- Secure credential storage using system keychain
- Encrypted API communications
- Local caching with TTL expiration
- Offline mode for air-gapped environments

## 🏗️ Architecture

### MCP Server Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI Assistant  │◄──►│   MCP Server    │◄──►│   VulnZap API   │
│   (Cursor/etc)  │    │   (Local)       │    │   (Remote)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Local Cache    │
                       │  (5-day TTL)    │
                       └─────────────────┘
```

### Package Detection Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Package Install │───►│   Extraction    │───►│  Vulnerability  │
│   Command       │    │   & Parsing     │    │    Scanning     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │ Supported Files │
                       │ • package.json  │
                       │ • requirements  │
                       │ • go.mod        │
                       │ • Cargo.toml    │
                       │ • pom.xml       │
                       │ • *.csproj      │
                       │ • build.gradle  │
                       │ • composer.json │
                       └─────────────────┘
```

## 🔧 Configuration

### Environment Variables
```bash
# Required
VULNZAP_API_KEY=your_api_key_here

# Server configuration
VULNZAP_SERVER_URL=https://api.vulnzap.com  # Override default server
```

### IDE Configuration Files

#### Cursor (.cursor/mcp.json)
```json
{
  "mcpServers": {
    "VulnZap": {
      "command": "vulnzap",
      "args": ["secure", "--ide", "cursor"],
      "env": {
        "VULNZAP_API_KEY": "your_api_key"
      }
    }
  }
}
```

#### Windsurf (.codeium/windsurf/mcp_config.json)
```json
{
  "mcpServers": {
    "VulnZap": {
      "command": "vulnzap",
      "args": ["secure", "--ide", "windsurf"],
      "env": {
        "VULNZAP_API_KEY": "your_api_key"
      }
    }
  }
}
```

## 🧪 Testing

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

## 📈 Performance

### Caching Strategy
- **Local Cache**: 5-day TTL for vulnerability data
- **Memory Cache**: In-memory caching for session data
- **Smart Invalidation**: Automatic cache refresh on stale data

### Response Times
- **Cached Results**: < 50ms
- **API Calls**: 200-500ms (depending on network)
- **Batch Scans**: ~100ms per package (parallelized)

### Resource Usage
- **Memory**: ~50MB base usage
- **Disk**: ~10MB cache directory
- **Network**: Minimal (only when cache misses)

## 🔄 Development Workflow

### Building from Source
```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Start development server with hot reload
npm run dev

# Start CLI in watch mode
npm run cli
```

### Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `npm test`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

## 📚 API Reference

### Core Functions

#### checkVulnerability(ecosystem, packageName, version, options)
Scans a single package for vulnerabilities.
```typescript
const result = await checkVulnerability('npm', 'express', '4.17.1', {
  useCache: true,
  useAi: false
});
```

#### checkBatch(packages)
Scans multiple packages in parallel.
```typescript
const results = await checkBatch([
  { packageName: 'express', ecosystem: 'npm', version: '4.17.1' },
  { packageName: 'requests', ecosystem: 'pip', version: '2.25.1' }
]);
```

#### extractPackagesFromDirectory(dirPath, ecosystem?)
Extracts package information from project files.
```typescript
const packages = extractPackagesFromDirectory('./my-project', 'npm');
```

## 🌐 Ecosystem Support

| Ecosystem | File Types | Status |
|-----------|------------|---------|
| **npm** | package.json | ✅ Full |
| **pip** | requirements.txt, setup.py | ✅ Full |
| **go** | go.mod | ✅ Full |
| **rust** | Cargo.toml | ✅ Full |
| **maven** | pom.xml | ✅ Full |
| **gradle** | build.gradle | ✅ Full |
| **nuget** | *.csproj, packages.config | ✅ Full |
| **composer** | composer.json | ✅ Full |

## 🐛 Troubleshooting

### Common Issues

#### "API key not configured"
```bash
# Solution: Set up your API key
vulnzap setup -k your_api_key_here
```

#### "VulnZap server is down"
```bash
# Check server status
vulnzap status

# VulnZap will automatically use local cache in offline mode
```

#### "No packages found to scan"
Make sure your project contains supported package files:
- `package.json` (npm)
- `requirements.txt` (pip)
- `go.mod` (go)
- `Cargo.toml` (rust)
- etc.

#### MCP Connection Issues
1. Verify IDE MCP configuration
2. Check that vulnzap is in your PATH
3. Restart your IDE after configuration changes

### Debug Mode
```bash
# Enable verbose logging
VULNZAP_DEBUG=true vulnzap secure --ide cursor

# Check MCP server logs
tail -f ~/.vulnzap/logs/mcp-server.log
```

## 📞 Support

- **Documentation**: [https://vulnzap.com/docs](https://vulnzap.com/docs)
- **Issues**: [GitHub Issues](https://github.com/vulnzap/vulnzap/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vulnzap/vulnzap/discussions)
- **Email**: support@plawlabs.com

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Model Context Protocol**: For enabling seamless AI integration
- **OWASP**: For security best practices and vulnerability guidelines
- **Security Community**: For vulnerability data and research
- **Open Source Contributors**: For making this project possible

## 🔮 Roadmap

### Upcoming Features
- [ ] Real-time CI/CD pipeline integration
- [ ] IDE vulnerability highlighting  
- [ ] Custom vulnerability rules
- [ ] SBOM generation and analysis
- [ ] Compliance reporting (SOC2, ISO 27001)
- [ ] Advanced threat modeling
- [ ] Container image scanning
- [ ] Infrastructure as Code scanning

### Planned Integrations
- [ ] VS Code extension
- [ ] JetBrains plugin
- [ ] GitHub Actions integration
- [ ] Jenkins plugin
- [ ] GitLab CI integration

---

**Made with ❤️ by the PlawLabs Team**

*Securing the future of AI-generated code, one package at a time.* 