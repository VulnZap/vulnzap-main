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
- **Cursor IDE**: Full MCP integration + automatic extension installation
- **VS Code**: Extension-only integration (no MCP required)
- **Windsurf IDE**: Full MCP integration + automatic extension installation
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

### 1. Complete Setup (Recommended)
```bash
# Complete onboarding with API key setup and IDE integration
npx vulnzap init
```

This command will:
- Guide you through API key setup
- Automatically detect installed IDEs (VSCode, Cursor, Windsurf)
- Allow you to select multiple IDEs for integration
- Configure MCP settings and install extensions
- Set up your development environment for secure coding

### 2. Manual Setup (Alternative)
```bash
# Setup API key only
vulnzap setup -k <your-api-key>

# Setup API key with specific IDE
vulnzap setup -k <your-api-key> --ide cursor
```

### 3. Start Scanning
Once connected, VulnZap automatically scans packages when your AI assistant tries to install them.

## 🔧 CLI Commands

### Setup & Configuration
```bash
# Complete setup with guided onboarding (recommended)
vulnzap init

# Setup API key only
vulnzap setup -k <api-key>

# Setup API key with specific IDE
vulnzap setup -k <api-key> --ide <cursor|vscode|windsurf>

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
# Connect to specific IDE (alternative to init/setup)
vulnzap connect [--ide cursor|vscode|windsurf]

# Start MCP server manually (for debugging)
vulnzap secure [--ide <ide>] [--port <port>]
```

#### Supported IDEs
- **Cursor IDE**: Full MCP integration + extension
- **VS Code**: Extension only (no MCP)
- **Windsurf IDE**: Full MCP integration + extension

#### Automatic IDE Detection
The `init` command automatically detects which of the supported IDEs are installed on your system and allows you to select multiple IDEs for integration.

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

---

**Made with ❤️ by the PlawLabs Team**

*Securing the future of AI-generated code.* 