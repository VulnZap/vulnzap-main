# VulnZap

<div align="center">
  <img src="https://github.com/vulnzap/vulnzap/raw/main/assets/logo.png" alt="VulnZap Logo" width="120" height="120">
  <h3>The Missing Security Layer for AI-Generated Code</h3>
  <p>Intercept vulnerabilities between AI-powered IDE suggestions and your codebase</p>

  [![npm version](https://img.shields.io/npm/v/vulnzap.svg?style=flat-square)](https://www.npmjs.org/package/vulnzap)
  [![Downloads](https://img.shields.io/npm/dm/vulnzap.svg?style=flat-square)](https://npmjs.org/package/vulnzap)
  [![License](https://img.shields.io/github/license/vulnzap/vulnzap.svg?style=flat-square)](https://github.com/vulnzap/vulnzap)
</div>

## Why VulnZap?

As AI coding assistants generate more of your codebase, they introduce dependencies without proper security vetting. VulnZap creates a security layer between your AI-powered IDE and your codebase, catching vulnerabilities before they become part of your project.

- **MCP Security Bridge**: Intercept vulnerabilities between AI-powered IDE suggestions and your codebase
- **AI Vulnerability Detection**: Catch vulnerabilities in AI-generated code in real-time
- **Real-Time Protection**: Secure your codebase as you write, not after deployment
- **Enterprise Integration**: Compatible with Cursor, Claude Code, Windsurf and other AI-powered editors

## Installation

```bash
npm install -g vulnzap
```

## Quick Start

1. **Create an account or log in**

```bash
vulnzap login
```

2. **Connect to your IDE**

```bash
vulnzap connect --ide cursor
```

3. **Start the security bridge**

```bash
vulnzap secure
```

4. **Code with confidence** - VulnZap will automatically scan for vulnerabilities in AI-generated code

## Documentation

### Authentication Commands

VulnZap supports multiple authentication methods for a seamless user experience:

#### `vulnzap login`

Log in to your VulnZap account.

```bash
vulnzap login [options]
```

Options:
- `--method <method>` - Authentication method: email, magic, google, github (default: "email")
- `--email <email>` - Email address for login

Examples:
```bash
vulnzap login                           # Interactive login
vulnzap login --method email --email user@example.com
vulnzap login --method magic --email user@example.com
vulnzap login --method google           # Opens browser for OAuth
vulnzap login --method github           # Opens browser for OAuth
```

#### `vulnzap logout`

Log out from your VulnZap account.

```bash
vulnzap logout
```

#### `vulnzap signup`

Sign up for a new VulnZap account and subscribe to premium features.

```bash
vulnzap signup
```

#### `vulnzap account`

View and manage your VulnZap account settings and subscription.

```bash
vulnzap account
```

#### `vulnzap upgrade`

Upgrade your account to a premium tier.

```bash
vulnzap upgrade
```

### Security Commands

#### `vulnzap secure`

Start the MCP security bridge to protect your AI coding.

```bash
vulnzap secure [options]
```

Options:
- `--mcp` - Use Model Context Protocol for IDE integration
- `--ide <ide-name>` - Specify IDE integration (cursor, claude-code, windsurf)
- `--port <port>` - Port to use for MCP server (default: 3456)
- `--api-key <key>` - Premium API key for enhanced features

#### `vulnzap check`

Check a package for vulnerabilities.

```bash
vulnzap check <package> [options]
```

Options:
- `-e, --ecosystem <ecosystem>` - Package ecosystem (npm, pip) (default: "npm")
- `-v, --version <version>` - Package version

Examples:
```bash
vulnzap check express@4.17.1
vulnzap check lodash --version 4.17.15 --ecosystem npm
```

#### `vulnzap connect`

Connect VulnZap to your AI-powered IDE.

```bash
vulnzap connect [options]
```

Options:
- `--ide <ide-name>` - IDE to connect with (cursor, claude-code, windsurf)

#### `vulnzap batch`

Batch scan multiple packages for vulnerabilities (Premium feature).

```bash
vulnzap batch [options]
```

Options:
- `-f, --file <file>` - Path to JSON file with packages to scan
- `-o, --output <file>` - Output file for results
- `--api-key <key>` - Premium API key (required for batch scanning)

## Account Management

VulnZap offers a comprehensive account management system with Stripe integration for subscriptions:

### Authentication Options

- **Email/Password**: Traditional authentication
- **Magic Link**: Passwordless email authentication
- **Google OAuth**: Log in with your Google account
- **GitHub OAuth**: Log in with your GitHub account

### Subscription Tiers

VulnZap is open-core, with a free tier that provides essential protection. For teams and organizations that need enhanced security, we offer premium plans:

#### Free Tier
- Basic vulnerability scanning
- MCP server integration
- GitHub Advisory Database
- Community support
- 50 scans per day limit

#### Pro Tier ($9/mo)
- Everything in Free tier
- Zero-day vulnerability alerts
- AI-generated code analysis
- Unlimited vulnerability scanning
- Priority fixes and updates
- Enterprise audit logs
- 1,000 scans per day

#### Enterprise Tier ($19/user/mo)
- Everything in Pro tier
- 24/7 dedicated support
- Custom security policies
- SOC2 compliance reporting
- Automated remediation
- Private vulnerability database
- 10,000 scans per day

### Subscription Management

Manage your subscription with the following commands:

```bash
vulnzap account    # View account details and subscription status
vulnzap upgrade    # Upgrade to a premium tier
```

## MCP Integration

VulnZap seamlessly integrates with AI assistants through the Model Context Protocol (MCP). This creates a security layer that:

1. Intercepts code snippets suggested by your AI assistant
2. Scans them for known vulnerabilities and security issues
3. Warns about potential issues directly in your IDE
4. Suggests secure alternatives when vulnerabilities are detected

To use VulnZap's MCP integration, simply run:

```bash
vulnzap secure --mcp --ide cursor
```

## Environment Variables

Create a `.env` file in your project root with these variables (see `.env.example`):

- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_ANON_KEY` - Supabase anonymous key
- `SUPABASE_SERVICE_KEY` - Supabase service role key
- `STRIPE_PUBLIC_KEY` - Stripe publishable key
- `STRIPE_SECRET_KEY` - Stripe secret key
- `STRIPE_WEBHOOK_SECRET` - Stripe webhook signing secret
- `NVD_API_KEY` - National Vulnerability Database API key
- `VULNZAP_API_KEY` - Your VulnZap premium API key

## Self-Hosting

VulnZap can be self-hosted for enterprise deployments:

1. Clone the repository
```bash
git clone https://github.com/vulnzap/vulnzap.git
cd vulnzap
```

2. Install dependencies
```bash
npm install
```

3. Set up environment variables (copy from `.env.example`)
```bash
cp .env.example .env
# Edit .env with your configuration values
```

4. Initialize the database
```bash
npm run db:seed
```

5. Build and start the server
```bash
npm run build
npm start
```

## How It Works

VulnZap runs as an MCP server that bridges your AI coding assistant with enterprise-grade security scanning:

1. **Connect**: VulnZap connects to your AI-powered IDE through the Model Context Protocol
2. **Intercept**: When your AI assistant suggests code, VulnZap intercepts it
3. **Scan**: The code is scanned for known vulnerabilities and security issues
4. **Protect**: If vulnerabilities are found, VulnZap alerts you and suggests secure alternatives

## Contributing

We welcome contributions to VulnZap! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read our [Contributing Guide](CONTRIBUTING.md) for more details.

## License

VulnZap is MIT licensed. See [LICENSE](LICENSE) for details.

## Security

If you discover a security vulnerability within VulnZap, please send an email to security@vulnzap.dev.

## Support

- Documentation: [https://docs.vulnzap.dev](https://docs.vulnzap.dev)
- Discord: [Join our community](https://discord.gg/vulnzap)
- GitHub Issues: [Report bugs](https://github.com/vulnzap/vulnzap/issues)
- Email: support@vulnzap.dev 