/**
 * Vulnzap Core Configuration
 * 
 * This file contains the core configuration for the Vulnzap SaaS platform.
 * It includes settings for all supported ecosystems, API endpoints, and service configurations.
 */

import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Load environment variables
dotenv.config();

// ESM __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');

// Default configuration values
const DEFAULT_CONFIG = {
  // Server settings
  PORT: parseInt(process.env.PORT || '3000', 10),
  MCP_ENABLED: process.env.MCP_ENABLED !== 'false',
  API_ENABLED: process.env.API_ENABLED !== 'false',
  WEB_ENABLED: process.env.WEB_ENABLED !== 'false',
  
  // Service endpoints
  GITHUB_ADVISORY_URL: 'https://api.github.com/advisories',
  NVD_API_URL: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  
  // API keys
  GITHUB_TOKEN: process.env.GITHUB_TOKEN || '',
  NVD_API_KEY: process.env.NVD_API_KEY || '',
  PREMIUM_API_KEY: process.env.PREMIUM_API_KEY || 'secret123',
  
  // Cache settings
  CACHE_DIR: path.join(PROJECT_ROOT, 'cache'),
  DATA_DIR: path.join(PROJECT_ROOT, 'data'),
  
  // Refresh intervals
  GITHUB_REFRESH_INTERVAL: parseInt(process.env.GITHUB_REFRESH_INTERVAL || '86400000'), // 24 hours
  NVD_REFRESH_INTERVAL: parseInt(process.env.NVD_REFRESH_INTERVAL || '86400000'), // 24 hours
  
  // Rate limiting
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW || '3600000'), // 1 hour
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '1000'),
  
  // Database settings (for subscription/user management)
  DB_URI: process.env.DB_URI || 'sqlite://vulnzap.db',
  
  // Subscription tiers
  SUBSCRIPTION_TIERS: {
    FREE: {
      name: 'Free',
      rateLimitPerHour: 100,
      batchSize: 5,
      ecosystems: ['npm', 'pip']
    },
    BASIC: {
      name: 'Basic',
      rateLimitPerHour: 1000,
      batchSize: 50,
      ecosystems: ['npm', 'pip', 'go']
    },
    PRO: {
      name: 'Professional',
      rateLimitPerHour: 5000,
      batchSize: 200,
      ecosystems: ['npm', 'pip', 'go', 'cargo']
    },
    ENTERPRISE: {
      name: 'Enterprise',
      rateLimitPerHour: 20000,
      batchSize: 1000,
      ecosystems: ['npm', 'pip', 'go', 'cargo', 'maven', 'nuget', 'composer']
    }
  },
  
  // Supported ecosystems and their configurations
  ECOSYSTEMS: {
    npm: {
      name: 'npm',
      displayName: 'Node.js (npm)',
      versionParser: 'semver',
      packageManager: 'npm',
      installCommand: 'npm install {package}@{version}',
      updateCommand: 'npm update {package}',
      latestCommand: 'npm install {package}@latest',
      registryUrl: 'https://registry.npmjs.org/',
      searchUrl: 'https://registry.npmjs.org/-/v1/search?text={query}&size=20',
      packageUrl: 'https://www.npmjs.com/package/{package}',
      aliases: ['node', 'nodejs', 'javascript', 'js']
    },
    
    pip: {
      name: 'pip',
      displayName: 'Python (pip)',
      versionParser: 'pep440',
      packageManager: 'pip',
      installCommand: 'pip install {package}=={version}',
      updateCommand: 'pip install --upgrade {package}',
      latestCommand: 'pip install --upgrade {package}',
      registryUrl: 'https://pypi.org/pypi/',
      searchUrl: 'https://pypi.org/search/?q={query}',
      packageUrl: 'https://pypi.org/project/{package}/',
      aliases: ['python', 'pypi']
    },
    
    go: {
      name: 'go',
      displayName: 'Go (modules)',
      versionParser: 'semver',
      packageManager: 'go',
      installCommand: 'go get {package}@{version}',
      updateCommand: 'go get -u {package}',
      latestCommand: 'go get -u {package}',
      registryUrl: 'https://pkg.go.dev/',
      searchUrl: 'https://pkg.go.dev/search?q={query}',
      packageUrl: 'https://pkg.go.dev/{package}',
      aliases: ['golang']
    },
    
    cargo: {
      name: 'cargo',
      displayName: 'Rust (Cargo)',
      versionParser: 'semver',
      packageManager: 'cargo',
      installCommand: 'cargo add {package}@{version}',
      updateCommand: 'cargo update {package}',
      latestCommand: 'cargo add {package}',
      registryUrl: 'https://crates.io/',
      searchUrl: 'https://crates.io/search?q={query}',
      packageUrl: 'https://crates.io/crates/{package}',
      aliases: ['rust', 'crates', 'crates.io']
    },
    
    maven: {
      name: 'maven',
      displayName: 'Java (Maven)',
      versionParser: 'maven',
      packageManager: 'mvn',
      installCommand: 'mvn dependency:get -Dartifact={group}:{package}:{version}',
      updateCommand: 'mvn versions:use-latest-versions -Dincludes={group}:{package}',
      latestCommand: 'mvn dependency:get -Dartifact={group}:{package}:LATEST',
      registryUrl: 'https://search.maven.org/',
      searchUrl: 'https://search.maven.org/search?q={query}',
      packageUrl: 'https://search.maven.org/artifact/{group}/{package}',
      aliases: ['java', 'gradle']
    },
    
    nuget: {
      name: 'nuget',
      displayName: '.NET (NuGet)',
      versionParser: 'semver',
      packageManager: 'dotnet',
      installCommand: 'dotnet add package {package} --version {version}',
      updateCommand: 'dotnet add package {package}',
      latestCommand: 'dotnet add package {package}',
      registryUrl: 'https://api.nuget.org/v3/index.json',
      searchUrl: 'https://www.nuget.org/packages?q={query}',
      packageUrl: 'https://www.nuget.org/packages/{package}',
      aliases: ['dotnet', 'csharp', 'cs', 'fsharp', 'fs', 'visualbasic', 'vb']
    },
    
    composer: {
      name: 'composer',
      displayName: 'PHP (Composer)',
      versionParser: 'semver',
      packageManager: 'composer',
      installCommand: 'composer require {package}:{version}',
      updateCommand: 'composer update {package}',
      latestCommand: 'composer require {package}',
      registryUrl: 'https://packagist.org/',
      searchUrl: 'https://packagist.org/search/?q={query}',
      packageUrl: 'https://packagist.org/packages/{package}',
      aliases: ['php', 'packagist']
    }
  },
  
  // Default enabled ecosystems (can be overridden by env vars)
  ENABLED_ECOSYSTEMS: (process.env.ENABLED_ECOSYSTEMS || 'npm,pip,go').split(',')
    .map(eco => eco.trim())
    .filter(Boolean)
};

/**
 * Build the final configuration, merging environment variables and defaults
 */
function buildConfig() {
  const config = { ...DEFAULT_CONFIG };
  
  // Filter to only enabled ecosystems
  config.SUPPORTED_ECOSYSTEMS = config.ENABLED_ECOSYSTEMS
    .filter(eco => config.ECOSYSTEMS[eco])
    .map(eco => config.ECOSYSTEMS[eco]);
  
  // Convert to a map for faster lookups
  config.ECOSYSTEM_MAP = new Map(
    config.SUPPORTED_ECOSYSTEMS.map(eco => [eco.name, eco])
  );
  
  // Add ecosystem aliases for faster lookups
  config.ECOSYSTEM_ALIASES = new Map();
  config.SUPPORTED_ECOSYSTEMS.forEach(eco => {
    eco.aliases.forEach(alias => {
      config.ECOSYSTEM_ALIASES.set(alias, eco.name);
    });
    // Add the main name as an alias to itself for consistency
    config.ECOSYSTEM_ALIASES.set(eco.name, eco.name);
  });
  
  return config;
}

// Export the final configuration
const CONFIG = buildConfig();
export default CONFIG; 