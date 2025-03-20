#!/usr/bin/env node

/**
 * VulnZap MCP - Standalone Server
 * 
 * This is a self-contained implementation of the VulnZap MCP server
 * that doesn't rely on dynamic imports to avoid path resolution issues.
 */

// Standard Node.js imports
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import semver from 'semver';
import dotenv from 'dotenv';

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

// Display help if requested
if (flags.help || flags.h) {
  console.log(`
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
  `);
  process.exit(0);
}

// Get package info
const require = createRequire(import.meta.url);
const packageJson = require('./package.json');

// Display version if requested
if (flags.version || flags.v) {
  console.log(`VulnZap MCP v${packageJson.version}`);
  process.exit(0);
}

// Set environment variables based on CLI flags
if (flags['nvd-key']) {
  process.env.NVD_API_KEY = flags['nvd-key'];
  process.env.USE_NVD = 'true';
  console.log('NVD integration enabled');
}

if (flags['github-token']) {
  process.env.GITHUB_TOKEN = flags['github-token'];
  console.log('GitHub Advisory Database integration enabled');
}

if (flags['data-path']) {
  process.env.DATA_PATH = flags['data-path'];
}

if (flags['premium-key']) {
  process.env.PREMIUM_API_KEY = flags['premium-key'];
}

if (flags.port) {
  process.env.PORT = flags.port;
}

// Load configuration from .env file
dotenv.config();

// Import MCP SDK directly
const sdkPath = require.resolve('@modelcontextprotocol/sdk/package.json');
const sdkDir = path.dirname(sdkPath);

// Import custom modules
import { initNvdClient, checkNvdVulnerability } from './nvd-client.js';
import { initGithubClient, checkGithubVulnerability, fetchAllAdvisories } from './github-client.js';

// Get __dirname equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const CONFIG = {
  PREMIUM_API_KEY: process.env.PREMIUM_API_KEY || 'test123',
  SUPPORTED_ECOSYSTEMS: [
    'npm', 'pip', 'gem', 'cargo', 'composer', 'go', 'maven', 'nuget', 
    'debian', 'ubuntu', 'alpine', 'centos', 'rhel', 'pypi'
  ],
  DATA_PATH: process.env.DATA_PATH || path.join(__dirname, 'data', 'advisories.json'),
  DATA_REFRESH_INTERVAL: parseInt(process.env.GITHUB_REFRESH_INTERVAL || '86400000'), // 24 hours in milliseconds
  USE_NVD: process.env.USE_NVD === 'true' || process.env.USE_NVD === '"true"',
  PREMIUM_FEATURES: {
    batchScan: true,
    detailedReport: true
  }
};

// Verify environment variables loaded correctly
console.log(`Environment loaded - NVD API Key: ${process.env.NVD_API_KEY ? 'Yes (hidden)' : 'No'}`);
console.log(`Environment loaded - GitHub Token: ${process.env.GITHUB_TOKEN ? 'Yes (hidden)' : 'No'}`);
console.log(`Environment loaded - USE_NVD: ${process.env.USE_NVD}`);

// Vulnerability database
let vulnerabilityDatabase = new Map();
let nvdConfig = null;
let githubConfig = null;

/**
 * Load vulnerability data from the GitHub Advisory Database file
 */
function loadVulnerabilityData() {
  try {
    if (!fs.existsSync(CONFIG.DATA_PATH)) {
      console.error(`Advisory data file not found at ${CONFIG.DATA_PATH}`);
      return false;
    }

    const data = JSON.parse(fs.readFileSync(CONFIG.DATA_PATH, 'utf8'));
    
    if (!data || !data.advisories || !Array.isArray(data.advisories)) {
      console.error('Invalid advisory data format');
      return false;
    }

    // Clear existing data
    vulnerabilityDatabase.clear();
    
    // Process each advisory
    data.advisories.forEach(advisory => {
      const { ecosystem, package: packageName, vulnerable_versions } = advisory;
      
      // Skip if missing required fields
      if (!ecosystem || !packageName || !vulnerable_versions) return;
      
      const key = `${ecosystem}:${packageName}`;
      
      // If this package already has vulnerabilities, append this one
      if (vulnerabilityDatabase.has(key)) {
        vulnerabilityDatabase.get(key).push({
          ...advisory,
          vulnerable_versions,
          source: 'local'
        });
      } else {
        // Otherwise create a new entry
        vulnerabilityDatabase.set(key, [{
          ...advisory,
          vulnerable_versions,
          source: 'local'
        }]);
      }
    });
    
    console.log(`Loaded ${vulnerabilityDatabase.size} package vulnerability records from GitHub Advisory Database`);
    console.log(`Last updated: ${data.last_updated || 'unknown'}`);
    return true;
  } catch (error) {
    console.error(`Error loading vulnerability data: ${error.message}`);
    return false;
  }
}

/**
 * Check if a pip package version is vulnerable based on version ranges
 */
function isPipVersionVulnerable(version, range) {
  // For pip, we'll implement a simplified version comparison
  // This handles basic ranges like "<=2.25.0", ">=2.25.1", "<1.1.3,>=1.0"
  
  if (!version || !range) return false;
  
  // Split the range into parts (handles multiple constraints)
  const rangeParts = range.split(',');
  
  for (const part of rangeParts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    
    // Extract operator and version
    const operator = trimmed.substring(0, 2);
    const rangeVersion = trimmed.substring(2);
    
    // Split versions into components
    const versionParts = version.split('.').map(Number);
    const rangeParts = rangeVersion.split('.').map(Number);
    
    // Pad arrays to equal length
    while (versionParts.length < rangeParts.length) versionParts.push(0);
    while (rangeParts.length < versionParts.length) rangeParts.push(0);
    
    // Compare version components
    let comparison = 0;
    for (let i = 0; i < versionParts.length; i++) {
      if (versionParts[i] > rangeParts[i]) {
        comparison = 1;
        break;
      } else if (versionParts[i] < rangeParts[i]) {
        comparison = -1;
        break;
      }
    }
    
    // Check if version satisfies this part of the range
    if (operator === '<=') {
      if (comparison > 0) return false;
    } else if (operator === '>=') {
      if (comparison < 0) return false;
    } else if (operator === '==') {
      if (comparison !== 0) return false;
    } else if (operator === '!=') {
      if (comparison === 0) return false;
    } else if (operator.startsWith('<') && !operator.includes('=')) {
      if (comparison >= 0) return false;
    } else if (operator.startsWith('>') && !operator.includes('=')) {
      if (comparison <= 0) return false;
    }
  }
  
  // If all range constraints are satisfied, the version is vulnerable
  return true;
}

/**
 * Check if a package version is vulnerable using local database
 */
function checkLocalVulnerability(ecosystem, packageName, packageVersion) {
  // Validate ecosystem
  if (!CONFIG.SUPPORTED_ECOSYSTEMS.includes(ecosystem)) {
    return { 
      isVulnerable: false, 
      error: `Unsupported ecosystem: ${ecosystem}. Supported ecosystems are: ${CONFIG.SUPPORTED_ECOSYSTEMS.join(', ')}` 
    };
  }
  
  // Format the key for lookup
  const key = `${ecosystem}:${packageName}`;
  const advisories = vulnerabilityDatabase.get(key);
  
  // If package not found in database
  if (!advisories || advisories.length === 0) {
    return { 
      isVulnerable: false, 
      isUnknown: true,
      message: `Package ${packageName} (${ecosystem}) not found in local vulnerability database` 
    };
  }
  
  // Validate version format
  if (ecosystem === 'npm' && !semver.valid(packageVersion)) {
    return { 
      isVulnerable: false, 
      error: `Invalid npm version format: ${packageVersion}. Expected semver format (e.g., 1.2.3)` 
    };
  }
  
  // Find matching vulnerabilities
  const matchingAdvisories = advisories.filter(advisory => {
    if (ecosystem === 'npm') {
      return semver.satisfies(packageVersion, advisory.vulnerable_versions);
    } else if (ecosystem === 'pip') {
      return isPipVersionVulnerable(packageVersion, advisory.vulnerable_versions);
    }
    return false;
  });

  if (matchingAdvisories.length > 0) {
    // Package is vulnerable
    return { 
      isVulnerable: true, 
      advisories: matchingAdvisories,
      source: 'local',
      message: `${packageName}@${packageVersion} (${ecosystem}) has ${matchingAdvisories.length} known vulnerabilities` 
    };
  }
  
  // Package is safe
  return { 
    isVulnerable: false, 
    source: 'local',
    message: `${packageName}@${packageVersion} (${ecosystem}) has no known vulnerabilities in local database` 
  };
}

/**
 * Comprehensive vulnerability check using all available sources
 */
async function checkVulnerability(ecosystem, packageName, packageVersion) {
  // Validate ecosystem
  if (!CONFIG.SUPPORTED_ECOSYSTEMS.includes(ecosystem)) {
    return { 
      isVulnerable: false, 
      error: `Unsupported ecosystem: ${ecosystem}. Supported ecosystems are: ${CONFIG.SUPPORTED_ECOSYSTEMS.join(', ')}` 
    };
  }
  
  // First check local database
  const localResult = checkLocalVulnerability(ecosystem, packageName, packageVersion);
  
  // If we have an error, return it immediately
  if (localResult.error) {
    return localResult;
  }
  
  // Initialize results array
  let allAdvisories = localResult.advisories || [];
  const sources = localResult.source ? [localResult.source] : [];
  
  // Check GitHub API if enabled
  if (githubConfig) {
    try {
      const githubResult = await checkGithubVulnerability(ecosystem, packageName, packageVersion, githubConfig);
      
      if (githubResult.vulnerabilities && githubResult.vulnerabilities.length > 0) {
        allAdvisories = [...allAdvisories, ...githubResult.vulnerabilities];
        sources.push(githubResult.source);
      }
    } catch (error) {
      console.error(`Error checking GitHub vulnerability: ${error.message}`);
    }
  }
  
  // Check NVD if enabled
  if (CONFIG.USE_NVD && nvdConfig) {
    try {
      const nvdResult = await checkNvdVulnerability(ecosystem, packageName, packageVersion, nvdConfig);
      
      if (nvdResult.vulnerabilities && nvdResult.vulnerabilities.length > 0) {
        allAdvisories = [...allAdvisories, ...nvdResult.vulnerabilities];
        sources.push(nvdResult.source);
      }
    } catch (error) {
      console.error(`Error checking NVD vulnerability: ${error.message}`);
    }
  }
  
  // Deduplicate advisories based on CVE ID
  const advisoriesMap = new Map();
  allAdvisories.forEach(adv => {
    const key = adv.cve_id || adv.id;
    if (!advisoriesMap.has(key)) {
      advisoriesMap.set(key, adv);
    }
  });
  
  const uniqueAdvisories = Array.from(advisoriesMap.values());
  
  // Return comprehensive result
  if (uniqueAdvisories.length > 0) {
    return {
      isVulnerable: true,
      advisories: uniqueAdvisories,
      sources: Array.from(new Set(sources)),
      message: `${packageName}@${packageVersion} (${ecosystem}) has ${uniqueAdvisories.length} known vulnerabilities across ${sources.length} sources`
    };
  } else if (localResult.isUnknown && sources.length <= 1) {
    return {
      isVulnerable: false,
      isUnknown: true,
      sources: Array.from(new Set(sources)),
      message: `Package ${packageName} (${ecosystem}) not found in any vulnerability database`
    };
  } else {
    return {
      isVulnerable: false,
      sources: Array.from(new Set(sources)),
      message: `${packageName}@${packageVersion} (${ecosystem}) has no known vulnerabilities`
    };
  }
}

/**
 * Refresh the vulnerability database from GitHub API
 */
async function refreshVulnerabilityDatabase() {
  if (!githubConfig || !githubConfig.githubToken) {
    console.warn('GitHub token not provided. Skipping database refresh.');
    return;
  }
  
  console.log('Refreshing vulnerability database from GitHub API...');
  
  try {
    const count = await fetchAllAdvisories(githubConfig, CONFIG.DATA_PATH);
    console.log(`Updated vulnerability database with ${count} advisories`);
    
    // Reload the data
    loadVulnerabilityData();
  } catch (error) {
    console.error(`Error refreshing vulnerability database: ${error.message}`);
  }
}

// Start the MCP server
async function main() {
  try {
    // Dynamic import the MCP SDK modules
    const serverModule = await import(path.join(sdkDir, 'dist/server/index.js'));
    const stdioModule = await import(path.join(sdkDir, 'dist/server/stdio.js'));
    
    const McpServer = serverModule.Server;
    const StdioServerTransport = stdioModule.StdioServerTransport;
    
    // Initialize NVD client if API key is available
    if (process.env.NVD_API_KEY && CONFIG.USE_NVD) {
      try {
        console.log(`Using NVD API key: ${process.env.NVD_API_KEY.substring(0, 5)}...`);
        const initResult = await initNvdClient({
          apiKey: process.env.NVD_API_KEY,
          cacheDir: path.join(__dirname, 'cache')
        });
        nvdConfig = initResult.config;
        console.log('NVD client initialized successfully');
      } catch (error) {
        console.error(`Failed to initialize NVD client: ${error.message}`);
        console.warn('Continuing without NVD integration');
      }
    } else {
      console.warn(`NVD integration disabled or API key not provided: USE_NVD=${CONFIG.USE_NVD}, API key exists: ${Boolean(process.env.NVD_API_KEY)}`);
    }
    
    // Initialize GitHub client if token is available
    if (process.env.GITHUB_TOKEN) {
      try {
        const initResult = await initGithubClient({
          githubToken: process.env.GITHUB_TOKEN,
          cacheDir: path.join(__dirname, 'cache')
        });
        githubConfig = initResult.config;
        console.log('GitHub client initialized successfully');
      } catch (error) {
        console.error(`Failed to initialize GitHub client: ${error.message}`);
        console.warn('Continuing without GitHub API integration');
      }
    } else {
      console.warn('GitHub token not provided. Continuing with limited functionality.');
    }
    
    // Load vulnerability data
    if (!loadVulnerabilityData()) {
      console.warn('Starting with empty vulnerability database. Check data file path.');
    }
    
    // Schedule periodic database refresh
    setInterval(refreshVulnerabilityDatabase, CONFIG.DATA_REFRESH_INTERVAL);
    
    // Create the MCP server
    const server = new McpServer({
      name: "Vulnzap",
      version: "2.0.0"
    });

    // Define a resource for vulnerability scanning
    // URI pattern: vuln://{ecosystem}/{packageName}/{packageVersion}
    server.setRequestHandler({
      method: "resources/read",
      params: {
        uri: "vuln://{ecosystem}/{packageName}/{packageVersion}"
      }
    }, async (request) => {
      try {
        // Extract parameters from the URI
        const uri = new URL(request.params.uri);
        const segments = uri.pathname.split('/').filter(Boolean);
        
        if (segments.length !== 3 || uri.protocol !== 'vuln:') {
          throw new Error("Invalid vulnerability URI format. Expected: vuln://{ecosystem}/{packageName}/{packageVersion}");
        }
        
        const [ecosystem, packageName, packageVersion] = segments;
        
        // Check if package is vulnerable
        const result = await checkVulnerability(ecosystem, packageName, packageVersion);
        
        // Construct response
        if (result.error) {
          // Return error response
          throw new Error(result.error);
        } else {
          // Determine status based on vulnerability and whether it's known
          let status = result.isUnknown ? "Unknown" : (result.isVulnerable ? "Vulnerable" : "Safe");
          let content = `${status}: ${result.message}`;
          
          // Add sources if available
          if (result.sources && result.sources.length > 0) {
            content += `\nSources: ${result.sources.join(', ')}`;
          }
          
          // Add vulnerability details if available
          if (result.isVulnerable && result.advisories) {
            content += `\n\nDetails:\n`;
            result.advisories.forEach(adv => {
              content += `- ${adv.title} (${adv.severity}`;
              if (adv.cvss_score) content += `, CVSS: ${adv.cvss_score}`;
              content += `, ${adv.cve_id || 'No CVE'}`;
              if (adv.source) content += `, Source: ${adv.source}`;
              content += `)\n`;
              content += `  ${adv.description}\n`;
            });
          }
          
          // Return result in MCP-compatible format
          return {
            contents: [{
              uri: request.params.uri,
              text: content
            }]
          };
        }
      } catch (error) {
        console.error(`Error processing vulnerability check: ${error.message}`);
        throw error;
      }
    });

    // Premium feature: Batch vulnerability scanning
    server.setRequestHandler({
      method: "tools/invoke",
      params: {
        name: "batch-scan",
        arguments: {
          packages: {},
          apiKey: { type: "string" }
        }
      }
    }, async (request) => {
      try {
        const { packages, apiKey } = request.params.arguments;
        
        // Check API key for premium access
        if (apiKey !== CONFIG.PREMIUM_API_KEY) {
          throw new Error("Invalid API key. Premium features require authentication.");
        }
        
        // Validate packages format
        if (!Array.isArray(packages)) {
          throw new Error("'packages' must be an array of objects with ecosystem, packageName, and packageVersion properties.");
        }
        
        // Process each package
        const results = await Promise.all(packages.map(async pkg => {
          const { ecosystem, packageName, packageVersion } = pkg;
          
          // Skip invalid entries
          if (!ecosystem || !packageName || !packageVersion) {
            return {
              package: pkg,
              status: "error",
              message: "Invalid package entry. Required fields: ecosystem, packageName, packageVersion"
            };
          }
          
          // Check vulnerability
          const result = await checkVulnerability(ecosystem, packageName, packageVersion);
          
          // Format the response
          if (result.error) {
            return {
              package: pkg,
              status: "error",
              message: result.error
            };
          } else if (result.isUnknown) {
            return {
              package: pkg,
              status: "unknown",
              message: result.message,
              sources: result.sources
            };
          } else {
            return {
              package: pkg,
              status: result.isVulnerable ? "vulnerable" : "safe",
              message: result.message,
              sources: result.sources,
              ...(result.isVulnerable && { 
                advisories: result.advisories.map(adv => ({
                  id: adv.id,
                  title: adv.title,
                  severity: adv.severity,
                  cvss_score: adv.cvss_score,
                  cve_id: adv.cve_id,
                  description: adv.description,
                  source: adv.source
                }))
              })
            };
          }
        }));
        
        // Return batch results
        return {
          content: [{ 
            type: "text", 
            text: JSON.stringify({ results }, null, 2) 
          }]
        };
      } catch (error) {
        console.error(`Error processing batch scan: ${error.message}`);
        throw error;
      }
    });

    // Premium feature: Detailed vulnerability report
    server.setRequestHandler({
      method: "tools/invoke",
      params: {
        name: "detailed-report",
        arguments: {
          ecosystem: { type: "string" },
          packageName: { type: "string" },
          packageVersion: { type: "string" },
          apiKey: { type: "string" }
        }
      }
    }, async (request) => {
      try {
        const { ecosystem, packageName, packageVersion, apiKey } = request.params.arguments;
        
        // Check API key for premium access
        if (apiKey !== CONFIG.PREMIUM_API_KEY) {
          throw new Error("Invalid API key. Premium features require authentication.");
        }
        
        // Validate required fields
        if (!ecosystem || !packageName || !packageVersion) {
          throw new Error("Required fields missing. Please provide ecosystem, packageName, and packageVersion.");
        }
        
        // Check vulnerability
        const result = await checkVulnerability(ecosystem, packageName, packageVersion);
        
        // Generate detailed report
        let report = `# Vulnerability Report for ${packageName}@${packageVersion} (${ecosystem})\n\n`;
        
        if (result.error) {
          report += `## Error\n\n${result.error}\n\n`;
        } else if (result.isUnknown) {
          report += `## Status: Unknown\n\n${result.message}\n\n`;
        } else if (result.isVulnerable) {
          report += `## Status: Vulnerable\n\n${result.message}\n\n`;
          
          // Add data sources
          if (result.sources && result.sources.length > 0) {
            report += `## Data Sources\n\n`;
            report += result.sources.map(source => `- ${source}`).join('\n');
            report += '\n\n';
          }
          
          // Add vulnerability details if available
          if (result.advisories && result.advisories.length > 0) {
            report += `## Vulnerabilities\n\n`;
            
            result.advisories.forEach(adv => {
              report += `### ${adv.title}\n\n`;
              report += `- **ID**: ${adv.id}\n`;
              report += `- **Severity**: ${adv.severity}\n`;
              if (adv.cvss_score) report += `- **CVSS Score**: ${adv.cvss_score}\n`;
              report += `- **CVE**: ${adv.cve_id || 'N/A'}\n`;
              report += `- **Data Source**: ${adv.source || 'N/A'}\n`;
              report += `- **Vulnerable Versions**: ${adv.vulnerable_versions}\n`;
              report += `- **Patched Versions**: ${adv.patched_versions || 'N/A'}\n`;
              report += `- **Description**: ${adv.description}\n\n`;
            });
          }
          
          // Add remediation advice
          report += `## Remediation\n\n`;
          report += `The recommended action is to update ${packageName} to the latest patched version.\n\n`;
          
          // For npm packages
          if (ecosystem === 'npm') {
            report += `Run the following command to update:\n\n`;
            report += `\`\`\`bash\nnpm update ${packageName}\n\`\`\`\n\n`;
            report += `Or specify a specific version:\n\n`;
            report += `\`\`\`bash\nnpm install ${packageName}@latest\n\`\`\`\n\n`;
          }
          
          // For pip packages
          if (ecosystem === 'pip') {
            report += `Run the following command to update:\n\n`;
            report += `\`\`\`bash\npip install --upgrade ${packageName}\n\`\`\`\n\n`;
          }
        } else {
          report += `## Status: Safe\n\n${result.message}\n\n`;
          
          // Add data sources
          if (result.sources && result.sources.length > 0) {
            report += `## Data Sources\n\n`;
            report += result.sources.map(source => `- ${source}`).join('\n');
            report += '\n\n';
          }
        }
        
        // Add disclaimer
        report += `## Disclaimer\n\n`;
        report += `This vulnerability report is generated automatically and may not be comprehensive. `;
        report += `Always review the security advisories from the package maintainers and consider additional security measures for critical applications.\n\n`;
        report += `Report generated by Vulnzap on ${new Date().toISOString()}\n`;
        
        // Return the report
        return {
          content: [{ 
            type: "text", 
            text: report
          }]
        };
      } catch (error) {
        console.error(`Error generating detailed report: ${error.message}`);
        throw error;
      }
    });

    // Set up the transport
    const transport = new StdioServerTransport();
    
    // Start the server
    server.connect(transport)
      .then(() => {
        console.log("Vulnzap MCP server started successfully");
        console.log("Ready to process MCP requests");
        console.log("\nActive Data Sources:");
        console.log("- Local database");
        if (githubConfig) console.log("- GitHub Advisory Database API");
        if (nvdConfig) console.log("- National Vulnerability Database (NVD)");
        
        console.log("\nSupported Ecosystems:");
        console.log(CONFIG.SUPPORTED_ECOSYSTEMS.join(', '));
        
        console.log("\nAvailable Tools:");
        console.log("- vulnerability-check: Check individual packages (vuln://npm/express/4.16.0)");
        console.log("- batch-scan: Scan multiple packages at once");
        console.log("- detailed-report: Generate comprehensive vulnerability reports");
        
        // Keep the process running
        process.stdin.resume();
      })
      .catch(error => {
        console.error(`Failed to start MCP server: ${error.message}`);
      });
  } catch (error) {
    console.error(`Failed to start Vulnzap server: ${error.message}`);
    process.exit(1);
  }
}

// Run the server
main().catch(error => {
  console.error(`Failed to start Vulnzap server: ${error.message}`);
  process.exit(1);
}); 