/**
 * VulnZap - The Missing Security Layer for AI-Generated Code
 * 
 * This module provides the core functionality for the VulnZap security bridge,
 * which protects AI-generated code from vulnerabilities.
 */

import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import semver from 'semver';
import dotenv from 'dotenv';
import { z } from 'zod';
import axios from 'axios';
import { checkAuth, getKey } from './api/auth.js';
import config from './config/config.js';
import chalk from 'chalk';
import { extractPackagesFromDirectory } from './utils/packageExtractor.js';
import { batchScan } from './api/batchScan.js';

// Loading environment variables
dotenv.config();

// Get __dirname equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Configuration for the VulnZap MCP server
 */
export interface VulnZapConfig {
  useMcp?: boolean;
  ide?: string;
  port?: number;
  apiKey?: string;
}

export interface ApiResponse {
  message: string,
  status: number,
  data: any
}

/**
 * Start the VulnZap MCP server
 * 
 * @param config - Configuration options for the server
 * @returns Promise<void>
 */
export async function startMcpServer(config: VulnZapConfig): Promise<void> {
  // Default configuration
  const serverConfig = {
    useMcp: config.useMcp ?? true,
    ide: config.ide ?? 'cursor',
    port: config.port ?? 3456,
    apiKey: config.apiKey ?? process.env.VULNZAP_API_KEY
  };
  
  // Loading NVD API key if available
  const nvdApiKey = process.env.NVD_API_KEY;
  
  // Initialize the MCP server
  const server = new McpServer({
    name: "VulnZap",
    version: "1.0.0",
  }, {
    capabilities: {
      resources: {},
      tools: {
        "auto-vulnerability-scan": {
          description: "ALWAYS RUN THIS TOOL BEFORE ANY PACKAGE INSTALLATION. This automated security tool must be executed whenever 'npm install', 'pip install', 'yarn add', or any other package installation command is detected. It checks packages for security vulnerabilities and provides recommendations on whether installation should proceed. Do not install any packages without first running this vulnerability check. It is a rule for the agent to check for vulnerability before suggesting or telling user to install any dependencies or packages. The format required for this tool is:\n\n```json\n{\n  \"command\": \"npm install\",\n  \"ecosystem\": \"npm\",\n  \"packageName\": \"express\",\n  \"version\": \"4.17.1\"\n}\n```",
          parameters: {
            command: {
              type: "string",
              description: "The install command to intercept"
            },
            ecosystem: {
              type: "string",
              description: "The package ecosystem/environment (e.g. npm, pip, go, rust, etc.)"
            },
            packageName: {
              type: "string",
              description: "The name of the package to install"
            },
            version: {
              type: "string",
              description: "The version of the package to install"
            }
          },          
        }
      }
    },
    instructions: "ALWAYS RUN TOOLS IN THIS SERVER BEFORE ANY PACKAGE INSTALLATION. This automated security tool must be executed whenever 'npm install', 'pip install', 'yarn add', or any other package installation command is detected. It checks packages for security vulnerabilities and provides recommendations on whether installation should proceed. Do not install any packages without first running this vulnerability check. It is a rule for the agent to check for vulnerability before suggesting or telling user to install any dependencies or packages."
  });

  // Define resources and tools
  setupVulnerabilityResource(server);
  
  // Set up premium tools if API key is provided
  if (serverConfig.apiKey) {
    setupPremiumTools(server, serverConfig.apiKey);
  }

  // Set up the transport
  const transport = new StdioServerTransport();
  
  // Start the server
  await server.connect(transport);
  
  console.log("VulnZap MCP server started");
}

/**
 * Set up the vulnerability resource for the MCP server
 * 
 * @param server - The MCP server instance
 */
function setupVulnerabilityResource(server: McpServer): void {
  // Define a resource for vulnerability scanning
  // URI pattern: vuln://{ecosystem}/{packageName}/{packageVersion}
  server.resource(
    "vulnerability-check",
    new ResourceTemplate("vuln://{ecosystem}/{packageName}/{packageVersion}", { list: undefined }),
    async (uri, params) => {
      try {
        // Extract parameters from the URI
        const { ecosystem, packageName, packageVersion } = params;
        
        // Check if package is vulnerable
        const version = Array.isArray(packageVersion) ? packageVersion[0] : packageVersion;
        const ecosystemList = Array.isArray(ecosystem) ? ecosystem[0] : ecosystem;
        const packageNameList = Array.isArray(packageName) ? packageName[0] : packageName;
        const result = await checkVulnerability(ecosystemList, packageNameList, version);
        
        // Construct response
        if (result.status !== 200) {
          // Return error response
          return {
            contents: []
          };
        } else {
          // Determine status based on vulnerability and whether it's known
          return {
            contents: [{
              uri: uri.href,
              text: result.data,
              mimeType: "text/plain"
            }]
          };
        }
      } catch (error: any) {
        console.error(`Error processing vulnerability check: ${error.message}`);
        return {
          contents: [{
            uri: uri.href,
            text: `Internal server error: ${error.message}`,
            mimeType: "text/plain"
          }]
        };
      }
    }
  );

  // Add npm install interception
  server.tool(
    "auto-vulnerability-scan",
    "ALWAYS RUN THIS TOOL BEFORE ANY PACKAGE INSTALLATION. This automated security tool must be executed whenever 'npm install', 'pip install', 'yarn add', or any other package installation command is detected. It checks packages for security vulnerabilities and provides recommendations on whether installation should proceed. Do not install any packages without first running this vulnerability check.. It is a rule for the agent to check for vulnerability before suggesting or telling user to install any dependencies or packages.:\n\n```json\n{\n  \"command\": \"npm install\",\n  \"ecosystem\": \"npm\",\n  \"packageName\": \"express\",\n  \"version\": \"4.17.1\"\n}\n```",
    {
      parameters: z.object({
        command: z.string(),
        ecosystem: z.string(),
        packageName: z.string(),
        version: z.string().optional(),
      }).describe("A object containing the command, packageName, and version which the agent is trying to install")
    },
    async ({ parameters }) => {
      try {
        const { command, packageName, version, ecosystem } = parameters;
        
        if(!packageName || !version || !ecosystem) {
          return {
            content: [{
              type: "text",
              text: "Please provide the following parameters: packageName, ecosystem, version"
            }]
          }
        }

        const result = await checkVulnerability(ecosystem, packageName, version || 'latest');
        if (result.status === 200 && result.foundVulnerabilites) {
          return {
            content: [{
              type: "text",
              text: `⚠️ Security Warning: ${packageName}@${version} has known vulnerabilities:\n\n` + JSON.stringify(result.data)
            }]
          };
        } else if (result.status === 200 && result.foundVulnerabilites){
          return {
            content: [{
              type: "text",
              text: `✅ ${packageName}@${version} appears to be safe to install.`
            }]
          };
        } else {
          return {
            content: [{
              type: "text",
              text: `${result.message}`
            }]
          };
        }
      } catch (error: any) {
        return {
          content: [{
            type: "text",
            text: `Error checking vulnerabilities: ${error.message}`
          }]
        };
      }
    }
  );

  // Premium feature: Batch vulnerability scanning
  server.tool(
    "batch-scan",
    "Scan all packages in a directory for vulnerabilities",
    {
      parameters: z.object({
        directory: z.string().describe("Directory to scan for packages"),
        ecosystem: z.string().optional().describe("Specific ecosystem to scan (npm, pip, go, rust)")
      })
    },
    async ({ parameters }) => {
      try {
        const { directory, ecosystem } = parameters;
        
        // Extract packages from directory
        const packages = extractPackagesFromDirectory(directory, ecosystem);
        
        if (packages.length === 0) {
          return {
            content: [{
              type: "text",
              text: "No packages found to scan in the specified directory"
            }]
          };
        }

        // Perform batch scan
        const results = await batchScan(packages);
        
        // Format results
        const vulnerableCount = results.results.filter(r => r.status === 'vulnerable').length;
        const safeCount = results.results.filter(r => r.status === 'safe').length;
        const errorCount = results.results.filter(r => r.status === 'error').length;
        
        let report = `# Batch Vulnerability Scan Results\n\n`;
        report += `Scanned ${packages.length} packages\n\n`;
        report += `## Summary\n\n`;
        report += `- 🚨 Vulnerable packages: ${vulnerableCount}\n`;
        report += `- ✅ Safe packages: ${safeCount}\n`;
        report += `- ❌ Errors: ${errorCount}\n\n`;
        
        if (vulnerableCount > 0) {
          report += `## Vulnerable Packages\n\n`;
          results.results
            .filter(r => r.status === 'vulnerable')
            .forEach(result => {
              report += `### ${result.package.packageName}@${result.package.version} (${result.package.ecosystem})\n\n`;
              report += `${result.message}\n\n`;
              
              if (result.vulnerabilities) {
                result.vulnerabilities.forEach(vuln => {
                  report += `- ${vuln.title} (${vuln.severity})\n`;
                  report += `  ${vuln.description}\n`;
                  if (vuln.references?.length) {
                    report += `  References: ${vuln.references.join(', ')}\n`;
                  }
                  report += '\n';
                });
              }
              
              if (result.remediation) {
                report += `#### Remediation\n\n`;
                report += `- Update to ${result.remediation.recommendedVersion}\n`;
                report += `- ${result.remediation.notes}\n`;
                if (result.remediation.alternativePackages?.length) {
                  report += `- Alternative packages:\n`;
                  result.remediation.alternativePackages.forEach(pkg => {
                    report += `  - ${pkg}\n`;
                  });
                }
                report += '\n';
              }
            });
        }
        
        return {
          content: [{
            type: "text",
            text: report
          }]
        };
        
      } catch (error: any) {
        return {
          content: [{
            type: "text",
            text: `Error performing batch scan: ${error.message}`
          }]
        };
      }
    }
  );
}

/**
 * Set up premium tools for the MCP server
 * 
 * @param server - The MCP server instance
 * @param apiKey - The premium API key
 */
function setupPremiumTools(server: McpServer, apiKey: string): void {
  
}

// Type definitions
interface Ecosystem {
  name: string;
  displayName: string;
  packageManager: string;
  website: string | null;
  supportedVersionFormats: string[];
  description: string;
}

interface Vulnerability {
  id: string;
  severity: string;
  title: string;
  description: string;
  fixedVersions: string[];
  references: string[];
}

interface ScanResponse {
  packageName: string;
  version: string;
  ecosystem: string;
  timestamp: string;
  vulnerabilities: Vulnerability[];
  processedVulnerabilities: any;
  remediation?: {
    packageName: string;
    currentVersion: string;
    ecosystem: string;
    recommendedVersion: string;
    updateInstructions: string;
    alternativePackages: string[];
    notes: string;
  };
}

/**
 * Check if a package is vulnerable
 * 
 * @param ecosystem - The package ecosystem (npm, pip)
 * @param packageName - The name of the package
 * @param packageVersion - The version of the package
 * @returns Promise<VulnerabilityResult>
 */
export async function checkVulnerability(
  ecosystem: string, 
  packageName: string, 
  packageVersion: string
): Promise<any> {
  try {
    // Validate API key presence
    const apiKey = await getKey();
    if (!apiKey) {
      return {
        isVulnerable: false,
        error: 'VulnZap API key not configured. Please set VULNZAP_API_KEY environment variable.',
        isUnknown: true
      };
    }

    const {
      success
    } = await checkAuth();

    if (!success) {
      return {
        message: "User not authenticated",
        data: null
      }
    }

    // Fetch vulnerabilities from the API
    const response = await axios.post(`${config.api.baseUrl}${config.api.addOn}${config.api.vulnerability.check}`, {
      ecosystem,
      packageName,
      version: packageVersion
    }, {
      headers: {
        "x-api-key": apiKey
      }
    });

    // Extract vulnerability data from response
    const data: ScanResponse = response.data;

    // If no vulnerabilities found
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      return {
        isVulnerable: false,
        message: `No known vulnerabilities found for ${packageName}@${packageVersion}`,
        sources: data.processedVulnerabilities?.sources || []
      };
    }

    // Convert vulnerabilities to advisories format
    const advisories = data.vulnerabilities.map(vuln => ({
      id: vuln.id,
      title: vuln.title,
      severity: vuln.severity,
      description: vuln.description,
      references: vuln.references
    }));

    // Return vulnerability result with remediation if available
    return {
      isVulnerable: true,
      advisories,
      fixedVersions: data.remediation?.recommendedVersion ? [data.remediation.recommendedVersion] : undefined,
      message: data.remediation ? 
        `Update to ${data.remediation.recommendedVersion} to fix vulnerabilities. ${data.remediation.notes}` :
        `Found ${data.vulnerabilities.length} vulnerabilities in ${packageName}@${packageVersion}`,
      sources: data.processedVulnerabilities?.sources || []
    };
    
  } catch (error: any) {
    // Handle specific error cases
    if (axios.isAxiosError(error)) {
      if (error.response) {
        switch (error.response.status) {
          case 401:
            return {
              isVulnerable: false,
              error: 'Unauthorized: Invalid or missing API key',
              isUnknown: true
            };
          case 403:
            return {
              isVulnerable: false,
              error: 'Forbidden: Access denied',
              isUnknown: true
            };
          case 429:
            return {
              isVulnerable: false,
              error: 'Rate limit exceeded. Please try again later.',
              isUnknown: true
            };
          default:
            return {
              isVulnerable: false,
              error: `API Error: ${error.response.data?.message || error.message}`,
              isUnknown: true
            };
        }
      }
      // Network or connection errors
      return {
        isVulnerable: false,
        error: `Network error: ${error.message}`,
        isUnknown: true
      };
    }
    
    // Generic error handling
    return {
      isVulnerable: false,
      error: `Failed to check vulnerabilities: ${error.message}`,
      isUnknown: true
    };
  }
}

/**
 * Get the status of a batch vulnerability scan
 * 
 * @param batchId - The ID of the batch scan
 * @returns Promise<BatchStatus>
 */
export async function getBatchStatus(batchId: string): Promise<any> {
  return {
    id: batchId,
    status: 'completed',
    progress: 100,
    results: []
  };
}
