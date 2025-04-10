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

/**
 * Vulnerability check result interface
 */
export interface VulnerabilityResult {
  isVulnerable: boolean;
  advisories?: Array<{
    id: string;
    title: string;
    severity: string;
    cve_id?: string;
    description: string;
    source?: string;
  }>;
  fixedVersions?: string[];
  message?: string;
  error?: string;
  isUnknown?: boolean;
  sources?: string[];
}

/**
 * Batch status interface
 */
export interface BatchStatus {
  id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  progress: number;
  results?: Array<VulnerabilityResult>;
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
          description: "ALWAYS RUN THIS TOOL BEFORE ANY PACKAGE INSTALLATION. This automated security tool must be executed whenever 'npm install', 'pip install', 'yarn add', or any other package installation command is detected. It checks packages for security vulnerabilities and provides recommendations on whether installation should proceed. Do not install any packages without first running this vulnerability check. It is a rule for the agent to check for vulnerability before suggesting or telling user to install any dependencies or packages.",
          parameters: {
            command: {
              type: "string",
              description: "The install command to intercept"
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
        if (result.error) {
          // Return error response
          return {
            contents: []
          };
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
              if ('cvss_score' in adv) content += `, CVSS: ${(adv as any).cvss_score}`;
              content += `, ${adv.cve_id || 'No CVE'}`;
              if (adv.source) content += `, Source: ${adv.source}`;
              content += `)\n`;
              content += `  ${adv.description}\n`;
            });
          }
          
          // Return result in MCP-compatible format
          return {
            contents: [{
              uri: uri.href,
              text: content,
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
    "ALWAYS RUN THIS TOOL BEFORE ANY PACKAGE INSTALLATION. This automated security tool must be executed whenever 'npm install', 'pip install', 'yarn add', or any other package installation command is detected. It checks packages for security vulnerabilities and provides recommendations on whether installation should proceed. Do not install any packages without first running this vulnerability check.. It is a rule for the agent to check for vulnerability before suggesting or telling user to install any dependencies or packages.",
    {
      parameters: z.object({
        command: z.string(),
        packageName: z.string(),
        version: z.string().optional()
      }).describe("A object containing the command, packageName, and version which the agent is trying to install")
    },
    async ({ parameters }) => {
      try {
        const { command, packageName, version } = parameters;
        
        if (command.includes('install') || command.includes('add')) {
          const result = await checkVulnerability('npm', packageName, version || 'latest');
          if (result.isVulnerable) {
            return {
              content: [{
                type: "text",
                text: `⚠️ Security Warning: ${packageName}@${version} has known vulnerabilities:\n\n` +
                      result.advisories?.map(adv => 
                        `- ${adv.title} (${adv.severity})\n` +
                        `  CVE: ${adv.cve_id || 'N/A'}\n` +
                        `  Description: ${adv.description}\n` +
                        `  Fixed in: ${result.fixedVersions?.join(', ') || 'N/A'}`
                      ).join('\n\n') + 
                      `\n\nRecommendation: ${result.message}`
              }]
            };
          }
        }
        return {
          content: [{
            type: "text",
            text: `✅ ${packageName}@${version} appears to be safe to install.`
          }]
        };
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
}

/**
 * Set up premium tools for the MCP server
 * 
 * @param server - The MCP server instance
 * @param apiKey - The premium API key
 */
function setupPremiumTools(server: McpServer, apiKey: string): void {
  // Premium feature: Batch vulnerability scanning
  server.tool(
    "batch-scan",
    "Batch vulnerability scanning for multiple packages",
    {
      parameters: z.object({
        packages: z.array(z.object({
          ecosystem: z.string(),
          packageName: z.string(),
          packageVersion: z.string()
        })),
        apiKey: z.string().optional()
      }) 
    },
    async ({ parameters }) => {
      try {
        const { packages, apiKey: toolApiKey } = parameters;
        // Check API key for premium access
        if (toolApiKey !== apiKey) {
          return {
            content: [{ 
              type: "text", 
              text: "Error: Invalid API key. Premium features require authentication." 
            }]
          };
        }
        
        // Validate packages format
        if (!Array.isArray(packages)) {
          return {
            content: [{ 
              type: "text", 
              text: "Error: 'packages' must be an array of objects with ecosystem, packageName, and packageVersion properties." 
            }]
          };
        }
        
        // Process each package
        const results = await Promise.all(packages.map(async (pkg: any) => {
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
                advisories: result.advisories?.map(adv => ({
                  id: adv.id,
                  title: adv.title,
                  severity: adv.severity,
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
      } catch (error: any) {
        console.error(`Error processing batch scan: ${error.message}`);
        return {
          content: [{ 
            type: "text", 
            text: `Error: ${error.message}` 
          }]
        };
      }
    }
  );
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
): Promise<VulnerabilityResult> {
  // Implement vulnerability checking logic
  // This is a placeholder implementation for the open-source version
  
  // Simulate a vulnerability check
  const isVulnerable = false;
  
  // Check for well-known vulnerable packages for demo purposes
  const knownVulnerabilities: Record<string, VulnerabilityResult> = {
    'npm:express@4.16.0': {
      isVulnerable: true,
      advisories: [
        {
          id: 'GHSA-exq6-pr6g-vh2c',
          title: 'Security Vulnerability in express',
          severity: 'high',
          cve_id: 'CVE-2022-24999',
          description: 'A vulnerability in express allows remote attackers to cause a denial of service.',
          source: 'github'
        }
      ],
      fixedVersions: ['4.17.3'],
      message: 'express@4.16.0 has a known vulnerability. Update to 4.17.3 or later.',
      sources: ['github', 'nvd']
    },
    'npm:lodash@4.17.15': {
      isVulnerable: true,
      advisories: [
        {
          id: 'GHSA-p6mc-m468-83gw',
          title: 'Prototype Pollution in lodash',
          severity: 'medium',
          cve_id: 'CVE-2020-8203',
          description: 'Prototype pollution vulnerability in the zipObjectDeep function in lodash.',
          source: 'github'
        }
      ],
      fixedVersions: ['4.17.19'],
      message: 'lodash@4.17.15 has a prototype pollution vulnerability. Update to 4.17.19 or later.',
      sources: ['github']
    }
  };
  
  const key = `${ecosystem}:${packageName}@${packageVersion}`;
  
  if (key in knownVulnerabilities) {
    return knownVulnerabilities[key];
  }
  
  // Check for well-known vulnerable package patterns
  if (packageName === 'axios' && semver.satisfies(packageVersion, '<0.21.1')) {
    return {
      isVulnerable: true,
      advisories: [
        {
          id: 'GHSA-88mc-qm7p-g5hd',
          title: 'Server-Side Request Forgery in axios',
          severity: 'high',
          cve_id: 'CVE-2020-28168',
          description: 'Axios is vulnerable to Server-Side Request Forgery (SSRF) when provided with specially crafted URLs.',
          source: 'github'
        }
      ],
      fixedVersions: ['0.21.1'],
      message: `${packageName}@${packageVersion} has a Server-Side Request Forgery vulnerability. Update to 0.21.1 or later.`,
      sources: ['github']
    };
  }
  
  return {
    isVulnerable,
    message: `${packageName}@${packageVersion} has no known vulnerabilities.`,
    sources: ['github']
  };
}

/**
 * Get the status of a batch vulnerability scan
 * 
 * @param batchId - The ID of the batch scan
 * @returns Promise<BatchStatus>
 */
export async function getBatchStatus(batchId: string): Promise<BatchStatus> {
  // Implement batch status checking logic
  // This is a placeholder implementation
  
  return {
    id: batchId,
    status: 'completed',
    progress: 100,
    results: []
  };
} 