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
    version: "1.0.0"
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
        const result = await checkVulnerability(ecosystem, packageName, packageVersion);
        
        // Construct response
        if (result.error) {
          // Return error response
          return {
            error: result.error
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
              text: content
            }]
          };
        }
      } catch (error: any) {
        console.error(`Error processing vulnerability check: ${error.message}`);
        return {
          error: `Internal server error: ${error.message}`
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
    { 
      packages: {}, 
      apiKey: { type: "string" } 
    },
    async ({ packages, apiKey: toolApiKey }) => {
      try {
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