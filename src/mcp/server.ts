/**
 * VulnZap - The Missing Security Layer for AI-Generated Code
 *
 * This module provides the core functionality for the VulnZap security bridge,
 * which protects AI-generated code from vulnerabilities.
 */

import {
    McpServer,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import dotenv from "dotenv";

import { batchScan } from "../api/batchScan.js";
import { cacheService } from "../services/cache.js";
import { saveKey, getKey } from "../api/auth.js";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

// Load environment variables
dotenv.config();

export interface ApiResponse {
    message: string;
    status: number;
    data: any;
}

// Get package version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
const version = packageJson.version;

/**
 * Start the VulnZap MCP server
 *
 * @returns Promise<void>
 */
export async function startMcpServer(): Promise<void> {
    // Check for API key from environment variable
    const envApiKey = process.env.VULNZAP_API_KEY;
    if (envApiKey) {
        try {
            await saveKey(envApiKey);
        } catch (error) {
            console.error('Failed to save API key from environment:', error);
        }
    }

    // Ensure we have an API key
    try {
        await getKey();
    } catch (error) {
        console.error('No API key found. Please run "vulnzap setup" or set VULNZAP_API_KEY environment variable.');
        process.exit(1);
    }

    // Initialize the MCP server
    const server = new McpServer(
        {
            name: "VulnZap",
            version: version,
        },
        {
            capabilities: {
                tools: {}
            }
        }
    );

    // Define resources and tools
    setupVulnerabilityResource(server);

    // Set up the transport
    const transport = new StdioServerTransport();

    // Start the server
    await server.connect(transport);
}

/**
 * Set up the vulnerability resource for the MCP server
 *
 * @param server - The MCP server instance
 */
function setupVulnerabilityResource(server: McpServer): void {
    // Batch vulnerability scanning
    server.tool(
        "package-vulnerability-scan",
        "Scan package(s) for known security vulnerabilities.\n\n" +
        "Call this tool whenever you need to:\n" +
        "- Check the security status of all packages in a codebase (before deployment, during onboarding, or after major changes)\n" +
        "- Audit a project for vulnerable dependencies across package.json, requirements.txt, etc.\n\n" +
        "Use this tool to ensure the entire project is free from known dependency vulnerabilities before release or as part of regular security hygiene.",
        {
            packages: z.array(z.object({
                packageName: z.string(),
                ecosystem: z.string(),
                version: z.string(),
            })),
        },
        async ({ packages }) => {            
            try {
                if (packages.length === 0) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: "No packages found to scan",
                            },
                        ],
                    };
                }

                // Perform batch scan
                const results = await batchScan(packages, {
                    useCache: true,
                    useAi: true
                });

                // Extract results array (same as CLI)
                const scanResults = results.results || [];

                const vulnerableCount = scanResults.filter(r => r.status === 'vulnerable').length;
                const safeCount = scanResults.filter(r => r.status === 'safe').length;
                const errorCount = scanResults.filter(r => r.status === 'error').length;

                let report = `# Batch Vulnerability Scan Results\n\n`;
                report += `Scanned ${packages.length} packages\n\n`;
                report += `## Summary\n\n`;
                report += `- 🚨 Vulnerable packages: ${vulnerableCount}\n`;
                report += `- ✅ Safe packages: ${safeCount}\n`;
                report += `- ❌ Errors: ${errorCount}\n\n`;

                // Display detailed results (same as CLI)
                if (vulnerableCount > 0) {
                    report += `## Vulnerable Packages\n\n`;
                    scanResults
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
                                    report += '- Alternative packages:\n';
                                    result.remediation.alternativePackages.forEach(pkg => {
                                        report += `  - ${pkg}\n`;
                                    });
                                }
                                report += '\n';
                            }
                        });
                }

                return {
                    content: [
                        {
                            type: "text",
                            text: `Here are the results of the batch scan, summarise it to the user and propose your actions:\n\n${report}`,
                        },
                    ],
                };
            } catch (error: any) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error performing batch scan: ${error.message}`,
                        },
                    ],
                };
            }
        }
    );
    server.tool(
        'repo_scan_start',
        'Start a vulnerability scan for a GitHub repository. The CLI will use real-time Server-Sent Events for live progress updates, with fallback to polling if needed. If repoUrl is unknown, first obtain it from package.json (repository.url) or README, or ask the user. Scans typically take 5+ minutes and consume tokens from the user\'s plan. Only initiate after all changes are finalized, committed, and pushed to the repo. Strongly confirm with the user before starting — pushing to production before a clean scan is risky. The scan runs in the cloud and continues even if the terminal is closed; you can monitor progress/logs in the dashboard and via repo_scan_progress. After completion, call repo_scan_progress (or peek_events if unsure), review any reported vulnerabilities, propose and apply fixes, re-scan if needed, and only deploy when the report is clean.',
        {
          repoUrl: z.string().optional().describe('Repository URL (e.g., https://github.com/owner/repo) without the .git extension'),
          branch: z.string().optional().default('main').describe('Branch to scan (defaults to main)')
        },
        async ({ repoUrl, branch }) => {
          try {
            // If repoUrl not provided or invalid, instruct the AGENT to obtain it first
            if (!repoUrl || !/github\.com\/[^/]+\/[^/]+$/.test(repoUrl)) {
              return {
                content: [
                  {
                    type: 'text',
                    text: [
                      'Repository URL not provided or invalid.',
                      '',
                      'Obtain the GitHub repository URL first:',
                      '1) Inspect package.json: repository.url',
                      '2) If absent, check README for a GitHub link',
                      '3) If still unknown, ask the user to provide https://github.com/owner/repo',
                      '',
                      'Before starting a scan:',
                      '- Ensure ALL changes are committed and pushed to the repository',
                      '- Confirm with the user to proceed (scans take 5+ minutes and consume tokens)',
                      '- It\'s risky to deploy to production before a clean scan',
                      '',
                      'Once you have the URL, run this command in the terminal and wait for completion:',
                      '',
                      'npx --yes vulnzap scan "<GITHUB_REPO_URL>" --output scan-results.json --wait',
                      '',
                      'Do not call any HTTP APIs for this action; use the terminal only.',
                      '',
                      'Notes:',
                      '- The --output flag saves results to scan-results.json for easy reading',
                      '- The --wait flag will wait for completion and show final results',
                      '- After completion, read the scan-results.json file to check the final status',
                      '- The scan runs in the cloud and continues if you close the terminal',
                      '- Track progress/logs in the dashboard or by calling repo_scan_progress',
                      '- After completion, call repo_scan_progress (or peek_events), review vulnerabilities, propose patches, and fix them',
                      '- Re-scan if needed and deploy only when the report is clean'
                    ].join('\n')
                  }
                ]
              };
            }
    
            // Instruct the AGENT to execute the CLI scan and wait
            const command = branch !== 'main'
              ? `npx --yes vulnzap scan "${repoUrl}" --branch ${branch} --output scan-results.json --wait`
              : `npx --yes vulnzap scan "${repoUrl}" --output scan-results.json --wait`;

            return {
              content: [
                {
                  type: 'text',
                  text: [
                    'Run the following command in the terminal and wait until it completes:',
                    '',
                    command,
                    '',
                    'Notes:',
                    `- Use the default branch unless you need a specific one (requested: ${branch}).`,
                    '- The --output flag saves results to scan-results.json for easy reading.',
                    '- The --wait flag will wait for completion and show final results.',
                    '- After completion, read the scan-results.json file to check the final status.',
                    '- Do not call any HTTP APIs to start the scan; use the terminal only.',
                    '- Scans typically take 5+ minutes and consume tokens from the user\'s plan.',
                    '- Ensure all changes are committed and pushed before starting.',
                    '- It\'s risky to deploy to production before a clean scan.',
                    '- The scan runs in the cloud and continues if you close the terminal.',
                    '- Monitor progress/logs in the dashboard or via repo_scan_progress.',
                    '- After completion, call repo_scan_progress (or peek_events), review vulnerabilities, propose patches, and fix them.',
                    '- Re-scan if needed and deploy only when the report is clean.'
                  ].join('\n')
                }
              ]
            };
          } catch (error) {
            console.error('Error in repo_scan_start tool:', error);
            return {
              content: [
                {
                  type: 'text',
                  text: `Error initiating scan: ${error instanceof Error ? error.message : 'Unknown error'}`
                }
              ]
            };
          }
        }
      );
}