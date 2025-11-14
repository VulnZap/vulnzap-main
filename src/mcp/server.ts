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
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { createRequire } from "module";

import { saveKey, getKey } from "../api/auth.js";
import { scanState } from "./scanState.js";
import {
    getCurrentCommitHash,
    getRepositoryUrl,
    getCurrentBranch,
    getUserIdentifier,
    getDiffFiles,
    isGitRepository
} from "../utils/gitUtils.js";

// Load environment variables
dotenv.config();

// Get package version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
const version = packageJson.version;

// Use createRequire to import @vulnzap/client (it only has require exports)
const require = createRequire(import.meta.url);
const { VulnzapClient } = require("@vulnzap/client");

// Global VulnzapClient instance
let vulnzapClient: any = null;

/**
 * Initialize VulnzapClient with API key
 */
async function initializeClient(): Promise<any> {
    if (vulnzapClient) {
        return vulnzapClient;
    }

    const apiKey = await getKey();
    vulnzapClient = new VulnzapClient({ apiKey });

    // Set up event listeners
    vulnzapClient.on("update", (evt: any) => {
        // Update scan state if needed
        // The client handles its own state, but we can track progress here
    });

    vulnzapClient.on("completed", (evt: any) => {
        // Store completed scan results in scanState
        // Find scan by jobId and mark as completed
        const scans = scanState.getAllScans();
        const scan = scans.find(s => s.jobId === evt.jobId);
        if (scan) {
            scanState.updateScan(scan.scan_id, {
                ...scan,
                timestamp: Date.now()
            });
        }
    });

    vulnzapClient.on("error", (err: any) => {
        console.error("VulnzapClient error:", err);
    });

    return vulnzapClient;
}

/**
 * Generate a scan_id from jobId or create a new one
 */
function generateScanId(jobId: string, type: 'diff' | 'full'): string {
    const prefix = type === 'diff' ? 'vz_' : 'vz_full_';
    // Use first 6 chars of jobId or generate short random string
    const shortId = jobId.substring(0, 6) || Math.random().toString(36).substring(2, 8);
    return `${prefix}${shortId}`;
}

/**
 * Transform client findings to spec format
 */
function transformFindings(findings: any[]): Array<{
    id: string;
    severity: string;
    path: string;
    range: {
        start: { line: number; col: number };
    };
}> {
    return findings.map((finding: any, index: number) => ({
        id: `VZ-${index + 1}`,
        severity: finding.severity || 'medium',
        path: finding.file || '',
        range: {
            start: {
                line: finding.line || 1,
                col: finding.column || 1
            }
        }
    }));
}

/**
 * Calculate severity counts
 */
function calculateCounts(findings: any[]): { high: number; medium: number; low: number; critical?: number } {
    const counts = { high: 0, medium: 0, low: 0, critical: 0 };
    findings.forEach((f: any) => {
        const severity = (f.severity || 'medium').toLowerCase();
        if (severity === 'critical') counts.critical = (counts.critical || 0) + 1;
        else if (severity === 'high') counts.high++;
        else if (severity === 'medium') counts.medium++;
        else counts.low++;
    });
    return counts;
}

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

    // Initialize VulnzapClient
    await initializeClient();

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

    // Define tools
    setupVulnzapTools(server);

    // Set up the transport
    const transport = new StdioServerTransport();

    // Start the server
    await server.connect(transport);
}

/**
 * Set up the Vulnzap MCP tools
 *
 * @param server - The MCP server instance
 */
function setupVulnzapTools(server: McpServer): void {
    // Tool 1: vulnzap.scan_diff
    server.tool(
        "vulnzap.scan_diff",
        "Fast, incremental, non-blocking scan on the current diff. Fire-and-forget: call this and continue coding, then poll results via vulnzap.status.",
        {
            repo: z.string().optional().default(".").describe("Path to the repo, usually '.'"),
            since: z.string().optional().default("HEAD").describe("Commit or ref to diff against, usually 'HEAD'"),
            paths: z.array(z.string()).optional().describe("Optional array of glob patterns to limit scope")
        },
        async ({ repo, since, paths }) => {
            try {
                // Ensure client is initialized
                const client = await initializeClient();

                // Check if it's a git repository
                if (!isGitRepository(repo)) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    error: "Not a git repository",
                                    message: `The path "${repo}" is not a git repository. Please run this tool from within a git repository.`
                                }, null, 2)
                            }
                        ]
                    };
                }

                // Auto-detect commit hash
                const commitHash = getCurrentCommitHash(repo) || since;
                if (!commitHash) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    error: "Could not determine commit hash",
                                    message: "Unable to get commit hash. Ensure you're in a git repository with commits."
                                }, null, 2)
                            }
                        ]
                    };
                }

                // Get diff files
                const files = getDiffFiles(since, repo, paths);
                if (files.length === 0) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    scan_id: null,
                                    queued: false,
                                    message: "No files changed in diff",
                                    summary: {
                                        files_considered: 0,
                                        mode: "diff"
                                    }
                                }, null, 2)
                            }
                        ]
                    };
                }

                // Get repository URL and user identifier
                const repository = getRepositoryUrl(repo) || undefined;
                const userIdentifier = getUserIdentifier(repo) || 'unknown';

                // Start commit scan
                const response = await client.scanCommit({
                    commitHash,
                    repository,
                    branch: getCurrentBranch(repo) || undefined,
                    files: files.map(f => ({
                        name: f.name,
                        content: f.content
                    })),
                    userIdentifier
                });

                // Generate scan_id and register scan
                const jobId = response.data.jobId;
                const scan_id = generateScanId(jobId, 'diff');
                scanState.registerScan({
                    scan_id,
                    jobId,
                    type: 'diff',
                    timestamp: Date.now(),
                    repo: repository || repo,
                    commitHash
                });

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                scan_id,
                                queued: true,
                                eta_ms: 8000, // Rough estimate for diff scans
                                next_hint: "call vulnzap.status with scan_id",
                                summary: {
                                    files_considered: files.length,
                                    mode: "diff"
                                }
                            }, null, 2)
                        }
                    ]
                };
            } catch (error: any) {
                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                error: error.message || "Unknown error",
                                message: `Failed to start diff scan: ${error.message}`
                            }, null, 2)
                        }
                    ]
                };
            }
        }
    );

    // Tool 2: vulnzap.status
    server.tool(
        "vulnzap.status",
        "Get the latest results for a scan or for the latest scan. This is how the agent finds out whether the last diff or full scan had vulnerabilities.",
        {
            scan_id: z.string().optional().describe("Explicit scan_id to check"),
            latest: z.boolean().optional().describe("Get status of latest scan for this repo")
        },
        async ({ scan_id, latest }) => {
            try {
                const client = await initializeClient();

                let targetScanId: string | undefined;
                let scanMetadata;

                if (latest) {
                    // Get latest scan for current repo
                    const repo = getRepositoryUrl() || ".";
                    scanMetadata = scanState.getLatestScan(repo);
                    if (!scanMetadata) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: false,
                                        message: "No scan found for this repository. Run vulnzap.scan_diff or vulnzap.full_scan first."
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                    targetScanId = scanMetadata.scan_id;
                } else if (scan_id) {
                    scanMetadata = scanState.getScan(scan_id);
                    if (!scanMetadata) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: false,
                                        message: `Scan ${scan_id} not found. It may have expired or never existed.`
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                    targetScanId = scan_id;
                } else {
                    // Default to latest
                    const repo = getRepositoryUrl() || ".";
                    scanMetadata = scanState.getLatestScan(repo);
                    if (!scanMetadata) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: false,
                                        message: "No scan found. Provide scan_id or use latest: true"
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                    targetScanId = scanMetadata.scan_id;
                }

                if (!scanMetadata || !targetScanId) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    ready: false,
                                    message: "Could not determine scan to check"
                                }, null, 2)
                            }
                        ]
                    };
                }

                // Try to get completed scan results from client cache/API
                try {
                    const results = await client.getCompletedCommitScan(scanMetadata.jobId);
                    
                    // Check if scan is completed and has results
                    if (results.status === 'completed' && results.results) {
                        // Extract findings from results (structure may vary)
                        const findings = results.results.findings || results.results || [];
                        const open_issues = transformFindings(findings);
                        const counts = calculateCounts(findings);

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: true,
                                        open_issues,
                                        counts,
                                        next_hint: "fix issues, then call scan_diff again before next commit"
                                    }, null, 2)
                                }
                            ]
                        };
                    } else {
                        // Still running
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: false,
                                        poll_after_ms: 5000
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                } catch (error: any) {
                    // Scan might still be running or not found
                    // Check if it's a 404 (not found/not ready) vs other error
                    if (error.message?.includes('404') || error.message?.includes('not found')) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: false,
                                        poll_after_ms: 5000
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                    throw error;
                }
            } catch (error: any) {
                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                ready: false,
                                error: error.message || "Unknown error",
                                message: `Failed to get scan status: ${error.message}`
                            }, null, 2)
                        }
                    ]
                };
            }
        }
    );

    // Tool 3: vulnzap.full_scan
    server.tool(
        "vulnzap.full_scan",
        "Baseline scan for the entire repository, used before serious pushes or deploys. Slower than diff scans, use sparingly.",
        {
            repo: z.string().optional().default(".").describe("Repository path"),
            mode: z.string().optional().default("baseline").describe("Scan mode, should be 'baseline'")
        },
        async ({ repo, mode }) => {
            try {
                const client = await initializeClient();

                // Check if it's a git repository
                if (!isGitRepository(repo)) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    error: "Not a git repository",
                                    message: `The path "${repo}" is not a git repository.`
                                }, null, 2)
                            }
                        ]
                    };
                }

                // Get repository URL
                const repository = getRepositoryUrl(repo);
                if (!repository) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    error: "Could not determine repository URL",
                                    message: "Unable to get repository URL from git remote. Ensure origin remote is configured."
                                }, null, 2)
                            }
                        ]
                    };
                }

                const branch = getCurrentBranch(repo) || 'main';
                const userIdentifier = getUserIdentifier(repo) || 'unknown';

                // Start repository scan
                const response = await client.scanRepository({
                    repository,
                    branch,
                    userIdentifier
                });

                // Generate scan_id and register scan
                const jobId = response.data.jobId;
                const scan_id = generateScanId(jobId, 'full');
                scanState.registerScan({
                    scan_id,
                    jobId,
                    type: 'full',
                    timestamp: Date.now(),
                    repo: repository
                });

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                scan_id,
                                queued: true,
                                eta_ms: 180000 // 3 minutes estimate for full scans
                            }, null, 2)
                        }
                    ]
                };
            } catch (error: any) {
                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                error: error.message || "Unknown error",
                                message: `Failed to start full scan: ${error.message}`
                            }, null, 2)
                        }
                    ]
                };
            }
        }
    );

    // Tool 4: vulnzap.report
    server.tool(
        "vulnzap.report",
        "Human readable snapshot of the last scan results. Intended for attaching to PRs or agent logs.",
        {
            scan_id: z.string().describe("Scan ID to generate report for"),
            format: z.string().optional().default("md").describe("Report format, currently only 'md' supported")
        },
        async ({ scan_id, format }) => {
            try {
                const client = await initializeClient();

                const scanMetadata = scanState.getScan(scan_id);
                if (!scanMetadata) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    error: "Scan not found",
                                    message: `Scan ${scan_id} not found`
                                }, null, 2)
                            }
                        ]
                    };
                }

                // Get scan results
                const results = await client.getCompletedCommitScan(scanMetadata.jobId);

                if (results.status !== 'completed' || !results.results) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    error: "Scan not completed",
                                    message: `Scan ${scan_id} is not yet completed. Use vulnzap.status to check progress.`
                                }, null, 2)
                            }
                        ]
                    };
                }

                // Extract findings from results (structure may vary)
                const findings = results.results.findings || results.results || [];

                // Generate markdown report
                let markdown = "## Vulnzap Findings\n\n";
                
                if (findings.length === 0) {
                    markdown += "✅ No vulnerabilities found.\n";
                } else {
                    const counts = calculateCounts(findings);
                    markdown += `### Summary\n\n`;
                    markdown += `- Total findings: ${findings.length}\n`;
                    if (counts.critical) markdown += `- Critical: ${counts.critical}\n`;
                    markdown += `- High: ${counts.high}\n`;
                    markdown += `- Medium: ${counts.medium}\n`;
                    markdown += `- Low: ${counts.low}\n\n`;

                    markdown += `### Details\n\n`;
                    findings.forEach((finding: any, index: number) => {
                        const severity = (finding.severity || 'medium').toUpperCase();
                        markdown += `#### [${severity}] ${finding.file || 'unknown'}:L${finding.line || '?'}\n\n`;
                        markdown += `${finding.message || 'No description'}\n\n`;
                    });
                }

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                markdown
                            }, null, 2)
                        }
                    ]
                };
            } catch (error: any) {
                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                error: error.message || "Unknown error",
                                message: `Failed to generate report: ${error.message}`
                            }, null, 2)
                        }
                    ]
                };
            }
        }
    );
}
