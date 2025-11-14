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
import { VulnzapClient } from "@vulnzap/client";

// Load environment variables
dotenv.config();

// Get package version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
const version = packageJson.version;

// Use createRequire to import @vulnzap/client (it only has require exports)
const require = createRequire(import.meta.url);

// Global VulnzapClient instance
let vulnzapClient: VulnzapClient | null = null;

async function initializeClient(): Promise<VulnzapClient> {
    if (vulnzapClient) return vulnzapClient;
    const apiKey = await getKey();
    vulnzapClient = new VulnzapClient({ apiKey });

    return vulnzapClient;
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
    vulnzapClient = await initializeClient();

    if (!vulnzapClient) {
        console.error('Failed to initialize VulnzapClient');
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
    server.registerTool(
        'vulnzap.scan_diff',
        {
            title: "Scan the current diff",
            description: "Fast, incremental, non-blocking scan on the current diff. Fire-and-forget: call this and continue coding, then poll results via vulnzap.status.",
            inputSchema: z.object({
                repo: z.string().describe("Path to the repo"),
                since: z.string().optional().default("HEAD").describe("Commit or ref to diff against, usually 'HEAD'"),
                paths: z.array(z.string()).optional().describe("Optional array of glob patterns to limit scope")
            })
        },
        async ({ repo, since = 'HEAD', paths = [] }) => {
            try {
                if (!vulnzapClient) {
                    console.error('Failed to initialize VulnzapClient');
                    process.exit(1);
                }

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
                const files = getDiffFiles(since || '', repo || '', paths || []);
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

                const userIdentifier = getUserIdentifier(repo) || 'unknown';

                // Start commit scan
                const response = await vulnzapClient.scanCommit({
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
                const scan_id = jobId;
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
                                next_hint: "call vulnzap.status with scan_id before your next commit",
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
    server.registerTool(
        'vulnzap.status',
        {
            title: "Get the latest results for a scan or for the latest scan",
            description: "Get the latest results for a scan or for the latest scan. This is how the agent finds out whether the last diff or full scan had vulnerabilities.",
            inputSchema: z.object({
                repo: z.string().describe("Path to the repo"),
                scan_id: z.string().optional().describe("Explicit scan_id to check"),
                latest: z.boolean().optional().describe("Get status of latest scan for this repo")
            })
        },
        async ({ repo, scan_id = undefined, latest = false }) => {
            try {
                if (!vulnzapClient) {
                    console.error('Failed to initialize VulnzapClient');
                    process.exit(1);
                }

                let targetScanId: string | undefined;
                let scanMetadata;

                if (latest) {
                    // Get latest scan for current repo
                    const repository = getRepositoryUrl(repo);
                    if (!repository) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: false,
                                        message: "Could not determine repository URL"
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                    scanMetadata = await vulnzapClient.getLatestCachedCommitScan(repository);
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
                    targetScanId = scanMetadata.jobId;
                } else {
                    // Default to latest
                    const repository = getRepositoryUrl(repo);
                    if (!repository) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: false,
                                        message: "Could not determine repository URL, check if you are in a git repository"
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                    scanMetadata = await vulnzapClient.getLatestCachedCommitScan(repository);
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
                    targetScanId = scanMetadata.jobId;
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
                    const results = await vulnzapClient.getCompletedCommitScan(targetScanId);
                    
                    // Check if scan is completed and has results
                    if (results.status === 'completed' && results.results) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        ready: true,
                                        findings: results.results,
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
    server.registerTool(
        'vulnzap.full_scan',
        {
            title: "Baseline scan for the entire repository",
            description: "Baseline scan for the entire repository, used before serious pushes or deploys. Slower than diff scans, use sparingly.",
            inputSchema: z.object({
                repo: z.string().describe("Path to the repo"),
            })
        },
        async ({ repo }) => {
            try {
                if (!vulnzapClient) {
                    console.error('Failed to initialize VulnzapClient');
                    process.exit(1);
                }

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
                const response = await vulnzapClient.scanRepository({
                    repository,
                    branch,
                    userIdentifier
                });

                // Generate scan_id and register scan
                const jobId = response.data.jobId;
                const scan_id = jobId;
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
    server.registerTool(
        'vulnzap.report',
        {
            title: "Human readable snapshot of the last scan results",
            description: "Human readable snapshot of the last scan results. Intended for attaching to PRs or agent logs.",
            inputSchema: z.object({
                repo: z.string().describe("Path to the repo"),
                scan_id: z.string().describe("Scan ID to generate report for")
            })
        },
        async ({ repo, scan_id }) => {
            try {
                if (!vulnzapClient) {
                    console.error('Failed to initialize VulnzapClient');
                    process.exit(1);
                }

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

                const results = await vulnzapClient.getCompletedCommitScan(scan_id);
                if (!results) {
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

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                report: results.results
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
