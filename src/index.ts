/**
 * VulnZap - The Missing Security Layer for AI-Generated Code
 * 
 * This module provides the core functionality for the VulnZap security bridge,
 * which protects AI-generated code from vulnerabilities.
 */

// Third-party imports
import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import axios from 'axios';
import dotenv from 'dotenv';

// Node.js built-in modules
import { fileURLToPath } from 'url';
import path from 'path';

// Local imports
import { checkAuth, getKey } from './api/auth.js';
import config from './config/config.js';
import { extractPackagesFromDirectory } from './utils/packageExtractor.js';
import { batchScan } from './api/batchScan.js';
import { ApiOptions, BatchScanResponse, ScanResponse } from './types/response.js';
import { cacheService } from './services/cache.js';
import { apiRequest } from './utils/apiClient.js';

// Load environment variables
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
	serverIsDown?: boolean;
}

export interface ApiResponse {
	message: string,
	status: number,
	data: any
}

// Local vulnerability check function
async function checkLocalVulnerability(ecosystem: string, packageName: string, version: string): Promise<any> {
	// First try to get from cache
	const cachedResult = cacheService.readCache(packageName, version, ecosystem);
	if (cachedResult) {
		return cachedResult;
	}
	
	// If not in cache, return null to indicate no local data available
	return null;
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
		apiKey: config.apiKey ?? process.env.VULNZAP_API_KEY,
		serverIsDown: config.serverIsDown ?? false
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

				if (!packageName || !ecosystem) {
					return {
						content: [{
							type: "text",
							text: "Please provide the required parameters: packageName and ecosystem"
						}]
					}
				}

				// First try to get from cache
				const cachedResult = cacheService.readCache(packageName, version || 'latest', ecosystem);
				if (cachedResult) {
					if (cachedResult.isVulnerable) {
						let actionLine = '';
						if (cachedResult.fixedVersions && cachedResult.fixedVersions.length > 0) {
							actionLine = `\nAction: Please update your package.json to use ${packageName}@${cachedResult.fixedVersions[0]} and run npm install to mitigate these issues.`;
						} else {
							actionLine = `\nAction: No fixed version is available. Consider using an alternative package or implementing additional security controls as described in the advisories.`;
						}
						return {
							content: [{
								type: "text",
								text: `⚠️ [CACHED] Security Warning: ${packageName}@${version} has known vulnerabilities:\n\n${JSON.stringify(cachedResult.advisories, null, 2)}\n\nRecommendation: ${cachedResult.message}${actionLine}`
							}]
						};
					} else {
						return {
							content: [{
								type: "text",
								text: `✅ [CACHED] ${packageName}@${version || 'latest'} appears to be safe to install.`
							}]
						};
					}
				}

				// If not in cache, try the API
				try {
					const result = await checkVulnerability(ecosystem, packageName, version || 'latest', {
						useCache: true,
						useAi: false
					});

					if (result.isVulnerable) {
						let actionLine = '';
						if (result.fixedVersions && result.fixedVersions.length > 0) {
							actionLine = `\nAction: Please update your package.json to use ${packageName}@${result.fixedVersions[0]} and run npm install to mitigate these issues.`;
						} else {
							actionLine = `\nAction: No fixed version is available. Consider using an latest version of ${packageName} or implementing additional security controls as described in the advisories.`;
						}
						return {
							content: [{
								type: "text",
								text: `⚠️ Security Warning: ${packageName}@${version} has known vulnerabilities:\n\n${JSON.stringify(result.advisories, null, 2)}\n\nRecommendation: ${result.message}${actionLine}`
							}]
						};
					} else if (result.error) {
						return {
							content: [{
								type: "text",
								text: `Error checking vulnerabilities: ${result.error}`
							}]
						};
					} else {
						return {
							content: [{
								type: "text",
								text: `✅ ${packageName}@${version || 'latest'} appears to be safe to install.`
							}]
						};
					}
				} catch (apiError) {
					console.error("API Error:", apiError);
					// If API fails, use local vulnerability database as fallback
					const localResult = await checkLocalVulnerability(ecosystem, packageName, version || 'latest');
					let actionLine = '';
					if (localResult) {
						if (localResult.fixedVersions && localResult.fixedVersions.length > 0) {
							actionLine = `\nAction: Please update your package.json to use ${packageName}@${localResult.fixedVersions[0]} and run npm install to mitigate these issues.`;
						} else {
							actionLine = `\nAction: No fixed version is available. Consider using an latest version of ${packageName} or implementing additional security controls as described in the advisories.`;
						}
						return {
							content: [{
								type: "text",
								text: `[OFFLINE MODE] Using local vulnerability database:\n${JSON.stringify(localResult, null, 2)}\n\nRecommendation: ${localResult.message}${actionLine}`
							}]
						};
					} else {
						return {
							content: [{
								type: "text",
								text: `⚠️ Warning: Unable to check vulnerabilities (network error) and no local data available. Please verify package security manually.`
							}]
						};
					}
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
		"Scan all packages in a directory for vulnerabilities. This tool scans a specified project directory for dependencies (across package.json, requirements.txt, etc.) and performs comprehensive vulnerability analysis on all detected packages. Always provide the absolute/full directory path to ensure correct package detection.",
		{
			parameters: z.object({
				directory: z.string().describe("Full absolute path of the directory to scan for packages (e.g., '/path/to/project' or 'C:\\path\\to\\project')"),
				ecosystem: z.string().optional().describe("Specific ecosystem to scan (npm, pip, go, rust, maven, gradle etc.)")
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
				const apiResponse = await batchScan(packages, {
					useCache: true,
					useAi: false
				});

				// Type guard for apiResponse.data
				const results: any[] = (apiResponse && typeof apiResponse === 'object' && 'data' in apiResponse && Array.isArray((apiResponse as any).data)) ? (apiResponse as any).data : [];

				const formattedResults = results.map((entry: any) => {
					const { package: pkg, result, processedResult } = entry;
					const advisories = [
						...(result.dataSources?.github || []),
						...(result.dataSources?.nvd || []),
						...(result.dataSources?.osv || []),
						...(result.dataSources?.database || [])
					];
					return {
						package: pkg,
						status: result.found ? 'vulnerable' : 'safe',
						message: result.message,
						advisories,
						processedResult,
						remediation: entry.remediation // if present
					};
				});

				const vulnerableCount = formattedResults.filter((r: any) => r.status === 'vulnerable').length;
				const safeCount = formattedResults.filter((r: any) => r.status === 'safe').length;
				const errorCount = formattedResults.filter((r: any) => r.status === 'error').length;

				let report = `# Batch Vulnerability Scan Results\n\n`;
				report += `Scanned ${packages.length} packages\n\n`;
				report += `## Summary\n\n`;
				report += `- 🚨 Vulnerable packages: ${vulnerableCount}\n`;
				report += `- ✅ Safe packages: ${safeCount}\n`;
				report += `- ❌ Errors: ${errorCount}\n\n`;

				if (vulnerableCount > 0) {
					report += `## Vulnerable Packages\n\n`;
					formattedResults
						.filter((r: any) => r.status === 'vulnerable')
						.forEach((result: any) => {
							report += `### ${result.package.packageName}@${result.package.version} (${result.package.ecosystem})\n\n`;
							report += `${result.message}\n\n`;
							if (result.advisories) {
								result.advisories.forEach((vuln: any) => {
									report += `- ${vuln.title || vuln.summary} (${vuln.severity})\n`;
									report += `  ${vuln.description || vuln.summary}\n`;
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
									(result.remediation.alternativePackages as string[]).forEach((pkg: string) => {
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
						text: `Here are the results of the batch scan, summarise it to the user and propose your actions:\n\n${report}`
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

	// Amplify Feature Prompt tool
	server.tool(
		"amplify-feature-prompt",
		"This tool MUST be called automatically whenever the user requests a new feature, application, or development task (e.g., 'build X', 'add Y', 'create Z', 'implement A', etc.).\n\nThe tool takes the user's prompt and project context, then generates a secure, production-grade, best-practices-amplified prompt for the agent to use.\n\nAgents MUST use this tool to transform all high-level feature or development requests before proceeding with any code generation, planning, or implementation.\n\nThis ensures that all outputs follow OWASP Top 10, use up-to-date packages, and adhere to modern security and quality standards.\n\nNever proceed with a user's feature or development request without first calling this tool and using its output as the new prompt.",
		{
			parameters: z.object({
				user_prompt: z.string().describe("The user's feature or application request"),
				context: z.string().optional().describe("Context of the current project or work done, practices followed so far (optional)")
			})
		},
		async ({ parameters }) => {
			const apiKey = await getKey();
			if (!apiKey) {
				return {
					content: [{ type: 'text', text: 'VulnZap API key not configured. Please set VULNZAP_API_KEY environment variable or run vulnzap setup to configure your API key.' }]
				};
			}
			try {
				const { user_prompt, context } = parameters;
				
				const response = await apiRequest(
					`${config.api.baseUrl}${config.api.addOn}${config.api.ai.base}`,
					'POST',
					{ user_prompt, context },
					{ "x-api-key": apiKey }
				);

				if (response.error) {
					return {
						content: [{ type: 'text', text: `Error amplifying prompt: ${response.error}` }]
					};
				}
				
				// Return a dummy amplified prompt response for now
				const amplified = `To build this feature, use this amplified prompt: "${response.amplified_prompt}", and follow these checklist: ${response.checklist}. Make sure you remember this and use it for all future prompts.`;

				return {
					content: [{
						type: "text",
						text: amplified
					}]
				};
			} catch (error: any) {
				return {
					content: [{
						type: "text",
						text: `Error amplifying prompt: ${error.message}`
					}]
				};
			}
		}
	);

	// Add latest_toolset tool
	server.tool(
		"latest_toolset",
		"Given a user prompt describing a new project, and optionally user/agent prescribed tools, return the best-suited tech stack and recommended packages, updating outdated tools and adding new ones as needed.",
		{
			parameters: z.object({
				user_prompt: z.string().describe("The user's project description or feature request"),
				user_tools: z.array(z.string()).optional().describe("Tools/packages the user wants to use (e.g., ['react', 'node 16'])"),
				agent_tools: z.array(z.string()).optional().describe("Tools/packages the agent plans to use (e.g., ['node 16', 'express'])")
			})
		},
		async ({ parameters }) => {
			const apiKey = await getKey();
			if (!apiKey) {
				return {
					content: [{ type: 'text', text: 'VulnZap API key not configured. Please set VULNZAP_API_KEY environment variable or run vulnzap setup to configure your API key.' }]
				};
			}

			const { user_prompt, user_tools = [], agent_tools = [] } = parameters;

			// Check cache first
			const cachedToolset = cacheService.readLatestToolsetCache(user_prompt, user_tools, agent_tools);
			if (cachedToolset) {
				return {
					content: [{ type: 'text', text: `[CACHED] Toolset for "${user_prompt}":\n${JSON.stringify(cachedToolset, null, 2)}` }]
				};
			}
			
			const response = await apiRequest(
				`${config.api.baseUrl}${config.api.addOn}${config.api.tools.base}`,
				'POST',
				{ user_prompt, user_tools, agent_tools },
				{ "x-api-key": apiKey }
			);

			if (response.error) {
				return {
					content: [{ type: 'text', text: `Error getting toolset: ${response.error}` }]
				};
			}

			const data = response.toolset;

			// Store in cache
			cacheService.writeLatestToolsetCache(user_prompt, user_tools, agent_tools, data);

			return {
				content: [{ type: 'text', text: `${JSON.stringify(data, null, 2)}` }]
			};
		}
	);

	// Add get_docs tool
	server.tool(
		"get_docs",
		"Run this tool whenever the agent feels like it lacks documentation for a package. Given a package name and context that package will be used in, returns the best documentation for that package. Caches docs locally for future requests.",
		{
			parameters: z.object({
				package_name: z.string().describe("The npm package or tool name to get docs for. (Format of package_name: ecosystem-packageName-version)"),
				context: z.string().optional().describe("How the tool/package will be used (to return the most relevant docs)")
			})
		},
		async ({ parameters }) => {
			const apiKey = await getKey();
			if (!apiKey) {
				return {
					content: [{ type: 'text', text: 'VulnZap API key not configured. Please set VULNZAP_API_KEY environment variable or run vulnzap setup to configure your API key.' }]
				};
			}

			const { package_name, context } = parameters;
			// Check cache first
			const cachedDocs = cacheService.readDocsCache(package_name);
			if (cachedDocs) {
				return {
					content: [{ type: 'text', text: `[CACHED] Docs for ${package_name}${context ? ` (context: ${context})` : ''}:\n${cachedDocs}` }]
				};
			}
			const response = await apiRequest(
				`${config.api.baseUrl}${config.api.addOn}${config.api.docs.base}`,
				'POST',
				{ package_name, context },
				{ "x-api-key": apiKey }
			);

			if (response.error) {
				return {
					content: [{ type: 'text', text: `Error getting docs: ${response.error}` }]
				};
			}

			const data = response.llm_response;

			// Store in cache
			cacheService.writeDocsCache(package_name, data);
			return {
				content: [{ type: 'text', text: `${JSON.stringify(data, null, 2)}` }]
			};
		}
	);

	// Add milestone-security-check tool
	// server.tool(
	// 	"milestone-security-check",
	// 	"Run security and stress tests at project milestones (e.g., after API implementation). Starts the API server, runs rate-limit, DDoS, and other tests, and reports results.",
	// 	{
	// 		parameters: z.object({
	// 			milestone_name: z.string().describe("Name of the project milestone (e.g., 'API implementation complete')"),
	// 			start_server_command: z.string().describe("Command to start the API server (e.g., 'npm run start:api')"),
	// 			api_base_url: z.string().describe("Base URL of the API server (e.g., 'http://localhost:3000')"),
	// 			test_scripts: z.array(z.string()).optional().describe("List of test scripts/types to run (e.g., ['rate-limit', 'ddos'])")
	// 		})
	// 	},
	// 	async ({ parameters }) => {
	// 		const { milestone_name, start_server_command, api_base_url, test_scripts = ["rate-limit", "ddos"] } = parameters;
	// 		const { spawn } = await import('child_process');
	// 		const axios = (await import('axios')).default;

	// 		let report = `# Milestone Security Check: ${milestone_name}\n`;
	// 		let serverProcess = null;
	// 		let serverStarted = false;
	// 		let serverOutput = '';
	// 		try {
	// 			// Start the API server
	// 			const [cmd, ...args] = start_server_command.split(' ');
	// 			serverProcess = spawn(cmd, args, { shell: true, detached: true });
	// 			serverProcess.stdout.on('data', (data) => { serverOutput += data.toString(); });
	// 			serverProcess.stderr.on('data', (data) => { serverOutput += data.toString(); });

	// 			// Wait for server to be up (poll /health or root endpoint)
	// 			const healthUrl = api_base_url.replace(/\/$/, '') + '/health';
	// 			const maxWait = 20000; // 20s
	// 			const interval = 1000;
	// 			let waited = 0;
	// 			let healthOk = false;
	// 			while (waited < maxWait) {
	// 				try {
	// 					await axios.get(healthUrl, { timeout: 2000 });
	// 					healthOk = true;
	// 					break;
	// 				} catch (e) {
	// 					await new Promise(res => setTimeout(res, interval));
	// 					waited += interval;
	// 				}
	// 			}
	// 			if (!healthOk) {
	// 				report += '\n❌ API server did not respond at ' + healthUrl + ' after 20s.\n';
	// 				if (serverProcess && serverProcess.pid) { process.kill(-serverProcess.pid); }
	// 				return { content: [{ type: 'text', text: report }] };
	// 			}
	// 			serverStarted = true;
	// 			report += '\n✅ API server started and responded at ' + healthUrl + '\n';

	// 			// Run test scripts
	// 			for (const script of test_scripts) {
	// 				if (script === 'rate-limit') {
	// 					report += '\n---\n**Rate-limit Test**\n';
	// 					let rateLimitResult = '';
	// 					try {
	// 						let success = 0, rateLimited = 0, errors = 0;
	// 						for (let i = 0; i < 50; i++) {
	// 							try {
	// 								await axios.get(api_base_url + '/test-rate', { timeout: 1000 });
	// 								success++;
	// 							} catch (err: any) {
	// 								if (err.response && err.response.status === 429) rateLimited++;
	// 								else errors++;
	// 							}
	// 						}
	// 						rateLimitResult = `Requests: 50, Success: ${success}, Rate-limited: ${rateLimited}, Errors: ${errors}`;
	// 						report += rateLimitResult + '\n';
	// 						if (rateLimited > 0) report += '✅ Rate-limiting appears to be enforced.\n';
	// 						else report += '❌ No rate-limiting detected.\n';
	// 					} catch (e: any) {
	// 						report += 'Error during rate-limit test: ' + e.message + '\n';
	// 					}
	// 				}
	// 				else if (script === 'ddos') {
	// 					report += '\n---\n**DDoS Simulation**\n';
	// 					let ddosResult = '';
	// 					try {
	// 						const requests = [];
	// 						for (let i = 0; i < 200; i++) {
	// 							requests.push(axios.get(api_base_url + '/test-ddos', { timeout: 1000 }).catch(e => e));
	// 						}
	// 						const results = await Promise.all(requests);
	// 						const ok = results.filter(r => r.status && r.status < 500).length;
	// 						const errors = results.length - ok;
	// 						ddosResult = `Requests: 200, Success: ${ok}, Errors: ${errors}`;
	// 						report += ddosResult + '\n';
	// 						if (errors > 0) report += '⚠️ Some requests failed under load.\n';
	// 						else report += '✅ Server handled DDoS simulation.\n';
	// 					} catch (e: any) {
	// 						report += 'Error during DDoS test: ' + e.message + '\n';
	// 					}
	// 				}
	// 				else {
	// 					report += `\n---\nUnknown test script: ${script}\n`;
	// 				}
	// 			}
	// 		} finally {
	// 			// Write the report to a log file in the API server directory
	// 			try {
	// 				const fs = await import('fs');
	// 				const path = await import('path');
	// 				const os = await import('os');
	// 				// Try to infer the working directory from the start_server_command (first arg is usually the script)
	// 				let homeDir = os.homedir();
	// 				const logPath = path.join(homeDir, '.vulnzap', 'milestone-security-report.log');
	// 				fs.writeFileSync(logPath, report, 'utf-8');
	// 				console.log(`Milestone security report written to: ${logPath}`);
	// 			} catch (e: any) {
	// 				console.error('Failed to write milestone security report log:', e.message);
	// 			}
	// 			// Clean up: kill server process if started
	// 			if (serverProcess && serverStarted && serverProcess.pid) {
	// 				try {
	// 					// Check if process is still running before killing
	// 					process.kill(-serverProcess.pid, 0); // throws if not running
	// 					process.kill(-serverProcess.pid);
	// 				} catch (e: any) {
	// 					if (e.code !== 'ESRCH') {
	// 						report += `\n(Server process stop error: ${e.message})\n`;
	// 					}
	// 				}
	// 				report += '\n(Server process stopped)\n';
	// 			}
	// 		}
	// 		return { content: [{ type: 'text', text: report }] };
	// 	}
	// );
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
	packageVersion: string,
	options: ApiOptions
): Promise<any> {
	try {
		// Check cache first
		if (options.useCache) {
			const cachedResult = cacheService.readCache(packageName, packageVersion, ecosystem);
			if (cachedResult) {
				return {
					...cachedResult,
					fromCache: true
				};
			}
		}

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

		// Fetch vulnerabilities from the API using apiRequest
		const response = await apiRequest(
			`${config.api.baseUrl}${config.api.addOn}${config.api.vulnerability.check}`,
			'POST',
			{
				ecosystem,
				packageName,
				version: packageVersion,
				noCache: !options.useCache,
				useAi: options.useAi
			},
			{
				"x-api-key": apiKey
			}
		);

		// Extract vulnerability data from response
		const data: ScanResponse = response.data;

		// Prepare result
		let result;

		// If no vulnerabilities found
		if (data.status === "safe") {
			result = {
				isVulnerable: false,
				message: `No known vulnerabilities found for ${packageName}@${packageVersion}`,
				sources: data.processedVulnerabilities?.sources || []
			};
		} else {
			// Convert vulnerabilities to advisories format
			const advisories = [
				...(data.vulnerabilities?.github || []),
				...(data.vulnerabilities?.nvd || []),
				...(data.vulnerabilities?.osv || []),
				...(data.vulnerabilities?.database || [])
			];
			const advisoriesList = advisories.map((vuln: any) => {
				return {
					title: vuln.title || vuln.summary,
					description: vuln.description || vuln.summary,
					severity: vuln.severity || 'unknown',
					references: vuln.references || [],
					cveId: vuln.cveId,
					ghsaId: vuln.ghsaId,
					cveStatus: vuln.cveStatus,
					ghsaStatus: vuln.ghsaStatus,
					firstPatchedVersion: vuln.firstPatchedVersion,
					publishedAt: vuln.publishedAt,
					updatedAt: vuln.updatedAt
				};
			});

			const sources = []
			if (data.vulnerabilities?.database?.length && data.vulnerabilities.database.length > 0) {
				sources.push("database")
			}
			if (data.vulnerabilities?.github?.length && data.vulnerabilities.github.length > 0) {
				sources.push("github")
			}
			if (data.vulnerabilities?.nvd?.length && data.vulnerabilities.nvd.length > 0) {
				sources.push("nvd")
			}
			if (data.vulnerabilities?.osv?.length && data.vulnerabilities.osv.length > 0) {
				sources.push("osv")
			}

			result = {
				isVulnerable: true,
				advisories: advisoriesList,
				fixedVersions: data.remediation?.recommendedVersion ? [data.remediation.recommendedVersion] : undefined,
				processedVulnerabilities: data.processedVulnerabilities,
				message: data.remediation ?
					`Update to ${data.remediation.recommendedVersion} to fix vulnerabilities. ${data.remediation.notes ? data.remediation.notes : ''} ${advisories.length} vulnerabilities in ${packageName}@${packageVersion}` :
					`${advisories.length} vulnerabilities in ${packageName}@${packageVersion}`,
				sources: sources
			};
		}

		// Cache the result
		cacheService.writeCache(packageName, packageVersion, ecosystem, result);

		return result;

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

export async function checkBatch(
	packages: {
		packageName: string,
		ecosystem: string,
		version: string
	}[]
) {
	try {
		// Check cache for each package first
		const results = await Promise.all(packages.map(async (pkg) => {
			const cachedResult = cacheService.readCache(pkg.packageName, pkg.version, pkg.ecosystem);
			if (cachedResult) {
				return {
					package: pkg,
					...cachedResult,
					fromCache: true
				};
			}
			return null;
		}));

		// Filter out packages that need to be checked
		const uncachedPackages = packages.filter((pkg, index) => !results[index]);

		if (uncachedPackages.length === 0) {
			return {
				results: results.filter((r: any) => r !== null),
				message: `All results retrieved from cache.`
			};
		}

		// Validate API key presence
		const apiKey = await getKey();
		if (!apiKey) {
			return {
				isVulnerable: false,
				error: 'VulnZap API key not configured. Please set VULNZAP_API_KEY environment variable.',
				isUnknown: true
			};
		}

		const { success } = await checkAuth();

		if (!success) {
			return {
				message: "User not authenticated",
				data: null
			}
		}

		const response = await apiRequest(
			`${config.api.baseUrl}${config.api.addOn}${config.api.vulnerability.batch}`,
			'POST',
			{ packages: uncachedPackages },
			{ "x-api-key": apiKey }
		);

		// The new API response format:
		// { message, status, data: [ { package, result, processedResult } ] }
		const data: any[] = (response && typeof response === 'object' && 'data' in response && Array.isArray((response as any).data)) ? (response as any).data : [];

		const apiResults = data.map((entry: any) => {
			const { package: pkg, result, processedResult } = entry;
			const advisories = [
				...(result.dataSources?.github || []),
				...(result.dataSources?.nvd || []),
				...(result.dataSources?.osv || []),
				...(result.dataSources?.database || [])
			];
			return {
				package: pkg,
				status: result.found ? 'vulnerable' : 'safe',
				message: result.message,
				advisories,
				processedResult
			};
		});

		// Combine cached and new results
		const finalResults = results.map((r: any, i: number) => r || apiResults[i]);

		return {
			results: finalResults,
			message: `Batch scan completed for ${packages.length} packages.`
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
