import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
import { execSync } from 'child_process';
import {
    installMcpConfig,
    supportsWorkspaceConfig,
    isMcpInstalled as checkMcpInstalled,
    getMcpConfigPath
} from './mcpConfig.js';
import { typography, layout } from './typography.js';

/**
 * Enhanced inquirer with custom styling
 */
const customPrompts = {
    ...inquirer,
    prompt: (questions: any) => inquirer.prompt(questions.map((q: any) => ({
        ...q,
        prefix: chalk.gray('›'),
    }))),
};

/**
 * Create a styled spinner
 */
const createSpinner = (text: string) => {
    return ora({
        text: chalk.gray(text),
        spinner: 'dots2',
        color: 'gray',
    });
};

/**
 * Get display name for an IDE
 */
function getIdeDisplayName(ide: string): string {
    const names: Record<string, string> = {
        'vscode': 'VS Code',
        'cursor': 'Cursor IDE',
        'windsurf': 'Windsurf IDE',
        'antigravity': 'Antigravity',
        'claude': 'Claude Code'
    };
    return names[ide] || ide;
}

/**
 * Detect installed IDEs on the system
 */
export async function detectInstalledIDEs(): Promise<string[]> {
    const installedIDEs: string[] = [];
    const supportedIDEs = [
        { name: 'vscode', command: 'code' },
        { name: 'cursor', command: 'cursor' },
        { name: 'windsurf', command: 'windsurf' }
    ];

    for (const ide of supportedIDEs) {
        try {
            execSync(`${ide.command} --version`, { stdio: 'pipe' });
            installedIDEs.push(ide.name);
        } catch (error) {
            // IDE not found in PATH
        }
    }

    // Always add these as options even if not auto-detected
    const alwaysAvailable = ['antigravity', 'claude'];
    for (const ide of alwaysAvailable) {
        if (!installedIDEs.includes(ide)) {
            installedIDEs.push(ide);
        }
    }

    return installedIDEs;
}

/**
 * Display manual configuration instructions
 */
function displayManualConfig(scope: 'workspace' | 'global') {
    layout.section();
    console.log(typography.header('Manual Configuration'));
    layout.spacer();

    console.log(typography.accent('For manual setup, add this to your IDE config:'));
    layout.spacer();

    if (scope === 'workspace') {
        console.log(typography.dim('VS Code (.vscode/mcp.json):'));
        console.log(typography.code(`{
  "servers": {
    "VulnZap": {
      "type": "stdio",
      "command": "npx",
      "args": ["vulnzap", "mcp"]
    }
  },
  "inputs": []
}`));
        layout.spacer();

        console.log(typography.dim('Cursor (.cursor/mcp.json):'));
        console.log(typography.code(`{
  "mcpServers": {
    "VulnZap": {
      "command": "npx",
      "args": ["vulnzap", "mcp"]
    }
  }
}`));
    } else {
        console.log(typography.dim('For all IDEs (except VS Code):'));
        console.log(typography.code(`{
  "mcpServers": {
    "VulnZap": {
      "command": "npx",
      "args": ["vulnzap", "mcp"]
    }
  }
}`));
        layout.spacer();

        console.log(typography.dim('VS Code Global:'));
        console.log(typography.code(`code --add-mcp '{"name":"VulnZap","command":"npx","args":["vulnzap","mcp"],"enabled":true}'`));
        layout.spacer();

        console.log(typography.dim('Claude CLI:'));
        console.log(typography.code(`claude mcp add --transport stdio vulnzap -- npx vulnzap mcp`));
    }

    layout.spacer();
    console.log(typography.dim('See full documentation at: https://vulnzap.com/docs/mcp'));
    layout.section();
}

/**
 * Configure MCP for VS Code using CLI command
 */
async function configureVSCodeGlobal(): Promise<{ success: boolean; configPath: string | null; message: string }> {
    try {
        const command = `code --add-mcp '{"name":"VulnZap","command":"npx","args":["vulnzap","mcp"],"enabled":true}'`;
        execSync(command, { stdio: 'pipe' });
        return {
            success: true,
            configPath: null,
            message: 'VS Code global MCP configuration added successfully'
        };
    } catch (error: any) {
        return {
            success: false,
            configPath: null,
            message: `Failed to configure VS Code: ${error.message}`
        };
    }
}

/**
 * Configure MCP for Claude using CLI command
 */
async function configureClaudeCLI(): Promise<{ success: boolean; configPath: string | null; message: string }> {
    try {
        // First check if vulnzap is already configured
        try {
            const listOutput = execSync('claude mcp list', { encoding: 'utf8' });
            if (listOutput.includes('vulnzap')) {
                return {
                    success: true,
                    configPath: null,
                    message: 'VulnZap already configured in Claude'
                };
            }
        } catch (e) {
            // claude CLI might not be available, fall back to file-based config
            return {
                success: false,
                configPath: null,
                message: 'Claude CLI not available, using file-based configuration'
            };
        }

        // Add the server
        const command = 'claude mcp add --transport stdio vulnzap -- npx vulnzap mcp';
        execSync(command, { stdio: 'pipe' });
        return {
            success: true,
            configPath: null,
            message: 'Claude MCP configuration added successfully'
        };
    } catch (error: any) {
        return {
            success: false,
            configPath: null,
            message: `Failed to configure Claude CLI: ${error.message}`
        };
    }
}

/**
 * Interactive MCP configuration flow
 * This is the main function used by both init and connect commands
 */
export async function configureMcpInteractive(): Promise<{ configured: number; skipped: boolean }> {
    layout.section();
    console.log(typography.accent('MCP Configuration'));
    layout.spacer();

    // Step 1: Ask for scope (workspace or global)
    const { scope } = await customPrompts.prompt([
        {
            type: 'list',
            name: 'scope',
            message: 'Configuration scope:',
            choices: [
                {
                    name: 'Workspace (this project only) - Recommended for teams',
                    value: 'workspace'
                },
                {
                    name: 'Global (all projects) - Recommended for personal use',
                    value: 'global'
                }
            ],
            default: 'global'
        }
    ]);

    // Step 2: Detect installed IDEs
    const spinner = createSpinner('Detecting installed IDEs...');
    spinner.start();
    const allIDEs = await detectInstalledIDEs();
    spinner.stop();

    // Step 3: Filter IDEs based on scope
    let availableIDEs: string[];
    if (scope === 'workspace') {
        availableIDEs = allIDEs.filter(ide => supportsWorkspaceConfig(ide));
        if (availableIDEs.length === 0) {
            console.log(typography.warning('No IDEs support workspace configuration'));
            console.log(typography.dim('Only VS Code and Cursor support workspace configs'));
            displayManualConfig(scope);
            return { configured: 0, skipped: true };
        }
    } else {
        availableIDEs = allIDEs;
    }

    // Step 4: Show IDE selection
    const ideChoices = availableIDEs.map(ide => {
        const isInstalled = checkMcpInstalled(ide, scope);
        const installedTag = isInstalled ? chalk.green(' ✓ Configured') : '';
        return {
            name: `${getIdeDisplayName(ide)}${installedTag}`,
            value: ide,
            checked: !isInstalled
        };
    });

    // Add skip option
    ideChoices.push({
        name: chalk.dim('Skip - Show manual configuration instead'),
        value: '__skip__',
        checked: false
    });

    const { selectedIDEs } = await customPrompts.prompt([
        {
            type: 'checkbox',
            name: 'selectedIDEs',
            message: `Select IDEs to configure (${scope}):`,
            choices: ideChoices
        }
    ]);

    // Handle skip
    if (selectedIDEs.includes('__skip__') || selectedIDEs.length === 0) {
        displayManualConfig(scope);
        return { configured: 0, skipped: true };
    }

    // Step 5: Configure each selected IDE
    let configuredCount = 0;
    for (const ide of selectedIDEs) {
        layout.spacer();
        console.log(typography.accent(`Configuring ${getIdeDisplayName(ide)}...`));

        const mcpSpinner = createSpinner(`Installing MCP configuration...`);
        mcpSpinner.start();

        try {
            let result;

            // Special handling for VS Code global
            if (ide === 'vscode' && scope === 'global') {
                result = await configureVSCodeGlobal();
            }
            // Special handling for Claude (try CLI first)
            else if (ide === 'claude' && scope === 'global') {
                result = await configureClaudeCLI();
                // If CLI fails, fall back to file-based config
                if (!result.success) {
                    result = installMcpConfig(ide, scope);
                }
            }
            // Standard file-based configuration
            else {
                result = installMcpConfig(ide, scope);
            }

            if (result.success) {
                mcpSpinner.succeed(typography.success(`${getIdeDisplayName(ide)} configured`));
                if (result.configPath) {
                    console.log(typography.dim(`  Config: ${result.configPath}`));
                }
                configuredCount++;
            } else {
                mcpSpinner.fail(typography.warning(`${getIdeDisplayName(ide)} configuration failed`));
                console.log(typography.dim(`  ${result.message}`));
            }
        } catch (error: any) {
            mcpSpinner.fail(typography.error(`Failed to configure ${getIdeDisplayName(ide)}`));
            console.error(typography.dim(`  Error: ${error.message}`));
        }
    }

    // Step 6: Show next steps
    if (configuredCount > 0) {
        layout.section();
        console.log(typography.success(`Successfully configured ${configuredCount} IDE${configuredCount > 1 ? 's' : ''}`));
        layout.spacer();
        console.log(typography.accent('Next Steps:'));
        console.log(typography.dim('  1. Restart your IDE(s)'));
        console.log(typography.dim('  2. VulnZap MCP tools will be available in your AI assistant'));
        console.log(typography.dim('  3. Start coding with security superpowers!'));
        layout.section();
    }

    return { configured: configuredCount, skipped: false };
}
