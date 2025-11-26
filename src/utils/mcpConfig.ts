import fs from 'fs';
import path from 'path';
import os from 'os';

/**
 * MCP Configuration Handler for VulnZap
 * Supports VS Code, Cursor, Windsurf, Antigravity, and Claude
 * 
 * Schema differences:
 * - VS Code: uses "servers" key with "type": "stdio"
 * - Cursor, Windsurf, Antigravity, Claude: use "mcpServers" key
 */

export interface MCPServerConfig {
    command: string;
    args: string[];
    type?: string; // Only for VS Code
}

export interface VSCodeMCPConfig {
    inputs?: any[];
    servers: {
        VulnZap: MCPServerConfig;
        [key: string]: MCPServerConfig;
    };
}

export interface GenericMCPConfig {
    mcpServers: {
        VulnZap: MCPServerConfig;
        [key: string]: MCPServerConfig;
    };
}

export function createMCPServerConfig(ide: string): MCPServerConfig {
    const config: MCPServerConfig = {
        command: 'npx',
        args: ['vulnzap', 'mcp']
    };

    // VS Code requires type field
    if (ide === 'vscode') {
        config.type = 'stdio';
    }

    return config;
}

/**
 * Get the appropriate JSON schema key for an IDE
 */
export function getSchemaKey(ide: string): 'servers' | 'mcpServers' {
    // Only VS Code uses 'servers', all others use 'mcpServers'
    return ide === 'vscode' ? 'servers' : 'mcpServers';
}

/**
 * Merge VulnZap config into existing config without overwriting other servers
 */
export function mergeVulnZapConfig(existingConfig: any, apiKey: string, ide: string): any {
    const schemaKey = getSchemaKey(ide);
    const serverConfig = createMCPServerConfig(ide);

    // Ensure the config object exists
    const config = existingConfig || {};

    if (!config[schemaKey] || typeof config[schemaKey] !== 'object') {
        config[schemaKey] = {};
    }

    // Add/update VulnZap server (only if not already present or needs update)
    config[schemaKey].VulnZap = serverConfig;

    // For VS Code schema, ensure inputs array exists
    if (schemaKey === 'servers') {
        config.inputs = config.inputs || [];
    }

    return config;
}

/**
 * Read and parse config file, backing up corrupted files
 */
export function readConfigFile(configPath: string): any | null {
    if (!fs.existsSync(configPath)) {
        return null;
    }

    try {
        const content = fs.readFileSync(configPath, 'utf8');
        return JSON.parse(content);
    } catch (e) {
        // Backup corrupted file
        const backupPath = `${configPath}.bak.${Date.now()}`;
        try {
            fs.renameSync(configPath, backupPath);
            console.warn(`Corrupted config backed up to: ${backupPath}`);
        } catch (backupError) {
            console.warn(`Could not backup corrupted config: ${backupError}`);
        }
        return null;
    }
}

/**
 * Write config to file
 */
export function writeConfigFile(configPath: string, config: any): void {
    const configDir = path.dirname(configPath);

    // Ensure directory exists
    if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true, mode: 0o755 });
    }

    // Write file
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), {
        encoding: 'utf8',
        mode: 0o644
    });
}

/**
 * Get MCP config path for a given IDE and scope
 * @param ide - IDE name (vscode, cursor, windsurf, antigravity, claude)
 * @param scope - 'workspace' or 'global' (only vscode and cursor support workspace)
 * @returns Config file path or null if not supported
 */
export function getMcpConfigPath(ide: string, scope: 'workspace' | 'global' = 'global'): string | null {
    const homeDir = os.homedir();
    const cwd = process.cwd();
    const platform = os.platform();

    switch (ide) {
        case 'vscode':
            if (scope === 'workspace') {
                return path.join(cwd, '.vscode', 'mcp.json');
            }
            // Global - use CLI command instead, return null
            return null;

        case 'cursor':
            if (scope === 'workspace') {
                return path.join(cwd, '.cursor', 'mcp.json');
            }
            return path.join(homeDir, '.cursor', 'mcp.json');

        case 'windsurf':
            // Windsurf only supports global
            if (scope === 'workspace') {
                return null;
            }
            return path.join(homeDir, '.codeium', 'windsurf', 'mcp_config.json');

        case 'antigravity':
            // Antigravity only supports global
            if (scope === 'workspace') {
                return null;
            }
            return path.join(homeDir, '.gemini', 'antigravity', 'mcp_config.json');

        case 'claude':
            // Claude only supports global
            if (scope === 'workspace') {
                return null;
            }
            if (platform === 'darwin') {
                return path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
            } else if (platform === 'win32') {
                return path.join(process.env.APPDATA || path.join(homeDir, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json');
            } else {
                return path.join(homeDir, '.claude.json');
            }

        default:
            return null;
    }
}

/**
 * Check if an IDE supports workspace configuration
 */
export function supportsWorkspaceConfig(ide: string): boolean {
    return ['vscode', 'cursor'].includes(ide);
}

/**
 * Install MCP configuration for a given IDE
 * @param ide - IDE name
 * @param scope - 'workspace' or 'global'
 * @param apiKey - API key (optional, not used in new config format)
 * @returns Object with success status and config path
 */
export function installMcpConfig(
    ide: string,
    scope: 'workspace' | 'global' = 'global',
    apiKey?: string
): { success: boolean; configPath: string | null; message: string } {
    // Validate scope for IDE
    if (scope === 'workspace' && !supportsWorkspaceConfig(ide)) {
        return {
            success: false,
            configPath: null,
            message: `${ide} does not support workspace configuration. Use global scope instead.`
        };
    }

    const configPath = getMcpConfigPath(ide, scope);

    if (!configPath) {
        // VS Code global uses CLI command
        if (ide === 'vscode' && scope === 'global') {
            return {
                success: false,
                configPath: null,
                message: 'VS Code global configuration should use CLI command: code --add-mcp'
            };
        }

        return {
            success: false,
            configPath: null,
            message: `Could not determine config path for ${ide} with scope ${scope}`
        };
    }

    try {
        // Read existing config
        let config = readConfigFile(configPath);

        // Merge VulnZap configuration (apiKey is ignored in new format)
        config = mergeVulnZapConfig(config, apiKey || '', ide);

        // Write configuration
        writeConfigFile(configPath, config);

        return {
            success: true,
            configPath,
            message: `Successfully installed VulnZap MCP configuration for ${ide}`
        };
    } catch (error: any) {
        return {
            success: false,
            configPath,
            message: `Failed to install MCP configuration: ${error.message}`
        };
    }
}

/**
 * Check if VulnZap MCP is already installed for an IDE
 */
export function isMcpInstalled(ide: string, scope: 'workspace' | 'global' = 'global'): boolean {
    const configPath = getMcpConfigPath(ide, scope);

    if (!configPath || !fs.existsSync(configPath)) {
        return false;
    }

    try {
        const config = readConfigFile(configPath);
        if (!config) return false;

        const schemaKey = getSchemaKey(ide);
        return !!(config[schemaKey]?.VulnZap);
    } catch (e) {
        return false;
    }
}
