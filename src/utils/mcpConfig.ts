import fs from 'fs';
import path from 'path';
import os from 'os';

/**
 * GitHub Copilot MCP Configuration Handler
 * Supports VS Code, Cursor, Windsurf, and JetBrains IDEs
 * 
 * Schema differences:
 * - VS Code/Cursor: use "servers" key
 * - Windsurf/JetBrains/Antigravity/Claude: use "mcpServers" key
 */

export interface MCPServerConfig {
    command: string;
    args: string[];
    env: {
        VULNZAP_API_KEY: string;
    };
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

export function createMCPServerConfig(apiKey: string): MCPServerConfig {
    return {
        command: 'npx',
        args: ['vulnzap', 'mcp'],
        env: {
            VULNZAP_API_KEY: apiKey
        }
    };
}

/**
 * Get the appropriate JSON schema key for an IDE
 */
export function getSchemaKey(ide: string): 'servers' | 'mcpServers' {
    const usesServersKey = ['vscode'];
    return usesServersKey.includes(ide) ? 'servers' : 'mcpServers';
}

/**
 * Merge VulnZap config into existing config without overwriting other servers
 */
export function mergeVulnZapConfig(existingConfig: any, apiKey: string, ide: string): any {
    const schemaKey = getSchemaKey(ide);
    const serverConfig = createMCPServerConfig(apiKey);

    // Ensure the config object  exists
    const config = existingConfig || {};

    if (!config[schemaKey] || typeof config[schemaKey] !== 'object') {
        config[schemaKey] = {};
    }

    // Add/update VulnZap server
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
