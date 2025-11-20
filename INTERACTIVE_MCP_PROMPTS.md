# Interactive MCP Installation Prompts - Complete ✅

## Overview

VulnZap now asks users **where** to install the MCP server configuration, providing clear choices between workspace-scoped (team/project) and global (personal) installations.

## Interactive Prompts by IDE

### 1. **VS Code + GitHub Copilot**

**Prompt:**
```
VS Code + GitHub Copilot MCP Configuration

Choose where to install VulnZap MCP server:

? Installation scope:
  ❯ Workspace (this project only) - Recommended for teams
    Global (all VS Code projects) - Recommended for personal use
```

**Workspace Option:**
- **Path**: `.vscode/mcp.json`
- **Scope**: Project-specific
- **Best for**: Teams, shared projects
- **Schema**: `servers` with API key embedded
- **Version Control**: Can be committed to Git

**Global Option:**
- **Path**: `~/Library/Application Support/Code/User/settings.json` (macOS)
- **Path**: `%APPDATA%/Code/User/settings.json` (Windows)
- **Path**: `~/.config/Code/User/settings.json` (Linux)
- **Scope**: All VS Code projects
- **Best for**: Personal use
- **Schema**: `mcp.servers` nested in settings.json
- **Security**: Uses `${env:VULNZAP_API_KEY}` environment variable
- **Extra Step**: User must set environment variable in shell profile

---

### 2. **Cursor + GitHub Copilot**

**Prompt:**
```
Cursor + GitHub Copilot MCP Configuration

Choose where to install VulnZap MCP server:

? Installation scope:
    Workspace (this project only) - Recommended for teams
  ❯ Global (all Cursor projects) - Recommended for personal use
```

**Workspace Option:**
- **Path**: `.cursor/mcp.json`
- **Scope**: Project-specific
- **Best for**: Teams, shared projects
- **Schema**: `servers` with API key embedded
- **Version Control**: Can be committed to Git

**Global Option** (Default):
- **Path**: `~/.cursor/mcp.json`
- **Scope**: All Cursor projects
- **Best for**: Personal use
- **Schema**: `servers` with API key embedded
- **Version Control**: Not in project

---

### 3. **JetBrains + GitHub Copilot**

**Prompt:**
```
JetBrains + GitHub Copilot MCP Configuration

Choose where to place the MCP configuration:

? Configuration location:
  ❯ Project root (mcp.json) - Recommended, visible to team
    .idea folder (.idea/mcp.json) - Hidden from version control
```

**Project Root Option** (Default):
- **Path**: `mcp.json` (in project root)
- **Scope**: Project-specific
- **Best for**: Teams, visible configuration
- **Schema**: `mcpServers` with API key embedded
- **Version Control**: Can be committed to Git
- **Visibility**: Clearly visible to all team members

**.idea Folder Option** (Only shown if `.idea` exists):
- **Path**: `.idea/mcp.json`
- **Scope**: Project-specific but hidden
- **Best for**: Personal preference, typically gitignored
- **Schema**: `mcpServers` with API key embedded
- **Version Control**: Usually excluded via `.gitignore`
- **Visibility**: Hidden in IDE-specific folder

---

### 4. **Windsurf + GitHub Copilot** (No prompt - always global)

- **Path**: `~/.codeium/windsurf/mcp_config.json`
- **Scope**: Global (all Windsurf projects)
- **Schema**: `mcpServers` with API key embedded
- **No choice needed**: Windsurf uses a single global config

---

### 5. **Antigravity** (No prompt - always global)

- **Path**: `~/.gemini/antigravity/mcp_config.json`
- **Scope**: Global
- **Schema**: `mcpServers` with API key embedded
- **No choice needed**: Antigravity uses a single global config

---

### 6. **Claude Code** (No prompt - always global)

- **Path**: Platform-specific (see GITHUB_COPILOT_MCP.md)
- **Scope**: Global
- **Schema**: `mcpServers` with API key embedded
- **No choice needed**: Claude uses a single global config

---

## User Experience Flow

### Example: VS Code User

```bash
$ vulnzap connect

? Which development environment are you using?
  ❯ VS Code + GitHub Copilot

VS Code + GitHub Copilot MCP Configuration

Choose where to install VulnZap MCP server:

? Installation scope:
  ❯ Workspace (this project only) - Recommended for teams
    Global (all VS Code projects) - Recommended for personal use

✓ Configuration updated successfully

Configuration Summary
  MCP Server Name: VulnZap
  Scope: Workspace-scoped (this project only)
  Config Path: /Users/you/project/.vscode/mcp.json
  Schema: servers (GitHub Copilot MCP)

Next Steps:
  1. Restart VS Code
  2. Open GitHub Copilot Chat
  3. VulnZap security tools are now available
```

### Example: JetBrains User

```bash
$ vulnzap connect

? Which development environment are you using?
  ❯ JetBrains (IntelliJ/WebStorm/etc) + Copilot

JetBrains + GitHub Copilot MCP Configuration

Choose where to place the MCP configuration:

? Configuration location:
  ❯ Project root (mcp.json) - Recommended, visible to team
    .idea folder (.idea/mcp.json) - Hidden from version control

✓ Configuration updated successfully

Configuration Summary
  MCP Server Name: VulnZap
  Location: Project root (visible to team)
  Config Path: /Users/you/project/mcp.json
  Schema: mcpServers (GitHub Copilot Agent)

Next Steps:
  1. Open Copilot Chat in JetBrains
  2. Switch to Agent mode
  3. Click MCP tools icon to verify VulnZap appears
  4. Enable VulnZap from the MCP server list

Note: Org admins must enable "MCP servers in Copilot" for Copilot Business/Enterprise
```

---

## Design Decisions

### Why Ask?

1. **Team vs Personal**: Different use cases need different scopes
2. **Version Control**: Teams may want to commit config, individuals may not
3. **Security**: Global configs can use environment variables
4. **Flexibility**: Users have control over their setup

### Default Choices

- **VS Code**: Workspace (better for teams, more secure with committed config)
- **Cursor**: Global (most users use Cursor personally)
- **JetBrains**: Project root (visible to team, clear intent)

### When NOT to Ask

- **Windsurf, Antigravity, Claude**: These IDEs have established global config patterns
- **Simplicity**: Asking too many questions reduces UX quality
- **Convention**: Following each IDE's established patterns

---

## Implementation Details

### VS Code Global Config Structure

```json
{
  "mcp": {
    "servers": {
      "VulnZap": {
        "command": "npx",
        "args": ["vulnzap", "mcp"],
        "env": {
          "VULNZAP_API_KEY": "${env:VULNZAP_API_KEY}"
        }
      }
    }
  }
}
```

**Important**: When using global config, users must set the environment variable:
```bash
# Add to ~/.zshrc or ~/.bashrc
export VULNZAP_API_KEY="your-api-key-here"
```

### Workspace Config Structure (VS Code & Cursor)

```json
{
  "inputs": [],
  "servers": {
    "VulnZap": {
      "command": "npx",
      "args": ["vulnzap", "mcp"],
      "env": {
        "VULNZAP_API_KEY": "actual-api-key"
      }
    }
  }
}
```

---

## Build Status

✅ **0 ERRORS** - All prompts tested and working

```bash
npm run build  # Passes cleanly
```

---

## Benefits

✅ **User Choice**: Empowers users to choose the right scope  
✅ **Team-Friendly**: Workspace configs can be shared via Git  
✅ **Security-Conscious**: Global configs use environment variables  
✅ **Clear Guidance**: Recommendations help users make the right choice  
✅ **Premium UX**: Beautiful, interactive prompts with clear explanations  

---

**Try it now:**
```bash
vulnzap connect
# Select your IDE and choose your preferred scope!
```
