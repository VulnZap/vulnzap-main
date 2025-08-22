import os from 'os';
import fs from 'fs';
import path, { join } from 'path';
import { execSync } from 'child_process';
import { getKey } from '../api/auth.js';

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
    } catch {
      const resolved = resolveIDECLIPath(ide.name);
      if (resolved) installedIDEs.push(ide.name);
    }
  }
  return installedIDEs;
}

export function quoteCmdIfNeeded(cmd: string): string {
  if (!cmd) return cmd;
  return cmd.includes(' ') ? `"${cmd}"` : cmd;
}

export function resolveIDECLIPath(ide: string): string | null {
  if (ide === 'vscode') return resolveVSCodeCLIPath();
  const platform = os.platform();
  const candidates: string[] = [];
  if (ide === 'cursor') {
    if (platform === 'darwin') {
      candidates.push('/Applications/Cursor.app/Contents/Resources/app/bin/cursor');
      candidates.push(join(os.homedir(), 'Applications', 'Cursor.app', 'Contents', 'Resources', 'app', 'bin', 'cursor'));
    } else if (platform === 'win32') {
      const localAppData = process.env.LOCALAPPDATA || join(os.homedir(), 'AppData', 'Local');
      candidates.push(join(localAppData, 'Programs', 'Cursor', 'bin', 'cursor.exe'));
    } else {
      candidates.push('/usr/bin/cursor');
      candidates.push('/snap/bin/cursor');
    }
  } else if (ide === 'windsurf') {
    if (platform === 'darwin') {
      candidates.push('/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf');
      candidates.push(join(os.homedir(), 'Applications', 'Windsurf.app', 'Contents', 'Resources', 'app', 'bin', 'windsurf'));
    } else if (platform === 'win32') {
      const localAppData = process.env.LOCALAPPDATA || join(os.homedir(), 'AppData', 'Local');
      candidates.push(join(localAppData, 'Programs', 'Windsurf', 'bin', 'windsurf.exe'));
    } else {
      candidates.push('/usr/bin/windsurf');
      candidates.push('/snap/bin/windsurf');
    }
  }
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {}
  }
  return null;
}

export function resolveVSCodeCLIPath(): string | null {
  const platform = os.platform();
  const candidates: string[] = [];

  if (platform === 'darwin') {
    candidates.push('/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code');
    candidates.push('/Applications/Visual Studio Code - Insiders.app/Contents/Resources/app/bin/code');
    candidates.push(join(os.homedir(), 'Applications', 'Visual Studio Code.app', 'Contents', 'Resources', 'app', 'bin', 'code'));
    candidates.push(join(os.homedir(), 'Applications', 'Visual Studio Code - Insiders.app', 'Contents', 'Resources', 'app', 'bin', 'code'));
    candidates.push('/usr/local/bin/code');
    candidates.push('/opt/homebrew/bin/code');
  } else if (platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || join(os.homedir(), 'AppData', 'Local');
    candidates.push(join(localAppData, 'Programs', 'Microsoft VS Code', 'bin', 'code.cmd'));
    candidates.push('C\\\\\\:\\\\\\\Program Files\\\\\\\Microsoft VS Code\\\\\\\bin\\\\\\\code.cmd');
    candidates.push('C\\\\\\:\\\\\\\Program Files (x86)\\\\\\\Microsoft VS Code\\\\\\\bin\\\\\\\code.cmd');
  } else {
    candidates.push('/usr/bin/code');
    candidates.push('/snap/bin/code');
  }

  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) {
        return p;
      }
    } catch {}
  }
  return null;
}

export function tryEnsureVSCodeSymlink(codePath: string): void {
  try {
    const platform = os.platform();
    if (platform === 'darwin' || platform === 'linux') {
      const binTargets = platform === 'darwin'
        ? ['/usr/local/bin/code', '/opt/homebrew/bin/code']
        : ['/usr/local/bin/code'];

      for (const target of binTargets) {
        try {
          const targetDir = path.dirname(target);
          if (!fs.existsSync(target) && fs.existsSync(targetDir)) {
            fs.symlinkSync(codePath, target);
          }
        } catch {}
      }
    }
  } catch {}
}

export async function installIDEExtension(ide: string) {
  try {
    if (ide === 'vscode') {
      let codeCmd = 'code';
      try {
        execSync(`${codeCmd} --version`, { stdio: 'pipe' });
      } catch {
        const resolved = resolveVSCodeCLIPath();
        if (resolved) {
          codeCmd = quoteCmdIfNeeded(resolved);
          tryEnsureVSCodeSymlink(resolved);
        } else {
          return { success: false, error: 'VS Code CLI not found', instructions: [
            'VS Code found but CLI not available in PATH.',
            'We attempted automatic detection; manual PATH install may be required.',
            'To add VS Code to PATH:',
            '  1. Open VS Code',
            '  2. Press Cmd+Shift+P (Ctrl+Shift+P on Windows/Linux)',
            '  3. Type "Shell Command: Install \"code\" command in PATH"',
            '  4. Run the command and restart your terminal'
          ]};
        }
      }
      const extensionId = 'vulnzap.vulnzap';
      try {
        execSync(`${codeCmd} --install-extension ${extensionId}`, { stdio: 'pipe' });
        return { success: true, instructions: [
          'VS Code Extension Setup Complete',
          '  Extension: VulnZap Security Scanner'
        ] };
      } catch {
        return { success: false, error: 'Extension not available in marketplace', instructions: [
          'VulnZap extension not yet available in marketplace',
          'Visit https://vulnzap.com/vscode for updates'
        ] };
      }
    } else if (ide === 'cursor') {
      const extensionId = 'vulnzap.vulnzap';
      const cursorCmd = quoteCmdIfNeeded(resolveIDECLIPath('cursor') || 'cursor');
      try {
        execSync(`${cursorCmd} --install-extension ${extensionId}`, { stdio: 'pipe' });
        return { success: true, instructions: ['Cursor Extension Setup Complete'] };
      } catch {
        return { success: false, error: 'Extension installation failed', instructions: [
          'Cursor Extension Installation Failed',
          'Visit https://vulnzap.com/cursor for updates'
        ] };
      }
    } else if (ide === 'windsurf') {
      const extensionId = 'vulnzap.vulnzap';
      const windsurfCmd = quoteCmdIfNeeded(resolveIDECLIPath('windsurf') || 'windsurf');
      try {
        execSync(`${windsurfCmd} --install-extension ${extensionId}`, { stdio: 'pipe' });
        return { success: true, instructions: ['Windsurf Extension Setup Complete'] };
      } catch {
        return { success: false, error: 'Extension installation failed', instructions: [
          'Windsurf Extension Installation Failed',
          'Visit https://vulnzap.com/windsurf for updates'
        ] };
      }
    }
    return { success: false, error: `Extension installation for ${ide} is not yet automated`, instructions: [] };
  } catch (error: any) {
    return { success: false, error: error.message, instructions: [] };
  }
}

export async function connectIDE(ide: string) {
  const apiKey = await getKey();
  const logFile = join(os.homedir(), '.vulnzap', 'info.log');
  const logStream = fs.createWriteStream(logFile, { flags: 'a' });
  logStream.write(`VulnZap connect command executed for ${ide} at ${new Date().toISOString()}\n`);
  logStream.end();

  if (ide === 'cursor') {
    const cursorDir = join(os.homedir(), '.cursor');
    if (!fs.existsSync(cursorDir)) fs.mkdirSync(cursorDir, { recursive: true });
    const cursorMcpConfigLocation = join(cursorDir, 'mcp.json');
    let cfg: any = {};
    if (fs.existsSync(cursorMcpConfigLocation)) {
      try { cfg = JSON.parse(fs.readFileSync(cursorMcpConfigLocation, 'utf8')); } catch { cfg = {}; }
    }
    if (!cfg.mcpServers) cfg.mcpServers = {};
    cfg.mcpServers.VulnZap = { url: 'https://vulnzap.com/mcp/sse', headers: { 'x-api-key': apiKey } };
    fs.writeFileSync(cursorMcpConfigLocation, JSON.stringify(cfg, null, 2));
    return { success: true };
  }
  if (ide === 'windsurf') {
    const windsurfDir = join(os.homedir(), '.codeium', 'windsurf');
    const windsurfMcpConfigLocation = join(windsurfDir, 'mcp_config.json');
    if (!fs.existsSync(windsurfDir)) fs.mkdirSync(windsurfDir, { recursive: true });
    let cfg: any = {};
    if (fs.existsSync(windsurfMcpConfigLocation)) {
      try { cfg = JSON.parse(fs.readFileSync(windsurfMcpConfigLocation, 'utf8')); } catch { cfg = { mcpServers: {} }; }
    } else { cfg = { mcpServers: {} }; }
    if (!cfg.mcpServers) cfg.mcpServers = {};
    cfg.mcpServers.VulnZap = { url: 'https://vulnzap.com/mcp/sse', headers: { 'x-api-key': apiKey } };
    fs.writeFileSync(windsurfMcpConfigLocation, JSON.stringify(cfg, null, 2));
    return { success: true };
  }
  if (ide === 'cline') {
    const clineDir = join(os.homedir(), 'AppData', 'Roaming', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings');
    const clineMcpConfigLocation = join(clineDir, 'cline_mcp_settings.json');
    if (!fs.existsSync(clineDir)) fs.mkdirSync(clineDir, { recursive: true });
    let cfg: any = {};
    if (fs.existsSync(clineMcpConfigLocation)) {
      try { cfg = JSON.parse(fs.readFileSync(clineMcpConfigLocation, 'utf8')); } catch { cfg = {}; }
    }
    if (!cfg.mcpServers) cfg.mcpServers = {};
    cfg.mcpServers.VulnZap = {
      url: 'https://vulnzap.com/mcp/sse',
      headers: { 'x-api-key': apiKey },
      alwaysAllow: ['auto-vulnerability-scan'],
      disabled: false,
      networkTimeout: 60000
    };
    fs.writeFileSync(clineMcpConfigLocation, JSON.stringify(cfg, null, 2));
    return { success: true };
  }
  return { success: false, error: `Unsupported IDE: ${ide}` };
}


