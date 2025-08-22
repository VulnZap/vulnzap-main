import blessed from 'blessed';
import { batchScan } from './api/batchScan.js';
import * as api from './api/apis.js';
import * as auth from './api/auth.js';
import { getKey, saveKey } from './api/auth.js';
import { extractPackagesFromDirectory } from './utils/packageExtractor.js';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';

type ScreenWithKeys = blessed.Widgets.Screen & { key: (keys: string | string[], cb: () => void) => void };

export async function startTUI() {
  const screen = blessed.screen({
    smartCSR: true,
    fullUnicode: true,
    dockBorders: true,
    title: 'VulnZap — Secure AI Development',
  }) as ScreenWithKeys;

  const sidebar = blessed.list({
    parent: screen,
    label: ' Menu ',
    mouse: true,
    keys: true,
    vi: true,
    width: '24%',
    height: '100%-1',
    border: 'line',
    style: {
      selected: { bg: 'cyan', fg: 'black' },
      item: { hover: { bg: 'gray' } },
    },
    items: [
      ' Quick Setup',
      ' Welcome',
      ' Setup',
      ' Status',
      ' Check Package',
      ' Batch Scan',
      ' IDE Connect',
      ' Exit',
    ],
  });

  const content = blessed.box({
    parent: screen,
    left: '24%',
    width: '76%',
    height: '100%-1',
    border: 'line',
    label: ' VulnZap ',
    scrollable: true,
    alwaysScroll: true,
    keys: true,
    mouse: true,
    vi: true,
    tags: true,
  });

  const footer = blessed.box({
    parent: screen,
    bottom: 0,
    height: 1,
    width: '100%',
    tags: true,
    style: { bg: 'black', fg: 'gray' },
    content: ' j/k or ↑/↓ to navigate • Space to toggle • Enter to select • Tab to switch • q to quit',
  });

  let lastInteractive: blessed.Widgets.BlessedElement | blessed.Widgets.ListElement | null = null;

  function write(text: string) {
    content.setContent(text);
    screen.render();
  }

  function append(text: string) {
    const current = (content.getContent?.() as string) || '';
    content.setContent(current + text);
    screen.render();
  }

  async function drawWelcome() {
    write(
      '{bold}VulnZap — Security-first AI development{/bold}\n\n' +
      'Streamlined setup, real-time vulnerability checks, and IDE integrations.\n\n' +
      '{gray}- Use the sidebar to explore actions{/gray}\n' +
      '{gray}- Press q at any time to exit{/gray}'
    );
  }

  async function drawStatus() {
    write('Checking server and account status...');
    try {
      const health = await api.checkHealth();
      const key = await getKey().catch(() => null);
      const ok = health?.status === 'ok';
      write(
        `{bold}System Status{/bold}\n\n` +
        `Server: ${ok ? '{green-fg}Healthy{/green-fg}' : '{red-fg}Offline{/red-fg}'}\n` +
        `Auth: ${key ? '{green-fg}Configured{/green-fg}' : '{yellow-fg}Not set{/yellow-fg}'}\n\n` +
        `{gray}Tip: Run Setup to configure API key and IDE integration.{/gray}`
      );
    } catch (e: any) {
      write(`{red-fg}Status check failed:{/red-fg} ${e.message || e}`);
    }
  }

  async function drawSetup() {
    const form = blessed.form({ parent: content, keys: true, mouse: true, left: 1, top: 1, width: '95%', height: '90%' });
    const label = blessed.text({ parent: form, tags: true, content: '{bold}Enter API Key{/bold}', top: 0, left: 0 });
    const input = blessed.textbox({ parent: form, top: 2, left: 0, width: '90%', height: 3, inputOnFocus: true, secret: true, censor: true, border: 'line' });
    const btn = blessed.button({ parent: form, mouse: true, keys: true, shrink: true, top: 6, left: 0, name: 'save', content: ' Save ', style: { bg: 'cyan', fg: 'black', focus: { bg: 'green' } } });

    btn.on('press', async () => {
      // @ts-ignore
      const val = input.getValue?.() || '';
      try {
        await saveKey(val.trim());
        content.children.forEach(ch => ch.detach());
        write('{green-fg}API key saved.{/green-fg}\n\nGo to Status to confirm connectivity.');
      } catch (e: any) {
        write(`{red-fg}Failed to save key:{/red-fg} ${e.message || e}`);
      }
    });

    // focus input by default
    input.focus();
    lastInteractive = input;
    screen.render();
  }

  // ---------- Quick Setup (Magical Flow)
  function step(title: string, body: string) {
    write(`{bold}${title}{/bold}\n\n${body}`);
  }

  function detectInstalledIDEs(): string[] {
    const installed: string[] = [];
    const supported = [
      { name: 'vscode', cmd: 'code' },
      { name: 'cursor', cmd: 'cursor' },
      { name: 'windsurf', cmd: 'windsurf' },
    ];
    for (const ide of supported) {
      try { execSync(`${ide.cmd} --version`, { stdio: 'pipe' }); installed.push(ide.name); continue; } catch {}
      const resolved = resolveIDECLIPath(ide.name);
      if (resolved) installed.push(ide.name);
    }
    return installed;
  }

  function resolveVSCodeCLIPath(): string | null {
    const platform = os.platform();
    const candidates: string[] = [];
    if (platform === 'darwin') {
      candidates.push('/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code');
      candidates.push('/opt/homebrew/bin/code');
      candidates.push('/usr/local/bin/code');
    } else if (platform === 'win32') {
      const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
      candidates.push(path.join(localAppData, 'Programs', 'Microsoft VS Code', 'bin', 'code.cmd'));
    } else {
      candidates.push('/usr/bin/code'); candidates.push('/snap/bin/code');
    }
    for (const p of candidates) { try { if (fs.existsSync(p)) return p; } catch {} }
    return null;
  }

  function resolveIDECLIPath(ide: string): string | null {
    if (ide === 'vscode') return resolveVSCodeCLIPath();
    const platform = os.platform();
    const candidates: string[] = [];
    if (ide === 'cursor') {
      if (platform === 'darwin') {
        candidates.push('/Applications/Cursor.app/Contents/Resources/app/bin/cursor');
      } else if (platform === 'win32') {
        const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
        candidates.push(path.join(localAppData, 'Programs', 'Cursor', 'bin', 'cursor.exe'));
      } else {
        candidates.push('/usr/bin/cursor'); candidates.push('/snap/bin/cursor');
      }
    } else if (ide === 'windsurf') {
      if (platform === 'darwin') {
        candidates.push('/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf');
      } else if (platform === 'win32') {
        const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
        candidates.push(path.join(localAppData, 'Programs', 'Windsurf', 'bin', 'windsurf.exe'));
      } else {
        candidates.push('/usr/bin/windsurf'); candidates.push('/snap/bin/windsurf');
      }
    }
    for (const p of candidates) { try { if (fs.existsSync(p)) return p; } catch {} }
    return null;
  }

  function quote(cmd: string) { return cmd.includes(' ') ? `"${cmd}"` : cmd; }

  function tryInstallExtension(ide: 'vscode'|'cursor'|'windsurf') {
    const extensionId = 'vulnzap.vulnzap';
    let cmd = ide === 'vscode' ? 'code' : ide;
    try { execSync(`${cmd} --version`, { stdio: 'pipe' }); } catch {
      const resolved = resolveIDECLIPath(ide);
      if (!resolved) return { success: false, message: `${ide} CLI not found` };
      cmd = quote(resolved);
    }
    try { execSync(`${cmd} --install-extension ${extensionId}`, { stdio: 'pipe' }); return { success: true }; }
    catch (e: any) { return { success: false, message: e?.message || 'install failed' }; }
  }

  async function connectIDE(ide: 'cursor'|'windsurf') {
    const home = os.homedir();
    const apiKey = await getKey();
    if (ide === 'cursor') {
      const cursorDir = path.join(home, '.cursor');
      if (!fs.existsSync(cursorDir)) fs.mkdirSync(cursorDir, { recursive: true });
      const cursorMcp = path.join(cursorDir, 'mcp.json');
      let cfg: any = {};
      if (fs.existsSync(cursorMcp)) { try { cfg = JSON.parse(fs.readFileSync(cursorMcp, 'utf8')); } catch { cfg = {}; } }
      cfg.mcpServers = cfg.mcpServers || {};
      cfg.mcpServers.VulnZap = { url: 'https://vulnzap.com/mcp/sse', headers: { 'x-api-key': apiKey } };
      fs.writeFileSync(cursorMcp, JSON.stringify(cfg, null, 2));
      return;
    }
    if (ide === 'windsurf') {
      const dir = path.join(home, '.codeium', 'windsurf');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfgFile = path.join(dir, 'mcp_config.json');
      let cfg: any = { mcpServers: {} };
      if (fs.existsSync(cfgFile)) { try { cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8')); } catch {} }
      cfg.mcpServers = cfg.mcpServers || {};
      cfg.mcpServers.VulnZap = { url: 'https://vulnzap.com/mcp/sse', headers: { 'x-api-key': apiKey } };
      fs.writeFileSync(cfgFile, JSON.stringify(cfg, null, 2));
      return;
    }
  }

  async function quickSetup() {
    // Step 1: Health check
    step('Checking VulnZap', 'Verifying server availability...');
    const healthy = await api.checkHealth().then(h => h?.status === 'ok').catch(() => false);
    append(`\nServer: ${healthy ? '{green-fg}Healthy{/green-fg}' : '{yellow-fg}Unavailable (will fallback){/yellow-fg}'}\n`);

    // Step 2: Authentication
    let key = await getKey().catch(() => null);
    if (!key) {
      step('Authentication', 'Choose a sign-in method:');
      const list = blessed.list({ parent: content, top: 4, left: 2, width: '80%', height: 4, keys: true, mouse: true, vi: true, border: 'line', items: ['Login with browser (recommended)', 'Enter API key manually'] });
      list.focus(); lastInteractive = list; screen.render();
      await new Promise<void>(resolve => {
        list.on('select', async (it: any) => {
          const choice = it.getText();
          list.detach();
          if (choice.startsWith('Login')) {
            write('{gray-fg}Opening browser for authentication...{/gray-fg}');
            auth.login('login').then(async (res: any) => {
              if (res?.success) { append('\n{green-fg}Authentication successful{/green-fg}'); resolve(); }
              else { append(`\n{red-fg}Auth failed{/red-fg}`); resolve(); }
              screen.render();
            }).catch(() => { append(`\n{red-fg}Auth failed{/red-fg}`); screen.render(); resolve(); });
          } else {
            const input = blessed.textbox({ parent: content, top: 4, left: 2, width: '80%', height: 3, inputOnFocus: true, secret: true, censor: true, border: 'line' });
            input.focus(); lastInteractive = input; screen.render();
            input.readInput(async (err, value) => {
              input.detach();
              if (value) await saveKey(value.trim());
              append(value ? '\n{green-fg}API key saved{/green-fg}' : '\n{yellow-fg}No key entered{/yellow-fg}');
              screen.render(); resolve();
            });
          }
        });
      });
    } else {
      append('\nAuth: {green-fg}Configured{/green-fg}\n');
    }

    // Step 3: IDEs
    step('IDE Integration', '{gray-fg}Detecting installed IDEs...{/gray-fg}');
    const ides = detectInstalledIDEs();
    append(`\nFound: ${ides.length ? ides.join(', ') : 'none'}`);
    screen.render();

    const selectable = ['cursor', 'windsurf', 'vscode'].filter(n => ides.includes(n));
    if (selectable.length) {
      const checklist = blessed.list({ parent: content, top: 6, left: 2, width: '80%', height: 6, keys: true, mouse: true, vi: true, border: 'line', items: selectable.map(n => `☐ ${n}`) });
      checklist.focus(); lastInteractive = checklist; screen.render();
      const chosen = await new Promise<string[]>((resolve) => {
        const set = new Set<string>();
        checklist.on('keypress', (ch, key) => {
          // @ts-ignore blessed typings
          const idx = (checklist as any).selected || 0;
          const name = selectable[idx];
          if (key?.name === 'space') {
            if (set.has(name)) { set.delete(name); (checklist as any).setItem(idx, `☐ ${name}`); }
            else { set.add(name); (checklist as any).setItem(idx, `☑ ${name}`); }
            screen.render();
          }
          if (key?.name === 'enter') { checklist.detach(); resolve(Array.from(set)); }
        });
      });

      for (const ide of chosen as ('cursor'|'windsurf'|'vscode')[]) {
        append(`\nConfiguring {cyan-fg}${ide}{/cyan-fg}...`);
        screen.render();
        if (ide === 'cursor' || ide === 'windsurf') {
          try { await connectIDE(ide); append(' {green-fg}MCP configured{/green-fg}'); } catch { append(' {red-fg}MCP config failed{/red-fg}'); }
        }
        const res = tryInstallExtension(ide);
        append(res.success ? ' {green-fg}Extension installed{/green-fg}' : ` {yellow-fg}${res.message}{/yellow-fg}`);
        screen.render();
      }
    } else {
      append('\n{yellow-fg}No supported IDEs detected. You can configure manually later.{/yellow-fg}');
    }

    // Step 4: Finish
    append('\n\n{bold}All set.{/bold} Your environment is secured.');
    append('\nPress q to quit or use the menu to explore.');
    screen.render();
  }

  async function drawCheck() {
    const form = blessed.form({ parent: content, keys: true, mouse: true, left: 1, top: 1, width: '95%', height: '95%' });
    blessed.text({ parent: form, tags: true, content: '{bold}Check Package{/bold}\nFormat: ecosystem:pkg@version', top: 0, left: 0 });
    const input = blessed.textbox({ parent: form, top: 3, left: 0, width: '80%', height: 3, inputOnFocus: true, border: 'line' });
    const btn = blessed.button({ parent: form, mouse: true, keys: true, shrink: true, top: 7, left: 0, content: ' Run ', style: { bg: 'cyan', fg: 'black' } });
    const out = blessed.box({ parent: form, top: 11, left: 0, width: '100%', height: '60%', border: 'line', scrollable: true, tags: true, alwaysScroll: true, keys: true, vi: true });

    async function run() {
      // @ts-ignore
      const val = (input.getValue?.() || '').trim();
      if (!val) return;
      out.setContent('{gray-fg}Scanning...{/gray-fg}');
      screen.render();
      try {
        const m = val.match(/^(\w+):([^@]+)@(.+)$/);
        if (!m) {
          out.setContent('{red-fg}Invalid format. Use ecosystem:pkg@version{/red-fg}');
          screen.render();
          return;
        }
        const [, ecosystem, packageName, version] = m;
        const result = await batchScan([{ ecosystem, packageName, version }], { useCache: true, useAi: true });
        const r = result.results?.[0];
        if (!r) {
          out.setContent('{red-fg}No result{/red-fg}');
        } else if (r.status === 'safe') {
          out.setContent(`{green-fg}Secure{/green-fg}\n${packageName}@${version} has no known vulnerabilities.`);
        } else if (r.status === 'vulnerable') {
          const vulns = (r.vulnerabilities || []).map(v => `- {yellow-fg}${v.title}{/yellow-fg} (${v.severity})`).join('\n');
          const rec = r.remediation?.recommendedVersion ? `\n\nRecommended: update to {cyan-fg}${r.remediation.recommendedVersion}{/cyan-fg}` : '';
          out.setContent(`{red-fg}Vulnerable{/red-fg}\n${vulns}${rec}`);
        } else {
          out.setContent(`{yellow-fg}${r.message || 'Unknown status'}{/yellow-fg}`);
        }
      } catch (e: any) {
        out.setContent(`{red-fg}Scan failed:{/red-fg} ${e.message || e}`);
      }
      screen.render();
    }

    btn.on('press', run);
    // @ts-ignore
    form.key(['enter'], run);
    input.focus();
    screen.render();
  }

  async function drawBatch() {
    write('{gray-fg}Scanning current directory...{/gray-fg}');
    try {
      const packages = extractPackagesFromDirectory(process.cwd(), undefined);
      if (packages.length === 0) {
        write('{yellow-fg}No package manager files found in this directory.{/yellow-fg}');
        return;
      }
      const results = await batchScan(packages, { useCache: true, useAi: true });
      const vulnerable = results.results.filter(r => r.status === 'vulnerable');
      const safe = results.results.filter(r => r.status === 'safe');
      write(`{bold}Batch Scan{/bold}\n\nTotal: ${packages.length}\nSafe: {green-fg}${safe.length}{/green-fg}\nVulnerable: {red-fg}${vulnerable.length}{/red-fg}`);
    } catch (e: any) {
      write(`{red-fg}Batch scan failed:{/red-fg} ${e.message || e}`);
    }
  }

  async function drawIDEConnect() {
    const home = os.homedir();
    const m1 = '- Cursor/Windsurf are fully automated with MCP and extension install.';
    const m2 = '- VS Code extension auto-install with smart CLI detection.';
    write(`{bold}IDE Integration{/bold}\n\n${m1}\n${m2}\n\nConfig files are stored under:\n{gray-fg}${path.join(home, '.vulnzap')}{/gray-fg}`);
  }

  const actions: Record<string, () => Promise<void>> = {
    ' Quick Setup': quickSetup,
    ' Welcome': drawWelcome,
    ' Setup': drawSetup,
    ' Status': drawStatus,
    ' Check Package': drawCheck,
    ' Batch Scan': drawBatch,
    ' IDE Connect': drawIDEConnect,
    ' Exit': async () => screen.destroy(),
  };

  sidebar.on('select', async (item) => {
    const label = (item as any).getText?.() || '';
    content.children.forEach(ch => ch.detach());
    const fn = actions[label];
    if (fn) await fn(); else await drawWelcome();
    if (lastInteractive && (lastInteractive as any).focus) {
      (lastInteractive as any).focus();
    } else {
      sidebar.focus();
    }
  });

  screen.key(['tab'], () => {
    if (screen.focused === sidebar && lastInteractive && (lastInteractive as any).focus) {
      (lastInteractive as any).focus();
    } else {
      sidebar.focus();
    }
    screen.render();
  });

  screen.key(['q', 'C-c'], () => screen.destroy());

  await quickSetup();
  sidebar.focus();
  screen.render();
}


