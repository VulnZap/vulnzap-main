import blessed from 'blessed';
import { batchScan } from './api/batchScan.js';
import * as api from './api/apis.js';
import { getKey, saveKey } from './api/auth.js';
import { extractPackagesFromDirectory } from './utils/packageExtractor.js';
import os from 'os';
import path from 'path';
import fs from 'fs';

type ScreenWithKeys = blessed.Widgets.Screen & { key: (keys: string | string[], cb: () => void) => void };

export async function startTUI() {
  const screen = blessed.screen({
    smartCSR: true,
    fullUnicode: true,
    dockBorders: true,
    title: 'VulnZap — Secure AI Development',
  }) as ScreenWithKeys;

  const layout = blessed.layout({ parent: screen, width: '100%', height: '100%', layout: 'grid' });

  const sidebar = blessed.list({
    parent: layout,
    label: ' Menu ',
    mouse: true,
    keys: true,
    vi: true,
    width: '24%',
    height: '100%',
    border: 'line',
    style: {
      selected: { bg: 'cyan', fg: 'black' },
      item: { hover: { bg: 'gray' } },
    },
    items: [
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
    parent: layout,
    width: '76%',
    height: '100%',
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
    content: ' j/k or ↑/↓ to navigate • Enter to select • q to quit',
  });

  function write(text: string) {
    content.setContent(text);
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
  });

  screen.key(['q', 'C-c'], () => screen.destroy());

  await drawWelcome();
  sidebar.focus();
  screen.render();
}


