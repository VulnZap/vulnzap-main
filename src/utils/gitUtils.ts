import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * Get the current commit hash (HEAD)
 */
export function getCurrentCommitHash(repoPath: string = '.'): string | null {
  try {
    const result = execSync('git rev-parse HEAD', {
      cwd: repoPath,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore']
    });
    return result.trim() || null;
  } catch (error) {
    return null;
  }
}

/**
 * Get repository URL from git remote
 */
export function getRepositoryUrl(repoPath: string = '.'): string | null {
  try {
    const result = execSync('git remote get-url origin', {
      cwd: repoPath,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore']
    });
    return normalizeRepoUrl(result.trim());
  } catch (error) {
    return null;
  }
}

/**
 * Get current branch name
 */
export function getCurrentBranch(repoPath: string = '.'): string | null {
  try {
    const result = execSync('git rev-parse --abbrev-ref HEAD', {
      cwd: repoPath,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore']
    });
    return result.trim() || null;
  } catch (error) {
    return null;
  }
}

/**
 * Get user identifier from git config (user.email)
 */
export function getUserIdentifier(repoPath: string = '.'): string | null {
  try {
    const result = execSync('git config user.email', {
      cwd: repoPath,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore']
    });
    return result.trim() || null;
  } catch (error) {
    return null;
  }
}

/**
 * Normalize repository URL to owner/repo format
 * Handles: https://github.com/owner/repo, git@github.com:owner/repo.git, owner/repo
 */
export function normalizeRepoUrl(url: string): string | null {
  if (!url) return null;

  // Remove .git suffix
  url = url.replace(/\.git$/, '');

  // Handle SSH format: git@github.com:owner/repo
  if (url.includes('@') && url.includes(':')) {
    const match = url.match(/:([^/]+\/[^/]+)$/);
    if (match) return match[1];
  }

  // Handle HTTPS format: https://github.com/owner/repo
  const httpsMatch = url.match(/github\.com[/:]([^/]+\/[^/]+)/);
  if (httpsMatch) return httpsMatch[1];

  // Handle git:// format: git://github.com/owner/repo
  const gitMatch = url.match(/git:\/\/[^/]+\/([^/]+\/[^/]+)/);
  if (gitMatch) return gitMatch[1];

  // If already in owner/repo format, return as-is
  if (/^[^/]+\/[^/]+$/.test(url)) {
    return url;
  }

  return null;
}

/**
 * Get diff files and their content since a commit/ref
 */
export function getDiffFiles(
  since: string,
  repoPath: string = '.',
  paths?: string[]
): Array<{ name: string; content: string; language?: string }> {
  try {
    // Get list of changed files
    const diffCommand = paths && paths.length > 0
      ? `git diff --name-only ${since} -- ${paths.map(p => `"${p}"`).join(' ')}`
      : `git diff --name-only ${since}`;

    const fileList = execSync(diffCommand, {
      cwd: repoPath,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim().split('\n').filter(Boolean);

    const files: Array<{ name: string; content: string; language?: string }> = [];

    for (const filePath of fileList) {
      try {
        // Get file content from working tree (current state)
        const content = readFileSync(join(repoPath, filePath), 'utf-8');
        
        // Detect language from file extension
        const language = detectLanguage(filePath);

        files.push({
          name: filePath,
          content,
          language
        });
      } catch (error) {
        // Skip files that can't be read (deleted, binary, etc.)
        continue;
      }
    }

    return files;
  } catch (error) {
    return [];
  }
}

/**
 * Detect programming language from file extension
 */
function detectLanguage(filePath: string): string | undefined {
  const ext = filePath.split('.').pop()?.toLowerCase();
  
  const languageMap: Record<string, string> = {
    'js': 'javascript',
    'jsx': 'javascript',
    'ts': 'typescript',
    'tsx': 'typescript',
    'py': 'python',
    'java': 'java',
    'go': 'go',
    'rs': 'rust',
    'rb': 'ruby',
    'php': 'php',
    'cpp': 'cpp',
    'cc': 'cpp',
    'cxx': 'cpp',
    'c': 'c',
    'cs': 'csharp',
    'swift': 'swift',
    'kt': 'kotlin',
    'scala': 'scala',
    'sh': 'bash',
    'bash': 'bash',
    'zsh': 'bash',
    'sql': 'sql',
    'html': 'html',
    'css': 'css',
    'scss': 'scss',
    'sass': 'sass',
    'json': 'json',
    'xml': 'xml',
    'yaml': 'yaml',
    'yml': 'yaml',
    'toml': 'toml',
    'md': 'markdown',
    'vue': 'vue',
    'svelte': 'svelte'
  };

  return ext ? languageMap[ext] : undefined;
}

/**
 * Check if current directory is a git repository
 */
export function isGitRepository(repoPath: string = '.'): boolean {
  try {
    execSync('git rev-parse --git-dir', {
      cwd: repoPath,
      stdio: ['ignore', 'pipe', 'ignore']
    });
    return true;
  } catch {
    return false;
  }
}

