import fs from 'fs';
import path from 'path';
import { parse as parseToml } from '@iarna/toml';

interface PackageInfo {
  packageName: string;
  ecosystem: string;
  version: string;
}

interface CargoToml {
  dependencies?: Record<string, string | { version: string }>;
  'dev-dependencies'?: Record<string, string | { version: string }>;
}

/**
 * Extract packages from package.json
 */
function extractFromPackageJson(filePath: string): PackageInfo[] {
  const content = fs.readFileSync(filePath, 'utf8');
  const pkg = JSON.parse(content);
  const packages: PackageInfo[] = [];

  // Extract dependencies
  const deps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.peerDependencies
  };

  for (const [name, version] of Object.entries(deps)) {
    packages.push({
      packageName: name,
      ecosystem: 'npm',
      version: version as string
    });
  }

  return packages;
}

/**
 * Extract packages from requirements.txt
 */
function extractFromRequirements(filePath: string): PackageInfo[] {
  const content = fs.readFileSync(filePath, 'utf8');
  const packages: PackageInfo[] = [];

  // Match package name and version
  const regex = /^([a-zA-Z0-9_.-]+)(?:==|>=|<=|>|<|~=)([0-9a-zA-Z_.-]+)$/;
  
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const match = trimmed.match(regex);
    if (match) {
      packages.push({
        packageName: match[1],
        ecosystem: 'pip',
        version: match[2]
      });
    }
  }

  return packages;
}

/**
 * Extract packages from go.mod
 */
function extractFromGoMod(filePath: string): PackageInfo[] {
  const content = fs.readFileSync(filePath, 'utf8');
  const packages: PackageInfo[] = [];

  // Match require statements
  const regex = /require\s+([a-zA-Z0-9/._-]+)\s+([a-zA-Z0-9.+-]+)/g;
  let match;

  while ((match = regex.exec(content)) !== null) {
    packages.push({
      packageName: match[1],
      ecosystem: 'go',
      version: match[2]
    });
  }

  return packages;
}

/**
 * Extract packages from Cargo.toml
 */
function extractFromCargoToml(filePath: string): PackageInfo[] {
  const content = fs.readFileSync(filePath, 'utf8');
  const toml = parseToml(content) as CargoToml;
  const packages: PackageInfo[] = [];

  // Extract dependencies
  const deps = {
    ...(toml.dependencies || {}),
    ...(toml['dev-dependencies'] || {})
  };

  for (const [name, value] of Object.entries(deps)) {
    let version = '';
    if (typeof value === 'string') {
      version = value;
    } else if (value && typeof value === 'object' && 'version' in value) {
      version = value.version as string;
    }

    if (version) {
      packages.push({
        packageName: name,
        ecosystem: 'rust',
        version
      });
    }
  }

  return packages;
}

/**
 * Find and extract packages from package manager files in a directory
 */
export function extractPackagesFromDirectory(dirPath: string, ecosystem?: string): PackageInfo[] {
  const files = fs.readdirSync(dirPath);
  let packages: PackageInfo[] = [];

  for (const file of files) {
    const filePath = path.join(dirPath, file);
    const stats = fs.statSync(filePath);

    if (stats.isDirectory()) {
      // Skip node_modules and other common dependency directories
      if (['node_modules', 'vendor', 'target', '.git'].includes(file)) continue;
      packages = packages.concat(extractPackagesFromDirectory(filePath, ecosystem));
    } else {
      if (ecosystem === 'npm' || !ecosystem) {
        if (file === 'package.json') {
          packages = packages.concat(extractFromPackageJson(filePath));
        }
      }
      if (ecosystem === 'pip' || !ecosystem) {
        if (file === 'requirements.txt') {
          packages = packages.concat(extractFromRequirements(filePath));
        }
      }
      if (ecosystem === 'go' || !ecosystem) {
        if (file === 'go.mod') {
          packages = packages.concat(extractFromGoMod(filePath));
        }
      }
      if (ecosystem === 'rust' || !ecosystem) {
        if (file === 'Cargo.toml') {
          packages = packages.concat(extractFromCargoToml(filePath));
        }
      }
    }
  }

  return packages;
} 