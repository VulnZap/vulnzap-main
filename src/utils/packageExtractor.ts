import fs from 'fs';
import path from 'path';
import { parse as parseToml } from '@iarna/toml';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';

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
 * Extract packages from pom.xml (Maven)
 */
function extractFromPomXml(filePath: string): PackageInfo[] {
  const content = fs.readFileSync(filePath, 'utf8');
  const packages: PackageInfo[] = [];
  
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(content, 'text/xml');
    
    // Get dependencies - cast doc to any to avoid type issues with xpath
    const dependencies = xpath.select('//dependency', doc as any) as Node[];
    
    for (const dep of dependencies) {
      const groupId = xpath.select('string(./groupId)', dep) as string;
      const artifactId = xpath.select('string(./artifactId)', dep) as string;
      const version = xpath.select('string(./version)', dep) as string;
      
      if (groupId && artifactId && version) {
        packages.push({
          packageName: `${groupId}:${artifactId}`,
          ecosystem: 'maven',
          version: version
        });
      }
    }
  } catch (error) {
    console.error(`Error parsing pom.xml: ${filePath}`, error);
  }
  
  return packages;
}

/**
 * Extract packages from .csproj (.NET)
 */
function extractFromCsproj(filePath: string): PackageInfo[] {
  const content = fs.readFileSync(filePath, 'utf8');
  const packages: PackageInfo[] = [];
  
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(content, 'text/xml');
    
    // Get PackageReference elements - cast doc to any to avoid type issues with xpath
    const packageRefs = xpath.select('//PackageReference', doc as any) as Node[];
    
    for (const pkg of packageRefs) {
      // Need to cast to Element to access getAttribute
      const element = pkg as unknown as Element;
      const packageName = element.getAttribute('Include');
      const version = element.getAttribute('Version');
      
      if (packageName && version) {
        packages.push({
          packageName,
          ecosystem: 'nuget',
          version
        });
      }
    }
  } catch (error) {
    console.error(`Error parsing .csproj: ${filePath}`, error);
  }
  
  return packages;
}

/**
 * Extract packages from build.gradle (Gradle)
 */
function extractFromGradle(filePath: string): PackageInfo[] {
  const content = fs.readFileSync(filePath, 'utf8');
  const packages: PackageInfo[] = [];
  
  // This is a simplified regex approach - for production use, 
  // a proper Gradle DSL parser would be better
  const implementationRegex = /(?:implementation|api|compile|testImplementation|runtimeOnly)\s+['"]([^:]+):([^:]+):([^'"]+)['"]/g;
  let match;
  
  while ((match = implementationRegex.exec(content)) !== null) {
    const groupId = match[1];
    const artifactId = match[2];
    const version = match[3];
    
    packages.push({
      packageName: `${groupId}:${artifactId}`,
      ecosystem: 'gradle',
      version
    });
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
      if (['node_modules', 'vendor', 'target', '.git', 'bin', 'obj'].includes(file)) continue;
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
      if (ecosystem === 'maven' || !ecosystem) {
        if (file === 'pom.xml') {
          packages = packages.concat(extractFromPomXml(filePath));
        }
      }
      if (ecosystem === 'nuget' || !ecosystem) {
        if (file.endsWith('.csproj')) {
          packages = packages.concat(extractFromCsproj(filePath));
        }
      }
      if (ecosystem === 'gradle' || !ecosystem) {
        if (file === 'build.gradle' || file === 'build.gradle.kts') {
          packages = packages.concat(extractFromGradle(filePath));
        }
      }
    }
  }

  return packages;
} 