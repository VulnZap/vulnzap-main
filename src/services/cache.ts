import fs from "fs";
import path from "path";
import os from "os";

// Cache configuration
export const CACHE_DIR = path.join(os.homedir(), ".vulnzap", "cache");
export const CACHE_TTL_MS = 5 * 24 * 60 * 60 * 1000; // 5 days in ms

// Types for cache operations
export interface CacheablePackage {
  packageName: string;
  packageVersion: string;
  ecosystem: string;
}

export interface CacheService {
  ensureCacheDir(): void;
  getCacheFilePath(
    packageName: string,
    packageVersion: string,
    ecosystem: string
  ): string;
  isCacheStale(cacheFile: string): boolean;
  readCache(
    packageName: string,
    packageVersion: string,
    ecosystem: string
  ): any | null;
  writeCache(
    packageName: string,
    packageVersion: string,
    ecosystem: string,
    data: any
  ): void;
  getDocsCacheFilePath(packageName: string): string;
  readDocsCache(packageName: string): any | null;
  writeDocsCache(packageName: string, docs: any): void;
  getLatestToolsetCacheFilePath(
    user_prompt: string,
    user_tools: string[],
    agent_tools: string[]
  ): string;
  readLatestToolsetCache(
    user_prompt: string,
    user_tools: string[],
    agent_tools: string[]
  ): any | null;
  writeLatestToolsetCache(
    user_prompt: string,
    user_tools: string[],
    agent_tools: string[],
    data: any
  ): void;
}

class VulnZapCacheService implements CacheService {
  ensureCacheDir(): void {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
    }
  }

  // Utility to sanitize package names for file paths
  private sanitizePackageName(packageName: string): string {
    // Replace @, /, and any non-alphanumeric character with '-'
    return packageName.replace(/[^a-zA-Z0-9.-]/g, "-");
  }

  getCacheFilePath(
    packageName: string,
    packageVersion: string,
    ecosystem: string
  ): string {
    const safePackageName = this.sanitizePackageName(packageName);
    return path.join(
      CACHE_DIR,
      `${ecosystem}-${safePackageName}-${packageVersion}.json`
    );
  }

  isCacheStale(cacheFile: string): boolean {
    if (!fs.existsSync(cacheFile)) return true;
    const stats = fs.statSync(cacheFile);
    const now = Date.now();
    if (now - stats.mtimeMs > CACHE_TTL_MS) {
      fs.unlinkSync(cacheFile);
      return true;
    }
    return false;
  }

  readCache(
    packageName: string,
    packageVersion: string,
    ecosystem: string
  ): any | null {
    this.ensureCacheDir();
    const cacheFile = this.getCacheFilePath(
      packageName,
      packageVersion,
      ecosystem
    );
    if (this.isCacheStale(cacheFile)) return null;
    try {
      return JSON.parse(fs.readFileSync(cacheFile, "utf8"));
    } catch {
      return null;
    }
  }

  writeCache(
    packageName: string,
    packageVersion: string,
    ecosystem: string,
    data: any
  ): void {
    this.ensureCacheDir();
    const cacheFile = this.getCacheFilePath(
      packageName,
      packageVersion,
      ecosystem
    );
    fs.writeFileSync(cacheFile, JSON.stringify(data, null, 2));
  }

  getDocsCacheFilePath(packageName: string): string {
    const safePackageName = this.sanitizePackageName(packageName);
    // If the packageName is too long, create a hash to avoid filesystem limits
    const fileName =
      safePackageName.length > 100
        ? this.createHash(packageName)
        : safePackageName;
    return path.join(CACHE_DIR, `${fileName}.docs.json`);
  }

  // Utility to create a simple hash for long strings
  private createHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return `hash-${Math.abs(hash)}`;
  }

  readDocsCache(packageName: string): any | null {
    this.ensureCacheDir();
    const cacheFile = this.getDocsCacheFilePath(packageName);
    if (!fs.existsSync(cacheFile)) return null;
    try {
      return JSON.parse(fs.readFileSync(cacheFile, "utf8"));
    } catch {
      return null;
    }
  }

  writeDocsCache(packageName: string, docs: any): void {
    this.ensureCacheDir();
    const cacheFile = this.getDocsCacheFilePath(packageName);
    fs.writeFileSync(cacheFile, JSON.stringify(docs, null, 2), "utf8");
  }

  // Utility to create a cache key for latest_toolset
  private getLatestToolsetCacheKey(
    user_prompt: string,
    user_tools: string[],
    agent_tools: string[]
  ): string {
    // Create a unique key based on the prompt and tools
    const base = `${user_prompt}__${user_tools.sort().join(",")}__${agent_tools
      .sort()
      .join(",")}`;
    // Sanitize and hash (simple hash for now)
    let hash = 0;
    for (let i = 0; i < base.length; i++) {
      hash = (hash << 5) - hash + base.charCodeAt(i);
      hash |= 0;
    }
    return `latest-toolset-${Math.abs(hash)}.json`;
  }

  getLatestToolsetCacheFilePath(
    user_prompt: string,
    user_tools: string[],
    agent_tools: string[]
  ): string {
    const fileName = this.getLatestToolsetCacheKey(
      user_prompt,
      user_tools,
      agent_tools
    );
    return path.join(CACHE_DIR, fileName);
  }

  readLatestToolsetCache(
    user_prompt: string,
    user_tools: string[],
    agent_tools: string[]
  ): any | null {
    this.ensureCacheDir();
    const cacheFile = this.getLatestToolsetCacheFilePath(
      user_prompt,
      user_tools,
      agent_tools
    );
    if (this.isCacheStale(cacheFile)) return null;
    try {
      return JSON.parse(fs.readFileSync(cacheFile, "utf8"));
    } catch {
      return null;
    }
  }

  writeLatestToolsetCache(
    user_prompt: string,
    user_tools: string[],
    agent_tools: string[],
    data: any
  ): void {
    this.ensureCacheDir();
    const cacheFile = this.getLatestToolsetCacheFilePath(
      user_prompt,
      user_tools,
      agent_tools
    );
    fs.writeFileSync(cacheFile, JSON.stringify(data, null, 2), "utf8");
  }
}

// Export a singleton instance
export const cacheService = new VulnZapCacheService();
