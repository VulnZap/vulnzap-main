import fs from 'fs';
import path from 'path';
import os from 'os';

// Cache configuration
export const CACHE_DIR = path.join(os.homedir(), '.vulnzap', 'cache');
export const CACHE_TTL_MS = 5 * 24 * 60 * 60 * 1000; // 5 days in ms

// Types for cache operations
export interface CacheablePackage {
  packageName: string;
  packageVersion: string;
  ecosystem: string;
}

export interface CacheService {
  ensureCacheDir(): void;
  getCacheFilePath(packageName: string, packageVersion: string, ecosystem: string): string;
  isCacheStale(cacheFile: string): boolean;
  readCache(packageName: string, packageVersion: string, ecosystem: string): any | null;
  writeCache(packageName: string, packageVersion: string, ecosystem: string, data: any): void;
}

class VulnZapCacheService implements CacheService {
  ensureCacheDir(): void {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
    }
  }

  getCacheFilePath(packageName: string, packageVersion: string, ecosystem: string): string {
    return path.join(CACHE_DIR, `${ecosystem}-${packageName}-${packageVersion}.json`);
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

  readCache(packageName: string, packageVersion: string, ecosystem: string): any | null {
    this.ensureCacheDir();
    const cacheFile = this.getCacheFilePath(packageName, packageVersion, ecosystem);
    if (this.isCacheStale(cacheFile)) return null;
    try {
      return JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
    } catch {
      return null;
    }
  }

  writeCache(packageName: string, packageVersion: string, ecosystem: string, data: any): void {
    this.ensureCacheDir();
    const cacheFile = this.getCacheFilePath(packageName, packageVersion, ecosystem);
    fs.writeFileSync(cacheFile, JSON.stringify(data, null, 2));
  }
}

// Export a singleton instance
export const cacheService = new VulnZapCacheService(); 