/**
 * In-memory scan state management for MCP tools
 * Tracks active scans and their metadata
 */

export interface ScanMetadata {
  scan_id: string;
  jobId: string;
  type: 'diff' | 'full';
  timestamp: number;
  repo?: string;
  commitHash?: string;
}

class ScanStateManager {
  private scans: Map<string, ScanMetadata> = new Map();
  private latestScans: Map<string, string> = new Map(); // repo -> latest scan_id

  /**
   * Register a new scan
   */
  registerScan(scan: ScanMetadata): void {
    this.scans.set(scan.scan_id, scan);
    
    if (scan.repo) {
      this.latestScans.set(scan.repo, scan.scan_id);
    }
  }

  /**
   * Get scan metadata by scan_id
   */
  getScan(scan_id: string): ScanMetadata | undefined {
    return this.scans.get(scan_id);
  }

  /**
   * Get latest scan for a repository
   */
  getLatestScan(repo: string): ScanMetadata | undefined {
    const scan_id = this.latestScans.get(repo);
    if (!scan_id) return undefined;
    return this.scans.get(scan_id);
  }

  /**
   * Update scan metadata
   */
  updateScan(scan_id: string, updates: Partial<ScanMetadata>): void {
    const existing = this.scans.get(scan_id);
    if (existing) {
      this.scans.set(scan_id, { ...existing, ...updates });
    }
  }

  /**
   * Get all scans (for debugging)
   */
  getAllScans(): ScanMetadata[] {
    return Array.from(this.scans.values());
  }

  /**
   * Clear old scans (optional cleanup)
   */
  clearOldScans(maxAge: number = 24 * 60 * 60 * 1000): void {
    const now = Date.now();
    for (const [scan_id, scan] of this.scans.entries()) {
      if (now - scan.timestamp > maxAge) {
        this.scans.delete(scan_id);
        // Also remove from latestScans if it was the latest
        if (scan.repo) {
          const latest = this.latestScans.get(scan.repo);
          if (latest === scan_id) {
            this.latestScans.delete(scan.repo);
          }
        }
      }
    }
  }
}

// Singleton instance
export const scanState = new ScanStateManager();

