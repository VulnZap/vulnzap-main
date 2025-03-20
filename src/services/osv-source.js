/**
 * Open Source Vulnerability (OSV) Database Source
 * 
 * Service for querying the OSV API for vulnerability information
 */

import fetch from 'node-fetch';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

import { CONFIG } from '../core/config.js';
import { cacheData, loadCachedData } from '../utils/cache-manager.js';
import { parseVersion, compareVersions } from '../utils/version-parsers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const CACHE_FILE = path.join(CONFIG.DATA_PATHS.CACHE_DIR, 'osv-vulnerabilities.json');
const REFRESH_INTERVAL = CONFIG.REFRESH_INTERVALS.OSV || 24 * 60 * 60 * 1000; // Default 24 hours

// OSV ecosystem mapping
const ECOSYSTEM_MAP = {
  'npm': 'npm',
  'pip': 'PyPI',
  'go': 'Go',
  'cargo': 'crates.io',
  'maven': 'Maven',
  'nuget': 'NuGet',
  'composer': 'Packagist'
};

/**
 * Open Source Vulnerability client
 */
export default class OsvSource {
  constructor(options = {}) {
    this.options = {
      apiUrl: CONFIG.SERVICE_ENDPOINTS.OSV || 'https://api.osv.dev/v1',
      cacheFile: options.cacheFile || CACHE_FILE,
      refreshInterval: options.refreshInterval || REFRESH_INTERVAL,
      ...options
    };
    
    this.vulnerabilities = new Map();
    this.lastRefreshed = 0;
    this.isInitialized = false;
  }
  
  /**
   * Initialize the data source
   */
  async initialize() {
    try {
      // Create cache directory if it doesn't exist
      await fs.mkdir(CONFIG.DATA_PATHS.CACHE_DIR, { recursive: true });
      
      // Load cached data if available
      const cachedData = await loadCachedData(this.options.cacheFile);
      
      if (cachedData) {
        this.vulnerabilities = new Map(Object.entries(cachedData.vulnerabilities));
        this.lastRefreshed = cachedData.timestamp || 0;
        
        console.log(`Loaded ${this.vulnerabilities.size} OSV vulnerabilities from cache`);
      }
      
      this.isInitialized = true;
      return true;
    } catch (error) {
      console.error('Failed to initialize OSV source', error);
      return false;
    }
  }
  
  /**
   * Save vulnerabilities to cache file
   */
  async saveToCache() {
    try {
      const cacheData = {
        timestamp: Date.now(),
        vulnerabilities: Object.fromEntries(this.vulnerabilities)
      };
      
      await fs.writeFile(this.options.cacheFile, JSON.stringify(cacheData));
      return true;
    } catch (error) {
      console.error('Failed to save OSV vulnerabilities to cache', error);
      return false;
    }
  }
  
  /**
   * Query OSV API for a specific package and version
   */
  async queryOsvApi(packageName, version, ecosystem) {
    try {
      const osvEcosystem = ECOSYSTEM_MAP[ecosystem] || ecosystem;
      
      const requestBody = {
        package: {
          name: packageName,
          ecosystem: osvEcosystem
        },
        version
      };
      
      // Make OSV API request
      const response = await fetch(`${this.options.apiUrl}/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OSV API error: ${response.status} - ${errorText}`);
      }
      
      const data = await response.json();
      return data.vulns || [];
    } catch (error) {
      console.error(`Error querying OSV for ${packageName}@${version}:`, error);
      return [];
    }
  }
  
  /**
   * Determines the severity level from various sources in an OSV entry
   */
  determineSeverity(osvVulnerability) {
    // OSV doesn't have a standard severity field, but may include it in database_specific
    
    // Try to get from CVSS
    if (osvVulnerability.severity && osvVulnerability.severity.length > 0) {
      for (const sev of osvVulnerability.severity) {
        if (sev.type === 'CVSS_V3') {
          const score = parseFloat(sev.score);
          
          if (score >= 9.0) return 'critical';
          if (score >= 7.0) return 'high';
          if (score >= 4.0) return 'medium';
          if (score > 0.0) return 'low';
          return 'none';
        }
      }
    }
    
    // Try to get from database-specific information
    if (osvVulnerability.database_specific) {
      // GitHub Security Advisory format
      if (osvVulnerability.database_specific.severity) {
        return osvVulnerability.database_specific.severity.toLowerCase();
      }
      
      // NVD format
      if (osvVulnerability.database_specific.cvss && osvVulnerability.database_specific.cvss.baseScore) {
        const score = parseFloat(osvVulnerability.database_specific.cvss.baseScore);
        
        if (score >= 9.0) return 'critical';
        if (score >= 7.0) return 'high';
        if (score >= 4.0) return 'medium';
        if (score > 0.0) return 'low';
        return 'none';
      }
    }
    
    // Default to medium if we can't determine
    return 'medium';
  }
  
  /**
   * Extract CVSS score from an OSV entry
   */
  extractCvssScore(osvVulnerability) {
    // Check severity section first
    if (osvVulnerability.severity && osvVulnerability.severity.length > 0) {
      for (const sev of osvVulnerability.severity) {
        if (sev.type === 'CVSS_V3' && sev.score) {
          return parseFloat(sev.score);
        }
      }
    }
    
    // Check database-specific
    if (osvVulnerability.database_specific) {
      // GHSA format
      if (osvVulnerability.database_specific.cvss && osvVulnerability.database_specific.cvss.score) {
        return parseFloat(osvVulnerability.database_specific.cvss.score);
      }
      
      // NVD format
      if (osvVulnerability.database_specific.cvss && osvVulnerability.database_specific.cvss.baseScore) {
        return parseFloat(osvVulnerability.database_specific.cvss.baseScore);
      }
    }
    
    return null;
  }
  
  /**
   * Process OSV API results into standardized format
   */
  processOsvResults(results, packageName, version, ecosystem) {
    return results
      .map(vuln => {
        // Extract severity information
        const severity = this.determineSeverity(vuln);
        const cvss = this.extractCvssScore(vuln);
        
        // Process affected versions
        let affectedVersions = null;
        if (vuln.affected && vuln.affected.length > 0) {
          // Join affected version ranges
          const ranges = [];
          
          vuln.affected.forEach(affected => {
            if (affected.versions) {
              // Direct version list
              affected.versions.forEach(ver => {
                ranges.push(`=${ver}`);
              });
            } else if (affected.ranges) {
              // Version ranges
              affected.ranges.forEach(range => {
                if (range.type === 'SEMVER') {
                  range.events.forEach((event, i, events) => {
                    if (event.introduced && events[i+1] && events[i+1].fixed) {
                      ranges.push(`>=${event.introduced} <${events[i+1].fixed}`);
                    } else if (event.introduced) {
                      ranges.push(`>=${event.introduced}`);
                    } else if (event.fixed) {
                      ranges.push(`<${event.fixed}`);
                    }
                  });
                }
              });
            }
          });
          
          affectedVersions = ranges.join(' || ');
        }
        
        // Extract references
        const references = (vuln.references || []).map(ref => ref.url);
        
        // Create standardized vulnerability object
        return {
          id: vuln.id,
          title: vuln.summary || 'Unknown vulnerability',
          description: vuln.details || 'No details available',
          severity,
          cvss,
          affectedVersions,
          safeVersions: null, // Calculate from affected versions if needed
          published: vuln.published,
          lastModified: vuln.modified,
          ecosystem,
          packageName,
          version,
          references,
          aliases: vuln.aliases || [],
          source: 'osv'
        };
      })
      .filter(Boolean); // Remove any null entries
  }
  
  /**
   * Find vulnerabilities for a specific package
   * 
   * @param {string} packageName - Package name
   * @param {string} version - Package version
   * @param {string} ecosystem - Package ecosystem (npm, pip, etc.)
   * @param {Object} options - Additional options
   * @returns {Promise<Array>} - Array of vulnerabilities
   */
  async findVulnerabilities(packageName, version, ecosystem, options = {}) {
    try {
      if (!this.isInitialized) {
        await this.initialize();
      }
      
      // Standardize ecosystem name
      const osvEcosystem = ECOSYSTEM_MAP[ecosystem] || ecosystem;
      
      // Check cache first
      const cacheKey = `${osvEcosystem}:${packageName}:${version}`;
      
      // Force refresh or not in cache
      if (options.refresh || !this.vulnerabilities.has(cacheKey)) {
        // Query OSV API
        const results = await this.queryOsvApi(packageName, version, ecosystem);
        
        // Process results
        const vulnerabilities = this.processOsvResults(results, packageName, version, ecosystem);
        
        // Update cache
        this.vulnerabilities.set(cacheKey, vulnerabilities);
        await this.saveToCache();
        
        return vulnerabilities;
      }
      
      // Return cached results
      return this.vulnerabilities.get(cacheKey) || [];
    } catch (error) {
      console.error(`Error finding OSV vulnerabilities for ${packageName}@${version}`, error);
      return [];
    }
  }
} 