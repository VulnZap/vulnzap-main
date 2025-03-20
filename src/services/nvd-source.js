/**
 * National Vulnerability Database (NVD) Source
 * 
 * Service for querying the NVD API for vulnerability information
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

const CACHE_FILE = path.join(CONFIG.DATA_PATHS.CACHE_DIR, 'nvd-vulnerabilities.json');
const REFRESH_INTERVAL = CONFIG.REFRESH_INTERVALS.NVD || 24 * 60 * 60 * 1000; // Default 24 hours

// Severity mapping from CVSS scores
const SEVERITY_MAP = {
  NONE: { min: 0.0, max: 0.0 },
  LOW: { min: 0.1, max: 3.9 },
  MEDIUM: { min: 4.0, max: 6.9 },
  HIGH: { min: 7.0, max: 8.9 },
  CRITICAL: { min: 9.0, max: 10.0 }
};

// Map ecosystem package formats to CPE product part
const ECOSYSTEM_CPE_MAP = {
  'npm': 'node.js',
  'pip': 'python',
  'go': 'go',
  'cargo': 'rust',
  'maven': 'maven',
  'nuget': 'nuget',
  'composer': 'php'
};

/**
 * National Vulnerability Database client
 */
export default class NvdSource {
  constructor(options = {}) {
    this.options = {
      apiUrl: CONFIG.SERVICE_ENDPOINTS.NVD,
      apiKey: process.env.NVD_API_KEY || CONFIG.API_KEYS.NVD,
      cacheFile: options.cacheFile || CACHE_FILE,
      refreshInterval: options.refreshInterval || REFRESH_INTERVAL,
      rateLimit: CONFIG.RATE_LIMITS.NVD || { limit: 5, window: 30 * 1000 }, // 5 requests per 30 seconds
      ...options
    };
    
    this.vulnerabilities = new Map();
    this.lastRefreshed = 0;
    this.isInitialized = false;
    
    // Rate limiting
    this.requestQueue = [];
    this.lastRequestTime = 0;
    this.requestsInWindow = 0;
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
        
        console.log(`Loaded ${this.vulnerabilities.size} NVD vulnerabilities from cache`);
      }
      
      this.isInitialized = true;
      return true;
    } catch (error) {
      console.error('Failed to initialize NVD source', error);
      return false;
    }
  }
  
  /**
   * Make a rate-limited API request
   */
  async makeRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
      const executeRequest = async () => {
        try {
          const now = Date.now();
          
          // Check rate limiting
          if (this.requestsInWindow >= this.options.rateLimit.limit) {
            const timeElapsed = now - this.lastRequestTime;
            
            if (timeElapsed < this.options.rateLimit.window) {
              // Wait for the next window
              const delay = this.options.rateLimit.window - timeElapsed;
              await new Promise(r => setTimeout(r, delay));
              
              // Reset counter
              this.requestsInWindow = 0;
            }
          }
          
          // Update request tracking
          this.lastRequestTime = Date.now();
          this.requestsInWindow++;
          
          // Execute the request
          const response = await fetch(url, options);
          
          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`NVD API error: ${response.status} - ${errorText}`);
          }
          
          const data = await response.json();
          resolve(data);
        } catch (error) {
          reject(error);
        }
      };
      
      executeRequest();
    });
  }
  
  /**
   * Search for vulnerabilities in NVD
   */
  async searchVulnerabilities(keyword, options = {}) {
    try {
      const apiKey = this.options.apiKey;
      
      // Build request URL
      let url = `${this.options.apiUrl}/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}`;
      
      // Add additional parameters
      if (options.pubStartDate) {
        url += `&pubStartDate=${encodeURIComponent(options.pubStartDate)}`;
      }
      
      if (options.pubEndDate) {
        url += `&pubEndDate=${encodeURIComponent(options.pubEndDate)}`;
      }
      
      // Add CPE match criteria if available
      if (options.cpeMatchString) {
        url += `&cpeName=${encodeURIComponent(options.cpeMatchString)}`;
      }
      
      // Prepare request
      const requestOptions = {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      };
      
      // Add API key if available
      if (apiKey) {
        requestOptions.headers['apiKey'] = apiKey;
      }
      
      // Make the request
      const response = await this.makeRequest(url, requestOptions);
      
      return response.vulnerabilities || [];
    } catch (error) {
      console.error(`Error searching NVD for ${keyword}:`, error);
      return [];
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
      console.error('Failed to save NVD vulnerabilities to cache', error);
      return false;
    }
  }
  
  /**
   * Map CVSS score to severity level
   */
  mapCvssToSeverity(cvssScore) {
    if (cvssScore === undefined || cvssScore === null) {
      return 'UNKNOWN';
    }
    
    for (const [severity, range] of Object.entries(SEVERITY_MAP)) {
      if (cvssScore >= range.min && cvssScore <= range.max) {
        return severity.toLowerCase();
      }
    }
    
    return 'unknown';
  }
  
  /**
   * Generate a CPE match string for a package
   */
  generateCpeMatch(packageName, ecosystem) {
    const cpeProduct = ECOSYSTEM_CPE_MAP[ecosystem] || ecosystem;
    return `cpe:2.3:a:*:${packageName}:*:*:*:*:*:${cpeProduct}:*:*`;
  }
  
  /**
   * Parse version range from CPE configuration
   */
  parseVersionRange(cpeConfiguration) {
    // This is a simplified version - a real implementation would parse the CPE configuration
    // to extract the affected version ranges
    if (!cpeConfiguration || !cpeConfiguration.nodes) {
      return null;
    }
    
    try {
      // Extract all version ranges
      const ranges = [];
      
      // Process CPE match nodes
      const processNode = (node) => {
        if (node.children) {
          node.children.forEach(processNode);
        }
        
        if (node.cpeMatch) {
          node.cpeMatch.forEach(match => {
            if (match.versionStartIncluding) {
              const rangeStart = `>=${match.versionStartIncluding}`;
              const rangeEnd = match.versionEndIncluding ? `<=${match.versionEndIncluding}` : 
                               match.versionEndExcluding ? `<${match.versionEndExcluding}` : '';
              
              ranges.push(rangeStart + (rangeEnd ? ' ' + rangeEnd : ''));
            } else if (match.versionStartExcluding) {
              const rangeStart = `>${match.versionStartExcluding}`;
              const rangeEnd = match.versionEndIncluding ? `<=${match.versionEndIncluding}` : 
                               match.versionEndExcluding ? `<${match.versionEndExcluding}` : '';
              
              ranges.push(rangeStart + (rangeEnd ? ' ' + rangeEnd : ''));
            } else if (match.versionEndIncluding) {
              ranges.push(`<=${match.versionEndIncluding}`);
            } else if (match.versionEndExcluding) {
              ranges.push(`<${match.versionEndExcluding}`);
            } else if (match.criteria && match.criteria.includes(':')) {
              // Extract version from CPE string
              const parts = match.criteria.split(':');
              if (parts.length >= 5) {
                const version = parts[5];
                if (version !== '*') {
                  ranges.push(`=${version}`);
                }
              }
            }
          });
        }
      };
      
      // Process all nodes
      cpeConfiguration.nodes.forEach(processNode);
      
      return ranges.join(' || ') || null;
    } catch (error) {
      console.error('Error parsing version range from CPE configuration:', error);
      return null;
    }
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
      
      // Check cache first
      const cacheKey = `${ecosystem}:${packageName}`;
      let vulnerabilities = this.vulnerabilities.get(cacheKey);
      
      // If not in cache or force refresh
      if (!vulnerabilities || options.refresh) {
        // Generate CPE match string
        const cpeMatch = this.generateCpeMatch(packageName, ecosystem);
        
        // Search NVD
        const results = await this.searchVulnerabilities(packageName, {
          cpeMatchString: cpeMatch
        });
        
        if (results.length > 0) {
          // Process and store vulnerabilities
          vulnerabilities = results.map(vuln => this.processVulnerability(vuln, packageName, ecosystem));
          
          // Update cache
          this.vulnerabilities.set(cacheKey, vulnerabilities);
          await this.saveToCache();
        } else {
          vulnerabilities = [];
        }
      }
      
      // Filter vulnerabilities affecting this version
      return vulnerabilities.filter(vuln => {
        // If we don't have version information, assume it's vulnerable
        if (!vuln.affectedVersions) return true;
        
        return this.isVersionAffected(version, vuln.affectedVersions, ecosystem);
      });
    } catch (error) {
      console.error(`Error finding NVD vulnerabilities for ${packageName}@${version}`, error);
      return [];
    }
  }
  
  /**
   * Process a vulnerability from NVD API
   */
  processVulnerability(vulnData, packageName, ecosystem) {
    try {
      const cve = vulnData.cve;
      
      // Extract CVSS score
      let cvssScore = null;
      let cvssVector = null;
      
      if (cve.metrics) {
        // Prefer CVSS 3.1
        if (cve.metrics.cvssMetricV31) {
          const metric = cve.metrics.cvssMetricV31[0];
          cvssScore = metric.cvssData.baseScore;
          cvssVector = metric.cvssData.vectorString;
        } 
        // Fall back to CVSS 3.0
        else if (cve.metrics.cvssMetricV30) {
          const metric = cve.metrics.cvssMetricV30[0];
          cvssScore = metric.cvssData.baseScore;
          cvssVector = metric.cvssData.vectorString;
        }
        // Fall back to CVSS 2.0
        else if (cve.metrics.cvssMetricV2) {
          const metric = cve.metrics.cvssMetricV2[0];
          cvssScore = metric.cvssData.baseScore;
          cvssVector = metric.cvssData.vectorString;
        }
      }
      
      // Extract version information
      let affectedVersions = null;
      
      if (cve.configurations) {
        affectedVersions = this.parseVersionRange(cve.configurations);
      }
      
      // Extract references
      const references = cve.references?.map(ref => ref.url) || [];
      
      // Build vulnerability object
      return {
        id: cve.id,
        title: cve.descriptions?.[0]?.value || 'Unknown vulnerability',
        description: cve.descriptions?.find(d => d.lang === 'en')?.value || cve.descriptions?.[0]?.value || '',
        severity: this.mapCvssToSeverity(cvssScore),
        cvss: cvssScore,
        cvssVector,
        affectedVersions,
        safeVersions: null, // NVD doesn't typically provide this
        published: cve.published,
        lastModified: cve.lastModified,
        ecosystem,
        packageName,
        references,
        source: 'nvd'
      };
    } catch (error) {
      console.error('Error processing NVD vulnerability:', error);
      return null;
    }
  }
  
  /**
   * Check if a package version is affected by a vulnerability
   * 
   * @param {string} version - Package version to check
   * @param {string} affectedRange - Affected version range
   * @param {string} ecosystem - Package ecosystem 
   * @returns {boolean} - True if the version is affected
   */
  isVersionAffected(version, affectedRange, ecosystem) {
    try {
      // Different ecosystems might have different version comparison logic
      return compareVersions(version, affectedRange, ecosystem);
    } catch (error) {
      console.error(`Error comparing versions: ${version} against ${affectedRange}`, error);
      // If we can't determine, assume it's vulnerable to be safe
      return true;
    }
  }
} 