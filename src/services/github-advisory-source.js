/**
 * GitHub Advisory Database Source
 * 
 * Service for querying the GitHub Advisory Database for vulnerability information
 */

import fetch from 'node-fetch';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

import CONFIG from '../core/config.js';
import { cacheData, loadCachedData } from '../utils/cache-manager.js';
import { parseVersion, compareVersions } from '../utils/version-parsers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const CACHE_FILE = path.join(CONFIG.DATA_PATHS.CACHE_DIR, 'github-advisories.json');
const REFRESH_INTERVAL = CONFIG.REFRESH_INTERVALS.GITHUB || 24 * 60 * 60 * 1000; // Default 24 hours

/**
 * GitHub Advisory Database client
 */
export default class GitHubAdvisorySource {
  constructor(options = {}) {
    this.options = {
      apiUrl: CONFIG.SERVICE_ENDPOINTS.GITHUB_ADVISORY,
      apiToken: process.env.GITHUB_TOKEN || CONFIG.API_KEYS.GITHUB,
      cacheFile: options.cacheFile || CACHE_FILE,
      refreshInterval: options.refreshInterval || REFRESH_INTERVAL,
      ...options
    };
    
    this.advisories = new Map();
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
        this.advisories = new Map(Object.entries(cachedData.advisories));
        this.lastRefreshed = cachedData.timestamp || 0;
        
        console.log(`Loaded ${this.advisories.size} GitHub advisories from cache`);
      }
      
      // Check if refresh is needed
      const now = Date.now();
      if (now - this.lastRefreshed > this.options.refreshInterval) {
        await this.refreshData();
      }
      
      this.isInitialized = true;
      return true;
    } catch (error) {
      console.error('Failed to initialize GitHub Advisory source', error);
      return false;
    }
  }
  
  /**
   * Refresh data from GitHub Advisory Database
   */
  async refreshData() {
    try {
      console.log('Refreshing GitHub Advisory Database...');
      
      // Here we would typically query the GitHub API
      // For this implementation, we'll use a simplified approach
      
      const fetchOptions = {};
      
      if (this.options.apiToken) {
        fetchOptions.headers = {
          'Authorization': `token ${this.options.apiToken}`
        };
      }
      
      // We would normally query GitHub's GraphQL API here
      // For simplicity, we'll just use a mock implementation
      
      // Mock data - in a real implementation, this would come from GitHub API
      const mockAdvisories = {
        'npm': {
          'lodash': [
            {
              id: 'GHSA-p6mc-m468-83gw',
              packageName: 'lodash',
              ecosystem: 'npm',
              severity: 'high',
              cvss: 7.8,
              affectedVersions: '<=4.17.19',
              safeVersions: '>=4.17.20',
              title: 'Prototype Pollution in lodash',
              description: 'Prototype pollution vulnerability in lodash before 4.17.20',
              publishedAt: '2021-02-15T18:45:30Z',
              references: ['https://github.com/lodash/lodash/pull/4759']
            }
          ],
          'minimist': [
            {
              id: 'GHSA-vh95-rmgr-6w4m',
              packageName: 'minimist',
              ecosystem: 'npm',
              severity: 'medium',
              cvss: 5.6,
              affectedVersions: '<0.2.1 || >=1.0.0 <1.2.3',
              safeVersions: '>=0.2.1 <1.0.0 || >=1.2.3',
              title: 'Prototype Pollution in minimist',
              description: 'Prototype pollution in minimist before 0.2.1 and 1.2.3',
              publishedAt: '2020-04-03T15:12:00Z',
              references: ['https://github.com/advisories/GHSA-vh95-rmgr-6w4m']
            }
          ]
        },
        'pip': {
          'django': [
            {
              id: 'GHSA-w24h-v4j5-v9qv',
              packageName: 'django',
              ecosystem: 'pip',
              severity: 'high',
              cvss: 8.1,
              affectedVersions: '<3.0.14 || >=3.1.0 <3.1.7',
              safeVersions: '>=3.0.14 <3.1.0 || >=3.1.7',
              title: 'Potential directory traversal via archive.extract()',
              description: 'Directory traversal vulnerability in django.utils.archive.extract()',
              publishedAt: '2021-02-19T15:30:00Z',
              references: ['https://www.djangoproject.com/weblog/2021/feb/19/security-releases/']
            }
          ]
        },
        'go': {
          'github.com/golang/go': [
            {
              id: 'GHSA-g9mp-8g3h-3c5c',
              packageName: 'github.com/golang/go',
              ecosystem: 'go',
              severity: 'medium',
              cvss: 5.5,
              affectedVersions: '>=1.15.0 <1.15.8 || >=1.16.0 <1.16.1',
              safeVersions: '<1.15.0 || >=1.15.8 <1.16.0 || >=1.16.1',
              title: 'Incorrect handling of invalid UTF-8 sequences',
              description: 'Go before 1.15.8 and 1.16.x before 1.16.1 has an improper handling of invalid UTF-8 sequences',
              publishedAt: '2021-02-25T20:00:00Z',
              references: ['https://go.dev/issue/44855']
            }
          ]
        }
      };
      
      // Process the advisory data
      for (const [ecosystem, packages] of Object.entries(mockAdvisories)) {
        for (const [packageName, advisories] of Object.entries(packages)) {
          const key = `${ecosystem}:${packageName}`;
          this.advisories.set(key, advisories);
        }
      }
      
      // Save to cache
      await this.saveToCache();
      
      this.lastRefreshed = Date.now();
      console.log(`Refreshed GitHub Advisory Database with ${this.advisories.size} package entries`);
      
      return true;
    } catch (error) {
      console.error('Failed to refresh GitHub Advisory data', error);
      return false;
    }
  }
  
  /**
   * Save advisories to cache file
   */
  async saveToCache() {
    try {
      const cacheData = {
        timestamp: Date.now(),
        advisories: Object.fromEntries(this.advisories)
      };
      
      await fs.writeFile(this.options.cacheFile, JSON.stringify(cacheData));
      return true;
    } catch (error) {
      console.error('Failed to save GitHub advisories to cache', error);
      return false;
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
      
      // Force refresh if requested
      if (options.refresh) {
        await this.refreshData();
      }
      
      // Check if we need to refresh based on time interval
      const now = Date.now();
      if (now - this.lastRefreshed > this.options.refreshInterval) {
        await this.refreshData();
      }
      
      // Lookup advisories for this package
      const key = `${ecosystem}:${packageName}`;
      const advisories = this.advisories.get(key) || [];
      
      // Filter advisories that affect this version
      const vulnerabilities = advisories.filter(advisory => 
        this.isVersionAffected(version, advisory.affectedVersions, ecosystem)
      );
      
      // Enrich vulnerability data
      return vulnerabilities.map(vuln => ({
        id: vuln.id,
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity,
        cvss: vuln.cvss,
        affectedVersions: vuln.affectedVersions,
        safeVersions: vuln.safeVersions,
        published: vuln.publishedAt,
        ecosystem,
        packageName,
        version,
        references: vuln.references,
        recommendation: `Update to ${vuln.safeVersions} or later`,
        source: 'github'
      }));
    } catch (error) {
      console.error(`Error finding GitHub advisories for ${packageName}@${version}`, error);
      return [];
    }
  }
} 