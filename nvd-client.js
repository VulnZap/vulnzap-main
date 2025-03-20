/**
 * National Vulnerability Database (NVD) API Client
 * 
 * This module provides functionality to fetch and process vulnerability data from the NVD.
 * It includes functions for querying the CVE API and mapping the results to the Vulnzap format.
 * 
 * Reference: https://nvd.nist.gov/developers/vulnerabilities
 */

import fetch from 'node-fetch';
import semver from 'semver';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const DEFAULT_CONFIG = {
  apiKey: process.env.NVD_API_KEY || '',
  cacheDir: path.join(__dirname, 'cache'),
  cacheFile: 'nvd-cache.json',
  requestDelay: 5000, // 5 seconds between requests to respect rate limits
  ecosystemMappings: {
    'npm': ['node', 'nodejs', 'npm', 'javascript', 'js'],
    'pip': ['python', 'pip', 'pypi']
  },
  baseUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0'
};

// Cache for NVD data
let nvdCache = new Map();
let lastFetchTime = 0;

/**
 * Initialize the NVD client
 * @param {Object} customConfig - Custom configuration options
 */
export async function initNvdClient(customConfig = {}) {
  const config = { ...DEFAULT_CONFIG, ...customConfig };
  
  // Create cache directory if it doesn't exist
  if (!fs.existsSync(config.cacheDir)) {
    fs.mkdirSync(config.cacheDir, { recursive: true });
  }
  
  // Load cache from disk if it exists
  const cacheFilePath = path.join(config.cacheDir, config.cacheFile);
  if (fs.existsSync(cacheFilePath)) {
    try {
      const cacheData = JSON.parse(fs.readFileSync(cacheFilePath, 'utf8'));
      
      if (cacheData && cacheData.entries) {
        nvdCache = new Map(cacheData.entries);
        lastFetchTime = cacheData.lastUpdate || 0;
        console.log(`Loaded ${nvdCache.size} NVD cache entries`);
      }
    } catch (error) {
      console.error(`Error loading NVD cache: ${error.message}`);
    }
  }
  
  return { config };
}

/**
 * Save the NVD cache to disk
 * @param {Object} config - Configuration options
 */
function saveCache(config) {
  const cacheFilePath = path.join(config.cacheDir, config.cacheFile);
  try {
    const cacheData = {
      lastUpdate: Date.now(),
      entries: Array.from(nvdCache.entries())
    };
    
    fs.writeFileSync(cacheFilePath, JSON.stringify(cacheData, null, 2));
    console.log(`Saved ${nvdCache.size} NVD cache entries`);
  } catch (error) {
    console.error(`Error saving NVD cache: ${error.message}`);
  }
}

/**
 * Fetch vulnerability data from NVD for a specific package
 * 
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @param {Object} config - Configuration options
 * @returns {Promise<Array>} - Array of vulnerability advisories
 */
export async function fetchPackageVulnerabilities(ecosystem, packageName, config) {
  if (!config.apiKey) {
    console.warn('NVD API key not provided. Some features may be limited.');
  }
  
  // Check cache first
  const cacheKey = `${ecosystem}:${packageName}`;
  if (nvdCache.has(cacheKey)) {
    const cachedData = nvdCache.get(cacheKey);
    // Return cached data if it exists and is less than 24 hours old
    if (cachedData && cachedData.timestamp > Date.now() - 86400000) {
      return cachedData.vulnerabilities;
    }
  }
  
  // Respect rate limits
  const now = Date.now();
  if (now - lastFetchTime < config.requestDelay) {
    await new Promise(resolve => setTimeout(resolve, config.requestDelay - (now - lastFetchTime)));
  }
  
  // Get ecosystem keywords for searching
  const ecosystemKeywords = config.ecosystemMappings[ecosystem] || [ecosystem];
  
  try {
    // Construct the NVD API URL with CPE filtering based on ecosystem and package name
    let url = `${config.baseUrl}?keywordSearch=${encodeURIComponent(packageName)}`;
    
    // Add additional parameters for better matching
    const additionalParams = ecosystemKeywords.map(keyword => 
      `cpeMatchString=cpe:2.3:a:*:${keyword}:*:*:*:*:*:*:*:*`
    ).join('&');
    
    if (additionalParams) {
      url += `&${additionalParams}`;
    }
    
    // Set headers including API key if available
    const headers = {
      'Content-Type': 'application/json',
    };
    
    if (config.apiKey) {
      headers['apiKey'] = config.apiKey;
    }
    
    // Make the request
    const response = await fetch(url, { headers });
    lastFetchTime = Date.now();
    
    if (!response.ok) {
      throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    const vulnerabilities = processNvdResponse(data, ecosystem, packageName);
    
    // Cache the result
    nvdCache.set(cacheKey, {
      timestamp: Date.now(),
      vulnerabilities
    });
    
    // Save cache to disk
    saveCache(config);
    
    return vulnerabilities;
  } catch (error) {
    console.error(`Error fetching NVD data for ${packageName} (${ecosystem}): ${error.message}`);
    return [];
  }
}

/**
 * Process the NVD API response and extract vulnerability information
 * 
 * @param {Object} response - The NVD API response
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @returns {Array} - Array of vulnerability advisories in Vulnzap format
 */
function processNvdResponse(response, ecosystem, packageName) {
  if (!response.vulnerabilities || !Array.isArray(response.vulnerabilities)) {
    return [];
  }
  
  const result = [];
  
  for (const item of response.vulnerabilities) {
    const cve = item.cve;
    
    if (!cve) continue;
    
    // Extract basic information
    const id = cve.id;
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';
    const published = cve.published;
    const lastModified = cve.lastModified;
    
    // Extract severity information
    let severity = 'unknown';
    let cvssScore = 0;
    
    if (cve.metrics?.cvssMetricV31) {
      const metric = cve.metrics.cvssMetricV31[0];
      cvssScore = metric?.cvssData?.baseScore || 0;
      severity = getSeverityFromScore(cvssScore);
    } else if (cve.metrics?.cvssMetricV30) {
      const metric = cve.metrics.cvssMetricV30[0];
      cvssScore = metric?.cvssData?.baseScore || 0;
      severity = getSeverityFromScore(cvssScore);
    } else if (cve.metrics?.cvssMetricV2) {
      const metric = cve.metrics.cvssMetricV2[0];
      cvssScore = metric?.cvssData?.baseScore || 0;
      severity = getSeverityFromScore(cvssScore);
    }
    
    // Extract version information
    let vulnerableVersions = '*';
    let patchedVersions = '';
    
    if (cve.configurations) {
      const versionInfo = extractVersionInfoFromNvd(cve.configurations, ecosystem, packageName);
      vulnerableVersions = versionInfo.vulnerableVersions || '*';
      patchedVersions = versionInfo.patchedVersions || '';
    }
    
    result.push({
      id: id,
      ecosystem: ecosystem,
      package: packageName,
      vulnerable_versions: vulnerableVersions,
      patched_versions: patchedVersions,
      title: `${id}: Vulnerability in ${packageName}`,
      description: description,
      severity: severity,
      cvss_score: cvssScore,
      cve_id: id,
      published_at: published,
      last_modified: lastModified,
      source: 'nvd'
    });
  }
  
  return result;
}

/**
 * Map CVSS score to severity level
 * 
 * @param {number} score - CVSS base score
 * @returns {string} - Severity level (critical, high, medium, low)
 */
function getSeverityFromScore(score) {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

/**
 * Extract version information from NVD configurations
 * 
 * @param {Array} configurations - NVD configuration nodes
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @returns {Object} - Object with vulnerableVersions and patchedVersions
 */
function extractVersionInfoFromNvd(configurations, ecosystem, packageName) {
  const vulnerableVersionRanges = [];
  const patchedVersionRanges = [];
  
  // Process all configurations
  for (const config of configurations) {
    if (!config.nodes) continue;
    
    for (const node of config.nodes) {
      if (!node.cpeMatch) continue;
      
      for (const cpeMatch of node.cpeMatch) {
        const cpe = cpeMatch.criteria || '';
        
        // Skip if not relevant to the current package/ecosystem
        if (!isRelevantCpe(cpe, ecosystem, packageName)) {
          continue;
        }
        
        // Extract version info from CPE
        const versionInfo = extractVersionFromCpe(cpe);
        if (!versionInfo) continue;
        
        if (cpeMatch.vulnerable === true) {
          // Format version range based on ecosystem
          if (ecosystem === 'npm') {
            if (versionInfo.version && versionInfo.version !== '*') {
              const operator = versionInfo.operator || '=';
              vulnerableVersionRanges.push(`${operator}${versionInfo.version}`);
            }
          } else {
            // For pip or other ecosystems
            if (versionInfo.version && versionInfo.version !== '*') {
              const operator = versionInfo.operator || '==';
              vulnerableVersionRanges.push(`${operator}${versionInfo.version}`);
            }
          }
        } else {
          // This is a non-vulnerable version (patched)
          if (versionInfo.version && versionInfo.version !== '*') {
            if (ecosystem === 'npm') {
              const operator = versionInfo.operator === '<' ? '>=' : '>';
              patchedVersionRanges.push(`${operator}${versionInfo.version}`);
            } else {
              const operator = versionInfo.operator === '<' ? '>=' : '>';
              patchedVersionRanges.push(`${operator}${versionInfo.version}`);
            }
          }
        }
      }
    }
  }
  
  // Convert ranges to a format suitable for the ecosystem
  return {
    vulnerableVersions: vulnerableVersionRanges.length > 0 
      ? vulnerableVersionRanges.join(' || ') 
      : '*',
    patchedVersions: patchedVersionRanges.length > 0 
      ? patchedVersionRanges.join(' || ') 
      : ''
  };
}

/**
 * Check if a CPE is relevant to a specific package and ecosystem
 * 
 * @param {string} cpe - The CPE string
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @returns {boolean} - True if relevant
 */
function isRelevantCpe(cpe, ecosystem, packageName) {
  if (!cpe) return false;
  
  // Split CPE into components
  const parts = cpe.split(':');
  if (parts.length < 5) return false;
  
  // Check if application component
  if (parts[2] !== 'a') return false;
  
  // Check package name (can be in vendor or product field)
  const vendor = parts[3];
  const product = parts[4];
  
  return product === packageName || vendor === packageName;
}

/**
 * Extract version information from a CPE string
 * 
 * @param {string} cpe - The CPE string
 * @returns {Object|null} - Version information or null if not found
 */
function extractVersionFromCpe(cpe) {
  if (!cpe) return null;
  
  // Split CPE into components
  const parts = cpe.split(':');
  if (parts.length < 6) return null;
  
  // Version is the 5th component (index 5)
  const version = parts[5];
  if (version === '*') return { version: '*' };
  
  // Check for version ranges in CPE (uncommon but possible)
  if (version.startsWith('<=') || version.startsWith('>=') || 
      version.startsWith('<') || version.startsWith('>') || 
      version.startsWith('==')) {
    const operator = version.match(/^[<>=]+/)[0];
    const versionNumber = version.substring(operator.length);
    return { operator, version: versionNumber };
  }
  
  return { version };
}

/**
 * Search for vulnerabilities across all sources
 * 
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @param {Object} config - Configuration options
 * @returns {Promise<Array>} - Combined vulnerabilities from all sources
 */
export async function searchAllSources(ecosystem, packageName, config) {
  // Fetch from NVD
  const nvdVulnerabilities = await fetchPackageVulnerabilities(ecosystem, packageName, config);
  
  return nvdVulnerabilities;
}

/**
 * Check if a version is vulnerable according to NVD data
 * 
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @param {string} packageVersion - The package version
 * @param {Object} config - Configuration options
 * @returns {Promise<Object>} - Vulnerability check result
 */
export async function checkNvdVulnerability(ecosystem, packageName, packageVersion, config) {
  // Fetch vulnerabilities
  const vulnerabilities = await fetchPackageVulnerabilities(ecosystem, packageName, config);
  
  if (vulnerabilities.length === 0) {
    return {
      isVulnerable: false,
      source: 'nvd',
      message: `No vulnerabilities found in NVD for ${packageName}@${packageVersion} (${ecosystem})`
    };
  }
  
  // Check each vulnerability
  const matchingVulnerabilities = vulnerabilities.filter(vuln => {
    const versionRange = vuln.vulnerable_versions;
    
    if (!versionRange || versionRange === '*') {
      // If no version is specified, consider it vulnerable
      return true;
    }
    
    if (ecosystem === 'npm') {
      try {
        // For npm, use semver
        return semver.satisfies(packageVersion, versionRange);
      } catch (error) {
        console.warn(`Invalid semver range for ${packageName}: ${versionRange}`);
        return false;
      }
    } else if (ecosystem === 'pip') {
      // For pip, use custom version comparison
      // This is simplified and should be replaced with a proper pip version comparison
      try {
        return isPipVersionVulnerable(packageVersion, versionRange);
      } catch (error) {
        console.warn(`Error comparing pip versions for ${packageName}: ${error.message}`);
        return false;
      }
    }
    
    // Default case
    return false;
  });
  
  if (matchingVulnerabilities.length > 0) {
    return {
      isVulnerable: true,
      source: 'nvd',
      vulnerabilities: matchingVulnerabilities,
      message: `${packageName}@${packageVersion} (${ecosystem}) has ${matchingVulnerabilities.length} known vulnerabilities in NVD`
    };
  } else {
    return {
      isVulnerable: false,
      source: 'nvd',
      message: `No matching vulnerabilities found in NVD for ${packageName}@${packageVersion} (${ecosystem})`
    };
  }
}

/**
 * Simple pip version comparison for NVD data
 * This is a duplicate of the function in index.js to avoid circular dependencies
 */
function isPipVersionVulnerable(version, range) {
  if (!version || !range) return false;
  
  // Split the range into parts (handles multiple constraints)
  const rangeParts = range.split(',');
  
  for (const part of rangeParts) {
    const operator = part.substring(0, 2);
    const rangeVersion = part.substring(2);
    
    // Split versions into components
    const versionParts = version.split('.').map(Number);
    const rangeParts = rangeVersion.split('.').map(Number);
    
    // Pad arrays to equal length
    while (versionParts.length < rangeParts.length) versionParts.push(0);
    while (rangeParts.length < versionParts.length) rangeParts.push(0);
    
    // Compare version components
    let comparison = 0;
    for (let i = 0; i < versionParts.length; i++) {
      if (versionParts[i] > rangeParts[i]) {
        comparison = 1;
        break;
      } else if (versionParts[i] < rangeParts[i]) {
        comparison = -1;
        break;
      }
    }
    
    // Check if version satisfies this part of the range
    if (operator === '<=') {
      if (comparison > 0) return false;
    } else if (operator === '>=') {
      if (comparison < 0) return false;
    } else if (operator === '==') {
      if (comparison !== 0) return false;
    } else if (operator === '!=') {
      if (comparison === 0) return false;
    } else if (operator.startsWith('<') && !operator.includes('=')) {
      if (comparison >= 0) return false;
    } else if (operator.startsWith('>') && !operator.includes('=')) {
      if (comparison <= 0) return false;
    }
  }
  
  // If all range constraints are satisfied, the version is vulnerable
  return true;
} 