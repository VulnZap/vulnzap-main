/**
 * GitHub Advisory Database API Client
 * 
 * This module provides functionality to fetch and process vulnerability data from GitHub.
 * It includes functions for querying the GitHub Security Advisory API and mapping the results to the Vulnzap format.
 * 
 * Reference: https://docs.github.com/en/rest/security-advisories/global-advisories
 */

import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const DEFAULT_CONFIG = {
  githubToken: process.env.GITHUB_TOKEN || '',
  cacheDir: path.join(__dirname, 'cache'),
  cacheFile: 'github-advisories-cache.json',
  requestDelay: 1000, // 1 second between requests to respect rate limits
  baseUrl: 'https://api.github.com/advisories',
  perPage: 100, // Maximum number of results per page
  ecosystemMapping: {
    'npm': 'npm',
    'pip': 'pip',
    'pypi': 'pip',
    'gem': 'rubygems',
    'cargo': 'rust',
    'composer': 'composer',
    'go': 'go',
    'maven': 'maven',
    'nuget': 'nuget',
    'debian': 'debian',
    'ubuntu': 'ubuntu',
    'alpine': 'alpine',
    'centos': 'centos',
    'rhel': 'rhel'
  }
};

// Cache for GitHub Advisory data
let githubCache = new Map();
let lastFetchTime = 0;

/**
 * Initialize the GitHub client
 * @param {Object} customConfig - Custom configuration options
 */
export async function initGithubClient(customConfig = {}) {
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
        githubCache = new Map(cacheData.entries);
        lastFetchTime = cacheData.lastUpdate || 0;
        console.log(`Loaded ${githubCache.size} GitHub Advisory cache entries`);
      }
    } catch (error) {
      console.error(`Error loading GitHub Advisory cache: ${error.message}`);
    }
  }
  
  return { config };
}

/**
 * Save the GitHub cache to disk
 * @param {Object} config - Configuration options
 */
function saveCache(config) {
  const cacheFilePath = path.join(config.cacheDir, config.cacheFile);
  try {
    const cacheData = {
      lastUpdate: Date.now(),
      entries: Array.from(githubCache.entries())
    };
    
    fs.writeFileSync(cacheFilePath, JSON.stringify(cacheData, null, 2));
    console.log(`Saved ${githubCache.size} GitHub Advisory cache entries`);
  } catch (error) {
    console.error(`Error saving GitHub Advisory cache: ${error.message}`);
  }
}

/**
 * Fetch vulnerability data from GitHub for a specific package
 * 
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @param {Object} config - Configuration options
 * @returns {Promise<Array>} - Array of vulnerability advisories
 */
export async function fetchPackageVulnerabilities(ecosystem, packageName, config) {
  if (!config.githubToken) {
    console.warn('GitHub token not provided. Using public API with rate limits.');
  }
  
  // Check cache first
  const cacheKey = `${ecosystem}:${packageName}`;
  if (githubCache.has(cacheKey)) {
    const cachedData = githubCache.get(cacheKey);
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
  
  try {
    // Map ecosystem to GitHub's ecosystem identifier
    const githubEcosystem = config.ecosystemMapping[ecosystem] || ecosystem;
    
    // Construct the GitHub API URL with ecosystem and package name filtering
    let url = `${config.baseUrl}?ecosystem=${githubEcosystem}&package=${packageName}&per_page=${config.perPage}`;
    
    // Set headers including GitHub token
    const headers = {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28'
    };
    
    if (config.githubToken) {
      headers['Authorization'] = `Bearer ${config.githubToken}`;
    }
    
    // Make the request
    const response = await fetch(url, { headers });
    lastFetchTime = Date.now();
    
    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    const vulnerabilities = processGithubResponse(data, ecosystem, packageName);
    
    // Cache the result
    githubCache.set(cacheKey, {
      timestamp: Date.now(),
      vulnerabilities
    });
    
    // Save cache to disk
    saveCache(config);
    
    return vulnerabilities;
  } catch (error) {
    console.error(`Error fetching GitHub Advisory data for ${packageName} (${ecosystem}): ${error.message}`);
    return [];
  }
}

/**
 * Process the GitHub API response and extract vulnerability information
 * 
 * @param {Object} response - The GitHub API response
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @returns {Array} - Array of vulnerability advisories in Vulnzap format
 */
function processGithubResponse(response, ecosystem, packageName) {
  if (!Array.isArray(response)) {
    return [];
  }
  
  const result = [];
  
  for (const advisory of response) {
    if (!advisory || advisory.withdrawn_at) continue; // Skip withdrawn advisories
    
    // Find the relevant vulnerable package details
    const vulnerablePackage = advisory.vulnerabilities?.find(v => 
      v.package?.ecosystem?.toLowerCase() === ecosystem.toLowerCase() && 
      v.package?.name?.toLowerCase() === packageName.toLowerCase()
    );
    
    if (!vulnerablePackage) continue;
    
    // Extract version information
    const vulnerableVersions = vulnerablePackage.vulnerable_version_range || '*';
    const patched = vulnerablePackage.patched_versions || '';
    
    // Map severity
    const severity = mapGithubSeverity(advisory.severity);
    
    result.push({
      id: advisory.ghsa_id || `GHSA-${advisory.id}`,
      ecosystem: ecosystem,
      package: packageName,
      vulnerable_versions: vulnerableVersions,
      patched_versions: patched,
      title: advisory.summary || `Vulnerability in ${packageName}`,
      description: advisory.description || 'No description available',
      severity: severity,
      cvss_score: advisory.cvss?.score || 0,
      cve_id: advisory.cve_id || advisory.aliases?.find(a => a.startsWith('CVE-')) || 'No CVE',
      published_at: advisory.published_at,
      last_modified: advisory.updated_at,
      source: 'github'
    });
  }
  
  return result;
}

/**
 * Map GitHub severity to Vulnzap severity
 * 
 * @param {string} githubSeverity - GitHub severity level
 * @returns {string} - Vulnzap severity level (critical, high, medium, low)
 */
function mapGithubSeverity(githubSeverity) {
  if (!githubSeverity) return 'unknown';
  
  const severity = githubSeverity.toLowerCase();
  
  switch (severity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'unknown';
  }
}

/**
 * Fetch all GitHub advisories and write to a local file
 * 
 * @param {Object} config - Configuration options
 * @param {string} outputPath - Path to write the advisories file
 * @returns {Promise<number>} - Number of advisories fetched
 */
export async function fetchAllAdvisories(config, outputPath) {
  if (!config.githubToken) {
    console.warn('GitHub token not provided. Using public API with rate limits.');
  }
  
  const headers = {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
  
  if (config.githubToken) {
    headers['Authorization'] = `Bearer ${config.githubToken}`;
  }
  
  let page = 1;
  let hasMorePages = true;
  const allAdvisories = [];
  
  console.log('Fetching GitHub advisories...');
  
  while (hasMorePages) {
    // Respect rate limits
    if (lastFetchTime > 0) {
      const now = Date.now();
      if (now - lastFetchTime < config.requestDelay) {
        await new Promise(resolve => setTimeout(resolve, config.requestDelay - (now - lastFetchTime)));
      }
    }
    
    const url = `${config.baseUrl}?per_page=${config.perPage}&page=${page}`;
    
    try {
      console.log(`Fetching page ${page}...`);
      const response = await fetch(url, { headers });
      lastFetchTime = Date.now();
      
      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      
      if (!Array.isArray(data) || data.length === 0) {
        hasMorePages = false;
      } else {
        allAdvisories.push(...data);
        page++;
        
        // Process advisories in batches
        if (page % 10 === 0) {
          console.log(`Fetched ${allAdvisories.length} advisories so far...`);
        }
      }
    } catch (error) {
      console.error(`Error fetching GitHub advisories: ${error.message}`);
      hasMorePages = false;
    }
  }
  
  console.log(`Fetched a total of ${allAdvisories.length} advisories`);
  
  // Process and format the advisories
  const processedAdvisories = [];
  
  for (const advisory of allAdvisories) {
    if (!advisory || advisory.withdrawn_at) continue; // Skip withdrawn advisories
    
    // Process each vulnerable package
    for (const vulnerability of advisory.vulnerabilities || []) {
      if (!vulnerability.package) continue;
      
      const ecosystem = vulnerability.package.ecosystem;
      const packageName = vulnerability.package.name;
      
      // Skip if missing required fields
      if (!ecosystem || !packageName) continue;
      
      processedAdvisories.push({
        id: advisory.ghsa_id || `GHSA-${advisory.id}`,
        ecosystem: ecosystem,
        package: packageName,
        vulnerable_versions: vulnerability.vulnerable_version_range || '*',
        patched_versions: vulnerability.patched_versions || '',
        title: advisory.summary || `Vulnerability in ${packageName}`,
        description: advisory.description || 'No description available',
        severity: mapGithubSeverity(advisory.severity),
        cvss_score: advisory.cvss?.score || 0,
        cve_id: advisory.cve_id || advisory.aliases?.find(a => a.startsWith('CVE-')) || 'No CVE',
        published_at: advisory.published_at
      });
    }
  }
  
  // Write the results to file
  try {
    const outputData = {
      advisories: processedAdvisories,
      last_updated: new Date().toISOString()
    };
    
    fs.writeFileSync(outputPath, JSON.stringify(outputData, null, 2));
    console.log(`Wrote ${processedAdvisories.length} advisories to ${outputPath}`);
    
    return processedAdvisories.length;
  } catch (error) {
    console.error(`Error writing advisories to file: ${error.message}`);
    return 0;
  }
}

/**
 * Check if a package is vulnerable according to GitHub advisories
 * 
 * @param {string} ecosystem - The package ecosystem (npm, pip)
 * @param {string} packageName - The name of the package
 * @param {string} packageVersion - The version of the package
 * @param {Object} config - Configuration options
 * @returns {Promise<Object>} - Vulnerability check result
 */
export async function checkGithubVulnerability(ecosystem, packageName, packageVersion, config) {
  try {
    const vulnerabilities = await fetchPackageVulnerabilities(ecosystem, packageName, config);
    
    if (!vulnerabilities || vulnerabilities.length === 0) {
      return {
        isVulnerable: false,
        source: 'github',
        message: `Package ${packageName}@${packageVersion} (${ecosystem}) not found in GitHub Advisory Database`
      };
    }
    
    // Check if the version matches any vulnerable version range
    const matchingVulnerabilities = vulnerabilities.filter(vuln => {
      // For npm, we can use semver
      if (ecosystem === 'npm') {
        const semverResult = require('semver').satisfies(packageVersion, vuln.vulnerable_versions);
        return semverResult;
      } 
      // For pip, we use a custom implementation
      else if (ecosystem === 'pip') {
        return isPipVersionVulnerable(packageVersion, vuln.vulnerable_versions);
      }
      return false;
    });
    
    if (matchingVulnerabilities.length > 0) {
      return {
        isVulnerable: true,
        vulnerabilities: matchingVulnerabilities,
        source: 'github',
        message: `${packageName}@${packageVersion} (${ecosystem}) has ${matchingVulnerabilities.length} known vulnerabilities in GitHub Advisory Database`
      };
    }
    
    return {
      isVulnerable: false,
      source: 'github',
      message: `${packageName}@${packageVersion} (${ecosystem}) has no known vulnerabilities in GitHub Advisory Database`
    };
  } catch (error) {
    console.error(`Error checking GitHub vulnerability: ${error.message}`);
    return {
      isVulnerable: false,
      error: error.message,
      source: 'github'
    };
  }
}

/**
 * Check if a pip package version is vulnerable based on version ranges
 * 
 * @param {string} version - The version to check
 * @param {string} range - The pip version range string
 * @returns {boolean} - True if vulnerable, false if not
 */
function isPipVersionVulnerable(version, range) {
  // For pip, we'll implement a simplified version comparison
  // This handles basic ranges like "<=2.25.0", ">=2.25.1", "<1.1.3,>=1.0"
  
  if (!version || !range) return false;
  
  // Split the range into parts (handles multiple constraints)
  const rangeParts = range.split(',');
  
  for (const part of rangeParts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    
    // Extract operator and version
    const operator = trimmed.substring(0, 2);
    const rangeVersion = trimmed.substring(2);
    
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