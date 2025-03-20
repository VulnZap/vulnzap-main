/**
 * Vulnzap Test Client
 * 
 * This script demonstrates various ways to use the Vulnzap multi-ecosystem
 * vulnerability scanner through its MCP API.
 */

import fetch from 'node-fetch';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Configuration
const API_URL = process.env.API_URL || 'http://localhost:3000/api/mcp';
const PREMIUM_API_KEY = process.env.PREMIUM_API_KEY;

/**
 * Make an API request to Vulnzap
 */
async function apiRequest(endpoint, method = 'GET', data = null, premium = false) {
  const url = `${API_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
  };
  
  // Add premium API key if available and requested
  if (premium && PREMIUM_API_KEY) {
    headers['x-api-key'] = PREMIUM_API_KEY;
  }
  
  const options = {
    method,
    headers,
  };
  
  // Add body data for non-GET requests
  if (data && method !== 'GET') {
    options.body = JSON.stringify(data);
  }
  
  try {
    const response = await fetch(url, options);
    const responseData = await response.json();
    
    if (!response.ok) {
      throw new Error(`API Error: ${responseData.error || response.statusText}`);
    }
    
    return responseData;
  } catch (error) {
    console.error(`Request failed: ${error.message}`);
    throw error;
  }
}

/**
 * Print a section header
 */
function printSection(title) {
  const border = '='.repeat(title.length + 8);
  console.log('\n' + border);
  console.log(`    ${title}`);
  console.log(border + '\n');
}

/**
 * Format and print scan results
 */
function printVulnResults(results) {
  const vulnCount = results.vulnerabilities.length;
  
  console.log(`\nPackage: ${results.packageName}@${results.version} (${results.ecosystem})`);
  console.log(`Timestamp: ${results.timestamp}`);
  console.log(`Found: ${vulnCount} vulnerabilities\n`);
  
  if (vulnCount === 0) {
    console.log('No vulnerabilities found. Package appears to be safe.\n');
    return;
  }
  
  // Print vulnerabilities by severity
  const severityOrder = ['critical', 'high', 'medium', 'low', 'unknown'];
  
  for (const severity of severityOrder) {
    const vulnsWithSeverity = results.vulnerabilities.filter(v => v.severity === severity);
    
    if (vulnsWithSeverity.length > 0) {
      console.log(`${severity.toUpperCase()} severity vulnerabilities (${vulnsWithSeverity.length}):`);
      
      for (const vuln of vulnsWithSeverity) {
        console.log(`- ${vuln.title} ${vuln.cve ? `(${vuln.cve})` : ''}`);
        
        if (vuln.description) {
          // Format description as an indented paragraph
          const description = vuln.description
            .split('\n')
            .map(line => `  ${line}`)
            .join('\n');
          console.log(description);
        }
        
        if (vuln.cvss) {
          console.log(`  CVSS Score: ${vuln.cvss}`);
        }
        
        if (vuln.fixedVersions && vuln.fixedVersions.length > 0) {
          console.log(`  Fixed in versions: ${vuln.fixedVersions.join(', ')}`);
        }
        
        console.log(''); // Empty line for readability
      }
    }
  }
  
  // Print remediation advice if available
  if (results.remediation) {
    console.log('REMEDIATION ADVICE:');
    console.log(`- Recommended version: ${results.remediation.recommendedVersion || 'No specific version recommended'}`);
    
    if (results.remediation.updateInstructions) {
      console.log(`- Update command: ${results.remediation.updateInstructions}`);
    }
    
    if (results.remediation.notes) {
      console.log(`- Notes: ${results.remediation.notes}`);
    }
    
    console.log(''); // Empty line for readability
  }
}

/**
 * Check a list of packages from various ecosystems
 */
async function checkMultiplePackages() {
  printSection('Testing Multiple Ecosystems');
  
  const testPackages = [
    { name: 'express', version: '4.17.1', ecosystem: 'npm' },
    { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
    { name: 'django', version: '3.0.6', ecosystem: 'pip' },
    { name: 'flask', version: '1.1.1', ecosystem: 'pip' },
    { name: 'github.com/gin-gonic/gin', version: 'v1.6.3', ecosystem: 'go' },
    { name: 'serde', version: '1.0.101', ecosystem: 'cargo' },
    { name: 'org.springframework:spring-core', version: '5.2.5.RELEASE', ecosystem: 'maven' },
    { name: 'Newtonsoft.Json', version: '12.0.2', ecosystem: 'nuget' },
    { name: 'symfony/symfony', version: '4.3.8', ecosystem: 'composer' },
  ];
  
  console.log(`Testing ${testPackages.length} packages across multiple ecosystems...\n`);
  
  // Check each package individually
  for (const pkg of testPackages) {
    try {
      console.log(`Scanning ${pkg.name}@${pkg.version} (${pkg.ecosystem})...`);
      
      const usePremium = Math.random() > 0.5 && PREMIUM_API_KEY; // Randomly use premium for demo
      
      const results = await apiRequest('/vulnerabilities', 'POST', {
        packageName: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
        includeDetails: true,
        includeReferences: true
      }, usePremium);
      
      // Print a summary of the results
      const vulnCount = results.vulnerabilities.length;
      const severities = results.vulnerabilities.map(v => v.severity);
      const hasCritical = severities.includes('critical');
      const hasHigh = severities.includes('high');
      
      console.log(`  Result: ${vulnCount} vulnerabilities found`);
      
      if (vulnCount > 0) {
        if (hasCritical) {
          console.log('  ⚠️  CRITICAL vulnerabilities present!');
        } else if (hasHigh) {
          console.log('  ⚠️  HIGH vulnerabilities present!');
        }
      } else {
        console.log('  ✅ No vulnerabilities detected');
      }
      
      console.log(''); // Empty line for readability
    } catch (error) {
      console.error(`  ❌ Error scanning ${pkg.name}: ${error.message}\n`);
    }
  }
}

/**
 * Perform a batch scan of multiple packages
 */
async function batchScanPackages() {
  printSection('Batch Scanning Packages');
  
  // Premium feature - requires API key
  if (!PREMIUM_API_KEY) {
    console.log('Skipping batch scan - no premium API key available');
    return;
  }
  
  const packagesToScan = [
    { name: 'express', version: '4.17.1', ecosystem: 'npm' },
    { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
    { name: 'django', version: '3.0.6', ecosystem: 'pip' },
    { name: 'flask', version: '1.1.1', ecosystem: 'pip' },
  ];
  
  console.log(`Batch scanning ${packagesToScan.length} packages...`);
  
  try {
    const results = await apiRequest('/batch-scan', 'POST', {
      packages: packagesToScan,
      generateReport: true,
      includeRemediation: true
    }, true);
    
    console.log(`\nBatch scan complete. Scanned ${results.totalPackages} packages.`);
    
    if (results.report) {
      const summary = results.report.summary;
      
      console.log('\nSCAN SUMMARY:');
      console.log(`- Total packages scanned: ${summary.scannedPackages}`);
      console.log(`- Vulnerable packages: ${summary.vulnerablePackages}`);
      console.log(`- Total vulnerabilities: ${summary.totalVulnerabilities}`);
      console.log(`  * Critical: ${summary.criticalVulnerabilities}`);
      console.log(`  * High: ${summary.highVulnerabilities}`);
      console.log(`  * Medium: ${summary.mediumVulnerabilities}`);
      console.log(`  * Low: ${summary.lowVulnerabilities}`);
      
      // Print ecosystems summary
      console.log('\nECOSYSTEMS:');
      for (const [eco, ecoData] of Object.entries(summary.ecosystems)) {
        console.log(`- ${eco}: ${ecoData.vulnerablePackages}/${ecoData.scannedPackages} vulnerable, ${ecoData.totalVulnerabilities} vulnerabilities`);
      }
    }
  } catch (error) {
    console.error(`Batch scan failed: ${error.message}`);
  }
}

/**
 * Get detailed report for a vulnerable package
 */
async function getDetailedReport() {
  printSection('Detailed Vulnerability Report');
  
  const packageToScan = {
    packageName: 'lodash',
    version: '4.17.15',
    ecosystem: 'npm'
  };
  
  console.log(`Getting detailed report for ${packageToScan.packageName}@${packageToScan.version} (${packageToScan.ecosystem})...`);
  
  try {
    const results = await apiRequest('/vulnerabilities', 'POST', {
      ...packageToScan,
      includeDetails: true,
      includeReferences: true
    }, !!PREMIUM_API_KEY);
    
    printVulnResults(results);
  } catch (error) {
    console.error(`Failed to get detailed report: ${error.message}`);
  }
}

/**
 * Get update suggestion for a vulnerable package
 */
async function getSuggestedUpdate() {
  printSection('Suggested Update (Premium Feature)');
  
  // Premium feature - requires API key
  if (!PREMIUM_API_KEY) {
    console.log('Skipping update suggestion - no premium API key available');
    return;
  }
  
  const packageToCheck = {
    packageName: 'lodash',
    version: '4.17.15',
    ecosystem: 'npm'
  };
  
  console.log(`Getting update suggestion for ${packageToCheck.packageName}@${packageToCheck.version} (${packageToCheck.ecosystem})...`);
  
  try {
    const results = await apiRequest('/suggest-update', 'POST', packageToCheck, true);
    
    console.log(`\nPackage: ${results.packageName}@${results.version} (${results.ecosystem})`);
    console.log(`Vulnerabilities: ${results.vulnerabilityCount}`);
    
    if (results.remediation) {
      console.log('\nREMEDIATION ADVICE:');
      console.log(`- Current version: ${results.remediation.currentVersion}`);
      console.log(`- Recommended version: ${results.remediation.recommendedVersion || 'No specific version recommended'}`);
      
      if (results.remediation.updateInstructions) {
        console.log(`- Update command: ${results.remediation.updateInstructions}`);
      }
      
      if (results.remediation.notes) {
        console.log(`- Notes: ${results.remediation.notes}`);
      }
    }
  } catch (error) {
    console.error(`Failed to get update suggestion: ${error.message}`);
  }
}

/**
 * List supported ecosystems
 */
async function listEcosystems() {
  printSection('Supported Ecosystems');
  
  try {
    const results = await apiRequest('/ecosystems');
    
    console.log(`Vulnzap supports ${results.ecosystems.length} package ecosystems:\n`);
    
    results.ecosystems.forEach(eco => {
      console.log(`- ${eco.displayName} (${eco.name})`);
      console.log(`  Package Manager: ${eco.packageManager}`);
      
      if (eco.website) {
        console.log(`  Website: ${eco.website}`);
      }
      
      if (eco.description) {
        console.log(`  ${eco.description}`);
      }
      
      console.log(''); // Empty line for readability
    });
  } catch (error) {
    console.error(`Failed to list ecosystems: ${error.message}`);
  }
}

/**
 * Check if server is running
 */
async function checkServerStatus() {
  printSection('Checking Server Status');
  
  try {
    const status = await apiRequest('/');
    
    console.log(`Vulnzap Server Status: ${status.status}`);
    console.log(`Version: ${status.version}`);
    console.log(`Description: ${status.description}`);
    console.log(`Supported Ecosystems: ${status.supportedEcosystems.join(', ')}`);
    console.log(`Premium Mode: ${status.premium ? 'Enabled' : 'Disabled'}`);
    
    console.log('\nServer is up and running! 🚀\n');
    return true;
  } catch (error) {
    console.error('ERROR: Vulnzap server is not running or not accessible.');
    console.error(`Make sure the server is running at ${API_URL}`);
    console.error('Try starting the server with: npm start\n');
    return false;
  }
}

/**
 * Main function
 */
async function main() {
  console.log('Vulnzap Test Client\n');
  console.log('This client demonstrates the multi-ecosystem vulnerability scanning capabilities of Vulnzap.');
  
  // Check if server is running
  const serverRunning = await checkServerStatus();
  
  if (!serverRunning) {
    process.exit(1);
  }
  
  // List supported ecosystems
  await listEcosystems();
  
  // Check packages from multiple ecosystems
  await checkMultiplePackages();
  
  // Get detailed report for a vulnerable package
  await getDetailedReport();
  
  // Perform batch scan
  await batchScanPackages();
  
  // Get update suggestion
  await getSuggestedUpdate();
  
  console.log('\nTest client completed. 🎉\n');
}

// Run the main function
main().catch(error => {
  console.error('Test client failed:', error);
  process.exit(1);
}); 