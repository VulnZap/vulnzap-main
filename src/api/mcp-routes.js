/**
 * Model Context Protocol (MCP) API Routes
 * 
 * This module defines the API routes for the Model Context Protocol (MCP) server.
 * It enables LLMs to interact with Vulnzap for vulnerability scanning across multiple ecosystems.
 */

import express from 'express';
import { ScannerManager } from '../core/scanner-manager.js';
import { CONFIG } from '../core/config.js';

// Create router
const router = express.Router();

// Initialize scanner manager
const scannerManager = new ScannerManager();

// Wait for scanner to be ready
let scannerReady = false;
scannerManager.on('ready', () => {
  scannerReady = true;
  console.log('Scanner manager ready');
});

scannerManager.on('error', (error) => {
  console.error('Scanner manager error:', error);
});

/**
 * MCP server info endpoint
 */
router.get('/', (req, res) => {
  res.json({
    name: 'Vulnzap MCP Server',
    version: '2.0.0',
    description: 'Vulnerability scanning service for multiple package ecosystems',
    status: scannerReady ? 'ready' : 'initializing',
    endpoints: [
      {
        path: '/vulnerabilities',
        description: 'Check a package for vulnerabilities',
        method: 'POST'
      },
      {
        path: '/scan-directory',
        description: 'Scan a directory for vulnerabilities',
        method: 'POST'
      },
      {
        path: '/batch-scan',
        description: 'Scan multiple packages in batch',
        method: 'POST'
      },
      {
        path: '/ecosystems',
        description: 'List supported ecosystems',
        method: 'GET'
      }
    ],
    supportedEcosystems: CONFIG.ENABLED_ECOSYSTEMS,
    premium: !!CONFIG.API_KEYS.PREMIUM_API_KEY,
  });
});

/**
 * List supported ecosystems
 */
router.get('/ecosystems', (req, res) => {
  const ecosystems = CONFIG.ENABLED_ECOSYSTEMS.map(eco => {
    const ecosystemConfig = CONFIG.ECOSYSTEMS[eco];
    return {
      name: eco,
      displayName: ecosystemConfig?.displayName || eco,
      packageManager: ecosystemConfig?.packageManager || eco,
      website: ecosystemConfig?.website || null,
      supportedVersionFormats: ecosystemConfig?.supportedVersionFormats || [],
      description: ecosystemConfig?.description || `Support for ${eco} packages`,
    };
  });
  
  res.json({ ecosystems });
});

/**
 * Check if scanner is ready or return error
 */
function checkScannerReady(req, res, next) {
  if (!scannerReady) {
    return res.status(503).json({
      error: 'Service is initializing. Please try again in a few moments.'
    });
  }
  next();
}

/**
 * Verify premium API key if present
 */
function verifyApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  
  // If premium features are requested but no API key provided
  if (req.body.premium && !apiKey) {
    return res.status(401).json({
      error: 'API key required for premium features'
    });
  }
  
  // If API key provided, verify it
  if (apiKey && apiKey !== CONFIG.API_KEYS.PREMIUM_API_KEY) {
    return res.status(401).json({
      error: 'Invalid API key'
    });
  }
  
  // Set premium flag based on API key
  req.isPremium = apiKey === CONFIG.API_KEYS.PREMIUM_API_KEY;
  
  next();
}

/**
 * Check a package for vulnerabilities
 */
router.post('/vulnerabilities', checkScannerReady, verifyApiKey, async (req, res) => {
  try {
    const { packageName, version, ecosystem } = req.body;
    
    // Validate required parameters
    if (!packageName || !version || !ecosystem) {
      return res.status(400).json({
        error: 'Missing required parameters: packageName, version, and ecosystem are required'
      });
    }
    
    // Check if ecosystem is supported
    if (!CONFIG.ENABLED_ECOSYSTEMS.includes(ecosystem)) {
      return res.status(400).json({
        error: `Unsupported ecosystem: ${ecosystem}`,
        supportedEcosystems: CONFIG.ENABLED_ECOSYSTEMS
      });
    }
    
    // Set scan options
    const options = {
      premium: req.isPremium,
      includeDetails: req.body.includeDetails || false,
      includeReferences: req.body.includeReferences || false,
      noCache: req.body.noCache || false
    };
    
    // Scan package
    const vulnerabilities = await scannerManager.scanPackage(packageName, version, ecosystem, options);
    
    // Format response
    const response = {
      packageName,
      version,
      ecosystem,
      timestamp: new Date().toISOString(),
      vulnerabilities: vulnerabilities.map(vuln => {
        // Basic vulnerability info
        const result = {
          id: vuln.id,
          title: vuln.title,
          severity: vuln.severity,
          cvss: vuln.cvss,
        };
        
        // Add CVE if available
        if (vuln.cve) {
          result.cve = vuln.cve;
        }
        
        // Include additional details if requested or premium
        if (options.includeDetails || options.premium) {
          result.description = vuln.description;
          result.fixedVersions = vuln.fixedVersions || [];
          result.published = vuln.published;
          result.modified = vuln.modified;
        }
        
        // Include references if requested or premium
        if (options.includeReferences || options.premium) {
          result.references = vuln.references || [];
        }
        
        return result;
      })
    };
    
    // Add remediation advice for premium users
    if (req.isPremium && vulnerabilities.length > 0) {
      response.remediation = scannerManager.getRemediationAdvice(
        packageName, 
        version, 
        ecosystem, 
        vulnerabilities
      );
    }
    
    res.json(response);
  } catch (error) {
    console.error('Error scanning package:', error);
    res.status(500).json({
      error: 'Error scanning package',
      message: error.message
    });
  }
});

/**
 * Scan a directory for vulnerabilities
 */
router.post('/scan-directory', checkScannerReady, verifyApiKey, async (req, res) => {
  try {
    const { directory } = req.body;
    
    // Validate required parameters
    if (!directory) {
      return res.status(400).json({
        error: 'Missing required parameter: directory'
      });
    }
    
    // Set scan options
    const options = {
      premium: req.isPremium,
      includeDetails: req.body.includeDetails || false,
      includeReferences: req.body.includeReferences || false,
      batch: req.body.batch || false,
      batchSize: req.body.batchSize || 10,
      noCache: req.body.noCache || false
    };
    
    // Scan directory
    const scanResults = await scannerManager.scanDirectory(directory, options);
    
    // Check for errors
    if (scanResults.error) {
      return res.status(400).json({
        error: scanResults.error
      });
    }
    
    // Generate report
    if (req.isPremium && req.body.generateReport) {
      const reportOptions = {
        includeRemediation: req.body.includeRemediation || false,
        scanId: req.body.scanId || `scan-${Date.now()}`
      };
      
      const report = scannerManager.generateReport(scanResults, reportOptions);
      scanResults.report = report;
    }
    
    res.json({
      directory,
      timestamp: new Date().toISOString(),
      results: scanResults
    });
  } catch (error) {
    console.error('Error scanning directory:', error);
    res.status(500).json({
      error: 'Error scanning directory',
      message: error.message
    });
  }
});

/**
 * Batch scan multiple packages
 */
router.post('/batch-scan', checkScannerReady, verifyApiKey, async (req, res) => {
  try {
    const { packages } = req.body;
    
    // Validate required parameters
    if (!packages || !Array.isArray(packages) || packages.length === 0) {
      return res.status(400).json({
        error: 'Missing or invalid required parameter: packages (array)'
      });
    }
    
    // Validate package format
    for (const pkg of packages) {
      if (!pkg.name || !pkg.version || !pkg.ecosystem) {
        return res.status(400).json({
          error: 'Invalid package format. Each package must have name, version, and ecosystem properties.',
          example: {
            packages: [
              { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
              { name: 'django', version: '3.2.0', ecosystem: 'pip' }
            ]
          }
        });
      }
      
      // Check if ecosystem is supported
      if (!CONFIG.ENABLED_ECOSYSTEMS.includes(pkg.ecosystem)) {
        return res.status(400).json({
          error: `Unsupported ecosystem: ${pkg.ecosystem}`,
          supportedEcosystems: CONFIG.ENABLED_ECOSYSTEMS
        });
      }
    }
    
    // Set scan options
    const options = {
      premium: req.isPremium,
      includeDetails: req.body.includeDetails || false,
      includeReferences: req.body.includeReferences || false,
      concurrency: req.body.concurrency || 3,
      timeout: req.body.timeout || 60000,
      noCache: req.body.noCache || false
    };
    
    // Batch scan
    const batchResults = await scannerManager.batchScan(packages, options);
    
    // Format response
    const formattedResults = batchResults.map(result => {
      const formattedResult = {
        packageName: result.packageName,
        version: result.version,
        ecosystem: result.ecosystem,
        vulnerabilities: result.vulnerabilities.map(vuln => {
          // Basic vulnerability info
          const vulnInfo = {
            id: vuln.id,
            title: vuln.title,
            severity: vuln.severity,
            cvss: vuln.cvss,
          };
          
          // Add CVE if available
          if (vuln.cve) {
            vulnInfo.cve = vuln.cve;
          }
          
          // Include additional details if requested or premium
          if (options.includeDetails || options.premium) {
            vulnInfo.description = vuln.description;
            vulnInfo.fixedVersions = vuln.fixedVersions || [];
            vulnInfo.published = vuln.published;
            vulnInfo.modified = vuln.modified;
          }
          
          // Include references if requested or premium
          if (options.includeReferences || options.premium) {
            vulnInfo.references = vuln.references || [];
          }
          
          return vulnInfo;
        })
      };
      
      // Add remediation advice for premium users
      if (req.isPremium && result.vulnerabilities.length > 0) {
        formattedResult.remediation = scannerManager.getRemediationAdvice(
          result.packageName, 
          result.version, 
          result.ecosystem, 
          result.vulnerabilities
        );
      }
      
      // Add error if any
      if (result.error) {
        formattedResult.error = result.error;
      }
      
      return formattedResult;
    });
    
    // Generate summary report for premium users
    let summary = null;
    if (req.isPremium && req.body.generateSummary) {
      summary = {
        totalPackages: batchResults.length,
        vulnerablePackages: batchResults.filter(result => result.vulnerabilities && result.vulnerabilities.length > 0).length,
        totalVulnerabilities: batchResults.reduce((total, result) => total + (result.vulnerabilities ? result.vulnerabilities.length : 0), 0),
        severityCounts: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0
        },
        ecosystemCounts: {},
        timestamp: new Date().toISOString()
      };
      
      // Count vulnerabilities by severity and ecosystem
      for (const result of batchResults) {
        if (result.vulnerabilities) {
          // Count by ecosystem
          summary.ecosystemCounts[result.ecosystem] = (summary.ecosystemCounts[result.ecosystem] || 0) + 1;
          
          // Count by severity
          for (const vuln of result.vulnerabilities) {
            const severity = vuln.severity.toLowerCase();
            if (severity === 'critical') summary.severityCounts.critical++;
            else if (severity === 'high') summary.severityCounts.high++;
            else if (severity === 'medium') summary.severityCounts.medium++;
            else if (severity === 'low') summary.severityCounts.low++;
            else summary.severityCounts.unknown++;
          }
        }
      }
    }
    
    res.json({
      timestamp: new Date().toISOString(),
      results: formattedResults,
      summary
    });
  } catch (error) {
    console.error('Error in batch scan:', error);
    res.status(500).json({
      error: 'Error in batch scan',
      message: error.message
    });
  }
});

/**
 * Health check endpoint
 */
router.get('/health', (req, res) => {
  res.json({
    status: scannerReady ? 'healthy' : 'initializing',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

export default router; 