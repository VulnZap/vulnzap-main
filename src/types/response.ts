// The 3 types are made different but are in same format due to the assumption that in future we may require them to behave differently and add source specific fields. 
export interface GitHubVulnerability {
    severity: string;
    cveId: string;
    ghsaId: string;
    vulnerableVersionRange: string;
    firstPatchedVersion: string;
    summary: string;
    cveStatus?: string;
    ghsaStatus?: string;
    description: string;
    publishedAt: string;
    updatedAt: string;
    references: string[];
}

export interface NvdVulnerability {
    severity: string;
    cveId: string;
    ghsaId: string;
    cveStatus?: string;
    ghsaStatus?: string;
    vulnerableVersionRange: string;
    firstPatchedVersion: string;
    summary: string;
    description: string;
    publishedAt: string;
    updatedAt: string;
    references: string[];
}

export interface OsvVulnerability {
    severity: string;
    cveId: string;
    ghsaId: string;
    cveStatus?: string;
    ghsaStatus?: string;
    vulnerableVersionRange: string;
    firstPatchedVersion: string;
    summary: string;
    description: string;
    publishedAt: string;
    updatedAt: string;
    references: string[];
}

export interface VulnerabilitiesSource {
    github?: any[];
    nvd?: any[];
    osv?: any[];
    database?: any[];
}

export interface ScannerError {
    code: string;
    message: string;
    source?: string;
}

export interface VulnerabilityResult {
    message: string;
    found: boolean;
    dataSources?: VulnerabilitiesSource;
    error?: ScannerError;
} 

export interface BatchScanResponse {
    package: PackageInfo,
    result: VulnerabilityResult,
    processedResult: any
}

export interface PackageInfo {
    packageName: string;
    ecosystem: string;
    version: string;
}
  
export interface ScanResponse {
    package: PackageInfo;
    timestamp: string;
    status: 'safe' | 'vulnerable' | 'error';
    vulnerabilities?: VulnerabilitiesSource;
    remediation?: {
      recommendedVersion: string;
      updateInstructions: string;
      alternativePackages: string[];
      notes: string;
    };
    processedVulnerabilities?: any;
  }