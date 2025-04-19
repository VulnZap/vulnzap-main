// Type definitions
export interface Ecosystem {
    name: string;
    displayName: string;
    packageManager: string;
    website: string | null;
    supportedVersionFormats: string[];
    description: string;
}

export interface Vulnerability {
    id: string;
    severity: string;
    title: string;
    description: string;
    fixedVersions: string[];
    references: string[];
}

export interface ScanResponse {
    packageName: string;
    version: string;
    ecosystem: string;
    timestamp: string;
    vulnerabilities: Vulnerability[];
    processedVulnerabilities: any;
    remediation?: {
        packageName: string;
        currentVersion: string;
        ecosystem: string;
        recommendedVersion: string;
        updateInstructions: string;
        alternativePackages: string[];
        notes: string;
    };
}

export interface BatchScanResponse {
    timestamp: string;
    results: Array<{
        package: string;
        version: string;
        ecosystem: string;
        vulnerabilities: Vulnerability[];
    }>;
}

export interface SBOMResponse {
    projectId: string;
    format: string;
    timestamp: string;
    sbom: any;
}

export interface UsageStatsResponse {
    period: string;
    stats: Array<{
        date: string;
        scans_count: number;
        batch_scans_count: number;
        ai_scans_count: number;
        sbom_scans_count: number;
    }>;
    limits: {
        scans: number;
        batchScans: number;
        aiScans: number;
        sbomScans: number;
    };
    features: {
        aiAssistedScans: boolean;
        sbomScanning: boolean;
        privateRepos: boolean;
        githubPrBot: boolean;
        githubPrAutopatch: boolean;
    };
}

export interface RemediationAdvice {
    packageName: string;
    currentVersion: string;
    ecosystem: string;
    recommendedVersion: string;
    updateInstructions: string;
    alternativePackages: string[];
    notes: string;
}