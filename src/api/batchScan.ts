import axios from 'axios';
import config from '../config/config.js';
import { getKey } from './auth.js';
import { ApiOptions } from '../types/response.js';

interface PackageInfo {
  packageName: string;
  ecosystem: string;
  version: string;
}

interface BatchScanResponse {
  id: string;
  status: 'completed' | 'processing' | 'failed';
  results: {
    package: PackageInfo;
    status: 'safe' | 'vulnerable' | 'error';
    message: string;
    vulnerabilities?: Array<{
      id: string;
      title: string;
      severity: string;
      description: string;
      references: string[];
    }>;
    remediation?: {
      recommendedVersion: string;
      updateInstructions: string;
      alternativePackages: string[];
      notes: string;
    };
  }[];
}

/**
 * Perform a batch vulnerability scan for multiple packages
 */
export async function batchScan(packages: PackageInfo[], options: ApiOptions): Promise<BatchScanResponse> {
  const apiKey = await getKey();
  if (!apiKey) {
    throw new Error('VulnZap API key not configured. Please set VULNZAP_API_KEY environment variable.');
  }

  try {
    const response = await axios.post(
      `${config.api.engine}${config.api.vulnerability.batch}`,
      { packages },
      {
        headers: {
          'x-api-key': apiKey
        }
      }
    );

    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
      if (error.response) {
        throw new Error(`API Error: ${error.response.data?.message || error.message}`);
      }
      throw new Error(`Network error: ${error.message}`);
    }
    throw error;
  }
}