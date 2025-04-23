import { v4 } from 'uuid';
import config from '../config/config.js';

const API_BASE_URL = config.api.baseUrl + config.api.addOn;

export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      method: 'GET',
    });
    if (response.ok) {
      return {
        status: "ok"
      };
    } else {
      return {
        status: "down"
      }
    }
  } catch (error) {
    return {
      status: "down"
    }
  }
}

export async function sendSbomResults(sbomResults: any): Promise<{
  status: 'success' | 'error';
  message: string;
  traceId: string | null;
}> {
  try {
    const response = await fetch(`${API_BASE_URL}${config.api.vulnerability.sbom}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        traceId: v4(),
        results: sbomResults,
        format: 'cyclonedx'
      }),
    });
    const data = await response.json();
    if (response.ok && data.status === 'success') {
      return {
        status: 'success',
        message: 'SBOM results sent successfully',
        traceId: data.data.traceId,
      };
    } else {
      return {
        status: 'error',
        message: data.message || 'Failed to send SBOM results',
        traceId: data.traceId,
      };
    }
  } catch (error) {
    return {
      status: 'error',
      message: 'Failed to send SBOM results',
      traceId: null,
    };
  }
}