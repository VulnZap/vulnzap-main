import axios from 'axios';
import config from '../config/config.js';
import { getKey } from './auth.js';

export interface RepoScanRequest {
  repoUrl: string;
  branch?: string;
  key?: string;
}

export interface RepoScanResponse {
  success: boolean;
  data: {
    jobId: string;
    projectId: string;
    status: 'pending' | 'processing' | 'completed' | 'failed';
    message: string;
    repository: string;
    branch: string;
    remaining: number;
  };
}

export interface ScanEvent {
  type: 'connected' | 'progress' | 'vulnerability' | 'completed' | 'failed';
  jobId: string;
  data: any;
  timestamp: string;
}

/**
 * Start a repository vulnerability scan
 */
export async function startRepoScan(request: RepoScanRequest): Promise<RepoScanResponse> {
  const apiKey = request.key || await getKey();
  if (!apiKey) {
    throw new Error('VulnZap API key not configured. Please run "vulnzap setup" first.');
  }

  // Validate repo URL format
  if (!request.repoUrl || !/github\.com\/[^/]+\/[^/]+$/.test(request.repoUrl)) {
    throw new Error('Invalid repository URL. Expected format: https://github.com/owner/repo');
  }

  // Convert the repoUrl to the format owner/repo
  const owner = request.repoUrl.split('/')[3];
  const repo = request.repoUrl.split('/')[4];
  const repoUrl = `${owner}/${repo}`;
  try {
    const response = await axios.post(
      `${config.api.engine}${config.api.repo.scan}`,
      {
        repository: repoUrl,
        branch: request.branch || 'main'
      },
      {
        headers: {
          'x-api-key': apiKey,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
      if (error.response) {
        // Handle specific API error responses
        const statusCode = error.response.status;
        const errorMessage = error.response.data?.message || error.message;

        switch (statusCode) {
          case 401:
            throw new Error('Authentication failed. Please check your API key.');
          case 403:
            throw new Error('Access denied. Please check your account permissions.');
          case 429:
            throw new Error('Rate limit exceeded. Please try again later.');
          case 400:
            throw new Error(`Invalid request: ${errorMessage}`);
          default:
            throw new Error(`API Error (${statusCode}): ${errorMessage}`);
        }
      }
      throw new Error(`Network error: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Stream real-time events for a repository scan using Server-Sent Events
 */
export async function streamScanEvents(
  scanId: string,
  onEvent: (event: ScanEvent) => void,
  onError?: (error: Error) => void
): Promise<void> {
  const apiKey = await getKey();
  if (!apiKey) {
    throw new Error('VulnZap API key not configured. Please run "vulnzap setup" first.');
  }

  try {
    const eventsUrl = `${config.api.engine}${config.api.repo.scan}/${scanId}/events`;

    const response = await fetch(eventsUrl, {
      method: 'GET',
      headers: {
        'x-api-key': apiKey,
        'Accept': 'text/event-stream',
        'Cache-Control': 'no-cache'
      }
    });

    if (!response.ok) {
      const responseText = await response.text();
      throw new Error(`Failed to connect to event stream: ${response.status} - ${responseText}`);
    }

    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('Failed to get response reader');
    }

    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          break;
        }

        const chunk = decoder.decode(value, { stream: true });
        buffer += chunk;
        
        const lines = buffer.split('\n');

        // Keep the last incomplete line in buffer
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const eventData = JSON.parse(line.slice(6));

              // Transform scanId to jobId if present (backend compatibility)
              if (eventData.scanId && !eventData.jobId) {
                eventData.jobId = eventData.scanId;
                delete eventData.scanId;
              }

              onEvent(eventData);

              // Stop reading if we receive a completed event
              if (eventData.type === 'completed') {
                reader.cancel();
                return;
              }
            } catch (parseError) {
              console.warn('Failed to parse event data:', parseError);
            }
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  } catch (error) {
    if (onError) {
      onError(error instanceof Error ? error : new Error('Unknown error'));
    } else {
      throw error;
    }
  }
}

/**
 * Get detailed scan results from the jobs endpoint
 */
export async function getScanResults(jobId: string): Promise<any> {
  const apiKey = await getKey();
  if (!apiKey) {
    throw new Error('VulnZap API key not configured. Please run "vulnzap setup" first.');
  }

  try {
    const response = await axios.get(
      `${config.api.engine}${config.api.jobs.get}/${jobId}`,
      {
        headers: {
          'x-api-key': apiKey,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
      if (error.response) {
        const statusCode = error.response.status;
        const errorMessage = error.response.data?.message || error.message;

        switch (statusCode) {
          case 401:
            throw new Error('Authentication failed. Please check your API key.');
          case 404:
            throw new Error('Scan results not found. The scan may not be completed yet.');
          default:
            throw new Error(`API Error (${statusCode}): ${errorMessage}`);
        }
      }
      throw new Error(`Network error: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Check the status of a repository scan (fallback for when SSE is not available)
 */
export async function getRepoScanStatus(scanId: string): Promise<RepoScanResponse> {
  const apiKey = await getKey();
  if (!apiKey) {
    throw new Error('VulnZap API key not configured. Please run "vulnzap setup" first.');
  }

  try {
    const response = await axios.get(
      `${config.api.engine}${config.api.repo.scan}/${scanId}`,
      {
        headers: {
          'x-api-key': apiKey,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
      if (error.response) {
        const statusCode = error.response.status;
        const errorMessage = error.response.data?.message || error.message;

        switch (statusCode) {
          case 401:
            throw new Error('Authentication failed. Please check your API key.');
          case 404:
            throw new Error('Scan not found. It may have been deleted or never existed.');
          default:
            throw new Error(`API Error (${statusCode}): ${errorMessage}`);
        }
      }
      throw new Error(`Network error: ${error.message}`);
    }
    throw error;
  }
}
