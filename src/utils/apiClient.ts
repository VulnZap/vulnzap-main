import axios, { AxiosRequestConfig, Method } from 'axios';

/**
 * Runs an async function with exponential backoff on failure (e.g., 500 errors, network errors).
 * @param fn The async function to run (should throw on error)
 * @param maxRetries Maximum number of retries (default 5)
 * @param initialDelay Initial delay in ms (default 500)
 * @returns The result of the function if successful
 */
export async function runWithBackoff<T>(fn: () => Promise<T>, maxRetries = 5, initialDelay = 500): Promise<T> {
  let attempt = 0;
  let delay = initialDelay;
  while (true) {
    try {
      return await fn();
    } catch (error: any) {
      attempt++;
      // Only retry on 500 or 503 errors
      const isRetryable =
        (error.response && (error.response.status === 500 || error.response.status === 503));
      if (!isRetryable || attempt > maxRetries) {
        throw error;
      }
      await new Promise(res => setTimeout(res, delay));
      delay *= 2; // Exponential backoff
    }
  }
}

/**
 * Makes an API request to the backend with exponential backoff on server/network errors.
 * @param endpoint The endpoint after the base URL (e.g., '/scan')
 * @param method HTTP method (default 'POST')
 * @param body Request body (object)
 * @param headers Optional headers
 * @param options Optional: { maxRetries, initialDelay }
 * @returns The JSON response
 */
export async function apiRequest<T = any>(
  endpoint: string,
  method: Method = 'POST',
  body?: any,
  headers?: Record<string, string>,
  options?: { maxRetries?: number; initialDelay?: number }
): Promise<T> {
  const config: AxiosRequestConfig = {
    url: endpoint,
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(headers || {})
    },
    data: body,
  };
  return runWithBackoff(async () => {
    const response = await axios(config);
    return response.data;
  }, options?.maxRetries, options?.initialDelay);
} 