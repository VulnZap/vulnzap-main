import axios, { AxiosRequestConfig, Method } from "axios";

/**
 * Runs an async function with exponential backoff on failure (e.g., 500 errors, network errors).
 * @param fn The async function to run (should throw on error)
 * @param maxRetries Maximum number of retries (default 5)
 * @param initialDelay Initial delay in ms (default 500)
 * @returns The result of the function if successful
 */
export async function runWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries = 5,
  initialDelay = 500
): Promise<T> {
  let attempt = 0;
  let delay = initialDelay;
  while (true) {
    try {
      return await fn();
    } catch (error: any) {
      attempt++;
      // Only retry on 500 or 503 errors
      const isRetryable =
        error.response &&
        (error.response.status === 500 || error.response.status === 503);
      if (!isRetryable || attempt > maxRetries) {
        if (error.response && error.response.data) {
          throw error.response.data;
        } else if (error.response) {
          throw error.response;
        } else {
          throw error;
        }
      }
      await new Promise((res) => setTimeout(res, delay));
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
  method: Method = "POST",
  body?: any,
  headers?: Record<string, string>,
  options?: { maxRetries?: number; initialDelay?: number }
): Promise<T> {
  const config: AxiosRequestConfig = {
    url: endpoint,
    method,
    headers: {
      "Content-Type": "application/json",
      ...(headers || {}),
    },
    data: body,
  };

  try {
    return await runWithBackoff(
      async () => {
        const response = await axios(config);
        // Ensure we always return something, even if response.data is undefined
        // Also handle cases where response.data might be a string that needs parsing
        let responseData = response.data;

        if (typeof responseData === "string") {
          try {
            // Try to parse if it's a JSON string
            responseData = JSON.parse(responseData);
          } catch {
            // If it's not JSON, return as-is
            responseData = { message: responseData };
          }
        }

        return responseData || {};
      },
      options?.maxRetries,
      options?.initialDelay
    );
  } catch (error: any) {
    // Enhanced error handling to provide more context
    // console.error('API request error details:', error);

    // Handle axios errors specifically
    if (error.response) {
      // The request was made and the server responded with a status code
      const status = error.response.status;
      const statusText = error.response.statusText;
      const responseData = error.response.data;

      let errorMessage = `HTTP ${status} ${statusText}`;

      if (responseData) {
        if (typeof responseData === "string") {
          errorMessage += `: ${responseData}`;
        } else if (responseData.message) {
          errorMessage += `: ${responseData.message}`;
        } else if (responseData.error) {
          errorMessage += `: ${responseData.error}`;
        } else {
          errorMessage += `: ${JSON.stringify(responseData)}`;
        }
      }

      throw new Error(`API request failed: ${errorMessage}`);
    } else if (error.request) {
      // The request was made but no response was received
      throw new Error(`API request failed: No response received from server`);
    } else if (error.message) {
      // Something happened in setting up the request
      throw new Error(`API request failed: ${error.message}`);
    } else if (error && typeof error === "object") {
      // If error is an object with other properties, try to extract useful info
      const errorKeys = Object.keys(error);
      if (errorKeys.length > 0) {
        const errorInfo = errorKeys
          .map((key) => `${key}: ${error[key]}`)
          .join(", ");
        throw new Error(`API request failed: ${errorInfo}`);
      } else {
        throw new Error(`API request failed: Unknown error object`);
      }
    } else if (typeof error === "string") {
      throw new Error(`API request failed: ${error}`);
    } else {
      throw new Error(`API request failed: Unknown error type`);
    }
  }
}
