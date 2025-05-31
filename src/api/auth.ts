import { createServer } from 'http';
import { AddressInfo } from 'net';
import open from 'open';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import os from 'os';
import chalk from 'chalk';
import config from '../config/config.js';

const API_BASE_URL = config.auth.baseUrl;
const AUTH_PORT = 54321;

interface AuthSession {
  access_token: string;
  refresh_token: string;
  expires_at: number;
}

// Helper function to get session file path
function getSessionFilePath(): string {
  const homeDir = os.homedir();
  return path.join(homeDir, '.vulnzap', 'session.json');
}

// Helper function to ensure directory exists
function ensureSessionDir() {
  const sessionDir = path.dirname(getSessionFilePath());
  if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true });
  }
}

// Helper function to save session
export async function saveSession(session: AuthSession) {
  try {
    ensureSessionDir();
    const sessionPath = getSessionFilePath();
    fs.writeFileSync(sessionPath, JSON.stringify(session, null, 2));
  } catch (error) {
    console.error('Error saving session:', error);
  }
}

export async function saveKey(apiKey: string | null) {
  if (!apiKey) return;
  
  try {
    ensureSessionDir();
    const configPath = path.join(os.homedir(), '.vulnzap', 'config.json');
    const config = fs.existsSync(configPath) 
      ? JSON.parse(fs.readFileSync(configPath, 'utf8'))
      : {};
    
    config.apiKey = apiKey;
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  } catch (error) {
    console.error('Error saving API key:', error);
  }
}

export async function getKey(): Promise<string> {
  try {
    // Check in .env file first
    const envKey = process.env.VULNZAP_API_KEY;
    if (envKey) return envKey;

    // Else check in config file
    const configPath = path.join(os.homedir(), '.vulnzap', 'config.json');
    if (!fs.existsSync(configPath)) {
      throw new Error('API key not found. Please run `vulnzap setup -k <your-api-key>` to save the API key to your system.');
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    if (!config.apiKey) {
      throw new Error('API key not found in config. Please run `vulnzap setup -k <your-api-key>` to save the API key to your system.');
    }

    return config.apiKey;
  } catch (error: any) {
    throw new Error(`Failed to get API key: ${error.message}`);
  }
}

// Helper function to get access token
export async function getAccessToken(): Promise<string> {
  // Try to get token from environment variable first
  const envToken = process.env.VULNZAP_API_KEY;
  if (envToken) {
    return envToken;
  }

  // Try to get token from session file
  try {
    const sessionPath = getSessionFilePath();
    if (fs.existsSync(sessionPath)) {
      const sessionData = fs.readFileSync(sessionPath, 'utf8');
      const session = JSON.parse(sessionData);
      if (session?.access_token) {
        return session.access_token;
      }
    }
  } catch (error) {
    console.error('Error reading session file:', error);
  }

  return '';
}

// Helper function to clear session
export async function clearSession() {
  try {
    const sessionPath = getSessionFilePath();
    if (fs.existsSync(sessionPath)) {
      fs.rmSync(sessionPath, { force: true, recursive: true });
    }
  } catch (error) {
    console.error('Error clearing session:', error);
  }
}

// Start local server for auth callback
function startAuthServer(state: string): Promise<AuthSession> {
  return new Promise((resolve, reject) => {
    let serverClosed = false;
    
    const server = createServer(async (req, res) => {
      if (serverClosed) return;
      
      const url = new URL(req.url!, `http://localhost:${AUTH_PORT}`);
      const urlState = url.searchParams.get('state');
      const access_token = url.searchParams.get('access_token');
      const refresh_token = url.searchParams.get('refresh_token');
      const expires_at = url.searchParams.get('expires_at');
      const apiKey = url.searchParams.get('api_key');

      if (urlState === state && access_token) {
        // Create session from callback parameters
        const session: AuthSession = {
          access_token,
          refresh_token: refresh_token || '',
          expires_at: expires_at ? parseInt(expires_at) : 0
        };

        await saveSession(session);

        if (apiKey) {
          await saveKey(apiKey);
        } else {
          console.log(chalk.cyan('\nNo API key found in your account.'));
          console.log(chalk.cyan('Please run `vulnzap setup` to configure your API key.\n'));
        }

        // Send success response
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));

        // Wait 3 seconds before closing to ensure response is sent
        setTimeout(() => {
          serverClosed = true;
          server.close();
          clearTimeout(timeoutId); // Clear the timeout
          resolve(session);
        }, 3000);
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid state parameter or missing tokens' }));
        
        // Wait 3 seconds before closing to ensure response is sent
        setTimeout(() => {
          serverClosed = true;
          server.close();
          clearTimeout(timeoutId); // Clear the timeout
          reject(new Error('Invalid state parameter or missing tokens'));
        }, 3000);
      }
    });

    // Set up 1-minute timeout
    const timeoutId = setTimeout(() => {
      if (!serverClosed) {
        console.log(chalk.yellow('\nAuthentication timeout (1 minute). Please try again.'));
        serverClosed = true;
        server.close();
        reject(new Error('Authentication timeout - no response received within 1 minute'));
      }
    }, 120000); // 120 seconds = 2 minutes

    server.listen(AUTH_PORT, () => {
      const address = server.address() as AddressInfo;
    });

    server.on('error', (error) => {
      if (!serverClosed) {
        serverClosed = true;
        clearTimeout(timeoutId);
        reject(error);
      }
    });
  });
}

// Browser-based login flow
export async function login(provider?: string): Promise<{ success: boolean; error?: string }> {
  try {
    const state = uuidv4();
    const callbackUrl = `http://localhost:${AUTH_PORT}/callback`;
    
    // Get auth URL from frontend
    const response = await fetch(`${API_BASE_URL}/auth/cli?` + new URLSearchParams({
      state,
      redirect_uri: callbackUrl,
      usecase: provider || 'login',
    }));

    const { url } = await response.json();
    if (!url) {
      throw new Error('Failed to get authentication URL');
    }

    // Open browser for auth
    await open(url);
    
    // Wait for auth callback with tokens
    const session = await startAuthServer(state);
    
    return { success: true };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

// Check authentication status
export async function checkAuth(): Promise<{ success: boolean; authenticated: boolean }> {
  const accessToken = await getAccessToken();
  if (!accessToken) {
    return { success: false, authenticated: false };
  }

  try {
    // const response = await fetch(`${API_BASE_URL}/auth/check`, {
    //   headers: { 'Authorization': `Bearer ${accessToken}` }
    // });
    // const data = await response.json();
    return { success: true, authenticated: true };
  } catch {
    return { success: false, authenticated: false };
  }
}

// Logout
export async function logout(): Promise<{ success: boolean }> {
  const accessToken = await getAccessToken();
  if (!accessToken) {
    return { success: true };
  }

  try {
    // await fetch(`${API_BASE_URL}/auth/logout`, {
    //   method: 'POST',
    //   headers: { 'Authorization': `Bearer ${accessToken}` }
    // });
    await clearSession();
    return { success: true };
  } catch {
    return { success: false };
  }
} 