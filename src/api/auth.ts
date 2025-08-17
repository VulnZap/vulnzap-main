import { createServer } from 'http';
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
    // Ensure the .vulnzap directory exists
    const vulnzapDir = path.join(os.homedir(), '.vulnzap');
    if (!fs.existsSync(vulnzapDir)) {
      fs.mkdirSync(vulnzapDir, { recursive: true, mode: 0o755 });
    }
    
    // Define the config file path
    const configPath = path.join(vulnzapDir, 'config.json');
    
    // Read existing config or create empty object
    let config: { apiKey?: string; [key: string]: any } = {};
    if (fs.existsSync(configPath)) {
      try {
        const configData = fs.readFileSync(configPath, 'utf8');
        config = JSON.parse(configData);
      } catch (parseError) {
        console.warn('Warning: Could not parse existing config.json, creating new one');
        config = {};
      }
    }
    
    // Update config with new API key
    config.apiKey = apiKey;
    
    // Write the config file with proper permissions
    const configContent = JSON.stringify(config, null, 2);
    fs.writeFileSync(configPath, configContent, { 
      encoding: 'utf8', 
      mode: 0o600 // Read/write for owner only for security
    });
  } catch (error: any) {
    console.error('Error saving API key:', error);
    throw new Error(`Failed to save API key: ${error.message}`);
  }
}

export async function getKey(): Promise<string> {
  try {
    // Check in config file
    const vulnzapDir = path.join(os.homedir(), '.vulnzap');
    const configPath = path.join(vulnzapDir, 'config.json');
    
    if (!fs.existsSync(configPath)) {
      throw new Error('API key not found. Please run `vulnzap setup -k <your-api-key>` to save the API key to your system.');
    }

    try {
      const configData = fs.readFileSync(configPath, 'utf8');
      const config = JSON.parse(configData);
      
      if (!config.apiKey) {
        throw new Error('API key not found in config. Please run `vulnzap setup -k <your-api-key>` to save the API key to your system.');
      }

      return config.apiKey;
    } catch (parseError) {
      throw new Error('Config file is corrupted. Please run `vulnzap setup -k <your-api-key>` to reconfigure your API key.');
    }
  } catch (error: any) {
    throw new Error(`Failed to get API key: ${error.message}`);
  }
}

// Helper function to get access token
export async function getAccessToken(): Promise<string> {
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

    // Set up 2-minute timeout
    const timeoutId = setTimeout(() => {
      if (!serverClosed) {
        console.log(chalk.yellow('\nAuthentication timeout (2 minutes). Please try again.'));
        serverClosed = true;
        server.close();
        reject(new Error('Authentication timeout - no response received within 2 minutes'));
      }
    }, 120000); // 120 seconds = 2 minutes

    server.listen(AUTH_PORT);

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