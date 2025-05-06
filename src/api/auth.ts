import { createServer } from 'http';
import { AddressInfo } from 'net';
import open from 'open';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import os from 'os';
import chalk from 'chalk';

const API_BASE_URL = 'https://vulnzap.com';
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
      throw new Error('API key not found. Please run `vulnzap login` or `vulnzap setup` to save the API key to your system.');
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    if (!config.apiKey) {
      throw new Error('API key not found in config. Please run `vulnzap login` or `vulnzap setup` to save the API key to your system.');
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
    const server = createServer(async (req, res) => {
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

        // Send success HTML
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <!DOCTYPE html>
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>VulnZap Authentication</title>
              <style>
                * {
                  margin: 0;
                  padding: 0;
                  box-sizing: border-box;
                }

                body {
                  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                  background: #000000;
                  height: 100vh;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  color: #ffffff;
                }

                .container {
                  background: #111111;
                  padding: 2.5rem;
                  border-radius: 0.5rem;
                  text-align: center;
                  max-width: 90%;
                  width: 400px;
                  animation: fadeIn 0.5s ease-out;
                  border: 1px solid #333333;
                }

                @keyframes fadeIn {
                  from {
                    opacity: 0;
                    transform: translateY(20px);
                  }
                  to {
                    opacity: 1;
                    transform: translateY(0);
                  }
                }

                @keyframes checkmark {
                  0% {
                    transform: scale(0);
                  }
                  50% {
                    transform: scale(1.2);
                  }
                  100% {
                    transform: scale(1);
                  }
                }

                .success-icon {
                  width: 60px;
                  height: 60px;
                  background: #ffffff;
                  border-radius: 50%;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  margin: 0 auto 1.5rem;
                  animation: checkmark 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.2s both;
                }

                .success-icon svg {
                  width: 30px;
                  height: 30px;
                  fill: #000000;
                }

                h1 {
                  font-size: 1.5rem;
                  font-weight: 600;
                  margin-bottom: 1rem;
                  color: #ffffff;
                }

                p {
                  color: #cccccc;
                  font-size: 1rem;
                  line-height: 1.5;
                  margin-bottom: 1.5rem;
                }

                .cli-box {
                  background: #000000;
                  border: 1px solid #333333;
                  border-radius: 0.25rem;
                  padding: 0.75rem;
                  font-family: 'Courier New', monospace;
                  color: #ffffff;
                  font-size: 0.9rem;
                  margin-top: 1rem;
                }
              </style>
            </head>
            <body>
              <div class="container">
                <div class="success-icon">
                  <svg viewBox="0 0 24 24">
                    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/>
                  </svg>
                </div>
                <h1>Successfully Authenticated!</h1>
                <p>You have been successfully logged in to VulnZap.</p>
                <div class="cli-box">
                  > Ready to scan for vulnerabilities
                </div>
                <script>
                  setTimeout(() => window.close(), 5000);
                </script>
              </div>
            </body>
          </html>
        `);

        server.close();
        resolve(session);
      } else {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('Invalid state parameter or missing tokens');
        server.close();
        reject(new Error('Invalid state parameter or missing tokens'));
      }
    });

    server.listen(AUTH_PORT, () => {
      const address = server.address() as AddressInfo;
    });

    server.on('error', (error) => {
      reject(error);
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