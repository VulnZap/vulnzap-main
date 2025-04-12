import { createServer } from 'http';
import { AddressInfo } from 'net';
import open from 'open';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import os from 'os';

const API_BASE_URL = process.env.VULNZAP_API_URL || 'https://vulnzap-frontend.vercel.app';
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
      fs.unlinkSync(sessionPath);
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

      if (urlState === state && access_token) {
        // Create session from callback parameters
        const session: AuthSession = {
          access_token,
          refresh_token: refresh_token || '',
          expires_at: expires_at ? parseInt(expires_at) : 0
        };

        await saveSession(session);

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
                  background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
                  height: 100vh;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  color: #ffffff;
                }

                .container {
                  background: rgba(255, 255, 255, 0.1);
                  backdrop-filter: blur(10px);
                  padding: 2.5rem;
                  border-radius: 1rem;
                  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                  text-align: center;
                  max-width: 90%;
                  width: 400px;
                  animation: fadeIn 0.5s ease-out;
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
                  background: #00c853;
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
                  fill: white;
                }

                h1 {
                  font-size: 1.5rem;
                  font-weight: 600;
                  margin-bottom: 1rem;
                  background: linear-gradient(135deg, #00c853 0%, #64dd17 100%);
                  -webkit-background-clip: text;
                  -webkit-text-fill-color: transparent;
                }

                p {
                  color: #e0e0e0;
                  font-size: 1rem;
                  line-height: 1.5;
                  margin-bottom: 1.5rem;
                }

                .cli-box {
                  background: rgba(0, 0, 0, 0.2);
                  border-radius: 0.5rem;
                  padding: 0.75rem;
                  font-family: 'Courier New', monospace;
                  color: #00c853;
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
                  setTimeout(() => window.close(), 2000);
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
      console.log(`Auth server listening on port ${address.port}`);
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
      redirect_uri: callbackUrl
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

// Browser-based signup flow (reuses login flow since frontend handles the distinction)
export async function signup(): Promise<{ success: boolean; error?: string }> {
  return login();
}

// Check authentication status
export async function checkAuth(): Promise<{ success: boolean; authenticated: boolean }> {
  const accessToken = await getAccessToken();
  if (!accessToken) {
    return { success: false, authenticated: false };
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/check`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const data = await response.json();
    return { success: true, authenticated: data.authenticated };
  } catch {
    return { success: false, authenticated: false };
  }
}

// Get user information
export async function getCurrentUser() {
  const accessToken = await getAccessToken();
  if (!accessToken) {
    return { success: false, user: null };
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/user`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const data = await response.json();
    return { success: true, user: data.user };
  } catch {
    return { success: false, user: null };
  }
}

// Logout
export async function logout(): Promise<{ success: boolean }> {
  const accessToken = await getAccessToken();
  if (!accessToken) {
    return { success: true };
  }

  try {
    await fetch(`${API_BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    await clearSession();
    return { success: true };
  } catch {
    return { success: false };
  }
} 