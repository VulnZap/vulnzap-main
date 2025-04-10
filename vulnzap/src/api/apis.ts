import fs from 'fs';
import path from 'path';
import os from 'os';

const API_BASE_URL = "http://localhost:3000";

export async function checkHealth() {
  const response = await fetch(`${API_BASE_URL}/health`, {
    method: 'GET',
  });
  return response.json();
}

// Auth API functions
export async function signUp(email: string, password: string, metadata?: any) {
  const response = await fetch(`${API_BASE_URL}/auth/signup`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password, metadata }),
  });
  return response.json();
}

export async function login(email: string, password: string) {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });
  const data = await response.json();
  if (data.session) {
    await saveSession(data.session);
  }
  return { success: true, ...data };
}

export async function sendMagicLink(email: string) {
  const response = await fetch(`${API_BASE_URL}/auth/magic-link`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email }),
  });
  const data = await response.json();
  return { success: true, ...data };
}

export async function oauthLogin(provider: 'google' | 'github') {
  const response = await fetch(`${API_BASE_URL}/auth/oauth/${provider}`, {
    method: 'POST',
  });
  const data = await response.json();
  if (data.session) {
    await saveSession(data.session);
  }
  return { success: true, ...data };
}

export async function getCurrentUser() {
  const response = await fetch(`${API_BASE_URL}/auth/user`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
  });
  return response.json();
}

export async function logout() {
  const accessToken = await getAccessToken();
  if (accessToken) {
    const response = await fetch(`${API_BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });
    await clearSession();
    return { success: true, ...response.json() };
  }
  return { success: false, message: 'No active session' };
}

export async function getSession() {
  const accessToken = await getAccessToken();
  if (!accessToken) {
    return { success: false, session: null };
  }

  const response = await fetch(`${API_BASE_URL}/auth/session`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });
  const data = await response.json();
  return { success: true, session: data.session };
}

export async function checkAuth() {
  const accessToken = await getAccessToken();
  if (!accessToken) {
    return { success: false, authenticated: false };
  }

  const response = await fetch(`${API_BASE_URL}/auth/check`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });
  const data = await response.json();
  return { success: true, authenticated: data.authenticated };
}

export async function getUserTier() {
  const response = await fetch(`${API_BASE_URL}/auth/tier`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
  });
  const data = await response.json();
  return { success: true, tier: data.tier };
}

export async function refreshSession() {
  const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
  });
  return response.json();
}

// Payment API functions
export async function createCheckout(tier: 'pro' | 'enterprise', successUrl?: string, cancelUrl?: string) {
  const response = await fetch(`${API_BASE_URL}/payment/checkout`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
    body: JSON.stringify({ tier, successUrl, cancelUrl }),
  });
  const data = await response.json();
  return { success: true, ...data };
}

export async function getSubscription() {
  const response = await fetch(`${API_BASE_URL}/payment/subscription`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
  });
  const data = await response.json();
  return { success: true, ...data };
}

export async function cancelSubscription() {
  const response = await fetch(`${API_BASE_URL}/payment/subscription/cancel`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
  });
  const data = await response.json();
  return { success: true, ...data };
}

export async function resumeSubscription() {
  const response = await fetch(`${API_BASE_URL}/payment/subscription/resume`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
  });
  const data = await response.json();
  return { success: true, ...data };
}

export async function updateSubscription(tier: 'pro' | 'enterprise') {
  const response = await fetch(`${API_BASE_URL}/payment/subscription/update`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
    body: JSON.stringify({ tier }),
  });
  const data = await response.json();
  return { success: true, ...data };
}

export async function getScanQuota() {
  const response = await fetch(`${API_BASE_URL}/payment/quota`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
  });
  const data = await response.json();
  return { success: true, ...data };
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

// Helper function to get access token
async function getAccessToken(): Promise<string> {
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

// Helper function to save session
export async function saveSession(session: any) {
  try {
    ensureSessionDir();
    const sessionPath = getSessionFilePath();
    fs.writeFileSync(sessionPath, JSON.stringify(session, null, 2));
  } catch (error) {
    console.error('Error saving session:', error);
  }
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