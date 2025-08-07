import { v4 } from 'uuid';
import config from '../config/config.js';
import { getKey } from './auth.js';

const API_BASE_URL = config.api.baseUrl + config.api.addOn;

export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/vulnzap/health`, {
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

export interface UserProfile {
  id: string;
  email: string;
  username: string;
  createdAt: string;
  lastLogin: string;
  isActive: boolean;
  usageBased: boolean;
  subscription: {
    tier: string;
    status: string;
    current_period_start: string;
    current_period_end: string;
    line_scans_limit: number;
  },
  apiUsage: {
    lineScans: number
  }
}

export async function getUserProfile(): Promise<UserProfile | null> {
  try {
    const apiKey = await getKey();
    const response = await fetch(`${API_BASE_URL}/api/user/profile`, {
      method: 'GET',
      headers: {
        'x-api-key': apiKey,
        'Content-Type': 'application/json',
      },
    });

    if (response.ok) {
      const profile = await response.json();
      return profile;
    } else {
      // Silently fail if profile endpoint isn't available yet
      return null;
    }
  } catch (error) {
    // Silently fail - don't interrupt user flow
    return null;
  }
}

export async function getUserUsage(): Promise<{ current: number; limit: number; period: string } | null> {
  try {
    const apiKey = await getKey();
    const response = await fetch(`${API_BASE_URL}/vulnzap/user/usage`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
    });

    if (response.ok) {
      const usage = await response.json();
      return usage;
    } else {
      return null;
    }
  } catch (error) {
    return null;
  }
}