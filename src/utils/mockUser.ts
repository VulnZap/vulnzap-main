import { UserProfile } from '../api/apis.js';

// Mock user data for testing personalized CLI features
export const mockUserProfile: UserProfile = {
  id: '123',
  email: 'alex@example.com',
  username: 'Alex Johnson',
  createdAt: '2021-01-01',
  lastLogin: '2021-01-01',
  isActive: true,
  usageBased: true,
  subscription: {
    tier: 'free',
    status: 'active',
    current_period_start: '2021-01-01',
    current_period_end: '2021-01-31',
    line_scans_limit: 25000
  },
  apiUsage: {
    lineScans: 20000
  }
};

export const mockProUserProfile: UserProfile = {
  id: '123',
  email: 'alex@example.com',
  username: 'Alex Johnson',
  createdAt: '2021-01-01',
  lastLogin: '2021-01-01',
  isActive: true,
  usageBased: true,
  subscription: {
    tier: 'pro',
    status: 'active',
    current_period_start: '2021-01-01',
    current_period_end: '2021-01-31',
    line_scans_limit: 250000
  },
  apiUsage: {
    lineScans: 245000
  }
};

export const mockEnterpriseUserProfile: UserProfile = {
  id: '123',
  email: 'alex@example.com',
  username: 'Alex Johnson',
  createdAt: '2021-01-01',
  lastLogin: '2021-01-01',
  isActive: true,
  usageBased: true,
  subscription: {
    tier: 'enterprise',
    status: 'active',
    current_period_start: '2021-01-01',
    current_period_end: '2021-01-31',
    line_scans_limit: 1000000
  },
  apiUsage: {
    lineScans: 125000
  }
};

// Function to enable mock mode (for testing)
export function getMockProfile(tier: 'free' | 'pro' | 'enterprise' = 'free'): UserProfile {
  switch (tier) {
    case 'pro':
      return mockProUserProfile;
    case 'enterprise':
      return mockEnterpriseUserProfile;
    default:
      return mockUserProfile;
  }
} 