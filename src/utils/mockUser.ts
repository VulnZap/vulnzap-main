import { UserProfile } from '../api/apis.js';

// Mock user data for testing personalized CLI features
export const mockUserProfile: UserProfile = {
  name: 'Alex Johnson',
  email: 'alex@example.com',
  tier: 'free',
  usage: {
    current: 97,
    limit: 100,
    period: 'month'
  },
  features: ['vulnerability-scanning', 'basic-reports']
};

export const mockProUserProfile: UserProfile = {
  name: 'Sarah Chen',
  email: 'sarah@company.com',
  tier: 'pro',
  usage: {
    current: 245,
    limit: 1000,
    period: 'month'
  },
  features: ['vulnerability-scanning', 'advanced-reports', 'team-collaboration', 'priority-support']
};

export const mockEnterpriseUserProfile: UserProfile = {
  name: 'David Kumar',
  email: 'david@enterprise.com',
  tier: 'enterprise',
  usage: {
    current: 1250,
    limit: 10000,
    period: 'month'
  },
  features: ['vulnerability-scanning', 'advanced-reports', 'team-collaboration', 'priority-support', 'custom-integrations', 'dedicated-support']
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