/**
 * Supabase Authentication Service
 * Provides methods for authenticating users with Supabase
 */

import { createClient, SupabaseClient, User, Session, Provider } from '@supabase/supabase-js';
import { config } from '../config/config.js';
import Conf from 'conf';
import keytar from 'keytar';
import fs from 'fs';
import path from 'path';

// Auth related types
export type AuthResponse = {
  user: User | null;
  session: Session | null;
  error: string | null;
};

export type UserMetadata = {
  name?: string;
  company?: string;
  website?: string;
  tier?: 'free' | 'pro' | 'enterprise';
  usage?: {
    scansToday: number;
    scanHistory: number;
    lastScan: string;
  };
};

// Create a secure storage for tokens
const store = new Conf({
  projectName: 'vulnzap',
  encryptionKey: 'vulnzap-secure-storage',
  schema: {
    session: {
      type: 'object',
    },
    user: {
      type: 'object',
    },
  },
});

// Service keyrings
const SERVICE_NAME = 'vulnzap-auth';
const ACCOUNT_KEY = 'default';

// Initialize Supabase client
let supabase: SupabaseClient;

/**
 * Initialize the Supabase client with configuration
 */
export function initSupabase(): SupabaseClient {
  if (!supabase) {
    supabase = createClient(
      config.supabase.url,
      config.supabase.anonKey,
      {
        auth: {
          autoRefreshToken: true,
          persistSession: true,
        },
      }
    );
  }
  return supabase;
}

/**
 * Sign up a new user with email and password
 */
export async function signUpWithEmail(email: string, password: string, metadata?: UserMetadata): Promise<AuthResponse> {
  const supabase = initSupabase();
  
  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: metadata || { tier: 'free' },
      },
    });
    
    if (error) {
      return { user: null, session: null, error: error.message };
    }
    
    if (data?.session) {
      await saveSession(data.session, data.user);
    }
    
    return { 
      user: data?.user || null, 
      session: data?.session || null, 
      error: null 
    };
  } catch (error: any) {
    return { user: null, session: null, error: error.message };
  }
}

/**
 * Sign in with email and password
 */
export async function signInWithEmail(email: string, password: string): Promise<AuthResponse> {
  const supabase = initSupabase();
  
  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });
    
    if (error) {
      return { user: null, session: null, error: error.message };
    }
    
    if (data?.session) {
      await saveSession(data.session, data.user);
    }
    
    return { 
      user: data?.user || null, 
      session: data?.session || null, 
      error: null 
    };
  } catch (error: any) {
    return { user: null, session: null, error: error.message };
  }
}

/**
 * Send a magic link to the provided email
 */
export async function sendMagicLink(email: string): Promise<{ success: boolean; error: string | null }> {
  const supabase = initSupabase();
  
  try {
    const { error } = await supabase.auth.signInWithOtp({
      email,
      options: {
        emailRedirectTo: `${config.api.baseUrl}/auth/callback`,
      },
    });
    
    if (error) {
      return { success: false, error: error.message };
    }
    
    return { success: true, error: null };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

/**
 * Sign in with OAuth provider (Google or GitHub)
 */
export async function signInWithProvider(provider: Provider): Promise<{ success: boolean; error: string | null; url?: string }> {
  const supabase = initSupabase();
  
  try {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: `${config.api.baseUrl}/auth/callback`,
      },
    });
    
    if (error) {
      return { success: false, error: error.message };
    }
    
    return { 
      success: true, 
      error: null,
      url: data?.url
    };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

/**
 * Get the current user from the session
 */
export async function getCurrentUser(): Promise<User | null> {
  const session = await getSession();
  
  if (!session) {
    const supabase = initSupabase();
    const { data } = await supabase.auth.getUser();
    return data?.user || null;
  }
  
  return session.user;
}

/**
 * Sign out the current user
 */
export async function signOut(): Promise<{ success: boolean; error: string | null }> {
  const supabase = initSupabase();
  
  try {
    const { error } = await supabase.auth.signOut();
    
    if (error) {
      return { success: false, error: error.message };
    }
    
    // Clear local storage
    await clearSession();
    
    return { success: true, error: null };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

/**
 * Save the session securely
 */
async function saveSession(session: Session, user: User | null): Promise<void> {
  try {
    // Save to secure storage
    store.set('session', session);
    if (user) {
      store.set('user', user);
    }
    
    // Also save to keytar for CLI usage
    if (session.access_token) {
      await keytar.setPassword(SERVICE_NAME, ACCOUNT_KEY, session.access_token);
    }
    
    // Ensure .vulnzap directory exists
    if (!fs.existsSync(config.app.homeDir)) {
      fs.mkdirSync(config.app.homeDir, { recursive: true });
    }
    
    // Save minimal info to disk for CLI usage
    const sessionInfo = {
      userId: user?.id,
      email: user?.email,
      expiresAt: session.expires_at,
      lastLogin: new Date().toISOString(),
      tier: user?.user_metadata?.tier || 'free',
    };
    
    fs.writeFileSync(
      path.join(config.app.homeDir, 'session.json'),
      JSON.stringify(sessionInfo, null, 2)
    );
  } catch (error) {
    console.error('Failed to save session:', error);
  }
}

/**
 * Get the current session
 */
export async function getSession(): Promise<Session | null> {
  try {
    // Try to get from secure storage first
    const session = store.get('session') as Session | undefined;
    
    if (session) {
      return session;
    }
    
    // Fall back to keytar
    const token = await keytar.getPassword(SERVICE_NAME, ACCOUNT_KEY);
    
    if (token) {
      const supabase = initSupabase();
      const { data, error } = await supabase.auth.getSession();
      
      if (!error && data?.session) {
        await saveSession(data.session, data.session.user);
        return data.session;
      }
    }
    
    return null;
  } catch (error) {
    console.error('Failed to get session:', error);
    return null;
  }
}

/**
 * Clear the session
 */
async function clearSession(): Promise<void> {
  try {
    store.delete('session');
    store.delete('user');
    
    await keytar.deletePassword(SERVICE_NAME, ACCOUNT_KEY);
    
    const sessionPath = path.join(config.app.homeDir, 'session.json');
    if (fs.existsSync(sessionPath)) {
      fs.unlinkSync(sessionPath);
    }
  } catch (error) {
    console.error('Failed to clear session:', error);
  }
}

/**
 * Check if user is authenticated
 */
export async function isAuthenticated(): Promise<boolean> {
  const user = await getCurrentUser();
  return !!user;
}

/**
 * Get the user's subscription tier
 */
export async function getUserTier(): Promise<'free' | 'pro' | 'enterprise'> {
  const user = await getCurrentUser();
  
  if (!user) {
    return 'free';
  }
  
  return user.user_metadata?.tier || 'free';
}

/**
 * Refresh the session
 */
export async function refreshSession(): Promise<{ success: boolean; error: string | null }> {
  const supabase = initSupabase();
  
  try {
    const { data, error } = await supabase.auth.refreshSession();
    
    if (error) {
      return { success: false, error: error.message };
    }
    
    if (data?.session) {
      await saveSession(data.session, data.user);
    }
    
    return { success: true, error: null };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

export default {
  initSupabase,
  signUpWithEmail,
  signInWithEmail,
  sendMagicLink,
  signInWithProvider,
  getCurrentUser,
  signOut,
  getSession,
  isAuthenticated,
  getUserTier,
  refreshSession,
}; 