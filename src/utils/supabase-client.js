import { createClient } from '@supabase/supabase-js';

// Initialize the Supabase client
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error('Missing Supabase environment variables');
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Auth helper functions
export const signInWithEmail = async (email, password) => {
  return await supabase.auth.signInWithPassword({ email, password });
};

export const signInWithGoogle = async () => {
  return await supabase.auth.signInWithOAuth({
    provider: 'google',
  });
};

export const signInWithGithub = async () => {
  return await supabase.auth.signInWithOAuth({
    provider: 'github',
  });
};

export const signUp = async (email, password) => {
  return await supabase.auth.signUp({ email, password });
};

export const signOut = async () => {
  return await supabase.auth.signOut();
};

export const resetPassword = async (email) => {
  return await supabase.auth.resetPasswordForEmail(email);
};

export const getCurrentUser = async () => {
  const { data, error } = await supabase.auth.getUser();
  return { user: data?.user, error };
};

export const getSession = async () => {
  const { data, error } = await supabase.auth.getSession();
  return { session: data?.session, error };
};

export const onAuthStateChange = (callback) => {
  return supabase.auth.onAuthStateChange(callback);
}; 