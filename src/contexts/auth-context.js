import React, { createContext, useContext, useEffect, useState } from 'react';
import { supabase, getCurrentUser, getSession } from '../utils/supabase-client';

// Create auth context
const AuthContext = createContext(null);

// Auth provider component
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Initialize auth state
    const initAuth = async () => {
      setLoading(true);

      // Check for existing session
      const { session: activeSession } = await getSession();
      setSession(activeSession);

      if (activeSession) {
        const { user: currentUser } = await getCurrentUser();
        setUser(currentUser);
      }

      // Listen for auth changes
      const { data: authListener } = supabase.auth.onAuthStateChange(
        async (event, newSession) => {
          setSession(newSession);
          setUser(newSession?.user || null);
          setLoading(false);
        }
      );

      setLoading(false);

      // Cleanup listener on unmount
      return () => {
        if (authListener) authListener.subscription.unsubscribe();
      };
    };

    initAuth();
  }, []);

  // Auth context value
  const value = {
    session,
    user,
    loading,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// Custom hook to use the auth context
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// HOC to protect routes that require authentication
export function withAuth(Component) {
  return function AuthenticatedComponent(props) {
    const { user, loading } = useAuth();

    // Show loading state
    if (loading) {
      return <div>Loading...</div>;
    }

    // Redirect to login if not authenticated
    if (!user) {
      if (typeof window !== 'undefined') {
        window.location.href = '/login';
      }
      return null;
    }

    // Render component if authenticated
    return <Component {...props} />;
  };
}
