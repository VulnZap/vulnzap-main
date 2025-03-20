import React, { useState } from 'react';
import { Auth } from '@supabase/auth-ui-react';
import { ThemeSupa } from '@supabase/auth-ui-shared';
import { supabase } from '../../utils/supabase-client';
import { useRouter } from 'next/router';

export function LoginForm() {
  const router = useRouter();
  const [authView, setAuthView] = useState('sign_in');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Handle successful authentication
  const handleAuthSuccess = () => {
    // Redirect to dashboard
    router.push('/dashboard');
  };

  return (
    <div className="w-full max-w-md mx-auto p-6 bg-card border border-border rounded-lg shadow-sm">
      <h2 className="text-2xl font-bold mb-6 text-center">
        {authView === 'sign_in' ? 'Sign In' : 
         authView === 'sign_up' ? 'Create Account' : 
         'Reset Password'}
      </h2>
      
      {error && (
        <div className="mb-4 p-3 bg-destructive/10 border border-destructive/30 rounded text-sm text-destructive">
          {error}
        </div>
      )}
      
      <Auth
        supabaseClient={supabase}
        appearance={{ 
          theme: ThemeSupa,
          variables: {
            default: {
              colors: {
                brand: 'var(--primary)',
                brandAccent: 'var(--primary-foreground)',
                inputBackground: 'var(--background)',
                inputBorder: 'var(--border)',
                inputText: 'var(--foreground)',
                inputPlaceholder: 'var(--muted-foreground)',
              },
              borderWidths: {
                buttonBorderWidth: '1px',
                inputBorderWidth: '1px',
              },
              radii: {
                borderRadiusButton: 'var(--radius)',
                buttonBorderRadius: 'var(--radius)',
                inputBorderRadius: 'var(--radius)',
              },
            },
          },
          style: {
            button: {
              border: '1px solid var(--border)',
              backgroundColor: 'var(--primary)',
              color: 'var(--primary-foreground)',
              fontWeight: '500',
              padding: '10px 15px',
              transition: 'all 0.2s',
            },
            anchor: {
              color: 'var(--primary)',
              textDecoration: 'none',
              fontWeight: '500',
            },
            message: {
              color: 'var(--foreground)',
              fontSize: '0.875rem',
            },
            container: {
              width: '100%',
            },
            label: {
              color: 'var(--foreground)',
              fontSize: '0.875rem',
              marginBottom: '4px',
            },
            input: {
              backgroundColor: 'var(--background)',
              borderColor: 'var(--border)',
              color: 'var(--foreground)',
              padding: '10px 15px',
              fontSize: '0.875rem',
            },
            divider: {
              backgroundColor: 'var(--border)',
            },
          },
        }}
        view={authView}
        providers={['google', 'github']}
        redirectTo={typeof window !== 'undefined' ? `${window.location.origin}/auth/callback` : undefined}
        onViewChange={(view) => setAuthView(view)}
        magicLink={true}
      />
    </div>
  );
} 