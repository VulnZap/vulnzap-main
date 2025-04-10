'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { LoginForm } from '../../components/auth/login-form';
import { useAuth } from '../../contexts/auth-context';

export default function LoginPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  // Redirect if already authenticated
  useEffect(() => {
    if (!loading && user) {
      router.push('/dashboard');
    }
  }, [user, loading, router]);

  if (loading) {
    return (
      <div className='flex items-center justify-center min-h-screen'>
        <div className='w-8 h-8 border-4 rounded-full border-primary border-t-transparent animate-spin'></div>
      </div>
    );
  }

  // Only show login form if not authenticated
  if (!user) {
    return (
      <div className='flex items-center justify-center min-h-screen p-4'>
        <div className='w-full max-w-md'>
          <div className='mb-8 text-center'>
            <h1 className='text-3xl font-bold'>Welcome Back</h1>
            <p className='mt-2 text-muted-foreground'>
              Sign in to access your VulnZap account
            </p>
          </div>
          <LoginForm />
        </div>
      </div>
    );
  }

  // This will rarely be shown as useEffect will redirect
  return null;
}
