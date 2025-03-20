"use client";

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { LoginForm } from '../../components/auth/login-form';
import { useAuth } from '../../contexts/auth-context';

export default function SignUpPage() {
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
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  // Only show signup form if not authenticated
  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="max-w-md w-full">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold">Create Your Account</h1>
            <p className="text-muted-foreground mt-2">Sign up to secure your dependencies with VulnZap</p>
          </div>
          <LoginForm initialView="sign_up" />
        </div>
      </div>
    );
  }

  // This will rarely be shown as useEffect will redirect
  return null;
} 