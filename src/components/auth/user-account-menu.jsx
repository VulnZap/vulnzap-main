'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../contexts/auth-context';
import { signOut } from '../../utils/supabase-client';

export function UserAccountMenu() {
  const { user } = useAuth();
  const router = useRouter();
  const [isOpen, setIsOpen] = useState(false);

  if (!user) {
    return (
      <div className='flex gap-4'>
        <Link
          href='/login'
          className='px-4 py-2 transition-colors border rounded-md border-border hover:bg-card/80'
        >
          Sign In
        </Link>
        <Link
          href='/signup'
          className='px-4 py-2 transition-colors rounded-md bg-primary text-primary-foreground hover:bg-primary/90'
        >
          Sign Up
        </Link>
      </div>
    );
  }

  const handleSignOut = async () => {
    await signOut();
    setIsOpen(false);
    router.push('/');
  };

  const toggleMenu = () => {
    setIsOpen(!isOpen);
  };

  // Get user initials or use first letter of email
  const getInitials = () => {
    if (user.user_metadata?.full_name) {
      return user.user_metadata.full_name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase();
    }
    return user.email[0].toUpperCase();
  };

  return (
    <div className='relative'>
      <button
        onClick={toggleMenu}
        className='flex items-center gap-2 px-3 py-2 transition-colors rounded-md hover:bg-card/80'
      >
        {user.user_metadata?.avatar_url ? (
          <img
            src={user.user_metadata.avatar_url}
            alt='Avatar'
            className='w-8 h-8 rounded-full'
          />
        ) : (
          <div className='flex items-center justify-center w-8 h-8 text-sm font-medium rounded-full bg-primary text-primary-foreground'>
            {getInitials()}
          </div>
        )}
        <span className='max-w-[140px] truncate'>
          {user.user_metadata?.full_name || user.email}
        </span>
      </button>

      {isOpen && (
        <div className='absolute right-0 z-10 w-48 py-1 mt-2 border rounded-md shadow-lg bg-card border-border'>
          <div className='px-4 py-2 border-b border-border'>
            <div className='font-medium truncate'>
              {user.user_metadata?.full_name || user.email}
            </div>
            <div className='text-xs truncate text-muted-foreground'>
              {user.email}
            </div>
          </div>

          <Link
            href='/dashboard'
            className='block px-4 py-2 text-sm transition-colors hover:bg-primary/10'
          >
            Dashboard
          </Link>

          <Link
            href='/dashboard/settings'
            className='block px-4 py-2 text-sm transition-colors hover:bg-primary/10'
          >
            Settings
          </Link>

          <button
            onClick={handleSignOut}
            className='block w-full px-4 py-2 text-sm text-left transition-colors text-destructive hover:bg-destructive/10'
          >
            Sign Out
          </button>
        </div>
      )}
    </div>
  );
}
