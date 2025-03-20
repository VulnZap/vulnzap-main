"use client";

import React from 'react';
import Link from 'next/link';
import { UserAccountMenu } from '../auth/user-account-menu';
import { useAuth } from '../../contexts/auth-context';

const navigation = [
  { name: "Features", href: "#features" },
  { name: "Ecosystems", href: "#ecosystems" },
  { name: "Pricing", href: "#pricing" },
  { name: "Documentation", href: "#docs" },
];

export function Header() {
  const { isAuthenticated } = useAuth();

  return (
    <header className="fixed inset-x-0 top-0 z-50 bg-background/80 backdrop-blur-lg">
      <nav className="flex items-center justify-between p-6 lg:px-8 max-w-7xl mx-auto" aria-label="Global">
        <div className="flex lg:flex-1">
          <Link href="/" className="-m-1.5 p-1.5 flex items-center gap-2">
            <div className="w-8 h-8 relative">
              <div className="absolute inset-0 bg-background rounded-md shadow-lg border border-border"></div>
              <div className="absolute inset-0 flex items-center justify-center">
                <svg width="24" height="24" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 8L18 2L28 12L22 18L12 8Z" fill="var(--chart-1)" />
                  <path d="M12 8L2 18L12 28L22 18L12 8Z" fill="var(--chart-3)" />
                  <path d="M22 18L12 28L18 34L28 24L22 18Z" fill="var(--chart-4)" />
                  <path d="M22 18L28 12L38 22L32 28L22 18Z" fill="var(--chart-2)" />
                  <path d="M20 15L25 20M20 15L15 20M20 15L20 10M20 25L15 20M20 25L25 20M20 25L20 30" stroke="var(--primary-foreground)" strokeWidth="1.5" />
                </svg>
              </div>
            </div>
            <span className="text-xl font-bold tracking-tight">
              <span className="text-primary">Vuln</span>
              <span className="text-foreground">Zap</span>
            </span>
          </Link>
        </div>
        <div className="hidden lg:flex lg:gap-x-10">
          {navigation.map((item) => (
            <Link key={item.name} href={item.href} className="text-sm font-semibold leading-6 hover:text-primary">
              {item.name}
            </Link>
          ))}
        </div>
        <div className="hidden lg:flex lg:flex-1 lg:justify-end">
          <Button asChild>
            <Link href="#get-started">Get Started</Link>
          </Button>
        </div>
        <div className="flex items-center gap-4">
          <a 
            href="https://github.com/vulnzap/vulnzap" 
            target="_blank" 
            rel="noopener noreferrer"
            className="hidden md:flex items-center gap-2 px-3 py-1 bg-card/50 border border-border rounded-full text-sm hover:bg-card transition-colors"
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
            </svg>
            GitHub
          </a>
          
          <UserAccountMenu />
        </div>
      </nav>
    </header>
  );
} 