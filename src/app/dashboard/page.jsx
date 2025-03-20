"use client";

import { useEffect, useState } from 'react';
import { DashboardLayout } from '../../components/dashboard/dashboard-layout';
import { useAuth } from '../../contexts/auth-context';
import { getUserSubscription } from '../../utils/stripe-client';
import { withAuth } from '../../contexts/auth-context';

function DashboardPage() {
  const { user } = useAuth();
  const [stats, setStats] = useState({
    scannedPackages: 0,
    vulnerabilitiesFound: 0,
    projectsProtected: 0,
    lastScanDate: null,
  });
  const [subscription, setSubscription] = useState({ tier: 'free' });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Load user subscription and stats
    const loadUserData = async () => {
      setLoading(true);
      try {
        // Get user subscription
        const { success, data } = await getUserSubscription();
        if (success && data) {
          setSubscription(data.subscription || { tier: 'free' });
          
          // In a real app, you would fetch the stats from the API
          // This is a placeholder with mock data
          setStats({
            scannedPackages: 287,
            vulnerabilitiesFound: 23,
            projectsProtected: 5,
            lastScanDate: new Date().toISOString(),
          });
        }
      } catch (error) {
        console.error('Error loading user data:', error);
      } finally {
        setLoading(false);
      }
    };

    if (user) {
      loadUserData();
    }
  }, [user]);

  return (
    <DashboardLayout>
      <div className="grid gap-6">
        <div className="flex flex-col space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">
            Welcome back, {user?.user_metadata?.full_name || user?.email?.split('@')[0] || 'User'}!
          </p>
        </div>
        
        {/* Subscription banner */}
        {subscription.tier === 'free' && (
          <div className="rounded-lg border border-primary/30 bg-primary/10 p-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <p className="text-sm">
                <strong>You're on the Free plan.</strong> Upgrade to Pro for advanced features.
              </p>
              <a
                href="/dashboard/billing"
                className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90"
              >
                Upgrade Plan
              </a>
            </div>
          </div>
        )}
        
        {/* Stats */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg border border-border bg-card p-4">
            <div className="grid gap-1">
              <h3 className="text-sm font-medium text-muted-foreground">Packages Scanned</h3>
              <div className="text-2xl font-bold">{stats.scannedPackages}</div>
            </div>
          </div>
          <div className="rounded-lg border border-border bg-card p-4">
            <div className="grid gap-1">
              <h3 className="text-sm font-medium text-muted-foreground">Vulnerabilities Found</h3>
              <div className="text-2xl font-bold">{stats.vulnerabilitiesFound}</div>
            </div>
          </div>
          <div className="rounded-lg border border-border bg-card p-4">
            <div className="grid gap-1">
              <h3 className="text-sm font-medium text-muted-foreground">Projects Protected</h3>
              <div className="text-2xl font-bold">{stats.projectsProtected}</div>
            </div>
          </div>
          <div className="rounded-lg border border-border bg-card p-4">
            <div className="grid gap-1">
              <h3 className="text-sm font-medium text-muted-foreground">Subscription</h3>
              <div className="text-2xl font-bold capitalize">{subscription.tier}</div>
            </div>
          </div>
        </div>
        
        {/* Recent scans */}
        <div className="rounded-lg border border-border">
          <div className="p-4">
            <h2 className="text-xl font-semibold">Recent Scans</h2>
          </div>
          <div className="p-4">
            {loading ? (
              <div className="flex items-center justify-center p-8">
                <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
              </div>
            ) : stats.scannedPackages > 0 ? (
              <div className="rounded-md border border-border">
                <div className="grid grid-cols-5 gap-4 p-4 font-medium border-b border-border">
                  <div>Package</div>
                  <div>Version</div>
                  <div>Ecosystem</div>
                  <div>Status</div>
                  <div>Date</div>
                </div>
                <div className="grid grid-cols-5 gap-4 p-4 text-sm">
                  <div>express</div>
                  <div>4.17.1</div>
                  <div>npm</div>
                  <div className="text-destructive">Vulnerable</div>
                  <div>{new Date().toLocaleDateString()}</div>
                </div>
                <div className="grid grid-cols-5 gap-4 p-4 text-sm bg-accent/30">
                  <div>django</div>
                  <div>3.2.12</div>
                  <div>pip</div>
                  <div className="text-green-600">Safe</div>
                  <div>{new Date().toLocaleDateString()}</div>
                </div>
                <div className="grid grid-cols-5 gap-4 p-4 text-sm">
                  <div>lodash</div>
                  <div>4.17.20</div>
                  <div>npm</div>
                  <div className="text-destructive">Vulnerable</div>
                  <div>{new Date().toLocaleDateString()}</div>
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center gap-2 p-8 text-center">
                <p className="text-muted-foreground">No scans yet.</p>
                <a
                  href="/dashboard/scans/new"
                  className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90"
                >
                  Run Your First Scan
                </a>
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}

export default withAuth(DashboardPage); 