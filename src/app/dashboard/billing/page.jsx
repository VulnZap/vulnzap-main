"use client";

import { useEffect, useState } from 'react';
import { DashboardLayout } from '../../../components/dashboard/dashboard-layout';
import { useAuth } from '../../../contexts/auth-context';
import { getUserSubscription, createCheckoutSession, cancelSubscription } from '../../../utils/stripe-client';
import { withAuth } from '../../../contexts/auth-context';

function BillingPage() {
  const { user } = useAuth();
  const [subscription, setSubscription] = useState({ tier: 'free', status: 'inactive' });
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    // Load user subscription
    const loadSubscription = async () => {
      setLoading(true);
      try {
        const { success, data } = await getUserSubscription();
        if (success && data) {
          setSubscription(data.subscription || { tier: 'free', status: 'inactive' });
        }
      } catch (error) {
        console.error('Error loading subscription:', error);
      } finally {
        setLoading(false);
      }
    };

    if (user) {
      loadSubscription();
    }
  }, [user]);

  const handleUpgrade = async (tier) => {
    setActionLoading(true);
    try {
      let priceId;
      if (tier === 'pro') {
        priceId = process.env.NEXT_PUBLIC_STRIPE_PRICE_ID_PRO;
      } else if (tier === 'enterprise') {
        priceId = process.env.NEXT_PUBLIC_STRIPE_PRICE_ID_ENTERPRISE;
      }

      if (!priceId) {
        throw new Error(`Invalid price ID for tier: ${tier}`);
      }

      await createCheckoutSession(priceId);
    } catch (error) {
      console.error('Error creating checkout session:', error);
      alert('Failed to redirect to checkout. Please try again.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleCancel = async () => {
    if (!confirm('Are you sure you want to cancel your subscription? You will lose access to premium features at the end of your billing period.')) {
      return;
    }

    setActionLoading(true);
    try {
      const { success, error } = await cancelSubscription();
      if (success) {
        setSubscription({ ...subscription, status: 'canceled' });
        alert('Your subscription has been canceled. You will have access until the end of your billing period.');
      } else {
        throw new Error(error || 'Failed to cancel subscription');
      }
    } catch (error) {
      console.error('Error canceling subscription:', error);
      alert('Failed to cancel subscription. Please try again.');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="grid gap-6">
        <div className="flex flex-col space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">Billing</h1>
          <p className="text-muted-foreground">Manage your subscription and billing information</p>
        </div>

        {/* Current subscription */}
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <div className="p-6">
            <h2 className="text-xl font-semibold mb-4">Current Plan</h2>
            {loading ? (
              <div className="flex items-center justify-center p-8">
                <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h3 className="text-sm font-medium text-muted-foreground">Plan</h3>
                    <p className="text-lg font-medium capitalize">{subscription.tier}</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-muted-foreground">Status</h3>
                    <p className="text-lg font-medium capitalize">{subscription.status || 'inactive'}</p>
                  </div>
                </div>
                
                {/* Action buttons based on subscription status */}
                <div className="flex flex-wrap gap-4 mt-6">
                  {subscription.tier === 'free' && (
                    <>
                      <button
                        onClick={() => handleUpgrade('pro')}
                        disabled={actionLoading}
                        className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none"
                      >
                        {actionLoading ? 'Processing...' : 'Upgrade to Pro'}
                      </button>
                      <button
                        onClick={() => handleUpgrade('enterprise')}
                        disabled={actionLoading}
                        className="inline-flex items-center justify-center rounded-md bg-card border border-border px-4 py-2 text-sm font-medium shadow hover:bg-card/80 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none"
                      >
                        {actionLoading ? 'Processing...' : 'Upgrade to Enterprise'}
                      </button>
                    </>
                  )}
                  
                  {(subscription.tier === 'pro' || subscription.tier === 'enterprise') && (
                    subscription.status === 'active' ? (
                      <button
                        onClick={handleCancel}
                        disabled={actionLoading}
                        className="inline-flex items-center justify-center rounded-md bg-destructive/10 text-destructive px-4 py-2 text-sm font-medium shadow hover:bg-destructive/20 focus:outline-none focus:ring-2 focus:ring-destructive focus:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none"
                      >
                        {actionLoading ? 'Processing...' : 'Cancel Subscription'}
                      </button>
                    ) : (
                      <button
                        onClick={() => handleUpgrade(subscription.tier)}
                        disabled={actionLoading}
                        className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none"
                      >
                        {actionLoading ? 'Processing...' : 'Renew Subscription'}
                      </button>
                    )
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Plans comparison */}
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="p-6">
            <h2 className="text-xl font-semibold mb-4">Compare Plans</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Free Plan */}
              <div className={`rounded-lg border ${subscription.tier === 'free' ? 'border-primary' : 'border-border'} p-6`}>
                <h3 className="text-xl font-semibold">Free</h3>
                <p className="text-3xl font-bold my-3">$0</p>
                <p className="text-muted-foreground text-sm mb-6">Basic features for solo developers</p>
                <ul className="space-y-2 mb-6">
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Real-time vulnerability scanning</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Basic MCP integration</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>GitHub Advisory Database</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted-foreground w-5 h-5 mt-0.5">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                    <span className="text-muted-foreground">Zero-day vulnerability alerts</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted-foreground w-5 h-5 mt-0.5">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                    <span className="text-muted-foreground">AI-generated code analysis</span>
                  </li>
                </ul>
                {subscription.tier === 'free' ? (
                  <button disabled className="w-full inline-flex items-center justify-center rounded-md bg-primary/30 px-4 py-2 text-sm font-medium text-primary-foreground shadow opacity-50 cursor-not-allowed">
                    Current Plan
                  </button>
                ) : (
                  <button 
                    onClick={() => handleCancel()}
                    disabled={actionLoading}
                    className="w-full inline-flex items-center justify-center rounded-md border border-border bg-card px-4 py-2 text-sm font-medium shadow hover:bg-card/80 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
                  >
                    Downgrade
                  </button>
                )}
              </div>

              {/* Pro Plan */}
              <div className={`rounded-lg border ${subscription.tier === 'pro' ? 'border-primary' : 'border-border'} p-6 shadow-lg`}>
                <h3 className="text-xl font-semibold">Pro</h3>
                <p className="text-3xl font-bold my-3">$9<span className="text-base font-normal">/mo</span></p>
                <p className="text-muted-foreground text-sm mb-6">Advanced features for professionals</p>
                <ul className="space-y-2 mb-6">
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Everything in Free</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Zero-day vulnerability alerts</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>AI-generated code analysis</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Unlimited vulnerability scanning</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted-foreground w-5 h-5 mt-0.5">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                    <span className="text-muted-foreground">24/7 dedicated support</span>
                  </li>
                </ul>
                {subscription.tier === 'pro' ? (
                  <button disabled className="w-full inline-flex items-center justify-center rounded-md bg-primary/30 px-4 py-2 text-sm font-medium text-primary-foreground shadow opacity-50 cursor-not-allowed">
                    Current Plan
                  </button>
                ) : (
                  <button 
                    onClick={() => handleUpgrade('pro')}
                    disabled={actionLoading}
                    className="w-full inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
                  >
                    {subscription.tier === 'enterprise' ? 'Downgrade to Pro' : 'Upgrade to Pro'}
                  </button>
                )}
              </div>

              {/* Enterprise Plan */}
              <div className={`rounded-lg border ${subscription.tier === 'enterprise' ? 'border-primary' : 'border-border'} p-6`}>
                <h3 className="text-xl font-semibold">Enterprise</h3>
                <p className="text-3xl font-bold my-3">$19<span className="text-base font-normal">/mo</span></p>
                <p className="text-muted-foreground text-sm mb-6">Complete solution for businesses</p>
                <ul className="space-y-2 mb-6">
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Everything in Pro</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>24/7 dedicated support</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Custom security policies</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>SOC2 compliance reporting</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary w-5 h-5 mt-0.5">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Automated remediation</span>
                  </li>
                </ul>
                {subscription.tier === 'enterprise' ? (
                  <button disabled className="w-full inline-flex items-center justify-center rounded-md bg-primary/30 px-4 py-2 text-sm font-medium text-primary-foreground shadow opacity-50 cursor-not-allowed">
                    Current Plan
                  </button>
                ) : (
                  <button 
                    onClick={() => handleUpgrade('enterprise')}
                    disabled={actionLoading}
                    className="w-full inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
                  >
                    Upgrade to Enterprise
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}

export default withAuth(BillingPage); 