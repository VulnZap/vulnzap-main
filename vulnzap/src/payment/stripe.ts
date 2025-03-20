/**
 * Stripe Payment Service
 * Handles subscription management and payment processing
 */

import Stripe from 'stripe';
import { config } from '../config/config.js';
import { createClient } from '@supabase/supabase-js';
import { getCurrentUser } from '../auth/supabase.js';
import { v4 as uuidv4 } from 'uuid';
import open from 'open';

// Initialize Stripe client
const stripe = new Stripe(config.stripe.secretKey, {
  apiVersion: '2023-10-16',
});

// Initialize Supabase client
const supabase = createClient(
  config.supabase.url,
  config.supabase.serviceKey || config.supabase.anonKey
);

/**
 * Subscription tier types
 */
export type SubscriptionTier = 'free' | 'pro' | 'enterprise';

/**
 * Subscription status types
 */
export type SubscriptionStatus = 
  | 'active'
  | 'canceled'
  | 'incomplete'
  | 'incomplete_expired'
  | 'past_due'
  | 'trialing'
  | 'unpaid';

/**
 * Subscription information
 */
export interface SubscriptionInfo {
  id: string;
  customerId: string;
  tier: SubscriptionTier;
  status: SubscriptionStatus;
  currentPeriodEnd: number;
  cancelAtPeriodEnd: boolean;
  createdAt: number;
  priceId: string;
}

/**
 * Create a checkout session for subscription
 * 
 * @param tier - The subscription tier
 * @param successUrl - URL to redirect to on success
 * @param cancelUrl - URL to redirect to on cancellation
 */
export async function createCheckoutSession(
  tier: 'pro' | 'enterprise',
  successUrl?: string,
  cancelUrl?: string
): Promise<{ success: boolean; error: string | null; url?: string; sessionId?: string }> {
  try {
    const user = await getCurrentUser();
    
    if (!user) {
      return { success: false, error: 'User not authenticated' };
    }
    
    // Default URLs
    const defaultSuccessUrl = `${config.api.baseUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`;
    const defaultCancelUrl = `${config.api.baseUrl}/payment/cancel`;
    
    // Get price ID for tier
    const priceId = tier === 'pro' ? config.stripe.prices.pro : config.stripe.prices.enterprise;
    
    // Check if user already has a customer ID
    const { data: customerData } = await supabase
      .from(config.tables.users)
      .select('stripe_customer_id')
      .eq('id', user.id)
      .single();
      
    let customerId = customerData?.stripe_customer_id;
    
    // Create customer if doesn't exist
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: {
          user_id: user.id,
        },
      });
      
      customerId = customer.id;
      
      // Save customer ID to database
      await supabase
        .from(config.tables.users)
        .update({ stripe_customer_id: customerId })
        .eq('id', user.id);
    }
    
    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: successUrl || defaultSuccessUrl,
      cancel_url: cancelUrl || defaultCancelUrl,
      metadata: {
        user_id: user.id,
        tier,
      },
    });
    
    return {
      success: true,
      error: null,
      url: session.url || undefined,
      sessionId: session.id,
    };
  } catch (error: any) {
    console.error('Error creating checkout session:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Open a browser to handle checkout
 * 
 * @param tier - The subscription tier
 */
export async function openCheckoutInBrowser(tier: 'pro' | 'enterprise'): Promise<{ success: boolean; error: string | null; sessionId?: string }> {
  try {
    // Create unique ID for this checkout
    const checkoutId = uuidv4();
    
    // Define URLs with the checkout ID
    const successUrl = `${config.api.baseUrl}/payment/cli-success?checkout_id=${checkoutId}`;
    const cancelUrl = `${config.api.baseUrl}/payment/cli-cancel?checkout_id=${checkoutId}`;
    
    // Create checkout session
    const result = await createCheckoutSession(tier, successUrl, cancelUrl);
    
    if (!result.success || !result.url) {
      return { success: false, error: result.error || 'Failed to create checkout session' };
    }
    
    // Open the browser
    await open(result.url);
    
    return { 
      success: true, 
      error: null,
      sessionId: result.sessionId
    };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

/**
 * Get the user's current subscription
 */
export async function getUserSubscription(): Promise<{ success: boolean; error: string | null; subscription?: SubscriptionInfo }> {
  try {
    const user = await getCurrentUser();
    
    if (!user) {
      return { success: false, error: 'User not authenticated' };
    }
    
    // Query the subscriptions table
    const { data, error } = await supabase
      .from(config.tables.subscriptions)
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();
      
    if (error) {
      return { success: false, error: error.message };
    }
    
    if (!data) {
      // No subscription found, return free tier info
      return { 
        success: true, 
        error: null,
        subscription: {
          id: 'free',
          customerId: '',
          tier: 'free',
          status: 'active',
          currentPeriodEnd: Number.MAX_SAFE_INTEGER,
          cancelAtPeriodEnd: false,
          createdAt: Date.now(),
          priceId: 'price_free',
        }
      };
    }
    
    // Return subscription info
    return {
      success: true,
      error: null,
      subscription: {
        id: data.subscription_id,
        customerId: data.customer_id,
        tier: data.tier,
        status: data.status,
        currentPeriodEnd: data.current_period_end,
        cancelAtPeriodEnd: data.cancel_at_period_end,
        createdAt: data.created_at,
        priceId: data.price_id,
      }
    };
  } catch (error: any) {
    console.error('Error getting user subscription:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Cancel a subscription
 */
export async function cancelSubscription(): Promise<{ success: boolean; error: string | null }> {
  try {
    const user = await getCurrentUser();
    
    if (!user) {
      return { success: false, error: 'User not authenticated' };
    }
    
    // Get user's subscription
    const { success, error, subscription } = await getUserSubscription();
    
    if (!success || !subscription) {
      return { success: false, error: error || 'Failed to get subscription' };
    }
    
    // No need to cancel if free tier
    if (subscription.tier === 'free') {
      return { success: true, error: null };
    }
    
    // Cancel at period end
    await stripe.subscriptions.update(subscription.id, {
      cancel_at_period_end: true,
    });
    
    // Update in database
    await supabase
      .from(config.tables.subscriptions)
      .update({ cancel_at_period_end: true })
      .eq('subscription_id', subscription.id);
      
    return { success: true, error: null };
  } catch (error: any) {
    console.error('Error cancelling subscription:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Resume a subscription that was cancelled
 */
export async function resumeSubscription(): Promise<{ success: boolean; error: string | null }> {
  try {
    const user = await getCurrentUser();
    
    if (!user) {
      return { success: false, error: 'User not authenticated' };
    }
    
    // Get user's subscription
    const { success, error, subscription } = await getUserSubscription();
    
    if (!success || !subscription) {
      return { success: false, error: error || 'Failed to get subscription' };
    }
    
    // Can't resume if not in a cancellable state
    if (subscription.tier === 'free' || !subscription.cancelAtPeriodEnd) {
      return { success: false, error: 'No subscription to resume' };
    }
    
    // Resume subscription by unsetting cancel_at_period_end
    await stripe.subscriptions.update(subscription.id, {
      cancel_at_period_end: false,
    });
    
    // Update in database
    await supabase
      .from(config.tables.subscriptions)
      .update({ cancel_at_period_end: false })
      .eq('subscription_id', subscription.id);
      
    return { success: true, error: null };
  } catch (error: any) {
    console.error('Error resuming subscription:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Update subscription to a different tier
 */
export async function updateSubscription(newTier: 'pro' | 'enterprise'): Promise<{ success: boolean; error: string | null }> {
  try {
    const user = await getCurrentUser();
    
    if (!user) {
      return { success: false, error: 'User not authenticated' };
    }
    
    // Get user's subscription
    const { success, error, subscription } = await getUserSubscription();
    
    if (!success || !subscription) {
      return { success: false, error: error || 'Failed to get subscription' };
    }
    
    // If free tier, need to create new subscription
    if (subscription.tier === 'free') {
      return { success: false, error: 'Please create a new subscription' };
    }
    
    // Get price ID for new tier
    const newPriceId = newTier === 'pro' ? config.stripe.prices.pro : config.stripe.prices.enterprise;
    
    // Update the subscription with the new price
    await stripe.subscriptions.update(subscription.id, {
      items: [
        {
          id: (await stripe.subscriptions.retrieve(subscription.id)).items.data[0].id,
          price: newPriceId,
        },
      ],
      proration_behavior: 'create_prorations',
    });
    
    // Update in database
    await supabase
      .from(config.tables.subscriptions)
      .update({ 
        tier: newTier,
        price_id: newPriceId
      })
      .eq('subscription_id', subscription.id);
      
    return { success: true, error: null };
  } catch (error: any) {
    console.error('Error updating subscription:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Check if the user is premium (paid tier)
 */
export async function isPremiumUser(): Promise<boolean> {
  try {
    const { success, subscription } = await getUserSubscription();
    
    if (!success || !subscription) {
      return false;
    }
    
    return (
      subscription.tier !== 'free' && 
      subscription.status === 'active'
    );
  } catch (error) {
    console.error('Error checking premium status:', error);
    return false;
  }
}

/**
 * Get the user's remaining scan quota
 */
export async function getRemainingScanQuota(): Promise<{ success: boolean; error: string | null; remaining?: number; total?: number }> {
  try {
    const user = await getCurrentUser();
    
    if (!user) {
      return { success: false, error: 'User not authenticated' };
    }
    
    // Get user's tier
    const { success, subscription } = await getUserSubscription();
    
    if (!success || !subscription) {
      // Default to free tier
      return { 
        success: true, 
        error: null,
        remaining: config.limits.free.scansPerDay,
        total: config.limits.free.scansPerDay
      };
    }
    
    // Get tier limits
    const tierLimits = config.limits[subscription.tier];
    
    // Get today's scan count
    const today = new Date().toISOString().split('T')[0];
    const { data, error } = await supabase
      .from(config.tables.usageStats)
      .select('scans_count')
      .eq('user_id', user.id)
      .eq('date', today)
      .single();
      
    if (error && error.code !== 'PGRST116') { // PGRST116 is "no rows returned" which is fine
      return { success: false, error: error.message };
    }
    
    const todayCount = data?.scans_count || 0;
    const remaining = Math.max(0, tierLimits.scansPerDay - todayCount);
    
    return {
      success: true,
      error: null,
      remaining,
      total: tierLimits.scansPerDay
    };
  } catch (error: any) {
    console.error('Error getting scan quota:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Process a webhook from Stripe
 */
export async function processWebhook(event: Stripe.Event): Promise<{ success: boolean; error: string | null }> {
  try {
    // Handle specific event types
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object as Stripe.Checkout.Session;
        
        // Get user ID from metadata
        const userId = session.metadata?.user_id;
        const tier = session.metadata?.tier;
        
        if (!userId || !tier) {
          return { success: false, error: 'Missing metadata' };
        }
        
        // Get subscription ID
        const subscriptionId = session.subscription as string;
        
        if (!subscriptionId) {
          return { success: false, error: 'Missing subscription ID' };
        }
        
        // Get subscription details
        const subscription = await stripe.subscriptions.retrieve(subscriptionId);
        
        // Insert into subscriptions table
        await supabase
          .from(config.tables.subscriptions)
          .insert({
            user_id: userId,
            subscription_id: subscription.id,
            customer_id: subscription.customer as string,
            status: subscription.status,
            tier: tier as SubscriptionTier,
            current_period_end: subscription.current_period_end,
            cancel_at_period_end: subscription.cancel_at_period_end,
            price_id: subscription.items.data[0].price.id,
          });
        
        // Update user's tier
        await supabase
          .from(config.tables.users)
          .update({ 
            tier,
            stripe_customer_id: subscription.customer as string
          })
          .eq('id', userId);
          
        break;
      }
      
      case 'customer.subscription.updated': {
        const subscription = event.data.object as Stripe.Subscription;
        
        // Update subscription in database
        await supabase
          .from(config.tables.subscriptions)
          .update({
            status: subscription.status,
            current_period_end: subscription.current_period_end,
            cancel_at_period_end: subscription.cancel_at_period_end,
          })
          .eq('subscription_id', subscription.id);
        
        break;
      }
      
      case 'customer.subscription.deleted': {
        const subscription = event.data.object as Stripe.Subscription;
        
        // Get user from subscription
        const { data: subscriptionData } = await supabase
          .from(config.tables.subscriptions)
          .select('user_id')
          .eq('subscription_id', subscription.id)
          .single();
          
        if (!subscriptionData) {
          return { success: false, error: 'Subscription not found' };
        }
        
        // Update subscription status
        await supabase
          .from(config.tables.subscriptions)
          .update({
            status: subscription.status,
            current_period_end: subscription.current_period_end,
            cancel_at_period_end: subscription.cancel_at_period_end,
          })
          .eq('subscription_id', subscription.id);
        
        // Reset user to free tier
        await supabase
          .from(config.tables.users)
          .update({ tier: 'free' })
          .eq('id', subscriptionData.user_id);
        
        break;
      }
    }
    
    return { success: true, error: null };
  } catch (error: any) {
    console.error('Error processing webhook:', error);
    return { success: false, error: error.message };
  }
}

export default {
  createCheckoutSession,
  openCheckoutInBrowser,
  getUserSubscription,
  cancelSubscription,
  resumeSubscription,
  updateSubscription,
  isPremiumUser,
  getRemainingScanQuota,
  processWebhook,
}; 