import { loadStripe } from '@stripe/stripe-js';

// Initialize Stripe
const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

// Create Stripe checkout session
export const createCheckoutSession = async (priceId) => {
  try {
    const response = await fetch('/api/create-checkout-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('supabase.auth.token')}`
      },
      body: JSON.stringify({ priceId }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to create checkout session');
    }

    const { url } = await response.json();
    window.location.href = url;
    return { success: true };
  } catch (error) {
    console.error('Error creating checkout session:', error);
    return { success: false, error: error.message };
  }
};

// Get user subscription data
export const getUserSubscription = async () => {
  try {
    const response = await fetch('/api/me', {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('supabase.auth.token')}`
      },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to get user subscription');
    }

    const data = await response.json();
    return { success: true, data };
  } catch (error) {
    console.error('Error getting user subscription:', error);
    return { success: false, error: error.message };
  }
};

// Cancel subscription
export const cancelSubscription = async () => {
  try {
    const response = await fetch('/api/cancel-subscription', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('supabase.auth.token')}`
      },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to cancel subscription');
    }

    return { success: true };
  } catch (error) {
    console.error('Error cancelling subscription:', error);
    return { success: false, error: error.message };
  }
};

export default stripePromise; 