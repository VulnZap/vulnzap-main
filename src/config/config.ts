/**
 * Configuration for VulnZap
 * 
 * Environment variables should be set in a .env file or in the system environment
 */

import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Load environment variables
dotenv.config();

// Get __dirname equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration object
export const config = {
  // App info
  app: {
    name: 'VulnZap',
    version: '1.0.0',
    homeDir: path.join(process.env.HOME || process.env.USERPROFILE || '', '.vulnzap'),
    tokenStorageKey: 'vulnzap_token',
    dataDir: path.join(__dirname, '../../data'),
  },

  // Server config
  server: {
    port: parseInt(process.env.PORT || '3456', 10),
    host: process.env.HOST || 'localhost',
  },

  // Stripe config
  stripe: {
    publicKey: process.env.STRIPE_PUBLIC_KEY || '',
    secretKey: process.env.STRIPE_SECRET_KEY || '',
    webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
    prices: {
      free: 'price_free',
      pro: process.env.STRIPE_PRICE_PRO || 'price_pro',
      enterprise: process.env.STRIPE_PRICE_ENTERPRISE || 'price_enterprise',
    },
    products: {
      pro: process.env.STRIPE_PRODUCT_PRO || 'prod_pro',
      enterprise: process.env.STRIPE_PRODUCT_ENTERPRISE || 'prod_enterprise',
    },
  },

  // API endpoints
  api: {
    baseUrl: process.env.NODE_ENV === 'development' ? 'http://localhost:4000' : 'https://vulnzap-server.vercel.app',
    addOn: '/api/v1/vulnzap',
    vulnerability: {
      check: '/scan',
      batch: '/batch-scan',
      sbom: '/sbom'
    },
    account: {
      info: '/account/info',
      subscription: '/account/subscription',
      usage: '/account/usage',
    },
  },
};

export default config; 