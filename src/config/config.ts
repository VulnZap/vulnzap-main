/**
 * Configuration for VulnZap
 *
 * Environment variables should be set in a .env file or in the system environment
 */

import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

// Load environment variables
dotenv.config();

// Get __dirname equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration object
export const config = {
  // App info
  app: {
    name: "VulnZap",
    version: "1.0.0",
    homeDir: path.join(
      process.env.HOME || process.env.USERPROFILE || "",
      ".vulnzap"
    ),
    tokenStorageKey: "vulnzap_token",
    dataDir: path.join(__dirname, "../../data"),
  },

  // Server config
  server: {
    port: parseInt("3456", 10),
    host: "localhost",
  },

  auth: {
    baseUrl: "https://vulnzap.com",
    // baseUrl: 'http://localhost:3000',  // Use for local development
  },

  // API endpoints
  api: {
    baseUrl: "https://vulnzap-server.vercel.app",
    // baseUrl: 'http://localhost:4000',  // Use for local development
    addOn: "/api/v1",
    enhanced: "/api/v2",
    vulnerability: {
      check: "/vulnzap/scan",
      batch: "/vulnzap/batch-scan",
    },
    account: {
      info: "/account/info",
      subscription: "/account/subscription",
      usage: "/account/usage",
    },
    docs: {
      base: "/enhanced-get-docs",
    },
    tools: {
      base: "/enhanced-latest-toolset",
    },
    ai: {
      base: "/enhanced-amplify-prompt",
    },
  },
};

export default config;
