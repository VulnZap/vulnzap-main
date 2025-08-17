/**
 * Configuration for VulnZap
 *
 * Environment variables should be set in a .env file or in the system environment
 */

import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Configuration object
export const config = {
  // Server config
  server: {
    port: parseInt("3456", 10),
    host: "localhost",
  },

  auth: {
    baseUrl: "https://vulnzap.com",
  },

  // API endpoints
  api: {
    engine: "https://engine.vulnzap.com",
    vulnerability: {
      batch: "/api/scan/dependency",
    },
  },
};

export default config;
