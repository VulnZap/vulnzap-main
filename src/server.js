/**
 * Vulnzap Server
 * 
 * Multi-ecosystem vulnerability scanning server with MCP interface for LLMs.
 * Supports npm, pip, Go, and other ecosystems with a comprehensive vulnerability database.
 */

import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';

import CONFIG from './core/config.js';
import mcpRoutes from './api/mcp-routes.js';

// Load environment variables
dotenv.config();

// Convert import.meta.url to __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Create required directories
(async () => {
  try {
    // Create cache directory if it doesn't exist
    await fs.mkdir(CONFIG.DATA_PATHS.CACHE_DIR, { recursive: true });
    console.log(`Created cache directory at: ${CONFIG.DATA_PATHS.CACHE_DIR}`);
    
    // Create data directory if it doesn't exist
    await fs.mkdir(CONFIG.DATA_PATHS.DATA_DIR, { recursive: true });
    console.log(`Created data directory at: ${CONFIG.DATA_PATHS.DATA_DIR}`);
  } catch (err) {
    console.error('Error creating directories:', err);
  }
})();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Request size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Basic request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
});

// Rate limiting middleware
const rateLimiter = (windowMs, maxRequests) => {
  const clients = new Map();
  
  return (req, res, next) => {
    const clientIP = req.ip;
    
    // Get current client data or initialize
    const clientData = clients.get(clientIP) || { 
      count: 0, 
      resetTime: Date.now() + windowMs 
    };
    
    // Check if window expired and reset
    if (Date.now() > clientData.resetTime) {
      clientData.count = 0;
      clientData.resetTime = Date.now() + windowMs;
    }
    
    // Increment count
    clientData.count++;
    
    // Update map
    clients.set(clientIP, clientData);
    
    // Check limit
    if (clientData.count > maxRequests) {
      return res.status(429).json({
        error: 'Rate limit exceeded', 
        retryAfter: Math.ceil((clientData.resetTime - Date.now()) / 1000)
      });
    }
    
    next();
  };
};

// Apply rate limiting for API endpoints
app.use('/api', rateLimiter(
  CONFIG.RATE_LIMITING.WINDOW_MS, 
  CONFIG.RATE_LIMITING.MAX_REQUESTS
));

// Routes
app.use('/mcp', mcpRoutes);

// API routes (if enabled)
if (CONFIG.SERVER.ENABLE_API) {
  try {
    const apiRoutes = await import('./api/api-routes.js');
    app.use('/api', apiRoutes.default);
    console.log('API routes enabled');
  } catch (err) {
    console.error('Error loading API routes:', err);
  }
}

// Web UI routes (if enabled)
if (CONFIG.SERVER.ENABLE_WEB) {
  try {
    const webRoutes = await import('./web/web-routes.js');
    app.use('/', webRoutes.default);
    console.log('Web UI routes enabled');
  } catch (err) {
    console.error('Error loading web routes:', err);
  }
}

// Default route
app.get('/', (req, res) => {
  res.json({
    name: 'Vulnzap Vulnerability Scanner',
    version: '2.0.0',
    description: 'Multi-ecosystem vulnerability scanning server with MCP interface',
    endpoints: {
      mcp: '/mcp - Model Context Protocol interface',
      api: '/api - REST API endpoints (if enabled)',
      web: '/ - Web interface (if enabled)'
    },
    supportedEcosystems: CONFIG.ENABLED_ECOSYSTEMS,
    docs: 'https://github.com/example/vulnzap'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred' : err.message
  });
});

// Not found handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: `The requested resource at ${req.originalUrl} was not found`
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`Vulnzap server running on port ${PORT}`);
  console.log(`Supported ecosystems: ${CONFIG.ENABLED_ECOSYSTEMS.join(', ')}`);
  console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
  
  if (CONFIG.SERVER.ENABLE_API) {
    console.log(`API endpoint: http://localhost:${PORT}/api`);
  }
  
  if (CONFIG.SERVER.ENABLE_WEB) {
    console.log(`Web UI: http://localhost:${PORT}`);
  }
});

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

function gracefulShutdown() {
  console.log('Received shutdown signal, closing server...');
  
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
  
  // Force close after timeout
  setTimeout(() => {
    console.error('Could not close connections in time, forcing shutdown');
    process.exit(1);
  }, 10000);
} 