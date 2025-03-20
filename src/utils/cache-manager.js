/**
 * Cache Manager
 * 
 * Utilities for caching and retrieving data
 */

import fs from 'fs/promises';
import path from 'path';

/**
 * Save data to a cache file
 * 
 * @param {string} filePath - Path to the cache file
 * @param {Object} data - Data to cache
 * @returns {Promise<boolean>} - Success/failure
 */
export async function cacheData(filePath, data) {
  try {
    // Create directory if it doesn't exist
    const dir = path.dirname(filePath);
    await fs.mkdir(dir, { recursive: true });
    
    // Write to file
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`Error caching data to ${filePath}:`, error);
    return false;
  }
}

/**
 * Load data from a cache file
 * 
 * @param {string} filePath - Path to the cache file
 * @returns {Promise<Object|null>} - Cached data or null if error/not found
 */
export async function loadCachedData(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    // File doesn't exist or is invalid
    return null;
  }
}

/**
 * Check if a cache file is stale
 * 
 * @param {string} filePath - Path to the cache file
 * @param {number} maxAge - Maximum age in milliseconds
 * @returns {Promise<boolean>} - True if cache is stale or doesn't exist
 */
export async function isCacheStale(filePath, maxAge) {
  try {
    const stats = await fs.stat(filePath);
    const fileAge = Date.now() - stats.mtime.getTime();
    return fileAge > maxAge;
  } catch (error) {
    // File doesn't exist, so cache is "stale"
    return true;
  }
}

/**
 * Clear a cache file if it exists
 * 
 * @param {string} filePath - Path to the cache file
 * @returns {Promise<boolean>} - Success/failure
 */
export async function clearCache(filePath) {
  try {
    await fs.unlink(filePath);
    return true;
  } catch (error) {
    // If file doesn't exist, consider it a success
    if (error.code === 'ENOENT') {
      return true;
    }
    console.error(`Error clearing cache at ${filePath}:`, error);
    return false;
  }
}

/**
 * Get cached data with automatic refresh
 * 
 * @param {string} filePath - Path to the cache file
 * @param {number} maxAge - Maximum age in milliseconds
 * @param {Function} refreshCallback - Function to call to refresh data
 * @returns {Promise<Object>} - Cached data (refreshed if stale)
 */
export async function getCachedData(filePath, maxAge, refreshCallback) {
  // Check if cache is stale
  const stale = await isCacheStale(filePath, maxAge);
  
  if (stale) {
    // Refresh cache
    const freshData = await refreshCallback();
    
    // Save to cache
    await cacheData(filePath, freshData);
    
    return freshData;
  } else {
    // Load from cache
    const cachedData = await loadCachedData(filePath);
    
    if (cachedData) {
      return cachedData;
    } else {
      // Cache is corrupted, refresh it
      const freshData = await refreshCallback();
      
      // Save to cache
      await cacheData(filePath, freshData);
      
      return freshData;
    }
  }
} 