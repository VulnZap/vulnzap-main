import { v4 } from 'uuid';
import config from '../config/config.js';

const API_BASE_URL = config.api.baseUrl + config.api.addOn;

export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/vulnzap/health`, {
      method: 'GET',
    });
    if (response.ok) {
      return {
        status: "ok"
      };
    } else {
      return {
        status: "down"
      }
    }
  } catch (error) {
    return {
      status: "down"
    }
  }
}