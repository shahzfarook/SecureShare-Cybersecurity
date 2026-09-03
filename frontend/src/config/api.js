/**
 * SecureShare API Configuration
 * Supports dynamic backend deployment URLs with Vercel and Render compatibility.
 */

export const API_BASE_URL = (
  import.meta.env.VITE_API_URL || "https://secureshare-api-suph.onrender.com"
).replace(/\/+$/, "");

/**
 * Resolves full API endpoint URL
 * @param {string} endpoint - Relative path (e.g. "/api/files/list")
 * @returns {string} - Full URL (e.g. "https://secureshare-api-suph.onrender.com/api/files/list")
 */
export const getApiUrl = (endpoint) => {
  if (!endpoint) return API_BASE_URL;
  const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  return `${API_BASE_URL}${cleanEndpoint}`;
};

export default API_BASE_URL;
