/**
 * SecureShare API Configuration
 * Automatically detects local vs cloud deployment.
 */
const isLocalhost =
  typeof window !== "undefined" &&
  (window.location.hostname === "localhost" ||
   window.location.hostname === "127.0.0.1" ||
   window.location.hostname === "[::1]" ||
   window.location.hostname.startsWith("192.168.") ||
   window.location.hostname.startsWith("10.") ||
   window.location.hostname === "");

const defaultLocalUrl = "http://localhost:5000";
const defaultCloudUrl = "https://secureshare-api-suph.onrender.com";

export const API_BASE_URL = (
  import.meta.env.VITE_API_URL
    ? import.meta.env.VITE_API_URL
    : (isLocalhost ? defaultLocalUrl : defaultCloudUrl)
).replace(/\/+$/, "");

/**
 * Resolves full API endpoint URL
 * @param {string} endpoint - Relative path (e.g. "/api/files/list")
 * @returns {string} - Full URL
 */
export const getApiUrl = (endpoint) => {
  if (!endpoint) return API_BASE_URL;
  const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  return `${API_BASE_URL}${cleanEndpoint}`;
};

export default API_BASE_URL;
