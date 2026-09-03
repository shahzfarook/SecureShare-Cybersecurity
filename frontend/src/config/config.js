/**
 * SecureShare Production Configuration for Vercel
 */
export const API_BASE_URL = (
  import.meta.env.VITE_API_URL || "https://secureshare-api-suph.onrender.com"
).replace(/\/+$/, "");

export const getApiUrl = (endpoint) => {
  if (!endpoint) return API_BASE_URL;
  const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  return `${API_BASE_URL}${cleanEndpoint}`;
};

export default API_BASE_URL;
