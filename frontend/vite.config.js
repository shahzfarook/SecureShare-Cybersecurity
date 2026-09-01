import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api/auth': {
        target: 'http://localhost:5000',
        changeOrigin: true
      },
      '/api/alerts': {
        target: 'http://localhost:5001',
        changeOrigin: true
      },
      '/api/stats': {
        target: 'http://localhost:5001',
        changeOrigin: true
      },
      '/api/logs': {
        target: 'http://localhost:5001',
        changeOrigin: true
      },
      '/api/analyze': {
        target: 'http://localhost:5001',
        changeOrigin: true
      }
    }
  }
})
