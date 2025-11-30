import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      injectRegister: "auto",
      registerType: "autoUpdate",
      workbox: { clientsClaim: true, skipWaiting: true }
    })
  ],
  build: {
    chunkSizeWarningLimit: 2000
  },
  server: {
    // Proxy setup for Cursor Deployment Platform Backend (via Docker Load Balancer)
    proxy: {
      '/api': {
        target: 'http://localhost:5030', // Points to nginx-lb mapped port
        changeOrigin: true,
        secure: false
      },
      '/deploy': {
        target: 'http://localhost:5030', // Points to nginx-lb mapped port
        changeOrigin: true,
        secure: false
      }
    }
  },
  resolve: {
    alias: {
      app: path.resolve(__dirname, "src/app")
    }
  }
});