import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({

  base: './',

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
    proxy: {
      '/api': {
        target: 'http://localhost:5030',
        changeOrigin: true,
        secure: false,
        timeout: 300000, // ✅ Added: 5 minute timeout
        proxyTimeout: 300000 // ✅ Added: 5 minute timeout
      },
      '/deploy': {
        target: 'http://localhost:5030',
        changeOrigin: true,
        secure: false,
        timeout: 300000, // ✅ Added
        proxyTimeout: 300000 // ✅ Added
      }
    }
  },
  resolve: {
    alias: {
      app: path.resolve(__dirname, "src/app")
    }
  }
});