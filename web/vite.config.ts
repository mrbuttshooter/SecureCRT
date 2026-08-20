import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The built assets are embedded into the Go binary, so there is no separate
// web root to deploy and no chance of the frontend and backend drifting apart
// in a deployment.
//
// The dev server proxies /api to a locally running bkd, so the browser sees
// one origin and the SameSite=Strict session cookie behaves as it does in
// production.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Hashed filenames let the assets be cached indefinitely while index.html
    // stays uncached, so an upgrade takes effect on the next page load.
    assetsDir: 'assets',
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8443',
        changeOrigin: false,
      },
    },
  },
})
