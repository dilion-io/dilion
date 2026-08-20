import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The Dilion dev server (auth + management plane) runs on :8787.
// Everything is proxied through the Vite dev server so the browser only ever
// talks to its own origin — no CORS configuration is needed anywhere.
const DILION_ORIGIN = process.env.DILION_ORIGIN ?? 'http://localhost:8787'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Supabase Auth compatible surface (supabase-js appends /auth/v1 itself).
      '/auth': { target: DILION_ORIGIN, changeOrigin: true },
      // Management plane consumed through the generated OpenAPI client.
      '/privacy': { target: DILION_ORIGIN, changeOrigin: true },
      '/iam': { target: DILION_ORIGIN, changeOrigin: true },
    },
  },
})
