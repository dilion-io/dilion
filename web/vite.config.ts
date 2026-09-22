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
    // Pinned, and strict on purpose. Vite's default is to hop to the next free
    // port when 5173 is taken, which silently breaks passkeys: a WebAuthn
    // credential is bound to the origin that created it, and the dev server
    // only trusts the origins in DILION_AUTH_WEBAUTHN_RP_ORIGINS (see the
    // Makefile's `dev` target). Failing to start is the honest outcome — run
    // `npm run dev -- --port 5174` and start the server with
    // `DEV_WEB_ORIGIN=http://localhost:5174 make dev` if you need another port.
    port: 5173,
    strictPort: true,
    proxy: {
      // Supabase Auth compatible surface (supabase-js appends /auth/v1 itself).
      '/auth': { target: DILION_ORIGIN, changeOrigin: true },
      // Management plane consumed through the generated OpenAPI client.
      '/privacy': { target: DILION_ORIGIN, changeOrigin: true },
      '/iam': { target: DILION_ORIGIN, changeOrigin: true },
    },
  },
})
