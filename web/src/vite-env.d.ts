/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Management-plane token (service_role JWT or `dk_` API key). DEV ONLY. */
  readonly VITE_DILION_SERVICE_TOKEN?: string
  /** Anon key handed to supabase-js. */
  readonly VITE_DILION_ANON_KEY?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
