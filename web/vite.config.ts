/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The reverse proxy serves web/dist as static files and routes /api itself, and
// the backend refuses every /api request that lacks the proxy secret. In dev,
// this server plays the proxy's part: it forwards /api to a locally running
// backend and adds the same X-Proxy-Auth header, taken from the environment so
// the secret never lands in the repository. It also sends the backend's own
// public origin as Origin, because the backend refuses state-changing requests
// whose Origin is another site, and the browser's is http://localhost:5173.
//
//   FG_PROXY_SECRET  the secret the backend was started with (required for dev)
//   FG_BASE_URL      the backend's FG_BASE_URL (required for dev)
//   FG_DEV_BACKEND   where the backend listens, default http://127.0.0.1:8080
const secret = process.env.FG_PROXY_SECRET ?? ''
const baseUrl = process.env.FG_BASE_URL ?? ''
const backend = process.env.FG_DEV_BACKEND ?? 'http://127.0.0.1:8080'

export default defineConfig(({ command }) => {
  if (command === 'serve' && !process.env.VITEST && (!secret || !baseUrl)) {
    throw new Error('npm run dev needs FG_PROXY_SECRET and FG_BASE_URL in the environment (the same values the backend runs with); see the README')
  }
  return {
    plugins: [react()],
    build: { outDir: 'dist' },
    server: {
      proxy: {
        '/api': {
          target: backend,
          headers: { 'X-Proxy-Auth': secret, Origin: baseUrl.replace(/\/$/, '') },
        },
      },
    },
    test: {
      environment: 'jsdom',
      setupFiles: ['./src/test/setup.ts'],
      globals: false,
    },
  }
})
