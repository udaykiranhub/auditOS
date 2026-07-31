import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // Proxy API calls to the FastAPI backend so the frontend stays a pure
    // client of the same API a human could curl (SPEC §4 hard rule).
    proxy: {
      '/audits': 'http://localhost:8000',
    },
  },
})
