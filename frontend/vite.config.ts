import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        // Points at the Odezzy API server (src/server.ts, `npm run api`),
        // NOT TrueForge (which runs on 8790) — those are two different
        // servers with two completely different route sets. This was
        // previously pointed at 8790, which meant every dashboard request
        // silently 404'd against TrueForge's own API and the UI fell back
        // to demo data on every single load, even with the real backend
        // running correctly on 4000.
        target: 'http://localhost:4000',
        changeOrigin: true,
      },
    },
  },
});
