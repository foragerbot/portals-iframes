import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // API routes (auth, files, gpt, admin, etc.)
      '/api': {
        target: 'http://localhost:4100',
        changeOrigin: true,
        secure: false,
      },

      // Public iframe hosting (preview + asset URLs)
      '/p': {
        target: 'http://127.0.0.1:4100',
        changeOrigin: true,
        secure: false,
      },

      // Optional: health check if you ever hit it via the UI origin
      '/health': {
        target: 'http://127.0.0.1:4100',
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
