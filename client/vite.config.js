import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1', 
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:4100',
      '/health': 'http://127.0.0.1:4100',
      '/p': 'http://127.0.0.1:4100'
    }
  }
});
