import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    target: 'es2022',
  },
  server: {
    proxy: {
      '/api': `http://localhost:${process.env.BACKEND_PORT || '8080'}`,
      '/ws': {
        target: `ws://localhost:${process.env.BACKEND_PORT || '8080'}`,
        ws: true,
      },
    },
  },
});
