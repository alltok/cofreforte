import { defineConfig } from 'vite';

export default defineConfig({
  // Caminhos relativos: funciona na raiz (Vercel/Netlify) e em subpastas (GitHub Pages).
  base: './',
  test: {
    environment: 'node',
    include: ['tests/**/*.test.js'],
    testTimeout: 30000,
  },
});
