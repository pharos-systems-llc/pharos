/* ========================================================================
 * Project: pharos
 * Component: Web Console
 * File: astro.config.mjs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * Configuration file for the Pharos Web Console. Sets the project to SSR 
 * mode (Node.js adapter) and enables Tailwind CSS for responsive styling.
 * * Traceability:
 * Related to Task 16.1 in Phase 16.
 * ======================================================================== */

// @ts-check
import { defineConfig } from 'astro/config';

import node from '@astrojs/node';
import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
  output: 'server',
  adapter: node({
    mode: 'middleware'
  }),

  security: {
    // Disable checkOrigin to support various Home Lab/Sandbox deployment scenarios 
    // where the site URL is not pre-defined at build time.
    checkOrigin: false,
  },

  vite: {
    plugins: [tailwindcss()],
    // __ALLOW_SKIP_AUTH__ is a build-time constant, not a runtime env var - it's `false` in any
    // normal build (including the Containerfile's plain `npm run build`, which is what the real
    // published image and both production/Sandbox deployments run), so the PHAROS_SKIP_AUTH
    // bypass in src/middleware.ts is provably unreachable in that build. Set it only when
    // explicitly building a throwaway artifact for local E2E testing:
    // `ALLOW_SKIP_AUTH=true npm run build`.
    define: {
      __ALLOW_SKIP_AUTH__: JSON.stringify(process.env.ALLOW_SKIP_AUTH === 'true'),
    },
  }
});