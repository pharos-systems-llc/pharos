/* ========================================================================
 * Project: pharos
 * Component: Web Console
 * File: vitest.config.ts
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * Vitest configuration for the Pharos Web Console. Enables unit testing
 * of library logic and Astro Actions with happy-dom environment.
 * * Traceability:
 * Related to Task 16.6 (Issue #69).
 * ======================================================================== */

import { defineConfig } from 'vitest/config';

export default defineConfig({
  // Vitest does not read astro.config.mjs's Vite settings - the __ALLOW_SKIP_AUTH__ define needs
  // to be repeated here too, or importing src/middleware.ts under test would throw a
  // ReferenceError. Defaults to false here as well, same as a normal build.
  define: {
    __ALLOW_SKIP_AUTH__: JSON.stringify(process.env.ALLOW_SKIP_AUTH === 'true'),
  },
  test: {
    environment: 'happy-dom',
    globals: true,
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
});
