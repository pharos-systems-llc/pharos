/* ========================================================================
 * Project: pharos
 * Component: Web Console
 * File: pharos-console-web/playwright.config.ts
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * E2E test configuration for Playwright. Enables automated browser
 * testing of the Web Console inside the Podman test environment.
 * * Traceability:
 * Related to Phase 17 Sandbox verification.
 * ======================================================================== */
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests-e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'https://localhost:3000',
    trace: 'on-first-retry',
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // NOTE: running E2E locally requires building the console with the E2E-only bypass compiled
  // in first - the plain `npm run build` used for real deployments does NOT include it:
  //   ALLOW_SKIP_AUTH=true npm run build && npm run test:e2e
  // See src/middleware.ts and astro.config.mjs for why.
  webServer: [
    {
      command: 'PHAROS_SANDBOX=true PHAROS_SERVER_URL=https://127.0.0.1:2378 PHAROS_HOST=127.0.0.1 PHAROS_PORT=2378 HOST=0.0.0.0 PORT=3000 node test-server.mjs',
      url: 'https://localhost:3000',
      reuseExistingServer: !process.env.CI,
      timeout: 120 * 1000,
    },
    {
      command: 'PHAROS_SKIP_AUTH=true cargo run --manifest-path ../Cargo.toml --package pharos-server',
      url: 'http://localhost:9090/metrics',
      reuseExistingServer: !process.env.CI,
      timeout: 300 * 1000,
    },
    {
      command: 'PHAROS_SKIP_AUTH=true PHAROS_SERVER=127.0.0.1:2378 PHAROS_MACHINE_NAME=e2e-pharos-main cargo run --manifest-path ../Cargo.toml --package pharos-pulse',
      // No URL to wait for, but it depends on server
      reuseExistingServer: !process.env.CI,
      timeout: 300 * 1000,
    }
  ],
});
