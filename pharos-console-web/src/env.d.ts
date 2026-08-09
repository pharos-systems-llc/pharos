/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />

declare namespace App {
    interface Locals {
        session?: import('./features/auth/jwt-logic').UserSession;
    }
}

// Build-time constant set via Vite's `define` (see astro.config.mjs / vitest.config.ts) - gates
// the PHAROS_SKIP_AUTH E2E-testing bypass in src/middleware.ts out of any normal build.
declare const __ALLOW_SKIP_AUTH__: boolean;
