#!/bin/bash
# ========================================================================
# Project: pharos
# Component: DevSecOps Automation
# File: scripts/pre-flight.sh
# Author: Richard D. (https://github.com/iamrichardd)
# License: AGPL-3.0 (See LICENSE file for details)
# * Purpose (The "Why"):
# Centralized verification script to be run inside the Podman test container.
# Ensures Rust builds, Astro builds, and Headless E2E tests pass before commit.
# * Traceability:
# Related to Phase 17 Sandbox verification.
# ========================================================================

set -e

# --- 0. Secret Detection ---
echo "--- [0/5] DevSecOps: Gitleaks Scan ---"
# Check if gitleaks is installed
if command -v gitleaks >/dev/null 2>&1; then
    # Run gitleaks detect on the current directory
    # --source .  : scan current directory
    # --no-git    : scan local workspace (uncommitted changes) instead of git history
    # --verbose   : show detail
    # --redact    : mask secrets in output
    gitleaks detect --source=. --no-git --verbose --redact
else
    echo "⚠️ Gitleaks not found. Skipping scan."
fi

# --- 0.5 Dependency Auditing ---
echo "--- [0.5/5] DevSecOps: Cargo Audit Scan ---"
if command -v cargo-audit >/dev/null 2>&1 || cargo help audit >/dev/null 2>&1; then
    # Ignoring known vulnerabilities tracked via issues:
    # RUSTSEC-2024-0437 (protobuf): Tracked as Debt #06 (Issue #147)
    # RUSTSEC-2023-0071 (rsa): Tracked as Bug #148 (Issue #148)
    # RUSTSEC-2025-0134 (rustls-pemfile, unmaintained): Tracked as Debt #64 (Issue #211)
    # RUSTSEC-2024-0436 (paste, unmaintained, transitive via ratatui): Tracked as Debt #65 (Issue #212)
    # RUSTSEC-2026-0002 (lru, unsound IterMut, transitive via ratatui): Tracked as Debt #65 (Issue #212)
    cargo audit --ignore RUSTSEC-2024-0437 --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2025-0134 --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0002
else
    echo "⚠️ cargo-audit not found. Skipping scan."
fi

# --- 1. Rust Verification ---
echo "--- [1/5] Rust: Building and Running Unit Tests ---"
cargo test --verbose
cargo build --package pharos-server
cargo build --package pharos-pulse
cargo build --package pharos-scan
cargo build --package ph
cargo build --package mdb

# --- 2. Marketing Site Verification ---
echo "--- [2/5] Marketing Site: Build ---"
cd website
npm install
npm run build
cd ..

# --- 3. Web Console Verification (Static) ---
echo "--- [3/5] Web Console: Static Analysis & Build ---"
cd pharos-console-web
npm install
npm run check
npm run build
cd ..

# --- 4. Web Console Verification (E2E) ---
echo "--- [4/5] Web Console: Running Playwright E2E Tests ---"
cd pharos-console-web
# Generate fresh ephemeral certs for E2E backend
rm -rf /tmp/e2e-certs
mkdir -p /tmp/e2e-certs
../scripts/gen-sandbox-certs.sh /tmp/e2e-certs
cat /tmp/e2e-certs/root-ca.crt >> /tmp/e2e-certs/pharos-server.crt
export PHAROS_TLS_CERT=/tmp/e2e-certs/pharos-server.crt
export PHAROS_TLS_KEY=/tmp/e2e-certs/pharos-server.key
export PHAROS_CA_CERT=/tmp/e2e-certs/root-ca.crt
export NODE_EXTRA_CA_CERTS=/tmp/e2e-certs/root-ca.crt

# Playwright config handles startup
npx playwright install chromium
npm run test:e2e
cd ..

echo "===================================================="
echo "✅ PRE-FLIGHT SUCCESSFUL: All systems verified."
echo "===================================================="
