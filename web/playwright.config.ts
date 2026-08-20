import { defineConfig } from '@playwright/test'

// Chromium is preinstalled at PLAYWRIGHT_BROWSERS_PATH in some environments,
// but the build there may not match the revision this Playwright version
// expects to download. BKD_E2E_CHROMIUM points at an existing binary in that
// case; otherwise Playwright uses its own.
const executablePath = process.env.BKD_E2E_CHROMIUM || undefined

export default defineConfig({
  testDir: './e2e',
  // Serial and single-worker: each spec file has its own account, and several
  // tests within a file sign in as it. scripts/e2e.sh provisions a fresh
  // instance per run, so the suite is repeatable; running the tests in one
  // file concurrently against one account would not be.
  workers: 1,
  fullyParallel: false,
  reporter: [['list']],
  use: {
    baseURL: process.env.BKD_E2E_URL ?? 'http://127.0.0.1:18500',
    // The export tests read the file the browser saved: an export nobody can
    // open is not an export, and only a real download proves the difference.
    acceptDownloads: true,
    trace: 'retain-on-failure',
    launchOptions: executablePath ? { executablePath } : {},
  },
})
