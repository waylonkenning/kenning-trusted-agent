import { defineConfig, devices } from '@playwright/test'

const portalUrl = process.env.E2E_PORTAL_URL || 'http://127.0.0.1:5199/app'
const parsedWorkers = process.env.PLAYWRIGHT_WORKERS ? Number.parseInt(process.env.PLAYWRIGHT_WORKERS, 10) : undefined
const configuredWorkers = Number.isInteger(parsedWorkers) && parsedWorkers > 0 ? parsedWorkers : undefined

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  // Each worker owns a disposable tenant and PAT set. Keep tests in a worker
  // serial because entitlement-changing tests share that worker's tenant.
  workers: configuredWorkers ?? (process.env.CI ? 4 : undefined),
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['line'], ['html', { open: 'never' }]] : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: portalUrl,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    ...devices['Desktop Chrome'],
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
