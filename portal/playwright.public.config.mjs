import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests/public',
  timeout: 30_000,
  forbidOnly: true,
  use: {
    baseURL: 'http://127.0.0.1:5198',
    ...devices['Desktop Chrome'],
  },
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1 --port 5198',
    url: 'http://127.0.0.1:5198',
    reuseExistingServer: !process.env.CI,
  },
})
