import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'

export const stateFile = process.env.PLAYWRIGHT_STATE_FILE || path.join(os.tmpdir(), 'kenning-playwright-e2e-state.json')

export function readState() {
  if (!fs.existsSync(stateFile)) {
    throw new Error(`Playwright fixture state is missing: ${stateFile}`)
  }
  return JSON.parse(fs.readFileSync(stateFile, 'utf8'))
}
