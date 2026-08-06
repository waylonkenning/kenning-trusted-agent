import { test as base } from '@playwright/test'
import { createE2EState } from './global-setup.mjs'
import { cleanupE2EState } from './global-teardown.mjs'

export const test = base.extend({
  e2e: [async ({}, use, workerInfo) => {
    const state = await createE2EState({ workerIndex: workerInfo.workerIndex })
    try {
      await use(state)
    } finally {
      await cleanupE2EState(state)
    }
  }, { scope: 'worker' }],
})

export { expect } from '@playwright/test'
