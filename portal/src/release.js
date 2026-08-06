/**
 * User-facing release identity compiled into the immutable web artifact.
 * The development pipeline supplies these values for every candidate.
 */

const environment = import.meta.env || {}

export const RELEASE = Object.freeze({
  id: environment.VITE_KENNING_RELEASE_ID || 'local',
  name: environment.VITE_KENNING_RELEASE_NAME || 'Ahipara',
  version: environment.VITE_KENNING_RELEASE_VERSION || '0.1.0-local',
  changelogPath: '/CHANGELOG.md',
})
