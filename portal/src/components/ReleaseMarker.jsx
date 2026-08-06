import React from 'react'
import { RELEASE } from '../release.js'

export default function ReleaseMarker() {
  return <a
    className="portal-release-link"
    href={RELEASE.changelogPath}
    aria-label={`View changelog for release ${RELEASE.name} ${RELEASE.version}`}
  >
    <span className="portal-release-label">Release</span>
    <strong>{RELEASE.name}</strong>
    <span className="portal-release-version">{RELEASE.version}</span>
  </a>
}
