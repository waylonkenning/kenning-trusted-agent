import React from 'react'
import { DEPLOYMENT_ENVIRONMENT } from '../lib.js'
import { Info, WarningCircle } from '@phosphor-icons/react'

function EnvironmentBanner() {
  if (DEPLOYMENT_ENVIRONMENT === 'production') return <div className="portal-env-banner portal-env-production"><WarningCircle size={15} weight="fill" /> PRODUCTION</div>
  if (DEPLOYMENT_ENVIRONMENT === 'development') return <div className="portal-env-banner portal-env-development"><Info size={15} weight="fill" /> DEVELOPMENT</div>
  if (DEPLOYMENT_ENVIRONMENT) return <div className="portal-env-banner portal-env-other"><Info size={15} weight="fill" /> {DEPLOYMENT_ENVIRONMENT.toUpperCase()}</div>
  return <div className="portal-env-banner portal-env-unknown"><WarningCircle size={15} weight="fill" /> Environment not configured</div>
}


export default EnvironmentBanner
