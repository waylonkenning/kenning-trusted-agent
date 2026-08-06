import { useCallback, useContext, useEffect, useRef, useState } from 'react'
import { PortalContext } from './PortalContext.jsx'
import { request } from './lib.js'

// useApiMutation wraps a write request with busy and error state.
// It returns [mutate, { busy, error }]. mutate(url, opts) sends the request,
// sets busy while it runs, stores any error, and reloads the view on success.
// tenantId and csrf come from PortalContext.
export function useApiMutation() {
  const { tenantId, csrf, load } = useContext(PortalContext)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const mutate = useCallback(async (url, opts = {}, { reload = true, tenantId: tenantOverride } = {}) => {
    setBusy(true)
    setError(null)
    try {
      const result = await request(url, opts, tenantOverride !== undefined ? tenantOverride : tenantId, csrf)
      if (reload && load) await load()
      return result
    } catch (caught) {
      setError(caught)
      throw caught
    } finally {
      setBusy(false)
    }
  }, [tenantId, csrf, load])

  return [mutate, { busy, error, setError }]
}

// useApiQuery loads several paths in parallel, like the portal loadView step.
// paths is a list of [key, url] pairs. It returns { data, loading, error, reload }.
// tenantId comes from PortalContext.
export function useApiQuery(paths, deps = []) {
  const { tenantId } = useContext(PortalContext)
  const [data, setData] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const dataRef = useRef({})
  const reloadSequence = useRef(0)

  const updateData = useCallback((updater) => {
    const next = typeof updater === 'function' ? updater(dataRef.current) : updater
    dataRef.current = next
    setData(next)
  }, [])

  const reload = useCallback(async () => {
    const sequence = reloadSequence.current + 1
    reloadSequence.current = sequence
    setLoading(true)
    setError(null)
    const results = await Promise.allSettled(paths.map(([, path]) => request(path, {}, tenantId)))
    if (sequence !== reloadSequence.current) return
    const next = {}
    const failures = []
    results.forEach((result, index) => {
      const [key] = paths[index]
      if (result.status === 'fulfilled') {
        const current = dataRef.current[key]
        const currentVersion = Number(current?.config_version || 0)
        const nextVersion = Number(result.value?.config_version || 0)
        next[key] = key === 'starterRules' && currentVersion > nextVersion ? current : result.value
      }
      else failures.push(result.reason)
    })
    dataRef.current = next
    setData(next)
    if (failures.length) {
      setError(Object.keys(next).length
        ? new Error('Some workspace data could not be loaded. Retry to refresh this view.')
        : failures[0])
    }
    setLoading(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId, ...deps])

  useEffect(() => { reload() }, [reload])

  return { data, loading, error, reload, updateData }
}
