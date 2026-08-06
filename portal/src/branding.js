const DEFAULT_BRANDING = {
  name: 'Kenning Software',
  title: 'Kenning Trusted Agent',
  primary_color: '',
  logo_url: '',
}

function validColor(value) {
  return /^#[0-9a-f]{6}$/i.test(String(value || '')) ? String(value) : ''
}

export function deploymentBranding() {
  return window.__KENNING_BRANDING__ || DEFAULT_BRANDING
}

export async function loadDeploymentBranding() {
  try {
    const response = await fetch('/branding.json', { cache: 'no-store' })
    if (!response.ok) return
    const payload = await response.json()
    if (!payload || typeof payload !== 'object') return
    const branding = {
      name: typeof payload.name === 'string' && payload.name.trim() ? payload.name.trim() : DEFAULT_BRANDING.name,
      title: typeof payload.title === 'string' && payload.title.trim() ? payload.title.trim() : DEFAULT_BRANDING.title,
      primary_color: validColor(payload.primary_color),
      logo_url: typeof payload.logo_url === 'string' && /^https:\/\/[^\s]+$/i.test(payload.logo_url) ? payload.logo_url : '',
    }
    window.__KENNING_BRANDING__ = branding
    if (branding.primary_color) {
      document.documentElement.style.setProperty('--brand-primary', branding.primary_color)
      document.documentElement.style.setProperty('--brand-accent', branding.primary_color)
    }
    window.dispatchEvent(new Event('kenning:branding'))
  } catch {
    // The default brand is safe when a deployment has not published branding.json yet.
  }
}
