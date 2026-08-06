import fs from 'node:fs'
import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const apiTarget = process.env.KENNING_API_PROXY_TARGET || process.env.E2E_API_URL || 'http://127.0.0.1:3000'
const siteRoot = path.resolve(new URL('.', import.meta.url).pathname)
const openapiPath = path.resolve(siteRoot, '../docs/openapi.json')
const changelogPath = path.resolve(siteRoot, '../CHANGELOG.md')

function localStaticReference() {
  return {
    name: 'local-static-reference',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const pathname = new URL(request.url || '/', 'http://localhost').pathname
        const files = {
          '/openapi.json': { path: openapiPath, type: 'application/json' },
          '/CHANGELOG.md': { path: changelogPath, type: 'text/markdown; charset=utf-8' },
        }[pathname]
        if (!files) return next()
        if (!fs.existsSync(files.path)) {
          response.statusCode = 404
          return response.end('Not found')
        }
        response.statusCode = 200
        response.setHeader('Cache-Control', 'no-store')
        response.setHeader('Content-Type', files.type)
        return response.end(fs.readFileSync(files.path))
      })
    },
  }
}

function localDevelopmentCsp() {
  return {
    name: 'local-development-csp',
    apply: 'serve',
    transformIndexHtml(html) {
      // Vite's React refresh preamble is an inline module in development.
      // Keep the production CSP in index.html and relax only the local
      // development response so the E2E runner exercises the actual app.
      return html.replace("script-src 'self';", "script-src 'self' 'unsafe-inline';")
    },
  }
}

export default defineConfig({
  plugins: [localStaticReference(), localDevelopmentCsp(), react()],
  server: {
    proxy: {
      '/v1': { target: apiTarget, changeOrigin: true, secure: true },
      '/auth': { target: apiTarget, changeOrigin: true, secure: true },
      '/health': { target: apiTarget, changeOrigin: true, secure: true },
      '/mcp': { target: apiTarget, changeOrigin: true, secure: true },
    },
  },
})
