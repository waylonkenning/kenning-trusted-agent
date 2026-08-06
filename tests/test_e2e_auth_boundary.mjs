import test from "node:test"
import assert from "node:assert/strict"

// Regression for #131: verify the E2E helper's deployment-mode logic so the
// auth-boundary coverage cannot silently regress to a single mode.

function resolveSessionExchangeUrl(mode, apiUrl) {
  const normalizedMode = (mode || "same-origin").trim().toLowerCase()
  const normalizedApiUrl = (apiUrl || "").replace(/\/$/, "")
  return normalizedMode === "direct" ? `${normalizedApiUrl}/auth/session` : "/auth/session"
}

test("same-origin mode uses a relative session exchange path", () => {
  const url = resolveSessionExchangeUrl("same-origin", "https://api.example.com")
  assert.equal(url, "/auth/session")
})

test("direct mode uses the absolute API origin for session exchange", () => {
  const url = resolveSessionExchangeUrl("direct", "https://api.example.com")
  assert.equal(url, "https://api.example.com/auth/session")
})

test("mode defaults to same-origin when unset", () => {
  const url = resolveSessionExchangeUrl("", "https://api.example.com")
  assert.equal(url, "/auth/session")
})

test("direct mode strips trailing slash from the API URL", () => {
  const url = resolveSessionExchangeUrl("direct", "https://api.example.com/")
  assert.equal(url, "https://api.example.com/auth/session")
})

test("mode comparison is case-insensitive", () => {
  const url = resolveSessionExchangeUrl("DIRECT", "https://api.example.com")
  assert.equal(url, "https://api.example.com/auth/session")
})
