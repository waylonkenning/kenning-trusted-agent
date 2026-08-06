import test from "node:test"
import assert from "node:assert/strict"
import { handler } from "../app/citation_fetcher.mjs"

// A public IP literal passes publicTarget without any real DNS network I/O
// (getaddrinfo returns a numeric IP directly), letting us exercise the fetch,
// redirect, and byte-limit paths with a mocked global fetch.
const PUBLIC_URL = "http://93.184.216.34/doc"

function mockFetch(responses) {
  const realFetch = globalThis.fetch
  const calls = []
  let index = 0
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options })
    const next = Array.isArray(responses) ? responses[Math.min(index, responses.length - 1)] : responses
    index += 1
    const value = typeof next === "function" ? next(String(url)) : next
    if (value instanceof Error) throw value
    return value
  }
  return {
    calls,
    restore() {
      globalThis.fetch = realFetch
    },
  }
}

function htmlResponse(body, status = 200, headers = {}) {
  return new Response(Buffer.from(body), {
    status,
    headers: { "content-type": "text/html; charset=utf-8", ...headers },
  })
}

test("rejects empty and over-long URLs before any fetch", async () => {
  const empty = await handler({})
  assert.equal(empty.retrieval_status, "transport_error")
  assert.match(empty.error, /bounded HTTP or HTTPS URL/i)

  const tooLong = await handler({ url: `http://example.org/${"a".repeat(9000)}` })
  assert.equal(tooLong.retrieval_status, "transport_error")
  assert.match(tooLong.error, /bounded HTTP or HTTPS URL/i)
})

test("rejects invalid and non-HTTP schemes", async () => {
  const invalid = await handler({ url: "not a url" })
  assert.equal(invalid.retrieval_status, "transport_error")
  assert.match(invalid.error, /invalid/i)

  const ftp = await handler({ url: "ftp://example.org/file" })
  assert.equal(ftp.retrieval_status, "transport_error")
  assert.match(ftp.error, /Only HTTP and HTTPS/i)
})

test("blocks private IPv4 literals before DNS or fetch", async () => {
  for (const host of ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "172.16.0.1", "0.0.0.0", "224.0.0.1"]) {
    const result = await handler({ url: `http://${host}/` })
    assert.equal(result.retrieval_status, "transport_error", `expected ${host} to be blocked`)
    assert.match(result.error, /Private source IP addresses are not allowed/i)
  }
})

test("blocks private IPv6 literals (fail-closed via DNS)", async () => {
  // URL hostnames keep IPv6 brackets, so isIP() does not match and the explicit
  // private-IP short-circuit is bypassed; the request must still fail closed.
  for (const host of ["[::1]", "[fd00::1]", "[fe80::1]", "[::ffff:127.0.0.1]"]) {
    const result = await handler({ url: `http://${host}/` })
    assert.equal(result.retrieval_status, "transport_error", `expected ${host} to be blocked`)
  }
})

test("blocks localhost and internal hostnames before DNS", async () => {
  for (const url of ["http://localhost/", "http://app.localhost/", "http://db.internal/"]) {
    const result = await handler({ url })
    assert.equal(result.retrieval_status, "transport_error", `expected ${url} to be blocked`)
    assert.match(result.error, /Private and internal source hosts are not allowed/i)
  }
})

test("rejects URLs that embed credentials", async () => {
  const result = await handler({ url: "http://user:secret@93.184.216.34/" })
  assert.equal(result.retrieval_status, "transport_error")
  assert.match(result.error, /credential-free HTTP and HTTPS/i)
})

test("fetches a public source and returns a bounded base64 body", async () => {
  const mock = mockFetch(htmlResponse("hello world"))
  try {
    const result = await handler({ url: PUBLIC_URL })
    assert.equal(result.retrieval_status, "success")
    assert.equal(result.status_code, 200)
    assert.equal(result.final_url, PUBLIC_URL)
    assert.match(result.content_type, /text\/html/)
    assert.equal(result.truncated, false)
    assert.equal(Buffer.from(result.body_base64, "base64").toString(), "hello world")
    assert.equal(mock.calls.length, 1)
  } finally {
    mock.restore()
  }
})

test("reports HTTP error statuses without a body", async () => {
  const mock = mockFetch(htmlResponse("missing", 404))
  try {
    const result = await handler({ url: PUBLIC_URL })
    assert.equal(result.retrieval_status, "http_error")
    assert.equal(result.status_code, 404)
    assert.match(result.error, /HTTP 404/)
    assert.equal(result.body_base64, undefined)
  } finally {
    mock.restore()
  }
})

test("follows redirects to a public destination and re-validates each hop", async () => {
  const mock = mockFetch([
    htmlResponse("", 301, { location: "http://93.184.216.34/final" }),
    htmlResponse("landed"),
  ])
  try {
    const result = await handler({ url: PUBLIC_URL })
    assert.equal(result.retrieval_status, "success")
    assert.equal(result.final_url, "http://93.184.216.34/final")
    assert.equal(Buffer.from(result.body_base64, "base64").toString(), "landed")
    assert.equal(mock.calls.length, 2)
  } finally {
    mock.restore()
  }
})

test("blocks a redirect that targets a private address", async () => {
  const mock = mockFetch(htmlResponse("", 302, { location: "http://169.254.169.254/latest/meta-data/" }))
  try {
    const result = await handler({ url: PUBLIC_URL })
    assert.equal(result.retrieval_status, "transport_error")
    assert.match(result.error, /Private source IP addresses are not allowed/i)
  } finally {
    mock.restore()
  }
})

test("bounds redirect chains and surfaces the final unredirected response", async () => {
  const mock = mockFetch(htmlResponse("", 302, { location: PUBLIC_URL }))
  try {
    const result = await handler({ url: PUBLIC_URL })
    // After MAX_REDIRECTS (5) hops the loop stops following; the trailing 3xx is
    // returned as an http_error rather than looping forever.
    assert.equal(result.retrieval_status, "http_error")
    assert.equal(result.status_code, 302)
    assert.equal(mock.calls.length, 6)
  } finally {
    mock.restore()
  }
})

test("truncates bodies larger than the bounded maximum", async () => {
  const mock = mockFetch(htmlResponse("x".repeat(5000)))
  try {
    const result = await handler({ url: PUBLIC_URL, max_source_bytes: 1024 })
    assert.equal(result.retrieval_status, "success")
    assert.equal(result.truncated, true)
    assert.equal(Buffer.from(result.body_base64, "base64").length, 1024)
  } finally {
    mock.restore()
  }
})

test("maps an aborted fetch to a timeout error", async () => {
  const abort = new Error("aborted")
  abort.name = "AbortError"
  const mock = mockFetch(abort)
  try {
    const result = await handler({ url: PUBLIC_URL })
    assert.equal(result.retrieval_status, "transport_error")
    assert.match(result.error, /timed out/i)
  } finally {
    mock.restore()
  }
})
