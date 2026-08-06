import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_TIMEOUT_MS = 12000;
const MAX_SOURCE_BYTES = 1_000_000;
const MAX_URL_LENGTH = 8192;
const MAX_REDIRECTS = 5;

const BROWSER_HEADERS = {
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "identity",
  "cache-control": "no-cache",
  pragma: "no-cache",
  "upgrade-insecure-requests": "1",
  "sec-fetch-dest": "document",
  "sec-fetch-mode": "navigate",
  "sec-fetch-site": "none",
};

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, parsed));
}

function boundedTimeout(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return DEFAULT_TIMEOUT_MS;
  return Math.max(1000, Math.min(MAX_TIMEOUT_MS, Math.round(parsed * 1000)));
}

function safeHeaders(response) {
  const result = {};
  for (const name of ["content-type", "content-length", "last-modified", "etag", "date", "cache-control"]) {
    const value = response.headers.get(name);
    if (value) result[name] = value.slice(0, 512);
  }
  return result;
}

function errorResult(message, statusCode = null) {
  return {
    retrieval_status: "transport_error",
    status_code: statusCode,
    error: String(message || "Source fetch failed").slice(0, 512),
  };
}

function privateAddress(address) {
  const normalized = String(address || "").toLowerCase();
  const version = isIP(normalized);
  if (version === 4) {
    const octets = normalized.split(".").map(Number);
    const first = octets[0];
    const second = octets[1];
    return (
      first === 0 ||
      first === 10 ||
      first === 127 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 192 && second === 0) ||
      (first === 198 && (second === 18 || second === 19)) ||
      (first === 198 && second === 51) ||
      (first === 203 && second === 0) ||
      first >= 224
    );
  }
  if (version === 6) {
    if (normalized === "::" || normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe8")) {
      return true;
    }
    if (normalized.startsWith("ff") || normalized.startsWith("2001:db8")) {
      return true;
    }
    const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return Boolean(mapped && privateAddress(mapped[1]));
  }
  return true;
}

async function publicTarget(targetUrl) {
  const parsed = new URL(targetUrl);
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) {
    throw new Error("Only credential-free HTTP and HTTPS URLs are supported.");
  }
  const hostname = parsed.hostname.toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".internal")) {
    throw new Error("Private and internal source hosts are not allowed.");
  }
  if (isIP(hostname) && privateAddress(hostname)) {
    throw new Error("Private source IP addresses are not allowed.");
  }
  const addresses = await Promise.race([
    lookup(hostname, { all: true, verbatim: true }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("Source DNS lookup timed out.")), 2000)),
  ]);
  if (!Array.isArray(addresses) || addresses.length === 0 || addresses.some((item) => privateAddress(item.address))) {
    throw new Error("Source host resolved to a private or unavailable address.");
  }
  return parsed;
}

async function readBoundedBody(response, maxSourceBytes) {
  const reader = response.body?.getReader?.();
  if (!reader) {
    const bytes = Buffer.from(await response.arrayBuffer());
    return { bytes: bytes.subarray(0, maxSourceBytes), truncated: bytes.length > maxSourceBytes };
  }
  const chunks = [];
  let total = 0;
  const readLimit = maxSourceBytes + 1;
  try {
    while (total < readLimit) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = Buffer.from(next.value);
      chunks.push(chunk);
      total += chunk.length;
      if (total >= readLimit) {
        await reader.cancel();
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = Buffer.concat(chunks);
  return { bytes: bytes.subarray(0, maxSourceBytes), truncated: bytes.length > maxSourceBytes };
}

async function fetchDocument(targetUrl, timeoutMs, userAgent, maxSourceBytes) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let currentUrl = await publicTarget(targetUrl);
    for (let redirect = 0; redirect <= MAX_REDIRECTS; redirect += 1) {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          ...BROWSER_HEADERS,
          "user-agent": userAgent,
        },
      });
      const statusCode = response.status;
      const headers = safeHeaders(response);
      if (statusCode >= 300 && statusCode < 400) {
        const location = response.headers.get("location");
        if (location && redirect < MAX_REDIRECTS) {
          currentUrl = await publicTarget(new URL(location, currentUrl).toString());
          continue;
        }
      }
      const finalUrl = currentUrl.toString();
      if (statusCode < 200 || statusCode >= 300) {
        return {
          retrieval_status: "http_error",
          status_code: statusCode,
          final_url: finalUrl,
          content_type: headers["content-type"] || "",
          headers,
          error: `Source returned HTTP ${statusCode}.`,
        };
      }
      const body = await readBoundedBody(response, maxSourceBytes);
      return {
        retrieval_status: "success",
        status_code: statusCode,
        final_url: finalUrl,
        content_type: headers["content-type"] || "",
        headers,
        truncated: body.truncated,
        body_base64: body.bytes.toString("base64"),
      };
    }
    return errorResult("Source redirect limit exceeded.");
  } catch (error) {
    const message = error?.name === "AbortError" ? "Source fetch timed out." : error?.message || String(error);
    return errorResult(message);
  } finally {
    clearTimeout(timer);
  }
}

export async function handler(event = {}) {
  const url = String(event.url || "").trim();
  if (url.length === 0 || url.length > MAX_URL_LENGTH) {
    return errorResult("A bounded HTTP or HTTPS URL is required.");
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return errorResult("The source URL is invalid.");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
    return errorResult("Only HTTP and HTTPS source URLs are supported.");
  }

  const maxSourceBytes = boundedInteger(event.max_source_bytes, MAX_SOURCE_BYTES, 1024, MAX_SOURCE_BYTES);
  const timeoutMs = boundedTimeout(event.timeout_seconds);
  const userAgent = String(event.user_agent || "Kenning-Citation-Trust/0.1").slice(0, 256);
  return fetchDocument(parsed, timeoutMs, userAgent, maxSourceBytes);
}
