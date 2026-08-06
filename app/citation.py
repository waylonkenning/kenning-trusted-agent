"""Explainable Citation Trust verification for agent responses."""

from __future__ import annotations

import email.utils
import fnmatch
import hashlib
import hmac
import html
import http.client
import os
import re
import socket
import time
import urllib.robotparser
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable


URL_PATTERN = re.compile(r"https?://[^\s<>\]\)\"']+", re.IGNORECASE)
MARKDOWN_URL_PATTERN = re.compile(r"\[[^\]]+\]\((https?://[^)]+)\)", re.IGNORECASE)
DOCUMENT_PATTERN = re.compile(r"\b[\w./-]+\.(?:pdf|docx?|xlsx?|csv|pptx?)\b", re.IGNORECASE)
IDENTIFIER_PATTERN = re.compile(r"\b[A-Z]{2,}[\w-]*/\d[\w./-]*\b")
TOKEN_PATTERN = re.compile(r"\d+(?:\.\d+)?|[a-z][a-z0-9'_-]*", re.IGNORECASE)
STOP_WORDS = {"a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "is", "of", "on", "or", "that", "the", "to", "was", "with"}
CITATION_QUALITY_RANK = {"low-quality": 0, "unknown": 1, "secondary": 1, "primary": 2, "authoritative": 3}
SECONDARY_HOSTS = {"medium.com", "substack.com", "wikipedia.org"}
SECONDARY_PATH_MARKERS = ("/article", "/analysis", "/blog", "/commentary", "/news", "/opinion")
BIBLIOGRAPHIC_RESOLVER_HOSTS = {"doi.org", "dx.doi.org", "handle.net", "hdl.handle.net"}
CLAIM_TYPE_POLICY_FIELDS = {"minimum_source_quality", "max_age_days", "require_currency"}
MAX_CLAIM_TYPE_POLICIES = 50
MAX_CLAIM_TYPE_LENGTH = 64
DEFAULT_CITATION_POLICY = {
    "allowed_domains": [],
    "blocked_domains": [],
    "trusted_domains": [],
    "require_https": False,
    "allow_inline_source_text": True,
    "respect_robots": True,
    "robots_fail_closed": False,
    "max_citations": 20,
    "max_source_bytes": 1_000_000,
    "max_age_days": 365,
    "minimum_source_quality": "unknown",
    "require_currency": False,
    "claim_type_policies": {},
}
REFERENCE_TYPES = {
    "document": "documents",
    "identifier": "identifiers",
    "footnote": "footnotes",
}
MAX_REFERENCE_SOURCES = 100


def _string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array.")
    if len(value) > 100:
        raise ValueError(f"{field} may contain at most 100 values.")
    result = [str(item).strip().lower().rstrip(".") for item in value if str(item).strip()]
    if any("/" in item or ":" in item or " " in item for item in result):
        raise ValueError(f"{field} must contain host names or wildcard host patterns, not URLs.")
    if len(set(result)) != len(result):
        raise ValueError(f"{field} must not contain duplicates.")
    return result


def _normalise_max_age_days(value: Any, field: str) -> int | None:
    try:
        max_age_days = int(value) if value is not None else None
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer or null.") from exc
    if max_age_days is not None and (max_age_days < 1 or max_age_days > 3650):
        raise ValueError(f"{field} must be between 1 and 3650 or null.")
    return max_age_days


def _normalise_claim_type_policies(value: Any) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("citation_policy.claim_type_policies must be an object.")
    if len(value) > MAX_CLAIM_TYPE_POLICIES:
        raise ValueError(f"citation_policy.claim_type_policies may contain at most {MAX_CLAIM_TYPE_POLICIES} claim types.")

    result: dict[str, dict[str, Any]] = {}
    for raw_claim_type, raw_override in value.items():
        claim_type = str(raw_claim_type or "").strip().lower()
        if not claim_type or len(claim_type) > MAX_CLAIM_TYPE_LENGTH or not re.fullmatch(r"[a-z0-9][a-z0-9 _.-]*", claim_type):
            raise ValueError(f"citation_policy.claim_type_policies keys must be simple claim type names up to {MAX_CLAIM_TYPE_LENGTH} characters.")
        if not isinstance(raw_override, dict):
            raise ValueError(f"citation_policy.claim_type_policies.{claim_type} must be an object.")
        unsupported = set(raw_override) - CLAIM_TYPE_POLICY_FIELDS
        if unsupported:
            raise ValueError(
                f"citation_policy.claim_type_policies.{claim_type} contains unsupported fields: {', '.join(sorted(unsupported))}."
            )
        override: dict[str, Any] = {}
        if "minimum_source_quality" in raw_override:
            minimum_quality = str(raw_override.get("minimum_source_quality") or "").lower()
            if minimum_quality not in CITATION_QUALITY_RANK:
                raise ValueError(
                    f"citation_policy.claim_type_policies.{claim_type}.minimum_source_quality must be low-quality, unknown, secondary, primary, or authoritative."
                )
            override["minimum_source_quality"] = minimum_quality
        if "max_age_days" in raw_override:
            override["max_age_days"] = _normalise_max_age_days(
                raw_override.get("max_age_days"),
                f"citation_policy.claim_type_policies.{claim_type}.max_age_days",
            )
        if "require_currency" in raw_override:
            require_currency = raw_override.get("require_currency")
            if not isinstance(require_currency, bool):
                raise ValueError(f"citation_policy.claim_type_policies.{claim_type}.require_currency must be a boolean.")
            override["require_currency"] = require_currency
        result[claim_type] = override
    return result


def normalise_citation_policy(value: Any = None) -> dict[str, Any]:
    """Validate tenant controls for source retrieval and citation thresholds."""

    if value is None:
        return dict(DEFAULT_CITATION_POLICY)
    if not isinstance(value, dict):
        raise ValueError("citation_policy must be an object.")
    require_https = value.get("require_https", DEFAULT_CITATION_POLICY["require_https"])
    allow_inline = value.get("allow_inline_source_text", DEFAULT_CITATION_POLICY["allow_inline_source_text"])
    require_currency = value.get("require_currency", DEFAULT_CITATION_POLICY["require_currency"])
    respect_robots = value.get("respect_robots", DEFAULT_CITATION_POLICY["respect_robots"])
    robots_fail_closed = value.get("robots_fail_closed", DEFAULT_CITATION_POLICY["robots_fail_closed"])
    if not all(isinstance(item, bool) for item in (require_https, allow_inline, respect_robots, robots_fail_closed, require_currency)):
        raise ValueError("citation_policy boolean fields must be booleans.")
    max_citations = value.get("max_citations", DEFAULT_CITATION_POLICY["max_citations"])
    max_source_bytes = value.get("max_source_bytes", DEFAULT_CITATION_POLICY["max_source_bytes"])
    max_age_days = value.get("max_age_days", DEFAULT_CITATION_POLICY["max_age_days"])
    try:
        max_citations = int(max_citations)
        max_source_bytes = int(max_source_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("citation_policy numeric fields must be integers.") from exc
    if max_citations < 1 or max_citations > 100:
        raise ValueError("citation_policy.max_citations must be between 1 and 100.")
    if max_source_bytes < 4096 or max_source_bytes > 10_000_000:
        raise ValueError("citation_policy.max_source_bytes must be between 4096 and 10000000.")
    max_age_days = _normalise_max_age_days(max_age_days, "citation_policy.max_age_days")
    minimum_quality = str(value.get("minimum_source_quality") or DEFAULT_CITATION_POLICY["minimum_source_quality"]).lower()
    if minimum_quality not in CITATION_QUALITY_RANK:
        raise ValueError("citation_policy.minimum_source_quality must be low-quality, unknown, secondary, primary, or authoritative.")
    return {
        "allowed_domains": _string_list(value.get("allowed_domains"), "citation_policy.allowed_domains"),
        "blocked_domains": _string_list(value.get("blocked_domains"), "citation_policy.blocked_domains"),
        "trusted_domains": _string_list(value.get("trusted_domains"), "citation_policy.trusted_domains"),
        "require_https": require_https,
        "allow_inline_source_text": allow_inline,
        "respect_robots": respect_robots,
        "robots_fail_closed": robots_fail_closed,
        "max_citations": max_citations,
        "max_source_bytes": max_source_bytes,
        "max_age_days": max_age_days,
        "minimum_source_quality": minimum_quality,
        "require_currency": require_currency,
        "claim_type_policies": _normalise_claim_type_policies(value.get("claim_type_policies")),
    }


def citation_policy_summary(value: Any = None) -> dict[str, Any]:
    policy = normalise_citation_policy(value)
    return dict(policy)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def extract_citations(response_text: str) -> dict[str, list[str]]:
    """Extract URLs, document references, identifiers, and footnote markers."""

    response_text = str(response_text or "")
    urls: list[str] = []
    for candidate in MARKDOWN_URL_PATTERN.findall(response_text) + URL_PATTERN.findall(response_text):
        cleaned = candidate.rstrip(".,;:!?])}")
        if cleaned not in urls:
            urls.append(cleaned)
    documents = list(dict.fromkeys(DOCUMENT_PATTERN.findall(response_text)))
    identifiers = list(dict.fromkeys(IDENTIFIER_PATTERN.findall(response_text)))
    footnotes = list(dict.fromkeys(re.findall(r"\[(\d+)\]", response_text)))
    return {"urls": urls, "documents": documents, "identifiers": identifiers, "footnotes": footnotes}


def _host(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "").lower().rstrip(".")


def _tokens(value: str) -> set[str]:
    return {token.lower() for token in TOKEN_PATTERN.findall(str(value or "")) if token.lower() not in STOP_WORDS}


def _numeric_tokens(value: str) -> list[str]:
    return [token.lower() for token in TOKEN_PATTERN.findall(str(value or "")) if token[:1].isdigit()]


def _numeric_sequence_in_source(claim: str, source_text: str) -> bool:
    """Require a claim's numeric values to occur together in one source context."""

    claim_numbers = _numeric_tokens(claim)
    if not claim_numbers:
        return True
    segments = re.split(r"(?<=[.!?])\s+", source_text)
    for segment in segments:
        source_numbers = _numeric_tokens(segment)
        width = len(claim_numbers)
        if any(source_numbers[index : index + width] == claim_numbers for index in range(len(source_numbers) - width + 1)):
            return True
    return False


def _entailment(claim: str, source_text: str) -> tuple[bool | None, float, str]:
    if not claim:
        return None, 0.5, "No claim was supplied for comparison."
    claim_text = " ".join(str(claim).lower().split())
    source_text = " ".join(str(source_text or "").lower().split())
    if not source_text:
        return False, 0.0, "The source returned no text that could be compared with the claim."
    if claim_text in source_text:
        return True, 0.98, "The complete claim phrase appears in the retrieved source text."

    claim_tokens = _tokens(claim)
    source_tokens = _tokens(source_text)
    if not claim_tokens:
        return None, 0.5, "The claim has no comparable content words."
    numeric_tokens = set(_numeric_tokens(claim))
    missing_numbers = numeric_tokens - source_tokens
    overlap = claim_tokens & source_tokens
    ratio = len(overlap) / len(claim_tokens)
    if missing_numbers or not _numeric_sequence_in_source(claim, source_text):
        return False, min(ratio, 0.35), "The source does not contain the claim's numeric values in the same context."
    if ratio >= 0.75:
        return True, min(0.9, 0.55 + ratio * 0.4), "Most claim terms are present in the source text."
    if ratio >= 0.45:
        return False, 0.45 + ratio * 0.2, "The source discusses related terms but does not clearly support the full claim."
    return False, max(0.05, ratio), "The source does not contain enough of the claim's terms to support it."


def _source_quality(url: str, trusted_domains: list[str] | None = None) -> tuple[str, float]:
    """Classify source quality using host authority and URL provenance signals.

    Government and intergovernmental hosts are authoritative; educational or
    clearly official data/policy paths are primary; known publishing platforms
    and article/blog/analysis paths are secondary; unclassified hosts remain
    unknown. This is a transparent baseline, not a claim that URL heuristics
    establish objective truth.
    """

    host = _host(url)
    path = urllib.parse.urlparse(url).path.lower()
    if _domain_matches(host, trusted_domains or []):
        return "primary", 1.0
    if host.endswith((".gov", ".govt.nz", ".gov.uk", ".gc.ca", ".gouv.fr")) or host in {"who.int", "un.org"}:
        return "authoritative", 1.0
    if host.endswith((".edu", ".ac.nz", ".ac.uk")):
        return "primary", 0.9
    if any(marker in path for marker in ("/official", "/policy", "/report", "/data", "/legislation")):
        return "primary", 0.8
    if host in SECONDARY_HOSTS or host.startswith("news.") or any(marker in path for marker in SECONDARY_PATH_MARKERS):
        return "secondary", 0.55
    if host:
        return "unknown", 0.5
    return "low-quality", 0.1


def _source_score(exists: Any, accessible: Any, authenticity: Any) -> int:
    """Score whether the cited source itself was successfully verified.

    Source score intentionally excludes source quality, freshness, and claim
    entailment. Those are separate findings so a tenant can distinguish a
    real source from a source that actually supports the cited claim.
    """

    return round(
        (
            float(bool(exists))
            + float(bool(accessible))
            + float(bool(authenticity))
        )
        / 3
        * 100
    )


def _claim_support_score(supports_claim: bool | None, entailment_score: float) -> int:
    """Score only claim-to-source support, not source quality or retrieval."""

    if supports_claim is not True:
        return 0
    return round(max(0.0, min(1.0, float(entailment_score))) * 100)


def _metadata_terms(value: Any) -> set[str]:
    value = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", str(value or ""))
    value = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", value)
    value = re.sub(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", " ", value)
    return {
        token.lower()
        for token in _tokens(str(value or ""))
        if token.lower() not in STOP_WORDS and len(token) > 2
    }


def _verify_reference_metadata(metadata: dict[str, Any], source_text: str) -> tuple[bool | None, int | None, dict[str, bool], str]:
    """Compare parsed bibliography metadata with retrieved source text."""

    source = " ".join(str(source_text or "").lower().split())
    checks: dict[str, bool] = {}
    for field in ("title", "authors", "year", "publisher"):
        expected = str(metadata.get(field) or "").strip()
        if not expected:
            continue
        if field == "year":
            checks[field] = expected.lower() in source
            continue
        terms = _metadata_terms(expected)
        if not terms:
            continue
        present = _metadata_terms(source)
        checks[field] = expected.lower() in source or len(terms & present) / len(terms) >= 0.7
    if not checks:
        return False, 0, {}, "No comparable bibliography metadata was extracted."
    score = round(sum(checks.values()) / len(checks) * 100)
    if all(checks.values()):
        return True, score, checks, "Bibliography metadata matches the retrieved source."
    failed = ", ".join(field for field, matched in checks.items() if not matched)
    return False, score, checks, f"Bibliography metadata did not match the retrieved source: {failed}."


def _redirect_authenticity(requested_url: str, final_url: str) -> bool:
    """Accept safe resolver redirects without treating them as source spoofing."""

    requested_host = _host(requested_url)
    final_host = _host(final_url)
    if not requested_host or not final_host:
        return False
    if requested_host == final_host:
        return True
    # DOI and Handle URLs are identifiers whose normal behavior is to redirect
    # to the publisher or repository landing page. The redirect destination is
    # still checked for HTTPS/HTTP validity and source content separately.
    if requested_host in BIBLIOGRAPHIC_RESOLVER_HOSTS:
        return True
    if requested_host.removeprefix("www.") == final_host.removeprefix("www."):
        return True
    return False


def _html_metadata_text(source_html: str) -> str:
    """Extract bounded bibliographic hints from HTML head metadata."""

    values: list[str] = []
    title = re.search(r"<title\b[^>]*>(.*?)</title>", source_html, re.IGNORECASE | re.DOTALL)
    if title:
        values.append(title.group(1))
    accepted_names = {"citation_title", "citation_author", "citation_publication_date", "citation_publisher", "dc.title", "dc.creator", "dcterms.title", "author", "publisher", "og:title"}
    for match in re.finditer(r"<meta\b[^>]*>", source_html, re.IGNORECASE | re.DOTALL):
        tag = match.group(0)
        name = re.search(r"\b(?:name|property)=[\"'](.*?)[\"']", tag, re.IGNORECASE | re.DOTALL)
        if not name or name.group(1).lower() not in accepted_names:
            continue
        content = re.search(r"\bcontent=[\"'](.*?)[\"']", tag, re.IGNORECASE | re.DOTALL)
        if content:
            values.append(content.group(1))
    return " ".join(html.unescape(value) for value in values)


def _pdf_metadata_text(source_bytes: bytes) -> str:
    """Extract standard PDF Info/XMP fields without parsing document content."""

    decoded = bytes(source_bytes or b"")[:2_000_000].decode("latin-1", errors="ignore")
    values: list[str] = []
    for field in ("Title", "Author", "Subject"):
        match = re.search(rf"/{field}\s*\(([^)]{{1,512}})\)", decoded, re.IGNORECASE)
        if match:
            values.append(match.group(1))
    for field in ("title", "creator", "description"):
        match = re.search(rf"<dc:{field}[^>]*>.*?<rdf:li[^>]*>(.*?)</rdf:li>", decoded, re.IGNORECASE | re.DOTALL)
        if match:
            values.append(match.group(1))
    return " ".join(html.unescape(value) for value in values)


def _currency(headers: dict[str, str], supplied_date: str | None = None, max_age_days: int | None = 365) -> tuple[str, float, str | None]:
    value = supplied_date or headers.get("last-modified")
    if not value:
        return "unknown", 0.5, None
    try:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            # HTTP Last-Modified values use RFC 7231 dates such as
            # "Fri, 17 Jul 2026 19:57:31 GMT". Do not use a substring check
            # for ISO detection: the "T" in "GMT" would misclassify them.
            parsed = email.utils.parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age_days = max(0, (datetime.now(timezone.utc) - parsed).days)
    except (TypeError, ValueError, OverflowError):
        return "unknown", 0.5, value
    if max_age_days is None or age_days <= max_age_days:
        return "recent", 1.0, value
    return "stale", 0.25, value


# Use a product identifier by default, but allow a deployment to select a
# browser-compatible user agent when a source's bot policy treats clients
# differently. This changes request identity only; it does not bypass source
# authentication, authorization, or TLS validation.
DEFAULT_CITATION_USER_AGENT = "Kenning-Citation-Trust/0.1"
ROBOTS_USER_AGENT = os.environ.get("CITATION_USER_AGENT", DEFAULT_CITATION_USER_AGENT).strip() or DEFAULT_CITATION_USER_AGENT
SOURCE_ACCEPT_HEADER = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
SOURCE_BROWSER_USER_AGENTS = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
)
TRANSIENT_SOURCE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
DEFAULT_SOURCE_RETRY_ATTEMPTS = 3
MAX_SOURCE_RETRY_ATTEMPTS = 4
DEFAULT_SOURCE_FETCH_BUDGET_SECONDS = 12.0
MAX_SOURCE_FETCH_BUDGET_SECONDS = 30.0
SOURCE_REMOTE_RETRIEVER: Callable[..., dict[str, Any]] | None = None


def set_source_remote_retriever(retriever: Callable[..., dict[str, Any]] | None) -> None:
    """Register an optional bounded transport fallback for server deployments."""

    global SOURCE_REMOTE_RETRIEVER
    SOURCE_REMOTE_RETRIEVER = retriever


def _bounded_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _source_retry_attempts() -> int:
    try:
        configured = int(os.environ.get("CITATION_FETCH_RETRY_ATTEMPTS", DEFAULT_SOURCE_RETRY_ATTEMPTS))
    except (TypeError, ValueError):
        configured = DEFAULT_SOURCE_RETRY_ATTEMPTS
    return max(1, min(MAX_SOURCE_RETRY_ATTEMPTS, configured))


def _source_fetch_budget(timeout: int) -> float:
    configured = _bounded_float(
        os.environ.get("CITATION_FETCH_BUDGET_SECONDS"),
        DEFAULT_SOURCE_FETCH_BUDGET_SECONDS,
        1.0,
        MAX_SOURCE_FETCH_BUDGET_SECONDS,
    )
    return min(configured, max(1.0, float(timeout) * _source_retry_attempts()))


def _source_user_agents() -> list[str]:
    """Return the configured identity followed by bounded browser fallbacks."""

    return list(dict.fromkeys([ROBOTS_USER_AGENT, *SOURCE_BROWSER_USER_AGENTS]))


def _source_request_headers(user_agent: str) -> dict[str, str]:
    return {
        "User-Agent": user_agent,
        "Accept": SOURCE_ACCEPT_HEADER,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }


def _source_payload_result(
    requested_url: str,
    payload: dict[str, Any],
    max_source_bytes: int,
    robots: dict[str, Any],
    attempts: list[dict[str, Any]],
    strategy: str,
    attempt_number: int = 1,
) -> dict[str, Any]:
    """Parse a fetched byte payload into the common citation source shape."""

    raw = bytes(payload.get("raw_bytes") or b"")[: int(max_source_bytes)]
    status_code = int(payload.get("status_code") or 0)
    final_url = str(payload.get("final_url") or requested_url)
    content_type = str(payload.get("content_type") or "")
    charset = str(payload.get("charset") or "utf-8")
    decoded = raw.decode(charset, errors="replace")
    if "html" in content_type.lower() or final_url.lower().endswith(('.html', '.htm')):
        source_metadata_text = _html_metadata_text(decoded)
        text = re.sub(r"<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>", " ", decoded, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", text)
    elif "pdf" in content_type.lower() or final_url.lower().endswith(".pdf"):
        source_metadata_text = _pdf_metadata_text(raw)
        text = decoded
    else:
        source_metadata_text = ""
        text = decoded
    text = re.sub(r"\s+", " ", text).strip()
    return {
        "exists": True,
        "accessible": True,
        "authenticity": _redirect_authenticity(requested_url, final_url),
        "status_code": status_code,
        "final_url": final_url,
        "content_type": content_type,
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "text": text,
        "source_metadata_text": source_metadata_text,
        "headers": {str(key).lower(): str(value) for key, value in (payload.get("headers") or {}).items()},
        "truncated": bool(payload.get("truncated")),
        "robots_allowed": bool(robots["allowed"]),
        "robots_status": robots["status"],
        "robots_url": robots.get("robots_url"),
        "retrieval_status": "success",
        "retrieval_attempts": attempt_number,
        "retrieval_strategy": str(payload.get("retrieval_strategy") or strategy),
        "retrieval_via": str(payload.get("retrieval_via") or "") or None,
        "retrieval_diagnostics": attempts,
    }


def _transport_error(error: BaseException) -> str:
    reason = getattr(error, "reason", None)
    if reason:
        return str(reason)
    return str(error) or type(error).__name__


def _is_transient_source_error(error: BaseException) -> bool:
    return isinstance(
        error,
        (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
            ConnectionError,
            OSError,
            http.client.RemoteDisconnected,
        ),
    )


def _robots_decision(url: str, timeout: int = 8, opener: Callable[..., Any] = urllib.request.urlopen) -> dict[str, Any]:
    """Return a bounded robots.txt decision for one source URL."""

    parsed = urllib.parse.urlparse(url)
    robots_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
    request = urllib.request.Request(robots_url, headers={"User-Agent": ROBOTS_USER_AGENT, "Accept": "text/plain"})
    try:
        with opener(request, timeout=timeout) as robots:
            raw = robots.read(262_145)
            if len(raw) > 262_144:
                return {"allowed": False, "status": "too_large", "robots_url": robots_url, "error": "robots.txt exceeded the response limit."}
            parser = urllib.robotparser.RobotFileParser()
            parser.set_url(robots_url)
            parser.parse(raw.decode("utf-8", errors="replace").splitlines())
            allowed = parser.can_fetch(ROBOTS_USER_AGENT, url)
            return {
                "allowed": bool(allowed),
                "status": "allowed" if allowed else "blocked",
                "robots_url": robots_url,
            }
    except urllib.error.HTTPError as error:
        if error.code in {404, 410}:
            return {"allowed": True, "status": "not_found", "robots_url": robots_url}
        if error.code in {401, 403}:
            # A protected or intentionally inaccessible robots endpoint does not
            # provide a valid crawl directive. Treat it as unavailable so the
            # tenant's robots_fail_closed policy decides whether retrieval may
            # continue. This avoids turning a robots endpoint's access control
            # into an accidental source-content denial by default.
            return {"allowed": True, "status": "unavailable", "robots_url": robots_url, "error": f"robots.txt returned HTTP {error.code}."}
        return {"allowed": True, "status": "unavailable", "robots_url": robots_url, "error": f"robots.txt returned HTTP {error.code}."}
    except (urllib.error.URLError, TimeoutError, ValueError):
        return {"allowed": True, "status": "unavailable", "robots_url": robots_url, "error": "robots.txt could not be retrieved."}


def retrieve_source(
    url: str,
    timeout: int = 8,
    max_source_bytes: int = 1_000_000,
    respect_robots: bool = True,
    robots_fail_closed: bool = False,
) -> dict[str, Any]:
    """Retrieve a source with bounded retries, browser fallbacks, and diagnostics."""

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"exists": False, "accessible": False, "authenticity": False, "error": "Only HTTP and HTTPS URLs are supported."}
    retry_attempts = _source_retry_attempts()
    fetch_budget = _source_fetch_budget(timeout)
    deadline = time.monotonic() + fetch_budget
    robots = {"allowed": True, "status": "disabled", "robots_url": None}
    if respect_robots:
        # Reserve part of the bounded budget for the source request itself.
        robots_timeout = min(float(timeout), max(1.0, fetch_budget / 3))
        robots = _robots_decision(url, timeout=int(robots_timeout))
        if not robots["allowed"] or (robots["status"] == "unavailable" and robots_fail_closed):
            return {
                "exists": False,
                "accessible": False,
                "authenticity": True,
                "final_url": url,
                "robots_allowed": False,
                "robots_status": robots["status"],
                "robots_url": robots.get("robots_url"),
                "retrieval_status": "policy_blocked",
                "retrieval_attempts": 0,
                "error": robots.get("error") or "Source retrieval is disallowed by robots.txt.",
            }
    attempts: list[dict[str, Any]] = []
    last_http_error: dict[str, Any] | None = None
    last_transport_error = ""
    user_agents = _source_user_agents()

    # Lambda's Python HTTPS stack can encounter edge/CDN transport behavior
    # that a browser-compatible Node fetch handles correctly. Keep this
    # internal fallback bounded and feed its bytes through the same parser and
    # robots/policy checks as the direct path.
    remote_retriever = SOURCE_REMOTE_RETRIEVER
    if remote_retriever is not None:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            try:
                remote_payload = remote_retriever(
                    url,
                    int(max_source_bytes),
                    max(1.0, min(float(timeout), remaining)),
                    user_agents[0],
                )
            except Exception as error:
                remote_payload = {"retrieval_status": "transport_error", "error": _transport_error(error)}
            remote_status = int(remote_payload.get("status_code") or 0)
            remote_strategy = str(remote_payload.get("retrieval_strategy") or "node_fetcher")
            if remote_payload.get("retrieval_status") == "success" and 200 <= remote_status < 300:
                return _source_payload_result(
                    url,
                    remote_payload,
                    max_source_bytes,
                    robots,
                    [{"attempt": 1, "strategy": remote_strategy, "status_code": remote_status}],
                    "node_fetcher",
                )
            remote_diagnostic = {
                "attempt": 1,
                "strategy": remote_strategy,
                "status_code": remote_status or None,
                "error": str(remote_payload.get("error") or "Remote source fetch failed")[:512],
            }
            attempts.append(remote_diagnostic)
            last_transport_error = str(remote_payload.get("error") or "Remote source fetch failed")
            if remote_payload.get("retrieval_status") == "http_error":
                last_http_error = {
                    "exists": remote_status != 404,
                    "accessible": False,
                    "authenticity": _redirect_authenticity(url, str(remote_payload.get("final_url") or url)),
                    "status_code": remote_status,
                    "final_url": str(remote_payload.get("final_url") or url),
                    "robots_allowed": bool(robots["allowed"]),
                    "robots_status": robots["status"],
                    "robots_url": robots.get("robots_url"),
                    "retrieval_status": "http_error",
                    "error": str(remote_payload.get("error") or f"Source returned HTTP {remote_status}."),
                }
                if remote_status not in TRANSIENT_SOURCE_STATUS_CODES | {403}:
                    return last_http_error

    for attempt_number in range(1, retry_attempts + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        attempts_remaining = retry_attempts - attempt_number + 1
        attempt_timeout = max(1.0, min(float(timeout), remaining / attempts_remaining))
        user_agent = user_agents[(attempt_number - 1) % len(user_agents)]
        request = urllib.request.Request(url, headers=_source_request_headers(user_agent))
        try:
            with urllib.request.urlopen(request, timeout=attempt_timeout) as source:
                raw = source.read(int(max_source_bytes) + 1)
                content_type = str(source.headers.get("content-type") or "")
                charset = source.headers.get_content_charset() or "utf-8"
                final_url = str(source.geturl())
                status_code = int(source.status)
                if not 200 <= status_code < 300 and status_code not in TRANSIENT_SOURCE_STATUS_CODES | {403}:
                    return {
                        "exists": status_code != 404,
                        "accessible": False,
                        "authenticity": _redirect_authenticity(url, final_url),
                        "status_code": status_code,
                        "final_url": final_url,
                        "robots_allowed": bool(robots["allowed"]),
                        "robots_status": robots["status"],
                        "robots_url": robots.get("robots_url"),
                        "retrieval_status": "http_error",
                        "retrieval_attempts": attempt_number,
                        "retrieval_diagnostics": attempts,
                        "error": f"Source returned HTTP {status_code}.",
                    }
                if 200 <= status_code < 300:
                    return _source_payload_result(
                        url,
                        {
                            "raw_bytes": raw,
                            "status_code": status_code,
                            "final_url": final_url,
                            "content_type": content_type,
                            "headers": dict(source.headers.items()),
                            "charset": charset,
                            "truncated": len(raw) > int(max_source_bytes),
                        },
                        max_source_bytes,
                        robots,
                        attempts,
                        "direct" if attempt_number == 1 and not attempts else "browser_fallback",
                        len(attempts) + 1,
                    )
                attempts.append({"attempt": attempt_number, "status_code": status_code, "user_agent": user_agent})
                last_http_error = {
                    "exists": status_code != 404,
                    "accessible": False,
                    "authenticity": _redirect_authenticity(url, final_url),
                    "status_code": status_code,
                    "final_url": final_url,
                    "robots_allowed": bool(robots["allowed"]),
                    "robots_status": robots["status"],
                    "robots_url": robots.get("robots_url"),
                    "retrieval_status": "http_error",
                    "error": f"Source returned HTTP {status_code}.",
                }
        except urllib.error.HTTPError as error:
            status_code = int(error.code)
            final_url = str(error.geturl())
            attempts.append({"attempt": attempt_number, "status_code": status_code, "user_agent": user_agent})
            last_http_error = {
                "exists": status_code != 404,
                "accessible": False,
                "authenticity": _redirect_authenticity(url, final_url),
                "status_code": status_code,
                "final_url": final_url,
                "robots_allowed": bool(robots["allowed"]),
                "robots_status": robots["status"],
                "robots_url": robots.get("robots_url"),
                "retrieval_status": "http_error",
                "error": f"Source returned HTTP {status_code}.",
            }
            if status_code not in TRANSIENT_SOURCE_STATUS_CODES | {403}:
                break
        except Exception as error:
            if not _is_transient_source_error(error):
                return {
                    "exists": False,
                    "accessible": False,
                    "authenticity": False,
                    "robots_allowed": bool(robots["allowed"]),
                    "robots_status": robots["status"],
                    "robots_url": robots.get("robots_url"),
                    "retrieval_status": "transport_error",
                    "retrieval_attempts": attempt_number,
                    "retrieval_diagnostics": attempts,
                    "error": _transport_error(error),
                }
            last_transport_error = _transport_error(error)
            attempts.append({"attempt": attempt_number, "error": last_transport_error, "user_agent": user_agent})

        remaining = deadline - time.monotonic()
        if attempt_number < retry_attempts and remaining > 0:
            time.sleep(min(0.25 * (2 ** (attempt_number - 1)), max(0.0, remaining - 0.01)))

    if last_http_error:
        last_http_error["retrieval_attempts"] = len(attempts)
        last_http_error["retrieval_diagnostics"] = attempts
        return last_http_error
    return {
        "exists": False,
        "accessible": False,
        "authenticity": False,
        "robots_allowed": bool(robots["allowed"]),
        "robots_status": robots["status"],
        "robots_url": robots.get("robots_url"),
        "retrieval_status": "transport_error",
        "retrieval_attempts": len(attempts),
        "retrieval_diagnostics": attempts,
        "error": last_transport_error or "Source fetch budget exhausted before a response was received.",
    }


def _domain_matches(host: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(host, pattern) for pattern in patterns)


def _source_allowed(url: str, policy: dict[str, Any]) -> tuple[bool, str | None]:
    parsed = urllib.parse.urlparse(url)
    scheme = str(parsed.scheme or "").lower()
    host = _host(url)
    if policy.get("require_https") and scheme != "https":
        return False, "The tenant citation policy requires HTTPS sources."
    if _domain_matches(host, policy.get("blocked_domains") or []):
        return False, "The source domain is blocked by the tenant citation policy."
    allowed = policy.get("allowed_domains") or []
    if allowed and not _domain_matches(host, allowed):
        return False, "The source domain is not allowlisted by the tenant citation policy."
    return True, None


def _claim_type(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalise_reference_sources(value: Any) -> dict[tuple[str, str], dict[str, Any]]:
    """Index caller-provided source metadata for extracted non-URL references."""

    if value is None:
        return {}
    if not isinstance(value, list):
        raise ValueError("reference_sources must be an array.")
    if len(value) > MAX_REFERENCE_SOURCES:
        raise ValueError(f"reference_sources may contain at most {MAX_REFERENCE_SOURCES} values.")
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"reference_sources item {index + 1} must be an object.")
        reference_type = str(raw.get("type") or "document").strip().lower()
        if reference_type not in REFERENCE_TYPES:
            raise ValueError("reference_sources.type must be document, identifier, or footnote.")
        reference = str(raw.get("reference") or raw.get("id") or raw.get("name") or "").strip()
        if not reference or len(reference) > 256:
            raise ValueError("reference_sources.reference is required and must be no longer than 256 characters.")
        key = (reference_type, reference)
        if key in indexed:
            raise ValueError(f"reference_sources contains a duplicate {reference_type} reference: {reference}.")
        indexed[key] = {
            "type": reference_type,
            "reference": reference,
            "source_url": str(raw.get("source_url") or raw.get("url") or "").strip(),
            "claim": str(raw.get("claim") or ""),
            "source_text": raw.get("source_text"),
            "source_hash": str(raw.get("source_hash") or "").strip(),
        }
    return indexed


def _verify_reference(
    reference_type: str,
    reference: str,
    source: dict[str, Any] | None,
    policy: dict[str, Any],
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "type": reference_type,
        "reference": reference,
        "resolved": bool(source),
        "verified": False,
        "source_verified": False,
        "source_score": 0,
        "claim_support_score": 0,
        "exists": False,
        "accessible": False,
        "authenticity": False,
        "supports_claim": None,
        "confidence": 0.0,
    }
    if not source:
        finding["reason"] = "No source metadata was supplied for this extracted reference."
        return finding

    source_url = str(source.get("source_url") or "")
    if source_url:
        citation = {
            "url": source_url,
            "claim": source.get("claim") or reference,
            "source_hash": source.get("source_hash") or None,
        }
        if source.get("source_text") is not None:
            citation["source_text"] = source["source_text"]
        checked = verify_citation(citation, policy=policy)
        finding.update(
            {
                "exists": checked.get("exists", False),
                "accessible": checked.get("accessible", False),
                "authenticity": checked.get("authenticity", False),
                "source_verified": checked.get("source_verified", False),
                "source_score": checked.get("source_score", 0),
                "claim_support_score": checked.get("claim_support_score", 0),
                "supports_claim": checked.get("supports_claim"),
                "confidence": checked.get("confidence", 0.0),
                "verified": bool(
                    checked.get("exists")
                    and checked.get("accessible")
                    and checked.get("authenticity")
                    and checked.get("supports_claim") is not False
                    and not checked.get("retrieval_blocked")
                ),
                "citation": checked,
            }
        )
        if not finding["verified"]:
            finding["reason"] = checked.get("reason") or "The reference source could not be fully verified."
        return finding

    source_text = source.get("source_text")
    source_hash = str(source.get("source_hash") or "").strip().lower()
    if source_text is not None and source_hash:
        if source_hash.startswith("sha256:"):
            source_hash = source_hash.removeprefix("sha256:")
        actual_hash = hashlib.sha256(str(source_text).encode("utf-8")).hexdigest()
        hash_matches = bool(re.fullmatch(r"[0-9a-f]{64}", source_hash)) and hmac.compare_digest(source_hash, actual_hash)
        supports, entailment_score, entailment_reason = _entailment(str(source.get("claim") or reference), str(source_text))
        finding.update(
            {
                "exists": True,
                "accessible": True,
                "authenticity": hash_matches,
                "source_verified": hash_matches,
                "source_score": _source_score(True, True, hash_matches),
                "supports_claim": supports,
                "claim_support_score": _claim_support_score(supports, entailment_score),
                "confidence": round(_claim_support_score(supports, entailment_score) / 100, 3),
                "content_sha256": actual_hash,
                "source_hash_verified": hash_matches,
                "verified": bool(hash_matches and supports is not False),
            }
        )
        if not finding["verified"]:
            finding["reason"] = "The supplied reference content could not be authenticated or did not support its claim."
        return finding

    finding["exists"] = True
    finding["reason"] = "Reference metadata was supplied, but a source_url or source_text plus source_hash is required for verification."
    return finding


def _effective_policy(policy: dict[str, Any], citation: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    claim_type = _claim_type(citation.get("claim_type") or citation.get("claim_category"))
    overrides = policy.get("claim_type_policies") if isinstance(policy.get("claim_type_policies"), dict) else {}
    override = overrides.get(claim_type) if claim_type else None
    effective = dict(policy)
    if isinstance(override, dict):
        effective.update(override)
    return claim_type, effective


def verify_citation(
    citation: dict[str, Any],
    retriever: Callable[[str], dict[str, Any]] = retrieve_source,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = str(citation.get("url") or citation.get("source") or "").strip()
    claim = str(citation.get("claim") or "")
    policy = normalise_citation_policy(policy)
    claim_type, effective_policy = _effective_policy(policy, citation)
    result: dict[str, Any] = {
        "url": url,
        "claim": claim,
        "claim_type": claim_type or None,
        "exists": False,
        "accessible": False,
        "authenticity": False,
        "supports_claim": None,
        "source_quality": "unknown",
        "currency": "unknown",
        "source_verified": False,
        "source_score": 0,
        "claim_support_score": 0,
        "confidence": 0.0,
        "claim_support_required": citation.get("claim_support_required", True) is not False,
        "verification_scope": "claim_support" if citation.get("claim_support_required", True) is not False else "source_only",
        "reference_verified": None,
        "reference_metadata_score": None,
        "reference_metadata_findings": {},
        "source_hash_verified": None,
        "source_quality_acceptable": False,
        "currency_acceptable": not effective_policy["require_currency"],
        "policy_scope": {
            "claim_type": claim_type or None,
            "minimum_source_quality": effective_policy["minimum_source_quality"],
            "max_age_days": effective_policy["max_age_days"],
            "require_currency": effective_policy["require_currency"],
        },
    }
    if not url:
        result.update({"source_quality": "low-quality", "reason": "No source URL was supplied."})
        return result

    allowed, restriction_reason = _source_allowed(url, effective_policy)
    if not allowed:
        result.update({"retrieval_blocked": True, "reason": restriction_reason})
        return result
    use_inline = bool(citation.get("source_text")) and policy["allow_inline_source_text"]
    if use_inline:
        inline_text = str(citation.get("source_text"))[: effective_policy["max_source_bytes"]]
        source = {
            "exists": True,
            "accessible": True,
            "authenticity": True,
            "status_code": 200,
            "final_url": url,
            "content_sha256": hashlib.sha256(inline_text.encode("utf-8")).hexdigest(),
            "text": inline_text,
            "headers": {},
            "robots_allowed": True,
            "robots_status": "inline",
            "truncated": len(str(citation.get("source_text"))) > effective_policy["max_source_bytes"],
        }
    elif retriever is retrieve_source:
        source = retrieve_source(
            url,
            max_source_bytes=effective_policy["max_source_bytes"],
            respect_robots=effective_policy["respect_robots"],
            robots_fail_closed=effective_policy["robots_fail_closed"],
        )
    else:
        source = retriever(url)
    result.update({
        key: source.get(key)
        for key in (
            "exists",
            "accessible",
            "authenticity",
            "status_code",
            "final_url",
            "truncated",
            "robots_allowed",
            "robots_status",
            "robots_url",
            "content_sha256",
            "source_metadata_text",
            "retrieval_status",
            "retrieval_attempts",
            "retrieval_strategy",
            "retrieval_via",
            "retrieval_diagnostics",
        )
        if key in source
    })
    result["source_score"] = _source_score(result.get("exists"), result.get("accessible"), result.get("authenticity"))
    result["source_verified"] = result["source_score"] == 100
    if source.get("robots_allowed") is False:
        result.update(
            {
                "retrieval_blocked": True,
                "supports_claim": None,
                "confidence": 0.0,
                "reason": source.get("error") or "Source retrieval is disallowed by robots.txt.",
            }
        )
        return result
    final_url = str(source.get("final_url") or url)
    final_allowed, final_restriction_reason = _source_allowed(final_url, effective_policy)
    if not final_allowed:
        result.update(
            {
                "retrieval_blocked": True,
                "supports_claim": None,
                "confidence": 0.0,
                "reason": final_restriction_reason,
            }
        )
        return result
    quality, _quality_score = _source_quality(final_url, effective_policy.get("trusted_domains"))
    result["source_quality"] = quality
    result["source_quality_acceptable"] = CITATION_QUALITY_RANK.get(quality, 0) >= CITATION_QUALITY_RANK[effective_policy["minimum_source_quality"]]
    if not source.get("exists") or not source.get("accessible"):
        # A source that could not be retrieved provides no evidence for the
        # claim. Do not award partial confidence for unknown currency or source
        # quality in this case; those dimensions are unknowable until content
        # is successfully retrieved.
        result.update(
            {
                "supports_claim": False if result["claim_support_required"] else None,
                "confidence": 0.0,
                "reason": source.get("error") or "The cited source could not be retrieved.",
            }
        )
        return result
    expected_hash = str(citation.get("source_hash") or citation.get("content_sha256") or "").strip().lower()
    if expected_hash:
        if expected_hash.startswith("sha256:"):
            expected_hash = expected_hash.removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            result.update(
                {
                    "source_hash_verified": False,
                    "authenticity": False,
                    "reason": "The supplied source_hash is not a SHA-256 digest.",
                }
            )
            return result
        actual_hash = str(source.get("content_sha256") or "").lower()
        result["source_hash_verified"] = bool(actual_hash) and hmac.compare_digest(expected_hash, actual_hash)
        if not result["source_hash_verified"]:
            result.update(
                {
                    "authenticity": False,
                    "reason": "The retrieved source content does not match the cited SHA-256 digest.",
                }
            )
    reference_metadata = citation.get("reference_metadata")
    if isinstance(reference_metadata, dict):
        reference_verified, reference_score, reference_findings, reference_reason = _verify_reference_metadata(
            reference_metadata,
            " ".join(
                value
                for value in (str(source.get("text") or ""), str(source.get("source_metadata_text") or ""))
                if value
            ),
        )
        result.update(
            {
                "reference_verified": reference_verified,
                "reference_metadata_score": reference_score,
                "reference_metadata_findings": reference_findings,
            }
        )
    else:
        reference_reason = ""
    if result["claim_support_required"]:
        result["supports_claim"], entailment_score, entailment_reason = _entailment(claim, str(source.get("text") or ""))
    else:
        result["supports_claim"] = None
        entailment_score = 0.0
        entailment_reason = "Claim support is not applicable to this source-only citation."
    result["currency"], _currency_score, published_at = _currency(
        source.get("headers") or {}, citation.get("published_at"), effective_policy["max_age_days"]
    )
    result["currency_acceptable"] = result["currency"] != "stale" and (
        result["currency"] != "unknown" or not effective_policy["require_currency"]
    )
    if published_at:
        result["published_at"] = published_at
    result["source_score"] = _source_score(result.get("exists"), result.get("accessible"), result.get("authenticity"))
    result["source_verified"] = result["source_score"] == 100
    result["claim_support_score"] = _claim_support_score(result["supports_claim"], entailment_score)
    result["confidence"] = round(result["claim_support_score"] / 100, 3)
    result["reason"] = source.get("error") or reference_reason or entailment_reason
    if result.get("source_hash_verified") is False and result.get("reason"):
        result["reason"] = "The retrieved source content does not match the cited SHA-256 digest."
    elif not result["source_quality_acceptable"]:
        result["reason"] = f"Source quality '{quality}' is below the tenant minimum '{effective_policy['minimum_source_quality']}'."
    elif not result["currency_acceptable"]:
        result["reason"] = "The source does not meet the tenant currency requirement."
    return result


def _overall_status(
    score: int,
    citations: list[dict[str, Any]],
    reference_findings: list[dict[str, Any]] | None = None,
) -> str:
    reference_findings = reference_findings or []
    if not citations and not reference_findings:
        return "warning"
    unresolved_references = [item for item in reference_findings if not item.get("verified")]
    if unresolved_references:
        return "warning" if score >= 50 else "fail"
    if any(item.get("reference_verified") is False for item in citations):
        return "warning" if score >= 50 else "fail"
    if score >= 80 and all(
        item.get("exists")
        and item.get("accessible")
        and item.get("authenticity")
        and item.get("reference_verified") is not False
        and not item.get("retrieval_blocked")
        and item.get("supports_claim") is not False
        and item.get("source_quality_acceptable", True)
        and item.get("currency_acceptable", True)
        for item in citations
    ):
        return "pass"
    if any(item.get("supports_claim") is False and item.get("source_verified") for item in citations):
        return "warning"
    if score >= 50:
        return "warning"
    return "fail"


def verify_response(payload: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Verify all cited sources in an agent response and return a trust score."""

    policy = normalise_citation_policy(policy)
    response_text = str(payload.get("response") or payload.get("answer") or payload.get("text") or "")
    extracted = extract_citations(response_text)
    supplied = payload.get("citations")
    citations: list[dict[str, Any]] = []
    if isinstance(supplied, list):
        for item in supplied:
            citations.append(item if isinstance(item, dict) else {"url": str(item)})
    elif extracted["urls"]:
        citations = [{"url": url} for url in extracted["urls"]]

    findings = [verify_citation(item, policy=policy) for item in citations[: policy["max_citations"]]]
    reference_sources = _normalise_reference_sources(payload.get("reference_sources"))
    reference_findings = [
        _verify_reference(reference_type, reference, reference_sources.get((reference_type, reference)), policy)
        for reference_type, field in REFERENCE_TYPES.items()
        for reference in extracted[field]
    ]
    score_inputs = []
    for item in findings:
        if item.get("claim_support_required", True) is False:
            # A bibliography URL has two independent checks: the URL/source
            # and the bibliographic record supplied by the report. A metadata
            # mismatch must lower the score even when the URL itself resolves.
            if item.get("reference_verified") is not None:
                source_score = float(item.get("source_score") or 0.0)
                metadata_score = float(item.get("reference_metadata_score") or 0.0)
                score_inputs.append(min(source_score, metadata_score) / 100)
            else:
                score_inputs.append(float(item.get("source_score") or 0.0) / 100)
        else:
            score_inputs.append(float(item.get("confidence") or 0.0))
    score_inputs.extend(float(item.get("confidence") or 0.0) for item in reference_findings)
    score = round(sum(score_inputs) / len(score_inputs) * 100) if score_inputs else 0
    return {
        "status": _overall_status(score, findings, reference_findings),
        "trust_score": score,
        "citations": findings,
        "reference_findings": reference_findings,
        "extracted_references": extracted,
        "checked_at": utc_now(),
        "summary": f"Verified {len(findings)} citation(s) and {len(reference_findings)} extracted reference(s); {sum(1 for item in findings if item.get('supports_claim') is True)} citations support their associated claims.",
        "citation_policy": citation_policy_summary(policy),
    }
