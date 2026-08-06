"""Deterministic report citation extraction for Citation Trust."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit

try:
    from citation import URL_PATTERN
except ImportError:  # pragma: no cover - package import path
    from .citation import URL_PATTERN


MAX_REPORT_TEXT_BYTES = 5_000_000
MAX_REPORT_CITATIONS = 1_000
REFERENCE_MARKER_PATTERN = re.compile(
    r"\b(?P<author>[A-Z][A-Za-z0-9&./'-]*(?:\s+[A-Za-z][A-Za-z0-9&./'-]*){0,10}(?:\s+et\s+al\.)?(?:\s*/\s*[A-Z][A-Za-z0-9&./'-]*)?),?\s*"
    r"\(?\s*(?P<year>(?:19|20)\d{2}|n\.d\.|forthcoming)\s*\[(?P<reference_id>\d{1,3})\]\s*\)?",
)
URL_TRAILING_PUNCTUATION = ".,;:!?)]}"
PDF_URL_SAFE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789-._~:/?#[]@!$&'()*+,;=%"
)


def _classify_citation(url: str, claim: str) -> tuple[str, bool, str]:
    """Classify a report URL before it is sent to claim entailment.

    A report contains more URLs than claim-bearing citations. Bibliography
    entries, licence pages, corrigenda, and chart/data downloads still need
    source verification, but the text surrounding those URLs is not a claim
    that can be compared sentence-by-sentence with the retrieved source.
    """

    parsed = urlsplit(str(url or ""))
    host = parsed.netloc.lower().split("@")[-1].split(":", 1)[0]
    path = parsed.path.lower()
    compact_claim = re.sub(r"\s+", "", str(claim or "").lower())
    normalised_claim = _normalise(claim).lower()

    if host in {"stat.link", "www.stat.link"} or path.endswith((".csv", ".xls", ".xlsx", ".zip")):
        return "data", False, "The URL points to a structured data or StatLink download."

    if (
        "creativecommons.org/" in host + path
        or "corrigenda" in path
        or any(marker in path for marker in ("/license", "/licence", "/terms", "/copyright"))
        or any(marker in compact_claim for marker in ("corrigenda", "creativecommons", "licence", "license"))
    ):
        return "metadata", False, "The URL appears to be licence, corrigenda, or publication metadata."

    if (
        re.match(r"^\d+\s+(?:see|for|available)", normalised_claim)
        or re.search(r"\b(?:for more information,?\s+see|available at|can be found at)\s*\.?(?:$|\s)", normalised_claim)
    ):
        return "reference", False, "The URL appears in a footnote or cross-reference context rather than a claim-bearing sentence."

    bibliography_signals = (
        normalised_claim.rstrip().endswith(", ."),
        bool(re.search(r"\[\d{1,3}\]", normalised_claim)),
        "references" in normalised_claim,
        "accessed on" in normalised_claim,
        "accessedon" in compact_claim,
        "oecd publishing" in normalised_claim or "oecdpublishing" in compact_claim,
        "please cite this publication" in normalised_claim or "pleasecitethispublication" in compact_claim,
        "isbn" in compact_claim,
        bool(re.search(r"\b(?:vol\.?|pp\.?|no\.?)\s*\d", normalised_claim)),
        bool(re.search(r"\b20\d{2}\b", normalised_claim) and (".pdf" in compact_claim or "gartner" in compact_claim)),
    )
    if any(bibliography_signals):
        return "bibliography", False, "The URL appears in a bibliographic reference rather than a claim-bearing sentence."

    if re.match(r"^\**\s*source\s*:", normalised_claim, re.IGNORECASE):
        return "source", False, "The URL appears in a source or footnote attribution rather than a claim-bearing sentence."

    return "claim", True, "The URL appears in ordinary prose; claim-to-source comparison applies."


def _clean_url(value: str) -> str:
    return str(value or "").strip().rstrip(URL_TRAILING_PUNCTUATION)


def _hosted_url(value: str) -> bool:
    return bool(re.match(r"^https?://[^/\s]+(?:/[^\s]*)?$", value, re.IGNORECASE))


def _consume_pdf_url(text: str, start: int) -> int:
    """Find the end of a URL whose PDF text contains layout whitespace.

    PDF.js often inserts spaces around hyphens in long, linked URLs. It can
    also insert a newline after a URL path separator or a trailing hyphen.
    Whitespace is consumed only when the neighbouring characters make it an
    unambiguous URL continuation; ordinary prose after a URL remains intact.
    """

    cursor = start
    while cursor < len(text):
        character = text[cursor]
        if character in PDF_URL_SAFE_CHARS:
            cursor += 1
            continue
        if not character.isspace():
            break

        gap_end = cursor
        while gap_end < len(text) and text[gap_end].isspace():
            gap_end += 1
        previous = text[cursor - 1] if cursor > start else ""
        following = text[gap_end] if gap_end < len(text) else ""

        # PDF.js may render a URL hyphen as `word - word`.
        if following == "-" and gap_end + 1 < len(text):
            cursor = gap_end + 1
            continue
        # A wrapped URL can end one line with `-`, `/`, or a query operator.
        if previous in "-/?#&=" and (following.isalnum() or following in "._~"):
            cursor = gap_end
            continue
        break
    return cursor


def _repair_spaced_url_fragments(text: str) -> str:
    """Reconstruct URLs split by PDF layout whitespace before URL extraction."""

    source = str(text or "")
    output: list[str] = []
    cursor = 0
    for match in re.finditer(r"https?://", source, re.IGNORECASE):
        if match.start() < cursor:
            continue
        output.append(source[cursor : match.start()])
        end = _consume_pdf_url(source, match.start())
        output.append(re.sub(r"\s+", "", source[match.start() : end]))
        cursor = end
    output.append(source[cursor:])
    return "".join(output)


def _join_wrapped_url_lines(text: str) -> str:
    """Join URL fragments split by PDF line wrapping.

    PDF text extraction commonly breaks long URLs at a hyphen or slash. We
    only join a following line when the URL fragment has an unmistakable
    continuation marker; ordinary prose is left untouched.
    """

    lines = str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    output: list[str] = []
    index = 0
    while index < len(lines):
        current = lines[index]
        while index + 1 < len(lines):
            match = re.search(r"https?://[^\s<>\]\)\"']+$", current, re.IGNORECASE)
            if not match or not match.group(0).endswith(("-", "/", "?", "&", "=")):
                break
            next_line = lines[index + 1].strip()
            # A reference URL can be split at a hyphen or slash. Do not join
            # the prose that follows a URL ending in a slash, e.g. the
            # `(accessed on ...)` line in a bibliography entry.
            if (
                not next_line
                or next_line.startswith(("http://", "https://", "(", "["))
                or not re.match(r"^[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]+", next_line)
            ):
                break
            current = current + next_line
            index += 1
        output.append(current)
        index += 1
    return "\n".join(output)


def _page_texts(text: str) -> list[str]:
    pages = _repair_spaced_url_fragments(str(text or "")).split("\f")
    # pdftotext commonly terminates a document with a form-feed. That marker
    # separates the final page from the empty tail; it is not an extra page.
    while len(pages) > 1 and not pages[-1].strip():
        pages.pop()
    return [_join_wrapped_url_lines(page) for page in pages]


def _normalise(value: str) -> str:
    return " ".join(str(value or "").split())


def _url_line_context(page_text: str, url: str) -> str:
    """Return the extracted line containing a URL, if one exists."""

    lowered_url = str(url or "").lower()
    for line in str(page_text or "").splitlines():
        if lowered_url in line.lower():
            return line
    return ""


def _source_footer_context(page_text: str, url: str) -> str:
    """Return source-footer context, including a wrapped footnote line."""

    lines = str(page_text or "").splitlines()
    for index, line in enumerate(lines):
        if str(url or "").lower() not in line.lower():
            continue
        stripped = line.strip()
        if re.match(r"^\**\s*source\s*:", stripped, re.IGNORECASE):
            return line
        if not re.match(r"^\*{1,3}\s*https?://", stripped, re.IGNORECASE):
            continue
        for previous in reversed(lines[max(0, index - 3) : index]):
            if re.match(r"^\**\s*source\s*:", previous.strip(), re.IGNORECASE):
                return f"{previous} {line}"
    return ""


def _claim_context(page_text: str, url: str) -> str:
    source_context = _source_footer_context(page_text, url)
    if source_context:
        context = _normalise(source_context.replace(url, ""))
        if context:
            return context[:1_200]

    line = _url_line_context(page_text, url)
    if line:
        line_context = _normalise(line.replace(url, ""))
        if line_context and len(line_context) >= 24:
            return line_context[:1_200]

    page = _normalise(page_text)
    position = page.lower().find(url.lower())
    if position < 0:
        return f"The report cites {url}."
    sentences = re.split(r"(?<=[.!?])\s+", page)
    offset = 0
    for sentence in sentences:
        end = offset + len(sentence)
        if offset <= position <= end:
            context = _normalise(sentence.replace(url, ""))
            if len(context) >= 24:
                return context[:1_200]
            break
        offset = end + 1
    start = max(0, position - 280)
    end = min(len(page), position + len(url) + 280)
    context = _normalise(page[start:end].replace(url, ""))
    return context[:1_200] or f"The report cites {url}."


def _bibliographic_context(page_text: str, url: str) -> str:
    """Return the complete reference entry containing a bibliography URL."""

    lines = str(page_text or "").splitlines()
    line_index = next((index for index, line in enumerate(lines) if url.lower() in line.lower()), None)
    if line_index is None:
        return ""

    entry_start = line_index
    author_year = re.compile(r"^(?:\[\d{1,3}\]\s*)?.+\((?:19\d{2}|20\d{2}|n\.d\.|forthcoming)\)", re.IGNORECASE)
    for index in range(line_index, max(-1, line_index - 9), -1):
        candidate = lines[index].strip()
        if candidate and author_year.match(candidate):
            entry_start = index
            break
        if candidate.upper() in {"REFERENCES", "BIBLIOGRAPHY", "REFERENCES AND NOTES"}:
            break

    entry_end = min(len(lines), line_index + 4)
    for index in range(line_index + 1, min(len(lines), line_index + 4)):
        candidate = lines[index].strip()
        if re.fullmatch(r"\[\d{1,3}\]", candidate):
            entry_end = index + 1
            break
        if author_year.match(candidate):
            entry_end = index
            break

    entry = _normalise(" ".join(lines[entry_start:entry_end]))
    return entry.replace(url, "").strip()[:1_200]


def _bibliographic_metadata(entry: str, reference_id: str | None = None) -> dict[str, Any]:
    """Extract conservative metadata from a bibliography entry.

    Missing fields remain absent. The verifier must not invent an author or
    title from an ambiguous PDF text fragment.
    """

    text = _normalise(re.sub(r"\[\d{1,3}\]", "", str(entry or ""))).strip(" .")
    metadata: dict[str, Any] = {"entry_text": text}
    if reference_id:
        metadata["reference_id"] = str(reference_id)
    date_match = re.search(r"\((?P<date>19\d{2}|20\d{2}|n\.d\.|forthcoming)\)", text, re.IGNORECASE)
    if date_match:
        metadata["year"] = date_match.group("date").lower()
        author_text = text[: date_match.start()].strip(" ,;:()")
        if author_text:
            metadata["authors"] = author_text

    quoted = re.search(r"[\u201c\"]([^\u201d\"]+)[\u201d\"]", text)
    if quoted:
        metadata["title"] = _normalise(quoted.group(1))
    elif date_match:
        title_start = date_match.end()
        remainder = text[title_start:].lstrip(" ,:)")
        title_end = re.search(r",\s*(?:OECD\s*Publishing|OECD\b|World\s+Bank|Gartner|No\.|Vol\.)", remainder, re.IGNORECASE)
        title = remainder[: title_end.start() if title_end else min(len(remainder), 240)].strip(" ,.")
        if title:
            metadata["title"] = title
    publisher_match = re.search(r"\b(OECD\s*Publishing|Gartner|World\s+Bank|UN(?:ited\s+Nations)?)\b", text, re.IGNORECASE)
    if publisher_match:
        metadata["publisher"] = _normalise(publisher_match.group(1))
    return metadata


def _bibliographic_reference_id(page_text: str, url: str) -> str | None:
    """Find a bracketed bibliography ID adjacent to a URL entry."""

    lines = str(page_text or "").splitlines()
    line_index = next((index for index, line in enumerate(lines) if url.lower() in line.lower()), None)
    if line_index is None:
        return None
    url_line = lines[line_index]
    author_year = re.compile(r"^(?:\[\d{1,3}\]\s*)?.+\((?:19\d{2}|20\d{2}|n\.d\.|forthcoming)\)", re.IGNORECASE)
    entry_start = line_index
    for index in range(line_index, max(-1, line_index - 9), -1):
        candidate = lines[index].strip()
        if candidate and author_year.match(candidate):
            entry_start = index
            break
    entry_match = re.match(r"\s*\[(\d{1,3})\]\s*", lines[entry_start])
    if entry_match:
        return entry_match.group(1)
    after_url = url_line.lower().find(url.lower()) + len(url)
    same_line = re.search(r"\[(\d{1,3})\]", url_line[after_url:])
    if same_line:
        return same_line.group(1)
    for index in range(line_index + 1, min(len(lines), line_index + 4)):
        match = re.fullmatch(r"\s*\[(\d{1,3})\]\s*", lines[index])
        if match:
            return match.group(1)
        if lines[index].strip() and re.match(r"^(?:\[\d{1,3}\]\s*)?.+\((?:19\d{2}|20\d{2}|n\.d\.|forthcoming)\)", lines[index].strip(), re.IGNORECASE):
            break
    return None


def _reference_author_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower().replace("et al.", ""))


def _reference_candidates(
    reference_id: str,
    author: str,
    year: str,
    page_number: int,
    bibliography_by_id: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], str]:
    candidates = list(bibliography_by_id.get(reference_id) or [])
    if not candidates:
        return [], "No bibliography URL was mapped to this reference ID."
    author_key = _reference_author_key(author)
    year_key = str(year or "").lower()
    matching = [
        item
        for item in candidates
        if str(item.get("metadata", {}).get("year") or "").lower() == year_key
        and (
            not author_key
            or author_key in _reference_author_key(item.get("metadata", {}).get("authors"))
            or _reference_author_key(item.get("metadata", {}).get("authors")).startswith(author_key)
        )
    ]
    if matching:
        candidates = matching
    if len(candidates) == 1:
        return candidates, "Reference marker resolved to one bibliography URL."
    # Reference numbers are often reused by separate reference sections. Use
    # document proximity as a deterministic tie-breaker, but expose that the
    # marker was ambiguous so a strict report can require human review if the
    # sections cannot be distinguished from extracted text alone.
    nearest = min(candidates, key=lambda item: abs(int(item.get("page") or 0) - page_number))
    distance = abs(int(nearest.get("page") or 0) - page_number)
    equally_near = [
        item
        for item in candidates
        if abs(int(item.get("page") or 0) - page_number) == distance
    ]
    if len(equally_near) > 1:
        return [], "Reference ID, author, and year map to multiple equally near bibliography URLs."
    return [nearest], "Reference ID was reused; the nearest matching bibliography URL was selected."


def _marker_context(page_text: str, marker_match: re.Match[str]) -> str:
    """Extract the sentence associated with an in-text reference marker."""

    page = _normalise(page_text)
    marker = _normalise(marker_match.group(0))
    position = len(_normalise(page_text[: marker_match.start()]))
    if position >= len(page) or marker.lower() not in page[max(0, position - 2) : position + len(marker) + 2].lower():
        position = page.lower().find(marker.lower())
    if position < 0:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", page)
    offset = 0
    for sentence in sentences:
        end = offset + len(sentence)
        if offset <= position <= end:
            context = REFERENCE_MARKER_PATTERN.sub("", sentence)
            return _normalise(context).strip(" .")[:1_200]
        offset = end + 1
    return ""  # pragma: no cover


def _marker_claim_required(claim: str) -> tuple[bool, str]:
    lowered = _normalise(claim).lower()
    if not lowered:
        return False, "The marker was not associated with a claim-bearing sentence."
    if lowered.startswith(("source:", "note:", "authors’ based on", "authors' based on")):
        return False, "The marker appears in a source or note label rather than a claim-bearing sentence."
    if len(re.findall(r"[a-z][a-z0-9'-]*", lowered)) < 5:
        return False, "The marker context is too short to establish a claim."
    return True, "The marker is associated with a claim-bearing sentence."


def _extract_urls(pages: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for page_number, page in enumerate(pages, start=1):
        for match in URL_PATTERN.finditer(page):
            url = _clean_url(match.group(0))
            if not url or not _hosted_url(url) or url in seen:
                continue
            seen.add(url)
            claim = _claim_context(page, url)
            category, claim_support_required, classification_reason = _classify_citation(url, claim)
            if category == "bibliography":
                claim = _bibliographic_context(page, url) or claim
            findings.append(
                {
                    "citation_id": f"citation-{len(findings) + 1:04d}",
                    "kind": "url",
                    "url": url,
                    "claim": claim,
                    "category": category,
                    "claim_support_required": claim_support_required,
                    "verification_scope": "claim_support" if claim_support_required else "source_only",
                    "classification_reason": classification_reason,
                    "page": page_number,
                    "source_offset": match.start(),
                }
            )
            if len(findings) >= MAX_REPORT_CITATIONS:
                return findings
    return findings


def _extract_bibliographic_references(pages: list[str], citations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    references: list[dict[str, Any]] = []
    by_reference_id: dict[str, list[dict[str, Any]]] = {}
    for citation in citations:
        if citation.get("category") != "bibliography":
            continue
        page_number = int(citation.get("page") or 1)
        page = pages[max(0, page_number - 1)]
        reference_id = _bibliographic_reference_id(page, str(citation.get("url") or ""))
        entry_text = str(citation.get("claim") or "")
        metadata = _bibliographic_metadata(entry_text, reference_id)
        citation["reference_id"] = reference_id
        citation["reference_metadata"] = metadata
        reference = {
            "reference_id": reference_id,
            "citation_id": citation.get("citation_id"),
            "url": citation.get("url"),
            "entry_text": entry_text,
            "metadata": metadata,
            "page": citation.get("page"),
        }
        references.append(reference)
        if reference_id:
            by_reference_id.setdefault(reference_id, []).append(reference)
    return references, by_reference_id


def _extract_reference_markers(
    pages: list[str],
    bibliography_by_id: dict[str, list[dict[str, Any]]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bibliography_by_id = bibliography_by_id or {}
    markers: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for page_number, page in enumerate(pages, start=1):
        for match in REFERENCE_MARKER_PATTERN.finditer(page):
            author = _normalise(match.group("author"))
            year = match.group("year")
            reference_id = match.group("reference_id")
            key = (author.lower(), year, reference_id)
            marker_claim = _marker_context(page, match)
            claim_required, claim_reason = _marker_claim_required(marker_claim)
            matched, resolution_reason = _reference_candidates(reference_id, author, year, page_number, bibliography_by_id)
            reference = matched[0] if matched else None
            if key not in seen:
                seen.add(key)
                markers.append(
                    {
                        "reference_id": reference_id,
                        "author": author,
                        "year": year,
                        "marker": f"{author}, {year}[{reference_id}]",
                        "page": page_number,
                        "citation_id": reference.get("citation_id") if reference else None,
                        "resolved": bool(reference),
                        "claim": marker_claim,
                        "claim_support_required": claim_required if reference else False,
                        "claim_context_reason": claim_reason if reference else resolution_reason,
                        "resolution_reason": resolution_reason,
                    }
                )
            if reference:
                claims.append(
                    {
                        "claim_id": f"reference-claim-{len(claims) + 1:04d}",
                        "reference_id": reference_id,
                        "citation_id": reference.get("citation_id"),
                        "marker": f"{author}, {year}[{reference_id}]",
                        "claim": marker_claim,
                        "claim_support_required": claim_required,
                        "claim_context_reason": claim_reason,
                        "page": page_number,
                    }
                )
    return markers, claims


def extract_report_citations(report_text: str, report_name: str = "") -> dict[str, Any]:
    """Extract report URLs and unresolved bibliographic markers deterministically."""

    text = str(report_text or "")
    text_bytes = text.encode("utf-8")
    if not text.strip():
        raise ValueError("report_text is required.")
    if len(text_bytes) > MAX_REPORT_TEXT_BYTES:
        raise ValueError(f"report_text must not exceed {MAX_REPORT_TEXT_BYTES} bytes.")
    pages = _page_texts(text)
    citations = _extract_urls(pages)
    bibliographic_references, bibliography_by_id = _extract_bibliographic_references(pages, citations)
    markers, reference_claims = _extract_reference_markers(pages, bibliography_by_id)
    category_counts: dict[str, int] = {}
    for citation in citations:
        category = str(citation.get("category") or "claim")
        category_counts[category] = category_counts.get(category, 0) + 1
    claim_candidates = sum(bool(citation.get("claim_support_required")) for citation in citations)
    return {
        "report_id": f"report-{hashlib.sha256(text_bytes).hexdigest()[:16]}",
        "report_name": str(report_name or "uploaded-report")[:256],
        "content_sha256": hashlib.sha256(text_bytes).hexdigest(),
        "page_count": len(pages),
        "citation_count": len(citations),
        "citations": citations,
        "bibliographic_reference_count": len(bibliographic_references),
        "bibliographic_references": bibliographic_references,
        "reference_marker_count": len(markers),
        "reference_markers": markers,
        "reference_claim_count": len(reference_claims),
        "reference_claims": reference_claims,
        "extraction": {
            "method": "deterministic-url-reference-extraction-with-context-classification",
            "complete": len(citations) < MAX_REPORT_CITATIONS,
            "truncated": len(citations) >= MAX_REPORT_CITATIONS,
            "url_citations": len(citations),
            "claim_candidates": claim_candidates,
            "source_only_citations": len(citations) - claim_candidates,
            "citation_categories": category_counts,
            "bibliographic_references": len(bibliographic_references),
            "reference_claims": len(reference_claims),
            "resolved_reference_markers": sum(bool(marker.get("resolved")) for marker in markers),
            "unresolved_reference_markers": sum(not marker.get("resolved") for marker in markers),
        },
    }
