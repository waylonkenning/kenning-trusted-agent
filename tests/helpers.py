"""Shared test helpers for the in-process Lambda test suite.

These helpers build Lambda proxy events and standard auth headers so that
tests do not repeat the same boilerplate. The event shape matches the
``lambda_handler`` proxy contract used across ``test_tenant_api.py`` and the
``_route`` helper: ``rawPath``, ``requestContext.http.method``, ``headers``,
an optional JSON ``body``, and optional ``queryStringParameters``.

The helpers only build data. They do not call the service. Tests still patch
``service.authenticate`` or call ``service.handle_*`` directly as before.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Iterable


# Default bearer token used by the in-process route tests. The real token
# value does not matter because tests patch ``service.authenticate``.
DEFAULT_BEARER_TOKEN = "kta_pat_test"


def make_event(
    method: str,
    path: str,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    auth: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a Lambda proxy event dict for ``lambda_handler``.

    ``method`` is the HTTP verb. ``path`` is the raw route path. ``body`` is
    encoded as JSON when it is not ``None``. ``headers`` and ``auth`` are
    merged into the event headers; pass the result of ``auth_headers`` as
    ``auth`` for a standard authenticated request. ``query`` maps to
    ``queryStringParameters``.
    """
    merged_headers: dict[str, str] = {}
    if headers:
        merged_headers.update(headers)
    if auth:
        merged_headers.update(auth)

    event: dict[str, Any] = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "headers": merged_headers,
    }
    if body is not None:
        event["body"] = json.dumps(body)
    if query:
        event["queryStringParameters"] = query
    return event


def auth_headers(
    tenant_id: str,
    subject: str,
    scopes: Iterable[str] | None = None,
    token: str = DEFAULT_BEARER_TOKEN,
) -> dict[str, str]:
    """Build standard auth headers for an authenticated proxy event.

    The header names match the ones ``service.authenticate`` reads:
    ``Authorization`` for the bearer token and ``X-Kenning-Tenant-Id`` for the
    tenant hint. ``subject`` and ``scopes`` are carried in ``X-Kenning-*``
    headers so tests can assert on the presented principal. Header casing is
    not significant because the service lowercases keys before lookup.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Kenning-Tenant-Id": tenant_id,
        "X-Kenning-Subject": subject,
    }
    if scopes is not None:
        headers["X-Kenning-Scopes"] = ",".join(scopes)
    return headers


def wait_for(
    predicate: Callable[[], Any],
    timeout: float = 10,
    interval: float = 0.1,
) -> Any:
    """Poll ``predicate`` until it returns a truthy value or time runs out.

    This replaces sleep-polling loops. ``predicate`` takes no arguments. The
    truthy result is returned. If no truthy result appears before ``timeout``
    seconds, raise ``AssertionError``.
    """
    deadline = time.monotonic() + timeout
    while True:
        result = predicate()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition was not met within {timeout} seconds"
            )
        time.sleep(interval)
