#!/usr/bin/env python3
"""Endpoint coverage audit: cross-reference OpenAPI spec against test files.

Parses docs/openapi.json for the canonical endpoint × method list, scans
tests/ for references, and reports which endpoint × method combinations
have test coverage.

Usage:
    python3 scripts/endpoint_coverage_audit.py                  # report only
    python3 scripts/endpoint_coverage_audit.py --fail-on-missing # CI gate
"""

import argparse
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENAPI_PATH = os.path.join(REPO_ROOT, "docs", "openapi.json")
TESTS_DIR = os.path.join(REPO_ROOT, "tests")

# Methods that appear in the OpenAPI spec
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

# Patterns that indicate a test references an endpoint path
# Matches: rawPath, _route(, _routed(, "path":, path ==, f-string paths
PATH_PATTERNS = [
    re.compile(r'"rawPath"\s*:\s*"([^"]+)"'),
    re.compile(r'_route(?:d)?\s*\(\s*"([^"]+)"'),
    re.compile(r'_route(?:d)?\s*\(\s*f"([^"]+)"'),
    re.compile(r'"path"\s*:\s*"([^"]+)"'),
    re.compile(r'path\s*==\s*"([^"]+)"'),
    re.compile(r'rawPath.*?"(/[^"]+)"'),
    re.compile(r'rawPath.*?f"(/[^"]+)"'),
    re.compile(r'self\.request\(\s*"(/[^"]+)"'),
    re.compile(r'self\.request\(\s*f"(/[^"]+)"'),
    re.compile(r'(?:self\.)?route\(\s*"([^"]+)"'),
    re.compile(r'(?:self\.)?route\(\s*f"([^"]+)"'),
]

# Direct handler function calls that map to endpoints
HANDLER_ENDPOINT_MAP = {
    "handle_revoke_token": ("/v1/tokens/{tokenId}/revoke", "POST"),
    "handle_update_member": ("/v1/tenants/{tenantId}/members/{subject}", "PATCH"),
    "handle_revoke_invitation": ("/v1/tenants/{tenantId}/invitations/{invitationId}/revoke", "POST"),
    "handle_list_grants": ("/v1/grants", "GET"),
    "handle_revoke_grant": ("/v1/grants/{grantId}/revoke", "POST"),
    "handle_revoke_platform_access_grant": ("/v1/platform/access-grants/{grantId}/revoke", "POST"),
    "handle_verify_proof": ("/v1/proofs/{proofId}/verify", "GET"),
    "handle_list_agent_credentials": ("/v1/agents/{agentId}/credentials", "GET"),
    "handle_get_agent_credential": ("/v1/agents/{agentId}/credentials/{credentialId}", "GET"),
    "handle_revoke_agent_credential": ("/v1/agents/{agentId}/credentials/{credentialId}/revoke", "POST"),
}

# Pattern to extract method from _route/_routed positional args: _route("/path", "POST", ...)
ROUTE_METHOD_RE = re.compile(r'_route(?:d)?\s*\(\s*"[^"]+"\s*,\s*"(GET|POST|PUT|PATCH|DELETE)"', re.IGNORECASE)

# Patterns that indicate auth-boundary testing
AUTH_PATTERNS = [
    re.compile(r'401|403|unauthorized|forbidden|no.?auth|missing.?token|invalid.?token|revoked|wrong.?scope|cross.?tenant', re.IGNORECASE),
    re.compile(r'authenticate.*return.*None|auth.*error|auth.*fail', re.IGNORECASE),
    re.compile(r'scopes.*\[\]|scopes.*empty|no.*scope', re.IGNORECASE),
]

# Patterns that indicate error-path testing
ERROR_PATTERNS = [
    re.compile(r'400|404|409|422|500|503', re.IGNORECASE),
    re.compile(r'bad.?request|not.?found|conflict|invalid|error|fail|raise|exception', re.IGNORECASE),
    re.compile(r'assert.*status.*[45]\d\d', re.IGNORECASE),
]


def load_openapi_endpoints():
    """Return a dict of {(path, method): True} from the OpenAPI spec."""
    with open(OPENAPI_PATH) as f:
        spec = json.load(f)
    endpoints = {}
    for path, methods in spec.get("paths", {}).items():
        for method in methods:
            if method.lower() in HTTP_METHODS:
                endpoints[(path, method.upper())] = True
    return endpoints


def normalise_path(path):
    """Normalise a test-referenced path to match OpenAPI parameterised paths.

    /v1/agents/my-agent → /v1/agents/{agentId}
    /v1/tenants/demo/members → /v1/tenants/{tenantId}/members

    Only replaces segments that look like concrete IDs (contain hyphens,
    dots, or are known test values), not sub-resource names like 'evaluate'.
    """
    # Known sub-resource names that should NOT be treated as IDs
    SUB_RESOURCES = {
        "evaluate", "outcome", "revoke", "publish", "reactivate", "simulate",
        "suspend", "test", "decision", "report", "verify", "extract",
        "credentials", "members", "invitations", "environments", "starter-rules",
        "retention", "run", "events", "export", "access-grants", "support",
        "read", "public-key", "confirm", "resend",
        "callback", "config", "login", "logout", "reauth", "session", "csrf",
        "passkeys", "accept", "redeem", "agent-guard", "agent-identity",
        "agent-proof", "citation-trust",
    }

    segments = path.rstrip("/").split("/")
    result = []
    # Map of parent resource → parameter name
    PARAM_NAMES = {
        "tenants": "{tenantId}",
        "agents": "{agentId}",
        "credentials": "{credentialId}",
        "policies": "{policyId}",
        "approvals": "{approvalId}",
        "grants": "{grantId}",
        "consents": "{consentId}",
        "access-grants": "{grantId}",
        "proofs": "{proofId}",
        "actions": "{actionId}",
        "tokens": "{tokenId}",
        "invitations": "{invitationId}",
        "members": "{subject}",
        "environments": "{environmentId}",
        "models": "{modelId}",
        "nonconformities": "{ncId}",
    }

    for i, seg in enumerate(segments):
        parent = segments[i - 1] if i > 0 else ""
        # Already-parameterised segments like {grant_id} from f-strings
        if seg.startswith("{") and seg.endswith("}") and parent in PARAM_NAMES:
            result.append(PARAM_NAMES[parent])
            continue
        # Only parameterise if: parent has a known param name AND this segment
        # is not a known sub-resource AND looks like a concrete value
        if parent in PARAM_NAMES and seg and seg not in SUB_RESOURCES:
            # Looks like a concrete ID if it contains hyphens, dots, @, or is
            # a known test value (demo, test, staging, etc.)
            if (re.search(r'[-.@]', seg) or seg in ("demo", "test", "staging", "prod")
                    or re.match(r'^[0-9a-f]{8,}$', seg)):
                result.append(PARAM_NAMES[parent])
                continue
        result.append(seg)

    return "/".join(result)


def scan_test_files():
    """Scan all test files and return endpoint references with context."""
    references = {}  # (normalised_path, method) -> {"files": set, "has_auth": bool, "has_error": bool}

    for filename in sorted(os.listdir(TESTS_DIR)):
        if not filename.startswith("test_") or not filename.endswith(".py"):
            continue
        filepath = os.path.join(TESTS_DIR, filename)
        with open(filepath) as f:
            content = f.read()

        # Find all path references
        for pattern in PATH_PATTERNS:
            for match in pattern.finditer(content):
                raw_path = match.group(1)
                if not raw_path.startswith("/"):
                    continue
                norm = normalise_path(raw_path)

                # Try to determine the HTTP method from surrounding context
                # Look at the surrounding ~200 chars for method hints
                start = max(0, match.start() - 200)
                end = min(len(content), match.end() + 200)
                context = content[start:end]

                methods_found = set()
                for m in HTTP_METHODS:
                    if re.search(rf'"method"\s*:\s*"{m.upper()}"', context, re.IGNORECASE):
                        methods_found.add(m.upper())
                    if re.search(rf'method\s*=\s*"{m.upper()}"', context, re.IGNORECASE):
                        methods_found.add(m.upper())

                # Also check for _route("/path", "POST") positional method
                # Search from the match start (not the whole context) so we
                # pick up the method on the SAME line, not a neighbouring one.
                line_end = content.find("\n", match.end())
                route_context = content[match.start():line_end if line_end != -1 else match.end() + 100]
                route_method_match = ROUTE_METHOD_RE.search(route_context)
                if route_method_match:
                    methods_found.add(route_method_match.group(1).upper())

                if not methods_found:
                    # Default: assume GET for path references without explicit method
                    methods_found = {"GET"}

                # Check for auth-boundary and error-path indicators
                has_auth = any(p.search(context) for p in AUTH_PATTERNS)
                has_error = any(p.search(context) for p in ERROR_PATTERNS)

                for method in methods_found:
                    key = (norm, method)
                    if key not in references:
                        references[key] = {"files": set(), "has_auth": False, "has_error": False}
                    references[key]["files"].add(filename)
                    references[key]["has_auth"] = references[key]["has_auth"] or has_auth
                    references[key]["has_error"] = references[key]["has_error"] or has_error

        # Also detect direct handler function calls (e.g. service.handle_revoke_token(...))
        for handler_name, (endpoint_path, endpoint_method) in HANDLER_ENDPOINT_MAP.items():
            if handler_name in content:
                key = (endpoint_path, endpoint_method)
                if key not in references:
                    references[key] = {"files": set(), "has_auth": False, "has_error": False}
                references[key]["files"].add(filename)
                # Check surrounding context for auth/error indicators
                for match in re.finditer(re.escape(handler_name), content):
                    start = max(0, match.start() - 200)
                    end = min(len(content), match.end() + 200)
                    context = content[start:end]
                    if any(p.search(context) for p in AUTH_PATTERNS):
                        references[key]["has_auth"] = True
                    if any(p.search(context) for p in ERROR_PATTERNS):
                        references[key]["has_error"] = True

    return references


def main():
    parser = argparse.ArgumentParser(description="Endpoint coverage audit")
    parser.add_argument("--fail-on-missing", action="store_true",
                        help="Exit non-zero if any endpoint has zero test coverage")
    parser.add_argument("--fail-on-incomplete", action="store_true",
                        help="Exit non-zero if any endpoint lacks auth-boundary or error-path tests")
    args = parser.parse_args()

    endpoints = load_openapi_endpoints()
    references = scan_test_files()

    # Build report
    covered = []
    missing = []
    incomplete = []

    for (path, method) in sorted(endpoints.keys()):
        ref = references.get((path, method))
        if ref is None:
            missing.append((path, method))
        elif not ref["has_auth"] or not ref["has_error"]:
            incomplete.append((path, method, ref))
        else:
            covered.append((path, method, ref))

    total = len(endpoints)
    print(f"Endpoint Coverage Audit")
    print(f"{'=' * 70}")
    print(f"OpenAPI endpoints: {total}")
    print(f"Fully covered (happy + auth + error): {len(covered)}")
    print(f"Partially covered (missing auth or error): {len(incomplete)}")
    print(f"Not covered: {len(missing)}")
    print()

    if missing:
        print(f"NOT COVERED ({len(missing)}):")
        print(f"{'-' * 70}")
        for path, method in missing:
            print(f"  {method:6s} {path}")
        print()

    if incomplete:
        print(f"PARTIALLY COVERED ({len(incomplete)}):")
        print(f"{'-' * 70}")
        for path, method, ref in incomplete:
            gaps = []
            if not ref["has_auth"]:
                gaps.append("auth-boundary")
            if not ref["has_error"]:
                gaps.append("error-path")
            files = ", ".join(sorted(ref["files"]))
            print(f"  {method:6s} {path}")
            print(f"         missing: {', '.join(gaps)}  (tested in: {files})")
        print()

    if covered:
        print(f"FULLY COVERED ({len(covered)}):")
        print(f"{'-' * 70}")
        for path, method, ref in covered:
            files = ", ".join(sorted(ref["files"]))
            print(f"  {method:6s} {path}  ({files})")
        print()

    # Exit code
    if args.fail_on_missing and missing:
        print(f"FAIL: {len(missing)} endpoint(s) have zero test coverage.")
        sys.exit(1)
    if args.fail_on_incomplete and (missing or incomplete):
        print(f"FAIL: {len(missing)} uncovered + {len(incomplete)} partially covered endpoint(s).")
        sys.exit(1)

    print("OK: All endpoints have test coverage." if not missing else f"WARNING: {len(missing)} endpoint(s) uncovered.")
    sys.exit(0)


if __name__ == "__main__":
    main()
