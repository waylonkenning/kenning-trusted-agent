#!/usr/bin/env python3
"""Validate the customer-owned deployment package before it is applied."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "infra" / "single-tenant" / "template.yaml"
REQUIRED_PARAMETERS = {
    "AgencyName",
    "AgencySlug",
    "EnvironmentName",
    "DeploymentMode",
    "RetentionDays",
    "LegalHoldDefault",
    "LambdaArtifactBucket",
    "LambdaArtifactKey",
    "CitationFetcherArtifactKey",
    "WebArtifactKey",
    "PortalTitle",
    "PortalPrimaryColor",
    "PortalDomain",
    "PortalCertificateArn",
    "CreateClientPipeline",
}
REQUIRED_RESOURCES = {
    "AuditTable",
    "TokenTable",
    "ReceiptKey",
    "TenantOAuthSecret",
    "GuardRole",
    "GuardFunction",
    "CitationFetcherFunction",
    "HttpApi",
    "PortalBucket",
    "PortalDistribution",
    "UserPool",
    "UserPoolClient",
    "LambdaErrorsAlarm",
    "OperationsDashboard",
}
# The public package must not depend on a hosted Kenning environment. Keep
# this tuple available for downstream forks to extend with their own hosted
# identifiers without baking any private environment values into the release.
FORBIDDEN_HOSTED_IDENTIFIERS: tuple[str, ...] = ()


def section_names(raw: str, section: str) -> set[str]:
    """Return top-level names in a CloudFormation section without a YAML dependency."""

    marker = re.search(rf"^{re.escape(section)}:\s*$", raw, re.MULTILINE)
    if not marker:
        return set()
    remainder = raw[marker.end():]
    next_section = re.search(r"^[A-Za-z][A-Za-z0-9_-]*:\s*$", remainder, re.MULTILINE)
    section_text = remainder[:next_section.start()] if next_section else remainder
    return set(re.findall(r"^  ([A-Za-z][A-Za-z0-9_-]*):\s*$", section_text, re.MULTILINE))


def validate_structure(path: Path = TEMPLATE) -> list[str]:
    raw = path.read_text(encoding="utf-8")
    errors: list[str] = []
    missing_parameters = sorted(REQUIRED_PARAMETERS - section_names(raw, "Parameters"))
    missing_resources = sorted(REQUIRED_RESOURCES - section_names(raw, "Resources"))
    if missing_parameters:
        errors.append(f"missing parameters: {', '.join(missing_parameters)}")
    if missing_resources:
        errors.append(f"missing resources: {', '.join(missing_resources)}")
    for identifier in FORBIDDEN_HOSTED_IDENTIFIERS:
        if identifier in raw:
            errors.append(f"hosted identifier is embedded in customer package: {identifier}")
    if not re.search(r"CONTROL_PLANE_SINGLE_TENANT_ID:\s*!Ref AgencySlug", raw):
        errors.append("Guard Lambda is not pinned to the parameterised single workspace.")
    if "PointInTimeRecoveryEnabled: true" not in raw:
        errors.append("DynamoDB point-in-time recovery is not enabled.")
    if "SigningBehavior: always" not in raw or "SigningProtocol: sigv4" not in raw:
        errors.append("CloudFront origin access control is not configured for SigV4.")
    return errors


def validate_cloudformation(path: Path, region: str) -> None:
    subprocess.run(
        [
            "aws",
            "cloudformation",
            "validate-template",
            "--region",
            region,
            "--template-body",
            f"file://{path}",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=TEMPLATE)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--skip-cloudformation", action="store_true")
    args = parser.parse_args()
    errors = validate_structure(args.template)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if not args.skip_cloudformation:
        validate_cloudformation(args.template, args.region)
    print(f"Single-tenant package validation passed: {args.template}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
