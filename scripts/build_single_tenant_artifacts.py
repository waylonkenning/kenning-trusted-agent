#!/usr/bin/env python3
"""Build immutable artifacts for a customer-owned KTA deployment.

This entry point is separate from the hosted development release builder. A
customer-owned stack is deployed in its own account and therefore does not
use the hosted production promotion path.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from build_release_artifacts import build_artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--environment", choices=("development", "staging", "production"), default="production")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-version", default="0.1.0")
    parser.add_argument("--release-sequence", type=int, default=1)
    parser.add_argument("--web-api-url", default="same-origin")
    args = parser.parse_args()
    build_artifacts(
        args.output_dir,
        args.environment,
        args.source_commit,
        args.web_api_url,
        args.release_id,
        release_version=args.release_version,
        release_sequence=args.release_sequence,
    )
    print(f"Built single-tenant release artifacts in {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
