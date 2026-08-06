#!/usr/bin/env python3
"""Run the repository test suite and reject skips or expected failures."""

from __future__ import annotations

import sys
import unittest
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def result_is_acceptable(result: unittest.TestResult) -> bool:
    return bool(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    os.chdir(ROOT)
    suite = unittest.defaultTestLoader.discover("tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print(f"Required test gate rejected {len(result.skipped)} skipped test(s).", file=sys.stderr)
    if result.expectedFailures:
        print(f"Required test gate rejected {len(result.expectedFailures)} expected failure(s).", file=sys.stderr)
    if result.unexpectedSuccesses:
        print(f"Required test gate rejected {len(result.unexpectedSuccesses)} unexpected success(es).", file=sys.stderr)
    if not result_is_acceptable(result):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
