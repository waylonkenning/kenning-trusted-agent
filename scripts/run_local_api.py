#!/usr/bin/env python3
"""Run the credential-free in-process API harness for local development."""

from __future__ import annotations

import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.local_api_harness import LocalApiFixture


def main() -> int:
    fixture = LocalApiFixture()
    values = fixture.start()
    print(f"Local API: {values['api_url']}")
    print(f"Test PAT: {values['pat']}")
    print(f"Test tenant: {values['tenant_id']}")

    def stop(_signum: int, _frame: object) -> None:
        fixture.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        while True:
            time.sleep(60)
    finally:
        fixture.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
