"""Probe the /stepup/verify endpoint to demonstrate authentication auditing.

Fires a mix of bad-token and no-parked-challenge requests. Every rejection
MUST land in the audit chain; run test/verify_chain.py afterwards to
confirm each probe is recorded as STEPUP/DENY.

Usage:
    python test/stepup_probe.py [subject=probe-test]
"""

from __future__ import annotations

import sys

import httpx

STEPUP = "http://localhost:8000/stepup/verify"


def probe(subject: str, token: str, tag: str) -> None:
    r = httpx.post(
        STEPUP,
        json={"subject_id": subject, "secondary_token": token},
        timeout=5.0,
    )
    print(f"  {tag:28s} -> status={r.status_code}  body={r.text[:120]}")


def main() -> int:
    subject = sys.argv[1] if len(sys.argv) > 1 else "probe-test"
    print(f"Probing /stepup/verify as subject='{subject}'\n")

    print("Phase 1: invalid tokens (should 401 and log STEPUP/DENY):")
    for i, bad in enumerate(
        ["", "hunter2", "admin", "koala_admin_toke", "KOALA_ADMIN_TOKEN"]
    ):
        probe(subject, bad, f"wrong-token #{i+1}")

    print("\nPhase 2: no active challenge (should 404 and log STEPUP/DENY):")
    probe("ghost-user-does-not-exist", "koala_admin_token", "no-parked subject")

    print("\nProbing done. Run `python test/verify_chain.py` to confirm")
    print("the rejections were written to the audit chain with decision='DENY'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
