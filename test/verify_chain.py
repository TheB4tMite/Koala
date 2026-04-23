"""Verify the tamper-evident audit chain end-to-end.

Pulls every row from ``audit_logs`` via ``docker exec zta-postgres psql``
(so no host-side DB driver is needed), then for each row recomputes:

    record_hash == sha256(prev_hash || canonical_json(event))

and checks that each row's ``prev_hash`` equals the previous row's
``record_hash`` (or the genesis hash for row 1).

Usage:
    python test/verify_chain.py
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from typing import Any

GENESIS = "0" * 64
CONTAINER = "zta-postgres"
DB_USER = "koala"
DB_NAME = "koala_audit"

# Strip the two storage-only columns from the JSON payload — they are not
# part of what the logger hashed.
_QUERY = (
    "SELECT coalesce("
    "  jsonb_agg(to_jsonb(al) - 'inserted_at' - 'seq' ORDER BY al.seq),"
    "  '[]'::jsonb"
    ")::text "
    "FROM audit_logs al;"
)


def _fetch() -> list[dict[str, Any]]:
    cmd = [
        "docker", "exec", CONTAINER,
        "psql", "-U", DB_USER, "-d", DB_NAME,
        "-At", "-c", _QUERY,
    ]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        sys.exit(f"psql failed: {exc.stderr.strip() or exc}")
    except FileNotFoundError:
        sys.exit("docker CLI not found on PATH; is Docker Desktop running?")
    out = out.strip()
    if not out:
        return []
    return json.loads(out)


def _canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _recompute(prev_hash: str, event: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(_canonical(event))
    return h.hexdigest()


def verify(rows: list[dict[str, Any]]) -> int:
    if not rows:
        print("No audit rows yet. Run the mock agent / stress tests first.")
        return 0

    prev = GENESIS
    broken = 0
    for i, row in enumerate(rows, start=1):
        event = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "subject_id": row["subject_id"],
            "action": row["action"],
            "decision": row["decision"],
            "resource_tier": row["resource_tier"],
            "details": row["details"],
        }
        expected_rec = _recompute(prev, event)
        prev_ok = row["prev_hash"] == prev
        rec_ok = row["record_hash"] == expected_rec

        tag = "OK" if (prev_ok and rec_ok) else "BROKEN"
        short = row["record_hash"][:12]
        print(
            f"  [{tag:6s}] row {i:3d}  {row['action']:10s} "
            f"subj={row['subject_id']:18s} "
            f"decision={str(row['decision']):9s} "
            f"hash={short}…"
        )
        if not prev_ok:
            print(f"           prev_hash MISMATCH: stored={row['prev_hash'][:16]}… expected={prev[:16]}…")
            broken += 1
        if not rec_ok:
            print(f"           record_hash MISMATCH: stored={row['record_hash'][:16]}… expected={expected_rec[:16]}…")
            broken += 1
        prev = row["record_hash"]

    print()
    if broken:
        print(f"CHAIN BROKEN — {broken} integrity failure(s) across {len(rows)} rows.")
        return 1
    print(f"CHAIN INTACT — {len(rows)} rows verified.")
    return 0


if __name__ == "__main__":
    sys.exit(verify(_fetch()))
