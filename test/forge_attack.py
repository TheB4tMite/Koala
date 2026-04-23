"""Direct-to-core attack harness.

This script runs INSIDE the PEP container so that:

    * it can reach http://mcp_core:8080/mcp (not exposed to the host), and
    * it can import ``shared.crypto.hmac_sign`` to forge signed envelopes
      using the shared secret.

It exercises three attacks against the MCP Core:

    1. No X-Koala-Context       -> expect HTTP 401 (-32000)
    2. Valid context (sanity)   -> expect HTTP 200
    3. Payload tamper           -> expect HTTP 401 "payload hash mismatch"
    4. Replay (stale timestamp) -> expect HTTP 401 "context timestamp too old"

Run from the host:

    docker cp test/forge_attack.py zta-pep:/tmp/forge_attack.py
    docker exec zta-pep python /tmp/forge_attack.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from shared.crypto.hmac_sign import sign_context

CORE_URL = os.getenv("MCP_CORE_URL", "http://mcp_core:8080/mcp")
SECRET = os.getenv("KOALA_SIGNING_SECRET", "koala_secret_dev")
ACCEPT = "application/json, text/event-stream"


def _build_body() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "attacker", "version": "0.0"},
            },
        }
    ).encode()


def _signed_header(
    body: bytes, *, timestamp: str | None = None, method: str = "initialize"
) -> str:
    ctx: dict[str, Any] = {
        "request_id": str(uuid.uuid4()),
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "method": method,
        "payload_hash": hashlib.sha256(body).hexdigest(),
        "resource_tier": "Public",
        "subject_id": "attacker",
    }
    ctx["signature"] = sign_context(ctx, SECRET)
    return base64.b64encode(json.dumps(ctx).encode()).decode()


def attack(
    name: str,
    body: bytes,
    headers: dict[str, str],
    *,
    expected_status: int,
) -> bool:
    try:
        r = httpx.post(CORE_URL, content=body, headers=headers, timeout=5.0)
    except httpx.RequestError as exc:
        print(f"[FAIL] {name}: transport error: {exc}")
        return False
    ok = r.status_code == expected_status
    tag = "PASS" if ok else "FAIL"
    print(f"[{tag}] {name}")
    print(f"       status={r.status_code} (expected {expected_status})")
    print(f"       body={r.text[:140]}")
    return ok


def main() -> int:
    body = _build_body()
    base = {"Accept": ACCEPT, "Content-Type": "application/json"}

    print(f"Target: {CORE_URL}\n")
    results = []

    # 1. No signature at all.
    results.append(
        attack(
            "1. missing X-Koala-Context (bare request)",
            body,
            dict(base),
            expected_status=401,
        )
    )

    # 2. Valid envelope — sanity check that our signing/verify agree.
    h = {**base, "X-Koala-Context": _signed_header(body)}
    results.append(
        attack(
            "2. valid signed context (sanity)",
            body,
            h,
            expected_status=200,
        )
    )

    # 3. Payload-binding attack: correct signed header, different body.
    tampered = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "read_dummy_file", "arguments": {}},
        }
    ).encode()
    h = {**base, "X-Koala-Context": _signed_header(body)}  # binds to original
    results.append(
        attack(
            "3. payload tamper (hash mismatch)",
            tampered,
            h,
            expected_status=401,
        )
    )

    # 4. Replay attack: valid signature, but timestamp is 2 minutes old.
    stale = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    h = {**base, "X-Koala-Context": _signed_header(body, timestamp=stale)}
    results.append(
        attack(
            "4. replay (stale timestamp >60s old)",
            body,
            h,
            expected_status=401,
        )
    )

    print(f"\nResult: {sum(results)}/{len(results)} checks passed.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
