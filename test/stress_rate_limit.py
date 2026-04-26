"""Stress-test the PDP rate limiter through the PEP.

Fires N tool-calls for a single subject and classifies each response into
one of the three PDP decision bands:

    PERMIT      — HTTP 200 from the core
    CHALLENGE   — request parks at the PEP; client sees a read timeout
    DENY        — HTTP 403 with JSON-RPC -32001

Usage:
    python test/stress_rate_limit.py [count=12] [subject=stress-test]
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from typing import Any

import httpx

PEP = "http://localhost:8000/mcp"
ACCEPT = "application/json, text/event-stream"
CLIENT_TIMEOUT_S = 2.5   # short enough that CHALLENGE parks show up as timeout


def _h(subject: str, sid: str | None = None) -> dict[str, str]:
    h = {
        "Accept": ACCEPT,
        "Content-Type": "application/json",
        "X-Koala-Subject": subject,
    }
    if sid:
        h["Mcp-Session-Id"] = sid
    return h


async def _initialize(client: httpx.AsyncClient, subject: str) -> str | None:
    r = await client.post(
        PEP,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "stress", "version": "0.1"},
            },
        },
        headers=_h(subject),
    )
    r.raise_for_status()
    sid = r.headers.get("mcp-session-id")
    await client.post(
        PEP,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=_h(subject, sid),
    )
    return sid


async def _call(
    client: httpx.AsyncClient, subject: str, sid: str | None, rpc_id: int
) -> tuple[str, Any]:
    body = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {
            "name": "get_drug_interactions",
            "arguments": {"drug_a": "aspirin", "drug_b": f"Stress-{rpc_id}"},
        },
    }
    try:
        r = await client.post(PEP, json=body, headers=_h(subject, sid))
    except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout):
        return "CHALLENGE (client timeout, still parked)", None
    if r.status_code == 200:
        return "PERMIT", None
    if r.status_code == 403:
        try:
            err = r.json().get("error", {}).get("message", "")
        except json.JSONDecodeError:
            err = r.text[:120]
        return "DENY", err
    if r.status_code == 408:
        return "CHALLENGE (PEP timeout)", None
    return f"OTHER status={r.status_code}", r.text[:120]


async def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    subject = sys.argv[2] if len(sys.argv) > 2 else "stress-test"

    print(f"Stress test: {count} requests as subject='{subject}'")
    print(f"PDP bands (default scorer): threshold=5 req/60s, penalty=0.2")
    print(f"  count  6 -> score 0.8  PERMIT")
    print(f"  count  7 -> score 0.6  CHALLENGE")
    print(f"  count  8 -> score 0.4  CHALLENGE")
    print(f"  count >8 -> score<0.4  DENY")
    print()

    summary: Counter[str] = Counter()
    async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT_S) as client:
        sid = await _initialize(client, subject)
        print(f"[init] session={sid}")
        # initialize + notifications/initialized already pushed 2 events into
        # the scorer window, so tools/list pushes a 3rd. Fire tool calls now.
        for i in range(count):
            label, extra = await _call(client, subject, sid, 100 + i)
            line = f"req {i+1:2d}: {label}"
            if extra:
                line += f"  ({extra})"
            print(line)
            summary[label.split()[0]] += 1
            # Small gap so PEP logs stay readable, not strictly required.
            await asyncio.sleep(0.15)

    print("\nSUMMARY")
    for band in ("PERMIT", "CHALLENGE", "DENY", "OTHER"):
        if summary.get(band):
            print(f"  {band:10s} {summary[band]}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
