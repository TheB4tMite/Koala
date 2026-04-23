"""Mock MCP client — Milestone 4.

Runs two scenarios against the PEP at ``localhost:8000``:

    1. Happy path: ``initialize`` -> ``tools/list`` -> ``tools/call``.
    2. CHALLENGE flow: spam the rate-limit threshold so the PDP downgrades
       the decision to ``CHALLENGE``, then concurrently fire a step-up
       request so the parked call is released and returns successfully.

Uses ``httpx.AsyncClient`` throughout so the CHALLENGE test can race the
MCP call and the ``/stepup/verify`` call on the same event loop.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import httpx

PEP_BASE = "http://localhost:8000"
PEP_MCP = f"{PEP_BASE}/mcp"
PEP_STEPUP = f"{PEP_BASE}/stepup/verify"

PROTOCOL_VERSION = "2024-11-05"
ACCEPT = "application/json, text/event-stream"
SUBJECT_ID = "test-agent-1"
STEPUP_TOKEN = "koala_admin_token"


def _parse(resp: httpx.Response) -> dict[str, Any] | None:
    if resp.status_code == 202 or not resp.content:
        return None
    ctype = resp.headers.get("content-type", "")
    if ctype.startswith("application/json"):
        return resp.json()
    if ctype.startswith("text/event-stream"):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line.removeprefix("data:").strip())
        raise RuntimeError(f"no data frame in SSE reply: {resp.text!r}")
    raise RuntimeError(f"unexpected content-type {ctype!r}: {resp.text!r}")


async def _rpc(
    client: httpx.AsyncClient,
    payload: dict[str, Any],
    session_id: str | None,
) -> tuple[dict[str, Any] | None, str | None, httpx.Response]:
    headers = {
        "Content-Type": "application/json",
        "Accept": ACCEPT,
        "X-Koala-Subject": SUBJECT_ID,
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = await client.post(PEP_MCP, json=payload, headers=headers)
    new_sid = resp.headers.get("mcp-session-id") or session_id
    # Don't raise on CHALLENGE paths — the caller inspects status.
    if resp.is_error and resp.status_code not in (408, 403):
        resp.raise_for_status()
    return _parse(resp), new_sid, resp


async def _initialize(client: httpx.AsyncClient) -> str | None:
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "koala-mock-agent", "version": "0.2.0"},
        },
    }
    body, sid, _ = await _rpc(client, init_req, None)
    print("== initialize ==")
    print(json.dumps(body, indent=2))
    print(f"session-id: {sid}")
    await _rpc(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        sid,
    )
    return sid


async def _tools_list(client: httpx.AsyncClient, sid: str | None) -> str | None:
    body, sid, _ = await _rpc(
        client, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid
    )
    print("\n== tools/list ==")
    print(json.dumps(body, indent=2))
    return sid


async def _call_weather(
    client: httpx.AsyncClient, sid: str | None, *, rpc_id: int, location: str
) -> tuple[dict[str, Any] | None, str | None, httpx.Response]:
    return await _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {
                "name": "get_weather",
                "arguments": {"location": location},
            },
        },
        sid,
    )


async def happy_path(client: httpx.AsyncClient) -> str | None:
    """Baseline: initialize + tools/list + one tool call. ~4 PDP events."""
    sid = await _initialize(client)
    sid = await _tools_list(client, sid)
    body, sid, _ = await _call_weather(
        client, sid, rpc_id=3, location="Bengaluru"
    )
    print("\n== tools/call get_weather (happy) ==")
    print(json.dumps(body, indent=2))
    return sid


async def trigger_challenge(
    client: httpx.AsyncClient, sid: str | None
) -> None:
    """Push the subject past the CHALLENGE threshold, then race step-up."""
    # The PDP scorer defaults to window=60s, threshold=5, penalty=0.2.
    # After the happy-path run there are already ~4 events in the window.
    # We fire 2 more PERMIT-band calls, then one more that lands in CHALLENGE.
    print("\n== priming rate limit ==")
    for i, city in enumerate(("Mysuru", "Chennai"), start=4):
        body, sid, resp = await _call_weather(
            client, sid, rpc_id=10 + i, location=city
        )
        print(f"prime #{i} status={resp.status_code} -> {json.dumps(body)[:140]}")

    print("\n== firing CHALLENGE request (will park) ==")
    challenge_task = asyncio.create_task(
        _call_weather(client, sid, rpc_id=999, location="ChallengeCity")
    )

    # Let the request reach the PEP and enter the parked state. The PEP
    # logs "parking request_id=..." at this point.
    await asyncio.sleep(1.0)

    if not challenge_task.done():
        print("-> request is parked; sending /stepup/verify")
        stepup_resp = await client.post(
            PEP_STEPUP,
            json={"subject_id": SUBJECT_ID, "secondary_token": STEPUP_TOKEN},
        )
        print(f"stepup status={stepup_resp.status_code} body={stepup_resp.text}")
    else:
        # Could happen if the PDP actually still permitted (timing raced).
        print("-> request completed without parking; skipping stepup")

    body, _sid, resp = await challenge_task
    print(f"\n== CHALLENGE result status={resp.status_code} ==")
    print(json.dumps(body, indent=2))


async def main() -> int:
    async with httpx.AsyncClient(timeout=45.0) as client:
        sid = await happy_path(client)
        await trigger_challenge(client, sid)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
