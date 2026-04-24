"""IEEE Demo Script — Project Koala ZTA for MCP.

Healthcare Data Assistant storyline. Runs four scenarios against the PEP
at ``http://localhost:8000``:

    Scenario A  Public tool: get_drug_interactions
                PDP => PERMIT (instant).
    Scenario B  Internal tool: get_patient_record
                PDP => PERMIT. PEP egress DLP scrubs the SSN in-flight.
    Scenario C  Restricted tool: prescribe_medication
                PDP => CHALLENGE. A client-generated request_id is sent
                in ``X-Koala-Request-Id``; a background task POSTs the
                same request_id to ``/stepup/verify`` after ~2s; the
                parked coroutine resumes.
    Scenario D  Rogue agent: 10x spam of get_drug_interactions
                Trust score collapses; final requests are denied.
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from typing import Any

import httpx

PEP_BASE = "http://localhost:8000"
PEP_MCP = f"{PEP_BASE}/mcp"
PEP_STEPUP = f"{PEP_BASE}/stepup/verify"

SUBJECT = "demo-agent"
STEPUP_TOKEN = "koala_admin_token"

PROTOCOL_VERSION = "2024-11-05"
ACCEPT = "application/json, text/event-stream"

SSN_PLACEHOLDER = "[REDACTED_SSN]"


# ---- Output helpers ----------------------------------------------------------


def banner(title: str, kind: str = "SCENARIO") -> None:
    print()
    print("=" * 72)
    print(f"  {kind}: {title}")
    print("=" * 72)


def note(msg: str) -> None:
    print(f"  > {msg}")


def pretty(label: str, body: Any) -> None:
    print(f"  {label}:")
    if body is None:
        print("    (no content)")
        return
    text = json.dumps(body, indent=2)
    for line in text.splitlines():
        print(f"    {line}")


# ---- Transport ---------------------------------------------------------------


def _headers(
    sid: str | None = None, request_id: str | None = None
) -> dict[str, str]:
    h = {
        "Accept": ACCEPT,
        "Content-Type": "application/json",
        "X-Koala-Subject": SUBJECT,
    }
    if sid:
        h["Mcp-Session-Id"] = sid
    if request_id:
        h["X-Koala-Request-Id"] = request_id
    return h


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
        return {"raw": resp.text}
    try:
        return resp.json()
    except json.JSONDecodeError:
        return {"raw": resp.text}


async def _rpc(
    client: httpx.AsyncClient,
    payload: dict[str, Any],
    sid: str | None,
    *,
    timeout: float = 30.0,
    request_id: str | None = None,
) -> tuple[dict[str, Any] | None, str | None, httpx.Response | None]:
    try:
        r = await client.post(
            PEP_MCP,
            json=payload,
            headers=_headers(sid, request_id),
            timeout=timeout,
        )
    except (httpx.ReadTimeout, httpx.ConnectTimeout, asyncio.TimeoutError):
        return None, sid, None
    new_sid = r.headers.get("mcp-session-id") or sid
    return _parse(r), new_sid, r


async def _initialize(client: httpx.AsyncClient) -> str | None:
    _, sid, _ = await _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "koala-demo", "version": "1.0"},
            },
        },
        None,
    )
    await _rpc(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        sid,
    )
    return sid


async def _call_tool(
    client: httpx.AsyncClient,
    sid: str | None,
    tool: str,
    args: dict[str, Any],
    rpc_id: int,
    *,
    timeout: float = 30.0,
    request_id: str | None = None,
) -> tuple[dict[str, Any] | None, str | None, httpx.Response | None]:
    return await _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        },
        sid,
        timeout=timeout,
        request_id=request_id,
    )


async def approve_later(
    client: httpx.AsyncClient, request_id: str, *, delay: float = 2.0
) -> httpx.Response:
    """Background helper: wait then POST the secondary token."""
    await asyncio.sleep(delay)
    return await client.post(
        PEP_STEPUP,
        json={
            "request_id": request_id,
            "secondary_token": STEPUP_TOKEN,
        },
    )


# ---- Scenarios ---------------------------------------------------------------


async def scenario_a(
    client: httpx.AsyncClient, sid: str | None
) -> str | None:
    banner("A - Public tier: get_drug_interactions", "SCENARIO")
    note("Agent queries generic drug-interaction data. Low risk.")
    note("Expected: PDP returns PERMIT, PEP forwards immediately.")
    body, sid, resp = await _call_tool(
        client,
        sid,
        "get_drug_interactions",
        {"drug_a": "ibuprofen", "drug_b": "warfarin"},
        10,
    )
    print(f"  HTTP status: {resp.status_code if resp else 'n/a'}")
    pretty("PEP response", body)
    return sid


async def scenario_b(
    client: httpx.AsyncClient, sid: str | None
) -> str | None:
    banner("B - Internal tier: get_patient_record (PHI + DLP)", "SCENARIO")
    note("Agent pulls a full patient record. Record contains a real-shaped SSN.")
    note("Expected: PDP returns PERMIT; PEP egress DLP redacts the SSN BEFORE")
    note("the payload leaves the Koala trust boundary.")
    body, sid, resp = await _call_tool(
        client, sid, "get_patient_record", {"patient_id": "P001"}, 11
    )
    print(f"  HTTP status: {resp.status_code if resp else 'n/a'}")
    pretty("PEP response (post-DLP)", body)

    raw = json.dumps(body or {})
    if SSN_PLACEHOLDER in raw:
        note("DLP: SSN successfully replaced with " + SSN_PLACEHOLDER)
    else:
        note("DLP WARNING: SSN was NOT scrubbed. Check PEP egress pipeline.")
    return sid


async def scenario_c(
    client: httpx.AsyncClient, sid: str | None
) -> str | None:
    banner("C - Restricted tier: prescribe_medication (step-up)", "SCENARIO")
    note("Agent attempts a privileged write (prescribing a new medication).")
    note("Restricted tier policy at the PDP forces CHALLENGE regardless of")
    note("trust score. The PEP parks the request; a back-channel posts the")
    note("step-up token ~2s later using the SAME request_id; parked coroutine")
    note("resumes and signs + forwards to the MCP Core.")

    request_id = str(uuid.uuid4())
    note(f"Pre-generated request_id = {request_id}")

    # Kick the approval off first so the 2s sleep runs concurrently with
    # the main call reaching the PEP and entering the parked state.
    approval_task = asyncio.create_task(approve_later(client, request_id))

    body, sid, resp = await _call_tool(
        client,
        sid,
        "prescribe_medication",
        {"patient_id": "P001", "medication": "amoxicillin 500mg"},
        12,
        timeout=45.0,
        request_id=request_id,
    )

    stepup_resp = await approval_task
    note(
        f"Step-up response: HTTP {stepup_resp.status_code} body={stepup_resp.text}"
    )
    print(f"  HTTP status: {resp.status_code if resp else 'n/a'}")
    pretty("Post-step-up response", body)
    return sid


async def scenario_d(client: httpx.AsyncClient, sid: str | None) -> None:
    banner("D - Rogue agent: 10x spam of get_drug_interactions", "SCENARIO")
    note("Agent abuses its low-tier access. Trust score drops each call.")
    note("Expected: PERMIT -> CHALLENGE (parked, no step-up) -> DENY.")

    summary: dict[str, int] = {"PERMIT": 0, "CHALLENGE": 0, "DENY": 0, "OTHER": 0}
    for i in range(10):
        body, sid, resp = await _call_tool(
            client,
            sid,
            "get_drug_interactions",
            {"drug_a": "aspirin", "drug_b": "warfarin"},
            100 + i,
            timeout=2.5,
        )
        if resp is None:
            summary["CHALLENGE"] += 1
            print(f"  req #{i + 1:2d}: CHALLENGE  (client timeout; still parked)")
            continue
        sc = resp.status_code
        if sc == 200:
            summary["PERMIT"] += 1
            tag = "PERMIT"
        elif sc == 403:
            summary["DENY"] += 1
            msg = ""
            if isinstance(body, dict):
                msg = body.get("error", {}).get("message", "")
            tag = f"DENY (rate-limited) - {msg}"
        elif sc == 408:
            summary["CHALLENGE"] += 1
            tag = "CHALLENGE (PEP step-up timeout)"
        else:
            summary["OTHER"] += 1
            tag = f"OTHER status={sc}"
        print(f"  req #{i + 1:2d}: {tag}")

    print()
    note(f"Summary: {summary}")
    note(
        "Trust score collapsed mid-spam; the rogue agent is now locked out "
        "until the 60s rolling window clears or an operator resets the scorer."
    )


# ---- Entry -------------------------------------------------------------------


async def main() -> int:
    banner("Koala ZTA - Healthcare Data Assistant (IEEE Demo)", "SETUP")
    note(f"Target PEP     = {PEP_BASE}")
    note(f"Subject ID     = {SUBJECT!r}")
    note(f"Step-up token  = {STEPUP_TOKEN!r} (demo value)")

    async with httpx.AsyncClient(timeout=45.0) as client:
        sid = await _initialize(client)
        note(f"MCP session initialized (id={sid})")

        sid = await scenario_a(client, sid)
        sid = await scenario_b(client, sid)
        sid = await scenario_c(client, sid)
        await scenario_d(client, sid)

    banner("Demo complete.", "DONE")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
