"""PEP (Policy Enforcement Point) — Milestone 4.

Pipeline per incoming request:

    1. Compute ``payload_hash = sha256(body)`` and build a
       :class:`SecurityContext`.
    2. POST the context to the PDP ``/authorize`` endpoint.
    3. On ``PERMIT``        — sign and forward immediately.
       On ``CHALLENGE``     — *park* the request on an ``asyncio.Event``
                              keyed by ``subject_id``. A second request to
                              ``POST /stepup/verify`` releases the event,
                              at which point the PEP signs the original
                              envelope and forwards it. A 30-second timeout
                              returns a JSON-RPC ``-32000``.
       On ``DENY``          — reject with JSON-RPC ``-32001``.

The signing key lives only on the PEP. The PDP is a pure decision engine.
Identity wiring (full OIDC) is still future work; until then the PEP reads
``X-Koala-Subject`` off the client request to seed ``subject_id``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from shared.crypto.hmac_sign import sign_context
from shared.schemas.security_context import SecurityContext

MCP_CORE_URL = os.getenv("MCP_CORE_URL", "http://mcp_core:8080/mcp")
PDP_URL = os.getenv("PDP_URL", "http://pdp:8181")
SIGNING_SECRET = os.getenv("KOALA_SIGNING_SECRET", "koala_secret_dev")
STEPUP_TOKEN = os.getenv("KOALA_STEPUP_TOKEN", "koala_admin_token")
STEPUP_TIMEOUT_S = float(os.getenv("KOALA_STEPUP_TIMEOUT_S", "30"))
UPSTREAM_TIMEOUT_S = float(os.getenv("MCP_UPSTREAM_TIMEOUT_S", "45"))
CONTEXT_HEADER = "X-Koala-Context"
SUBJECT_HEADER = "X-Koala-Subject"

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}

# Parked challenges waiting for step-up. Key: subject_id. Value: the event
# the request handler is awaiting. Access is single-threaded under the
# uvicorn event loop, so no explicit lock is needed.
PARKED_REQUESTS: dict[str, asyncio.Event] = {}

logger = logging.getLogger("pep")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="ZTA-MCP PEP", version="0.5.0")
_client: httpx.AsyncClient | None = None


@app.on_event("startup")
async def _startup() -> None:
    global _client
    _client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_S)
    logger.info("PEP up; forwarding to %s via PDP %s", MCP_CORE_URL, PDP_URL)


@app.on_event("shutdown")
async def _shutdown() -> None:
    if _client is not None:
        await _client.aclose()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "pep"}


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP}


def _parse_rpc(body: bytes) -> dict[str, Any] | None:
    if not body:
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _build_context(
    rpc: dict[str, Any] | None, payload_hash: str, subject_id: str
) -> SecurityContext:
    method = (rpc or {}).get("method", "") or "<no-method>"
    tool_name: str | None = None
    if method == "tools/call":
        params = (rpc or {}).get("params") or {}
        if isinstance(params, dict):
            tool_name = params.get("name")
    return SecurityContext(
        request_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        method=method,
        tool_name=tool_name,
        resource_tier="Public",
        payload_hash=payload_hash,
        subject_id=subject_id,
    )


def _encode_context_header(context: SecurityContext) -> str:
    raw = context.model_dump_json(exclude_none=True).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _rpc_error(status: int, id_: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "jsonrpc": "2.0",
            "id": id_,
            "error": {"code": code, "message": message},
        },
    )


async def _forward(
    request: Request, body: bytes, context: SecurityContext, rpc_id: Any
) -> Response:
    """Sign the context and proxy the original request to the MCP Core."""
    assert _client is not None
    context.signature = sign_context(context.to_signable(), SIGNING_SECRET)

    headers = _filter_headers(dict(request.headers))
    headers[CONTEXT_HEADER] = _encode_context_header(context)

    try:
        upstream = await _client.request(
            method=request.method,
            url=MCP_CORE_URL,
            content=body,
            headers=headers,
            params=request.query_params,
        )
    except httpx.RequestError as exc:
        logger.exception("upstream failure")
        return _rpc_error(502, rpc_id, -32000, f"upstream unreachable: {exc!s}")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_filter_headers(dict(upstream.headers)),
        media_type=upstream.headers.get("content-type"),
    )


async def _park_for_stepup(subject_id: str, request_id: str) -> bool:
    """Block this request until a matching ``/stepup/verify`` arrives.

    Returns ``True`` if the step-up succeeded, ``False`` on timeout.
    """
    event = asyncio.Event()
    # Overwriting an existing parked event is intentional: only the most
    # recent challenge for a given subject holds the slot. Earlier parked
    # coroutines will time out on their own.
    PARKED_REQUESTS[subject_id] = event
    logger.info(
        "parking request_id=%s subject=%s for step-up", request_id, subject_id
    )
    try:
        await asyncio.wait_for(event.wait(), timeout=STEPUP_TIMEOUT_S)
        return True
    except asyncio.TimeoutError:
        return False
    finally:
        # Clear our slot iff it's still ours (the stepup handler also pops
        # on success, and a newer challenge may have replaced us).
        if PARKED_REQUESTS.get(subject_id) is event:
            PARKED_REQUESTS.pop(subject_id, None)


@app.post("/mcp")
@app.get("/mcp")
@app.delete("/mcp")
async def mcp_proxy(request: Request) -> Response:
    assert _client is not None
    body = await request.body()
    rpc = _parse_rpc(body)
    rpc_id = rpc.get("id") if rpc else None

    subject_id = request.headers.get(SUBJECT_HEADER) or "anonymous"
    payload_hash = hashlib.sha256(body).hexdigest()
    context = _build_context(rpc, payload_hash, subject_id)

    try:
        decision_resp = await _client.post(
            f"{PDP_URL}/authorize",
            json=context.model_dump(exclude_none=True),
        )
        decision_resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.exception("PDP unreachable")
        return _rpc_error(
            502, rpc_id, -32000, f"policy decision point unreachable: {exc!s}"
        )

    decision_body = decision_resp.json()
    decision = decision_body.get("decision")
    context.trust_score = decision_body.get("trust_score")

    if decision == "DENY":
        logger.info(
            "PDP denied request_id=%s reason=%s",
            context.request_id,
            decision_body.get("reason"),
        )
        return _rpc_error(
            403, rpc_id, -32001, f"denied by policy: {decision_body.get('reason')}"
        )

    if decision == "CHALLENGE":
        released = await _park_for_stepup(subject_id, context.request_id)
        if not released:
            logger.info(
                "step-up timeout request_id=%s subject=%s",
                context.request_id,
                subject_id,
            )
            return _rpc_error(
                408, rpc_id, -32000, "Step-up authentication timed out"
            )
        logger.info(
            "step-up verified request_id=%s subject=%s — forwarding",
            context.request_id,
            subject_id,
        )
        context.decision = "PERMIT"
        return await _forward(request, body, context, rpc_id)

    if decision != "PERMIT":
        return _rpc_error(502, rpc_id, -32000, f"unexpected PDP decision: {decision}")

    context.decision = "PERMIT"
    return await _forward(request, body, context, rpc_id)


# ---- Step-up endpoint --------------------------------------------------------


class StepupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_id: str
    secondary_token: str


@app.post("/stepup/verify")
async def stepup_verify(payload: StepupRequest) -> dict[str, str]:
    # M4 uses a static admin token. M5+ replaces this with a TOTP / WebAuthn
    # round-trip against an identity provider.
    if payload.secondary_token != STEPUP_TOKEN:
        logger.warning(
            "stepup: bad token for subject=%s", payload.subject_id
        )
        raise HTTPException(status_code=401, detail="invalid secondary token")

    event = PARKED_REQUESTS.pop(payload.subject_id, None)
    if event is None:
        raise HTTPException(
            status_code=404, detail="no pending challenge for subject"
        )
    event.set()
    logger.info("stepup: released subject=%s", payload.subject_id)
    return {"status": "success"}
