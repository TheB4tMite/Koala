"""PEP (Policy Enforcement Point) — Milestone 5.

Adds tamper-evident audit logging: after a successful tool execution
returned by the MCP Core, the PEP appends a ``TOOL_CALL`` event (with
response latency) to the shared hash-chain log. Step-up timeouts and policy
denials are also logged as ``DENY`` / ``STEPUP`` events for completeness.

Pipeline:

    1. Build ``SecurityContext`` (request_id, timestamp, method, tool_name,
       payload_hash = sha256(body), subject_id from X-Koala-Subject).
    2. POST the context to the PDP ``/authorize``.
    3. On ``PERMIT``     — sign and forward.
       On ``CHALLENGE``  — park on an asyncio.Event keyed by subject_id;
                           ``/stepup/verify`` releases it.
       On ``DENY``       — JSON-RPC -32001.
    4. Log the final outcome (and latency) to the audit chain.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from shared.audit.logger import AuditLogger, logger_from_env
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

PARKED_REQUESTS: dict[str, asyncio.Event] = {}

logger = logging.getLogger("pep")
logging.basicConfig(level=logging.INFO)

_client: httpx.AsyncClient | None = None
_audit: AuditLogger | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _client, _audit
    _client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_S)
    _audit = logger_from_env(service="pep")
    await _audit.connect()
    # PDP also runs init_schema on startup; calling it here is idempotent
    # and means the PEP can write even if the PDP is slower to come up.
    await _audit.init_schema()
    logger.info("PEP up; forwarding to %s via PDP %s", MCP_CORE_URL, PDP_URL)
    try:
        yield
    finally:
        await _client.aclose()
        await _audit.close()


app = FastAPI(title="ZTA-MCP PEP", version="0.6.0", lifespan=lifespan)


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
) -> tuple[Response, float, int]:
    """Sign, forward, and return the upstream response + latency_ms + status."""
    assert _client is not None
    context.signature = sign_context(context.to_signable(), SIGNING_SECRET)

    headers = _filter_headers(dict(request.headers))
    headers[CONTEXT_HEADER] = _encode_context_header(context)

    start = time.perf_counter()
    try:
        upstream = await _client.request(
            method=request.method,
            url=MCP_CORE_URL,
            content=body,
            headers=headers,
            params=request.query_params,
        )
    except httpx.RequestError as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        logger.exception("upstream failure")
        return (
            _rpc_error(502, rpc_id, -32000, f"upstream unreachable: {exc!s}"),
            latency_ms,
            0,
        )
    latency_ms = (time.perf_counter() - start) * 1000

    response = Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_filter_headers(dict(upstream.headers)),
        media_type=upstream.headers.get("content-type"),
    )
    return response, latency_ms, upstream.status_code


async def _park_for_stepup(subject_id: str, request_id: str) -> bool:
    event = asyncio.Event()
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
        if PARKED_REQUESTS.get(subject_id) is event:
            PARKED_REQUESTS.pop(subject_id, None)


async def _audit_tool_call(
    *,
    subject_id: str,
    context: SecurityContext,
    upstream_status: int,
    latency_ms: float,
    stepped_up: bool,
) -> None:
    assert _audit is not None
    try:
        await _audit.append_log(
            {
                "subject_id": subject_id,
                "action": "TOOL_CALL",
                "decision": "PERMIT",
                "resource_tier": context.resource_tier,
                "details": {
                    "request_id": context.request_id,
                    "method": context.method,
                    "tool_name": context.tool_name,
                    "upstream_status": upstream_status,
                    "latency_ms": round(latency_ms, 2),
                    "stepped_up": stepped_up,
                    "trust_score": context.trust_score,
                },
            }
        )
    except Exception:
        # Audit failure must not poison the user response; it is logged loudly
        # so operators can investigate. In a regulated deployment the service
        # should fail-closed here, but M5 keeps the request path available.
        logger.exception("audit append failed for request_id=%s", context.request_id)


async def _audit_denial(
    *, subject_id: str, context: SecurityContext, reason: str, action: str
) -> None:
    assert _audit is not None
    try:
        await _audit.append_log(
            {
                "subject_id": subject_id,
                "action": action,
                "decision": "DENY",
                "resource_tier": context.resource_tier,
                "details": {
                    "request_id": context.request_id,
                    "method": context.method,
                    "tool_name": context.tool_name,
                    "reason": reason,
                },
            }
        )
    except Exception:
        logger.exception("audit append failed for request_id=%s", context.request_id)


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
        reason = decision_body.get("reason") or "denied"
        logger.info(
            "PDP denied request_id=%s reason=%s", context.request_id, reason
        )
        await _audit_denial(
            subject_id=subject_id,
            context=context,
            reason=reason,
            action="DENY",
        )
        return _rpc_error(403, rpc_id, -32001, f"denied by policy: {reason}")

    stepped_up = False
    if decision == "CHALLENGE":
        released = await _park_for_stepup(subject_id, context.request_id)
        if not released:
            logger.info(
                "step-up timeout request_id=%s subject=%s",
                context.request_id,
                subject_id,
            )
            await _audit_denial(
                subject_id=subject_id,
                context=context,
                reason="step-up timeout",
                action="STEPUP",
            )
            return _rpc_error(
                408, rpc_id, -32000, "Step-up authentication timed out"
            )
        logger.info(
            "step-up verified request_id=%s subject=%s — forwarding",
            context.request_id,
            subject_id,
        )
        stepped_up = True

    if decision not in ("PERMIT", "CHALLENGE"):
        return _rpc_error(502, rpc_id, -32000, f"unexpected PDP decision: {decision}")

    context.decision = "PERMIT"
    response, latency_ms, upstream_status = await _forward(
        request, body, context, rpc_id
    )

    # Audit only *successful* tool execution in the successful-path bucket;
    # upstream 2xx / 3xx counts as success from the PEP's perspective. A 4xx
    # or 5xx from the core is logged as a denial-ish event instead.
    if 200 <= upstream_status < 400:
        await _audit_tool_call(
            subject_id=subject_id,
            context=context,
            upstream_status=upstream_status,
            latency_ms=latency_ms,
            stepped_up=stepped_up,
        )
    else:
        await _audit_denial(
            subject_id=subject_id,
            context=context,
            reason=f"upstream status {upstream_status}",
            action="TOOL_CALL",
        )

    return response


# ---- Step-up endpoint --------------------------------------------------------


class StepupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_id: str
    secondary_token: str


async def _audit_stepup(
    *,
    subject_id: str,
    decision: str,
    reason: str,
    http_status: int,
) -> None:
    """Record a step-up outcome on the tamper-evident audit chain.

    Every branch of :func:`stepup_verify` must funnel through here so that
    probing attacks (bad tokens, no-parked-challenge reconnaissance) are
    immutably recorded alongside legitimate successes.
    """
    assert _audit is not None
    try:
        await _audit.append_log(
            {
                "subject_id": subject_id,
                "action": "STEPUP",
                "decision": decision,
                "resource_tier": None,
                "details": {
                    "reason": reason,
                    "http_status": http_status,
                },
            }
        )
    except Exception:
        logger.exception("audit append failed for stepup subject=%s", subject_id)


@app.post("/stepup/verify")
async def stepup_verify(payload: StepupRequest) -> dict[str, str]:
    if payload.secondary_token != STEPUP_TOKEN:
        logger.warning("stepup: bad token for subject=%s", payload.subject_id)
        await _audit_stepup(
            subject_id=payload.subject_id,
            decision="DENY",
            reason="Invalid token",
            http_status=401,
        )
        raise HTTPException(status_code=401, detail="invalid secondary token")

    event = PARKED_REQUESTS.pop(payload.subject_id, None)
    if event is None:
        logger.warning(
            "stepup: no parked challenge for subject=%s", payload.subject_id
        )
        await _audit_stepup(
            subject_id=payload.subject_id,
            decision="DENY",
            reason="No active challenge",
            http_status=404,
        )
        raise HTTPException(
            status_code=404, detail="no pending challenge for subject"
        )

    event.set()
    logger.info("stepup: released subject=%s", payload.subject_id)
    await _audit_stepup(
        subject_id=payload.subject_id,
        decision="PERMIT",
        reason="Step-up verified",
        http_status=200,
    )
    return {"status": "success"}
