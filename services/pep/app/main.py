"""PEP (Policy Enforcement Point) — step-up keyed by ``request_id``.

Pipeline:

    1. Read ``X-Koala-Request-Id`` header (client-supplied); fall back to a
       server-generated UUID4. This value is the park key, the
       ``SecurityContext.request_id``, and the identifier the client posts
       back to ``/stepup/verify``.
    2. Compute ``payload_hash = sha256(body)`` and build a
       :class:`SecurityContext`.
    3. POST to the PDP ``/authorize``.
    4. On ``PERMIT``    — sign and forward.
       On ``CHALLENGE`` — park on an ``asyncio.Event`` keyed by
                          ``request_id``. ``POST /stepup/verify`` releases
                          the event; the parked coroutine then signs the
                          original envelope and proxies to the Core. A
                          30 s timeout returns JSON-RPC ``-32000``.
       On ``DENY``      — JSON-RPC ``-32001``.
    5. Audit every outcome.

Signing, SignatureMiddleware, and audit-logger internals are unchanged.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
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
REQUEST_ID_HEADER = "X-Koala-Request-Id"

# Declarative catalogue of tools the PDP tier-policy classifies as
# Restricted. Used for logging + tier mapping; the PDP is what actually
# forces the CHALLENGE decision.
RESTRICTED_TOOLS: frozenset[str] = frozenset({"prescribe_medication"})

TOOL_RESOURCE_TIER: dict[str, str] = {
    "get_drug_interactions": "Public",
    "get_patient_record": "Internal",
    "prescribe_medication": "Restricted",
}

_SSN_PATTERN = re.compile(rb"\b\d{3}-\d{2}-\d{4}\b")
_SSN_REPLACEMENT = b"[REDACTED_SSN]"

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

# Parked-challenge store. Keyed by request_id so concurrent challenges for
# the same subject do not collide on a single slot.
PARKED_REQUESTS: dict[str, asyncio.Event] = {}

# Side-car metadata kept in lock-step with PARKED_REQUESTS on every mutation
# so the STEPUP audit row can record the original subject/tool even though
# the endpoint is keyed only by request_id.
_PARKED_META: dict[str, dict[str, Any]] = {}

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
    await _audit.init_schema()
    logger.info("PEP up; forwarding to %s via PDP %s", MCP_CORE_URL, PDP_URL)
    try:
        yield
    finally:
        await _client.aclose()
        await _audit.close()


app = FastAPI(title="ZTA-MCP PEP", version="0.7.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "pep"}


# ---- helpers -----------------------------------------------------------------


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
    rpc: dict[str, Any] | None,
    payload_hash: str,
    subject_id: str,
    request_id: str,
) -> SecurityContext:
    method = (rpc or {}).get("method", "") or "<no-method>"
    tool_name: str | None = None
    if method == "tools/call":
        params = (rpc or {}).get("params") or {}
        if isinstance(params, dict):
            tool_name = params.get("name")
    resource_tier = (
        TOOL_RESOURCE_TIER.get(tool_name, "Public") if tool_name else "Public"
    )
    return SecurityContext(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        method=method,
        tool_name=tool_name,
        resource_tier=resource_tier,
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


def _scrub_egress(body: bytes) -> bytes:
    if not body:
        return body
    return _SSN_PATTERN.sub(_SSN_REPLACEMENT, body)


async def _forward(
    request: Request, body: bytes, context: SecurityContext, rpc_id: Any
) -> tuple[Response, float, int]:
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

    scrubbed = _scrub_egress(upstream.content)
    response = Response(
        content=scrubbed,
        status_code=upstream.status_code,
        headers=_filter_headers(dict(upstream.headers)),
        media_type=upstream.headers.get("content-type"),
    )
    return response, latency_ms, upstream.status_code


async def _park_for_stepup(
    request_id: str, subject_id: str, tool_name: str | None
) -> bool:
    """Park until ``/stepup/verify`` arrives for ``request_id``.

    ``try/finally`` guarantees both stores drop this entry on any exit —
    success, timeout, or coroutine cancellation — so no memory leak.
    """
    event = asyncio.Event()
    PARKED_REQUESTS[request_id] = event
    _PARKED_META[request_id] = {
        "subject_id": subject_id,
        "tool_name": tool_name,
        "approved": False,
    }
    logger.info(
        "parking request_id=%s subject=%s tool=%s",
        request_id,
        subject_id,
        tool_name,
    )
    try:
        await asyncio.wait_for(event.wait(), timeout=STEPUP_TIMEOUT_S)
        if not _PARKED_META.get(request_id, {}).get("approved"):
            raise TimeoutError("Step-up not approved")
        return True
    except (asyncio.TimeoutError, TimeoutError):
        return False
    finally:
        # Only evict our own slot — a re-park with the same request_id
        # would have installed a fresh Event we must not clobber.
        if PARKED_REQUESTS.get(request_id) is event:
            PARKED_REQUESTS.pop(request_id, None)
            _PARKED_META.pop(request_id, None)


# ---- audit wrappers ----------------------------------------------------------


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


async def _audit_stepup(
    *,
    request_id: str,
    subject_id: str | None,
    tool_name: str | None,
    decision: str,
    reason: str,
    http_status: int,
) -> None:
    assert _audit is not None
    try:
        await _audit.append_log(
            {
                "subject_id": subject_id or f"unknown:rid={request_id}",
                "action": "STEPUP",
                "decision": decision,
                "resource_tier": None,
                "details": {
                    "request_id": request_id,
                    "tool_name": tool_name,
                    "reason": reason,
                    "http_status": http_status,
                },
            }
        )
    except Exception:
        logger.exception("audit append failed for stepup rid=%s", request_id)


# ---- router ------------------------------------------------------------------


@app.post("/mcp")
@app.get("/mcp")
@app.delete("/mcp")
async def mcp_proxy(request: Request) -> Response:
    assert _client is not None
    body = await request.body()
    rpc = _parse_rpc(body)
    rpc_id = rpc.get("id") if rpc else None

    subject_id = request.headers.get(SUBJECT_HEADER) or "anonymous"
    # Prefer the client-supplied request_id so the agent can reference the
    # same value from the /stepup/verify side-channel; fall back to a
    # server UUID when the header is absent.
    client_rid = request.headers.get(REQUEST_ID_HEADER)
    request_id = client_rid or str(uuid.uuid4())
    payload_hash = hashlib.sha256(body).hexdigest()
    context = _build_context(rpc, payload_hash, subject_id, request_id)

    if context.tool_name in RESTRICTED_TOOLS:
        logger.info(
            "restricted tool attempt request_id=%s subject=%s tool=%s",
            request_id,
            subject_id,
            context.tool_name,
        )

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
        logger.info("PDP denied request_id=%s reason=%s", request_id, reason)
        await _audit_denial(
            subject_id=subject_id,
            context=context,
            reason=reason,
            action="DENY",
        )
        return _rpc_error(403, rpc_id, -32001, f"denied by policy: {reason}")

    stepped_up = False
    if decision == "CHALLENGE":
        released = await _park_for_stepup(
            request_id=request_id,
            subject_id=subject_id,
            tool_name=context.tool_name,
        )
        if not released:
            logger.info(
                "step-up timeout request_id=%s subject=%s",
                request_id,
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
            request_id,
            subject_id,
        )
        stepped_up = True

    if decision not in ("PERMIT", "CHALLENGE"):
        return _rpc_error(502, rpc_id, -32000, f"unexpected PDP decision: {decision}")

    context.decision = "PERMIT"
    response, latency_ms, upstream_status = await _forward(
        request, body, context, rpc_id
    )

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


# ---- step-up endpoint --------------------------------------------------------


class StepupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    secondary_token: str


@app.post("/stepup/verify")
async def stepup_verify(payload: StepupRequest) -> dict[str, str]:
    event = PARKED_REQUESTS.get(payload.request_id)
    if event is None:
        logger.warning(
            "stepup: no parked challenge for request_id=%s", payload.request_id
        )
        await _audit_stepup(
            request_id=payload.request_id,
            subject_id=None,
            tool_name=None,
            decision="DENY",
            reason="No active challenge",
            http_status=404,
        )
        raise HTTPException(
            status_code=404, detail="no pending challenge for request_id"
        )

    meta = _PARKED_META.get(payload.request_id, {})
    subject_id = meta.get("subject_id")
    tool_name = meta.get("tool_name")

    if payload.secondary_token != STEPUP_TOKEN:
        logger.warning(
            "stepup: bad token for request_id=%s subject=%s",
            payload.request_id,
            subject_id,
        )
        await _audit_stepup(
            request_id=payload.request_id,
            subject_id=subject_id,
            tool_name=tool_name,
            decision="DENY",
            reason="Invalid token",
            http_status=401,
        )
        raise HTTPException(status_code=401, detail="invalid secondary token")

    # Mark approval on the meta BEFORE releasing the event so the parked
    # coroutine sees ``approved=True`` as soon as ``event.wait()`` returns.
    # Deletion of both stores happens exclusively in ``_park_for_stepup``'s
    # finally block — a single source of deletion prevents races.
    _PARKED_META.setdefault(payload.request_id, {})["approved"] = True
    event.set()

    logger.info(
        "stepup: released request_id=%s subject=%s",
        payload.request_id,
        subject_id,
    )
    await _audit_stepup(
        request_id=payload.request_id,
        subject_id=subject_id,
        tool_name=tool_name,
        decision="PERMIT",
        reason="Step-up verified",
        http_status=200,
    )
    return {"status": "success"}
