"""MCP Core — Milestone 3.

Deny-by-default gate. Every request to a non-whitelisted path must carry a
valid ``X-Koala-Context`` whose:

  * HMAC signature verifies under the shared secret,
  * ``timestamp`` is within ``[now - MAX_AGE_S, now + MAX_SKEW_S]`` — this
    neutralizes replay attacks by bounding the window in which a captured
    envelope is usable,
  * ``payload_hash`` equals ``sha256(raw body)`` — preventing header reuse
    against a different payload.

Only ``/health`` is exempt.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp

from shared.crypto.hmac_sign import verify_signature

SIGNING_SECRET = os.getenv("KOALA_SIGNING_SECRET", "koala_secret_dev")
CONTEXT_HEADER = "x-koala-context"
MCP_PATH = "/mcp"
WHITELISTED_PATHS: frozenset[str] = frozenset({"/health"})

MAX_AGE_S = 60.0   # reject envelopes older than this
MAX_SKEW_S = 5.0   # tolerate this much clock drift into the future

logger = logging.getLogger("mcp_core")
logging.basicConfig(level=logging.INFO)

mcp = FastMCP(
    name="zta-mcp-core",
    instructions="Dummy MCP server for ZTA wrapper integration tests.",
    host="0.0.0.0",
    port=8080,
    streamable_http_path=MCP_PATH,
    stateless_http=True,
)


@mcp.tool()
def get_weather(location: str) -> dict[str, str | float]:
    """Return a fake weather report for ``location``."""
    return {
        "location": location,
        "temperature_c": 21.5,
        "conditions": "sunny",
        "source": "mock",
    }


@mcp.tool()
def read_dummy_file() -> str:
    """Return the contents of a hard-coded dummy file."""
    return (
        "Project Koala — dummy file.\n"
        "This content is served by the MCP Core for integration tests.\n"
    )


def _rpc_error(code: int, message: str, status: int = 401) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": code, "message": message},
        },
    )


def _decode_header(raw: str) -> dict[str, Any] | None:
    try:
        decoded = base64.b64decode(raw.encode("ascii"), validate=True)
        payload = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _parse_ts(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        ts = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


async def _health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "mcp_core"})


class SignatureMiddleware(BaseHTTPMiddleware):
    """Deny-by-default gate. Whitelist for liveness; everything else signed."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        secret: str,
        whitelist: frozenset[str],
        max_age_s: float = MAX_AGE_S,
        max_skew_s: float = MAX_SKEW_S,
    ) -> None:
        super().__init__(app)
        self._secret = secret
        self._whitelist = whitelist
        self._max_age_s = max_age_s
        self._max_skew_s = max_skew_s

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if request.url.path in self._whitelist:
            return await call_next(request)

        raw = request.headers.get(CONTEXT_HEADER)
        if not raw:
            logger.warning(
                "reject: missing %s header path=%s",
                CONTEXT_HEADER,
                request.url.path,
            )
            return _rpc_error(-32000, "missing X-Koala-Context header")

        context = _decode_header(raw)
        if context is None:
            logger.warning("reject: malformed context header")
            return _rpc_error(-32000, "malformed X-Koala-Context header")

        signature = context.pop("signature", None)
        if not isinstance(signature, str) or not signature:
            logger.warning("reject: no signature in context")
            return _rpc_error(-32000, "context missing signature")

        if not verify_signature(context, signature, self._secret):
            logger.warning(
                "reject: bad signature request_id=%s", context.get("request_id")
            )
            return _rpc_error(-32000, "invalid context signature")

        # Replay window check — must come AFTER signature verification so an
        # attacker can't craft fake timestamps to probe the clock.
        ts = _parse_ts(context.get("timestamp"))
        if ts is None:
            logger.warning("reject: unparseable timestamp")
            return _rpc_error(-32000, "invalid context timestamp")

        now = datetime.now(timezone.utc)
        age_s = (now - ts).total_seconds()
        if age_s > self._max_age_s:
            logger.warning(
                "reject: stale envelope age=%.2fs request_id=%s",
                age_s,
                context.get("request_id"),
            )
            return _rpc_error(-32000, "context timestamp too old (replay?)")
        if age_s < -self._max_skew_s:
            logger.warning(
                "reject: future envelope skew=%.2fs request_id=%s",
                -age_s,
                context.get("request_id"),
            )
            return _rpc_error(-32000, "context timestamp in the future")

        expected_hash = context.get("payload_hash")
        if not isinstance(expected_hash, str) or not expected_hash:
            logger.warning("reject: context missing payload_hash")
            return _rpc_error(-32000, "context missing payload_hash")

        body = await request.body()
        actual_hash = hashlib.sha256(body).hexdigest()
        if not _hmac.compare_digest(actual_hash, expected_hash):
            logger.warning(
                "reject: payload hash mismatch request_id=%s",
                context.get("request_id"),
            )
            return _rpc_error(-32000, "payload hash mismatch")

        # Re-inject body for the downstream MCP handler (reading request.body
        # above consumed the ASGI receive stream).
        request._body = body  # type: ignore[attr-defined]

        logger.info(
            "permit request_id=%s method=%s tool=%s age=%.2fs",
            context.get("request_id"),
            context.get("method"),
            context.get("tool_name"),
            age_s,
        )
        return await call_next(request)


def _build_app() -> ASGIApp:
    app = mcp.streamable_http_app()
    app.routes.append(Route("/health", _health, methods=["GET"]))
    app.add_middleware(
        SignatureMiddleware,
        secret=SIGNING_SECRET,
        whitelist=WHITELISTED_PATHS,
    )
    return app


if __name__ == "__main__":
    uvicorn.run(_build_app(), host="0.0.0.0", port=8080)
