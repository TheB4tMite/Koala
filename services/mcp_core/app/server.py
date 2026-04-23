"""MCP Core — Healthcare Data Assistant demo build.

Hosts three tools that simulate a clinical-decision assistant:

    * get_drug_interactions  (Public)     — reference lookup, low risk.
    * get_patient_record     (Internal)   — PHI read; returns a fake SSN
                                            the PEP DLP layer will scrub.
    * prescribe_medication   (Restricted) — privileged write; the PDP
                                            forces a step-up challenge on
                                            this resource tier.

The signature / timestamp / payload-hash middleware is *unchanged* from
Milestone 3 — only the tools and the in-memory dataset are demo-specific.
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

MAX_AGE_S = 60.0
MAX_SKEW_S = 5.0

logger = logging.getLogger("mcp_core")
logging.basicConfig(level=logging.INFO)

mcp = FastMCP(
    name="zta-mcp-core",
    instructions=(
        "Healthcare Data Assistant mock MCP server. "
        "Exposes drug-interaction lookup, patient record retrieval, "
        "and a privileged prescribing endpoint."
    ),
    host="0.0.0.0",
    port=8080,
    streamable_http_path=MCP_PATH,
    stateless_http=True,
)


# ---- Mock clinical dataset ---------------------------------------------------

_PATIENTS: dict[str, dict[str, Any]] = {
    "P001": {
        "patient_id": "P001",
        "name": "Alice Walker",
        "ssn": "123-45-6789",
        "date_of_birth": "1984-06-12",
        "medications": ["lisinopril 10mg"],
        "allergies": ["penicillin"],
    },
    "P002": {
        "patient_id": "P002",
        "name": "Bob Martinez",
        "ssn": "987-65-4321",
        "date_of_birth": "1972-11-30",
        "medications": ["metformin 500mg", "atorvastatin 20mg"],
        "allergies": [],
    },
    "P003": {
        "patient_id": "P003",
        "name": "Clara Nguyen",
        "ssn": "555-11-2233",
        "date_of_birth": "1995-02-18",
        "medications": [],
        "allergies": ["sulfa"],
    },
}

_INTERACTIONS: dict[tuple[str, str], dict[str, str]] = {
    ("aspirin", "warfarin"): {
        "severity": "MAJOR",
        "effect": "Synergistic bleeding risk.",
    },
    ("ibuprofen", "warfarin"): {
        "severity": "MAJOR",
        "effect": "NSAID + anticoagulant increases GI bleed risk; avoid.",
    },
    ("amoxicillin", "warfarin"): {
        "severity": "MODERATE",
        "effect": "Potentiation of anticoagulant effect; monitor INR.",
    },
    ("lisinopril", "potassium"): {
        "severity": "MODERATE",
        "effect": "Additive hyperkalemia risk; monitor serum potassium.",
    },
}


def _canonical_pair(drug_a: str, drug_b: str) -> tuple[str, str]:
    a, b = drug_a.strip().lower(), drug_b.strip().lower()
    return (a, b) if a <= b else (b, a)


# ---- Tools -------------------------------------------------------------------


@mcp.tool()
def get_drug_interactions(drug_a: str, drug_b: str) -> dict[str, Any]:
    """Return a reference-library interaction summary for two drugs.

    Public tier: no PHI, no writes.
    """
    key = _canonical_pair(drug_a, drug_b)
    info = _INTERACTIONS.get(key)
    if info is None:
        return {
            "drug_a": key[0],
            "drug_b": key[1],
            "severity": "NONE",
            "effect": "No known major interaction in this formulary.",
            "source": "Koala mock formulary v1.0",
        }
    return {
        "drug_a": key[0],
        "drug_b": key[1],
        "severity": info["severity"],
        "effect": info["effect"],
        "source": "Koala mock formulary v1.0",
    }


@mcp.tool()
def get_patient_record(patient_id: str) -> dict[str, Any]:
    """Return the full patient record including demographics and PHI.

    Internal tier: returns a synthetic SSN so the PEP's DLP layer has
    something to scrub on the way out.
    """
    patient = _PATIENTS.get(patient_id.strip().upper())
    if patient is None:
        return {
            "error": "not_found",
            "message": f"No patient record for id={patient_id!r}",
        }
    # Return a shallow copy so downstream mutation doesn't leak into state.
    return {
        "patient_id": patient["patient_id"],
        "name": patient["name"],
        "ssn": patient["ssn"],
        "date_of_birth": patient["date_of_birth"],
        "medications": list(patient["medications"]),
        "allergies": list(patient["allergies"]),
    }


@mcp.tool()
def prescribe_medication(patient_id: str, medication: str) -> dict[str, Any]:
    """Append a new prescription to a patient's record.

    Restricted tier: the PDP forces a step-up challenge before the PEP
    will forward this call to the Core.
    """
    pid = patient_id.strip().upper()
    patient = _PATIENTS.get(pid)
    if patient is None:
        return {
            "status": "error",
            "message": f"No patient record for id={patient_id!r}",
        }
    med = medication.strip()
    if not med:
        return {"status": "error", "message": "medication must be non-empty"}
    patient["medications"].append(med)
    return {
        "status": "prescribed",
        "patient_id": pid,
        "medication": med,
        "active_medications": list(patient["medications"]),
        "prescribed_at": datetime.now(timezone.utc).isoformat(),
    }


# ---- Signature middleware (unchanged from M3) --------------------------------


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
