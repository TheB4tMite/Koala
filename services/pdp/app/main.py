"""PDP (Policy Decision Point) — Milestone 5.

Evaluates a ``SecurityContext`` against a dynamic trust score and returns a
decision. On every decision the PDP appends a tamper-evident audit event to
the shared hash-chain log. A background task sweeps expired entries from the
in-memory trust-scorer store every 60 seconds.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from app.trust.scorer import DEFAULT_SCORER, TrustScorer
from shared.audit.logger import AuditLogger, logger_from_env
from shared.schemas.security_context import Decision, SecurityContext

PERMIT_THRESHOLD = 0.8
CHALLENGE_THRESHOLD = 0.4
GC_INTERVAL_S = 60.0

logger = logging.getLogger("pdp")
logging.basicConfig(level=logging.INFO)

_scorer: TrustScorer = DEFAULT_SCORER
_audit: AuditLogger | None = None


async def _gc_loop() -> None:
    while True:
        try:
            await asyncio.sleep(GC_INTERVAL_S)
            removed = _scorer.sweep()
            if removed:
                logger.info("trust-scorer gc: evicted %d idle subjects", removed)
        except asyncio.CancelledError:
            logger.info("trust-scorer gc: stopping")
            raise
        except Exception:
            logger.exception("trust-scorer gc: iteration failed")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _audit
    _audit = logger_from_env(service="pdp")
    await _audit.connect()
    await _audit.init_schema()

    gc_task = asyncio.create_task(_gc_loop(), name="trust-scorer-gc")
    logger.info("PDP up; gc interval=%.0fs", GC_INTERVAL_S)
    try:
        yield
    finally:
        gc_task.cancel()
        try:
            await gc_task
        except asyncio.CancelledError:
            pass
        await _audit.close()


app = FastAPI(title="ZTA-MCP PDP", version="0.6.0", lifespan=lifespan)


class AuthorizeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    trust_score: float
    reason: str


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "pdp"}


def _resolve_subject(context: SecurityContext) -> str:
    return context.subject_id or context.agent_id or "anonymous"


def _decide(score: float, count: int, tier: str | None) -> tuple[Decision, str]:
    # Restricted-tier resources always require a step-up challenge, regardless
    # of how well-behaved the subject has been. Only an outright rate-limit
    # collapse (score below the CHALLENGE floor) escalates that to DENY.
    if tier == "Restricted":
        if score < CHALLENGE_THRESHOLD:
            return (
                "DENY",
                f"restricted tier + rate exceeded: rate={count}/min trust={score:.2f}",
            )
        return (
            "CHALLENGE",
            f"restricted tier requires step-up (trust={score:.2f} rate={count}/min)",
        )

    if score >= PERMIT_THRESHOLD:
        return "PERMIT", f"ok: trust={score:.2f} rate={count}/min"
    if score >= CHALLENGE_THRESHOLD:
        return (
            "CHALLENGE",
            f"step-up required: rate={count}/min trust={score:.2f}",
        )
    return "DENY", f"rate limit exceeded: rate={count}/min trust={score:.2f}"


@app.post("/authorize", response_model=AuthorizeResponse)
async def authorize(context: SecurityContext) -> AuthorizeResponse:
    assert _audit is not None, "audit logger not initialized"
    subject = _resolve_subject(context)
    result = _scorer.record_and_score(subject)
    decision, reason = _decide(result.score, result.count, context.resource_tier)

    await _audit.append_log(
        {
            "subject_id": subject,
            "action": "AUTHORIZE",
            "decision": decision,
            "resource_tier": context.resource_tier,
            "details": {
                "request_id": context.request_id,
                "method": context.method,
                "tool_name": context.tool_name,
                "trust_score": result.score,
                "rate_in_window": result.count,
                "reason": reason,
            },
        }
    )

    return AuthorizeResponse(
        decision=decision,
        trust_score=result.score,
        reason=reason,
    )
