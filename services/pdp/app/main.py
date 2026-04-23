"""PDP (Policy Decision Point) — Milestone 4.

Evaluates a ``SecurityContext`` against a dynamic trust score and returns a
decision (``PERMIT`` / ``CHALLENGE`` / ``DENY``). A background task sweeps
expired entries out of the scorer's in-memory store every 60 seconds so that
idle subjects don't leak memory.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from app.trust.scorer import DEFAULT_SCORER, TrustScorer
from shared.schemas.security_context import Decision, SecurityContext

PERMIT_THRESHOLD = 0.8
CHALLENGE_THRESHOLD = 0.4
GC_INTERVAL_S = 60.0

logger = logging.getLogger("pdp")
logging.basicConfig(level=logging.INFO)

_scorer: TrustScorer = DEFAULT_SCORER


async def _gc_loop() -> None:
    """Drain expired entries from the trust-score store on a fixed cadence."""
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
            # A crashing GC must not kill the PDP. Log and keep looping.
            logger.exception("trust-scorer gc: iteration failed")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_gc_loop(), name="trust-scorer-gc")
    logger.info("PDP up; gc interval=%.0fs", GC_INTERVAL_S)
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="ZTA-MCP PDP", version="0.5.0", lifespan=lifespan)


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


def _decide(score: float, count: int) -> tuple[Decision, str]:
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
    subject = _resolve_subject(context)
    result = _scorer.record_and_score(subject)
    decision, reason = _decide(result.score, result.count)
    return AuthorizeResponse(
        decision=decision,
        trust_score=result.score,
        reason=reason,
    )
