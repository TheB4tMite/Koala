"""Tamper-evident audit logger.

Canonical implementation. Both PEP and PDP import this module. (The file at
``services/pdp/app/audit/logger.py`` is a thin re-export kept for the
per-service path documented in the Milestone 5 task brief — the actual code
cannot live under ``services/pdp`` because ``services/pep`` needs to import
it too, and each service's Docker image only copies its own app/ plus
``shared/``.)

Chain construction
------------------
Every append runs inside a Postgres transaction that first takes a per-chain
``pg_advisory_xact_lock``. Inside the lock we:

    1. read the ``record_hash`` of the most recent row (or the genesis
       hash if the table is empty),
    2. compute ``record_hash = sha256(prev_hash || canonical_json(event))``,
    3. insert the new row.

The advisory lock serializes concurrent appenders across PEP and PDP so the
chain remains strictly linear even under load.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import asyncpg

from shared.schemas.audit_event import AuditEvent

GENESIS_HASH = "0" * 64
# Stable 32-bit int used as the advisory-lock key for the audit chain.
_CHAIN_LOCK_ID = 0x4B4F414C  # 'KOAL'

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_logs (
    seq          BIGSERIAL PRIMARY KEY,
    id           UUID        NOT NULL UNIQUE,
    timestamp    TIMESTAMPTZ NOT NULL,
    subject_id   TEXT        NOT NULL,
    action       TEXT        NOT NULL,
    decision     TEXT,
    resource_tier TEXT,
    details      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash    CHAR(64)    NOT NULL,
    record_hash  CHAR(64)    NOT NULL UNIQUE,
    inserted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_logs(subject_id);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_logs(action);
"""

logger = logging.getLogger("audit")


def _canonical(event: dict[str, Any]) -> bytes:
    """Deterministic JSON bytes for hashing."""
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_record_hash(prev_hash: str, event: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(_canonical(event))
    return h.hexdigest()


class AuditLogger:
    """Async hash-chained audit logger backed by Postgres."""

    def __init__(self, dsn: str, *, service: str) -> None:
        self._dsn = dsn
        self._service = service
        self._pool: asyncpg.Pool | None = None

    async def connect(
        self, *, retries: int = 15, backoff_s: float = 1.0
    ) -> None:
        """Create the connection pool, retrying until Postgres is ready."""
        last_exc: Exception | None = None
        for attempt in range(1, retries + 1):
            try:
                self._pool = await asyncpg.create_pool(
                    self._dsn, min_size=1, max_size=5
                )
                logger.info(
                    "audit logger connected (service=%s attempt=%d)",
                    self._service,
                    attempt,
                )
                return
            except (OSError, asyncpg.PostgresError) as exc:
                last_exc = exc
                logger.warning(
                    "audit logger connect attempt %d/%d failed: %s",
                    attempt,
                    retries,
                    exc,
                )
                await asyncio.sleep(backoff_s)
        raise RuntimeError(
            f"could not connect to audit DB after {retries} attempts"
        ) from last_exc

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def init_schema(self) -> None:
        assert self._pool is not None, "connect() must run before init_schema()"
        async with self._pool.acquire() as conn:
            await conn.execute(_SCHEMA_SQL)
        logger.info("audit_logs table ready (service=%s)", self._service)

    async def append_log(self, event_data: dict[str, Any]) -> AuditEvent:
        """Append a new event to the chain and return the persisted row.

        ``event_data`` may omit ``id`` / ``timestamp`` / ``details``; they are
        defaulted. ``prev_hash`` and ``record_hash`` are computed here and
        MUST NOT be supplied by the caller.
        """
        assert self._pool is not None, "connect() must run before append_log()"

        payload = dict(event_data)
        payload.setdefault("id", str(uuid.uuid4()))
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        payload.setdefault("details", {})
        payload.pop("prev_hash", None)
        payload.pop("record_hash", None)

        # Canonicalize sub-values that would otherwise break determinism
        # (asyncpg would accept a dict for JSONB, but we hash the dict so
        # the in-Python representation must match what gets stored).
        details = payload.get("details") or {}
        if not isinstance(details, dict):
            raise TypeError("details must be a dict")
        payload["details"] = details

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock($1)", _CHAIN_LOCK_ID
                )
                row = await conn.fetchrow(
                    "SELECT record_hash FROM audit_logs ORDER BY seq DESC LIMIT 1"
                )
                prev_hash = row["record_hash"] if row else GENESIS_HASH
                record_hash = _compute_record_hash(prev_hash, payload)

                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        id, timestamp, subject_id, action, decision,
                        resource_tier, details, prev_hash, record_hash
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
                    """,
                    uuid.UUID(payload["id"]),
                    datetime.fromisoformat(payload["timestamp"]),
                    payload["subject_id"],
                    payload["action"],
                    payload.get("decision"),
                    payload.get("resource_tier"),
                    json.dumps(payload["details"], sort_keys=True),
                    prev_hash,
                    record_hash,
                )

        event = AuditEvent(
            id=payload["id"],
            timestamp=payload["timestamp"],
            subject_id=payload["subject_id"],
            action=payload["action"],
            decision=payload.get("decision"),
            resource_tier=payload.get("resource_tier"),
            details=payload["details"],
            prev_hash=prev_hash,
            record_hash=record_hash,
        )
        logger.info(
            "audit[%s] %s subject=%s decision=%s hash=%s",
            self._service,
            event.action,
            event.subject_id,
            event.decision,
            event.record_hash[:12],
        )
        return event


def logger_from_env(service: str) -> AuditLogger:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    return AuditLogger(dsn, service=service)
