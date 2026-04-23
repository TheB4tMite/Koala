"""AuditEvent — the row schema for the tamper-evident audit log.

Every security-relevant action (PDP decisions, PEP tool executions) produces
one ``AuditEvent``. Rows are linked via ``prev_hash`` / ``record_hash`` so
that silently deleting or mutating any row breaks the chain from that point
onward and is detectable by re-hashing.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Action = Literal["AUTHORIZE", "TOOL_CALL", "STEPUP", "DENY"]


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str                         # UUID4 as string
    timestamp: str                  # ISO-8601 UTC
    subject_id: str
    action: Action
    decision: str | None = None     # "PERMIT" / "CHALLENGE" / "DENY" / None
    resource_tier: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str                  # 64-char hex, "0"*64 at genesis
    record_hash: str                # 64-char hex

    def to_signable(self) -> dict[str, Any]:
        """Event bytes that the ``record_hash`` is computed over.

        The hash input is ``prev_hash + canonical_json(to_signable())``; the
        ``record_hash`` and ``prev_hash`` themselves are never part of the
        input (``record_hash`` is the output; ``prev_hash`` is prepended as
        its own string so the chain is order-sensitive).
        """
        data = self.model_dump()
        data.pop("prev_hash", None)
        data.pop("record_hash", None)
        return data
