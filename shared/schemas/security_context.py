"""SecurityContext — the envelope that travels with every authorized request.

Built and signed at the PEP, evaluated by the PDP, verified by the MCP Core.

Schema contract (enforced by Pydantic with ``extra='forbid'``):

    Required
        request_id    : str            # UUID4 assigned by the PEP
        timestamp     : str            # ISO-8601 UTC, used for replay defense
        method        : str            # JSON-RPC method name
        payload_hash  : str            # sha256 hex of the raw body — binds
                                       # the envelope to a specific payload

    Optional
        tool_name     : str | None
        resource_tier : ResourceTier   = "Public"
        subject_id    : str | None     # *** acting principal used by the PDP
                                       # trust scorer; REQUIRED field in the
                                       # schema even when value is None ***
        agent_id      : str | None
        trust_score   : float | None   # stamped by the PEP post-PDP
        decision      : Decision|None  # "PERMIT" | "DENY" | "CHALLENGE"
        signature     : str | None     # hex HMAC-SHA256, applied by the PEP
"""

from __future__ import annotations

from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict

ResourceTier = Literal["Public", "Internal", "Confidential", "Restricted"]

# Decision values MUST include all three. The scorer's CHALLENGE band depends
# on this, and the PEP relies on strict equality against "PERMIT".
Decision = Literal["PERMIT", "DENY", "CHALLENGE"]
_REQUIRED_DECISIONS: frozenset[str] = frozenset({"PERMIT", "DENY", "CHALLENGE"})
assert _REQUIRED_DECISIONS == frozenset(get_args(Decision)), (
    "Decision literal drift: expected PERMIT/DENY/CHALLENGE"
)


class SecurityContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    timestamp: str
    method: str
    payload_hash: str
    tool_name: str | None = None
    resource_tier: ResourceTier = "Public"
    subject_id: str | None = None
    agent_id: str | None = None
    trust_score: float | None = None
    decision: Decision | None = None
    signature: str | None = None

    def to_signable(self) -> dict[str, Any]:
        """Return the context as a dict with the signature field stripped.

        Both signer and verifier must agree on the input bytes; ``signature``
        itself is never part of its own input.
        """
        data = self.model_dump(exclude_none=True)
        data.pop("signature", None)
        return data


# Import-time contract: fail loudly if someone removes a required field.
_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"request_id", "timestamp", "method", "payload_hash"}
)
_DECLARED_FIELDS: frozenset[str] = frozenset(SecurityContext.model_fields)
assert _REQUIRED_FIELDS <= _DECLARED_FIELDS, (
    f"SecurityContext missing required fields: {_REQUIRED_FIELDS - _DECLARED_FIELDS}"
)
assert "subject_id" in _DECLARED_FIELDS, "SecurityContext must declare subject_id"
