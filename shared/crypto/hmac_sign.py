"""HMAC-SHA256 signing for SecurityContext envelopes.

The PDP signs; the MCP Core verifies. Both sides must agree on the canonical
serialization of the context dict — we use ``json.dumps`` with sorted keys and
no whitespace so the byte sequence is deterministic regardless of insertion
order.
"""

from __future__ import annotations

import hmac
import json
from hashlib import sha256
from typing import Any


def _canonical(context: dict[str, Any]) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_context(context_dict: dict[str, Any], secret: str) -> str:
    """Return a hex-encoded HMAC-SHA256 signature for ``context_dict``."""
    mac = hmac.new(secret.encode("utf-8"), _canonical(context_dict), sha256)
    return mac.hexdigest()


def verify_signature(
    context_dict: dict[str, Any], signature: str, secret: str
) -> bool:
    """Constant-time verify a signature produced by :func:`sign_context`."""
    expected = sign_context(context_dict, secret)
    return hmac.compare_digest(expected, signature)
