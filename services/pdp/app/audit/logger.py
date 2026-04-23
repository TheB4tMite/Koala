"""Per-service re-export for the requested Milestone 5 path.

The canonical implementation lives in :mod:`shared.audit.logger` so that the
PEP can import the same code — cross-service imports from ``services/`` are
not wired through the Dockerfiles; only ``shared/`` is copied into each
image. This module exists so ``services.pdp.app.audit.logger`` resolves per
the original task brief.
"""

from shared.audit.logger import AuditLogger, GENESIS_HASH, logger_from_env

__all__ = ["AuditLogger", "GENESIS_HASH", "logger_from_env"]
