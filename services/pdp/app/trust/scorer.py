"""Dynamic trust scorer — Milestone 3 (post-audit).

A subject's score starts at ``1.0`` and is penalized by ``penalty`` for every
request inside the rolling ``window_s`` seconds beyond ``threshold``. State is
a thread-safe in-memory dict keyed by ``subject_id``.

ARCHITECTURE WARNING
--------------------
This in-memory dictionary is a **temporary mock**. It MUST be replaced with a
centralized Policy Information Point (PIP) like Redis to ensure consistent
trust scoring across multiple PDP replicas. Running more than one PDP
instance with this backend will produce divergent scores per replica and
defeat horizontal scaling — violating the ZTA requirement that the PDP be
stateless.

Memory hygiene
--------------
When a subject's sliding-window deque empties after GC, the key is removed
from the dict. Without this, one-shot or low-rate subjects would leak keys
forever, creating an OOM vulnerability on long-running PDPs.
"""

# TODO(zta-pip): Replace the ``_events`` dict with a centralized PIP (Redis
# recommended). The scorer interface — ``record_and_score`` / ``peek`` /
# ``reset`` — is deliberately narrow so this swap is mechanical. Until then
# the PDP MUST run as a single replica.

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class ScoreResult:
    score: float
    count: int  # requests observed for this subject inside the window


class TrustScorer:
    """Sliding-window rate-limit-based trust scorer."""

    def __init__(
        self,
        *,
        window_s: float = 60.0,
        threshold: int = 5,
        penalty: float = 0.2,
    ) -> None:
        self._window_s = window_s
        self._threshold = threshold
        self._penalty = penalty
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def record_and_score(self, subject_id: str) -> ScoreResult:
        """Record a request for ``subject_id`` and return the updated score."""
        now = time.monotonic()
        cutoff = now - self._window_s

        with self._lock:
            events = self._events[subject_id]
            events.append(now)
            while events and events[0] < cutoff:
                events.popleft()
            count = len(events)
            # Defensive: with a fresh append this branch is unreachable today,
            # but it keeps the invariant "empty deque => key evicted" local to
            # every mutation site so future refactors can't leak keys.
            if not events:
                del self._events[subject_id]

        excess = max(0, count - self._threshold)
        score = max(0.0, min(1.0, 1.0 - self._penalty * excess))
        return ScoreResult(score=score, count=count)

    def peek(self, subject_id: str) -> int:
        """Return the current in-window count without recording a new event.

        GCs expired events as a side effect and evicts the subject key when
        its deque drains — this is the hot path that recovers memory from
        subjects who have gone quiet.
        """
        now = time.monotonic()
        cutoff = now - self._window_s

        with self._lock:
            events = self._events.get(subject_id)
            if events is None:
                return 0
            while events and events[0] < cutoff:
                events.popleft()
            if not events:
                del self._events[subject_id]
                return 0
            return len(events)

    def sweep(self) -> int:
        """Evict all subjects whose windows have fully expired.

        Callable from a periodic task; returns the number of keys removed.
        Needed because only ``record_and_score`` and ``peek`` would otherwise
        observe a given subject, and a subject that never comes back would
        leak its last-known deque until process restart.
        """
        now = time.monotonic()
        cutoff = now - self._window_s
        removed = 0

        with self._lock:
            for subject_id in list(self._events.keys()):
                events = self._events[subject_id]
                while events and events[0] < cutoff:
                    events.popleft()
                if not events:
                    del self._events[subject_id]
                    removed += 1
        return removed

    def reset(self, subject_id: str | None = None) -> None:
        """Drop state for ``subject_id`` (or all subjects when ``None``)."""
        with self._lock:
            if subject_id is None:
                self._events.clear()
            else:
                self._events.pop(subject_id, None)


DEFAULT_SCORER = TrustScorer()
