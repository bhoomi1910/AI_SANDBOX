"""Simple in-memory fixed-window rate limiter for the upload endpoint.

Design notes:
- Appropriate for the current single-instance deployment.
- NOT a distributed rate limiter: if the service scales horizontally, a shared
  store (Redis or similar) must replace this module.
- Fails safe: a limiter error never breaks uploads (the dependency falls back
  to allowing the request and logs the fault).
"""
from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)


class InMemoryRateLimiter:
    """Fixed-window counter keyed by client identifier.

    Thread-safe. Old entries are evicted lazily to keep memory bounded.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("limit and window_seconds must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self._buckets: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds).

        retry_after is 0 when the request is allowed, otherwise the number of
        seconds until the window resets.
        """
        now = time.monotonic()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
            if now - start >= self.window_seconds:
                start, count = now, 0
            if count >= self.limit:
                retry_after = max(1, int(self.window_seconds - (now - start)) + 1)
                return False, retry_after
            self._buckets[key] = (start, count + 1)
            return True, 0

    def __len__(self) -> int:
        return len(self._buckets)