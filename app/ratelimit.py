"""In-memory sliding-window rate limiter (per client IP). Use Redis instead when running several servers."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0):
        self.limit = limit
        self.window = window_seconds
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        recent = self.hits[key]
        while recent and now - recent[0] > self.window:
            recent.popleft()
        if len(recent) >= self.limit:
            return False
        recent.append(now)
        return True

    def retry_after(self, key: str) -> int:
        recent = self.hits.get(key)
        if not recent:
            return 0
        return max(1, int(self.window - (time.monotonic() - recent[0])) + 1)
