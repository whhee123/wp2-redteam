"""Rolling failure circuit breaker for campaign infrastructure health."""

from __future__ import annotations

import math
from collections import deque

from sandbox.fuzzer.models import FailureKind


class SystemicFailureCircuitBreaker:
    def __init__(self, *, window_size: int, threshold: float) -> None:
        self.window_size = window_size
        self.threshold = threshold
        self.failure_limit = max(1, math.ceil(window_size * threshold))
        self._observations: deque[bool] = deque(maxlen=window_size)

    def record(self, classification: str) -> bool:
        """Record one terminal attempt and return whether the breaker is open."""

        if classification == FailureKind.INTEGRITY_FAILURE.value:
            return True
        self._observations.append(
            classification == FailureKind.SYSTEMIC_INFRASTRUCTURE.value
        )
        return sum(self._observations) >= self.failure_limit

    @property
    def systemic_failures(self) -> int:
        return sum(self._observations)

