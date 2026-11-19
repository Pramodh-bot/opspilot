"""A small thread-safe circuit breaker used to protect calls to the LLM provider."""

import threading
import time
from collections.abc import Callable
from enum import Enum
from typing import TypeVar

T = TypeVar("T")


class BreakerState(str, Enum):
    closed = "closed"
    half_open = "half_open"
    open = "open"


class CircuitOpenError(RuntimeError):
    """Raised instead of calling the protected function while the circuit is open."""


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._opened_at = 0.0
        self._state = BreakerState.closed
        self._probe_in_flight = False

    @property
    def state(self) -> BreakerState:
        with self._lock:
            return self._current_state()

    def _current_state(self) -> BreakerState:
        if self._state is BreakerState.open and self._clock() - self._opened_at >= self.recovery_seconds:
            self._state = BreakerState.half_open
            self._probe_in_flight = False
        return self._state

    def call(self, fn: Callable[[], T]) -> T:
        with self._lock:
            state = self._current_state()
            if state is BreakerState.open:
                raise CircuitOpenError("circuit open")
            if state is BreakerState.half_open:
                if self._probe_in_flight:
                    raise CircuitOpenError("circuit half-open, probe in flight")
                self._probe_in_flight = True
        try:
            result = fn()
        except Exception:
            self._on_failure()
            raise
        self._on_success()
        return result

    def _on_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._probe_in_flight = False
            self._state = BreakerState.closed

    def _on_failure(self) -> None:
        with self._lock:
            self._probe_in_flight = False
            self._failures += 1
            if self._state is BreakerState.half_open or self._failures >= self.failure_threshold:
                self._state = BreakerState.open
                self._opened_at = self._clock()

    def gauge_value(self) -> int:
        return {BreakerState.closed: 0, BreakerState.half_open: 1, BreakerState.open: 2}[self.state]
