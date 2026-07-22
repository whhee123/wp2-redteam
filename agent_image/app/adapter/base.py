"""Framework-independent Agent adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from app.protocol import ExecutionRequest, TraceEvent


class AgentAdapter(ABC):
    @abstractmethod
    async def execute(self, request: ExecutionRequest) -> AsyncIterator[TraceEvent]:
        raise NotImplementedError

