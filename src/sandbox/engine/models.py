"""Protocols used to keep the execution engine independently testable."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from sandbox.config import SandboxLimits
from sandbox.fuzzer.models import SandboxRunContext
from sandbox.models import ExecutionRequest, ExecutionResult, ScoreResult, TracePage
from sandbox.scheduler.models import SandboxHandle
from sandbox.storage.trajectory_store import CommittedTrajectory


class Scheduler(Protocol):
    async def create(
        self,
        execution_id: str,
        image_ref: str,
        limits: SandboxLimits,
        *,
        run_context: SandboxRunContext | None = None,
    ) -> SandboxHandle: ...

    async def wait_until_ready(self, handle: SandboxHandle) -> None: ...

    async def destroy(self, handle: SandboxHandle) -> None: ...


class Runtime(Protocol):
    async def submit(self, handle: SandboxHandle, request: ExecutionRequest) -> None: ...

    def poll_and_stream_events(
        self,
        handle: SandboxHandle,
        request: ExecutionRequest,
    ) -> AsyncIterator[TracePage]: ...

    async def get_result(
        self,
        handle: SandboxHandle,
        execution_id: str,
    ) -> ExecutionResult: ...


class Scorer(Protocol):
    def score(self, trajectory: CommittedTrajectory) -> ScoreResult: ...
