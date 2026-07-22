"""Bounded worker queues and deterministic result ordering."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from sandbox.fuzzer.models import CandidateExecutionOutcome, WorkItem


class DeterministicResultBuffer:
    def __init__(self, *, first_sequence: int = 1, max_size: int = 32) -> None:
        self.next_sequence = first_sequence
        self.max_size = max_size
        self._items: dict[int, tuple[CandidateExecutionOutcome, str]] = {}

    def add(
        self,
        sequence: int,
        outcome: CandidateExecutionOutcome,
        lease_token: str,
    ) -> None:
        if sequence < self.next_sequence:
            return
        if sequence not in self._items and len(self._items) >= self.max_size:
            raise RuntimeError("deterministic result buffer capacity exceeded")
        self._items[sequence] = (outcome, lease_token)

    def pop_ready(self) -> list[tuple[CandidateExecutionOutcome, str]]:
        ready = []
        while self.next_sequence in self._items:
            ready.append(self._items.pop(self.next_sequence))
            self.next_sequence += 1
        return ready

    def __len__(self) -> int:
        return len(self._items)


async def execution_worker(
    worker_id: str,
    execution_queue: asyncio.Queue[tuple[WorkItem, str] | None],
    result_queue: asyncio.Queue[tuple[WorkItem, CandidateExecutionOutcome, str]],
    execute: Callable[[WorkItem], Awaitable[CandidateExecutionOutcome]],
) -> None:
    while True:
        item = await execution_queue.get()
        try:
            if item is None:
                return
            work, token = item
            outcome = await execute(work)
            await result_queue.put((work, outcome, token))
        finally:
            execution_queue.task_done()
