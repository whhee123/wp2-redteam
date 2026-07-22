"""Execution handoff for accepted replay-fork candidates."""

from __future__ import annotations

from typing import Any, Protocol

from sandbox.mutation.exceptions import MutationTargetError
from sandbox.mutation.models import MutationCandidate, MutationCandidateKind
from sandbox.replay.models import ForkInjection, ForkSuffixMode


class ReplayForkService(Protocol):
    def checkpoints(self, replay_id: str) -> list[Any]: ...

    async def fork(self, *args, **kwargs): ...


async def execute_fork_candidate(
    candidate: MutationCandidate,
    replay_engine: ReplayForkService,
    *,
    execution_id: str | None = None,
    child_replay_id: str | None = None,
    run_context: Any | None = None,
):
    if candidate.candidate_kind != MutationCandidateKind.FORK or candidate.fork is None:
        raise MutationTargetError("candidate is not a replay fork")
    specification = candidate.fork
    checkpoint = next(
        (
            item
            for item in replay_engine.checkpoints(specification.parent_replay_id)
            if item.checkpoint_id == specification.checkpoint_id
        ),
        None,
    )
    if checkpoint is None or not checkpoint.recoverable:
        raise MutationTargetError("fork checkpoint is missing or not recoverable")
    if specification.injection_type not in checkpoint.allowed_injection_types:
        raise MutationTargetError("fork injection type is not allowed at checkpoint")
    return await replay_engine.fork(
        specification.parent_replay_id,
        specification.checkpoint_id,
        ForkInjection(
            type=specification.injection_type,
            content=specification.content,
        ),
        suffix_mode=ForkSuffixMode(specification.suffix_mode),
        operator=f"mutator:{candidate.operator_id}:{candidate.mutation_id}",
        execution_id=execution_id,
        child_replay_id=child_replay_id,
        run_context=run_context,
    )
