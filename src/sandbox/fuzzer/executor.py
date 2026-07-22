"""Worker-side execution handoff for every supported work source."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol

from sandbox.coverage.input import CoverageInputResolver
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.fuzzer.models import (
    CandidateExecutionOutcome,
    SandboxRunContext,
    WorkItem,
    WorkSourceKind,
)
from sandbox.models import RunOutcome, TestCase
from sandbox.mutation.handoff import execute_fork_candidate
from sandbox.mutation.models import MutationCandidateKind, to_test_case
from sandbox.mutation.store import MutationStore


class ExecutionService(Protocol):
    async def run_test_case(
        self,
        case: TestCase,
        *,
        execution_id: str | None = None,
        run_context: SandboxRunContext | None = None,
    ) -> RunOutcome: ...


class CandidateExecutor:
    def __init__(
        self,
        execution_engine: ExecutionService,
        mutation_store: MutationStore,
        *,
        case_source: TemplateCaseSource | None = None,
        replay_engine=None,
        coverage_resolver: CoverageInputResolver | None = None,
        template_seed: int = 42,
    ) -> None:
        self.execution_engine = execution_engine
        self.mutation_store = mutation_store
        self.case_source = case_source or TemplateCaseSource()
        self.replay_engine = replay_engine
        self.coverage_resolver = coverage_resolver
        self.template_seed = template_seed

    async def execute(self, work: WorkItem) -> CandidateExecutionOutcome:
        if not work.execution_id or work.status.value != "leased":
            raise ValueError("candidate executor requires leased work with execution ID")
        started = datetime.now(UTC)
        monotonic_started = time.monotonic()
        source_kind = "week1"
        run_outcome: RunOutcome | None = None
        replay_id = None
        trajectory_id = None
        trajectory_path = None
        error_code = None
        error_message = None
        execution_status = "failed"
        container_removed = True
        score = None
        try:
            if work.source.kind == WorkSourceKind.FORK:
                if self.replay_engine is None:
                    raise RuntimeError("fork work requires a replay engine")
                candidate = self.mutation_store.get_candidate(work.source.candidate_id or "")
                if candidate.candidate_kind != MutationCandidateKind.FORK:
                    raise ValueError("fork work references a non-fork candidate")
                manifest = await execute_fork_candidate(
                    candidate,
                    self.replay_engine,
                    execution_id=work.execution_id,
                    child_replay_id=f"replay-{work.execution_id}",
                    run_context=SandboxRunContext(
                        campaign_id=work.campaign_id,
                        work_item_id=work.work_item_id,
                        attempt=work.attempt,
                    ),
                )
                source_kind = "fork"
                replay_id = manifest.replay_id
                trajectory_id = manifest.trajectory_id
                execution_status = "succeeded"
            else:
                case = self.resolve_case(work)
                metadata = {
                    **case.metadata,
                    "campaign_id": work.campaign_id,
                    "work_item_id": work.work_item_id,
                    "attempt": work.attempt,
                    "work_source": work.source.model_dump(mode="json"),
                }
                if work.source.kind == WorkSourceKind.SOAK_PROBE:
                    metadata["measurement_class"] = "soak_probe"
                case = case.model_copy(update={"metadata": metadata})
                run_outcome = await self.execution_engine.run_test_case(
                    case,
                    execution_id=work.execution_id,
                    run_context=SandboxRunContext(
                        campaign_id=work.campaign_id,
                        work_item_id=work.work_item_id,
                        attempt=work.attempt,
                    ),
                )
                execution_status = run_outcome.execution.status.value
                container_removed = run_outcome.container_removed
                score = run_outcome.score
                error_code = run_outcome.execution.error_code
                error_message = run_outcome.execution.error_message
                if run_outcome.trajectory_path is not None:
                    trajectory_path = str(run_outcome.trajectory_path)
                    if self.coverage_resolver is not None:
                        resolved = self.coverage_resolver.from_trajectory_path(
                            run_outcome.trajectory_path,
                            prompt=case.prompt,
                        )
                        trajectory_id = resolved.trajectory_id
                    else:
                        trajectory_id = work.execution_id
        except Exception as exc:
            error_code = type(exc).__name__
            error_message = str(exc)[:2_000]
            execution_status = "failed"
        finished = datetime.now(UTC)
        return CandidateExecutionOutcome(
            work_item_id=work.work_item_id,
            attempt=work.attempt,
            source=work.source,
            coverage_source_kind=source_kind,
            execution_id=work.execution_id,
            trajectory_id=trajectory_id,
            trajectory_path=trajectory_path,
            replay_id=replay_id,
            execution_status=execution_status,
            score=score,
            container_removed=container_removed,
            started_at=started,
            finished_at=finished,
            duration_ms=max(0, round((time.monotonic() - monotonic_started) * 1_000)),
            error_code=error_code,
            error_message=error_message,
        )

    def resolve_case(self, work: WorkItem) -> TestCase:
        if work.source.kind in {WorkSourceKind.INITIAL_CASE, WorkSourceKind.SOAK_PROBE}:
            return self.case_source.generate(
                work.source.case_id or "",
                seed=self.template_seed,
            )
        candidate = self.mutation_store.get_candidate(work.source.candidate_id or "")
        if candidate.candidate_kind != MutationCandidateKind.PROMPT:
            raise ValueError("prompt work references a non-prompt candidate")
        return to_test_case(candidate)


def classify_outcome(outcome: CandidateExecutionOutcome) -> str:
    if not outcome.container_removed:
        return "systemic_infrastructure"
    if outcome.score and outcome.score.verdict == "infrastructure_error":
        return "transient_infrastructure"
    if outcome.error_code:
        integrity_markers = {
            "TraceIntegrityError",
            "CoverageIntegrityError",
            "FuzzerIntegrityError",
        }
        if outcome.error_code in integrity_markers:
            return "integrity_failure"
        return "transient_infrastructure"
    if outcome.execution_status != "succeeded":
        return "case_failure"
    return "success"
