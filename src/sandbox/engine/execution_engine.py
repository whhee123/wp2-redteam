"""End-to-end red-team execution orchestration."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sandbox.config import WeekOneConfig
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.engine.models import Runtime, Scheduler, Scorer
from sandbox.fuzzer.models import SandboxRunContext
from sandbox.identifiers import validate_execution_id
from sandbox.models import (
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    RunOutcome,
    TestCase,
)
from sandbox.scoring.rule_scorer import RuleBasedScorer
from sandbox.storage.trajectory_store import TrajectoryStore
from sandbox.versions import AGENT_VERSION


class RedTeamExecutionEngine:
    """Own the test lifecycle while delegating container details to the scheduler."""

    def __init__(
        self,
        config: WeekOneConfig,
        scheduler: Scheduler,
        runtime: Runtime,
        scorer: Scorer,
        case_source: TemplateCaseSource | None = None,
    ) -> None:
        self.config = config
        self.scheduler = scheduler
        self.runtime = runtime
        self.scorer = scorer
        self.case_source = case_source or TemplateCaseSource()

    async def run_case(self, template_id: str, *, seed: int | None = None) -> RunOutcome:
        case = self.case_source.generate(
            template_id,
            seed=self.config.seed if seed is None else seed,
        )
        return await self.run_test_case(case)

    async def run_test_case(
        self,
        case: TestCase,
        *,
        execution_id: str | None = None,
        run_context: SandboxRunContext | None = None,
    ) -> RunOutcome:
        """Execute an already validated case through the standard sandbox lifecycle."""
        execution_id = execution_id or f"exec-{uuid4().hex}"
        validate_execution_id(execution_id)
        request = ExecutionRequest(
            execution_id=execution_id,
            case_id=case.case_id,
            prompt=case.prompt,
            max_steps=self.config.max_steps,
            timeout_seconds=self.config.sandbox.execution_timeout_seconds,
            metadata=case.metadata,
            seed=case.seed,
            scenario_id=case.scenario_id,
            agent_version=AGENT_VERSION,
            model=self.config.model,
        )
        store = TrajectoryStore(
            self.config.tracing.output_dir,
            execution_id,
            max_events=self.config.tracing.max_events,
        )
        handle = None
        result: ExecutionResult | None = None
        score = None
        trajectory_path: Path | None = None
        # Scheduler.create() cleans any partial container before it raises.
        removed = True
        failure: Exception | None = None

        try:
            if run_context is None:
                handle = await self.scheduler.create(
                    execution_id,
                    self.config.sandbox.image,
                    self.config.sandbox.limits,
                )
            else:
                handle = await self.scheduler.create(
                    execution_id,
                    self.config.sandbox.image,
                    self.config.sandbox.limits,
                    run_context=run_context,
                )
            removed = False
            request = request.model_copy(update={"image_digest": handle.image_digest})
            await self.scheduler.wait_until_ready(handle)
            await self.runtime.submit(handle, request)
            async for page in self.runtime.poll_and_stream_events(handle, request):
                store.append(page.events)
            result = await self.runtime.get_result(handle, execution_id)
            trajectory = store.commit(
                final_sequence=result.final_sequence,
                trace_count=result.trace_count,
            )
            trajectory_path = trajectory.path
            score = self.scorer.score(trajectory)
        except Exception as exc:
            failure = exc
            result = ExecutionResult(
                execution_id=execution_id,
                status=ExecutionStatus.FAILED,
                error_code=type(exc).__name__,
                error_message=str(exc)[:2_000],
                trace_count=len(store.events),
                final_sequence=store.events[-1].sequence if store.events else None,
            )
            score = RuleBasedScorer.infrastructure_error(execution_id, str(exc)[:2_000])
        finally:
            if handle is not None:
                try:
                    await self.scheduler.destroy(handle)
                    removed = True
                except Exception as cleanup_exc:
                    removed = False
                    failure = cleanup_exc
                    result = ExecutionResult(
                        execution_id=execution_id,
                        status=ExecutionStatus.FAILED,
                        error_code=type(cleanup_exc).__name__,
                        error_message=str(cleanup_exc)[:2_000],
                        trace_count=len(store.events),
                        final_sequence=store.events[-1].sequence if store.events else None,
                    )
                    score = RuleBasedScorer.infrastructure_error(
                        execution_id,
                        f"container cleanup failed: {cleanup_exc}",
                    )

        if result is None:
            message = str(failure) if failure else "execution produced no result"
            result = ExecutionResult(
                execution_id=execution_id,
                status=ExecutionStatus.FAILED,
                error_code="InfrastructureError",
                error_message=message,
            )
        return RunOutcome(
            execution=result,
            trajectory_path=trajectory_path,
            score=score,
            container_removed=removed,
        )
