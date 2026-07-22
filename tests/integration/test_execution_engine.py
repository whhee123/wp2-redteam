from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from sandbox.config import TraceConfig, WeekOneConfig
from sandbox.engine.execution_engine import RedTeamExecutionEngine
from sandbox.models import (
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    TraceEvent,
    TracePage,
)
from sandbox.scheduler.models import SandboxHandle
from sandbox.scoring.rule_scorer import RuleBasedScorer


class FakeScheduler:
    def __init__(self) -> None:
        self.destroyed = False

    async def create(self, execution_id, image_ref, limits):
        return SandboxHandle(
            execution_id=execution_id,
            container_id="container-1",
            runtime_url="http://127.0.0.1:12345",
            capability_token="token",
            image_digest="sha256:test",
            scheduler_instance_id="scheduler-1",
        )

    async def wait_until_ready(self, handle) -> None:
        return None

    async def destroy(self, handle) -> None:
        self.destroyed = True


class FakeRuntime:
    def __init__(self, *, fail_after_submit: bool = False) -> None:
        self.fail_after_submit = fail_after_submit

    async def submit(self, handle, request: ExecutionRequest) -> None:
        return None

    async def poll_and_stream_events(
        self,
        handle,
        request: ExecutionRequest,
    ) -> AsyncIterator[TracePage]:
        if self.fail_after_submit:
            raise RuntimeError("simulated Runtime crash")
        events = [
            TraceEvent(
                execution_id=request.execution_id,
                sequence=0,
                event_type="execution_started",
                source="runtime",
            ),
            TraceEvent(
                execution_id=request.execution_id,
                sequence=1,
                event_type="security_violation",
                source="policy",
                data={"risk_category": "unauthorized_file_read"},
            ),
            TraceEvent(
                execution_id=request.execution_id,
                sequence=2,
                event_type="execution_finished",
                source="runtime",
            ),
        ]
        yield TracePage(events=events, next_after_sequence=2, terminal=True, final_sequence=2)

    async def get_result(self, handle, execution_id: str) -> ExecutionResult:
        return ExecutionResult(
            execution_id=execution_id,
            status=ExecutionStatus.SUCCEEDED,
            trace_count=3,
            final_sequence=2,
        )


async def test_engine_completes_score_then_cleanup(tmp_path: Path) -> None:
    scheduler = FakeScheduler()
    config = WeekOneConfig(tracing=TraceConfig(output_dir=tmp_path, pull_interval_seconds=0))
    engine = RedTeamExecutionEngine(config, scheduler, FakeRuntime(), RuleBasedScorer())
    outcome = await engine.run_case("path-absolute-001")
    assert outcome.execution.status == ExecutionStatus.SUCCEEDED
    assert outcome.score.verdict == "blocked_attempt"
    assert outcome.trajectory_path.exists()
    assert outcome.container_removed is True
    assert scheduler.destroyed is True


async def test_engine_cleans_container_after_runtime_failure(tmp_path: Path) -> None:
    scheduler = FakeScheduler()
    config = WeekOneConfig(tracing=TraceConfig(output_dir=tmp_path, pull_interval_seconds=0))
    engine = RedTeamExecutionEngine(
        config,
        scheduler,
        FakeRuntime(fail_after_submit=True),
        RuleBasedScorer(),
    )
    outcome = await engine.run_case("path-absolute-001")
    assert outcome.execution.status == ExecutionStatus.FAILED
    assert outcome.score.verdict == "infrastructure_error"
    assert outcome.container_removed is True
    assert scheduler.destroyed is True



async def test_engine_executes_prebuilt_test_case_through_same_lifecycle(
    tmp_path: Path,
) -> None:
    scheduler = FakeScheduler()
    config = WeekOneConfig(tracing=TraceConfig(output_dir=tmp_path, pull_interval_seconds=0))
    engine = RedTeamExecutionEngine(config, scheduler, FakeRuntime(), RuleBasedScorer())
    case = engine.case_source.generate("path-absolute-001", seed=42).model_copy(
        update={"metadata": {"mutation_id": "sha256:mutation"}}
    )

    outcome = await engine.run_test_case(case)

    assert outcome.execution.status == ExecutionStatus.SUCCEEDED
    assert outcome.trajectory_path is not None
    assert outcome.trajectory_path.exists()
    assert outcome.container_removed is True
