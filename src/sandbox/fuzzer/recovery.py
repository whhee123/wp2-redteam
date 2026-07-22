"""Crash reconciliation for leases, completed outcomes, and campaign resources."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sandbox.coverage.events import terminal_kind
from sandbox.errors import TraceIntegrityError
from sandbox.fuzzer.models import (
    CandidateExecutionOutcome,
    CleanupReport,
    FailureKind,
    WorkItem,
    WorkItemStatus,
    WorkSourceKind,
)
from sandbox.fuzzer.store import FuzzerStore
from sandbox.scoring.rule_scorer import RuleBasedScorer
from sandbox.storage.trajectory_store import TrajectoryStore


class CampaignCleaner(Protocol):
    async def cleanup_campaign_orphans(
        self,
        campaign_id: str,
        *,
        active_execution_ids: set[str],
        max_age_seconds: int,
    ) -> CleanupReport: ...


class RecoveryManager:
    def __init__(
        self,
        store: FuzzerStore,
        *,
        scheduler: CampaignCleaner | None = None,
        trajectory_root: Path | None = None,
        scorer: RuleBasedScorer | None = None,
        max_transient_attempts: int = 2,
        recovery_grace_seconds: int = 30,
    ) -> None:
        self.store = store
        self.scheduler = scheduler
        self.trajectory_root = trajectory_root
        self.scorer = scorer or RuleBasedScorer()
        self.max_transient_attempts = max_transient_attempts
        self.recovery_grace_seconds = recovery_grace_seconds

    async def reconcile(self) -> tuple[list[WorkItem], CleanupReport | None]:
        now = datetime.now(UTC)
        for work in self.store.list_work(WorkItemStatus.LEASED):
            if self._recover_committed_trajectory(work, now=now):
                continue
            if work.lease_expires_at is None or work.lease_expires_at > now:
                continue
            if work.attempt <= self.max_transient_attempts:
                self.store.schedule_retry(
                    work.work_item_id,
                    failure_kind=FailureKind.TRANSIENT_INFRASTRUCTURE,
                    error_code="LeaseExpired",
                    delay_seconds=self.recovery_grace_seconds,
                )
            else:
                self.store.finish_work(
                    work.work_item_id,
                    WorkItemStatus.DEAD_LETTER,
                    failure_kind=FailureKind.TRANSIENT_INFRASTRUCTURE,
                    error_code="LeaseAttemptsExhausted",
                )
        self.store.release_due_retries(now=now)
        active = {
            work.execution_id
            for work in self.store.list_work(WorkItemStatus.LEASED)
            if work.execution_id
        }
        cleanup = None
        if self.scheduler is not None:
            cleanup = await self.scheduler.cleanup_campaign_orphans(
                self.store.campaign_id,
                active_execution_ids=active,
                max_age_seconds=self.recovery_grace_seconds,
            )
        return self.store.list_work(WorkItemStatus.EXECUTED), cleanup

    async def cleanup_shutdown_orphans(self) -> CleanupReport | None:
        if self.scheduler is None:
            return None
        return await self.scheduler.cleanup_campaign_orphans(
            self.store.campaign_id,
            active_execution_ids=set(),
            max_age_seconds=0,
        )

    def _recover_committed_trajectory(self, work: WorkItem, *, now: datetime) -> bool:
        if (
            self.trajectory_root is None
            or not work.execution_id
            or not work.lease_token_digest
            or work.source.kind == WorkSourceKind.FORK
        ):
            return False
        path = self.trajectory_root / f"{work.execution_id}.jsonl"
        if not path.is_file():
            return False
        try:
            trajectory = TrajectoryStore.load(path)
            if trajectory.execution_id != work.execution_id:
                raise TraceIntegrityError("recovered trajectory execution_id mismatch")
            status = terminal_kind(trajectory.events)
            score = self.scorer.score(trajectory)
            error_code = None
            error_message = None
        except Exception as exc:
            status = "failed"
            score = None
            error_code = (
                "TraceIntegrityError"
                if isinstance(exc, TraceIntegrityError)
                else type(exc).__name__
            )
            error_message = str(exc)[:2_000]
        outcome = CandidateExecutionOutcome(
            work_item_id=work.work_item_id,
            attempt=work.attempt,
            source=work.source,
            coverage_source_kind="week1",
            execution_id=work.execution_id,
            trajectory_id=work.execution_id if score is not None else None,
            trajectory_path=str(path),
            execution_status=status,
            score=score,
            container_removed=True,
            started_at=now,
            finished_at=now,
            duration_ms=0,
            error_code=error_code,
            error_message=error_message,
        )
        self.store.record_outcome(outcome, lease_token=work.lease_token_digest)
        return True
