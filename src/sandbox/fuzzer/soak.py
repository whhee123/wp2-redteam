"""Infrastructure soak probes that do not affect fuzzing coverage or corpus."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

from sandbox.fuzzer.executor import CandidateExecutor, classify_outcome
from sandbox.fuzzer.models import (
    CampaignStatus,
    CampaignStopReason,
    FailureKind,
    WorkItem,
    WorkItemStatus,
    WorkSourceKind,
    WorkSourceRef,
    work_item_id_for,
)
from sandbox.fuzzer.recovery import RecoveryManager
from sandbox.fuzzer.store import FuzzerStore


class SoakProbeRegistry:
    """Locked, harmless templates used only to measure infrastructure health."""

    version = "soak-probes-v1"
    case_ids = ("benign-control-001", "write-file-001", "internal-api-001")

    def source(self, sequence: int) -> WorkSourceRef:
        case_id = self.case_ids[sequence % len(self.case_ids)]
        return WorkSourceRef(
            kind=WorkSourceKind.SOAK_PROBE,
            probe_id=f"{self.version}-{sequence:08d}",
            case_id=case_id,
        )


class SoakRunner:
    def __init__(
        self,
        store: FuzzerStore,
        executor: CandidateExecutor,
        recovery: RecoveryManager,
        *,
        lease_seconds: int,
        heartbeat_seconds: int,
        registry: SoakProbeRegistry | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.store = store
        self.executor = executor
        self.recovery = recovery
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.registry = registry or SoakProbeRegistry()
        self.monotonic = monotonic
        self.sleep = sleep

    async def run(
        self,
        *,
        duration_seconds: float,
        probe_interval_seconds: float,
        max_probes: int | None = None,
    ) -> CampaignStatus:
        if duration_seconds <= 0 or probe_interval_seconds <= 0:
            raise ValueError("soak duration and probe interval must be positive")
        recovered, cleanup = await self.recovery.reconcile()
        if cleanup and cleanup.failures:
            self.store.transition_campaign(CampaignStatus.FAILED)
            return CampaignStatus.FAILED
        for work in recovered:
            self._commit_probe(work)
        self._start_or_resume()

        started = self.monotonic()
        next_probe_at = started
        existing_probes = [
            work for work in self.store.list_work() if work.source.kind == WorkSourceKind.SOAK_PROBE
        ]
        terminal_statuses = {
            WorkItemStatus.COMMITTED,
            WorkItemStatus.FAILED,
            WorkItemStatus.DEAD_LETTER,
            WorkItemStatus.SKIPPED,
        }
        completed_probes = sum(work.status in terminal_statuses for work in existing_probes)
        next_probe_sequence = len(existing_probes)
        try:
            while True:
                status = self.store.status()
                if status == CampaignStatus.PAUSE_REQUESTED:
                    self.store.transition_campaign(CampaignStatus.PAUSED)
                    return CampaignStatus.PAUSED
                if status == CampaignStatus.STOP_REQUESTED:
                    self.store.transition_campaign(
                        CampaignStatus.COMPLETED,
                        reason=CampaignStopReason.USER_REQUESTED,
                    )
                    return CampaignStatus.COMPLETED
                if self.monotonic() - started >= duration_seconds or (
                    max_probes is not None and completed_probes >= max_probes
                ):
                    self.store.transition_campaign(
                        CampaignStatus.COMPLETED,
                        reason=CampaignStopReason.BUDGET_EXHAUSTED,
                    )
                    return CampaignStatus.COMPLETED

                delay = next_probe_at - self.monotonic()
                if delay > 0:
                    await self.sleep(min(delay, 0.25))
                    continue
                queued_probes = [
                    work
                    for work in self.store.list_work(WorkItemStatus.QUEUED)
                    if work.source.kind == WorkSourceKind.SOAK_PROBE
                ]
                if queued_probes:
                    work = queued_probes[0]
                else:
                    source = self.registry.source(next_probe_sequence)
                    work, _created = self.store.create_work(
                        WorkItem(
                            work_item_id=work_item_id_for(self.store.campaign_id, source),
                            campaign_id=self.store.campaign_id,
                            source=source,
                            priority=1.0,
                            created_iteration=self.store.iteration(),
                        )
                    )
                    next_probe_sequence += 1
                leased = self.store.lease_next(
                    "soak-worker",
                    lease_seconds=self.lease_seconds,
                )
                if leased is None or leased[0].work_item_id != work.work_item_id:
                    raise RuntimeError("soak probe lease order was not deterministic")
                leased_work, token = leased
                outcome = await self._execute_with_heartbeat(leased_work, token)
                executed = self.store.record_outcome(outcome, lease_token=token)
                self._commit_probe(executed)
                self.store.advance_iteration()
                completed_probes += 1
                next_probe_at += probe_interval_seconds
        finally:
            self.store.add_active_runtime(max(0.0, self.monotonic() - started))

    def _start_or_resume(self) -> None:
        status = self.store.status()
        if status == CampaignStatus.CREATED:
            self.store.transition_campaign(CampaignStatus.BOOTSTRAPPING)
            self.store.transition_campaign(CampaignStatus.RUNNING)
        elif status == CampaignStatus.PAUSED:
            self.store.transition_campaign(CampaignStatus.RUNNING)
        elif status not in {CampaignStatus.RUNNING, CampaignStatus.PAUSE_REQUESTED}:
            raise ValueError(f"campaign cannot enter soak from {status.value}")

    async def _execute_with_heartbeat(self, work: WorkItem, token: str):
        task = asyncio.create_task(self.executor.execute(work))
        while True:
            done, _pending = await asyncio.wait(
                {task},
                timeout=self.heartbeat_seconds,
            )
            if done:
                return task.result()
            self.store.renew_lease(
                work.work_item_id,
                token,
                lease_seconds=self.lease_seconds,
            )

    def _commit_probe(self, work: WorkItem) -> None:
        outcome = self.store.latest_outcome(work.work_item_id)
        if outcome is None:
            raise RuntimeError("executed soak probe is missing its outcome")
        classification = classify_outcome(outcome)
        if classification == "success":
            self.store.finish_work(work.work_item_id, WorkItemStatus.COMMITTED)
            return
        failure = FailureKind(classification)
        target = (
            WorkItemStatus.FAILED
            if failure == FailureKind.CASE_FAILURE
            else WorkItemStatus.DEAD_LETTER
        )
        self.store.finish_work(
            work.work_item_id,
            target,
            failure_kind=failure,
            error_code=outcome.error_code,
        )
