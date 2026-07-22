"""Single-writer coverage-guided fuzzing campaign coordinator."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path

from sandbox.coverage.input import CoverageInputResolver
from sandbox.coverage.models import CoverageInput, CoverageResult
from sandbox.coverage.store import CoverageStore
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.fuzzer.circuit_breaker import SystemicFailureCircuitBreaker
from sandbox.fuzzer.config import FuzzerConfig
from sandbox.fuzzer.corpus import CorpusPolicy
from sandbox.fuzzer.energy import EnergyScheduler
from sandbox.fuzzer.exceptions import FuzzerIntegrityError
from sandbox.fuzzer.executor import CandidateExecutor, classify_outcome
from sandbox.fuzzer.metrics import CampaignMetrics
from sandbox.fuzzer.models import (
    CampaignManifest,
    CampaignStatus,
    CampaignStopReason,
    CandidateExecutionOutcome,
    FailureKind,
    SeedOrigin,
    SeedRecord,
    SeedStatus,
    WorkItem,
    WorkItemStatus,
    WorkSourceKind,
    WorkSourceRef,
    fuzzer_digest,
    seed_id_for,
    work_item_id_for,
)
from sandbox.fuzzer.queue import execution_worker
from sandbox.fuzzer.recovery import RecoveryManager
from sandbox.fuzzer.seed_pool import SeedPool
from sandbox.models import TestCase
from sandbox.mutation.feedback import MutationFeedbackBuilder
from sandbox.mutation.models import MutationCandidate, MutationCandidateKind
from sandbox.mutation.mutator import SemanticMutator
from sandbox.mutation.normalizer import prompt_digest
from sandbox.mutation.store import MutationStore


@dataclass(frozen=True)
class EnqueueResult:
    created_count: int
    duplicate_count: int
    rejected_count: int


def initialize_campaign(
    store,
    config: FuzzerConfig,
    manifest: CampaignManifest,
    case_source: TemplateCaseSource,
    initial_case_ids: list[str],
) -> None:
    """Create locked campaign state without requiring Docker to be available."""

    if not initial_case_ids:
        raise ValueError("campaign requires at least one initial case")
    store.initialize(manifest)
    for template_id in dict.fromkeys(initial_case_ids):
        case = case_source.generate(template_id, seed=config.random_seed)
        seed = SeedRecord(
            seed_id=seed_id_for(case, origin=SeedOrigin.TEMPLATE),
            origin=SeedOrigin.TEMPLATE,
            case=case,
            mutation_depth=0,
            prompt_sha256=prompt_digest(case.prompt),
        )
        store.save_seed(seed)
        source = WorkSourceRef(kind=WorkSourceKind.INITIAL_CASE, case_id=template_id)
        store.create_work(
            WorkItem(
                work_item_id=work_item_id_for(config.campaign_id, source),
                campaign_id=config.campaign_id,
                source=source,
                priority=1.0,
                created_iteration=0,
            )
        )


class FuzzingEngine:
    def __init__(
        self,
        config: FuzzerConfig,
        *,
        store,
        mutation_store: MutationStore,
        coverage_store: CoverageStore,
        mutator: SemanticMutator,
        feedback_builder: MutationFeedbackBuilder,
        executor: CandidateExecutor,
        recovery: RecoveryManager | None = None,
        case_source: TemplateCaseSource | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.mutation_store = mutation_store
        self.coverage_store = coverage_store
        self.mutator = mutator
        self.feedback_builder = feedback_builder
        self.executor = executor
        self.recovery = recovery or RecoveryManager(
            store,
            max_transient_attempts=config.retry.max_transient_attempts,
            recovery_grace_seconds=config.leases.recovery_grace_seconds,
        )
        self.case_source = case_source or TemplateCaseSource()
        self.seed_pool = SeedPool(
            store,
            config.seed_pool,
            max_depth=config.energy.max_mutation_depth,
        )
        self.energy = EnergyScheduler(config.energy, store, config.campaign_id)
        self.corpus = CorpusPolicy()
        self.failure_circuit = SystemicFailureCircuitBreaker(
            window_size=config.retry.systemic_failure_window,
            threshold=config.retry.systemic_failure_threshold,
        )
        self.metrics = CampaignMetrics(store)
        self.execution_queue: asyncio.Queue[tuple[WorkItem, str] | None] = asyncio.Queue(
            maxsize=config.concurrency.execution_queue_size
        )
        self.result_queue: asyncio.Queue[tuple[WorkItem, CandidateExecutionOutcome, str]] = (
            asyncio.Queue(maxsize=config.concurrency.result_queue_size)
        )
        self._pending_results: dict[int, tuple[CandidateExecutionOutcome, str]] = {}
        self._throughput_inflight: dict[str, tuple[WorkItem, str]] = {}
        self._throughput_dispatch_count = 0
        self._throughput_last_heartbeat = time.monotonic()
        self._next_commit_sequence = self._find_next_commit_sequence()

    def create(self, manifest: CampaignManifest, initial_case_ids: list[str]) -> None:
        initialize_campaign(
            self.store,
            self.config,
            manifest,
            self.case_source,
            initial_case_ids,
        )

    async def run(self) -> CampaignStatus:
        status = self.store.status()
        if status in {CampaignStatus.COMPLETED, CampaignStatus.FAILED}:
            return status
        recovered, cleanup = await self.recovery.reconcile()
        if cleanup and cleanup.failures:
            raise FuzzerIntegrityError("campaign orphan cleanup failed")
        for work in recovered:
            outcome = self.store.latest_outcome(work.work_item_id)
            if outcome and work.dispatch_sequence:
                self._pending_results[work.dispatch_sequence] = (outcome, "recovered")
        if status == CampaignStatus.CREATED:
            self.store.transition_campaign(CampaignStatus.BOOTSTRAPPING)
        elif status == CampaignStatus.PAUSED:
            self.store.transition_campaign(CampaignStatus.RUNNING)

        workers = [
            asyncio.create_task(
                execution_worker(
                    f"worker-{index + 1}",
                    self.execution_queue,
                    self.result_queue,
                    self.executor.execute,
                )
            )
            for index in range(self.config.concurrency.sandbox_workers)
        ]
        started = time.monotonic()
        persisted_runtime = float(self.store.campaign_values()["active_runtime_seconds"])
        try:
            while True:
                current = self.store.status()
                if current == CampaignStatus.PAUSE_REQUESTED:
                    if await self._drain_throughput_for_shutdown():
                        continue
                    self.store.transition_campaign(CampaignStatus.PAUSED)
                    break
                if current == CampaignStatus.STOP_REQUESTED:
                    if await self._drain_throughput_for_shutdown():
                        continue
                    self._skip_unleased_work()
                    self.store.transition_campaign(
                        CampaignStatus.COMPLETED,
                        reason=CampaignStopReason.USER_REQUESTED,
                    )
                    break
                if self._budget_exhausted(persisted_runtime + time.monotonic() - started):
                    if await self._drain_throughput_for_shutdown():
                        continue
                    self._skip_unleased_work()
                    self.store.transition_campaign(
                        CampaignStatus.COMPLETED,
                        reason=CampaignStopReason.BUDGET_EXHAUSTED,
                    )
                    break

                self.store.release_due_retries()
                if self.config.scheduling.mode == "throughput":
                    dispatched = await self._execute_throughput_tick(allow_lease=True)
                else:
                    dispatched = await self._execute_available_wave()
                if dispatched:
                    self._drain_commits()
                    self._finish_bootstrap_if_ready()
                    if self.config.scheduling.mode == "deterministic_rounds":
                        continue
                else:
                    self._drain_commits()
                    self._finish_bootstrap_if_ready()

                if self.store.status() == CampaignStatus.BOOTSTRAPPING:
                    if self.store.list_work(WorkItemStatus.RETRY_WAIT):
                        await asyncio.sleep(0.05)
                        continue
                    self.store.transition_campaign(
                        CampaignStatus.FAILED,
                        reason=CampaignStopReason.NO_ELIGIBLE_SEEDS,
                    )
                    break

                if self._budget_exhausted(
                    persisted_runtime + time.monotonic() - started
                ):
                    continue
                if (
                    self.config.scheduling.mode == "throughput"
                    and self._throughput_feedback_lag()
                    >= self.config.scheduling.max_feedback_lag_work_items
                ):
                    await asyncio.sleep(0.05)
                    continue
                created = await self._generate_next_wave()
                if created:
                    continue
                if self._has_pending_work():
                    await asyncio.sleep(0.05)
                    continue
                no_progress = int(self.store.campaign_values()["generation_no_progress"])
                if (
                    self.config.budget.stop_on_stagnation
                    and no_progress >= self.config.budget.stagnation_window
                ):
                    self.store.transition_campaign(
                        CampaignStatus.COMPLETED,
                        reason=CampaignStopReason.STAGNATED,
                    )
                    break
                next_iteration = self.seed_pool.next_cooldown_iteration()
                if next_iteration is not None:
                    self.store.advance_iteration(next_iteration)
                    self.seed_pool.reactivate_due(next_iteration)
                    continue
                self.store.transition_campaign(
                    CampaignStatus.COMPLETED,
                    reason=CampaignStopReason.NO_ELIGIBLE_SEEDS,
                )
                break
        finally:
            elapsed = max(0.0, time.monotonic() - started)
            self.store.add_active_runtime(elapsed)
            shutdown_error: Exception | None = None
            try:
                await self._shutdown_workers(workers)
            except Exception as exc:
                shutdown_error = exc
            try:
                cleanup = await asyncio.wait_for(
                    self.recovery.cleanup_shutdown_orphans(),
                    timeout=self.config.shutdown.cleanup_timeout_seconds,
                )
                if cleanup is not None and cleanup.failures:
                    shutdown_error = FuzzerIntegrityError(
                        f"campaign cleanup failed for {len(cleanup.failures)} resources"
                    )
            except Exception as exc:
                shutdown_error = shutdown_error or exc
            coverage = self.coverage_store.snapshot(include_heatmap=False)
            snapshot = self.metrics.snapshot(
                coverage,
                active_runtime_seconds=persisted_runtime + elapsed,
                queue_length=self.execution_queue.qsize(),
                active_workers=0,
            )
            self.metrics.write(snapshot)
            if shutdown_error is not None:
                if self.store.status() != CampaignStatus.FAILED:
                    self.store.transition_campaign(
                        CampaignStatus.FAILED,
                        reason=CampaignStopReason.SYSTEMIC_INFRASTRUCTURE_FAILURE,
                        audit_data={"phase": "shutdown_cleanup"},
                    )
                raise FuzzerIntegrityError("campaign shutdown cleanup failed") from shutdown_error
        return self.store.status()

    def request_pause(self) -> None:
        self.store.transition_campaign(CampaignStatus.PAUSE_REQUESTED)

    def request_stop(self) -> None:
        self.store.transition_campaign(CampaignStatus.STOP_REQUESTED)

    async def _shutdown_workers(self, workers: list[asyncio.Task]) -> None:
        try:
            async with asyncio.timeout(self.config.shutdown.graceful_timeout_seconds):
                for _ in workers:
                    await self.execution_queue.put(None)
                await self.execution_queue.join()
                await asyncio.gather(*workers, return_exceptions=True)
                return
        except TimeoutError:
            for worker in workers:
                worker.cancel()
        try:
            await asyncio.wait_for(
                asyncio.gather(*workers, return_exceptions=True),
                timeout=self.config.shutdown.cleanup_timeout_seconds,
            )
        except TimeoutError as exc:
            raise FuzzerIntegrityError(
                "campaign workers did not stop within cleanup timeout"
            ) from exc

    async def _drain_throughput_for_shutdown(self) -> bool:
        if (
            self.config.scheduling.mode != "throughput"
            or not self._throughput_inflight
        ):
            return False
        await self._execute_throughput_tick(allow_lease=False)
        self._drain_commits()
        self._finish_bootstrap_if_ready()
        return bool(self._throughput_inflight)

    async def _execute_throughput_tick(self, *, allow_lease: bool) -> int:
        activity = 0
        workers = self.config.concurrency.sandbox_workers
        while (
            allow_lease
            and len(self._throughput_inflight) < workers
            and self._remaining_execution_budget() > 0
        ):
            self._throughput_dispatch_count += 1
            worker_id = f"worker-{(self._throughput_dispatch_count - 1) % workers + 1}"
            item = self.store.lease_next(
                worker_id,
                lease_seconds=self.config.leases.lease_seconds,
            )
            if item is None:
                break
            work, token = item
            self._throughput_inflight[work.work_item_id] = item
            await self.execution_queue.put(item)
            activity += 1

        if not self._throughput_inflight:
            return activity
        await self._renew_throughput_leases_if_due()
        elapsed = time.monotonic() - self._throughput_last_heartbeat
        timeout = max(0.01, self.config.leases.heartbeat_seconds - elapsed)
        try:
            completed = await asyncio.wait_for(self.result_queue.get(), timeout=timeout)
        except TimeoutError:
            await self._renew_throughput_leases_if_due(force=True)
            return activity

        self._record_throughput_result(completed)
        activity += 1
        while True:
            try:
                completed = self.result_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._record_throughput_result(completed)
            activity += 1
        await self._renew_throughput_leases_if_due()
        return activity

    def _record_throughput_result(
        self,
        completed: tuple[WorkItem, CandidateExecutionOutcome, str],
    ) -> None:
        work, outcome, token = completed
        try:
            active = self._throughput_inflight.pop(work.work_item_id, None)
            if active is None or active[1] != token:
                raise FuzzerIntegrityError("throughput result has no matching active lease")
            executed = self.store.record_outcome(outcome, lease_token=token)
            if executed.dispatch_sequence is None:
                raise FuzzerIntegrityError("executed work is missing dispatch sequence")
            self._pending_results[executed.dispatch_sequence] = (outcome, token)
        finally:
            self.result_queue.task_done()

    async def _renew_throughput_leases_if_due(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if (
            not force
            and now - self._throughput_last_heartbeat
            < self.config.leases.heartbeat_seconds
        ):
            return
        for work, token in self._throughput_inflight.values():
            self.store.renew_lease(
                work.work_item_id,
                token,
                lease_seconds=self.config.leases.lease_seconds,
            )
        self._throughput_last_heartbeat = now

    def _throughput_feedback_lag(self) -> int:
        return len(self._throughput_inflight) + len(self._pending_results)

    async def _execute_available_wave(self) -> int:
        leased: list[tuple[WorkItem, str]] = []
        limit = min(
            self.config.concurrency.sandbox_workers,
            self._remaining_execution_budget(),
        )
        for index in range(limit):
            item = self.store.lease_next(
                f"worker-{index + 1}",
                lease_seconds=self.config.leases.lease_seconds,
            )
            if item is None:
                break
            leased.append(item)
            await self.execution_queue.put(item)
        heartbeat_stop = asyncio.Event()
        heartbeat = asyncio.create_task(self._heartbeat_leases(leased, heartbeat_stop))
        completed: list[tuple[WorkItem, CandidateExecutionOutcome, str]] = []
        try:
            for _ in leased:
                completed.append(await self.result_queue.get())
        finally:
            heartbeat_stop.set()
            await heartbeat
        for _work, outcome, token in completed:
            try:
                executed = self.store.record_outcome(outcome, lease_token=token)
                assert executed.dispatch_sequence is not None
                self._pending_results[executed.dispatch_sequence] = (outcome, token)
            finally:
                self.result_queue.task_done()
        return len(leased)

    async def _heartbeat_leases(
        self,
        leased: list[tuple[WorkItem, str]],
        stop: asyncio.Event,
    ) -> None:
        if not leased:
            return
        while True:
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self.config.leases.heartbeat_seconds,
                )
                return
            except TimeoutError:
                for work, token in leased:
                    self.store.renew_lease(
                        work.work_item_id,
                        token,
                        lease_seconds=self.config.leases.lease_seconds,
                    )

    def _drain_commits(self) -> None:
        while self._next_commit_sequence in self._pending_results:
            outcome, _token = self._pending_results.pop(self._next_commit_sequence)
            terminal = self._commit_outcome(outcome)
            if not terminal:
                return
            self._next_commit_sequence += 1

    def _commit_outcome(self, outcome: CandidateExecutionOutcome) -> bool:
        work = self.store.get_work(outcome.work_item_id)
        classification = classify_outcome(outcome)
        circuit_open = self.failure_circuit.record(classification)
        if classification != "success":
            return self._commit_failure(
                work,
                outcome,
                classification,
                circuit_open=circuit_open,
            )
        if work.source.kind == WorkSourceKind.SOAK_PROBE:
            self.store.finish_work(work.work_item_id, WorkItemStatus.COMMITTED)
            return True
        coverage_input = self._coverage_input(work, outcome)
        coverage = self.coverage_store.evaluate(coverage_input)
        work = self.store.update_executed_trajectory(
            work.work_item_id,
            trajectory_id=coverage.trajectory_id,
            trajectory_path=outcome.trajectory_path,
        )

        if work.source.kind == WorkSourceKind.INITIAL_CASE:
            current_seed = self._initial_seed(work.source.case_id or "")
            activated = self._activate_seed(current_seed, coverage)
            parent_update = activated
            promoted = None
        else:
            if not work.parent_seed_id:
                raise FuzzerIntegrityError("derived work is missing parent seed")
            current_seed = self.store.get_seed(work.parent_seed_id)
            parent_update = self._parent_after_result(current_seed, coverage)
            promoted = self._promoted_seed(work, coverage, prompt=coverage_input.prompt)
        known_verdicts = self.store.observed_verdicts(coverage.behavior_profile_hash)
        decision = self.corpus.evaluate(
            coverage,
            outcome.score,
            previous_verdicts=known_verdicts,
        )
        evidence_seed = promoted or parent_update
        corpus_entry = (
            self.corpus.build_entry(
                campaign_id=self.config.campaign_id,
                iteration=self.store.iteration(),
                seed=evidence_seed,
                work=work,
                coverage=coverage,
                score=outcome.score,
                decision=decision,
            )
            if decision.retain
            else None
        )
        observation = self.corpus.build_observation(
            campaign_id=self.config.campaign_id,
            iteration=self.store.iteration(),
            seed_id=evidence_seed.seed_id,
            work=work,
            coverage=coverage,
            score=outcome.score,
        )
        self.store.commit_observation(
            work.work_item_id,
            observation,
            corpus_entry=corpus_entry,
            parent_seed=parent_update,
            promoted_seed=promoted,
        )
        return True

    def _commit_failure(
        self,
        work: WorkItem,
        outcome: CandidateExecutionOutcome,
        classification: str,
        *,
        circuit_open: bool,
    ) -> bool:
        failure = FailureKind(classification)
        if work.parent_seed_id:
            self.seed_pool.record_child_result(
                work.parent_seed_id,
                interesting=False,
                successful=False,
                infrastructure_failure=failure
                in {FailureKind.TRANSIENT_INFRASTRUCTURE, FailureKind.SYSTEMIC_INFRASTRUCTURE},
                iteration=self.store.iteration(),
            )
        if failure == FailureKind.TRANSIENT_INFRASTRUCTURE and (
            work.attempt <= self.config.retry.max_transient_attempts
        ):
            delay = min(
                self.config.retry.initial_backoff_seconds * 2 ** max(0, work.attempt - 1),
                self.config.retry.max_backoff_seconds,
            )
            self.store.schedule_retry(
                work.work_item_id,
                failure_kind=failure,
                error_code=outcome.error_code or "TransientInfrastructure",
                delay_seconds=delay,
            )
            return False
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
        should_pause = failure == FailureKind.INTEGRITY_FAILURE or (
            failure == FailureKind.SYSTEMIC_INFRASTRUCTURE and circuit_open
        )
        if should_pause and self.store.status() in {
            CampaignStatus.RUNNING,
            CampaignStatus.BOOTSTRAPPING,
        }:
            self.store.transition_campaign(
                CampaignStatus.PAUSE_REQUESTED,
                reason=CampaignStopReason.SYSTEMIC_INFRASTRUCTURE_FAILURE,
            )
        return True

    async def _generate_next_wave(self) -> int:
        iteration = self.store.iteration()
        seed = self.seed_pool.select(iteration)
        if seed is None:
            self.store.record_generation_progress(created_count=0)
            return 0
        snapshot = self.coverage_store.snapshot(include_heatmap=False)
        coverage = self._coverage_for_seed(seed)
        mutation_seed = self.seed_pool.to_mutation_seed(seed, coverage)
        feedback = self.feedback_builder.build(
            mutation_seed,
            snapshot,
            schedule_weights=self.coverage_store.schedule_weights(),
            history=self.mutation_store.snapshot(),
        )
        decision = self.energy.assign(seed, feedback, snapshot, iteration=iteration)
        self.seed_pool.record_selection(seed.seed_id, decision.assigned_energy)
        remaining = self._remaining_execution_budget()
        pending = self._pending_work_count()
        requested = min(
            decision.assigned_energy,
            self.config.concurrency.max_pending_work_items - pending,
            remaining,
        )
        if requested <= 0:
            return 0
        batch = await self.mutator.mutate(
            mutation_seed,
            feedback,
            requested,
            random_seed=self._iteration_seed(iteration),
        )
        result = self._enqueue_candidates(batch.accepted, seed, iteration)
        self.seed_pool.record_generation_result(
            seed.seed_id,
            generated_candidates=batch.generated_count,
            new_work_items=result.created_count,
            iteration=iteration,
            no_progress_threshold=self.config.scheduling.generation_no_progress_threshold,
        )
        self.store.record_generation_progress(created_count=result.created_count)
        self.store.advance_iteration()
        return result.created_count

    def _enqueue_candidates(
        self,
        candidates: list[MutationCandidate],
        seed: SeedRecord,
        iteration: int,
    ) -> EnqueueResult:
        created = duplicates = rejected = 0
        for candidate in candidates:
            expected_kind = (
                WorkSourceKind.MUTATION
                if candidate.candidate_kind == MutationCandidateKind.PROMPT
                else WorkSourceKind.FORK
            )
            source = WorkSourceRef(kind=expected_kind, candidate_id=candidate.mutation_id)
            _, was_created = self.store.create_work(
                WorkItem(
                    work_item_id=work_item_id_for(self.config.campaign_id, source),
                    campaign_id=self.config.campaign_id,
                    source=source,
                    parent_seed_id=seed.seed_id,
                    priority=candidate.mutation_priority,
                    created_iteration=iteration,
                )
            )
            created += int(was_created)
            duplicates += int(not was_created)
        return EnqueueResult(created, duplicates, rejected)

    def _coverage_input(
        self,
        work: WorkItem,
        outcome: CandidateExecutionOutcome,
    ) -> CoverageInput:
        resolver: CoverageInputResolver | None = self.executor.coverage_resolver
        if resolver is None:
            raise FuzzerIntegrityError("campaign execution requires a coverage resolver")
        if work.source.kind == WorkSourceKind.FORK:
            if not outcome.replay_id:
                raise FuzzerIntegrityError("fork outcome is missing replay_id")
            return resolver.from_manifest(outcome.replay_id)
        if not outcome.trajectory_path:
            raise FuzzerIntegrityError("successful execution is missing trajectory path")
        case = self.executor.resolve_case(work)
        return resolver.from_trajectory_path(Path(outcome.trajectory_path), prompt=case.prompt)

    def _initial_seed(self, template_id: str) -> SeedRecord:
        for seed in self.store.list_seeds(SeedStatus.PENDING):
            if seed.case.metadata.get("template_id") == template_id:
                return seed
        raise FuzzerIntegrityError(f"pending bootstrap seed not found: {template_id}")

    def _activate_seed(self, seed: SeedRecord, coverage: CoverageResult) -> SeedRecord:
        return seed.model_copy(
            update={
                "coverage_trajectory_id": coverage.trajectory_id,
                "coverage_result_digest": fuzzer_digest(coverage),
                "behavior_profile_hash": coverage.behavior_profile_hash,
                "risk_categories": sorted({hit.category_id for hit in coverage.risk_hits}),
                "max_risk_depth": max((hit.depth for hit in coverage.risk_hits), default=0),
                "status": SeedStatus.ACTIVE,
            }
        )

    def _parent_after_result(self, seed: SeedRecord, coverage: CoverageResult) -> SeedRecord:
        interesting = bool(
            coverage.new_behavior_count
            or coverage.new_risk_count
            or coverage.risk_depth_changes
            or any(link.novelty_class != "known_pair" for link in coverage.behavior_risk_links)
        )
        no_gain = 0 if interesting else seed.consecutive_no_gain + 1
        status = seed.status
        cooldown = seed.cooldown_until_iteration
        if no_gain >= self.config.seed_pool.cooldown_no_gain_threshold:
            status = SeedStatus.COOLED
            cooldown = self.store.iteration() + self.config.seed_pool.cooldown_iterations
        return seed.model_copy(
            update={
                "executed_children": seed.executed_children + 1,
                "interesting_children": seed.interesting_children + int(interesting),
                "successful_executions": seed.successful_executions + 1,
                "consecutive_no_gain": no_gain,
                "status": status,
                "cooldown_until_iteration": cooldown,
            }
        )

    def _promoted_seed(
        self,
        work: WorkItem,
        coverage: CoverageResult,
        *,
        prompt: str | None,
    ) -> SeedRecord | None:
        interesting = bool(
            coverage.new_behavior_count
            or coverage.new_risk_count
            or coverage.risk_depth_changes
            or any(link.novelty_class != "known_pair" for link in coverage.behavior_risk_links)
        )
        if not interesting or not work.source.candidate_id:
            return None
        candidate = self.mutation_store.get_candidate(work.source.candidate_id)
        if candidate.candidate_kind == MutationCandidateKind.PROMPT:
            case = self.executor.resolve_case(work)
            origin = SeedOrigin.MUTATION
        else:
            parent = self.store.get_seed(work.parent_seed_id or "")
            case = TestCase(
                case_id="fork-" + candidate.mutation_id.removeprefix("sha256:")[:24],
                prompt=prompt or parent.case.prompt,
                scenario_id="fork-mutation",
                target_risks=candidate.target_risks,
                seed=candidate.random_seed,
                metadata={"mutation_id": candidate.mutation_id},
            )
            origin = SeedOrigin.FORK
        status = (
            SeedStatus.RETIRED
            if candidate.mutation_depth >= self.config.energy.max_mutation_depth
            else SeedStatus.ACTIVE
        )
        return SeedRecord(
            seed_id=seed_id_for(case, origin=origin, parent_seed_id=work.parent_seed_id),
            origin=origin,
            case=case,
            parent_seed_id=work.parent_seed_id,
            mutation_id=candidate.mutation_id,
            replay_id=work.replay_id,
            checkpoint_id=(candidate.fork.checkpoint_id if candidate.fork else None),
            mutation_depth=candidate.mutation_depth,
            prompt_sha256=prompt_digest(case.prompt),
            coverage_trajectory_id=coverage.trajectory_id,
            coverage_result_digest=fuzzer_digest(coverage),
            behavior_profile_hash=coverage.behavior_profile_hash,
            risk_categories=sorted({hit.category_id for hit in coverage.risk_hits}),
            max_risk_depth=max((hit.depth for hit in coverage.risk_hits), default=0),
            status=status,
            virtual_runtime=self.seed_pool.minimum_active_virtual_runtime(),
        )

    def _coverage_for_seed(self, seed: SeedRecord) -> CoverageResult | None:
        if not seed.coverage_result_digest:
            return None
        return next(
            (
                result
                for result in self.coverage_store.all_results()
                if fuzzer_digest(result) == seed.coverage_result_digest
            ),
            None,
        )

    def _finish_bootstrap_if_ready(self) -> None:
        if self.store.status() != CampaignStatus.BOOTSTRAPPING:
            return
        if self.store.list_seeds(SeedStatus.PENDING):
            return
        if any(
            self.store.list_work(status)
            for status in (
                WorkItemStatus.QUEUED,
                WorkItemStatus.LEASED,
                WorkItemStatus.EXECUTED,
                WorkItemStatus.RETRY_WAIT,
            )
        ):
            return
        self.store.transition_campaign(CampaignStatus.RUNNING)

    def _find_next_commit_sequence(self) -> int:
        sequence = 1
        terminal = {
            WorkItemStatus.COMMITTED,
            WorkItemStatus.FAILED,
            WorkItemStatus.DEAD_LETTER,
            WorkItemStatus.SKIPPED,
        }
        by_sequence = {
            work.dispatch_sequence: work
            for work in self.store.list_work()
            if work.dispatch_sequence is not None
        }
        while sequence in by_sequence and by_sequence[sequence].status in terminal:
            sequence += 1
        return sequence

    def _pending_work_count(self) -> int:
        return sum(
            len(self.store.list_work(status))
            for status in (
                WorkItemStatus.QUEUED,
                WorkItemStatus.LEASED,
                WorkItemStatus.EXECUTED,
                WorkItemStatus.RETRY_WAIT,
            )
        )

    def _has_pending_work(self) -> bool:
        return self._pending_work_count() > 0

    def _remaining_execution_budget(self) -> int:
        maximum = self.config.budget.max_executions
        if maximum is None:
            return self.config.concurrency.max_pending_work_items
        attempts = int(self.store.campaign_values()["execution_attempts"])
        return max(0, maximum - attempts)

    def _budget_exhausted(self, runtime_seconds: float) -> bool:
        budget = self.config.budget
        values = self.store.campaign_values()
        return any(
            (
                budget.max_duration_seconds is not None
                and runtime_seconds >= budget.max_duration_seconds,
                budget.max_executions is not None
                and int(values["execution_attempts"]) >= budget.max_executions,
                budget.max_generated_candidates is not None
                and self.mutation_store.snapshot().total_accepted
                >= budget.max_generated_candidates,
                budget.max_corpus_entries is not None
                and len(self.store.corpus_entries()) >= budget.max_corpus_entries,
            )
        )

    def _skip_unleased_work(self) -> None:
        for work in self.store.list_work(WorkItemStatus.QUEUED):
            self.store.finish_work(work.work_item_id, WorkItemStatus.SKIPPED)

    def _iteration_seed(self, iteration: int) -> int:
        return int(
            fuzzer_digest(
                {
                    "campaign_id": self.config.campaign_id,
                    "random_seed": self.config.random_seed,
                    "iteration": iteration,
                }
            ).removeprefix("sha256:")[:16],
            16,
        )
