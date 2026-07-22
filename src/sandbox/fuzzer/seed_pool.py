"""Persistent weighted-virtual-runtime seed selection and lifecycle updates."""

from __future__ import annotations

from sandbox.coverage.models import CoverageResult
from sandbox.fuzzer.config import SeedPoolConfig
from sandbox.fuzzer.exceptions import FuzzerIntegrityError
from sandbox.fuzzer.models import SeedRecord, SeedStatus
from sandbox.fuzzer.store import FuzzerStore
from sandbox.mutation.models import MutationSeed


class SeedPool:
    def __init__(self, store: FuzzerStore, config: SeedPoolConfig, *, max_depth: int) -> None:
        self.store = store
        self.config = config
        self.max_depth = max_depth

    def select(self, iteration: int) -> SeedRecord | None:
        self.reactivate_due(iteration)
        eligible = [
            seed
            for seed in self.store.list_seeds(SeedStatus.ACTIVE)
            if seed.cooldown_until_iteration is None or seed.cooldown_until_iteration <= iteration
        ]
        return min(eligible, key=lambda seed: (seed.virtual_runtime, seed.seed_id), default=None)

    def record_selection(self, seed_id: str, assigned_energy: int) -> SeedRecord:
        seed = self.store.get_seed(seed_id)
        if seed.status != SeedStatus.ACTIVE:
            raise FuzzerIntegrityError("only active seeds can be selected")
        updated = seed.model_copy(
            update={
                "times_selected": seed.times_selected + 1,
                "virtual_runtime": seed.virtual_runtime + 1 / max(1, assigned_energy),
            }
        )
        self.store.update_seed(updated, event="seed_selected")
        return updated

    def record_generation_result(
        self,
        seed_id: str,
        *,
        generated_candidates: int,
        new_work_items: int,
        iteration: int,
        no_progress_threshold: int,
    ) -> SeedRecord:
        seed = self.store.get_seed(seed_id)
        no_progress = 0 if new_work_items else seed.consecutive_generation_no_progress + 1
        status = seed.status
        cooldown = seed.cooldown_until_iteration
        if no_progress >= no_progress_threshold and status == SeedStatus.ACTIVE:
            status = SeedStatus.COOLED
            cooldown = iteration + self.config.cooldown_iterations
        updated = seed.model_copy(
            update={
                "generated_candidates": seed.generated_candidates + generated_candidates,
                "consecutive_generation_no_progress": no_progress,
                "status": status,
                "cooldown_until_iteration": cooldown,
            }
        )
        self.store.update_seed(updated, event="seed_generation_recorded")
        return updated

    def record_child_result(
        self,
        seed_id: str,
        *,
        interesting: bool,
        successful: bool,
        infrastructure_failure: bool,
        iteration: int,
    ) -> SeedRecord:
        seed = self.store.get_seed(seed_id)
        no_gain = seed.consecutive_no_gain
        if interesting:
            no_gain = 0
        elif not infrastructure_failure:
            no_gain += 1
        status = seed.status
        cooldown = seed.cooldown_until_iteration
        if no_gain >= self.config.cooldown_no_gain_threshold and status == SeedStatus.ACTIVE:
            status = SeedStatus.COOLED
            cooldown = iteration + self.config.cooldown_iterations
        infrastructure_failures = seed.infrastructure_failures + int(infrastructure_failure)
        if infrastructure_failures >= self.config.quarantine_failure_threshold:
            status = SeedStatus.QUARANTINED
            cooldown = None
        updated = seed.model_copy(
            update={
                "executed_children": seed.executed_children + 1,
                "interesting_children": seed.interesting_children + int(interesting),
                "successful_executions": seed.successful_executions + int(successful),
                "failed_executions": seed.failed_executions
                + int(not successful and not infrastructure_failure),
                "infrastructure_failures": infrastructure_failures,
                "consecutive_no_gain": no_gain,
                "status": status,
                "cooldown_until_iteration": cooldown,
            }
        )
        self.store.update_seed(updated, event="seed_child_recorded")
        return updated

    def activate_bootstrap(self, seed_id: str, coverage: CoverageResult) -> SeedRecord:
        seed = self.store.get_seed(seed_id)
        if seed.status != SeedStatus.PENDING:
            raise FuzzerIntegrityError("bootstrap activation requires pending seed")
        updated = seed.model_copy(
            update={
                "coverage_trajectory_id": coverage.trajectory_id,
                "coverage_result_digest": _coverage_digest(coverage),
                "behavior_profile_hash": coverage.behavior_profile_hash,
                "risk_categories": sorted({hit.category_id for hit in coverage.risk_hits}),
                "max_risk_depth": max((hit.depth for hit in coverage.risk_hits), default=0),
                "status": (
                    SeedStatus.RETIRED
                    if seed.mutation_depth >= self.max_depth
                    else SeedStatus.ACTIVE
                ),
            }
        )
        self.store.update_seed(updated, event="seed_bootstrapped")
        return updated

    def reactivate_due(self, iteration: int) -> int:
        changed = 0
        for seed in self.store.list_seeds(SeedStatus.COOLED):
            if seed.cooldown_until_iteration is None or seed.cooldown_until_iteration > iteration:
                continue
            updated = seed.model_copy(
                update={
                    "status": SeedStatus.ACTIVE,
                    "cooldown_until_iteration": None,
                    "consecutive_no_gain": seed.consecutive_no_gain // 2,
                    "consecutive_generation_no_progress": 0,
                }
            )
            self.store.update_seed(updated, event="seed_reactivated")
            changed += 1
        return changed

    def next_cooldown_iteration(self) -> int | None:
        values = [
            seed.cooldown_until_iteration
            for seed in self.store.list_seeds(SeedStatus.COOLED)
            if seed.cooldown_until_iteration is not None
        ]
        return min(values, default=None)

    def minimum_active_virtual_runtime(self) -> float:
        seeds = self.store.list_seeds(SeedStatus.ACTIVE)
        return min((seed.virtual_runtime for seed in seeds), default=0.0)

    @staticmethod
    def to_mutation_seed(seed: SeedRecord, coverage: CoverageResult | None) -> MutationSeed:
        return MutationSeed(
            seed_id=seed.seed_id,
            case=seed.case,
            prompt_sha256=seed.prompt_sha256,
            parent_mutation_id=seed.mutation_id,
            mutation_depth=seed.mutation_depth,
            coverage_result=coverage,
            behavior_profile_hash=seed.behavior_profile_hash,
            replay_id=seed.replay_id,
            checkpoint_id=seed.checkpoint_id,
        )


def _coverage_digest(coverage: CoverageResult) -> str:
    from sandbox.fuzzer.models import fuzzer_digest

    return fuzzer_digest(coverage)
