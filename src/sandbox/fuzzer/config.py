"""Validated configuration for a single-process fuzzing campaign."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator


class BudgetConfig(BaseModel):
    max_duration_seconds: int | None = Field(default=7_200, ge=1)
    max_executions: int | None = Field(default=500, ge=1)
    max_generated_candidates: int | None = Field(default=2_000, ge=1)
    max_corpus_entries: int | None = Field(default=500, ge=1)
    stagnation_window: int = Field(default=100, ge=1)
    stop_on_stagnation: bool = True


class ConcurrencyConfig(BaseModel):
    sandbox_workers: int = Field(default=2, ge=1, le=64)
    execution_queue_size: int = Field(default=8, ge=1)
    result_queue_size: int = Field(default=8, ge=1)
    max_pending_work_items: int = Field(default=32, ge=1)
    host_memory_limit_bytes: int | None = Field(default=None, ge=1)
    host_nano_cpus: int | None = Field(default=None, ge=1)


class SchedulingConfig(BaseModel):
    mode: Literal["deterministic_rounds", "throughput"] = "deterministic_rounds"
    max_feedback_lag_work_items: int = Field(default=0, ge=0)
    generation_no_progress_threshold: int = Field(default=3, ge=1)


class LeaseConfig(BaseModel):
    lease_seconds: int = Field(default=240, ge=3)
    heartbeat_seconds: int = Field(default=30, ge=1)
    recovery_grace_seconds: int = Field(default=30, ge=0)


class RetryConfig(BaseModel):
    max_transient_attempts: int = Field(default=2, ge=0, le=5)
    initial_backoff_seconds: int = Field(default=2, ge=0)
    max_backoff_seconds: int = Field(default=30, ge=0)
    systemic_failure_window: int = Field(default=20, ge=1)
    systemic_failure_threshold: float = Field(default=0.5, gt=0, le=1)


class EnergyConfig(BaseModel):
    formula_version: str = "energy-v1"
    base_energy: int = Field(default=4, ge=1)
    min_energy: int = Field(default=1, ge=1)
    max_energy: int = Field(default=16, ge=1)
    novelty_weight: float = Field(default=1.25, ge=0)
    risk_gap_weight: float = Field(default=1.0, ge=0)
    rarity_weight: float = Field(default=0.75, ge=0)
    stagnation_decay_interval: int = Field(default=3, ge=1)
    stagnation_decay: float = Field(default=0.5, gt=0, le=1)
    minimum_stagnation_factor: float = Field(default=0.125, gt=0, le=1)
    max_mutation_depth: int = Field(default=5, ge=1)


class SeedPoolConfig(BaseModel):
    max_active_seeds: int = Field(default=500, ge=1)
    cooldown_no_gain_threshold: int = Field(default=6, ge=1)
    cooldown_iterations: int = Field(default=20, ge=1)
    quarantine_failure_threshold: int = Field(default=3, ge=1)


class CorpusConfig(BaseModel):
    policy_version: str = "coverage-corpus-v1"
    retain_non_interesting_trajectories: bool = True
    export_prompts: bool = False


class SnapshotConfig(BaseModel):
    every_committed_items: int = Field(default=10, ge=1)
    every_seconds: int = Field(default=60, ge=1)


class ShutdownConfig(BaseModel):
    graceful_timeout_seconds: int = Field(default=180, ge=1)
    cleanup_timeout_seconds: int = Field(default=60, ge=1)


class FuzzerConfig(BaseModel):
    campaign_id: str = "week5-local"
    target_profile_id: str = "standard-fake"
    random_seed: int = 42
    store_root: Path = Path("data/fuzzing")
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    scheduling: SchedulingConfig = Field(default_factory=SchedulingConfig)
    leases: LeaseConfig = Field(default_factory=LeaseConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    energy: EnergyConfig = Field(default_factory=EnergyConfig)
    seed_pool: SeedPoolConfig = Field(default_factory=SeedPoolConfig)
    corpus: CorpusConfig = Field(default_factory=CorpusConfig)
    snapshots: SnapshotConfig = Field(default_factory=SnapshotConfig)
    shutdown: ShutdownConfig = Field(default_factory=ShutdownConfig)

    @model_validator(mode="after")
    def validate_campaign(self) -> FuzzerConfig:
        if (
            not self.campaign_id
            or self.campaign_id in {".", ".."}
            or any(character in self.campaign_id for character in "/\\:")
        ):
            raise ValueError("invalid fuzzer campaign_id")
        finite = (
            self.budget.max_duration_seconds,
            self.budget.max_executions,
            self.budget.max_generated_candidates,
            self.budget.max_corpus_entries,
        )
        if all(value is None for value in finite):
            raise ValueError("at least one finite campaign budget is required")
        if not self.energy.min_energy <= self.energy.base_energy <= self.energy.max_energy:
            raise ValueError("energy must satisfy min_energy <= base_energy <= max_energy")
        concurrency = self.concurrency
        if concurrency.execution_queue_size < concurrency.sandbox_workers:
            raise ValueError("execution queue must be at least the worker count")
        if concurrency.result_queue_size < concurrency.sandbox_workers:
            raise ValueError("result queue must be at least the worker count")
        if concurrency.max_pending_work_items < concurrency.execution_queue_size:
            raise ValueError("max pending work must be at least the execution queue size")
        if self.leases.lease_seconds < 3 * self.leases.heartbeat_seconds:
            raise ValueError("lease must be at least three heartbeat intervals")
        if self.retry.max_backoff_seconds < self.retry.initial_backoff_seconds:
            raise ValueError("retry max backoff cannot be below initial backoff")
        lag = self.scheduling.max_feedback_lag_work_items
        if self.scheduling.mode == "deterministic_rounds" and lag != 0:
            raise ValueError("deterministic rounds require zero feedback lag")
        if self.scheduling.mode == "throughput" and not (
            concurrency.sandbox_workers <= lag <= concurrency.max_pending_work_items
        ):
            raise ValueError("throughput feedback lag must cover workers and pending bound")
        return self

    @classmethod
    def from_yaml(cls, path: Path) -> FuzzerConfig:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls.model_validate(payload.get("fuzzer", payload))


def load_fuzzer_config(path: Path) -> FuzzerConfig:
    return FuzzerConfig.from_yaml(path)
