"""Strict, versioned contracts for persistent fuzzing campaigns."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sandbox.identifiers import validate_execution_id
from sandbox.models import ScoreResult, TestCase
from sandbox.replay.digests import sha256_digest

Digest = str


class FuzzerContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"


class CampaignStatus(StrEnum):
    CREATED = "created"
    BOOTSTRAPPING = "bootstrapping"
    RUNNING = "running"
    PAUSE_REQUESTED = "pause_requested"
    PAUSED = "paused"
    STOP_REQUESTED = "stop_requested"
    COMPLETED = "completed"
    FAILED = "failed"


class CampaignStopReason(StrEnum):
    BUDGET_EXHAUSTED = "budget_exhausted"
    STAGNATED = "stagnated"
    USER_REQUESTED = "user_requested"
    NO_ELIGIBLE_SEEDS = "no_eligible_seeds"
    SYSTEMIC_INFRASTRUCTURE_FAILURE = "systemic_infrastructure_failure"


class SeedStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    COOLED = "cooled"
    RETIRED = "retired"
    QUARANTINED = "quarantined"


class SeedOrigin(StrEnum):
    TEMPLATE = "template"
    MUTATION = "mutation"
    FORK = "fork"


class WorkSourceKind(StrEnum):
    INITIAL_CASE = "initial_case"
    MUTATION = "mutation"
    FORK = "fork"
    SOAK_PROBE = "soak_probe"


class WorkItemStatus(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    EXECUTED = "executed"
    COMMITTED = "committed"
    RETRY_WAIT = "retry_wait"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"
    SKIPPED = "skipped"


class FailureKind(StrEnum):
    CASE_FAILURE = "case_failure"
    TRANSIENT_INFRASTRUCTURE = "transient_infrastructure"
    SYSTEMIC_INFRASTRUCTURE = "systemic_infrastructure"
    INTEGRITY_FAILURE = "integrity_failure"
    CANCELLED = "cancelled"


class CorpusReason(StrEnum):
    NEW_BEHAVIOR = "new_behavior"
    NEW_RISK_CATEGORY = "new_risk_category"
    RISK_DEPTH_INCREASE = "risk_depth_increase"
    NEW_BEHAVIOR_RISK_LINK = "new_behavior_risk_link"
    POLICY_VIOLATION = "policy_violation"
    DIVERGENT_SECURITY_OUTCOME = "divergent_security_outcome"


class WorkSourceRef(FuzzerContract):
    kind: WorkSourceKind
    case_id: str | None = None
    candidate_id: Digest | None = None
    probe_id: str | None = None

    @model_validator(mode="after")
    def validate_source(self) -> WorkSourceRef:
        if self.kind == WorkSourceKind.INITIAL_CASE:
            valid = bool(self.case_id and not self.candidate_id and not self.probe_id)
        elif self.kind in {WorkSourceKind.MUTATION, WorkSourceKind.FORK}:
            valid = bool(self.candidate_id and not self.case_id and not self.probe_id)
        else:
            valid = bool(self.probe_id and self.case_id and not self.candidate_id)
        if not valid:
            raise ValueError(f"invalid fields for work source {self.kind.value}")
        return self


class CampaignManifest(FuzzerContract):
    campaign_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    config_digest: Digest
    taxonomy_version: str
    taxonomy_digest: Digest
    risk_scope_version: str
    risk_scope_digest: Digest
    mutation_registry_version: str
    mutation_registry_digest: Digest
    mutation_provider: str
    mutation_provider_version: str
    mutation_model_name: str | None = None
    mutation_model_digest: str | None = None
    agent_model_name: str
    agent_model_digest: str | None = None
    agent_model_runtime_image: str | None = None
    agent_model_runtime_digest: str | None = None
    agent_image: str
    agent_image_digest: str | None = None
    target_profile_id: str
    energy_formula_version: str
    corpus_policy_version: str
    scheduler_policy_version: str
    random_seed: int


class SeedRecord(FuzzerContract):
    seed_id: Digest
    origin: SeedOrigin
    case: TestCase
    parent_seed_id: Digest | None = None
    mutation_id: Digest | None = None
    replay_id: str | None = None
    checkpoint_id: str | None = None
    mutation_depth: int = Field(ge=0)
    prompt_sha256: Digest
    coverage_trajectory_id: str | None = None
    coverage_result_digest: Digest | None = None
    behavior_profile_hash: Digest | None = None
    risk_categories: list[str] = Field(default_factory=list)
    max_risk_depth: int = Field(default=0, ge=0, le=3)
    status: SeedStatus = SeedStatus.PENDING
    times_selected: int = Field(default=0, ge=0)
    generated_candidates: int = Field(default=0, ge=0)
    executed_children: int = Field(default=0, ge=0)
    interesting_children: int = Field(default=0, ge=0)
    consecutive_no_gain: int = Field(default=0, ge=0)
    consecutive_generation_no_progress: int = Field(default=0, ge=0)
    successful_executions: int = Field(default=0, ge=0)
    failed_executions: int = Field(default=0, ge=0)
    infrastructure_failures: int = Field(default=0, ge=0)
    virtual_runtime: float = Field(default=0.0, ge=0.0)
    cooldown_until_iteration: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_lineage_and_coverage(self) -> SeedRecord:
        if self.origin == SeedOrigin.TEMPLATE and (self.parent_seed_id or self.mutation_id):
            raise ValueError("template seed cannot have mutation lineage")
        if self.origin in {SeedOrigin.MUTATION, SeedOrigin.FORK} and not (
            self.parent_seed_id and self.mutation_id
        ):
            raise ValueError("derived seed requires parent_seed_id and mutation_id")
        coverage = (
            self.coverage_trajectory_id,
            self.coverage_result_digest,
            self.behavior_profile_hash,
        )
        if any(coverage) and not all(coverage):
            raise ValueError("seed coverage references must appear together")
        return self


class EnergyDecision(FuzzerContract):
    decision_id: Digest
    campaign_id: str
    seed_id: Digest
    iteration: int = Field(ge=0)
    base_energy: int = Field(ge=1)
    novelty_factor: float = Field(gt=0)
    risk_gap_factor: float = Field(gt=0)
    rarity_factor: float = Field(gt=0)
    stability_factor: float = Field(gt=0)
    stagnation_factor: float = Field(gt=0)
    depth_factor: float = Field(gt=0)
    assigned_energy: int = Field(ge=1)
    formula_version: str
    coverage_snapshot_digest: Digest
    seed_state_digest: Digest


class WorkItem(FuzzerContract):
    work_item_id: Digest
    campaign_id: str
    source: WorkSourceRef
    parent_seed_id: Digest | None = None
    priority: float
    status: WorkItemStatus = WorkItemStatus.QUEUED
    created_iteration: int = Field(ge=0)
    dispatch_sequence: int | None = Field(default=None, ge=1)
    attempt: int = Field(default=0, ge=0)
    execution_id: str | None = None
    lease_owner: str | None = None
    lease_token_digest: Digest | None = None
    lease_expires_at: datetime | None = None
    retry_not_before: datetime | None = None
    trajectory_id: str | None = None
    trajectory_path: str | None = None
    replay_id: str | None = None
    coverage_result_digest: Digest | None = None
    corpus_entry_id: Digest | None = None
    failure_kind: FailureKind | None = None
    error_code: str | None = None

    @model_validator(mode="after")
    def validate_state(self) -> WorkItem:
        derived = self.source.kind in {WorkSourceKind.MUTATION, WorkSourceKind.FORK}
        if derived != bool(self.parent_seed_id):
            raise ValueError("mutation/fork work requires exactly one parent seed")
        lease = (self.lease_owner, self.lease_token_digest, self.lease_expires_at)
        if any(lease) and not all(lease):
            raise ValueError("lease fields must appear together")
        terminal_with_sequence = {
            WorkItemStatus.EXECUTED,
            WorkItemStatus.COMMITTED,
            WorkItemStatus.FAILED,
            WorkItemStatus.DEAD_LETTER,
        }
        if self.status in terminal_with_sequence and self.dispatch_sequence is None:
            raise ValueError(f"{self.status.value} work requires dispatch_sequence")
        if self.status == WorkItemStatus.LEASED and (
            self.dispatch_sequence is None or not all(lease) or not self.execution_id
        ):
            raise ValueError("leased work requires sequence, execution ID, and lease")
        return self


class CandidateExecutionOutcome(FuzzerContract):
    work_item_id: Digest
    attempt: int = Field(ge=1)
    source: WorkSourceRef
    coverage_source_kind: Literal["week1", "recording", "fork"]
    execution_id: str
    trajectory_id: str | None = None
    trajectory_path: str | None = None
    replay_id: str | None = None
    execution_status: str
    score: ScoreResult | None = None
    container_removed: bool
    started_at: datetime
    finished_at: datetime
    duration_ms: int = Field(ge=0)
    error_code: str | None = None
    error_message: str | None = None


class CorpusEntry(FuzzerContract):
    corpus_entry_id: Digest
    campaign_id: str
    seed_id: Digest
    candidate_id: Digest | None = None
    work_item_id: Digest
    trajectory_id: str
    coverage_result_digest: Digest
    reasons: list[CorpusReason] = Field(min_length=1)
    evidence_event_sequences: list[int] = Field(default_factory=list)
    behavior_profile_hash: Digest
    risk_categories: list[str] = Field(default_factory=list)
    max_risk_depth: int = Field(ge=0, le=3)
    score_verdict: str | None = None
    replay_id: str | None = None
    created_iteration: int = Field(ge=0)


class Observation(FuzzerContract):
    observation_id: Digest
    campaign_id: str
    work_item_id: Digest
    seed_id: Digest | None = None
    trajectory_id: str
    coverage_result_digest: Digest
    behavior_profile_hash: Digest
    risk_categories: list[str] = Field(default_factory=list)
    max_risk_depth: int = Field(ge=0, le=3)
    score_verdict: str | None = None
    behavior_delta: float = Field(ge=0)
    risk_delta: float = Field(ge=0)
    combined_delta: float = Field(ge=0)
    created_iteration: int = Field(ge=0)


class CampaignSnapshot(FuzzerContract):
    campaign_id: str
    status: CampaignStatus
    stop_reason: CampaignStopReason | None = None
    iteration: int = Field(ge=0)
    active_runtime_seconds: float = Field(ge=0)
    seed_counts: dict[str, int] = Field(default_factory=dict)
    work_counts: dict[str, int] = Field(default_factory=dict)
    corpus_size: int = Field(ge=0)
    successful_executions: int = Field(ge=0)
    case_failures: int = Field(ge=0)
    infrastructure_failures: int = Field(ge=0)
    retries: int = Field(ge=0)
    uncleared_containers: int = Field(ge=0)
    behavior_features: int = Field(ge=0)
    behavior_profiles: int = Field(ge=0)
    risk_categories: int = Field(ge=0)
    applicable_intent_coverage: float | None = None
    applicable_behavior_coverage: float | None = None
    applicable_impact_coverage: float | None = None
    new_behavior_per_hour: float = Field(ge=0)
    risk_depth_gain_per_hour: float = Field(ge=0)
    execution_p50_ms: float | None = None
    execution_p95_ms: float | None = None
    queue_length: int = Field(ge=0)
    active_workers: int = Field(ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SandboxRunContext(FuzzerContract):
    campaign_id: str
    work_item_id: str
    attempt: int = Field(ge=1)


class CleanupFailure(FuzzerContract):
    resource_id: str
    error: str


class CleanupReport(FuzzerContract):
    campaign_id: str
    discovered: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    failures: list[CleanupFailure] = Field(default_factory=list)


class TargetProfile(FuzzerContract):
    profile_id: str
    profile_version: str
    image_ref: str
    image_digest: str | None = None
    agent_version: str
    model_provider: Literal["fake", "ollama"]
    model_name: str
    model_digest: str | None = None
    model_runtime_image: str | None = None
    model_runtime_digest: str | None = None
    risk_scope_path: Path
    fixture_pack_version: str
    max_steps: int = Field(ge=1)
    execution_timeout_seconds: int = Field(ge=1)
    required_capabilities: list[str] = Field(default_factory=list)


def fuzzer_digest(value: object) -> str:
    """Canonical digest with all non-integral floats made explicit decimal strings."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python", exclude_none=False)
    return sha256_digest(_decimalize_floats(value))


def _decimalize_floats(value: object) -> object:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("fuzzer digest cannot contain NaN or Infinity")
        if value.is_integer():
            return int(value)
        return str(value)
    if isinstance(value, dict):
        return {key: _decimalize_floats(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_decimalize_floats(item) for item in value]
    return value


def seed_id_for(case: TestCase, *, origin: SeedOrigin, parent_seed_id: str | None = None) -> str:
    return fuzzer_digest(
        {
            "kind": "fuzzer-seed-v1",
            "origin": origin.value,
            "case": case,
            "parent_seed_id": parent_seed_id,
        }
    )


def work_item_id_for(campaign_id: str, source: WorkSourceRef) -> str:
    return fuzzer_digest({"kind": "fuzzer-work-v1", "campaign_id": campaign_id, "source": source})


def execution_id_for(campaign_id: str, work_item_id: str, attempt: int) -> str:
    suffix = fuzzer_digest(
        {"campaign_id": campaign_id, "work_item_id": work_item_id, "attempt": attempt}
    ).removeprefix("sha256:")[:24]
    return validate_execution_id(f"fuzz-{suffix}", fuzz_only=True)
