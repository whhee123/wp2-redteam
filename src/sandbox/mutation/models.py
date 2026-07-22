"""Strict contracts for coverage-guided mutation."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sandbox.coverage.models import CoverageResult
from sandbox.models import TestCase

Digest = str


class MutationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"


class MutationProviderKind(StrEnum):
    RULE_BASED = "rule_based"
    OLLAMA = "ollama"


class MutationCandidateKind(StrEnum):
    PROMPT = "prompt"
    FORK = "fork"


class MutationRejectionReason(StrEnum):
    INVALID_SCHEMA = "invalid_schema"
    EMPTY_PROMPT = "empty_prompt"
    PROMPT_TOO_LONG = "prompt_too_long"
    UNKNOWN_OPERATOR = "unknown_operator"
    INCOMPATIBLE_OPERATOR = "incompatible_operator"
    INVALID_TARGET_RISK = "invalid_target_risk"
    UNREACHABLE_TARGET = "unreachable_target"
    EXACT_DUPLICATE = "exact_duplicate"
    NEAR_DUPLICATE = "near_duplicate"
    BATCH_OPERATOR_QUOTA = "batch_operator_quota"
    BATCH_TARGET_QUOTA = "batch_target_quota"
    INVALID_FORK = "invalid_fork"
    PROVIDER_ERROR = "provider_error"


class MutationSeed(MutationContract):
    seed_id: str = Field(min_length=1, max_length=256)
    case: TestCase
    prompt_sha256: Digest = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    parent_mutation_id: str | None = None
    mutation_depth: int = Field(default=0, ge=0)
    coverage_result: CoverageResult | None = None
    behavior_profile_hash: Digest | None = None
    replay_id: str | None = None
    checkpoint_id: str | None = None


class RiskGap(MutationContract):
    category_id: str
    label: str
    observed_depth: int = Field(ge=0, le=3)
    max_reachable_depth: int = Field(ge=1, le=3)
    next_target_depth: int = Field(ge=1, le=3)
    gap_ratio: float = Field(ge=0.0, le=1.0)
    report_weight: float = Field(ge=0.0)
    schedule_weight: float = Field(ge=0.0)


class LinkNoveltySummary(MutationContract):
    both_new: int = Field(default=0, ge=0)
    behavior_new: int = Field(default=0, ge=0)
    risk_new: int = Field(default=0, ge=0)
    known_pair: int = Field(default=0, ge=0)
    linked_risk_categories: list[str] = Field(default_factory=list)


class MutationFeedback(MutationContract):
    campaign_id: str
    taxonomy_version: str
    risk_scope_version: str
    coverage_snapshot_digest: Digest
    parent_coverage_digest: Digest | None = None
    behavior_profile_hash: Digest | None = None
    risk_gaps: list[RiskGap] = Field(default_factory=list)
    parent_behavior_delta: float = Field(default=0.0, ge=0.0)
    parent_risk_seed_delta: float = Field(default=0.0, ge=0.0)
    parent_combined_delta: float = Field(default=0.0, ge=0.0)
    link_novelty: LinkNoveltySummary = Field(default_factory=LinkNoveltySummary)
    recent_operator_counts: dict[str, int] = Field(default_factory=dict)
    recent_target_counts: dict[str, int] = Field(default_factory=dict)
    recent_path_counts: dict[str, int] = Field(default_factory=dict)


class MutationHistorySnapshot(MutationContract):
    campaign_id: str
    total_batches: int = Field(default=0, ge=0)
    total_accepted: int = Field(default=0, ge=0)
    total_rejected: int = Field(default=0, ge=0)
    operator_counts: dict[str, int] = Field(default_factory=dict)
    target_counts: dict[str, int] = Field(default_factory=dict)
    path_counts: dict[str, int] = Field(default_factory=dict)


class MutationOperatorSpec(MutationContract):
    operator_id: str = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=128)
    provider_modes: list[MutationProviderKind]
    candidate_kinds: list[MutationCandidateKind]
    supported_target_depths: list[int]
    compatible_risk_categories: list[str] = Field(default_factory=list)
    preserves_core_intent: bool = True
    expected_behavior_tags: list[str] = Field(default_factory=list)
    prompt_template_version: str

    @model_validator(mode="after")
    def validate_depths(self) -> MutationOperatorSpec:
        if not self.provider_modes or not self.candidate_kinds:
            raise ValueError("mutation operator requires provider modes and candidate kinds")
        if not self.supported_target_depths or any(
            depth < 1 or depth > 3 for depth in self.supported_target_depths
        ):
            raise ValueError("supported target depths must be between 1 and 3")
        return self


class MutationOperatorRegistry(MutationContract):
    registry_version: str
    operators: list[MutationOperatorSpec]


class PlannedMutation(MutationContract):
    operator_id: str
    target_risks: list[str] = Field(min_length=1)
    target_depths: dict[str, int]
    requested_count: int = Field(ge=1)
    initial_priority: float = Field(ge=0.0, le=1.0)


class MutationPlan(MutationContract):
    plan_id: Digest
    feedback_digest: Digest
    items: list[PlannedMutation] = Field(min_length=1)
    oversample_count: int = Field(ge=1)


class RawMutationCandidate(MutationContract):
    prompt: str = Field(min_length=1, max_length=32_000)
    operator_id: str
    target_risks: list[str] = Field(min_length=1)
    expected_novelty: str = ""
    constraints_preserved: list[str] = Field(default_factory=list)


class RawMutationBatch(MutationContract):
    candidates: list[RawMutationCandidate] = Field(default_factory=list)


class ForkMutationSpec(MutationContract):
    parent_replay_id: str
    checkpoint_id: str
    injection_type: Literal["prompt_replace", "prompt_append"]
    content: str = Field(min_length=1, max_length=32_000)
    suffix_mode: Literal[
        "live_and_record",
        "strict_with_replacements",
    ] = "live_and_record"


class MutationCandidate(MutationContract):
    mutation_id: Digest
    candidate_kind: MutationCandidateKind
    parent_seed_id: str
    parent_mutation_id: str | None = None
    mutation_depth: int = Field(ge=1)
    operator_id: str
    operator_version: str
    target_risks: list[str]
    target_depths: dict[str, int]
    prompt: str | None = None
    fork: ForkMutationSpec | None = None
    prompt_sha256: Digest
    normalized_prompt_sha256: Digest
    dedupe_key: Digest
    provider: MutationProviderKind
    provider_version: str
    model_name: str | None = None
    model_digest: str | None = None
    generation_prompt_version: str
    random_seed: int
    expected_novelty: str = ""
    constraints_preserved: list[str] = Field(default_factory=list)
    # Optional only so candidates persisted before path statistics were introduced
    # remain readable. Newly accepted candidates must always populate this field.
    path_signature: str | None = None
    priority_components: dict[str, float] = Field(default_factory=dict)
    mutation_priority: float = Field(ge=0.0, le=1.0)
    feedback_digest: Digest

    @model_validator(mode="after")
    def validate_candidate_kind(self) -> MutationCandidate:
        if self.candidate_kind == MutationCandidateKind.PROMPT:
            if self.prompt is None or self.fork is not None:
                raise ValueError("prompt candidate requires prompt and forbids fork")
        elif self.fork is None:
            raise ValueError("fork candidate requires fork specification")
        if self.provider == MutationProviderKind.OLLAMA and not (
            self.model_name and self.model_digest
        ):
            raise ValueError("Ollama mutation candidate requires model name and digest")
        return self


class RejectedMutation(MutationContract):
    attempt_id: Digest
    parent_seed_id: str
    operator_id: str | None = None
    target_risks: list[str] = Field(default_factory=list)
    prompt_sha256: Digest | None = None
    reason: MutationRejectionReason
    detail: str = ""


class MutationBatch(MutationContract):
    batch_id: Digest
    campaign_id: str
    request_digest: Digest
    requested_count: int = Field(ge=1)
    generated_count: int = Field(ge=0)
    accepted: list[MutationCandidate] = Field(default_factory=list)
    rejected: list[RejectedMutation] = Field(default_factory=list)
    exhausted: bool = False
    already_generated: bool = False


def to_test_case(candidate: MutationCandidate) -> TestCase:
    if candidate.candidate_kind != MutationCandidateKind.PROMPT or candidate.prompt is None:
        raise ValueError("only prompt mutation candidates can become TestCase")
    return TestCase(
        case_id="mut-" + candidate.mutation_id.removeprefix("sha256:")[:24],
        prompt=candidate.prompt,
        scenario_id="mutation",
        target_risks=candidate.target_risks,
        seed=candidate.random_seed,
        metadata={
            "mutation_id": candidate.mutation_id,
            "parent_seed_id": candidate.parent_seed_id,
            "parent_mutation_id": candidate.parent_mutation_id,
            "mutation_depth": candidate.mutation_depth,
            "operator_id": candidate.operator_id,
            "operator_version": candidate.operator_version,
            "provider": candidate.provider.value,
            "provider_version": candidate.provider_version,
            "model_name": candidate.model_name,
            "model_digest": candidate.model_digest,
            "generation_prompt_version": candidate.generation_prompt_version,
            "feedback_digest": candidate.feedback_digest,
        },
    )
