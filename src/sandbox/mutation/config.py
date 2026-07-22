"""Typed configuration for the mutation pipeline."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator

from sandbox.mutation.models import MutationProviderKind


class MutationProviderConfig(BaseModel):
    kind: MutationProviderKind = MutationProviderKind.RULE_BASED
    provider_version: str = "rule-mutator-v1"
    model_name: str | None = None
    model_digest: str | None = None
    endpoint: str | None = None
    endpoint_allowlist: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    timeout_seconds: int = Field(default=120, ge=1, le=600)
    max_response_bytes: int = Field(default=1_048_576, ge=1_024, le=16_777_216)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    generation_prompt_version: str = "mutator-system-v1"

    @model_validator(mode="after")
    def validate_provider(self) -> MutationProviderConfig:
        if self.kind == MutationProviderKind.RULE_BASED:
            if self.endpoint is not None:
                raise ValueError("rule-based mutation provider does not use an endpoint")
            return self
        if not (self.endpoint and self.model_name and self.model_digest):
            raise ValueError("Ollama mutation provider requires endpoint, model name, and digest")
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "http" or parsed.hostname not in self.endpoint_allowlist:
            raise ValueError("mutation endpoint must be an allowlisted HTTP host")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("mutation endpoint must not contain credentials or query data")
        return self


class MutationGenerationConfig(BaseModel):
    default_count: int = Field(default=8, ge=1, le=64)
    max_count: int = Field(default=64, ge=1, le=64)
    oversample_factor: int = Field(default=3, ge=1, le=10)
    max_generation_attempts: int = Field(default=4, ge=1, le=20)
    max_raw_candidates_per_batch: int = Field(default=96, ge=1, le=1_000)
    max_mutation_depth: int = Field(default=5, ge=1, le=20)


class MutationDiversityConfig(BaseModel):
    normalization_version: str = "1.0"
    similarity_backend: str = "character_3gram"
    similarity_version: str = "char3-jaccard-v1"
    near_duplicate_threshold: float = Field(default=0.92, gt=0.0, le=1.0)
    similarity_history_limit: int = Field(default=200, ge=0, le=10_000)
    max_operator_share: float = Field(default=0.50, gt=0.0, le=1.0)
    max_target_share: float = Field(default=0.60, gt=0.0, le=1.0)


class MutationPriorityConfig(BaseModel):
    priority_profile: str = "lexical-safe-v1"
    formula_version: str = "lexical-safe-v1"
    target_risk_gap_weight: float = Field(default=0.50, ge=0.0)
    expected_semantic_novelty_weight: float = Field(default=0.0, ge=0.0)
    parent_case_value_weight: float = Field(default=0.25, ge=0.0)
    operator_underuse_weight: float = Field(default=0.10, ge=0.0)
    similarity_penalty: float = Field(default=0.10, ge=0.0)
    path_frequency_penalty: float = Field(default=0.05, ge=0.0)
    cold_start_parent_value: float = Field(default=0.50, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def lexical_profile_is_honest(self) -> MutationPriorityConfig:
        if self.priority_profile == "lexical-safe-v1" and self.expected_semantic_novelty_weight:
            raise ValueError("lexical priority profile cannot weight semantic novelty")
        return self


class MutationConfig(BaseModel):
    campaign_id: str = "week4-baseline"
    operator_registry_path: Path = Path("config/mutation-operators.yaml")
    store_root: Path = Path("data/mutations")
    provider: MutationProviderConfig = Field(default_factory=MutationProviderConfig)
    generation: MutationGenerationConfig = Field(default_factory=MutationGenerationConfig)
    diversity: MutationDiversityConfig = Field(default_factory=MutationDiversityConfig)
    priority: MutationPriorityConfig = Field(default_factory=MutationPriorityConfig)

    @model_validator(mode="after")
    def validate_config(self) -> MutationConfig:
        if (
            not self.campaign_id
            or self.campaign_id in {".", ".."}
            or any(character in self.campaign_id for character in "/\\:")
        ):
            raise ValueError("invalid mutation campaign_id")
        if self.generation.default_count > self.generation.max_count:
            raise ValueError("default mutation count exceeds max_count")
        if self.generation.max_count > self.generation.max_raw_candidates_per_batch:
            raise ValueError("max_count exceeds max_raw_candidates_per_batch")
        return self
