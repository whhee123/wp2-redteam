"""Versioned contracts for behavior and risk coverage."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sandbox.protocol import TraceEvent


class CoverageContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"


class CoverageInput(CoverageContract):
    trajectory_id: str = Field(min_length=1, max_length=256)
    execution_id: str = Field(min_length=1, max_length=256)
    source_kind: Literal[
        "week1",
        "recording",
        "strict_replay",
        "live_replay",
        "fork",
        "raw",
    ] = "raw"
    events: list[TraceEvent]
    prompt: str | None = None
    final_answer: str | None = None
    input_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    manifest_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_events(self) -> CoverageInput:
        if not self.events:
            raise ValueError("coverage input requires at least one event")
        for expected, event in enumerate(self.events):
            if event.execution_id != self.execution_id:
                raise ValueError("event execution_id does not match coverage input")
            if event.sequence != expected:
                raise ValueError("coverage input events must be contiguous")
        if self.events[-1].event_type not in {
            "execution_finished",
            "execution_timed_out",
            "execution_cancelled",
            "execution_error",
        }:
            raise ValueError("coverage input must end with a terminal execution event")
        return self


class BehaviorFeatureKind(StrEnum):
    TOOL_UNIGRAM = "tool_unigram"
    TOOL_BIGRAM = "tool_bigram"
    TOOL_TRIGRAM = "tool_trigram"
    NODE_EDGE = "node_edge"
    TOOL_RESULT = "tool_result"
    PARAM_SHAPE = "param_shape"
    SECURITY_TRANSITION = "security_transition"
    TERMINATION = "termination"


class BehaviorFeature(CoverageContract):
    kind: BehaviorFeatureKind
    value: str = Field(min_length=1, max_length=512)
    source_sequences: list[int] = Field(default_factory=list)
    frequency: int = Field(default=1, ge=1)


class BehaviorProfile(CoverageContract):
    trajectory_id: str
    execution_id: str
    features: list[BehaviorFeature] = Field(default_factory=list)
    profile_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    feature_count: int = Field(default=0, ge=0)


class EvidenceRule(CoverageContract):
    tool_name: str | None = None
    argument_patterns: dict[str, str] = Field(default_factory=dict)
    security_risk_category: str | None = None
    result_risk_category: str | None = None
    allowed: bool | None = None
    outcomes: list[str] = Field(default_factory=list)
    termination: str | None = None


class RiskCategory(CoverageContract):
    id: str = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=256)
    description: str = ""
    report_weight: float | None = Field(default=None, ge=0.0)
    keywords: list[str] = Field(default_factory=list)
    evidence_rules: list[EvidenceRule] = Field(default_factory=list)
    impact_rules: list[EvidenceRule] = Field(default_factory=list)
    children: list[RiskCategory] = Field(default_factory=list)


class RiskTaxonomy(CoverageContract):
    taxonomy_version: str = Field(min_length=1, max_length=128)
    categories: list[RiskCategory]


class CampaignRiskWeights(CoverageContract):
    campaign_id: str
    taxonomy_version: str
    schedule_weights: dict[str, float] = Field(default_factory=dict)


class RiskReachability(CoverageContract):
    max_reachable_depth: int = Field(ge=1, le=3)
    rationale: str = ""


class CampaignRiskScope(CoverageContract):
    scope_version: str = Field(min_length=1, max_length=128)
    taxonomy_version: str = Field(min_length=1, max_length=128)
    categories: dict[str, RiskReachability] = Field(default_factory=dict)


class EvidenceReference(CoverageContract):
    source: Literal["trace_event", "prompt", "final_answer", "manifest"]
    event_sequence: int | None = Field(default=None, ge=0)
    artifact_digest: str | None = None
    excerpt_digest: str | None = None

    @model_validator(mode="after")
    def validate_reference(self) -> EvidenceReference:
        if self.source == "trace_event" and self.event_sequence is None:
            raise ValueError("trace event evidence requires event_sequence")
        if self.source != "trace_event" and not (self.artifact_digest or self.excerpt_digest):
            raise ValueError("non-event evidence requires a digest")
        return self


class RiskHit(CoverageContract):
    trajectory_id: str
    execution_id: str
    category_id: str
    depth: int = Field(ge=1, le=3)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    recognizer: Literal["rule", "pattern", "keyword", "classifier", "impact"]
    rationale: str = ""


class RiskDepthChange(CoverageContract):
    category_id: str
    previous_depth: int = Field(ge=0, le=3)
    current_depth: int = Field(ge=1, le=3)
    depth_gain: int = Field(ge=1, le=3)

    @model_validator(mode="after")
    def validate_gain(self) -> RiskDepthChange:
        if self.current_depth - self.previous_depth != self.depth_gain:
            raise ValueError("depth_gain must equal current_depth - previous_depth")
        return self


class BehaviorRiskLink(CoverageContract):
    relation: Literal["same_tool_window"] = "same_tool_window"
    tool_name: str
    tool_call_sequence: int = Field(ge=0)
    behavior_kind: BehaviorFeatureKind
    behavior_value: str
    behavior_source_sequences: list[int] = Field(default_factory=list)
    risk_category_id: str
    risk_depth: int = Field(ge=1, le=3)
    risk_recognizers: list[
        Literal["rule", "pattern", "keyword", "classifier", "impact"]
    ] = Field(default_factory=list)
    risk_evidence_sequences: list[int] = Field(default_factory=list)
    behavior_new: bool = False
    risk_new: bool = False
    risk_depth_improved: bool = False
    novelty_class: Literal[
        "both_new",
        "behavior_new",
        "risk_new",
        "known_pair",
    ]


class CoverageResult(CoverageContract):
    trajectory_id: str
    execution_id: str
    input_digest: str
    behavior_profile_hash: str
    behavior_features_total: int = Field(default=0, ge=0)
    new_behavior_features: list[str] = Field(default_factory=list)
    new_behavior_count: int = Field(default=0, ge=0)
    cumulative_behavior_count: int = Field(default=0, ge=0)
    behavior_growth_rate: float = Field(default=0.0, ge=0.0)
    risk_hits: list[RiskHit] = Field(default_factory=list)
    new_risk_categories: list[str] = Field(default_factory=list)
    new_risk_count: int = Field(default=0, ge=0)
    improved_risk_depths: dict[str, int] = Field(default_factory=dict)
    risk_depth_changes: list[RiskDepthChange] = Field(default_factory=list)
    risk_progress_delta: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_seed_delta: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_scope_exceeded: list[str] = Field(default_factory=list)
    behavior_risk_links: list[BehaviorRiskLink] = Field(default_factory=list)
    cumulative_risk_count: int = Field(default=0, ge=0)
    intent_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    behavior_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    impact_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    behavior_delta: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_delta: float = Field(default=0.0, ge=0.0, le=1.0)
    combined_delta: float = Field(default=0.0, ge=0.0)
    already_evaluated: bool = False


class HeatmapCell(CoverageContract):
    behavior_cluster_id: str
    behavior_cluster_label: str
    risk_category_id: str
    trajectory_count: int = Field(default=0, ge=0)
    max_depth: int = Field(default=0, ge=0, le=3)
    new_coverage_count: int = Field(default=0, ge=0)
    confirmed_vulnerabilities: int = Field(default=0, ge=0)


class PrettyHeatmapRow(CoverageContract):
    behavior_cluster_id: str
    label: str
    trajectory_ids: list[str] = Field(default_factory=list)


class PrettyHeatmapColumn(CoverageContract):
    risk_category_id: str
    label: str


class PrettyHeatmapCell(CoverageContract):
    behavior_cluster_id: str
    behavior_cluster_label: str
    risk_category_id: str
    risk_category_label: str
    trajectory_count: int = Field(default=0, ge=0)
    max_depth: int = Field(default=0, ge=0, le=3)
    new_coverage_count: int = Field(default=0, ge=0)
    confirmed_vulnerabilities: int = Field(default=0, ge=0)


class PrettyHeatmapReport(CoverageContract):
    campaign_id: str
    taxonomy_version: str
    rows: list[PrettyHeatmapRow] = Field(default_factory=list)
    columns: list[PrettyHeatmapColumn] = Field(default_factory=list)
    cells: list[PrettyHeatmapCell] = Field(default_factory=list)


class CoverageSnapshot(CoverageContract):
    campaign_id: str
    taxonomy_version: str
    total_trajectories: int = Field(default=0, ge=0)
    total_features: int = Field(default=0, ge=0)
    total_risk_categories: int = Field(default=0, ge=0)
    unique_behavior_profiles: int = Field(default=0, ge=0)
    intent_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    behavior_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    impact_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_depths: dict[str, int] = Field(default_factory=dict)
    risk_scope_version: str
    applicable_risk_categories: int = Field(default=0, ge=0)
    applicable_intent_coverage: float | None = Field(default=None, ge=0.0, le=1.0)
    applicable_behavior_coverage: float | None = Field(default=None, ge=0.0, le=1.0)
    applicable_impact_coverage: float | None = Field(default=None, ge=0.0, le=1.0)
    not_applicable_risk_categories: list[str] = Field(default_factory=list)
    uncovered_intent_categories: list[str] = Field(default_factory=list)
    uncovered_behavior_categories: list[str] = Field(default_factory=list)
    uncovered_impact_categories: list[str] = Field(default_factory=list)
    scope_exceeded_categories: dict[str, int] = Field(default_factory=dict)
    heatmap_data: list[dict[str, Any]] = Field(default_factory=list)
