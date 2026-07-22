"""Versioned replay, recording, checkpoint, and comparison contracts."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from sandbox.protocol import ToolReplayMode

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
ImageIdentity = Annotated[
    str,
    Field(pattern=r"^(?:.+@)?sha256:[0-9a-f]{64}$"),
]


class ReplayContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"


class ReplayMode(StrEnum):
    STRICT = "strict"
    LIVE = "live"


class ForkSuffixMode(StrEnum):
    LIVE_AND_RECORD = "live_and_record"
    STRICT_WITH_REPLACEMENTS = "strict_with_replacements"


class ReplayStatus(StrEnum):
    MATCHED = "matched"
    DIVERGED = "diverged"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CheckpointKind(StrEnum):
    BEFORE_MODEL = "before_model"
    AFTER_MODEL = "after_model"
    BEFORE_TOOL = "before_tool"
    AFTER_TOOL = "after_tool"
    NODE_COMMIT = "node_commit"


class ResumePhase(StrEnum):
    CALL_MODEL = "call_model"
    APPLY_MODEL_DECISION = "apply_model_decision"
    CALL_TOOL = "call_tool"
    APPLY_TOOL_RESULT = "apply_tool_result"
    ENTER_NEXT_NODE = "enter_next_node"


DEFAULT_INJECTIONS: dict[CheckpointKind, list[str]] = {
    CheckpointKind.BEFORE_MODEL: ["prompt_replace", "prompt_append"],
    CheckpointKind.AFTER_MODEL: ["model_decision_replace"],
    CheckpointKind.BEFORE_TOOL: ["tool_result_replace"],
    CheckpointKind.AFTER_TOOL: ["prompt_replace", "prompt_append"],
    CheckpointKind.NODE_COMMIT: ["prompt_replace", "prompt_append"],
}


class ArtifactRef(ReplayContract):
    media_type: str = Field(min_length=1, max_length=255)
    sha256: Digest
    size_bytes: int = Field(ge=0)
    relative_path: str

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if not value or "\\" in value or value.startswith(("/", "//")):
            raise ValueError("artifact path must be a forward-slash relative path")
        if re.match(r"^[A-Za-z]:", value):
            raise ValueError("artifact path must not contain a drive prefix")
        parts = value.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError("artifact path contains an unsafe segment")
        return value


class ReplayManifest(ReplayContract):
    model_config = ConfigDict(extra="forbid", frozen=True)

    replay_id: str
    trajectory_id: str
    created_at: datetime
    case_id: str
    scenario_id: str
    seed: int
    image_ref: str
    image_digest: ImageIdentity
    image_digest_kind: Literal["repo_digest", "image_id"]
    runtime_version: str
    protocol_version: str = "1"
    agent_version: str
    graph_version: str | None = None
    system_prompt_version: str | None = None
    system_prompt_digest: Digest | None = None
    trace_schema_version: str = "1.1"
    state_codec_version: str = "1.0"
    tool_registry_version: str | None = None
    policy_version: str | None = None
    normalization_version: str = "1.0"
    canonical_json_version: str = "1.0"
    default_tool_replay_mode: ToolReplayMode
    recording_complete: bool = True
    incomplete_reason: str | None = None
    prompt_digest: Digest
    initial_state_digest: Digest
    normalized_behavior_trace_digest: Digest
    determinism_config_digest: Digest
    prompt: ArtifactRef
    events: ArtifactRef
    initial_state: ArtifactRef
    determinism_config: ArtifactRef
    model_decisions: ArtifactRef
    tool_records: ArtifactRef
    checkpoints: ArtifactRef
    recording_audit: ArtifactRef | None = None
    filesystem_snapshot: ArtifactRef | None = None
    mock_responses: ArtifactRef | None = None
    parent_replay_id: str | None = None
    parent_trajectory_id: str | None = None
    fork_sequence: int | None = Field(default=None, ge=0)
    fork_checkpoint_id: str | None = None
    injection_digest: Digest | None = None
    parent_prefix_digest: Digest | None = None
    parent_prefix: ArtifactRef | None = None
    manifest_digest: Digest | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class ReplayRequest(ReplayContract):
    execution_id: str
    replay_run_id: str
    source_replay_id: str
    mode: ReplayMode
    manifest_relative_path: str


class ReplayCheckpointsRequest(ReplayContract):
    execution_id: str
    manifest_relative_path: str


class ForkInjection(ReplayContract):
    type: Literal[
        "prompt_replace",
        "prompt_append",
        "model_decision_replace",
        "tool_result_replace",
    ]
    content: JsonValue


class RecordedForkInjection(ForkInjection):
    content_digest: Digest
    operator: str
    created_at: datetime


class ReplayForkRequest(ReplayContract):
    execution_id: str
    child_replay_id: str
    manifest_relative_path: str
    checkpoint_id: str
    suffix_mode: ForkSuffixMode = ForkSuffixMode.LIVE_AND_RECORD
    injection: ForkInjection


class StateCheckpoint(ReplayContract):
    checkpoint_id: str
    execution_id: str
    sequence: int = Field(ge=0)
    logical_time: int = Field(ge=0)
    kind: CheckpointKind
    node_name: str | None = None
    resume_phase: ResumePhase
    resume_sequence: int = Field(ge=0)
    state_codec_version: str = "1.0"
    state_digest: Digest | None = None
    state_artifact: ArtifactRef | None = None
    next_model_decision_index: int = Field(default=0, ge=0)
    next_tool_interaction_index: int = Field(default=0, ge=0)
    allowed_injection_types: list[str] = Field(default_factory=list)
    recoverable: bool = True
    non_recoverable_reasons: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def apply_default_injections(cls, value: Any) -> Any:
        if isinstance(value, dict) and "allowed_injection_types" not in value:
            kind = CheckpointKind(value.get("kind"))
            value = {**value, "allowed_injection_types": list(DEFAULT_INJECTIONS[kind])}
        return value

    @model_validator(mode="after")
    def validate_recoverability(self) -> StateCheckpoint:
        if self.recoverable:
            if self.state_digest is None or self.state_artifact is None:
                raise ValueError("recoverable checkpoint requires state digest and artifact")
            if self.non_recoverable_reasons:
                raise ValueError("recoverable checkpoint cannot contain failure reasons")
        elif not self.non_recoverable_reasons:
            raise ValueError("non-recoverable checkpoint requires at least one reason")
        return self


class RecordedModelDecision(ReplayContract):
    decision_id: str
    sequence: int = Field(ge=0)
    decision_index: int = Field(ge=0)
    before_checkpoint_id: str
    after_checkpoint_id: str | None = None
    input_digest: Digest
    output_digest: Digest
    action: JsonValue
    model_name: str
    model_version: str


class RecordedToolInteraction(ReplayContract):
    interaction_id: str
    sequence: int = Field(ge=0)
    interaction_index: int = Field(ge=0)
    before_checkpoint_id: str
    after_checkpoint_id: str | None = None
    tool_name: str
    arguments: dict[str, JsonValue]
    arguments_digest: Digest
    result: JsonValue | None = None
    result_artifact: ArtifactRef | None = None
    result_digest: Digest
    replay_mode: ToolReplayMode
    policy_decision: str
    side_effect_digest_before: Digest | None = None
    side_effect_digest_after: Digest | None = None
    state_delta_artifact: ArtifactRef | None = None

    @model_validator(mode="after")
    def exactly_one_result_representation(self) -> RecordedToolInteraction:
        inline_was_set = "result" in self.model_fields_set
        if inline_was_set == (self.result_artifact is not None):
            raise ValueError("exactly one of result or result_artifact must be provided")
        return self


class CheckpointStateEnvelope(ReplayContract):
    state_codec_version: str = "1.0"
    checkpoint_kind: CheckpointKind
    resume_phase: ResumePhase
    logical_time: int = Field(ge=0)
    next_model_decision_index: int = Field(ge=0)
    next_tool_interaction_index: int = Field(ge=0)
    agent_state: dict[str, JsonValue]
    virtual_filesystem_state: dict[str, JsonValue]
    fake_shell_state: dict[str, JsonValue]
    mock_api_state: dict[str, JsonValue]
    rng_states: dict[str, JsonValue] = Field(default_factory=dict)
    environment: dict[str, str] = Field(default_factory=dict)


class CheckpointComparison(ReplayContract):
    source_checkpoint_id: str
    replay_checkpoint_id: str
    kind: CheckpointKind
    source_state_digest: Digest
    replay_state_digest: Digest
    matched: bool


class ReplayResult(ReplayContract):
    replay_run_id: str
    source_replay_id: str
    source_trajectory_id: str | None = None
    replay_trajectory_id: str | None = None
    status: ReplayStatus
    source_behavior_digest: Digest | None = None
    replay_behavior_digest: Digest | None = None
    source_final_state_digest: Digest | None = None
    replay_final_state_digest: Digest | None = None
    checkpoint_comparisons: list[CheckpointComparison] = Field(default_factory=list)
    first_divergence_behavior_index: int | None = Field(default=None, ge=0)
    source_divergence_sequence: int | None = Field(default=None, ge=0)
    replay_divergence_sequence: int | None = Field(default=None, ge=0)
    divergence_reason: str | None = None
    error_code: int | None = None
    missing_artifacts: list[str] = Field(default_factory=list)
    container_removed: bool


class ReplayAuditEvent(ReplayContract):
    replay_run_id: str
    audit_sequence: int = Field(ge=0)
    timestamp: datetime
    event_type: str
    data: dict[str, JsonValue] = Field(default_factory=dict)
