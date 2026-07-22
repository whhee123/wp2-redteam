"""Single source of truth for host/container JSON-RPC contracts.

The Docker image copies the host ``sandbox`` package into the runtime image.
``agent_image/app/protocol.py`` only re-exports these definitions and therefore
cannot silently drift from the host package.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"


class ExecutionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"

    @property
    def terminal(self) -> bool:
        return self in {
            self.SUCCEEDED,
            self.FAILED,
            self.CANCELLED,
            self.TIMED_OUT,
        }


class ToolReplayMode(StrEnum):
    EXECUTE_AND_VERIFY = "execute_and_verify"
    STUB_RESPONSE = "stub_response"


class ModelProvider(StrEnum):
    FAKE = "fake"
    OLLAMA = "ollama"


class ModelOptions(ContractModel):
    provider: ModelProvider = ModelProvider.FAKE
    model_name: str = "llama3"
    model_digest: str | None = Field(default=None, min_length=1, max_length=256)
    endpoint: str | None = None
    timeout_seconds: int = Field(default=60, ge=1, le=600)

    @model_validator(mode="after")
    def validate_provider_endpoint(self) -> ModelOptions:
        if self.provider == ModelProvider.OLLAMA and not self.endpoint:
            raise ValueError("Ollama provider requires an endpoint")
        return self


class ModelToolCall(ContractModel):
    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ModelInput(ContractModel):
    prompt: str = Field(min_length=1, max_length=32_000)
    step_count: int = Field(default=0, ge=0)
    max_steps: int = Field(default=20, ge=1, le=100)
    previous_action: dict[str, Any] | None = None
    tool_result: dict[str, Any] | None = None
    pending_messages: list[dict[str, Any]] = Field(default_factory=list)


class ModelDecision(ContractModel):
    assistant_text: str | None = Field(default=None, max_length=32_000)
    tool_calls: list[ModelToolCall] = Field(default_factory=list, max_length=8)
    continue_loop: bool = False
    final_answer: str | None = Field(default=None, max_length=32_000)


class RecordingOptions(ContractModel):
    enabled: bool = False
    checkpoint_policy: str = "stable_boundaries"
    default_tool_replay_mode: ToolReplayMode = ToolReplayMode.EXECUTE_AND_VERIFY
    normalization_version: str = "1.0"


class ExecutionRequest(ContractModel):
    execution_id: str = Field(min_length=1, max_length=128)
    case_id: str = Field(min_length=1, max_length=128)
    prompt: str = Field(min_length=1, max_length=32_000)
    max_steps: int = Field(default=20, ge=1, le=100)
    timeout_seconds: int = Field(default=120, ge=1, le=600)
    metadata: dict[str, Any] = Field(default_factory=dict)
    seed: int | None = None
    scenario_id: str | None = None
    agent_version: str | None = None
    image_digest: str | None = None
    recording: RecordingOptions | None = None
    model: ModelOptions | None = None


class TraceEvent(ContractModel):
    execution_id: str
    sequence: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    data: dict[str, Any] = Field(default_factory=dict)
    logical_time: int | None = Field(default=None, ge=0)
    input_digest: str | None = None
    output_digest: str | None = None
    state_digest: str | None = None
    checkpoint_id: str | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value


class CheckpointDigestRecord(ContractModel):
    checkpoint_index: int = Field(ge=0)
    kind: str
    state_digest: str


class ExecutionResult(ContractModel):
    execution_id: str
    status: ExecutionStatus
    final_answer: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    trace_count: int = Field(default=0, ge=0)
    final_sequence: int | None = Field(default=None, ge=0)
    final_state_digest: str | None = None
    checkpoint_digests: list[CheckpointDigestRecord] = Field(default_factory=list)


class TracePage(ContractModel):
    events: list[TraceEvent] = Field(default_factory=list)
    next_after_sequence: int = -1
    terminal: bool = False
    final_sequence: int | None = None


class EventsRequest(BaseModel):
    execution_id: str
    after_sequence: int = Field(default=-1, ge=-1)
    limit: int = Field(default=100, ge=1, le=100)


class ExecutionIdRequest(BaseModel):
    execution_id: str


class JsonRpcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jsonrpc: str
    id: str | int | None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


def rpc_result(request_id: str | int | None, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def rpc_error(
    request_id: str | int | None,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
