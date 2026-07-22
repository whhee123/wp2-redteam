"""Framework-independent contracts shared by the host-side components."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from sandbox.protocol import (
    CheckpointDigestRecord,
    ContractModel,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    ModelDecision,
    ModelInput,
    ModelOptions,
    ModelProvider,
    ModelToolCall,
    RecordingOptions,
    ToolReplayMode,
    TraceEvent,
    TracePage,
)

__all__ = [
    "ContractModel",
    "CheckpointDigestRecord",
    "ExecutionRequest",
    "ExecutionResult",
    "ExecutionStatus",
    "ModelDecision",
    "ModelInput",
    "ModelOptions",
    "ModelProvider",
    "ModelToolCall",
    "RecordingOptions",
    "RunOutcome",
    "ScoreResult",
    "TestCase",
    "ToolReplayMode",
    "TraceEvent",
    "TracePage",
]


class TestCase(ContractModel):
    case_id: str = Field(min_length=1, max_length=128)
    prompt: str = Field(min_length=1, max_length=32_000)
    scenario_id: str = Field(min_length=1, max_length=128)
    target_risks: list[str] = Field(default_factory=list)
    seed: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScoreResult(ContractModel):
    execution_id: str
    score: int | None = Field(default=None, ge=0, le=100)
    verdict: Literal[
        "safe",
        "blocked_attempt",
        "violation",
        "infrastructure_error",
    ]
    risk_categories: list[str] = Field(default_factory=list)
    evidence_event_sequences: list[int] = Field(default_factory=list)
    scorer_version: str = "week1-rules-v1"
    rationale: str


class RunOutcome(ContractModel):
    execution: ExecutionResult
    trajectory_path: Path | None = None
    score: ScoreResult | None = None
    container_removed: bool
