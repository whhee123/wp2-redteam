"""Recording session and stable-boundary checkpoint persistence."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.replay.decision_recorder import DecisionRecorder
from app.replay.state_codec import StateCodec
from app.replay.tool_recorder import ToolRecorder
from sandbox.protocol import RecordingOptions, TraceEvent
from sandbox.replay.canonical import canonical_json_bytes
from sandbox.replay.digests import sha256_bytes
from sandbox.replay.models import (
    ArtifactRef,
    CheckpointKind,
    ResumePhase,
    StateCheckpoint,
)


class RecordingSession:
    def __init__(
        self,
        request,
        model,
        tools,
        output_dir: Path | None = None,
        *,
        start_node: str = "agent",
    ) -> None:
        options = request.recording or RecordingOptions(enabled=True)
        self.request = request
        self.output_dir = output_dir or Path(
            os.environ.get("REPLAY_OUTPUT_DIR", "/workspace/replay-out")
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.codec = StateCodec()
        self.model = DecisionRecorder(model)
        self.tools = ToolRecorder(tools, replay_mode=options.default_tool_replay_mode)
        self.checkpoints: list[StateCheckpoint] = []
        self.audit_events: list[dict[str, Any]] = []
        self.initial_state_bytes: bytes | None = None
        self.start_node = start_node

    def start(self, state: dict[str, Any]) -> None:
        checkpoint = self._capture(
            state,
            kind=CheckpointKind.NODE_COMMIT,
            resume_phase=ResumePhase.ENTER_NEXT_NODE,
            sequence=0,
            node_name="start",
        )
        self.initial_state_bytes = self._state_bytes(checkpoint)

    def before_model(self, state: dict[str, Any], sequence: int) -> StateCheckpoint:
        checkpoint = self._capture(
            state,
            kind=CheckpointKind.BEFORE_MODEL,
            resume_phase=ResumePhase.CALL_MODEL,
            sequence=sequence,
            node_name="agent",
        )
        self.model.set_context(sequence=sequence, before_checkpoint_id=checkpoint.checkpoint_id)
        return checkpoint

    def after_model(self, state: dict[str, Any], sequence: int) -> StateCheckpoint:
        checkpoint = self._capture(
            state,
            kind=CheckpointKind.AFTER_MODEL,
            resume_phase=ResumePhase.APPLY_MODEL_DECISION,
            sequence=sequence,
            node_name="agent",
        )
        self.model.attach_after_checkpoint(checkpoint.checkpoint_id)
        return checkpoint

    def before_tool(self, state: dict[str, Any], sequence: int) -> StateCheckpoint:
        checkpoint = self._capture(
            state,
            kind=CheckpointKind.BEFORE_TOOL,
            resume_phase=ResumePhase.CALL_TOOL,
            sequence=sequence,
            node_name="tool",
        )
        self.tools.set_context(sequence=sequence, before_checkpoint_id=checkpoint.checkpoint_id)
        return checkpoint

    def after_tool(self, state: dict[str, Any], sequence: int) -> StateCheckpoint:
        checkpoint = self._capture(
            state,
            kind=CheckpointKind.AFTER_TOOL,
            resume_phase=ResumePhase.APPLY_TOOL_RESULT,
            sequence=sequence,
            node_name="tool",
        )
        self.tools.attach_after_checkpoint(checkpoint.checkpoint_id)
        return checkpoint

    def finalize(self, state: dict[str, Any], events: list[TraceEvent]) -> None:
        self._capture(
            state,
            kind=CheckpointKind.NODE_COMMIT,
            resume_phase=ResumePhase.ENTER_NEXT_NODE,
            sequence=max(0, len(events) - 1),
            node_name="finalize",
        )
        self._write_artifacts(events, complete=True, incomplete_reason=None)

    def finalize_incomplete(
        self,
        events: list[TraceEvent],
        *,
        reason: str,
    ) -> None:
        self.audit_events.append(
            {
                "event_type": "recording_incomplete",
                "reason": reason,
                "truncated_artifacts": ["events.jsonl", "checkpoints.jsonl"],
            }
        )
        self.checkpoints = [
            checkpoint.model_copy(
                update={
                    "recoverable": False,
                    "non_recoverable_reasons": [f"recording incomplete: {reason}"],
                }
            )
            for checkpoint in self.checkpoints
        ]
        self._write_artifacts(events, complete=False, incomplete_reason=reason)

    def _write_artifacts(
        self,
        events: list[TraceEvent],
        *,
        complete: bool,
        incomplete_reason: str | None,
    ) -> None:
        if self.initial_state_bytes is None:
            raise RuntimeError("recording session was not started")
        self._write("prompt.json", canonical_json_bytes({"prompt": self.request.prompt}))
        self._write("initial-state.json", self.initial_state_bytes)
        self._write(
            "determinism-config.json",
            canonical_json_bytes(
                {
                    "seed": self.request.seed,
                    "max_steps": self.request.max_steps,
                    "timeout_seconds": self.request.timeout_seconds,
                    "start_node": self.start_node,
                    "recording_complete": complete,
                    "incomplete_reason": incomplete_reason,
                    "model": (
                        self.request.model.model_dump(mode="json")
                        if self.request.model is not None
                        else None
                    ),
                }
            ),
        )
        self._write_jsonl("events.jsonl", [event.model_dump(mode="json") for event in events])
        self._write_jsonl(
            "model-decisions.jsonl",
            [decision.model_dump(mode="json") for decision in self.model.decisions],
        )
        self._write_jsonl(
            "tool-records.jsonl",
            [record.model_dump(mode="json") for record in self.tools.interactions],
        )
        self._write_jsonl(
            "checkpoints.jsonl",
            [checkpoint.model_dump(mode="json") for checkpoint in self.checkpoints],
        )
        self._write_jsonl("recording-audit.jsonl", self.audit_events)

    def _capture(
        self,
        state: dict[str, Any],
        *,
        kind: CheckpointKind,
        resume_phase: ResumePhase,
        sequence: int,
        node_name: str,
    ) -> StateCheckpoint:
        envelope = self.codec.export(
            state,
            self.tools,
            checkpoint_kind=kind,
            resume_phase=resume_phase,
            logical_time=len(self.checkpoints),
            next_model_decision_index=len(self.model.decisions),
            next_tool_interaction_index=len(self.tools.interactions),
        )
        payload = canonical_json_bytes(envelope)
        digest = sha256_bytes(payload)
        hex_digest = digest.removeprefix("sha256:")
        relative_path = f"states/{hex_digest}.json"
        self._write(relative_path, payload)
        checkpoint = StateCheckpoint(
            checkpoint_id=f"checkpoint-{uuid4().hex}",
            execution_id=self.request.execution_id,
            sequence=max(0, sequence),
            logical_time=len(self.checkpoints),
            kind=kind,
            node_name=node_name,
            resume_phase=resume_phase,
            resume_sequence=max(0, sequence + 1),
            state_digest=digest,
            state_artifact=ArtifactRef(
                media_type="application/json",
                sha256=digest,
                size_bytes=len(payload),
                relative_path=relative_path,
            ),
            next_model_decision_index=len(self.model.decisions),
            next_tool_interaction_index=len(self.tools.interactions),
        )
        self.checkpoints.append(checkpoint)
        self.audit_events.append(
            {
                "event_type": "checkpoint_created",
                "checkpoint_id": checkpoint.checkpoint_id,
                "kind": kind.value,
                "state_digest": digest,
            }
        )
        return checkpoint

    def _state_bytes(self, checkpoint: StateCheckpoint) -> bytes:
        if checkpoint.state_artifact is None:
            raise RuntimeError("checkpoint has no state artifact")
        return (self.output_dir / checkpoint.state_artifact.relative_path).read_bytes()

    def _write_jsonl(self, relative_path: str, records: list[dict[str, Any]]) -> None:
        payload = b"".join(canonical_json_bytes(record) + b"\n" for record in records)
        self._write(relative_path, payload)

    def _write(self, relative_path: str, payload: bytes) -> None:
        destination = self.output_dir / Path(*relative_path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".partial")
        temporary.write_bytes(payload)
        os.replace(temporary, destination)
