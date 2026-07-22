"""Digest-only checkpoint observer used during replay comparison."""

from __future__ import annotations

from typing import Any

from app.replay.state_codec import StateCodec
from sandbox.protocol import CheckpointDigestRecord
from sandbox.replay.digests import sha256_digest
from sandbox.replay.models import CheckpointKind, ResumePhase


class ReplayCheckpointObserver:
    def __init__(self, model, tools) -> None:
        self.model = model
        self.tools = tools
        self.codec = StateCodec()
        self.records: list[CheckpointDigestRecord] = []

    @property
    def final_state_digest(self) -> str | None:
        return self.records[-1].state_digest if self.records else None

    def capture(
        self,
        state: dict[str, Any],
        *,
        kind: CheckpointKind,
        resume_phase: ResumePhase,
    ) -> CheckpointDigestRecord:
        envelope = self.codec.export(
            state,
            self.tools,
            checkpoint_kind=kind,
            resume_phase=resume_phase,
            logical_time=len(self.records),
            next_model_decision_index=int(getattr(self.model, "next_index", 0)),
            next_tool_interaction_index=int(getattr(self.tools, "next_index", 0)),
        )
        record = CheckpointDigestRecord(
            checkpoint_index=len(self.records),
            kind=kind.value,
            state_digest=sha256_digest(envelope),
        )
        self.records.append(record)
        return record

