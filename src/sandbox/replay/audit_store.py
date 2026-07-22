"""Independent replay-control audit stream, separate from behavior trajectories."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sandbox.replay.canonical import canonical_json_bytes
from sandbox.replay.models import ReplayAuditEvent


class ReplayAuditStore:
    def __init__(self, replay_run_id: str) -> None:
        self.replay_run_id = replay_run_id
        self._events: list[ReplayAuditEvent] = []

    @property
    def events(self) -> tuple[ReplayAuditEvent, ...]:
        return tuple(self._events)

    def append(self, event_type: str, data: dict[str, Any] | None = None) -> ReplayAuditEvent:
        event = ReplayAuditEvent(
            replay_run_id=self.replay_run_id,
            audit_sequence=len(self._events),
            timestamp=datetime.now(UTC),
            event_type=event_type,
            data=data or {},
        )
        self._events.append(event)
        return event

    def to_jsonl(self) -> bytes:
        return b"".join(canonical_json_bytes(event) + b"\n" for event in self._events)

