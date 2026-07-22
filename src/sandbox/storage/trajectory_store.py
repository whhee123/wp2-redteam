"""Append-only JSONL trace storage with strict sequence validation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sandbox.errors import TraceIntegrityError
from sandbox.identifiers import validate_execution_id
from sandbox.models import TraceEvent


@dataclass(frozen=True)
class CommittedTrajectory:
    execution_id: str
    path: Path
    events: tuple[TraceEvent, ...]


@dataclass(frozen=True)
class PartialTrajectory:
    """Diagnostic view of a non-committed trajectory prefix."""

    execution_id: str
    path: Path
    events: tuple[TraceEvent, ...]


class TrajectoryStore:
    """Persist one execution to a partial file and atomically commit it."""

    def __init__(self, output_dir: Path, execution_id: str, max_events: int = 1_000) -> None:
        try:
            validate_execution_id(execution_id)
        except ValueError as exc:
            raise TraceIntegrityError("invalid trajectory execution_id") from exc
        self.output_dir = output_dir
        self.execution_id = execution_id
        self.max_events = max_events
        self.partial_path = output_dir / f"{execution_id}.jsonl.partial"
        self.final_path = output_dir / f"{execution_id}.jsonl"
        self._events: list[TraceEvent] = []
        self._next_sequence = 0
        output_dir.mkdir(parents=True, exist_ok=True)
        if self.partial_path.exists() or self.final_path.exists():
            raise TraceIntegrityError(f"trajectory path already exists for {execution_id}")

    @property
    def events(self) -> tuple[TraceEvent, ...]:
        return tuple(self._events)

    def append(self, events: list[TraceEvent]) -> None:
        if not events:
            return
        if len(self._events) + len(events) > self.max_events:
            raise TraceIntegrityError("trace event limit exceeded")

        serialized: list[str] = []
        for event in events:
            if event.execution_id != self.execution_id:
                raise TraceIntegrityError("event execution_id does not match trajectory")
            if event.sequence != self._next_sequence:
                raise TraceIntegrityError(
                    f"expected sequence {self._next_sequence}, got {event.sequence}"
                )
            serialized.append(event.model_dump_json())
            self._events.append(event)
            self._next_sequence += 1

        with self.partial_path.open("a", encoding="utf-8", newline="\n") as stream:
            for line in serialized:
                stream.write(line)
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

    def commit(self, *, final_sequence: int | None, trace_count: int) -> CommittedTrajectory:
        if final_sequence is None:
            raise TraceIntegrityError("terminal result is missing final_sequence")
        if not self._events:
            raise TraceIntegrityError("cannot commit an empty trajectory")
        if self._events[-1].sequence != final_sequence:
            raise TraceIntegrityError(
                f"last event sequence {self._events[-1].sequence} != {final_sequence}"
            )
        if len(self._events) != trace_count:
            raise TraceIntegrityError(
                f"event count {len(self._events)} != runtime trace_count {trace_count}"
            )
        if not self._events[-1].event_type.startswith("execution_"):
            raise TraceIntegrityError("last event must be a terminal execution event")
        self.partial_path.replace(self.final_path)
        return CommittedTrajectory(
            execution_id=self.execution_id,
            path=self.final_path,
            events=tuple(self._events),
        )

    @classmethod
    def load(cls, path: Path) -> CommittedTrajectory:
        events = cls._read_events(path)
        if not events:
            raise TraceIntegrityError("trajectory is empty")
        execution_id = cls._validate_contiguous(events)
        return CommittedTrajectory(execution_id=execution_id, path=path, events=events)

    @classmethod
    def load_partial(cls, path: Path) -> PartialTrajectory:
        """Load a retained `.jsonl.partial` file without making it scoreable."""

        if not path.name.endswith(".jsonl.partial"):
            raise TraceIntegrityError("partial trajectory path must end with .jsonl.partial")
        events = cls._read_events(path)
        if not events:
            execution_id = path.name.removesuffix(".jsonl.partial")
        else:
            execution_id = cls._validate_contiguous(events)
        return PartialTrajectory(execution_id=execution_id, path=path, events=events)

    @staticmethod
    def _read_events(path: Path) -> tuple[TraceEvent, ...]:
        try:
            return tuple(
                TraceEvent.model_validate_json(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        except Exception as exc:
            raise TraceIntegrityError(f"invalid trajectory JSONL: {path}") from exc

    @staticmethod
    def _validate_contiguous(events: tuple[TraceEvent, ...]) -> str:
        execution_id = events[0].execution_id
        for expected, event in enumerate(events):
            if event.execution_id != execution_id or event.sequence != expected:
                raise TraceIntegrityError("stored trajectory is not contiguous")
        return execution_id
