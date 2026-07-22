from __future__ import annotations

from pathlib import Path

import pytest

from sandbox.errors import TraceIntegrityError
from sandbox.models import TraceEvent
from sandbox.storage.trajectory_store import TrajectoryStore


def event(execution_id: str, sequence: int, event_type: str) -> TraceEvent:
    return TraceEvent(
        execution_id=execution_id,
        sequence=sequence,
        event_type=event_type,
        source="test",
    )


def test_store_commits_contiguous_terminal_trace(tmp_path: Path) -> None:
    store = TrajectoryStore(tmp_path, "exec-1")
    store.append(
        [
            event("exec-1", 0, "execution_started"),
            event("exec-1", 1, "execution_finished"),
        ]
    )
    trajectory = store.commit(final_sequence=1, trace_count=2)
    assert trajectory.path.exists()
    assert not store.partial_path.exists()
    assert TrajectoryStore.load(trajectory.path).events == trajectory.events


def test_store_rejects_sequence_gap(tmp_path: Path) -> None:
    store = TrajectoryStore(tmp_path, "exec-1")
    with pytest.raises(TraceIntegrityError, match="expected sequence 0"):
        store.append([event("exec-1", 1, "execution_started")])


def test_store_rejects_non_terminal_last_event(tmp_path: Path) -> None:
    store = TrajectoryStore(tmp_path, "exec-1")
    store.append([event("exec-1", 0, "tool_call")])
    with pytest.raises(TraceIntegrityError, match="terminal execution event"):
        store.commit(final_sequence=0, trace_count=1)


def test_load_partial_recovers_valid_event_prefix(tmp_path: Path) -> None:
    store = TrajectoryStore(tmp_path, "exec-partial")
    store.append(
        [
            event("exec-partial", 0, "execution_started"),
            event("exec-partial", 1, "tool_call"),
        ]
    )

    partial = TrajectoryStore.load_partial(store.partial_path)

    assert partial.execution_id == "exec-partial"
    assert partial.path == store.partial_path
    assert [item.sequence for item in partial.events] == [0, 1]
