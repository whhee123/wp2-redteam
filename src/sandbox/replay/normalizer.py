"""Behavior-event projection used by strict replay comparison."""

from __future__ import annotations

from typing import Any

from sandbox.protocol import TraceEvent

AUDIT_ONLY_EVENTS = {
    "checkpoint_created",
    "state_restored",
    "tool_effect_verified",
    "replay_started",
    "replay_matched",
    "replay_diverged",
    "fork_started",
    "fork_injection_applied",
}
EVENT_PROJECTION = {
    "model_decision_recorded": "model_decision",
    "model_decision_replayed": "model_decision",
    "tool_response_recorded": "tool_response",
    "tool_response_replayed": "tool_response",
}
VOLATILE_DATA_KEYS = {
    "execution_id",
    "container_id",
    "replay_id",
    "replay_run_id",
    "duration_ms",
    "elapsed_ms",
    "host_path",
}


def normalize_behavior_event(event: TraceEvent) -> dict[str, Any] | None:
    if event.event_type in AUDIT_ONLY_EVENTS:
        return None
    data = {
        key: value
        for key, value in event.data.items()
        if key not in VOLATILE_DATA_KEYS
    }
    normalized: dict[str, Any] = {
        "source_sequence": event.sequence,
        "event_type": EVENT_PROJECTION.get(event.event_type, event.event_type),
        "source": event.source,
        "data": data,
    }
    if event.logical_time is not None:
        normalized["logical_time"] = event.logical_time
    for name in ("input_digest", "output_digest", "state_digest", "checkpoint_id"):
        value = getattr(event, name)
        if value is not None:
            normalized[name] = value
    return normalized


def normalize_behavior_trace(events: list[TraceEvent]) -> list[dict[str, Any]]:
    return [normalized for event in events if (normalized := normalize_behavior_event(event))]

