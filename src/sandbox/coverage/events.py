"""Shared event-window utilities for feature and risk extraction."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sandbox.protocol import TraceEvent

EventLike = TraceEvent | dict[str, Any]


def event_type(event: EventLike) -> str:
    return event.event_type if isinstance(event, TraceEvent) else str(event.get("event_type", ""))


def event_source(event: EventLike) -> str:
    return event.source if isinstance(event, TraceEvent) else str(event.get("source", ""))


def event_data(event: EventLike) -> dict[str, Any]:
    data = event.data if isinstance(event, TraceEvent) else event.get("data", {})
    return dict(data) if isinstance(data, dict) else {}


def event_sequence(event: EventLike) -> int:
    if isinstance(event, TraceEvent):
        return event.sequence
    return int(event.get("source_sequence", event.get("sequence", -1)))


@dataclass
class ToolWindow:
    tool_name: str
    arguments: dict[str, Any]
    call_sequence: int
    evidence_sequences: list[int] = field(default_factory=list)
    security_categories: list[str] = field(default_factory=list)
    result: dict[str, Any] | None = None
    result_sequence: int | None = None
    closed: bool = False


def iter_tool_windows(events: Iterable[EventLike]) -> list[ToolWindow]:
    windows: list[ToolWindow] = []
    current: ToolWindow | None = None
    for event in events:
        kind = event_type(event)
        data = event_data(event)
        sequence = event_sequence(event)
        if kind == "tool_call":
            if current is not None:
                windows.append(current)
            arguments = data.get("arguments")
            current = ToolWindow(
                tool_name=str(data.get("name", "")),
                arguments=dict(arguments) if isinstance(arguments, dict) else {},
                call_sequence=sequence,
                evidence_sequences=[sequence],
            )
            continue
        if current is None:
            continue
        if kind == "security_violation":
            risk_category = data.get("risk_category")
            if isinstance(risk_category, str) and risk_category:
                current.security_categories.append(risk_category)
            current.evidence_sequences.append(sequence)
        elif kind == "tool_result":
            current.result = data
            current.result_sequence = sequence
            current.evidence_sequences.append(sequence)
            current.closed = True
            windows.append(current)
            current = None
        elif kind == "node_start" and event_source(event).removeprefix("langgraph.") == "tool":
            # A tool node may precede its tool_call; it only closes an already malformed window.
            if current.call_sequence != sequence:
                windows.append(current)
                current = None
    if current is not None:
        windows.append(current)
    return windows


def terminal_kind(events: Iterable[EventLike]) -> str:
    last_type = ""
    for event in events:
        kind = event_type(event)
        if kind.startswith("execution_"):
            last_type = kind
    return {
        "execution_finished": "succeeded",
        "execution_timed_out": "timed_out",
        "execution_cancelled": "cancelled",
        "execution_error": "error",
    }.get(last_type, "error")
