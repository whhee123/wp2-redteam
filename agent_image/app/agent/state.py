"""LangGraph state for the isolated Fake Agent."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class SandboxAgentState(TypedDict, total=False):
    prompt: str
    execution_id: str
    step_count: int
    max_steps: int
    action: dict[str, Any] | None
    pending_tool_calls: list[dict[str, Any]]
    tool_result: dict[str, Any] | None
    continue_loop: bool
    assistant_text: str | None
    final_answer: str | None
    pending_messages: list[dict[str, Any]]
    trace_events: Annotated[list[dict[str, Any]], operator.add]
