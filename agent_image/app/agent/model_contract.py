"""Stable projection between graph state and model-facing contracts."""

from __future__ import annotations

from typing import Any

from app.protocol import ModelDecision, ModelInput, ModelToolCall


def build_model_input(prompt: str, state: dict[str, Any] | None = None) -> ModelInput:
    state = state or {}
    return ModelInput(
        prompt=prompt,
        step_count=int(state.get("step_count", 0)),
        max_steps=int(state.get("max_steps", 20)),
        previous_action=state.get("action"),
        tool_result=state.get("tool_result"),
        pending_messages=list(state.get("pending_messages") or []),
    )


def coerce_model_input(
    value: ModelInput | str,
    *,
    state: dict[str, Any] | None = None,
) -> ModelInput:
    if isinstance(value, ModelInput):
        return value
    return build_model_input(value, state)


def coerce_recorded_decision(value: Any) -> ModelDecision:
    if not isinstance(value, dict):
        raise ValueError("recorded model decision must be an object")
    if "tool_calls" in value or "assistant_text" in value or "final_answer" in value:
        return ModelDecision.model_validate(value)
    # Backward compatibility with second-week manifests.
    action = value.get("action")
    calls = [ModelToolCall.model_validate(action)] if action is not None else []
    return ModelDecision(
        tool_calls=calls,
        continue_loop=bool(value.get("continue_loop", False)),
    )

