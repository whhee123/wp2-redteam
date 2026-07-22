"""Explicit JSON state export/import; pickle is intentionally unsupported."""

from __future__ import annotations

from typing import Any

from sandbox.replay.models import CheckpointKind, CheckpointStateEnvelope, ResumePhase

AGENT_STATE_FIELDS = {
    "prompt",
    "step_count",
    "max_steps",
    "action",
    "pending_tool_calls",
    "tool_result",
    "continue_loop",
    "assistant_text",
    "final_answer",
    "current_node",
    "pending_messages",
}


class StateCodec:
    version = "1.0"

    def export(
        self,
        state: dict[str, Any],
        tools,
        *,
        checkpoint_kind: CheckpointKind,
        resume_phase: ResumePhase,
        logical_time: int,
        next_model_decision_index: int,
        next_tool_interaction_index: int,
    ) -> CheckpointStateEnvelope:
        tool_state = tools.export_state()
        return CheckpointStateEnvelope(
            checkpoint_kind=checkpoint_kind,
            resume_phase=resume_phase,
            logical_time=logical_time,
            next_model_decision_index=next_model_decision_index,
            next_tool_interaction_index=next_tool_interaction_index,
            agent_state={
                key: value
                for key, value in state.items()
                if key in AGENT_STATE_FIELDS
            },
            virtual_filesystem_state=tool_state["virtual_filesystem_state"],
            fake_shell_state=tool_state["fake_shell_state"],
            mock_api_state=tool_state["mock_api_state"],
            rng_states={},
            environment={"agent_runtime": "fake-langgraph-v1"},
        )

    def restore(
        self,
        envelope: CheckpointStateEnvelope,
        tools,
        *,
        execution_id: str,
    ) -> dict[str, Any]:
        if envelope.state_codec_version != self.version:
            raise ValueError("state codec version is incompatible")
        tools.import_state(
            {
                "virtual_filesystem_state": envelope.virtual_filesystem_state,
                "fake_shell_state": envelope.fake_shell_state,
                "mock_api_state": envelope.mock_api_state,
            }
        )
        return {**envelope.agent_state, "execution_id": execution_id}
