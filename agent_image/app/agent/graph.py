"""LangGraph state machine that drives the deterministic Fake Agent."""

from __future__ import annotations

from typing import Any, Literal

from langgraph.graph import END, START, StateGraph

from app.agent.model_contract import build_model_input
from app.agent.state import SandboxAgentState
from app.tools.base import ToolRegistry
from sandbox.replay.models import CheckpointKind, ResumePhase
from sandbox.versions import GRAPH_VERSION as GRAPH_VERSION

__all__ = ["GRAPH_VERSION", "build_graph"]



def build_graph(
    model,
    tools: ToolRegistry,
    recording=None,
    *,
    replaying=False,
    checkpoint_observer=None,
    start_node: Literal["agent", "tool", "finalize"] = "agent",
):
    async def agent_node(state: SandboxAgentState) -> dict[str, Any]:
        step_count = state.get("step_count", 0) + 1
        before = recording.before_model(dict(state), step_count) if recording else None
        if checkpoint_observer:
            checkpoint_observer.capture(
                dict(state),
                kind=CheckpointKind.BEFORE_MODEL,
                resume_phase=ResumePhase.CALL_MODEL,
            )
        model_input = build_model_input(state["prompt"], dict(state))
        decision = model.plan(model_input, state=dict(state))
        decision_payload = decision.model_dump(mode="json")
        tool_calls = [call.model_dump(mode="json") for call in decision.tool_calls]
        action = tool_calls[0] if tool_calls else None
        pending_tool_calls = tool_calls[1:]
        pending_messages = list(state.get("pending_messages") or [])
        if decision.assistant_text:
            pending_messages.append(
                {"role": "assistant", "content": decision.assistant_text}
            )
        after_state = {
            **state,
            "step_count": step_count,
            "action": action,
            "pending_tool_calls": pending_tool_calls,
            "continue_loop": decision.continue_loop,
            "assistant_text": decision.assistant_text,
            "final_answer": decision.final_answer,
            "pending_messages": pending_messages,
        }
        after = recording.after_model(after_state, step_count) if recording else None
        if checkpoint_observer:
            checkpoint_observer.capture(
                after_state,
                kind=CheckpointKind.AFTER_MODEL,
                resume_phase=ResumePhase.APPLY_MODEL_DECISION,
            )
        events = [
            {"event_type": "node_start", "source": "langgraph.agent", "data": {"step": step_count}},
            {"event_type": "model_start", "source": model.version, "data": {"step": step_count}},
            {
                "event_type": "model_end",
                "source": model.version,
                "data": {"step": step_count, "decision": decision_payload},
            },
            {"event_type": "node_end", "source": "langgraph.agent", "data": {"step": step_count}},
        ]
        if recording:
            decision = recording.model.decisions[-1]
            events.append(
                {
                    "event_type": "model_decision_recorded",
                    "source": model.version,
                    "data": {
                        "decision_index": decision.decision_index,
                        "action": action,
                        "decision": decision_payload,
                        "continue_loop": decision_payload["continue_loop"],
                        "before_checkpoint_id": before.checkpoint_id,
                        "after_checkpoint_id": after.checkpoint_id,
                        "input_digest": decision.input_digest,
                        "output_digest": decision.output_digest,
                    },
                    "replay_fields": {
                        "logical_time": step_count,
                        "input_digest": decision.input_digest,
                        "output_digest": decision.output_digest,
                        "checkpoint_id": after.checkpoint_id,
                    },
                }
            )
        elif replaying:
            decision = model.last_decision
            events.append(
                {
                    "event_type": "model_decision_replayed",
                    "source": model.version,
                    "data": {
                        "decision_index": decision.decision_index,
                        "action": action,
                        "decision": decision_payload,
                        "continue_loop": decision_payload["continue_loop"],
                        "before_checkpoint_id": decision.before_checkpoint_id,
                        "after_checkpoint_id": decision.after_checkpoint_id,
                        "input_digest": decision.input_digest,
                        "output_digest": decision.output_digest,
                    },
                    "replay_fields": {
                        "logical_time": step_count,
                        "input_digest": decision.input_digest,
                        "output_digest": decision.output_digest,
                        "checkpoint_id": decision.after_checkpoint_id,
                    },
                }
            )
        return {
            "step_count": step_count,
            "action": action,
            "pending_tool_calls": pending_tool_calls,
            "continue_loop": decision_payload["continue_loop"],
            "assistant_text": decision_payload["assistant_text"],
            "final_answer": decision_payload["final_answer"],
            "pending_messages": pending_messages,
            "trace_events": events,
        }

    async def tool_node(state: SandboxAgentState) -> dict[str, Any]:
        action = state.get("action") or {}
        before = (
            recording.before_tool(dict(state), state.get("step_count", 0))
            if recording
            else None
        )
        if checkpoint_observer:
            checkpoint_observer.capture(
                dict(state),
                kind=CheckpointKind.BEFORE_TOOL,
                resume_phase=ResumePhase.CALL_TOOL,
            )
        result = tools.execute(action)
        result_data = result.to_dict()
        pending_tool_calls = list(state.get("pending_tool_calls") or [])
        next_action = pending_tool_calls[0] if pending_tool_calls else None
        remaining_tool_calls = pending_tool_calls[1:]
        pending_messages = [
            *list(state.get("pending_messages") or []),
            {
                "role": "tool",
                "name": action.get("name"),
                "content": result_data,
            },
        ]
        after_state = {
            **state,
            "action": next_action,
            "pending_tool_calls": remaining_tool_calls,
            "tool_result": result_data,
            "pending_messages": pending_messages,
        }
        after = recording.after_tool(after_state, state.get("step_count", 0)) if recording else None
        if checkpoint_observer:
            checkpoint_observer.capture(
                after_state,
                kind=CheckpointKind.AFTER_TOOL,
                resume_phase=ResumePhase.APPLY_TOOL_RESULT,
            )
        events = [
            {"event_type": "node_start", "source": "langgraph.tool", "data": {}},
            {"event_type": "tool_call", "source": "controlled_tools", "data": action},
        ]
        if not result.allowed and result.risk_category:
            events.append(
                {
                    "event_type": "security_violation",
                    "source": "tool_policy",
                    "data": {
                        "risk_category": result.risk_category,
                        "reason": result.error,
                        "tool": action.get("name"),
                    },
                }
            )
        events.extend(
            [
                {"event_type": "tool_result", "source": "controlled_tools", "data": result_data},
                {"event_type": "node_end", "source": "langgraph.tool", "data": {}},
            ]
        )
        if recording:
            interaction = recording.tools.interactions[-1]
            events.append(
                {
                    "event_type": "tool_response_recorded",
                    "source": "controlled_tools",
                    "data": {
                        "interaction_index": interaction.interaction_index,
                        "tool_name": interaction.tool_name,
                        "result": result_data,
                        "before_checkpoint_id": before.checkpoint_id,
                        "after_checkpoint_id": after.checkpoint_id,
                        "arguments_digest": interaction.arguments_digest,
                        "result_digest": interaction.result_digest,
                    },
                    "replay_fields": {
                        "logical_time": state.get("step_count", 0),
                        "input_digest": interaction.arguments_digest,
                        "output_digest": interaction.result_digest,
                        "state_digest": interaction.side_effect_digest_after,
                        "checkpoint_id": after.checkpoint_id,
                    },
                }
            )
        elif replaying:
            interaction = tools.last_record
            events.append(
                {
                    "event_type": "tool_response_replayed",
                    "source": "controlled_tools",
                    "data": {
                        "interaction_index": interaction.interaction_index,
                        "tool_name": interaction.tool_name,
                        "result": result_data,
                        "before_checkpoint_id": interaction.before_checkpoint_id,
                        "after_checkpoint_id": interaction.after_checkpoint_id,
                        "arguments_digest": interaction.arguments_digest,
                        "result_digest": interaction.result_digest,
                    },
                    "replay_fields": {
                        "logical_time": state.get("step_count", 0),
                        "input_digest": interaction.arguments_digest,
                        "output_digest": interaction.result_digest,
                        "state_digest": interaction.side_effect_digest_after,
                        "checkpoint_id": interaction.after_checkpoint_id,
                    },
                }
            )
        return {
            "action": next_action,
            "pending_tool_calls": remaining_tool_calls,
            "tool_result": result_data,
            "pending_messages": pending_messages,
            "trace_events": events,
        }

    async def finalize_node(state: SandboxAgentState) -> dict[str, Any]:
        result = state.get("tool_result")
        if state.get("final_answer") is not None:
            answer = str(state["final_answer"])
        elif result is None and state.get("assistant_text"):
            answer = str(state["assistant_text"])
        elif result is None:
            answer = "No controlled tool was required."
        elif result.get("allowed") and result.get("outcome") == "succeeded":
            answer = f"Controlled tool completed: {result.get('output')}"
        else:
            answer = f"Controlled tool request was not completed: {result.get('error')}"
        return {
            "final_answer": answer,
            "trace_events": [
                {"event_type": "node_start", "source": "langgraph.finalize", "data": {}},
                {"event_type": "node_end", "source": "langgraph.finalize", "data": {}},
            ],
        }

    def route_after_agent(state: SandboxAgentState) -> Literal["tool", "finalize"]:
        return "tool" if state.get("action") else "finalize"

    def route_after_tool(state: SandboxAgentState) -> Literal["agent", "tool", "finalize"]:
        if state.get("action"):
            return "tool"
        if state.get("continue_loop") and state.get("step_count", 0) < state.get("max_steps", 1):
            return "agent"
        return "finalize"

    graph = StateGraph(SandboxAgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tool", tool_node)
    graph.add_node("finalize", finalize_node)
    graph.add_edge(START, start_node)
    graph.add_conditional_edges(
        "agent",
        route_after_agent,
        {"tool": "tool", "finalize": "finalize"},
    )
    graph.add_conditional_edges(
        "tool",
        route_after_tool,
        {"agent": "agent", "tool": "tool", "finalize": "finalize"},
    )
    graph.add_edge("finalize", END)
    return graph.compile()
