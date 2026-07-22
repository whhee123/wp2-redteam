"""Translate LangGraph updates into normalized Runtime trace events."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from app.adapter.base import AgentAdapter
from app.agent.graph import build_graph
from app.agent.model_factory import ModelFactory
from app.protocol import ExecutionRequest, TraceEvent
from app.replay.checkpoint import RecordingSession
from app.replay.checkpoint_observer import ReplayCheckpointObserver
from app.tools.base import ToolRegistry
from app.tracing.collector import TraceCollector
from sandbox.replay.models import CheckpointKind, ResumePhase

MUTATION_METADATA_KEYS = (
    "mutation_id",
    "parent_seed_id",
    "parent_mutation_id",
    "mutation_depth",
    "operator_id",
    "operator_version",
    "feedback_digest",
)



class LangGraphAdapter(AgentAdapter):
    def __init__(self, model_factory=None) -> None:
        self.model_factory = model_factory or ModelFactory()
        self.last_checkpoint_digests = []
        self.last_final_state_digest: str | None = None

    async def execute(self, request: ExecutionRequest) -> AsyncIterator[TraceEvent]:
        base_model = self.model_factory.create(request.model)
        base_tools = ToolRegistry()
        recording = None
        if request.recording is not None and request.recording.enabled:
            recording = RecordingSession(request, base_model, base_tools)
            model = recording.model
            tools = recording.tools
        else:
            model = base_model
            tools = base_tools
        initial = self.initial_state(request)
        async for event in self._execute_graph(
            request,
            model=model,
            tools=tools,
            initial=initial,
            recording=recording,
            replaying=False,
            start_node="agent",
        ):
            yield event

    async def execute_replay(
        self,
        request: ExecutionRequest,
        *,
        model,
        tools,
        initial: dict[str, Any],
        start_node: str = "agent",
    ) -> AsyncIterator[TraceEvent]:
        async for event in self._execute_graph(
            request,
            model=model,
            tools=tools,
            initial=initial,
            recording=None,
            replaying=True,
            start_node=start_node,
        ):
            yield event

    async def execute_fork(
        self,
        request: ExecutionRequest,
        *,
        model,
        tools,
        initial: dict[str, Any],
        recording,
        start_node: str,
    ) -> AsyncIterator[TraceEvent]:
        async for event in self._execute_graph(
            request,
            model=model,
            tools=tools,
            initial=initial,
            recording=recording,
            replaying=False,
            start_node=start_node,
        ):
            yield event

    @staticmethod
    def initial_state(request: ExecutionRequest) -> dict[str, Any]:
        return {
            "prompt": request.prompt,
            "execution_id": request.execution_id,
            "step_count": 0,
            "max_steps": request.max_steps,
            "action": None,
            "pending_tool_calls": [],
            "tool_result": None,
            "continue_loop": False,
            "assistant_text": None,
            "final_answer": None,
            "pending_messages": [],
            "trace_events": [],
        }

    async def _execute_graph(
        self,
        request: ExecutionRequest,
        *,
        model,
        tools,
        initial: dict[str, Any],
        recording,
        replaying: bool,
        start_node: str,
    ) -> AsyncIterator[TraceEvent]:
        collector = TraceCollector(request.execution_id)
        emitted_events: list[TraceEvent] = []
        checkpoint_observer = (
            ReplayCheckpointObserver(model, tools) if replaying else None
        )
        if checkpoint_observer:
            checkpoint_observer.capture(
                initial,
                kind=CheckpointKind.NODE_COMMIT,
                resume_phase=ResumePhase.ENTER_NEXT_NODE,
            )
        started = collector.emit(
            "execution_started",
            "runtime",
            {
                "case_id": request.case_id,
                "scenario_id": request.scenario_id,
                "agent_version": request.agent_version,
                "image_digest": request.image_digest,
                **{
                    key: request.metadata[key]
                    for key in MUTATION_METADATA_KEYS
                    if key in request.metadata
            },
            },
        )
        emitted_events.append(started)
        yield started
        graph = build_graph(
            model,
            tools,
            recording,
            replaying=replaying,
            checkpoint_observer=checkpoint_observer,
            start_node=start_node,
        )
        if recording:
            recording.start(initial)
        final_answer: str | None = None
        current_state = dict(initial)
        slow_loop = "无限循环" in request.prompt or "loop forever" in request.prompt.casefold()
        try:
            async for update in graph.astream(
                initial,
                stream_mode="updates",
                config={"recursion_limit": request.max_steps * 3 + 5},
            ):
                for node_update in update.values():
                    if not isinstance(node_update, dict):
                        continue
                    if node_update.get("final_answer") is not None:
                        final_answer = str(node_update["final_answer"])
                    current_state.update(
                        {key: value for key, value in node_update.items() if key != "trace_events"}
                    )
                    for spec in node_update.get("trace_events", []):
                        event = collector.emit(
                            str(spec["event_type"]),
                            str(spec["source"]),
                            dict(spec.get("data") or {}),
                            **dict(spec.get("replay_fields") or {}),
                        )
                        emitted_events.append(event)
                        yield event
                await asyncio.sleep(0.02 if slow_loop else 0)
        except asyncio.CancelledError:
            if recording:
                recording.finalize_incomplete(
                    emitted_events,
                    reason="cancelled_or_timed_out",
                )
            raise
        except Exception as exc:
            event = collector.emit(
                "execution_error",
                "runtime",
                {"error_type": type(exc).__name__, "message": str(exc)},
            )
            emitted_events.append(event)
            if recording:
                recording.finalize_incomplete(
                    emitted_events,
                    reason=type(exc).__name__,
                )
            yield event
            raise
        finished = collector.emit(
            "execution_finished",
            "runtime",
            {"final_answer": final_answer, "restricted_data_exposed": False},
        )
        emitted_events.append(finished)
        if checkpoint_observer:
            checkpoint_observer.capture(
                current_state,
                kind=CheckpointKind.NODE_COMMIT,
                resume_phase=ResumePhase.ENTER_NEXT_NODE,
            )
            self.last_checkpoint_digests = list(checkpoint_observer.records)
            self.last_final_state_digest = checkpoint_observer.final_state_digest
        else:
            self.last_checkpoint_digests = []
            self.last_final_state_digest = None
        if recording:
            recording.finalize(current_state, emitted_events)
        if replaying:
            model.assert_consumed()
            tools.assert_consumed()
        yield finished
