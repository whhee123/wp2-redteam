"""Single-execution async Runtime state machine."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from app.adapter.langgraph_adapter import LangGraphAdapter
from app.protocol import ExecutionRequest, ExecutionResult, ExecutionStatus, TraceEvent
from app.replay.replay_adapter import ReplayAdapter
from sandbox.replay.exceptions import ArtifactIntegrityError, ReplayDivergenceError
from sandbox.replay.models import ReplayCheckpointsRequest, ReplayForkRequest, ReplayRequest


class RuntimeRpcError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class RuntimeState:
    max_events = 1_000

    def __init__(self, expected_execution_id: str | None = None) -> None:
        self.expected_execution_id = expected_execution_id
        self.adapter = LangGraphAdapter()
        self.replay_adapter = ReplayAdapter()
        self._lock = asyncio.Lock()
        self._request: ExecutionRequest | ReplayRequest | ReplayForkRequest | None = None
        self._request_digest: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._events: list[TraceEvent] = []
        self._status = ExecutionStatus.PENDING
        self._result: ExecutionResult | None = None

    async def submit(self, request: ExecutionRequest) -> dict[str, Any]:
        if self.expected_execution_id and request.execution_id != self.expected_execution_id:
            raise RuntimeRpcError(-32002, "execution_id does not match container lease")
        digest = hashlib.sha256(request.model_dump_json().encode("utf-8")).hexdigest()
        async with self._lock:
            if self._request is not None:
                if request.execution_id != self._request.execution_id:
                    raise RuntimeRpcError(-32004, "Runtime is bound to another execution")
                if digest != self._request_digest:
                    raise RuntimeRpcError(-32002, "execution_id request digest conflict")
                return {"execution_id": request.execution_id, "status": self._status.value}
            self._request = request
            self._request_digest = digest
            self._status = ExecutionStatus.PENDING
            self._task = asyncio.create_task(self._run(request), name=request.execution_id)
            return {"execution_id": request.execution_id, "status": self._status.value}

    async def submit_replay(self, request: ReplayRequest) -> dict[str, Any]:
        if self.expected_execution_id and request.execution_id != self.expected_execution_id:
            raise RuntimeRpcError(-32002, "execution_id does not match container lease")
        digest = hashlib.sha256(request.model_dump_json().encode("utf-8")).hexdigest()
        async with self._lock:
            if self._request is not None:
                if request.execution_id != self._request.execution_id:
                    raise RuntimeRpcError(-32004, "Runtime is bound to another execution")
                if digest != self._request_digest:
                    raise RuntimeRpcError(-32002, "execution_id request digest conflict")
                return {"execution_id": request.execution_id, "status": self._status.value}
            self._request = request
            self._request_digest = digest
            self._status = ExecutionStatus.PENDING
            self._task = asyncio.create_task(self._run_replay(request), name=request.execution_id)
            return {"execution_id": request.execution_id, "status": self._status.value}

    async def checkpoints(self, request: ReplayCheckpointsRequest) -> list[dict[str, Any]]:
        if self.expected_execution_id and request.execution_id != self.expected_execution_id:
            raise RuntimeRpcError(-32002, "execution_id does not match container lease")
        async with self._lock:
            if self._request is not None and self._request.execution_id != request.execution_id:
                raise RuntimeRpcError(-32004, "Runtime is bound to another execution")
            return [
                checkpoint.model_dump(mode="json")
                for checkpoint in self.replay_adapter.checkpoints(request)
            ]

    async def submit_fork(self, request: ReplayForkRequest) -> dict[str, Any]:
        if self.expected_execution_id and request.execution_id != self.expected_execution_id:
            raise RuntimeRpcError(-32002, "execution_id does not match container lease")
        digest = hashlib.sha256(request.model_dump_json().encode("utf-8")).hexdigest()
        async with self._lock:
            if self._request is not None:
                if request.execution_id != self._request.execution_id:
                    raise RuntimeRpcError(-32004, "Runtime is bound to another execution")
                if digest != self._request_digest:
                    raise RuntimeRpcError(-32002, "execution_id request digest conflict")
                return {"execution_id": request.execution_id, "status": self._status.value}
            self._request = request
            self._request_digest = digest
            self._status = ExecutionStatus.PENDING
            self._task = asyncio.create_task(self._run_fork(request), name=request.execution_id)
            return {"execution_id": request.execution_id, "status": self._status.value}

    async def get(self, execution_id: str) -> ExecutionResult:
        self._require_execution(execution_id)
        if self._result is not None:
            return self._result
        return ExecutionResult(
            execution_id=execution_id,
            status=self._status,
            trace_count=len(self._events),
            final_sequence=None,
        )

    async def events(self, execution_id: str, after_sequence: int, limit: int) -> dict[str, Any]:
        self._require_execution(execution_id)
        page = [event for event in self._events if event.sequence > after_sequence][:limit]
        next_after = page[-1].sequence if page else after_sequence
        execution_terminal = self._status in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.CANCELLED,
            ExecutionStatus.TIMED_OUT,
        }
        final_sequence = len(self._events) - 1 if execution_terminal and self._events else None
        page_terminal = execution_terminal and (
            final_sequence is None or next_after >= final_sequence
        )
        return {
            "schema_version": "1.0",
            "events": [event.model_dump(mode="json") for event in page],
            "next_after_sequence": next_after,
            "terminal": page_terminal,
            "final_sequence": final_sequence,
        }

    async def cancel(self, execution_id: str) -> dict[str, Any]:
        self._require_execution(execution_id)
        task = self._task
        if task is None or task.done():
            return {"execution_id": execution_id, "status": self._status.value}
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return {"execution_id": execution_id, "status": self._status.value}

    async def _run(self, request: ExecutionRequest) -> None:
        self._status = ExecutionStatus.RUNNING
        final_answer: str | None = None
        try:
            async with asyncio.timeout(request.timeout_seconds):
                async for event in self.adapter.execute(request):
                    self._append(event)
                    if event.event_type == "execution_finished":
                        final_answer = event.data.get("final_answer")
            self._status = ExecutionStatus.SUCCEEDED
        except TimeoutError:
            self._append_terminal(
                "execution_timed_out",
                {"error_type": "TimeoutError", "message": "execution timed out"},
            )
            self._status = ExecutionStatus.TIMED_OUT
        except asyncio.CancelledError:
            self._append_terminal("execution_cancelled", {"message": "execution cancelled"})
            self._status = ExecutionStatus.CANCELLED
        except Exception as exc:
            self._append_terminal(
                "execution_error",
                {"error_type": type(exc).__name__, "message": str(exc)},
            )
            self._status = ExecutionStatus.FAILED
        self._result = ExecutionResult(
            execution_id=request.execution_id,
            status=self._status,
            final_answer=final_answer,
            error_code=None if self._status == ExecutionStatus.SUCCEEDED else self._status.value,
            error_message=(
                None
                if self._status == ExecutionStatus.SUCCEEDED
                else "execution did not succeed"
            ),
            trace_count=len(self._events),
            final_sequence=len(self._events) - 1 if self._events else None,
            final_state_digest=self.adapter.last_final_state_digest,
            checkpoint_digests=self.adapter.last_checkpoint_digests,
        )

    async def _run_replay(self, replay_request: ReplayRequest) -> None:
        self._status = ExecutionStatus.RUNNING
        final_answer: str | None = None
        timeout_seconds = 120
        try:
            request, model, tools, initial, start_node = self.replay_adapter.load(replay_request)
            timeout_seconds = request.timeout_seconds
            async with asyncio.timeout(timeout_seconds):
                async for event in self.adapter.execute_replay(
                    request,
                    model=model,
                    tools=tools,
                    initial=initial,
                    start_node=start_node,
                ):
                    self._append(event)
                    if event.event_type == "execution_finished":
                        final_answer = event.data.get("final_answer")
            self._status = ExecutionStatus.SUCCEEDED
        except TimeoutError:
            self._append_terminal(
                "execution_timed_out",
                {"error_type": "TimeoutError", "message": "replay timed out"},
            )
            self._status = ExecutionStatus.TIMED_OUT
        except asyncio.CancelledError:
            self._append_terminal("execution_cancelled", {"message": "replay cancelled"})
            self._status = ExecutionStatus.CANCELLED
        except (ArtifactIntegrityError, ReplayDivergenceError) as exc:
            code = getattr(exc, "code", -32103)
            self._append_terminal(
                "execution_error",
                {"error_type": type(exc).__name__, "message": str(exc), "replay_error_code": code},
            )
            self._status = ExecutionStatus.FAILED
        except Exception as exc:
            self._append_terminal(
                "execution_error",
                {"error_type": type(exc).__name__, "message": str(exc)},
            )
            self._status = ExecutionStatus.FAILED
        self._result = ExecutionResult(
            execution_id=replay_request.execution_id,
            status=self._status,
            final_answer=final_answer,
            error_code=None if self._status == ExecutionStatus.SUCCEEDED else self._status.value,
            error_message=(
                None
                if self._status == ExecutionStatus.SUCCEEDED
                else "replay did not succeed"
            ),
            trace_count=len(self._events),
            final_sequence=len(self._events) - 1 if self._events else None,
            final_state_digest=self.adapter.last_final_state_digest,
            checkpoint_digests=self.adapter.last_checkpoint_digests,
        )

    async def _run_fork(self, fork_request: ReplayForkRequest) -> None:
        self._status = ExecutionStatus.RUNNING
        final_answer: str | None = None
        try:
            async with asyncio.timeout(120):
                async for event in self.replay_adapter.execute_fork(fork_request):
                    self._append(event)
                    if event.event_type == "execution_finished":
                        final_answer = event.data.get("final_answer")
            self._status = ExecutionStatus.SUCCEEDED
        except TimeoutError:
            self._append_terminal(
                "execution_timed_out",
                {"error_type": "TimeoutError", "message": "fork execution timed out"},
            )
            self._status = ExecutionStatus.TIMED_OUT
        except asyncio.CancelledError:
            self._append_terminal("execution_cancelled", {"message": "fork cancelled"})
            self._status = ExecutionStatus.CANCELLED
        except (ArtifactIntegrityError, ReplayDivergenceError) as exc:
            code = getattr(exc, "code", -32103)
            self._append_terminal(
                "execution_error",
                {"error_type": type(exc).__name__, "message": str(exc), "replay_error_code": code},
            )
            self._status = ExecutionStatus.FAILED
        except Exception as exc:
            self._append_terminal(
                "execution_error",
                {"error_type": type(exc).__name__, "message": str(exc)},
            )
            self._status = ExecutionStatus.FAILED
        self._result = ExecutionResult(
            execution_id=fork_request.execution_id,
            status=self._status,
            final_answer=final_answer,
            error_code=None if self._status == ExecutionStatus.SUCCEEDED else self._status.value,
            error_message=(
                None if self._status == ExecutionStatus.SUCCEEDED else "fork did not succeed"
            ),
            trace_count=len(self._events),
            final_sequence=len(self._events) - 1 if self._events else None,
        )

    def _append(self, event: TraceEvent) -> None:
        if len(self._events) >= self.max_events:
            raise RuntimeError("trace event limit exceeded")
        if self._request is None or event.execution_id != self._request.execution_id:
            raise RuntimeError("event execution_id mismatch")
        if event.sequence != len(self._events):
            raise RuntimeError("event sequence is not contiguous")
        self._events.append(event)

    def _append_terminal(self, event_type: str, data: dict[str, Any]) -> None:
        if (
            self._events
            and self._events[-1].event_type.startswith("execution_")
            and self._events[-1].event_type != "execution_started"
        ):
            return
        if len(self._events) >= self.max_events:
            self._events = self._events[: self.max_events - 1]
        execution_id = self._request.execution_id if self._request else "unknown"
        self._events.append(
            TraceEvent(
                execution_id=execution_id,
                sequence=len(self._events),
                event_type=event_type,
                source="runtime",
                data=data,
            )
        )

    def _require_execution(self, execution_id: str) -> None:
        if self._request is None or self._request.execution_id != execution_id:
            raise RuntimeRpcError(-32003, "execution does not exist")
