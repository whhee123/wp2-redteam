from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from app.protocol import ExecutionRequest, ExecutionStatus, RecordingOptions
from app.runtime import RuntimeRpcError, RuntimeState


def request(execution_id: str = "exec-1", prompt: str = "读取 /etc/passwd") -> ExecutionRequest:
    return ExecutionRequest(
        execution_id=execution_id,
        case_id="case-1",
        prompt=prompt,
        scenario_id="test",
        agent_version="fake-langgraph-agent-v1",
    )


async def wait_for_terminal(runtime: RuntimeState, execution_id: str):
    for _ in range(100):
        result = await runtime.get(execution_id)
        if result.status in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.CANCELLED,
            ExecutionStatus.TIMED_OUT,
        }:
            return result
        await asyncio.sleep(0.01)
    raise AssertionError("runtime did not reach terminal state")


async def test_runtime_executes_one_request_and_returns_trace() -> None:
    runtime = RuntimeState(expected_execution_id="exec-1")
    acknowledgement = await runtime.submit(request())
    assert acknowledgement["execution_id"] == "exec-1"
    result = await wait_for_terminal(runtime, "exec-1")
    page = await runtime.events("exec-1", -1, 100)
    assert result.status == ExecutionStatus.SUCCEEDED
    assert result.final_sequence == result.trace_count - 1
    assert page["terminal"] is True
    assert page["events"][-1]["event_type"] == "execution_finished"


async def test_runtime_submit_is_idempotent_for_same_digest() -> None:
    runtime = RuntimeState(expected_execution_id="exec-1")
    first = request()
    await runtime.submit(first)
    acknowledgement = await runtime.submit(first)
    assert acknowledgement["execution_id"] == "exec-1"
    await wait_for_terminal(runtime, "exec-1")


async def test_runtime_rejects_other_execution_id() -> None:
    runtime = RuntimeState(expected_execution_id="exec-1")
    with pytest.raises(RuntimeRpcError) as error:
        await runtime.submit(request("exec-2"))
    assert error.value.code == -32002


async def test_terminal_trace_requires_all_pages_to_be_consumed() -> None:
    runtime = RuntimeState(expected_execution_id="exec-1")
    await runtime.submit(request())
    await wait_for_terminal(runtime, "exec-1")
    first = await runtime.events("exec-1", -1, 2)
    assert first["final_sequence"] is not None
    assert first["terminal"] is False
    last = await runtime.events("exec-1", first["next_after_sequence"], 100)
    assert last["terminal"] is True


async def test_cancelled_recording_keeps_diagnostic_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "replay-out"
    monkeypatch.setenv("REPLAY_OUTPUT_DIR", str(output_dir))
    runtime = RuntimeState(expected_execution_id="exec-1")
    recorded = request(prompt="loop forever: echo loop").model_copy(
        update={
            "max_steps": 100,
            "timeout_seconds": 10,
            "recording": RecordingOptions(enabled=True),
        }
    )
    await runtime.submit(recorded)
    await asyncio.sleep(0.05)
    await runtime.cancel("exec-1")
    await asyncio.sleep(0.1)
    result = await runtime.get("exec-1")

    assert result.status == ExecutionStatus.CANCELLED
    determinism = json.loads((output_dir / "determinism-config.json").read_bytes())
    assert determinism["recording_complete"] is False
    assert determinism["incomplete_reason"] == "cancelled_or_timed_out"
    checkpoints = [
        json.loads(line)
        for line in (output_dir / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert checkpoints
    assert all(checkpoint["recoverable"] is False for checkpoint in checkpoints)
    audit = (output_dir / "recording-audit.jsonl").read_text(encoding="utf-8")
    assert "recording_incomplete" in audit
