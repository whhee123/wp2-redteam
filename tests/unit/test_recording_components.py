from __future__ import annotations

from pathlib import Path

import pytest
from app.adapter.langgraph_adapter import LangGraphAdapter
from app.agent.fake_model import FakeChatModel
from app.replay.decision_recorder import DecisionRecorder, RecordedDecisionModel
from app.replay.state_codec import StateCodec
from app.replay.tool_recorder import ToolRecorder, ToolReplayer
from app.tools.base import ToolRegistry

from sandbox.models import ExecutionRequest, RecordingOptions
from sandbox.protocol import ToolReplayMode
from sandbox.replay.exceptions import ReplayDivergenceError
from sandbox.replay.models import CheckpointKind, ResumePhase


def test_decision_recorder_wraps_plan_and_strict_model_consumes_it() -> None:
    recorder = DecisionRecorder(FakeChatModel())
    recorder.set_context(sequence=3, before_checkpoint_id="before-1")
    expected = recorder.plan("读取 /workspace/public.txt")
    recorder.attach_after_checkpoint("after-1")

    record = recorder.decisions[0]
    assert record.decision_index == 0
    assert record.before_checkpoint_id == "before-1"
    assert record.after_checkpoint_id == "after-1"

    replay = RecordedDecisionModel(recorder.decisions)
    assert replay.plan("读取 /workspace/public.txt") == expected
    replay.assert_consumed()

    mismatch = RecordedDecisionModel(recorder.decisions)
    with pytest.raises(ReplayDivergenceError) as error:
        mismatch.plan("different prompt")
    assert error.value.code == -32106


def test_tool_recorder_execute_and_verify_round_trip() -> None:
    recorder = ToolRecorder(
        ToolRegistry(),
        replay_mode=ToolReplayMode.EXECUTE_AND_VERIFY,
    )
    action = {"name": "write_file", "arguments": {"path": "/workspace/a.txt", "content": "x"}}
    recorder.set_context(sequence=4, before_checkpoint_id="before-tool")
    expected = recorder.execute(action)
    recorder.attach_after_checkpoint("after-tool")

    replayer = ToolReplayer(ToolRegistry(), recorder.interactions)
    actual = replayer.execute(action)
    assert actual == expected
    replayer.assert_consumed()


def test_state_codec_restores_agent_and_all_controlled_tool_state() -> None:
    tools = ToolRegistry()
    tools.execute(
        {"name": "write_file", "arguments": {"path": "/workspace/new.txt", "content": "saved"}}
    )
    codec = StateCodec()
    envelope = codec.export(
        {"prompt": "hello", "execution_id": "old", "step_count": 2, "unknown": "drop"},
        tools,
        checkpoint_kind=CheckpointKind.AFTER_TOOL,
        resume_phase=ResumePhase.APPLY_TOOL_RESULT,
        logical_time=3,
        next_model_decision_index=1,
        next_tool_interaction_index=1,
    )
    restored_tools = ToolRegistry()
    state = codec.restore(envelope, restored_tools, execution_id="new")
    assert state["execution_id"] == "new"
    assert "unknown" not in state
    assert restored_tools.filesystem.read_file("/workspace/new.txt").output == "saved"
    assert restored_tools.state_digest() == tools.state_digest()


async def test_recording_request_writes_replay_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "replay-out"
    monkeypatch.setenv("REPLAY_OUTPUT_DIR", str(output_dir))
    request = ExecutionRequest(
        execution_id="record-1",
        case_id="case-1",
        prompt="读取 /workspace/public.txt",
        max_steps=5,
        timeout_seconds=5,
        recording=RecordingOptions(enabled=True),
    )
    events = [event async for event in LangGraphAdapter().execute(request)]
    assert events[-1].event_type == "execution_finished"
    assert any(event.event_type == "model_decision_recorded" for event in events)
    assert any(event.event_type == "tool_response_recorded" for event in events)
    assert any(event.schema_version == "1.1" for event in events)
    expected_files = {
        "prompt.json",
        "initial-state.json",
        "determinism-config.json",
        "events.jsonl",
        "model-decisions.jsonl",
        "tool-records.jsonl",
        "checkpoints.jsonl",
        "recording-audit.jsonl",
    }
    assert expected_files <= {path.name for path in output_dir.iterdir()}
    assert list((output_dir / "states").glob("*.json"))
