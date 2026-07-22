from __future__ import annotations

from app.protocol import ExecutionRequest as ContainerExecutionRequest
from app.protocol import TraceEvent as ContainerTraceEvent

from sandbox.protocol import ExecutionRequest, ModelOptions, RecordingOptions, TraceEvent


def test_container_reexports_the_canonical_protocol_models() -> None:
    assert ContainerExecutionRequest is ExecutionRequest
    assert ContainerTraceEvent is TraceEvent
    assert ContainerExecutionRequest.model_json_schema() == ExecutionRequest.model_json_schema()


def test_recording_extension_is_optional_and_strict() -> None:
    request = ExecutionRequest(
        execution_id="exec-1",
        case_id="case-1",
        prompt="hello",
        recording=RecordingOptions(enabled=True),
    )
    assert request.recording is not None and request.recording.enabled is True
    assert request.recording.default_tool_replay_mode == "execute_and_verify"


def test_trace_event_accepts_week_two_optional_fields() -> None:
    event = TraceEvent(
        schema_version="1.1",
        execution_id="exec-1",
        sequence=0,
        event_type="model_decision_recorded",
        source="fake-model-v1",
        logical_time=1,
        input_digest="sha256:" + "a" * 64,
        output_digest="sha256:" + "b" * 64,
        checkpoint_id="checkpoint-1",
    )
    assert event.logical_time == 1


def test_model_options_reserve_optional_model_digest() -> None:
    options = ModelOptions(
        model_name="local-model",
        model_digest="sha256:" + "a" * 64,
    )

    assert options.model_digest == "sha256:" + "a" * 64
    assert options.model_dump(mode="json")["model_digest"] == options.model_digest
