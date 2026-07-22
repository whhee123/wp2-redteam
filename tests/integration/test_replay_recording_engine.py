from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from app.adapter.langgraph_adapter import LangGraphAdapter
from app.agent.fake_model import FakeChatModel
from app.replay.checkpoint import RecordingSession
from app.replay.replay_adapter import StrictReplayAdapter
from app.tools.base import ToolRegistry

from sandbox.config import TraceConfig, WeekOneConfig
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.models import ExecutionResult, ExecutionStatus, TraceEvent, TracePage
from sandbox.replay.artifact_store import ArtifactStore
from sandbox.replay.canonical import canonical_json_bytes
from sandbox.replay.comparator import Comparator
from sandbox.replay.exceptions import ReplayPreparationError
from sandbox.replay.manifest import ManifestStore
from sandbox.replay.models import (
    ArtifactRef,
    CheckpointKind,
    ForkInjection,
    ForkSuffixMode,
    ReplayCheckpointsRequest,
    ReplayMode,
    ReplayRequest,
)
from sandbox.replay.replay_engine import ReplayEngine
from sandbox.scheduler.models import SandboxHandle
from sandbox.scoring.rule_scorer import RuleBasedScorer


class FakeScheduler:
    def __init__(self) -> None:
        self.destroyed = False

    async def create(self, execution_id, image_ref, limits):
        return SandboxHandle(
            execution_id=execution_id,
            container_id="container-1",
            runtime_url="http://127.0.0.1:8080",
            capability_token="token",
            image_digest="sha256:" + "2" * 64,
            scheduler_instance_id="scheduler-1",
        )

    async def wait_until_ready(self, handle) -> None:
        return None

    async def destroy(self, handle) -> None:
        self.destroyed = True


class RecordingRuntime:
    def __init__(self, output_dir: Path, replay_input: Path) -> None:
        self.output_dir = output_dir
        self.replay_input = replay_input
        self.events = []
        self.final_state_digest = None
        self.checkpoint_digests = []

    async def submit(self, handle, request) -> None:
        self.events = [event async for event in LangGraphAdapter().execute(request)]

    async def poll_and_stream_events(self, handle, request):
        yield TracePage(
            events=self.events,
            next_after_sequence=self.events[-1].sequence,
            terminal=True,
            final_sequence=self.events[-1].sequence,
        )

    async def replay_submit(self, handle, request) -> None:
        adapter = StrictReplayAdapter(self.replay_input)
        self.events = [
            event async for event in adapter.execute(request)
        ]
        self.final_state_digest = adapter.last_final_state_digest
        self.checkpoint_digests = adapter.last_checkpoint_digests

    async def replay_fork_submit(self, handle, request) -> None:
        shutil.rmtree(self.output_dir, ignore_errors=True)
        self.events = [
            event async for event in StrictReplayAdapter(self.replay_input).execute_fork(request)
        ]

    async def poll_execution_events(self, handle, execution_id, *, timeout_seconds):
        yield TracePage(
            events=self.events,
            next_after_sequence=self.events[-1].sequence,
            terminal=True,
            final_sequence=self.events[-1].sequence,
        )

    async def get_result(self, handle, execution_id):
        return ExecutionResult(
            execution_id=execution_id,
            status=ExecutionStatus.SUCCEEDED,
            final_answer="recorded",
            trace_count=len(self.events),
            final_sequence=self.events[-1].sequence,
            final_state_digest=self.final_state_digest,
            checkpoint_digests=self.checkpoint_digests,
        )


class LocalTransfer:
    def __init__(self, output_dir: Path, replay_input: Path, artifact_store: ArtifactStore) -> None:
        self.output_dir = output_dir
        self.replay_input = replay_input
        self.artifact_store = artifact_store

    async def download(self, handle):
        return {
            path.relative_to(self.output_dir).as_posix(): path.read_bytes()
            for path in self.output_dir.rglob("*")
            if path.is_file()
        }

    async def upload(self, handle, manifest) -> None:
        (self.replay_input / "artifacts").mkdir(parents=True, exist_ok=True)
        (self.replay_input / "manifest.json").write_bytes(canonical_json_bytes(manifest))
        references = [
            manifest.prompt,
            manifest.events,
            manifest.initial_state,
            manifest.determinism_config,
            manifest.model_decisions,
            manifest.tool_records,
            manifest.checkpoints,
        ]
        for line in self.artifact_store.read_bytes(manifest.checkpoints).splitlines():
            checkpoint = json.loads(line)
            if checkpoint.get("state_artifact"):
                references.append(ArtifactRef.model_validate(checkpoint["state_artifact"]))
        for reference in references:
            destination = (
                self.replay_input
                / "artifacts"
                / Path(*reference.relative_path.split("/"))
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(self.artifact_store.read_bytes(reference))


class IncompleteRuntime:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.events = []

    async def submit(self, handle, request) -> None:
        session = RecordingSession(
            request,
            FakeChatModel(),
            ToolRegistry(),
            output_dir=self.output_dir,
        )
        initial = LangGraphAdapter.initial_state(request)
        session.start(initial)
        started = TraceEvent(
            execution_id=request.execution_id,
            sequence=0,
            event_type="execution_started",
            source="runtime",
        )
        session.finalize_incomplete([started], reason="cancelled")
        self.events = [
            started,
            TraceEvent(
                execution_id=request.execution_id,
                sequence=1,
                event_type="execution_cancelled",
                source="runtime",
            ),
        ]

    async def poll_and_stream_events(self, handle, request):
        yield TracePage(
            events=self.events,
            next_after_sequence=1,
            terminal=True,
            final_sequence=1,
        )

    async def get_result(self, handle, execution_id):
        return ExecutionResult(
            execution_id=execution_id,
            status=ExecutionStatus.CANCELLED,
            trace_count=2,
            final_sequence=1,
        )


async def test_record_builds_and_seals_manifest_before_cleanup(
    tmp_path: Path,
    monkeypatch,
) -> None:
    replay_out = tmp_path / "runtime-replay-out"
    monkeypatch.setenv("REPLAY_OUTPUT_DIR", str(replay_out))
    config = WeekOneConfig(
        tracing=TraceConfig(output_dir=tmp_path / "trajectories", pull_interval_seconds=0.01)
    )
    scheduler = FakeScheduler()
    artifact_store = ArtifactStore(tmp_path / "artifacts")
    manifest_store = ManifestStore(tmp_path / "replays")
    replay_input = tmp_path / "replay-in"
    runtime = RecordingRuntime(replay_out, replay_input)
    engine = ReplayEngine(
        config,
        scheduler,
        runtime,
        RuleBasedScorer(),
        manifest_store,
        artifact_store,
        LocalTransfer(replay_out, replay_input, artifact_store),
        TemplateCaseSource(),
    )
    manifest = await engine.record_template("benign-control-001", seed=42)
    assert manifest.manifest_digest is not None
    assert manifest_store.load(manifest.replay_id) == manifest
    assert artifact_store.read_bytes(manifest.model_decisions)
    assert artifact_store.read_bytes(manifest.tool_records)
    assert artifact_store.read_bytes(manifest.checkpoints)
    assert scheduler.destroyed is True

    (replay_input / "artifacts").mkdir(parents=True)
    (replay_input / "manifest.json").write_bytes(canonical_json_bytes(manifest))
    references = [
        manifest.prompt,
        manifest.events,
        manifest.initial_state,
        manifest.determinism_config,
        manifest.model_decisions,
        manifest.tool_records,
        manifest.checkpoints,
    ]
    for line in artifact_store.read_bytes(manifest.checkpoints).splitlines():
        checkpoint = json.loads(line)
        if checkpoint.get("state_artifact"):
            references.append(ArtifactRef.model_validate(checkpoint["state_artifact"]))
    for reference in references:
        destination = replay_input / "artifacts" / Path(*reference.relative_path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(artifact_store.read_bytes(reference))

    replay_events = [
        event
        async for event in StrictReplayAdapter(replay_input).execute(
            ReplayRequest(
                execution_id="strict-replay-1",
                replay_run_id="run-1",
                source_replay_id=manifest.replay_id,
                mode=ReplayMode.STRICT,
                manifest_relative_path="manifest.json",
            )
        )
    ]
    comparison = Comparator().compare(engine.runtime.events, replay_events)
    assert comparison.matched is True

    runtime_checkpoints = StrictReplayAdapter(replay_input).checkpoints(
        ReplayCheckpointsRequest(
            execution_id="checkpoint-query-1",
            manifest_relative_path="manifest.json",
        )
    )
    assert runtime_checkpoints
    assert engine.checkpoints(manifest.replay_id) == runtime_checkpoints

    host_result = await engine.replay(manifest.replay_id, replay_run_id="host-run-1")
    assert host_result.status == "matched"
    assert host_result.container_removed is True
    assert host_result.source_final_state_digest == host_result.replay_final_state_digest
    assert host_result.source_final_state_digest is not None
    assert host_result.checkpoint_comparisons
    assert all(item.matched for item in host_result.checkpoint_comparisons)
    assert (
        tmp_path
        / "replays"
        / manifest.replay_id
        / "runs"
        / "host-run-1"
        / "result.json"
    ).is_file()
    assert (
        tmp_path
        / "replays"
        / manifest.replay_id
        / "runs"
        / "host-run-1"
        / "replay-audit.jsonl"
    ).is_file()

    live_result = await engine.replay(
        manifest.replay_id,
        mode=ReplayMode.LIVE,
        replay_run_id="host-live-run-1",
    )
    assert live_result.status == "matched"
    assert live_result.source_behavior_digest == live_result.replay_behavior_digest

    fork_checkpoint = next(
        checkpoint
        for checkpoint in engine.checkpoints(manifest.replay_id)
        if "prompt_append" in checkpoint.allowed_injection_types
    )
    child = await engine.fork(
        manifest.replay_id,
        fork_checkpoint.checkpoint_id,
        ForkInjection(type="prompt_append", content=" 请继续概括。"),
    )
    assert child.parent_replay_id == manifest.replay_id
    assert child.fork_checkpoint_id == fork_checkpoint.checkpoint_id
    assert child.injection_digest is not None
    assert child.parent_prefix is not None
    assert artifact_store.read_bytes(child.parent_prefix)
    child_result = await engine.replay(
        child.replay_id,
        replay_run_id="child-strict-run-1",
    )
    assert child_result.status == "matched"

    after_model = next(
        checkpoint
        for checkpoint in engine.checkpoints(manifest.replay_id)
        if checkpoint.kind == CheckpointKind.AFTER_MODEL
    )
    replacement_child = await engine.fork(
        manifest.replay_id,
        after_model.checkpoint_id,
        ForkInjection(
            type="model_decision_replace",
            content={
                "action": {
                    "name": "read_file",
                    "arguments": {"path": "/workspace/public.txt"},
                },
                "continue_loop": False,
                "remaining_decisions": [],
            },
        ),
        suffix_mode=ForkSuffixMode.STRICT_WITH_REPLACEMENTS,
    )
    replacement_result = await engine.replay(
        replacement_child.replay_id,
        replay_run_id="replacement-child-run-1",
    )
    assert replacement_result.status == "matched"

    before_tool = next(
        checkpoint
        for checkpoint in engine.checkpoints(manifest.replay_id)
        if checkpoint.kind == CheckpointKind.BEFORE_TOOL
    )
    tool_result_child = await engine.fork(
        manifest.replay_id,
        before_tool.checkpoint_id,
        ForkInjection(
            type="tool_result_replace",
            content={
                "allowed": True,
                "outcome": "succeeded",
                "output": "synthetic replacement",
                "error": None,
                "risk_category": None,
            },
        ),
    )
    tool_result_replay = await engine.replay(
        tool_result_child.replay_id,
        replay_run_id="tool-result-child-run-1",
    )
    assert tool_result_replay.status == "matched"


async def test_incomplete_recording_is_sealed_for_diagnostics_but_not_replayable(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "incomplete-output"
    config = WeekOneConfig(tracing=TraceConfig(output_dir=tmp_path / "trajectories"))
    scheduler = FakeScheduler()
    artifacts = ArtifactStore(tmp_path / "artifacts")
    manifests = ManifestStore(tmp_path / "replays")
    engine = ReplayEngine(
        config,
        scheduler,
        IncompleteRuntime(output_dir),
        RuleBasedScorer(),
        manifests,
        artifacts,
        LocalTransfer(output_dir, tmp_path / "replay-in", artifacts),
        TemplateCaseSource(),
    )

    manifest = await engine.record_template("loop-timeout-001", seed=42)
    assert manifest.recording_complete is False
    assert manifest.incomplete_reason == "cancelled"
    assert all(
        checkpoint.recoverable is False
        for checkpoint in engine.checkpoints(manifest.replay_id)
    )
    with pytest.raises(ReplayPreparationError) as error:
        await engine.replay(manifest.replay_id)
    assert error.value.code == -32102
    assert scheduler.destroyed is True
