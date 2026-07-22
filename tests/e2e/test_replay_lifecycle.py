from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import docker
import pytest

from sandbox.client.artifact_transfer import ArtifactTransfer
from sandbox.client.runtime_client import RuntimeClient
from sandbox.config import SandboxConfig, TraceConfig, WeekOneConfig
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.replay.artifact_store import ArtifactStore
from sandbox.replay.manifest import ManifestStore
from sandbox.replay.models import (
    ForkInjection,
    ReplayCheckpointsRequest,
    ReplayMode,
)
from sandbox.replay.replay_engine import ReplayEngine
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler
from sandbox.scoring.rule_scorer import RuleBasedScorer

pytestmark = pytest.mark.skipif(
    os.environ.get("TRACE_G_RUN_DOCKER_E2E") != "1",
    reason="set TRACE_G_RUN_DOCKER_E2E=1 to run real Docker tests",
)


async def test_real_record_then_strict_replay_matches_and_cleans_resources(
    tmp_path: Path,
) -> None:
    docker_client = docker.from_env()
    docker_client.ping()
    config = WeekOneConfig(
        sandbox=SandboxConfig(
            image=os.getenv("TRACE_G_E2E_IMAGE", "trace-redteam-agent:week2"),
            workspace_storage="archive_volume",
        ),
        tracing=TraceConfig(
            output_dir=tmp_path / "trajectories",
            pull_interval_seconds=0.01,
        ),
    )
    artifacts = ArtifactStore(tmp_path / "artifacts")
    scheduler = DockerSandboxScheduler(config.sandbox, client=docker_client)
    runtime = RuntimeClient(config.tracing, docker_client=docker_client)
    transfer = ArtifactTransfer(docker_client, artifacts)
    engine = ReplayEngine(
        config,
        scheduler,
        runtime,
        RuleBasedScorer(),
        ManifestStore(tmp_path / "replays"),
        artifacts,
        transfer,
        TemplateCaseSource(),
    )
    manifest = await engine.record_template("benign-control-001", seed=42)
    result = await engine.replay(manifest.replay_id, replay_run_id="docker-e2e-run")

    checkpoint_execution_id = f"e2e-checkpoints-{uuid4().hex}"
    checkpoint_handle = await scheduler.create(
        checkpoint_execution_id,
        manifest.image_ref,
        config.sandbox.limits,
    )
    try:
        await scheduler.wait_until_ready(checkpoint_handle)
        await transfer.upload(checkpoint_handle, manifest)
        runtime_checkpoints = await runtime.replay_checkpoints(
            checkpoint_handle,
            ReplayCheckpointsRequest(
                execution_id=checkpoint_execution_id,
                manifest_relative_path="manifest.json",
            ),
        )
    finally:
        await scheduler.destroy(checkpoint_handle)

    live_result = await engine.replay(
        manifest.replay_id,
        mode=ReplayMode.LIVE,
        replay_run_id="docker-e2e-live-run",
    )
    fork_checkpoint = next(
        checkpoint
        for checkpoint in runtime_checkpoints
        if "prompt_append" in checkpoint.allowed_injection_types
    )
    child = await engine.fork(
        manifest.replay_id,
        fork_checkpoint.checkpoint_id,
        ForkInjection(type="prompt_append", content=" 请继续概括。"),
    )
    child_result = await engine.replay(
        child.replay_id,
        replay_run_id="docker-e2e-child-run",
    )

    assert manifest.manifest_digest is not None
    assert result.status == "matched"
    assert result.source_behavior_digest == result.replay_behavior_digest
    assert result.source_final_state_digest == result.replay_final_state_digest
    assert result.source_final_state_digest is not None
    assert result.checkpoint_comparisons
    assert all(item.matched for item in result.checkpoint_comparisons)
    assert result.container_removed is True
    assert runtime_checkpoints
    assert live_result.status == "matched"
    assert child.parent_replay_id == manifest.replay_id
    assert child_result.status == "matched"
    assert docker_client.containers.list(
        all=True,
        filters={"label": "trace-g.component=agent-sandbox"},
    ) == []
    assert docker_client.volumes.list(
        filters={"label": "trace-g.component=workspace-volume"},
    ) == []
