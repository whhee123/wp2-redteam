from __future__ import annotations

import math
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from sandbox.protocol import ToolReplayMode, TraceEvent
from sandbox.replay.artifact_store import ArtifactStore
from sandbox.replay.canonical import canonical_json_bytes
from sandbox.replay.comparator import Comparator
from sandbox.replay.digests import sha256_digest
from sandbox.replay.exceptions import (
    ArtifactIntegrityError,
    CanonicalizationError,
    ManifestIntegrityError,
)
from sandbox.replay.manifest import ManifestStore, seal_manifest
from sandbox.replay.models import (
    ArtifactRef,
    CheckpointKind,
    ReplayManifest,
    ResumePhase,
    StateCheckpoint,
)


def test_canonical_json_normalizes_unicode_keys_and_utc() -> None:
    value = {
        "é": "e\u0301",
        "time": datetime(2026, 7, 16, 12, 30, tzinfo=UTC),
        "a": 1,
    }
    assert canonical_json_bytes(value) == (
        b'{"a":1,"time":"2026-07-16T12:30:00.000000Z","\xc3\xa9":"\xc3\xa9"}'
    )


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, -0.0, 1.5])
def test_canonical_json_rejects_ambiguous_floats(value: float) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes(value)


def test_artifact_store_is_content_addressed_and_detects_tampering(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    first = store.put_bytes(b"same payload", media_type="application/octet-stream")
    second = store.put_bytes(b"same payload", media_type="application/octet-stream")
    assert first == second
    assert store.read_bytes(first) == b"same payload"

    artifact_path = store.root / Path(*first.relative_path.split("/"))
    artifact_path.write_bytes(b"tampered")
    with pytest.raises(ArtifactIntegrityError):
        store.read_bytes(first)


@pytest.mark.parametrize(
    "unsafe",
    ["../x", "/absolute", "C:/drive", "a\\b", "a//b", "./a"],
)
def test_artifact_ref_rejects_unsafe_paths(unsafe: str) -> None:
    with pytest.raises(ValidationError):
        ArtifactRef(
            media_type="application/json",
            sha256="sha256:" + "a" * 64,
            size_bytes=1,
            relative_path=unsafe,
        )


def test_checkpoint_kind_applies_documented_injection_defaults() -> None:
    reference = ArtifactRef(
        media_type="application/json",
        sha256="sha256:" + "a" * 64,
        size_bytes=1,
        relative_path="sha256/aa/aa/" + "a" * 64,
    )
    expected = {
        CheckpointKind.BEFORE_MODEL: ["prompt_replace", "prompt_append"],
        CheckpointKind.AFTER_MODEL: ["model_decision_replace"],
        CheckpointKind.BEFORE_TOOL: ["tool_result_replace"],
        CheckpointKind.AFTER_TOOL: ["prompt_replace", "prompt_append"],
        CheckpointKind.NODE_COMMIT: ["prompt_replace", "prompt_append"],
    }
    for kind, injections in expected.items():
        checkpoint = StateCheckpoint(
            checkpoint_id=f"cp-{kind}",
            execution_id="exec-1",
            sequence=0,
            logical_time=0,
            kind=kind,
            resume_phase=ResumePhase.CALL_MODEL,
            resume_sequence=1,
            state_digest="sha256:" + "a" * 64,
            state_artifact=reference,
        )
        assert checkpoint.allowed_injection_types == injections


def _artifact_set(store: ArtifactStore) -> dict[str, ArtifactRef]:
    names = [
        "prompt",
        "events",
        "initial_state",
        "determinism_config",
        "model_decisions",
        "tool_records",
        "checkpoints",
    ]
    return {
        name: store.put_bytes(name.encode(), media_type="application/json")
        for name in names
    }


def _manifest(store: ArtifactStore, replay_id: str = "replay-1") -> ReplayManifest:
    refs = _artifact_set(store)
    digest = "sha256:" + "1" * 64
    return ReplayManifest(
        replay_id=replay_id,
        trajectory_id="trajectory-1",
        created_at=datetime(2026, 7, 16, tzinfo=UTC),
        case_id="case-1",
        scenario_id="scenario-1",
        seed=42,
        image_ref="trace-g/agent-runtime:week2",
        image_digest="sha256:" + "2" * 64,
        image_digest_kind="image_id",
        runtime_version="0.2.0",
        agent_version="fake-langgraph-agent-v1",
        default_tool_replay_mode=ToolReplayMode.EXECUTE_AND_VERIFY,
        prompt_digest=digest,
        initial_state_digest=digest,
        normalized_behavior_trace_digest=digest,
        determinism_config_digest=digest,
        **refs,
    )


def test_manifest_digest_is_json_mode_excluding_only_manifest_digest(tmp_path: Path) -> None:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    manifest = _manifest(artifacts)
    expected = sha256_digest(
        manifest.model_dump(
            mode="json",
            exclude={"manifest_digest"},
            exclude_none=False,
        )
    )
    sealed = seal_manifest(manifest)
    assert sealed.manifest_digest == expected


def test_manifest_store_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    store = ManifestStore(tmp_path / "replays")
    sealed = seal_manifest(_manifest(artifacts))
    path = store.save(sealed)
    assert store.load("replay-1") == sealed

    digest_path = path.with_name("manifest.sha256")
    digest_path.write_text("sha256:" + "0" * 64, encoding="ascii")
    with pytest.raises(ManifestIntegrityError):
        store.load("replay-1")


def test_comparator_ignores_ids_timestamps_and_audit_events() -> None:
    source = [
        TraceEvent(
            execution_id="source",
            sequence=0,
            event_type="model_decision_recorded",
            source="model-v1",
            data={"execution_id": "source", "action": {"name": "read_file"}},
        )
    ]
    replay = [
        TraceEvent(
            execution_id="replay",
            sequence=0,
            event_type="replay_started",
            source="runtime",
        ),
        TraceEvent(
            execution_id="replay",
            sequence=1,
            event_type="model_decision_replayed",
            source="model-v1",
            data={"execution_id": "replay", "action": {"name": "read_file"}},
        ),
    ]
    result = Comparator().compare(source, replay)
    assert result.matched is True

