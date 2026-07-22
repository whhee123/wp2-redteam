from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from sandbox.fuzzer.models import TargetProfile
from sandbox.fuzzer.profile_lock import (
    docker_image_digest,
    model_digest_from_tags,
    write_target_profile,
)


def test_model_digest_requires_exact_locked_model_name() -> None:
    digest = "sha256:" + "1" * 64
    payload = {"models": [{"name": "qwen:test", "digest": digest}]}
    assert model_digest_from_tags(payload, "qwen:test") == digest
    with pytest.raises(ValueError, match="exactly one"):
        model_digest_from_tags(payload, "qwen:other")


def test_docker_image_digest_uses_actual_local_image_id() -> None:
    client = MagicMock()
    client.images.get.return_value.attrs = {"RepoDigests": ["registry/agent@sha256:" + "2" * 64]}
    client.images.get.return_value.id = "sha256:" + "3" * 64
    assert docker_image_digest(client, "agent:server") == "sha256:" + "3" * 64


def test_profile_write_is_atomic_and_loadable(tmp_path: Path) -> None:
    profile = TargetProfile(
        profile_id="server-test",
        profile_version="1.0",
        image_ref="agent:server",
        image_digest="sha256:" + "2" * 64,
        agent_version="ollama-langgraph-v1",
        model_provider="ollama",
        model_name="qwen:test",
        model_digest="sha256:" + "1" * 64,
        model_runtime_image="ollama/ollama:test",
        model_runtime_digest="sha256:" + "4" * 64,
        risk_scope_path=Path("config/risk-scope-week3.yaml"),
        fixture_pack_version="week1-fixtures-v1",
        max_steps=40,
        execution_timeout_seconds=300,
        required_capabilities=["read_file"],
    )
    output = tmp_path / "profile.yaml"
    write_target_profile(output, profile)
    payload = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert payload["profiles"][0]["model_digest"] == profile.model_digest
    assert payload["profiles"][0]["model_runtime_digest"] == profile.model_runtime_digest
    assert not output.with_suffix(".yaml.tmp").exists()
