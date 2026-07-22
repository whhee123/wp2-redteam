from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sandbox.fuzzer.models import TargetProfile
from sandbox.fuzzer.profile_lock import verify_target_profile


def _profile() -> TargetProfile:
    return TargetProfile(
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
    )


def test_verify_target_profile_accepts_current_digests(monkeypatch) -> None:
    profile = _profile()
    monkeypatch.setattr(
        "sandbox.fuzzer.profile_lock.fetch_ollama_model_digest",
        lambda *_args: profile.model_digest,
    )
    monkeypatch.setattr(
        "sandbox.fuzzer.profile_lock.docker_image_digest",
        lambda _client, image_ref: (
            profile.image_digest
            if image_ref == profile.image_ref
            else profile.model_runtime_digest
        ),
    )
    monkeypatch.setattr(
        "sandbox.fuzzer.profile_lock.docker_container_image_digest",
        lambda *_args: profile.model_runtime_digest,
    )
    verify_target_profile(
        client=MagicMock(),
        ollama_admin_endpoint="http://127.0.0.1:11434",
        profile=profile,
    )


def test_verify_target_profile_rejects_model_drift(monkeypatch) -> None:
    profile = _profile()
    monkeypatch.setattr(
        "sandbox.fuzzer.profile_lock.fetch_ollama_model_digest",
        lambda *_args: "sha256:" + "9" * 64,
    )
    with pytest.raises(ValueError, match="model digest"):
        verify_target_profile(
            client=MagicMock(),
            ollama_admin_endpoint="http://127.0.0.1:11434",
            profile=profile,
        )

def test_verify_target_profile_rejects_ollama_runtime_image_drift(monkeypatch) -> None:
    profile = _profile()
    monkeypatch.setattr(
        "sandbox.fuzzer.profile_lock.fetch_ollama_model_digest",
        lambda *_args: profile.model_digest,
    )
    monkeypatch.setattr(
        "sandbox.fuzzer.profile_lock.docker_image_digest",
        lambda _client, image_ref: (
            profile.image_digest
            if image_ref == profile.image_ref
            else profile.model_runtime_digest
        ),
    )
    monkeypatch.setattr(
        "sandbox.fuzzer.profile_lock.docker_container_image_digest",
        lambda *_args: "sha256:" + "9" * 64,
    )
    with pytest.raises(ValueError, match="container image digest"):
        verify_target_profile(
            client=MagicMock(),
            ollama_admin_endpoint="http://127.0.0.1:11434",
            profile=profile,
        )
