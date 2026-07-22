from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from sandbox.config import SandboxConfig, SandboxLimits
from sandbox.errors import InfrastructureError
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler


def _client(*, internal: bool) -> MagicMock:
    container = MagicMock()
    container.id = "container-1"
    container.image.attrs = {"RepoDigests": []}
    container.image.id = "sha256:image"
    network = MagicMock()
    network.name = "trace-g-model-internal"
    network.attrs = {
        "Driver": "bridge",
        "Internal": internal,
        "Labels": {"trace-g.network-policy": "ollama-only"},
    }
    client = MagicMock()
    client.networks.get.return_value = network
    client.containers.run.return_value = container
    return client


def _config() -> SandboxConfig:
    return SandboxConfig(
        ollama_endpoint="http://ollama:11434",
        model_network_name="trace-g-model-internal",
    )


def test_ollama_requires_internal_service_endpoint() -> None:
    assert _config().ollama_endpoint == "http://ollama:11434"
    with pytest.raises(ValidationError, match="internal model network"):
        SandboxConfig(
            ollama_endpoint="http://host.docker.internal:11434",
            model_network_name="trace-g-model-internal",
        )
    with pytest.raises(ValidationError, match="internal model network"):
        SandboxConfig(
            ollama_endpoint="http://ollama:11434/api/chat",
            model_network_name="trace-g-model-internal",
        )


def test_scheduler_rejects_labeled_bridge_that_still_has_egress() -> None:
    scheduler = DockerSandboxScheduler(_config(), client=_client(internal=False))
    with pytest.raises(InfrastructureError, match="internal network"):
        scheduler._create_sync("exec-1", "image:test", SandboxLimits())


def test_scheduler_uses_internal_network_without_host_gateway() -> None:
    client = _client(internal=True)
    scheduler = DockerSandboxScheduler(_config(), client=client)
    scheduler._create_sync("exec-1", "image:test", SandboxLimits())
    create = client.containers.run.call_args.kwargs
    assert create["network_mode"] == "trace-g-model-internal"
    assert create["extra_hosts"] is None
