from __future__ import annotations

from unittest.mock import MagicMock

from sandbox.config import SandboxConfig, SandboxLimits
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler


def test_scheduler_uses_configured_network_mode() -> None:
    container = MagicMock()
    container.id = "container-1"
    container.image.attrs = {"RepoDigests": []}
    container.image.id = "sha256:test"
    client = MagicMock()
    client.containers.run.return_value = container
    scheduler = DockerSandboxScheduler(
        SandboxConfig(network_mode="custom-model-network"),
        client=client,
        scheduler_instance_id="scheduler-1",
    )

    scheduler._create_sync("exec-1", "image:test", SandboxLimits())

    assert client.containers.run.call_args.kwargs["network_mode"] == "custom-model-network"

